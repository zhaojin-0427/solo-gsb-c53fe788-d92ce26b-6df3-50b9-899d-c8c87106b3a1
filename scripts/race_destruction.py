"""Regression harness: logical destruction of custody-record lineages (v1.6).

Run (needs KEYVAULT_FAULT_INJECTION=1 for the lock-waiter scenarios; the docker
compose ``demo`` profile sets it automatically):

    python -m scripts.race_destruction

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and pins every required property of logical destruction:

  D1  basic lineage: along completed migration edges the named record AND all
      descendants are destroyed in one transaction; online encrypted shards are
      deleted for the whole lineage while secret-free tombstones remain.
  D2  in-flight recovery and migration sessions on the lineage are moved to the
      non-revivable ``destroyed`` terminal state in the same transaction; after
      the commit every old-session nonce/claim/submit gets CUSTODY_DESTROYED,
      no shard plaintext or wrapped ciphertext is ever delivered.
  D3  destruction vs migration completion (migration wins the race): while the
      destruction is parked holding lineage custody locks, the threshold
      migration submit queues; ordered exactly one way — here the migration
      commits first and the destruction then includes the freshly created
      descendant: the new custody's shards are deleted too, never missed.
  D4  destruction vs migration completion (destruction wins): the destruction
      commits while a threshold submit is queued on the migration row lock; the
      queued submit fails with CUSTODY_DESTROYED and creates no new custody.
  D5  idempotency: replaying the same Idempotency-Key returns the same receipt
      (200), even against an already-destroyed root; the same key with a
      different root is IDEMPOTENCY_CONFLICT; a different key on the destroyed
      root returns a zero-count receipt without error.
  D6  destruction vs shard claim: a claim queued behind the destruction never
      delivers shard plaintext after the commit — CUSTODY_DESTROYED.
  D7  process-pending cleanup: pending accumulation shards of blocked sessions
      are purged from the in-memory store once the destruction transaction
      commits.
  D8  recovery cannot start on a destroyed custody; cross-tenant destruction and
      cross-tenant receipt GET are rejected (FORBIDDEN); receipt GET works for
      the owner; audit chain stays valid and secret-free.
  D9  concurrent reuse of one Idempotency-Key for two UNRELATED roots: both
      requests pass the receipt pre-check (pinned at
      ``destruction.after_receipt_check``), the later receipt insert hits
      ``uq_destruction_idem`` — exactly one request gets 201 + a queryable
      receipt, the other a stable 409 IDEMPOTENCY_CONFLICT (never an unhandled
      500); the loser's lineage destruction / shard deletion / session blocking
      / completion audit are all rolled back and the denial audit matches the
      actual result. Same-key same-root concurrent retries still return the one
      same receipt, and a generic mid-transaction failure is a 500 — never
      misreported as an idempotency conflict.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys

# The gates must be armed before app construction reads settings.
os.environ.setdefault("KEYVAULT_FAULT_INJECTION", "1")

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.crypto import sha256_hex
from app.db import Database, wait_for_database
from app.faults import FaultBoard
from app.main import app
from app.pending import PendingShareStore
from app.seed import seed, demo_credentials

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail and not ok else ""))


def body_of(r) -> dict:
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {}


class _Raw500:
    """Stand-in for the 500 a real HTTP client gets on an unhandled exception.

    Under httpx's ASGI transport, Starlette's ServerErrorMiddleware sends the
    500 response and then re-raises the original exception (uvicorn itself
    swallows that re-raise); we surface it as a plain 500 here.
    """

    def __init__(self, exc: BaseException):
        self.status_code = 500
        self.text = f"{type(exc).__name__}: {exc}"

    def json(self) -> dict:
        return {}


def sign(priv_hex: str, message: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        message.encode()
    ).hex()


EPOCH = {"valid_from": "2026-01-01T00:00:00Z",
         "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}


@contextlib.asynccontextmanager
async def server():
    settings = get_settings()
    await wait_for_database(settings.database_url)
    await seed()
    database = Database(settings.database_url)
    await database.connect()
    app.state.db = database
    app.state.pending = PendingShareStore()
    app.state.fault_enabled = True
    board = FaultBoard()
    app.state.fault_board = board
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        try:
            yield http, database.pool, board
        finally:
            await database.close()


def auth(key: str) -> dict:
    return {"X-API-Key": key}


async def wait_lock_waiters(pool, expect: int, like: str, timeout: float = 10.0) -> int:
    sql = f"""
        SELECT count(*)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'transactionid'
          AND NOT l.granted
          AND a.query LIKE '%{like}%'
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        seen = await pool.fetchval(sql)
        if seen >= expect:
            return seen
        await asyncio.sleep(0.02)
    return seen


class Harness:
    def __init__(self, http, pool, creds):
        self.http = http
        self.pool = pool
        self.tenant_key = creds["tenant"]["api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.secret = b"destruction-lineage-regression-secret-0123"

    def h(self, name: str) -> dict:
        return auth(self.cust[name]["api_key"])

    async def make_policy(self, pid: str, custodians=("alice", "bob", "carol"), threshold: int = 2):
        ids = [f"cus_demo_{n}" for n in custodians]
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": pid, "threshold": threshold, "custodian_ids": ids, "epoch": EPOCH,
        })
        assert r.status_code == 201, r.text

    async def make_custody(self, policy: str) -> str:
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": policy, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return r.json()["custody_id"]

    async def migrate_chain(self, tag: str, hops: int = 2):
        """Create custody then complete ``hops`` migrations; return id chain."""
        src_policy = f"pol_d_{tag}_0"
        await self.make_policy(src_policy)
        cid = await self.make_custody(src_policy)
        chain = [cid]
        prev_policy, prev_cid = src_policy, cid
        for i in range(1, hops + 1):
            tgt_policy = f"pol_d_{tag}_{i}"
            await self.make_policy(tgt_policy)
            mid = body_of(await self.http.post(
                "/migrations", headers={**auth(self.tenant_key),
                                        "Idempotency-Key": f"d-{tag}-hop{i}"},
                json={"source_custody_id": prev_cid, "target_policy_id": tgt_policy,
                      "target_version": 1}))["migration_id"]
            for name in ("alice", "bob"):
                prepped = await self.mig_prep(name, mid)
                r = await self.http.post("/migrations/shares", headers=self.h(name),
                                         json=prepped)
                assert r.status_code == 200, r.text
            new_cid = body_of(r)["new_custody_id"]
            assert new_cid, r.text
            chain.append(new_cid)
            prev_policy, prev_cid = tgt_policy, new_cid
        return chain

    async def mig_prep(self, name: str, mid: str) -> dict:
        h = self.h(name)
        r = await self.http.post("/migrations/nonces", headers=h, json={"migration_id": mid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/migrations/shards/claim", headers=h,
                                 json={"migration_id": mid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {"migration_id": mid, "nonce": nonce, "point_x": c["point_x"],
                "shard_hex": c["shard_hex"],
                "signature": sign(self.cust[name]["signing_private_key"], c["signing_message"])}

    async def rec_prep(self, name: str, sid: str) -> dict:
        h = self.h(name)
        r = await self.http.post("/recoveries/nonces", headers=h, json={"session_id": sid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/recoveries/shards/claim", headers=h,
                                 json={"session_id": sid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {"session_id": sid, "nonce": nonce, "point_x": c["point_x"],
                "shard_hex": c["shard_hex"],
                "signature": sign(self.cust[name]["signing_private_key"], c["signing_message"])}

    async def open_recovery(self, cid: str) -> str:
        r = await self.http.post("/recoveries", headers=auth(self.tenant_key), json={
            "custody_id": cid,
            "request_digest": "00" * 32,
            "recovery_public_key": "11" * 32,
        })
        assert r.status_code == 201, r.text
        return r.json()["session_id"]

    async def open_migration(self, cid: str, target: str, idem: str) -> str:
        r = await self.http.post("/migrations",
                                 headers={**auth(self.tenant_key), "Idempotency-Key": idem},
                                 json={"source_custody_id": cid, "target_policy_id": target,
                                       "target_version": 1})
        assert r.status_code == 201, r.text
        return r.json()["migration_id"]

    async def destroy(self, cid: str, idem: str, extra_headers: dict | None = None):
        try:
            return await self.http.post("/destructions",
                                        headers={**auth(self.tenant_key),
                                                 "Idempotency-Key": idem, **(extra_headers or {})},
                                        json={"root_custody_id": cid})
        except Exception as exc:  # ASGI transport re-raises the 500 path exception
            return _Raw500(exc)

    async def custody_status(self, cid: str):
        return await self.pool.fetchval("SELECT status FROM key_custodies WHERE id=$1", cid)

    async def shard_count(self, cid: str) -> int:
        return await self.pool.fetchval("SELECT count(*) FROM shards WHERE custody_id=$1", cid)


async def scenario_d1(hs: Harness, tag: str):
    label = "D1(lineage+shards)"
    chain = await hs.migrate_chain(tag, hops=2)
    root, child, grandchild = chain
    r = await hs.destroy(root, f"d1-{tag}")
    rc = body_of(r)
    check(f"{label}: 201 receipt covers root+2 descendants",
          r.status_code == 201 and rc.get("custody_count") == 3
          and rc.get("root_custody_id") == root
          and set(rc.get("custody_ids", [])) == set(chain),
          f"HTTP {r.status_code}: {r.text[:200]}")
    check(f"{label}: 9 online encrypted shards deleted (3 custodies x 3)",
          rc.get("shards_deleted") == 9, str(rc.get("shards_deleted")))
    for cid in chain:
        check(f"{label}: {cid[:16]}… tombstone=destroyed, shards gone",
              await hs.custody_status(cid) == "destroyed" and await hs.shard_count(cid) == 0)
    # 墓碑保留无秘密要素（id/摘要/长度仍可查）
    row = await hs.pool.fetchrow(
        "SELECT secret_digest, secret_length, policy_id, destroyed_at IS NOT NULL AS d "
        "FROM key_custodies WHERE id=$1", root)
    check(f"{label}: secret-free tombstone retained",
          row is not None and row["d"] and len(row["secret_digest"]) == 64
          and row["secret_length"] == len(hs.secret))
    # scope 字段明确只覆盖在线数据
    check(f"{label}: receipt scope = online_service_data_only",
          rc.get("scope") == "online_service_data_only")


async def scenario_d2(hs: Harness, tag: str):
    label = "D2(block-inflight)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    sid_root = await hs.open_recovery(root)
    sid_child = await hs.open_recovery(child)
    tgt = f"pol_d_{tag}_open"
    await hs.make_policy(tgt)
    mid = await hs.open_migration(child, tgt, f"d2-{tag}")

    # 在途会话里先领取好分片/nonce（销毁后必须全部失效）
    pa = await hs.mig_prep("alice", mid)
    ra = await hs.rec_prep("alice", sid_child)

    r = await hs.destroy(root, f"d2-{tag}")
    rc = body_of(r)
    check(f"{label}: receipt blocks 2 recoveries + 1 migration",
          r.status_code == 201 and rc.get("recovery_blocked") == 2
          and rc.get("migration_blocked") == 1 and rc.get("custody_count") == 2, r.text)

    for sid in (sid_root, sid_child):
        g = body_of(await hs.http.get(f"/recoveries/{sid}", headers=auth(hs.tenant_key)))
        check(f"{label}: recovery {sid[:12]}… shows destroyed", g.get("status") == "destroyed")
    g = body_of(await hs.http.get(f"/migrations/{mid}", headers=auth(hs.tenant_key)))
    check(f"{label}: migration shows destroyed", g.get("status") == "destroyed")

    # 旧会话再下发/提交一律 CUSTODY_DESTROYED
    rr = await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa)
    check(f"{label}: queued migration submit -> CUSTODY_DESTROYED",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])
    rr = await hs.http.post("/recoveries/shares", headers=hs.h("alice"), json=ra)
    check(f"{label}: queued recovery submit -> CUSTODY_DESTROYED",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])
    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("bob"),
                            json={"session_id": sid_root})
    check(f"{label}: nonce after destroy -> CUSTODY_DESTROYED",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])
    rr = await hs.http.post("/migrations/shards/claim", headers=hs.h("bob"),
                            json={"migration_id": mid, "nonce": "00" * 32})
    check(f"{label}: claim after destroy -> CUSTODY_DESTROYED",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])


async def scenario_d3(hs: Harness, board: FaultBoard, tag: str):
    """Migration completion wins the lock race; destruction includes the child."""
    label = "D3(destroy-vs-complete:migration-wins)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    tgt2 = f"pol_d_{tag}_t2"
    await hs.make_policy(tgt2)
    mid = await hs.open_migration(child, tgt2, f"d3-{tag}")
    pa = await hs.mig_prep("alice", mid)
    pb = await hs.mig_prep("bob", mid)
    await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa)

    # 销毁在谱系 custody 行锁已持有、会话行未锁处 park；bob 的门限提交
    # 需要 child custody 行锁，只能在销毁身后排队——本交错确定性验证
    # “销毁先赢”（迁移先赢的相反交错见 d3b）。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "destruction.after_lineage_lock"}
    destroy_task = asyncio.create_task(hs.destroy(root, f"d3-{tag}", gate))
    await board.wait_reached(f"destruction.after_lineage_lock:{label}")

    submit_task = asyncio.create_task(
        hs.http.post("/migrations/shares", headers=hs.h("bob"), json=pb))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: migration submit waits on lineage custody lock", queued == 1, f"q={queued}")

    await board.release_gate(f"destruction.after_lineage_lock:{label}")
    rd = await destroy_task
    rs = await submit_task
    # 销毁持有 child custody 行锁直到提交：提交必然输掉 -> CUSTODY_DESTROYED。
    check(f"{label}: destruction wins custody-lock order, submit rejected 410",
          rd.status_code == 201 and rs.status_code == 410
          and body_of(rs)["error"]["code"] == "CUSTODY_DESTROYED",
          f"destroy={rd.status_code} submit={rs.status_code} {rs.text[:150]}")
    rc = body_of(rd)
    check(f"{label}: no descendant inserted by loser (still 2 custodies)",
          rc.get("custody_count") == 2, str(rc.get("custody_count")))

    # ---- d3b: 迁移先赢。门限提交先持有 child custody 锁并 park 在
    # migration.after_lock（已锁 custody、会话行锁）之后不现实——after_lock
    # 位于两锁之后。改用 before_resplit：此时迁移已持两锁且尚未提交，
    # 销毁在 child custody 锁上等待；放行后迁移先提交，销毁随后必须把新
    # 后代纳入谱系并删除其分片。
    label2 = "D3b(complete-wins:child-included)"
    chain2 = await hs.migrate_chain(f"{tag}b", hops=1)
    root2, child2 = chain2
    tgt3 = f"pol_d_{tag}b_t"
    await hs.make_policy(tgt3)
    mid2 = await hs.open_migration(child2, tgt3, f"d3b-{tag}")
    pa2 = await hs.mig_prep("alice", mid2)
    pb2 = await hs.mig_prep("bob", mid2)
    await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa2)
    gate2 = {"X-Fault-Key": label2, "X-Fault-Gate": "migration.before_resplit"}
    submit_task2 = asyncio.create_task(
        hs.http.post("/migrations/shares", headers={**hs.h("bob"), **gate2}, json=pb2))
    await board.wait_reached(f"migration.before_resplit:{label2}")
    destroy_task2 = asyncio.create_task(hs.destroy(root2, f"d3b-{tag}"))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label2}: destruction waits behind completing migration", queued == 1, f"q={queued}")
    await board.release_gate(f"migration.before_resplit:{label2}")
    rs2 = await submit_task2
    rd2 = await destroy_task2
    new_cid = body_of(rs2).get("new_custody_id")
    check(f"{label2}: migration completes first with new custody",
          rs2.status_code == 200 and bool(new_cid), rs2.text[:200])
    rc2 = body_of(rd2)
    check(f"{label2}: destruction then covers root+child+new-grandchild",
          rd2.status_code == 201 and rc2.get("custody_count") == 3
          and new_cid in rc2.get("custody_ids", []),
          f"{rd2.status_code} {rc2.get('custody_count')}")
    check(f"{label2}: new descendant shards deleted too (never missed)",
          await hs.custody_status(new_cid) == "destroyed"
          and await hs.shard_count(new_cid) == 0)


async def scenario_d4(hs: Harness, board: FaultBoard, tag: str):
    """Destruction commits while a threshold submit queues on the migration lock."""
    label = "D4(destroy-wins:no-missed-child)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    tgt = f"pol_d_{tag}_t"
    await hs.make_policy(tgt)
    mid = await hs.open_migration(child, tgt, f"d4-{tag}")
    pa = await hs.mig_prep("alice", mid)
    pb = await hs.mig_prep("bob", mid)
    await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa)

    # bob 提交先到 migration.after_lock（custody+会话两锁在手，尚未重分片）。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "migration.after_lock"}
    submit_task = asyncio.create_task(
        hs.http.post("/migrations/shares", headers={**hs.h("bob"), **gate}, json=pb))
    await board.wait_reached(f"migration.after_lock:{label}")

    # 销毁在 child custody 行锁上排队（迁移正持有它）。
    destroy_task = asyncio.create_task(hs.destroy(root, f"d4-{tag}"))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: destruction queues behind parked submit", queued == 1, f"q={queued}")

    # 放行提交：它继续重分片并提交——迁移赢（等价 D3b 的锁序）。
    # 为覆盖“销毁赢、提交排在会话锁上”，见 d4b：销毁先持有 custody 锁，
    # 提交在 migration_sessions 行锁队列里。
    await board.release_gate(f"migration.after_lock:{label}")
    rs = await submit_task
    rd = await destroy_task
    check(f"{label}: parked submit completes, destruction follows",
          rs.status_code == 200 and rd.status_code == 201,
          f"{rs.status_code}/{rd.status_code}")
    new_cid = body_of(rs).get("new_custody_id")
    check(f"{label}: grandchild included and destroyed",
          new_cid in body_of(rd).get("custody_ids", [])
          and await hs.custody_status(new_cid) == "destroyed")

    # d4b: 销毁先持有谱系锁并 park；提交已过 nonce/claim，直接发请求，它会
    # 阻塞在 child custody 锁上（销毁持有中）——放行销毁后提交得 410。
    label2 = "D4b(submit-queued-destroy-commits)"
    chain2 = await hs.migrate_chain(f"{tag}b", hops=1)
    root2, child2 = chain2
    tgt2 = f"pol_d_{tag}b_t"
    await hs.make_policy(tgt2)
    mid2 = await hs.open_migration(child2, tgt2, f"d4b-{tag}")
    pa2 = await hs.mig_prep("alice", mid2)
    pb2 = await hs.mig_prep("bob", mid2)
    await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa2)
    gate2 = {"X-Fault-Key": label2, "X-Fault-Gate": "destruction.after_lineage_lock"}
    destroy_task2 = asyncio.create_task(hs.destroy(root2, f"d4b-{tag}", gate2))
    await board.wait_reached(f"destruction.after_lineage_lock:{label2}")
    submit_task2 = asyncio.create_task(
        hs.http.post("/migrations/shares", headers=hs.h("bob"), json=pb2))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label2}: threshold submit queues behind destruction", queued == 1, f"q={queued}")
    await board.release_gate(f"destruction.after_lineage_lock:{label2}")
    rd2 = await destroy_task2
    rs2 = await submit_task2
    check(f"{label2}: queued submit gets 410 after destroy commit",
          rd2.status_code == 201 and rs2.status_code == 410
          and body_of(rs2)["error"]["code"] == "CUSTODY_DESTROYED", rs2.text[:160])
    new_custodies = await hs.pool.fetchval(
        "SELECT count(*) FROM migration_sessions WHERE source_custody_id=$1 "
        "AND new_custody_id IS NOT NULL", child2)
    check(f"{label2}: loser inserted no descendant custody", new_custodies == 0, str(new_custodies))


async def scenario_d5(hs: Harness, tag: str):
    label = "D5(idempotency)"
    chain = await hs.migrate_chain(tag, hops=1)
    root = chain[0]
    r1 = await hs.destroy(root, f"d5-{tag}")
    rc1 = body_of(r1)
    did = rc1.get("destruction_id")
    r2 = await hs.destroy(root, f"d5-{tag}")
    rc2 = body_of(r2)
    check(f"{label}: same key replay -> 200 same receipt",
          r2.status_code == 200 and rc2.get("destruction_id") == did
          and rc2.get("shards_deleted") == rc1.get("shards_deleted")
          and rc2.get("custody_ids") == rc1.get("custody_ids"), r2.text[:200])
    # GET 回执
    r = await hs.http.get(f"/destructions/{did}", headers=auth(hs.tenant_key))
    check(f"{label}: GET receipt by id",
          r.status_code == 200 and body_of(r).get("destruction_id") == did, r.text[:200])
    # 同键不同根 -> IDEMPOTENCY_CONFLICT
    other = await hs.make_custody((await _fresh_policy(hs, f"{tag}x")))
    r = await hs.destroy(other, f"d5-{tag}")
    check(f"{label}: same key different root -> IDEMPOTENCY_CONFLICT",
          r.status_code == 409 and body_of(r)["error"]["code"] == "IDEMPOTENCY_CONFLICT", r.text[:200])
    # 不同键重复销毁已毁根：成功，零计数回执
    r = await hs.destroy(root, f"d5-other-{tag}")
    rc = body_of(r)
    check(f"{label}: different key on destroyed root -> 201 zero-effect receipt",
          r.status_code == 201 and rc.get("custody_count") == 2
          and rc.get("shards_deleted") == 0 and rc.get("recovery_blocked") == 0
          and rc.get("migration_blocked") == 0, r.text[:200])
    # 缺少幂等键
    r = await hs.http.post("/destructions", headers=auth(hs.tenant_key),
                           json={"root_custody_id": root})
    check(f"{label}: missing idempotency key -> BAD_REQUEST",
          r.status_code == 400 and body_of(r)["error"]["code"] == "BAD_REQUEST", r.text[:200])


async def _fresh_policy(hs: Harness, tag: str) -> str:
    pid = f"pol_d_{tag}_fresh"
    await hs.make_policy(pid)
    return pid


async def scenario_d6(hs: Harness, board: FaultBoard, tag: str):
    label = "D6(destroy-vs-claim)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    # 针对 child 新开一个进行中迁移，bob 已领 nonce，claim 与销毁争锁
    tgt = f"pol_d_{tag}_t"
    await hs.make_policy(tgt)
    mid = await hs.open_migration(child, tgt, f"d6-{tag}")
    r = await hs.http.post("/migrations/nonces", headers=hs.h("bob"), json={"migration_id": mid})
    nonce = r.json()["nonce"]
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "destruction.after_lineage_lock"}
    dt = asyncio.create_task(hs.destroy(root, f"d6-{tag}", gate))
    await board.wait_reached(f"destruction.after_lineage_lock:{label}")
    ct = asyncio.create_task(hs.http.post("/migrations/shards/claim", headers=hs.h("bob"),
                                         json={"migration_id": mid, "nonce": nonce}))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: claim queues on lineage custody lock", queued == 1, f"q={queued}")
    await board.release_gate(f"destruction.after_lineage_lock:{label}")
    rd = await dt
    rc = await ct
    check(f"{label}: queued claim never delivers shard -> 410",
          rd.status_code == 201 and rc.status_code == 410
          and body_of(rc)["error"]["code"] == "CUSTODY_DESTROYED"
          and "shard_hex" not in rc.text, rc.text[:200])


async def scenario_d7(hs: Harness, tag: str):
    label = "D7(pending-purge)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    # child 上开恢复并提交 1 份分片 -> 内存有待累计分片
    sid = await hs.open_recovery(child)
    prepped = await hs.rec_prep("alice", sid)
    r = await hs.http.post("/recoveries/shares", headers=hs.h("alice"), json=prepped)
    assert r.status_code == 200 and body_of(r)["shares_received"] == 1, r.text
    check(f"{label}: pending shard accumulated before destroy",
          app.state.pending.count(sid) == 1)
    rd = await hs.destroy(root, f"d7-{tag}")
    check(f"{label}: destruction 201 and blocked the open recovery",
          rd.status_code == 201 and body_of(rd).get("recovery_blocked") == 1, rd.text[:200])
    check(f"{label}: pending accumulation shard purged after commit",
          app.state.pending.count(sid) == 0)
    # 迁移待累计分片同理
    tgt = f"pol_d_{tag}_t"
    chain2 = await hs.migrate_chain(f"{tag}b", hops=1)
    root2, child2 = chain2
    await hs.make_policy(tgt)
    mid = await hs.open_migration(child2, tgt, f"d7-{tag}b")
    mp = await hs.mig_prep("alice", mid)
    r = await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=mp)
    assert r.status_code == 200, r.text
    check(f"{label}: migration pending accumulated", app.state.pending.count(mid) == 1)
    await hs.destroy(root2, f"d7-{tag}b2")
    check(f"{label}: migration pending purged after commit",
          app.state.pending.count(mid) == 0)


async def scenario_d8(hs: Harness, tag: str):
    label = "D8(access-control+audit)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    rd = await hs.destroy(root, f"d8-{tag}")
    did = body_of(rd)["destruction_id"]
    # 不得再开恢复
    rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": child, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery start on destroyed -> 410",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])
    # 不得再发起迁移
    tgt = f"pol_d_{tag}_t"
    await hs.make_policy(tgt)
    rr = await hs.http.post("/migrations",
                            headers={**auth(hs.tenant_key), "Idempotency-Key": f"d8m-{tag}"},
                            json={"source_custody_id": child, "target_policy_id": tgt,
                                  "target_version": 1})
    check(f"{label}: migration start on destroyed -> 410",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED", rr.text[:200])
    # 未知根 -> NOT_FOUND
    rr = await hs.destroy("cus_secret_does_not_exist", f"d8nf-{tag}")
    check(f"{label}: unknown root -> NOT_FOUND",
          rr.status_code == 404 and body_of(rr)["error"]["code"] == "NOT_FOUND", rr.text[:200])
    # 跨租户
    r = await hs.http.post("/admin/tenants", headers=auth(demo_credentials()["admin_api_key"]),
                           json={"name": f"destruction-tenant-{tag}"})
    assert r.status_code == 201, r.text
    other_key = r.json()["api_key"]
    rr = await hs.http.post("/destructions",
                            headers={**auth(other_key), "Idempotency-Key": f"d8xt-{tag}"},
                            json={"root_custody_id": root})
    check(f"{label}: cross-tenant destroy -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:200])
    rr = await hs.http.get(f"/destructions/{did}", headers=auth(other_key))
    check(f"{label}: cross-tenant receipt GET -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:200])
    # 审计链有效、无明文、含 destruction.complete
    r = await hs.http.get("/audit/replay", headers=auth(hs.tenant_key))
    chain_rep = r.json()
    actions = [e["action"] for e in chain_rep["entries"]]
    check(f"{label}: audit chain valid with destruction.complete",
          chain_rep.get("valid") is True and "destruction.complete" in actions)
    raw = json.dumps(chain_rep)
    check(f"{label}: audit carries no secret plaintext",
          hs.secret.hex() not in raw and hs.secret.decode() not in raw)
    des_rows = await hs.pool.fetch(
        "SELECT basis FROM audit_log WHERE action='destruction.complete' "
        "AND resource=$1", did)
    raw2 = json.dumps(
        [json.loads(d["basis"]) if isinstance(d["basis"], str) else d["basis"]
         for d in des_rows], default=str)
    check(f"{label}: destruction audit is secret-free, replayable",
          len(des_rows) == 1 and hs.secret.hex() not in raw2 and "custody_ids" in raw2)


async def scenario_d9(hs: Harness, board: FaultBoard, tag: str):
    """Concurrent reuse of one Idempotency-Key for two unrelated roots.

    Pins the receipt pre-check interleaving with the
    ``destruction.after_receipt_check`` gate: both requests pass the pre-check,
    the later receipt insert hits ``uq_destruction_idem`` and must degrade to a
    deterministic 409 IDEMPOTENCY_CONFLICT with a full rollback — never an
    unhandled database error.
    """
    label = "D9(idem-key-race:conflict)"
    chain_a = await hs.migrate_chain(f"{tag}a", hops=1)
    chain_b = await hs.migrate_chain(f"{tag}b", hops=1)
    root_a, child_a = chain_a
    root_b, child_b = chain_b
    # 失败方谱系上的在途恢复会话（已入池 1 份待累计分片）：回滚后必须仍是
    # open，且进程内待累计分片不得被清理。
    sid_b = await hs.open_recovery(child_b)
    prepped_b = await hs.rec_prep("alice", sid_b)
    r = await hs.http.post("/recoveries/shares", headers=hs.h("alice"), json=prepped_b)
    assert r.status_code == 200 and body_of(r)["shares_received"] == 1, r.text
    check(f"{label}: loser-side recovery accumulated a pending shard",
          app.state.pending.count(sid_b) == 1)
    key = f"d9-{tag}"
    gate_a = {"X-Fault-Key": f"{label}-a",
              "X-Fault-Gate": "destruction.after_receipt_check"}
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "destruction.after_receipt_check"}

    ta = asyncio.create_task(hs.destroy(root_a, key, gate_a))
    tb = asyncio.create_task(hs.destroy(root_b, key, gate_b))
    # 钉住交错：两个请求都已通过回执预查（都未发现既有回执）。
    await board.wait_reached(f"destruction.after_receipt_check:{label}-a")
    await board.wait_reached(f"destruction.after_receipt_check:{label}-b")

    # 先放行 A：完整提交 -> 201 + 可查询回执。
    await board.release_gate(f"destruction.after_receipt_check:{label}-a")
    ra = await ta
    did = body_of(ra).get("destruction_id")
    check(f"{label}: first request -> 201 receipt",
          ra.status_code == 201 and bool(did)
          and body_of(ra).get("root_custody_id") == root_a,
          f"{ra.status_code} {ra.text[:200]}")

    # 再放行 B：回执插入撞上 uq_destruction_idem -> 整体回滚 -> 409。
    await board.release_gate(f"destruction.after_receipt_check:{label}-b")
    rb = await tb
    check(f"{label}: second request -> stable 409 IDEMPOTENCY_CONFLICT (not 500)",
          rb.status_code == 409
          and body_of(rb).get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT",
          f"{rb.status_code} {rb.text[:200]}")

    # 胜方谱系已销毁；败方谱系/分片/在途会话全部回滚、原样保留。
    check(f"{label}: winner lineage destroyed, shards deleted",
          await hs.custody_status(root_a) == "destroyed"
          and await hs.custody_status(child_a) == "destroyed"
          and await hs.shard_count(root_a) == 0
          and await hs.shard_count(child_a) == 0)
    check(f"{label}: loser lineage intact (destruction rolled back)",
          await hs.custody_status(root_b) == "active"
          and await hs.custody_status(child_b) == "active"
          and await hs.shard_count(root_b) == 3
          and await hs.shard_count(child_b) == 3)
    g = body_of(await hs.http.get(f"/recoveries/{sid_b}", headers=auth(hs.tenant_key)))
    check(f"{label}: loser in-flight recovery still open (block rolled back)",
          g.get("status") == "open", str(g.get("status")))
    check(f"{label}: loser pending shard NOT purged (rollback leaves memory alone)",
          app.state.pending.count(sid_b) == 1)

    # 该幂等键全库只有一份回执（胜方的），可 GET。
    r = await hs.http.get(f"/destructions/{did}", headers=auth(hs.tenant_key))
    check(f"{label}: winner receipt queryable by id",
          r.status_code == 200 and body_of(r).get("destruction_id") == did,
          r.text[:200])
    cnt = await hs.pool.fetchval(
        "SELECT count(*) FROM destructions WHERE idempotency_key_hash=$1",
        sha256_hex(key.encode()))
    check(f"{label}: exactly one receipt row for the idempotency key",
          cnt == 1, str(cnt))

    # 审计与实际结果一致：败方没有 destruction.complete（完成审计随事务
    # 回滚），且恰有一条 destruction.start denied / IDEMPOTENCY_CONFLICT。
    complete_roots = set()
    for rec in await hs.pool.fetch(
            "SELECT basis FROM audit_log WHERE action='destruction.complete'"):
        basis = rec["basis"]
        complete_roots.add((json.loads(basis) if isinstance(basis, str) else basis)
                           .get("root_custody_id"))
    check(f"{label}: no completion audit for loser root (rolled back)",
          root_b not in complete_roots)
    denied = await hs.pool.fetch(
        "SELECT error_code FROM audit_log "
        "WHERE action='destruction.start' AND result='denied' AND resource=$1",
        root_b)
    check(f"{label}: denial audit consistent with actual result",
          len(denied) == 1 and denied[0]["error_code"] == "IDEMPOTENCY_CONFLICT",
          str([dict(d) for d in denied]))

    # 冲突后败方换新幂等键即可安全重试（回执不占位）。
    rr = await hs.destroy(root_b, f"d9-retry-{tag}")
    check(f"{label}: loser retries with a fresh key -> 201 zero-conflict receipt",
          rr.status_code == 201
          and body_of(rr).get("root_custody_id") == root_b
          and body_of(rr).get("shards_deleted") == 6,
          f"{rr.status_code} {rr.text[:200]}")
    check(f"{label}: real destruction then purges the pending shard",
          app.state.pending.count(sid_b) == 0)

    # ---- D9b: 同键同根并发重试——第二个请求在根行锁上排队，胜方提交后
    # 经预查重放，取得同一份回执（200）。
    label2 = "D9b(same-root-concurrent-retry)"
    chain_c = await hs.migrate_chain(f"{tag}c", hops=1)
    root_c = chain_c[0]
    key2 = f"d9b-{tag}"
    gate_c = {"X-Fault-Key": f"{label2}-a",
              "X-Fault-Gate": "destruction.after_receipt_check"}
    t1 = asyncio.create_task(hs.destroy(root_c, key2, gate_c))
    await board.wait_reached(f"destruction.after_receipt_check:{label2}-a")
    t2 = asyncio.create_task(hs.destroy(root_c, key2))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label2}: same-root retry queues on root custody lock",
          queued == 1, f"q={queued}")
    await board.release_gate(f"destruction.after_receipt_check:{label2}-a")
    r1 = await t1
    r2 = await t2
    check(f"{label2}: 201 then 200 replay of the same receipt",
          r1.status_code == 201 and r2.status_code == 200
          and body_of(r1).get("destruction_id")
          and body_of(r2).get("destruction_id") == body_of(r1).get("destruction_id"),
          f"{r1.status_code}/{r2.status_code} {r2.text[:150]}")

    # ---- D9c: 双闸门同时放行——败者的回执插入在唯一索引上等待胜者提交，
    # 解析后确定性 409；结果集合恒为 {201, 409}，回执恒为一份。
    label3 = "D9c(simultaneous-release)"
    chain_d = await hs.migrate_chain(f"{tag}d", hops=1)
    chain_e = await hs.migrate_chain(f"{tag}e", hops=1)
    root_d = chain_d[0]
    root_e = chain_e[0]
    key3 = f"d9c-{tag}"
    gate_d = {"X-Fault-Key": f"{label3}-a",
              "X-Fault-Gate": "destruction.after_receipt_check"}
    gate_e = {"X-Fault-Key": f"{label3}-b",
              "X-Fault-Gate": "destruction.after_receipt_check"}
    td = asyncio.create_task(hs.destroy(root_d, key3, gate_d))
    te = asyncio.create_task(hs.destroy(root_e, key3, gate_e))
    await board.wait_reached(f"destruction.after_receipt_check:{label3}-a")
    await board.wait_reached(f"destruction.after_receipt_check:{label3}-b")
    await board.release_gate(f"destruction.after_receipt_check:{label3}-a")
    await board.release_gate(f"destruction.after_receipt_check:{label3}-b")
    rd, re_ = await asyncio.gather(td, te)
    by_root = {root_d: rd, root_e: re_}
    codes = sorted(r.status_code for r in (rd, re_))
    check(f"{label3}: exactly one 201 and one 409", codes == [201, 409], str(codes))
    if codes == [201, 409]:
        win_root = next(root for root, r in by_root.items() if r.status_code == 201)
        lose_root = next(root for root, r in by_root.items() if r.status_code == 409)
        check(f"{label3}: 409 carries IDEMPOTENCY_CONFLICT",
              body_of(by_root[lose_root]).get("error", {}).get("code")
              == "IDEMPOTENCY_CONFLICT",
              by_root[lose_root].text[:150])
        check(f"{label3}: winner destroyed / loser intact",
              await hs.custody_status(win_root) == "destroyed"
              and await hs.custody_status(lose_root) == "active")
        cnt = await hs.pool.fetchval(
            "SELECT count(*) FROM destructions WHERE idempotency_key_hash=$1",
            sha256_hex(key3.encode()))
        check(f"{label3}: still exactly one receipt row", cnt == 1, str(cnt))

    # ---- D9d: 预查后注入通用故障（模拟连接中止/其它数据库错误）——必须
    # 原样 500，绝不能误判为 409 幂等冲突；事务整体回滚，同键可安全重试。
    label4 = "D9d(generic-error-not-conflict)"
    chain_f = await hs.migrate_chain(f"{tag}f", hops=1)
    root_f = chain_f[0]
    key4 = f"d9d-{tag}"
    rf = await hs.destroy(root_f, key4, {
        "X-Fault-Key": label4,
        "X-Fault-Fail": "destruction.after_receipt_check:RAISE"})
    check(f"{label4}: generic failure surfaces as 500, not 409",
          rf.status_code == 500, f"{rf.status_code} {rf.text[:150]}")
    check(f"{label4}: lineage rolled back after generic failure",
          await hs.custody_status(root_f) == "active"
          and await hs.shard_count(root_f) == 3)
    cnt = await hs.pool.fetchval(
        "SELECT count(*) FROM destructions WHERE idempotency_key_hash=$1",
        sha256_hex(key4.encode()))
    check(f"{label4}: no receipt row after generic failure", cnt == 0, str(cnt))
    rr = await hs.destroy(root_f, key4)
    check(f"{label4}: same key retries cleanly -> 201",
          rr.status_code == 201
          and body_of(rr).get("root_custody_id") == root_f,
          f"{rr.status_code} {rr.text[:150]}")


async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        suffix = os.urandom(4).hex()
        await scenario_d1(hs, f"{suffix}1")
        await scenario_d2(hs, f"{suffix}2")
        await scenario_d3(hs, board, f"{suffix}3")
        await scenario_d4(hs, board, f"{suffix}4")
        await scenario_d5(hs, f"{suffix}5")
        await scenario_d6(hs, board, f"{suffix}6")
        await scenario_d7(hs, f"{suffix}7")
        await scenario_d8(hs, f"{suffix}8")
        await scenario_d9(hs, board, f"{suffix}9")

        r = await http.get("/audit/replay", headers=auth(hs.tenant_key))
        check("final: audit hash chain valid across destruction scenarios",
              r.json().get("valid") is True)

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} destruction checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("DESTRUCTION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
