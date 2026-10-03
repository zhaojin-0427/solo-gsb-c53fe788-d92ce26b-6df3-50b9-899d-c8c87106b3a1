"""Regression harness: cross-policy migration after losing in-memory pending shares.

Run (needs KEYVAULT_FAULT_INJECTION=1 for the lock-waiter scenario; the docker
compose ``demo`` profile sets it automatically):

    python -m scripts.race_migration

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and simulates an API restart / pending-pool eviction by swapping
or clearing the in-memory ``PendingShareStore`` while committed share
submissions remain in the database — the exact situation that previously left a
migration session stuck ``open`` until TTL: the first custodian's committed
submission could never be re-sent (unique constraint + spent nonce), so the
threshold could never be reached, yet the open session kept the per-custody and
per-idempotency-key unique placeholders and blocked any re-start.

Expected behavior under test (v1.5):

  M1  restart after the first committed share: the threshold-reaching submit
      gets a deterministic THRESHOLD_NOT_MET(pending_shares_unavailable); in
      the same transaction (session row lock still held) its own share is
      undone (memory token + db row + nonce), the session is committed as a
      queryable ``failed`` terminal state, and a plaintext-free
      ``migration.fail`` audit entry is appended. No new custody is created.
  M2  after the failure a NEW idempotency key re-starts the migration from the
      source record and completes exactly once — one new custody, source
      record untouched.
  M3  the SAME idempotency key may also safely retry after failure (201 fresh
      session, not a 200 replay of the failed row); once it completes, replay
      returns the same new custody. Still exactly one new custody.
  M4  a submitter queued on the session row lock while the gap is being
      detected can never complete the old migration: it fails fast with
      MIGRATION_FAILED and leaves no trace (no count, nonce unspent).
  M5  eviction of just that session's pending shares (sweep / capacity
      eviction) behaves exactly like a full restart.
  M6  a transient post-pool failure (audit/connection style) must NOT be
      mistaken for the lost-shares gap: the session stays open, the v1.3
      token-scoped undo boundary applies, and a clean retry completes.
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


def sign(priv_hex: str, message: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        message.encode()
    ).hex()


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


async def wait_lock_waiters(pool, expect: int, timeout: float = 10.0) -> int:
    """Wait until ``expect`` backends hold an ungranted row lock on a migration."""
    sql = """
        SELECT count(*)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'transactionid'
          AND NOT l.granted
          AND (a.query LIKE '%migration_sessions%FOR UPDATE%'
               OR a.query LIKE '%key_custodies%FOR UPDATE%')
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        seen = await pool.fetchval(sql)
        if seen >= expect:
            return seen
        await asyncio.sleep(0.05)
    return seen


class Harness:
    def __init__(self, http, pool, creds):
        self.http = http
        self.pool = pool
        self.tenant_key = creds["tenant"]["api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.secret = b"migration-lost-shares-regression-0123456789"

    def h(self, name: str) -> dict:
        return auth(self.cust[name]["api_key"])

    async def make_policies(self, tag: str):
        """Fresh 2-of-3 source policy + custody and a distinct target policy."""
        src = f"pol_msrc_{tag}"
        tgt = f"pol_mtgt_{tag}"
        for pid in (src, tgt):
            r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
                "policy_id": pid, "threshold": 2,
                "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                "epoch": {"valid_from": "2026-01-01T00:00:00Z",
                          "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0},
            })
            assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": src, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return src, tgt, r.json()["custody_id"]

    async def start(self, custody_id: str, target: str, idem: str):
        return await self.http.post(
            "/migrations",
            headers={**auth(self.tenant_key), "Idempotency-Key": idem},
            json={"source_custody_id": custody_id, "target_policy_id": target,
                  "target_version": 1},
        )

    async def prep(self, name: str, mid: str) -> dict:
        h = self.h(name)
        r = await self.http.post("/migrations/nonces", headers=h, json={"migration_id": mid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/migrations/shards/claim", headers=h,
                                 json={"migration_id": mid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {
            "headers": dict(h),
            "json": {"migration_id": mid, "nonce": nonce, "point_x": c["point_x"],
                     "shard_hex": c["shard_hex"],
                     "signature": sign(self.cust[name]["signing_private_key"],
                                       c["signing_message"])},
        }

    async def submit(self, prepped: dict, extra_headers: dict | None = None):
        headers = {**prepped["headers"], **(extra_headers or {})}
        return await self.http.post("/migrations/shares", headers=headers,
                                    json=prepped["json"])

    async def mig_row(self, mid: str):
        return await self.pool.fetchrow(
            "SELECT status, new_custody_id, "
            "(SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1) AS subs "
            "FROM migration_sessions WHERE id=$1", mid)

    async def nonce_spent(self, mid: str, custodian_id: str):
        return await self.pool.fetchval(
            "SELECT spent FROM migration_nonces WHERE migration_id=$1 AND custodian_id=$2",
            mid, custodian_id)

    async def custody_count(self) -> int:
        return await self.pool.fetchval("SELECT count(*) FROM key_custodies")

    async def completed_migrations(self, custody_id: str) -> int:
        return await self.pool.fetchval(
            "SELECT count(*) FROM migration_sessions WHERE source_custody_id=$1 "
            "AND new_custody_id IS NOT NULL", custody_id)


def simulate_restart() -> None:
    """API 进程重启：数据库提交计数保留，内存待累计分片全部丢失。"""
    app.state.pending = PendingShareStore()


async def scenario_m1(hs: Harness, tag: str):
    label = "M1(restart->failed)"
    src, tgt, cid = await hs.make_policies(tag)
    idem = f"m1-{tag}"
    r = await hs.start(cid, tgt, idem)
    m1 = body_of(r)
    check(f"{label}: migration session created (open)",
          r.status_code == 201 and m1.get("status") == "open", r.text)
    mid = m1["migration_id"]

    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    check(f"{label}: alice share committed (1/2)",
          r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)

    # 首名托管人已提交；API 进程重启，内存待累计分片丢失、数据库计数保留。
    simulate_restart()
    row = await hs.mig_row(mid)
    check(f"{label}: restart wiped pending pool, db count kept",
          app.state.pending.count(mid) == 0 and row["subs"] == 1 and row["status"] == "open",
          f"mem={app.state.pending.count(mid)} subs={row['subs']} status={row['status']}")

    # 另一名托管人提交使数据库计数达到源门限：检出缺片。
    pb = await hs.prep("bob", mid)
    r = await hs.submit(pb)
    err = body_of(r).get("error", {})
    check(f"{label}: threshold-reaching submit -> THRESHOLD_NOT_MET(pending_shares_unavailable)",
          r.status_code == 409 and err.get("code") == "THRESHOLD_NOT_MET"
          and err.get("basis", {}).get("reason") == "pending_shares_unavailable"
          and err.get("basis", {}).get("migration_status") == "failed",
          f"HTTP {r.status_code}: {r.text[:200]}")

    row = await hs.mig_row(mid)
    check(f"{label}: session committed as queryable failed terminal state",
          row["status"] == "failed" and row["new_custody_id"] is None, str(dict(row)))
    check(f"{label}: detecting share undone (db count back to 1, bob nonce unspent)",
          row["subs"] == 1 and await hs.nonce_spent(mid, "cus_demo_bob") is False,
          f"subs={row['subs']}")
    check(f"{label}: failed session leaves no pending shares in memory",
          app.state.pending.count(mid) == 0)

    r = await hs.http.get(f"/migrations/{mid}", headers=auth(hs.tenant_key))
    g = body_of(r)
    check(f"{label}: GET reports failed state with committed share history",
          r.status_code == 200 and g.get("status") == "failed"
          and g.get("shares_received") == 1 and g.get("new_custody_id") is None, r.text)

    # 旧会话的一切后续请求确定性拒绝，不得再完成迁移。
    r = await hs.http.post("/migrations/nonces", headers=hs.h("carol"),
                           json={"migration_id": mid})
    check(f"{label}: nonce on failed session -> MIGRATION_FAILED",
          r.status_code == 409 and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED",
          f"HTTP {r.status_code}: {r.text[:200]}")
    r = await hs.submit(pb)
    check(f"{label}: submit retry on failed session -> MIGRATION_FAILED",
          r.status_code == 409 and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED",
          f"HTTP {r.status_code}: {r.text[:200]}")
    r = await hs.http.post("/migrations/shards/claim", headers=hs.h("alice"),
                           json={"migration_id": mid, "nonce": pa["json"]["nonce"]})
    check(f"{label}: claim on failed session -> MIGRATION_FAILED",
          r.status_code == 409 and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED",
          f"HTTP {r.status_code}: {r.text[:200]}")

    # 无明文审计：migration.fail 入链、链完整、不含秘密/分片明文。
    r = await hs.http.get("/audit/replay", headers=auth(hs.tenant_key))
    chain = r.json()
    actions = [e["action"] for e in chain["entries"]]
    check(f"{label}: audit chain valid and records migration.fail",
          chain.get("valid") is True and "migration.fail" in actions)
    raw = json.dumps(chain)
    check(f"{label}: audit carries no plaintext (secret/shard)",
          hs.secret.hex() not in raw and pb["json"]["shard_hex"] not in raw)
    return src, tgt, cid


async def scenario_m2(hs: Harness, tag: str, tgt: str, cid: str) -> None:
    label = "M2(new-key-restart)"
    custodies_before = await hs.custody_count()
    r = await hs.start(cid, tgt, f"m2-{tag}")
    m2 = body_of(r)
    check(f"{label}: new idempotency key re-starts from source record (201)",
          r.status_code == 201 and m2.get("status") == "open"
          and m2.get("source_custody_id") == cid, r.text)
    mid2 = m2["migration_id"]

    pa = await hs.prep("alice", mid2)
    pb = await hs.prep("bob", mid2)
    r = await hs.submit(pa)
    check(f"{label}: original custodian can submit on the fresh session",
          r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: retried migration completes with a new custody",
          r.status_code == 200 and b.get("completed") and b.get("new_custody_id"), r.text)
    new_cid = b.get("new_custody_id")

    done = await hs.completed_migrations(cid)
    check(f"{label}: exactly one new custody for the source record (no duplicates)",
          done == 1 and (await hs.custody_count()) == custodies_before + 1,
          f"completed={done}")
    src_status = await hs.pool.fetchval("SELECT status FROM key_custodies WHERE id=$1", cid)
    new_shards = await hs.pool.fetchval("SELECT count(*) FROM shards WHERE custody_id=$1", new_cid)
    new_pol = await hs.pool.fetchval("SELECT policy_id FROM key_custodies WHERE id=$1", new_cid)
    check(f"{label}: source untouched, new custody bound to target policy",
          src_status == "active" and new_shards == 3 and new_pol == tgt,
          f"src={src_status} shards={new_shards} pol={new_pol}")

    r = await hs.start(cid, tgt, f"m2-{tag}")
    check(f"{label}: idempotent replay of the key returns the same new custody",
          r.status_code == 200 and body_of(r).get("status") == "completed"
          and body_of(r).get("new_custody_id") == new_cid, r.text)


async def scenario_m3(hs: Harness, tag: str) -> None:
    label = "M3(same-key-retry)"
    _, tgt, cid = await hs.make_policies(tag)
    idem = f"m3-{tag}"
    mid = body_of(await hs.start(cid, tgt, idem))["migration_id"]
    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text
    simulate_restart()
    pb = await hs.prep("bob", mid)
    r = await hs.submit(pb)
    check(f"{label}: gap detected -> session failed",
          body_of(r).get("error", {}).get("code") == "THRESHOLD_NOT_MET"
          and (await hs.mig_row(mid))["status"] == "failed", r.text)

    # 同一幂等键安全重试：返回 201 新会话，而不是 200 重放 failed 行。
    r = await hs.start(cid, tgt, idem)
    m3 = body_of(r)
    check(f"{label}: same idempotency key retries as a fresh session (201)",
          r.status_code == 201 and m3.get("migration_id") != mid
          and m3.get("status") == "open", r.text)
    mid3 = m3["migration_id"]
    pa = await hs.prep("alice", mid3)
    pb = await hs.prep("bob", mid3)
    await hs.submit(pa)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: retried session completes exactly once",
          r.status_code == 200 and b.get("completed") and b.get("new_custody_id"), r.text)

    r = await hs.start(cid, tgt, idem)
    check(f"{label}: replay of the same key now returns the completed session",
          r.status_code == 200 and body_of(r).get("status") == "completed"
          and body_of(r).get("new_custody_id") == b.get("new_custody_id"), r.text)
    done = await hs.completed_migrations(cid)
    check(f"{label}: no duplicate new custody from same-key retry",
          done == 1, f"completed={done}")


async def scenario_m4(hs: Harness, board: FaultBoard, tag: str) -> None:
    label = "M4(lock-waiter)"
    _, tgt, cid = await hs.make_policies(tag)
    mid = body_of(await hs.start(cid, tgt, f"m4-{tag}"))["migration_id"]
    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text
    simulate_restart()
    pb = await hs.prep("bob", mid)
    pc = await hs.prep("carol", mid)

    # bob 的提交在“计数已达门限、即将重组”处 park（会话行锁仍持有）。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "migration.before_resplit"}
    bob_task = asyncio.create_task(hs.submit(pb, gate))
    await board.wait_reached(f"migration.before_resplit:{label}")

    # carol 的旧会话提交排队等待同一把行锁——绝不允许它在之后完成迁移。
    carol_task = asyncio.create_task(hs.submit(pc))
    queued = await wait_lock_waiters(hs.pool, 1)
    check(f"{label}: old-session submit waits on the row lock during fail-over",
          queued == 1, f"waiters={queued}")

    await board.release_gate(f"migration.before_resplit:{label}")
    rb = await bob_task
    check(f"{label}: detector gets THRESHOLD_NOT_MET and commits the failed state",
          rb.status_code == 409
          and body_of(rb).get("error", {}).get("code") == "THRESHOLD_NOT_MET",
          f"HTTP {rb.status_code}: {rb.text[:200]}")
    rc = await carol_task
    check(f"{label}: lock waiter can no longer complete -> MIGRATION_FAILED",
          rc.status_code == 409
          and body_of(rc).get("error", {}).get("code") == "MIGRATION_FAILED",
          f"HTTP {rc.status_code}: {rc.text[:200]}")
    row = await hs.mig_row(mid)
    check(f"{label}: waiter left no trace (count=1, carol nonce unspent, no new custody)",
          row["status"] == "failed" and row["subs"] == 1 and row["new_custody_id"] is None
          and await hs.nonce_spent(mid, "cus_demo_carol") is False, str(dict(row)))


async def scenario_m5(hs: Harness, tag: str) -> None:
    label = "M5(pool-eviction)"
    _, tgt, cid = await hs.make_policies(tag)
    mid = body_of(await hs.start(cid, tgt, f"m5-{tag}"))["migration_id"]
    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text

    # 内存池淘汰（sweep/容量逐出）只清该会话的待累计分片，效果同重启。
    app.state.pending.clear(mid)
    row = await hs.mig_row(mid)
    check(f"{label}: eviction dropped pending shares, db count kept",
          app.state.pending.count(mid) == 0 and row["subs"] == 1,
          f"mem={app.state.pending.count(mid)} subs={row['subs']}")
    pb = await hs.prep("bob", mid)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: eviction gap -> THRESHOLD_NOT_MET + failed terminal state",
          r.status_code == 409
          and b.get("error", {}).get("code") == "THRESHOLD_NOT_MET"
          and (await hs.mig_row(mid))["status"] == "failed",
          f"HTTP {r.status_code}: {r.text[:200]}")
    r = await hs.start(cid, tgt, f"m5b-{tag}")
    check(f"{label}: new key immediately re-starts after eviction failure",
          r.status_code == 201 and body_of(r).get("status") == "open", r.text)


async def scenario_m6(hs: Harness, tag: str) -> None:
    label = "M6(transient-fault-stays-open)"
    _, tgt, cid = await hs.make_policies(tag)
    mid = body_of(await hs.start(cid, tgt, f"m6-{tag}"))["migration_id"]
    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text
    pb = await hs.prep("bob", mid)
    # 入池后的瞬时失败（审计/连接类）：只回滚本次提交，会话保持 open，
    # 绝不得误判为缺片 failed 终态（v1.3 双重撤销边界语义不变）。
    gate = {"X-Fault-Key": label,
            "X-Fault-Fail": "migration.after_add:INTEGRITY_CHECK_FAILED"}
    r = await hs.submit(pb, gate)
    check(f"{label}: injected post-pool failure -> deterministic 4xx",
          r.status_code in (400, 409)
          and body_of(r).get("error", {}).get("code") == "INTEGRITY_CHECK_FAILED",
          f"HTTP {r.status_code}: {r.text[:200]}")
    row = await hs.mig_row(mid)
    check(f"{label}: transient failure keeps session open (not failed)",
          row["status"] == "open" and row["subs"] == 1
          and await hs.nonce_spent(mid, "cus_demo_bob") is False, str(dict(row)))
    check(f"{label}: committed pending share preserved in memory",
          app.state.pending.count(mid) == 1)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: clean retry completes the migration exactly once",
          r.status_code == 200 and b.get("completed") and b.get("new_custody_id"), r.text)
    check(f"{label}: pending pool drained after completion",
          app.state.pending.count(mid) == 0)


async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        suffix = os.urandom(4).hex()
        _, tgt1, cid1 = await scenario_m1(hs, f"{suffix}a")
        await scenario_m2(hs, f"{suffix}b", tgt1, cid1)
        await scenario_m3(hs, f"{suffix}c")
        await scenario_m4(hs, board, f"{suffix}d")
        await scenario_m5(hs, f"{suffix}e")
        await scenario_m6(hs, f"{suffix}f")

        r = await http.get("/audit/replay", headers=auth(hs.tenant_key))
        check("final: audit hash chain valid across all failure scenarios",
              r.json().get("valid") is True)

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} migration-failover checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("MIGRATION FAILOVER CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
