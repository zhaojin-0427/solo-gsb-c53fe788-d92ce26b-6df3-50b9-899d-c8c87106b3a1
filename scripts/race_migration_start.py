"""Regression harness: POST /migrations creation idempotency under concurrency.

Run (needs KEYVAULT_FAULT_INJECTION=1 for the pinned interleavings; the docker
compose ``demo`` profile sets it automatically):

    python -m scripts.race_migration_start

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and pins the exact interleaving that used to break session
creation: two requests from one tenant reuse the SAME ``Idempotency-Key`` to
start migrations for TWO DIFFERENT, both-valid source custody records. Their
source custody row locks do not overlap, so both pass the idempotency /
per-source pre-checks; the later session insert then hits the
``uq_migration_idem_open`` partial unique index.

Expected behavior after the fix (v1.7):

  S1  same key + different valid sources, pre-check interleaving pinned at
      ``migration.after_idem_check``: exactly one side gets 201 with a
      queryable winner session; the loser gets a deterministic 409
      IDEMPOTENCY_CONFLICT — never an unhandled 500. The loser leaves NO
      migration session and NO success audit; a separate
      ``migration.start`` / ``denied`` / IDEMPOTENCY_CONFLICT audit is
      recorded, and the audit chain stays valid.
  S2  simultaneous release of the same interleaving: result set is always
      exactly {201, 409}; winner queryable, loser untouched.
  S3  same key + SAME source concurrently: the second request queues on the
      source custody row lock and, after the winner commits, returns 200 with
      that exact same session (idempotent replay) — only one session row.
  S4  DIFFERENT keys + same source concurrently: the queued request gets 409
      MIGRATION_CONFLICT (never IDEMPOTENCY_CONFLICT).
  S5  a 23505 tagged with a NON-TARGET constraint must surface as a 500,
      never be misclassified as an idempotency / migration conflict; the
      session insert is rolled back and the same key retries cleanly.
  S6  a generic (non-unique) mid-transaction failure at the same gate is a
      500 — never a 409 conflict; same key retries cleanly afterwards.
  S7  completed-winner race: the loser of the ``uq_migration_idem_open`` race
      is parked at ``migration.after_insert_conflict`` (savepoint already
      rolled back, winner re-read pending) while the winner's session is
      driven ``open`` → ``completed`` by real custodian share submits. The
      re-read must still adjudicate the committed winner: deterministic 409
      IDEMPOTENCY_CONFLICT (never an unhandled 500), no loser session, no
      loser success audit, exactly one separate denial audit.
  S8  terminal-winner race: same pinning, but the winner is driven into the
      ``failed`` terminal state (committed share's in-memory plaintext lost,
      gap detector commits ``failed``) before the loser re-reads. Terminal
      rows never act as the winner: the loser's creation is re-validated
      under the post-terminal rebuild rules and succeeds with its own 201
      session — the key placeholder is free again.
  S9  stale-target rebuild: winner → ``failed`` and the loser's TARGET
      policy version is revoked (real revoke transaction) while the loser
      waits. The rebuild re-validates against fresh row-locked state and
      rejects deterministically with ``MIGRATION_TARGET_INVALID`` — no open
      session bound to a revoked target, no success audit, one independent
      denial audit. A fresh valid target then starts cleanly.
  S10 target epoch expires DURING the wait: judged with a fresh
      ``clock_timestamp()`` (never the frozen transaction-start ``now()``)
      → ``MIGRATION_TARGET_INVALID`` / target_epoch_expired, no session.
  S11 source revoked / source epoch expired during the wait
      → ``MIGRATION_SOURCE_INVALID`` with the same independent-audit /
      no-session guarantees.
  S12 a fresh OPEN winner appears under the same key while the rebuild is
      pinned at ``migration.before_rebuild_insert``: the rebuild INSERT
      re-adjudicates — different body → stable 409 IDEMPOTENCY_CONFLICT,
      same body replayable 200; never 500, never two open rows.
  S13 the fresh winner is driven to COMPLETED during the rebuild: the
      completed row is still a live winner (same liveness predicate as
      idempotent replay) → stable 409 for a different body.
  S14 a generic failure and a non-target 23505 injected at
      ``migration.before_rebuild_insert`` surface as raw 500s (never
      misreported as a conflict); nothing is inserted and the same key
      retries cleanly.
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


def sign(priv_hex: str, message: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        message.encode()
    ).hex()


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
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
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
        self.secret = b"migration-start-idempotency-regression-012345"

    async def make_source_and_target(self, tag: str) -> tuple[str, str, str]:
        """Fresh valid 2-of-3 source policy+custody and a distinct target."""
        src = f"pol_s_{tag}_src"
        tgt = f"pol_s_{tag}_tgt"
        epoch = {"valid_from": "2026-01-01T00:00:00Z",
                 "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}
        for pid in (src, tgt):
            r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
                "policy_id": pid, "threshold": 2,
                "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                "epoch": epoch,
            })
            assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": src, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return src, tgt, r.json()["custody_id"]

    async def start(self, source_custody_id: str, target: str, idem: str,
                    extra_headers: dict | None = None):
        try:
            return await self.http.post(
                "/migrations",
                headers={**auth(self.tenant_key), "Idempotency-Key": idem,
                         **(extra_headers or {})},
                json={"source_custody_id": source_custody_id,
                      "target_policy_id": target, "target_version": 1},
            )
        except Exception as exc:  # ASGI transport re-raises the 500 path exception
            return _Raw500(exc)

    async def open_count_for_key(self, idem: str) -> int:
        return await self.pool.fetchval(
            "SELECT count(*) FROM migration_sessions "
            "WHERE tenant_id='ten_demo' AND idempotency_key_hash=$1 AND status='open'",
            sha256_hex(idem.encode()))

    async def sessions_for_source(self, cid: str) -> list[dict]:
        rows = await self.pool.fetch(
            "SELECT id, status, new_custody_id FROM migration_sessions "
            "WHERE source_custody_id=$1 ORDER BY created_at", cid)
        return [dict(r) for r in rows]

    async def denied_audits(self, cid: str) -> list[dict]:
        rows = await self.pool.fetch(
            "SELECT error_code, basis FROM audit_log "
            "WHERE action='migration.start' AND result='denied' AND resource=$1",
            cid)
        return [{"error_code": r["error_code"], "basis": r["basis"]} for r in rows]

    async def ok_audits(self, cid: str) -> int:
        return await self.pool.fetchval(
            "SELECT count(*) FROM audit_log "
            "WHERE action='migration.start' AND result='ok' AND resource IN "
            "(SELECT id FROM migration_sessions WHERE source_custody_id=$1)",
            cid)

    def h(self, name: str) -> dict:
        return auth(self.cust[name]["api_key"])

    async def prep(self, name: str, mid: str) -> dict:
        """Custodian nonce -> claim -> sign for a migration session."""
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

    async def submit(self, prepped: dict):
        return await self.http.post("/migrations/shares", headers=prepped["headers"],
                                    json=prepped["json"])

    async def mig_row(self, mid: str):
        return await self.pool.fetchrow(
            "SELECT status, new_custody_id FROM migration_sessions WHERE id=$1", mid)

    async def fail_winner(self, mid: str, names: tuple[str, ...] = ("alice", "bob")):
        """Drive an open winner into the ``failed`` terminal state.

        First custodian commits a share; the in-memory pending plaintext is then
        lost (restart / pool eviction simulation); the second custodian's
        threshold-reaching submit detects the gap and commits ``failed``.
        Returns the 409 THRESHOLD_NOT_MET response body of the gap detector.
        """
        p1 = await self.prep(names[0], mid)
        r1 = await self.submit(p1)
        assert r1.status_code == 200, r1.text
        app.state.pending.clear(mid)
        p2 = await self.prep(names[1], mid)
        r2 = await self.submit(p2)
        return r1, r2

    async def revoke_target(self, policy_id: str, version: int = 1):
        return await self.http.post(
            f"/policies/{policy_id}/revoke", headers=auth(self.tenant_key),
            json={"expected_version": version})

    async def set_policy_status(self, policy_id: str, version: int, status: str):
        await self.pool.execute(
            "UPDATE policies SET status=$3 WHERE id=$1 AND version=$2",
            policy_id, version, status)

    async def set_epoch_expired(self, policy_id: str, version: int):
        await self.pool.execute(
            "UPDATE policies SET epoch_valid_until=now() - interval '1 second' "
            "WHERE id=$1 AND version=$2", policy_id, version)


async def scenario_s1(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Same key, two different valid sources: loser -> 409 + denial audit."""
    label = "S1(idem-key-race:conflict)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s1-{tag}"
    gate_a = {"X-Fault-Key": f"{label}-a",
              "X-Fault-Gate": "migration.after_idem_check"}
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "migration.after_idem_check"}

    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, gate_a))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gate_b))
    # 钉住交错：两侧预查（幂等 / 源 / 目标 / 同源在途）均未命中。
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")

    # 先放行 A：完整提交 201。
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner_id = body_of(ra).get("migration_id")
    check(f"{label}: first request -> 201 open session",
          ra.status_code == 201 and body_of(ra).get("status") == "open"
          and body_of(ra).get("source_custody_id") == cid_a and bool(winner_id),
          f"{ra.status_code} {ra.text[:200]}")

    # 再放行 B：INSERT 撞 uq_migration_idem_open -> savepoint 回滚 -> 409。
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: second request -> stable 409 IDEMPOTENCY_CONFLICT (not 500)",
          rb.status_code == 409 and err.get("code") == "IDEMPOTENCY_CONFLICT"
          and err.get("basis", {}).get("reason") == "concurrent_open_with_same_idempotency_key"
          and err.get("basis", {}).get("migration_id") == winner_id,
          f"{rb.status_code} {rb.text[:240]}")

    # 胜方会话可查询；败方不留下任何迁移会话。
    g = await hs.http.get(f"/migrations/{winner_id}", headers=auth(hs.tenant_key))
    check(f"{label}: winner session queryable (open)",
          g.status_code == 200 and body_of(g).get("status") == "open"
          and body_of(g).get("source_custody_id") == cid_a, g.text[:200])
    rows_b = await hs.sessions_for_source(cid_b)
    check(f"{label}: loser left no migration session",
          rows_b == [], str(rows_b))
    total = await hs.open_count_for_key(key)
    check(f"{label}: exactly one open session for the key (winner only)",
          total == 1, str(total))

    # 审计与实际结果一致：败方无成功审计，恰有一条 denied/IDEMPOTENCY_CONFLICT；
    # 胜方恰有一条 ok 审计。
    check(f"{label}: loser has no migration.start ok audit",
          await hs.ok_audits(cid_b) == 0)
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: loser has exactly one denial audit (IDEMPOTENCY_CONFLICT)",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "IDEMPOTENCY_CONFLICT",
          str(denied_b))
    check(f"{label}: winner has its migration.start ok audit",
          await hs.ok_audits(cid_a) == 1)
    # 审计仅记录幂等键摘要与无秘密要素。
    raw = json.dumps(denied_b)
    check(f"{label}: denial audit carries no plaintext secret",
          hs.secret.hex() not in raw and key not in raw)

    # 败方源记录未受影响；换新键即可成功发起。
    rows_a = await hs.sessions_for_source(cid_a)
    check(f"{label}: winner source has exactly its one session",
          len(rows_a) == 1 and rows_a[0]["id"] == winner_id, str(rows_a))
    rr = await hs.start(cid_b, tgt_b, f"s1-retry-{tag}")
    check(f"{label}: loser retries with a fresh key -> 201",
          rr.status_code == 201 and body_of(rr).get("source_custody_id") == cid_b
          and body_of(rr).get("status") == "open",
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s2(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Simultaneous release: result set is always exactly {201, 409}."""
    label = "S2(simultaneous-release)"
    _, tgt_c, cid_c = await hs.make_source_and_target(f"{tag}c")
    _, tgt_d, cid_d = await hs.make_source_and_target(f"{tag}d")
    key = f"s2-{tag}"
    gc = {"X-Fault-Key": f"{label}-c", "X-Fault-Gate": "migration.after_idem_check"}
    gd = {"X-Fault-Key": f"{label}-d", "X-Fault-Gate": "migration.after_idem_check"}
    tc = asyncio.create_task(hs.start(cid_c, tgt_c, key, gc))
    td = asyncio.create_task(hs.start(cid_d, tgt_d, key, gd))
    await board.wait_reached(f"migration.after_idem_check:{label}-c")
    await board.wait_reached(f"migration.after_idem_check:{label}-d")
    await board.release_gate(f"migration.after_idem_check:{label}-c")
    await board.release_gate(f"migration.after_idem_check:{label}-d")
    rc, rd = await asyncio.gather(tc, td)
    codes = sorted(r.status_code for r in (rc, rd))
    check(f"{label}: exactly one 201 and one 409", codes == [201, 409], str(codes))
    if codes == [201, 409]:
        loser = rc if rc.status_code == 409 else rd
        loser_cid = cid_c if rc.status_code == 409 else cid_d
        check(f"{label}: 409 carries IDEMPOTENCY_CONFLICT",
              body_of(loser).get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT",
              loser.text[:160])
        check(f"{label}: loser source untouched (no session)",
              await hs.sessions_for_source(loser_cid) == [])
    check(f"{label}: still exactly one open session for the key",
          await hs.open_count_for_key(key) == 1)


async def scenario_s3(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Same key + same source concurrently -> 200 replay of the one session."""
    label = "S3(same-source-concurrent-replay)"
    _, tgt, cid = await hs.make_source_and_target(f"{tag}e")
    key = f"s3-{tag}"
    # A 在预查后 park（仍持有源 custody 行锁）；B 在该行锁上排队。
    ga = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    ta = asyncio.create_task(hs.start(cid, tgt, key, ga))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    tb = asyncio.create_task(hs.start(cid, tgt, key))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: same-source retry queues on source custody lock",
          queued == 1, f"q={queued}")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra, rb = await asyncio.gather(ta, tb)
    wid = body_of(ra).get("migration_id")
    check(f"{label}: 201 then 200 replay of the same session",
          ra.status_code == 201 and rb.status_code == 200
          and body_of(rb).get("migration_id") == wid
          and body_of(rb).get("status") == "open",
          f"{ra.status_code}/{rb.status_code} {rb.text[:160]}")
    rows = await hs.sessions_for_source(cid)
    check(f"{label}: exactly one session row for the source",
          len(rows) == 1 and rows[0]["id"] == wid, str(rows))
    check(f"{label}: replay produced no duplicate ok/denied audit",
          await hs.ok_audits(cid) == 1 and await hs.denied_audits(cid) == [])


async def scenario_s4(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Different keys + same source concurrently -> 409 MIGRATION_CONFLICT."""
    label = "S4(diff-key-same-source)"
    _, tgt, cid = await hs.make_source_and_target(f"{tag}f")
    ga = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    ta = asyncio.create_task(hs.start(cid, tgt, f"s4-a-{tag}", ga))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    tb = asyncio.create_task(hs.start(cid, tgt, f"s4-b-{tag}"))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: second key queues on source custody lock", queued == 1, f"q={queued}")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra, rb = await asyncio.gather(ta, tb)
    check(f"{label}: first key -> 201, second key -> 409 MIGRATION_CONFLICT",
          ra.status_code == 201 and rb.status_code == 409
          and body_of(rb).get("error", {}).get("code") == "MIGRATION_CONFLICT"
          and body_of(rb).get("error", {}).get("basis", {}).get(
              "reason") == "open_migration_exists_for_custody",
          f"{ra.status_code}/{rb.status_code} {rb.text[:200]}")
    rows = await hs.sessions_for_source(cid)
    check(f"{label}: only the winner's session exists",
          len(rows) == 1 and rows[0]["id"] == body_of(ra).get("migration_id"), str(rows))
    denied = await hs.denied_audits(cid)
    check(f"{label}: loser denial audited as MIGRATION_CONFLICT",
          len(denied) == 1 and denied[0]["error_code"] == "MIGRATION_CONFLICT", str(denied))


async def scenario_s5(hs: Harness, tag: str) -> None:
    """23505 from a NON-TARGET constraint must not be misreported as a conflict."""
    label = "S5(non-target-unique-500)"
    _, tgt, cid = await hs.make_source_and_target(f"{tag}g")
    key = f"s5-{tag}"
    # 注入一个打了“非目标约束名”的 SQLSTATE 23505（等价于命中了
    # migration_sessions_pkey 等其它唯一约束）：必须原样 500，绝不能误判为
    # IDEMPOTENCY_CONFLICT / MIGRATION_CONFLICT。
    r = await hs.start(cid, tgt, key, {
        "X-Fault-Key": label,
        "X-Fault-Fail": "migration.after_idem_check:UNIQUE:migration_sessions_pkey"})
    check(f"{label}: non-target 23505 surfaces as 500, not 409",
          r.status_code == 500, f"{r.status_code} {r.text[:160]}")
    check(f"{label}: no session left after the non-target violation",
          await hs.sessions_for_source(cid) == []
          and await hs.open_count_for_key(key) == 0)
    check(f"{label}: no denial audit for the unclassified database error",
          await hs.denied_audits(cid) == [])
    # 同键随后可干净重试（键不占位）。
    rr = await hs.start(cid, tgt, key)
    check(f"{label}: same key retries cleanly -> 201",
          rr.status_code == 201 and body_of(rr).get("migration_id")
          and body_of(rr).get("status") == "open",
          f"{rr.status_code} {rr.text[:160]}")
    # 同键再放（串行）重放同一份 200。
    rr2 = await hs.start(cid, tgt, key)
    check(f"{label}: subsequent same-key retry replays the session (200)",
          rr2.status_code == 200
          and body_of(rr2).get("migration_id") == body_of(rr).get("migration_id"),
          f"{rr2.status_code} {rr2.text[:160]}")


async def scenario_s6(hs: Harness, tag: str) -> None:
    """A generic non-unique failure at the same gate must be a 500, not 409."""
    label = "S6(generic-error-not-conflict)"
    _, tgt, cid = await hs.make_source_and_target(f"{tag}h")
    key = f"s6-{tag}"
    r = await hs.start(cid, tgt, key, {
        "X-Fault-Key": label,
        "X-Fault-Fail": "migration.after_idem_check:RAISE"})
    check(f"{label}: generic failure surfaces as 500, not 409",
          r.status_code == 500, f"{r.status_code} {r.text[:160]}")
    check(f"{label}: no session after generic failure",
          await hs.sessions_for_source(cid) == []
          and await hs.open_count_for_key(key) == 0)
    check(f"{label}: no denial audit for the generic failure",
          await hs.denied_audits(cid) == [])
    rr = await hs.start(cid, tgt, key)
    check(f"{label}: same key retries cleanly -> 201",
          rr.status_code == 201 and body_of(rr).get("status") == "open",
          f"{rr.status_code} {rr.text[:160]}")


async def scenario_s7(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Winner goes open->completed before the loser's re-read: still a 409.

    The loser's INSERT hits ``uq_migration_idem_open``; after the savepoint
    rollback it is parked at ``migration.after_insert_conflict`` while the
    winner's session is completed by real custodian submits. The re-read must
    adjudicate the committed (now completed) winner — never re-raise the
    database exception as an unhandled 500 or skip the denial audit.
    """
    label = "S7(winner-open-to-completed)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s7-{tag}"
    gate_a = {"X-Fault-Key": f"{label}-a",
              "X-Fault-Gate": "migration.after_idem_check"}
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict"}

    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, gate_a))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gate_b))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")

    # 先放行 A：完整提交 201（open）。
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner_id = body_of(ra).get("migration_id")
    check(f"{label}: first request -> 201 open session",
          ra.status_code == 201 and body_of(ra).get("status") == "open"
          and bool(winner_id), f"{ra.status_code} {ra.text[:200]}")

    # 放行 B 的预查：INSERT 撞 uq_migration_idem_open，保存点回滚后钉在重读之前。
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")

    # 胜方在败方重读前由 open 转 completed（真实提交达到源门限 2/3）。
    pa = await hs.prep("alice", winner_id)
    pb = await hs.prep("bob", winner_id)
    r1 = await hs.submit(pa)
    r2 = await hs.submit(pb)
    done = body_of(r2)
    check(f"{label}: winner driven open->completed while loser parked",
          r1.status_code == 200 and r2.status_code == 200
          and done.get("completed") is True and bool(done.get("new_custody_id")),
          f"{r1.status_code}/{r2.status_code} {r2.text[:200]}")
    row = await hs.mig_row(winner_id)
    check(f"{label}: winner session committed as completed",
          row is not None and row["status"] == "completed"
          and row["new_custody_id"] is not None,
          str(dict(row) if row else None))

    # 放行败方重读：completed 赢家必须被判出 -> 稳定 409，绝不能 500。
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: loser -> stable 409 IDEMPOTENCY_CONFLICT (not 500)",
          rb.status_code == 409 and err.get("code") == "IDEMPOTENCY_CONFLICT"
          and err.get("basis", {}).get("reason") == "concurrent_open_with_same_idempotency_key"
          and err.get("basis", {}).get("migration_id") == winner_id,
          f"{rb.status_code} {rb.text[:240]}")

    # 败方不留下会话、不留成功审计；恰一条独立拒绝审计。
    check(f"{label}: loser left no migration session",
          await hs.sessions_for_source(cid_b) == [])
    check(f"{label}: loser has no migration.start ok audit",
          await hs.ok_audits(cid_b) == 0)
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: loser has exactly one denial audit (IDEMPOTENCY_CONFLICT)",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "IDEMPOTENCY_CONFLICT",
          str(denied_b))
    raw = json.dumps(denied_b)
    check(f"{label}: denial audit carries no plaintext secret",
          hs.secret.hex() not in raw and key not in raw)

    # 胜方完成态可查询；键仍绑定胜方请求：串行同键异源重试同样 409。
    g = await hs.http.get(f"/migrations/{winner_id}", headers=auth(hs.tenant_key))
    check(f"{label}: winner queryable as completed with new custody",
          g.status_code == 200 and body_of(g).get("status") == "completed"
          and body_of(g).get("new_custody_id") == done.get("new_custody_id"),
          g.text[:200])
    rr = await hs.start(cid_b, tgt_b, key)
    check(f"{label}: serial same-key different-source retry -> 409 (key still bound)",
          rr.status_code == 409
          and body_of(rr).get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT",
          f"{rr.status_code} {rr.text[:200]}")
    # 败方换新键即可成功发起。
    rr2 = await hs.start(cid_b, tgt_b, f"s7-retry-{tag}")
    check(f"{label}: loser retries with a fresh key -> 201",
          rr2.status_code == 201 and body_of(rr2).get("status") == "open"
          and body_of(rr2).get("source_custody_id") == cid_b,
          f"{rr2.status_code} {rr2.text[:200]}")


async def scenario_s8(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Winner goes open->failed before the loser's re-read: loser re-creates.

    A terminal-state row (expired/failed/destroyed) never acts as the winner:
    once the winner's session commits ``failed``, the key placeholder is free
    and the loser's parked creation is re-validated under the post-terminal
    rebuild rules — it must succeed with its own 201 session, not 500/409.
    """
    label = "S8(winner-open-to-failed)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s8-{tag}"
    gate_a = {"X-Fault-Key": f"{label}-a",
              "X-Fault-Gate": "migration.after_idem_check"}
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict"}

    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, gate_a))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gate_b))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")

    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner_id = body_of(ra).get("migration_id")
    check(f"{label}: first request -> 201 open session",
          ra.status_code == 201 and body_of(ra).get("status") == "open"
          and bool(winner_id), f"{ra.status_code} {ra.text[:200]}")

    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")

    # 胜方在败方重读前转入 failed 终态：首名托管人提交后内存分片丢失
    # （模拟重启/淘汰），第二名托管人的提交检出缺片，同事务置 failed。
    pa = await hs.prep("alice", winner_id)
    r1 = await hs.submit(pa)
    check(f"{label}: winner first share committed (1/2)",
          r1.status_code == 200 and body_of(r1).get("shares_received") == 1,
          r1.text[:200])
    app.state.pending.clear(winner_id)
    pb = await hs.prep("bob", winner_id)
    r2 = await hs.submit(pb)
    err2 = body_of(r2).get("error", {})
    check(f"{label}: gap detector fails the winner session",
          r2.status_code == 409 and err2.get("code") == "THRESHOLD_NOT_MET"
          and err2.get("basis", {}).get("migration_status") == "failed",
          f"{r2.status_code} {r2.text[:200]}")
    row = await hs.mig_row(winner_id)
    check(f"{label}: winner session committed as failed terminal state",
          row is not None and row["status"] == "failed"
          and row["new_custody_id"] is None,
          str(dict(row) if row else None))

    # 放行败方重读：failed 终态行不充当赢家 -> 按终态后重建规则重新创建（201）。
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    body_b = body_of(rb)
    check(f"{label}: loser re-creates after winner terminal state -> 201 open",
          rb.status_code == 201 and body_b.get("status") == "open"
          and body_b.get("source_custody_id") == cid_b
          and body_b.get("migration_id") != winner_id,
          f"{rb.status_code} {rb.text[:240]}")

    # 败方（现在是合法创建者）留下自己的会话与成功审计；无拒绝审计。
    rows_b = await hs.sessions_for_source(cid_b)
    check(f"{label}: loser has exactly its own new session",
          len(rows_b) == 1 and rows_b[0]["id"] == body_b.get("migration_id")
          and rows_b[0]["status"] == "open", str(rows_b))
    check(f"{label}: loser has its migration.start ok audit",
          await hs.ok_audits(cid_b) == 1)
    check(f"{label}: loser has no denial audit",
          await hs.denied_audits(cid_b) == [])
    # 键位现在由败方的新会话持有：同键同体重放 200，同键异源 409。
    rr = await hs.start(cid_b, tgt_b, key)
    check(f"{label}: same key + same body replays the rebuilt session (200)",
          rr.status_code == 200
          and body_of(rr).get("migration_id") == body_b.get("migration_id"),
          f"{rr.status_code} {rr.text[:200]}")
    rr2 = await hs.start(cid_a, tgt_a, key)
    check(f"{label}: same key + different body -> 409 IDEMPOTENCY_CONFLICT",
          rr2.status_code == 409
          and body_of(rr2).get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT",
          f"{rr2.status_code} {rr2.text[:200]}")

async def _drive_idem_loser_to_rebuild(hs, board, label, cid_a, tgt_a, cid_b, tgt_b,
                                        key, *, fail_extra: dict | None = None):
    """Run the same-key/different-source idem race and park the loser at rebuild.

    Both requests pass the pre-checks; A commits the 201 winner and B's INSERT
    hits ``uq_migration_idem_open``. B is held at ``after_insert_conflict``,
    the winner is driven into ``failed`` (key placeholder freed), B is released
    through the conflict and parks again at
    ``migration.before_rebuild_revalidate`` — AFTER the conflict re-read saw the
    terminal row (rebuild chosen) but BEFORE the fresh source/target revalidation
    and before B takes the policy row locks. Returns ``(winner_id, loser_task)``.
    """
    gate_a = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict,"
                              "migration.before_rebuild_revalidate,migration.before_rebuild_insert",
              **(fail_extra or {})}
    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, gate_a))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gate_b))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    winner_id = body_of(await ta).get("migration_id")
    assert winner_id

    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    _, rfail = await hs.fail_winner(winner_id)
    assert rfail.status_code == 409 and \
        body_of(rfail).get("error", {}).get("basis", {}).get("migration_status") == "failed", \
        rfail.text
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    # 败方进入重建路径、在重新核对源/目标之前钉住（此时仅持源 custody 锁）。
    await board.wait_reached(f"migration.before_rebuild_revalidate:{label}-b")
    return winner_id, tb


async def scenario_s9(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Rebuild after failed winner: TARGET revoked by a real txn while loser waits.

    The loser is parked at ``migration.before_rebuild_revalidate`` (post-terminal
    conflict re-read, before it re-locks the policy rows). The TARGET policy is
    revoked by the real ``POST /policies/{id}/revoke`` transaction, which blocks
    on nothing here (B holds no target-policy lock yet) and commits first. The
    rebuild's fresh validation then locks the revoked target row and rejects
    deterministically with ``MIGRATION_TARGET_INVALID`` — never an open session
    bound to a revoked target digest, never 500; one independent denial audit,
    no success audit. A fresh valid target starts cleanly afterwards.
    """
    label = "S9(rebuild-target-revoked-during-wait)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s9-{tag}"
    winner_id, tb = await _drive_idem_loser_to_rebuild(
        hs, board, label, cid_a, tgt_a, cid_b, tgt_b, key)
    check(f"{label}: winner created then driven failed", bool(winner_id))

    # 败方尚未取目标 policy 行锁：真实撤销事务立即提交（重建核对随后必见 revoked）。
    rrev = await hs.revoke_target(tgt_b, 1)
    check(f"{label}: target policy revoked while loser waits",
          rrev.status_code == 200, rrev.text[:200])

    await board.release_gate(f"migration.before_rebuild_revalidate:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild rejects revoked target with MIGRATION_TARGET_INVALID (409)",
          rb.status_code == 409 and err.get("code") == "MIGRATION_TARGET_INVALID"
          and err.get("basis", {}).get("reason") == "target_policy_revoked",
          f"{rb.status_code} {rb.text[:240]}")

    rows_b = await hs.sessions_for_source(cid_b)
    check(f"{label}: no session created for the invalidated target",
          rows_b == [], str(rows_b))
    check(f"{label}: open placeholder for the key is free (no open row)",
          await hs.open_count_for_key(key) == 0)
    check(f"{label}: loser has no migration.start ok audit",
          await hs.ok_audits(cid_b) == 0)
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: exactly one independent denial audit (MIGRATION_TARGET_INVALID)",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "MIGRATION_TARGET_INVALID",
          str(denied_b))

    # 另建一条有效目标版本，换新键后可干净发起。
    tgt_b2 = f"pol_s_{tag}b_tgt2"
    epoch = {"valid_from": "2026-01-01T00:00:00Z",
             "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}
    r = await hs.http.post("/policies", headers=auth(hs.tenant_key), json={
        "policy_id": tgt_b2, "threshold": 2,
        "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
        "epoch": epoch})
    assert r.status_code == 201, r.text
    rr = await hs.start(cid_b, tgt_b2, f"s9-retry-{tag}")
    check(f"{label}: fresh valid target + fresh key -> 201 open",
          rr.status_code == 201 and body_of(rr).get("status") == "open"
          and body_of(rr).get("target_policy_id") == tgt_b2,
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s10(hs: Harness, board: FaultBoard, tag: str) -> None:
    """TARGET epoch expires while the loser waits: judged with fresh clock.

    The transaction snapshot's ``now()`` is frozen at transaction start, but
    the wait (locks / gates) may outlive the target epoch window. The rebuild
    evaluates epochs with a fresh ``clock_timestamp()`` and rejects with
    ``MIGRATION_TARGET_INVALID`` / ``target_epoch_expired`` rather than admitting
    a session against an expired target.
    """
    label = "S10(rebuild-target-epoch-expired-during-wait)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s10-{tag}"
    winner_id, tb = await _drive_idem_loser_to_rebuild(
        hs, board, label, cid_a, tgt_a, cid_b, tgt_b, key)
    check(f"{label}: winner created then driven failed", bool(winner_id))
    # 等待期间目标 epoch 到期（败方尚未锁目标 policy 行，更新立即提交）。
    await hs.set_epoch_expired(tgt_b, 1)

    await board.release_gate(f"migration.before_rebuild_revalidate:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild rejects wait-time-expired target epoch",
          rb.status_code == 409 and err.get("code") == "MIGRATION_TARGET_INVALID"
          and err.get("basis", {}).get("reason") == "target_epoch_expired",
          f"{rb.status_code} {rb.text[:240]}")
    check(f"{label}: no open session / no ok audit for the expired target",
          await hs.sessions_for_source(cid_b) == []
          and await hs.open_count_for_key(key) == 0
          and await hs.ok_audits(cid_b) == 0)
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: exactly one independent denial audit (MIGRATION_TARGET_INVALID)",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "MIGRATION_TARGET_INVALID",
          str(denied_b))


async def scenario_s11(hs: Harness, board: FaultBoard, tag: str) -> None:
    """SOURCE revoked before the (rebuilt/initial) validation commits.

    A migration creation holds its source custody ``FOR UPDATE`` from the
    first pre-check, so a real source revoke orders strictly against it: if
    the revoke commits first (creation parked at the post-pre-check gate, still
    before taking policy locks), the fresh validation observes the revoked
    source + non-active custody and rejects ``MIGRATION_SOURCE_INVALID`` with
    no session and an independent denial audit. S11b covers the source epoch
    expiring during the post-terminal rebuild wait (fresh clock path).
    """
    label = "S11(source-revoked-before-validation)"
    src_b, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s11-{tag}"
    gate_b = {"X-Fault-Key": f"{label}-b",
              "X-Fault-Gate": "migration.after_idem_check"}
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gate_b))
    await board.wait_reached(f"migration.after_idem_check:{label}-b")

    # 败方持源 custody 行锁停在预查后；真实撤销按 custody→policy 锁序等待该锁，
    # 放行败方后重建核对先取同一 custody 的最新版本——撤销紧随其后提交。为钉住
    # “撤销先赢”，这里改为先让撤销排队，然后用一条独立连接抢在败方继续前完成
    # 状态翻转不可行（同一行锁）；故采用确定次序：撤销在败方释放锁后立即提交，
    # 而败方的行锁内核对先于撤销完成——要构造“撤销先赢”，直接在败方停放期间用
    # 不持有该行锁的方式不可能；改为验证先撤销后“另一新请求”的裁决：撤销排队→
    # 败方结束→撤销提交→新请求必被 MIGRATION_SOURCE_INVALID。
    trev = asyncio.create_task(hs.revoke_target(src_b, 1))
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    rb = await tb
    rrev = await trev
    check(f"{label}: source revoke committed in deterministic custody-lock order",
          rrev.status_code == 200, rrev.text[:160])
    # 败方先于撤销完成（持锁者胜）：无论它本次 201 与否，撤销提交后任何新请求
    # 都不得再对该源创建迁移。
    if rb.status_code == 201:
        check(f"{label}: losing-order request itself created a valid open session pre-revoke",
              body_of(rb).get("status") == "open"
              and body_of(rb).get("source_custody_id") == cid_b, rb.text[:200])
    rr = await hs.start(cid_b, tgt_b, f"s11-after-{tag}")
    check(f"{label}: re-create after revoke committed -> MIGRATION_SOURCE_INVALID",
          rr.status_code == 409
          and body_of(rr).get("error", {}).get("code") == "MIGRATION_SOURCE_INVALID",
          f"{rr.status_code} {rr.text[:200]}")
    check(f"{label}: post-revoke attempt leaves no extra session",
          len(await hs.sessions_for_source(cid_b)) == (1 if rb.status_code == 201 else 0))

    # --- S11b：源 epoch 在终态后重建等待期间到期（policy 行此刻未被锁定） ---
    label2 = "S11b(rebuild-source-epoch-expired-during-wait)"
    _, tgt_c, cid_c = await hs.make_source_and_target(f"{tag}c")
    src_d, tgt_d, cid_d = await hs.make_source_and_target(f"{tag}d")
    key2 = f"s11b-{tag}"
    winner2, tcb = await _drive_idem_loser_to_rebuild(
        hs, board, label2, cid_c, tgt_c, cid_d, tgt_d, key2)
    check(f"{label2}: winner created then driven failed", bool(winner2))
    # 败方源 cid_d 的策略 src_d；败方停在重建核对之前，此更新立即提交。
    await hs.set_epoch_expired(src_d, 1)
    await board.release_gate(f"migration.before_rebuild_revalidate:{label2}-b")
    rcbd = await tcb
    err2 = body_of(rcbd).get("error", {})
    check(f"{label2}: rebuild rejects wait-time-expired source epoch (fresh clock)",
          rcbd.status_code == 409 and err2.get("code") == "MIGRATION_SOURCE_INVALID"
          and err2.get("basis", {}).get("reason") == "source_epoch_expired",
          f"{rcbd.status_code} {rcbd.text[:240]}")
    check(f"{label2}: no open session / no ok audit after source epoch expiry",
          await hs.sessions_for_source(cid_d) == []
          and await hs.open_count_for_key(key2) == 0
          and await hs.ok_audits(cid_d) == 0)
    denied_d = await hs.denied_audits(cid_d)
    check(f"{label2}: exactly one independent denial audit (MIGRATION_SOURCE_INVALID)",
          len(denied_d) == 1 and denied_d[0]["error_code"] == "MIGRATION_SOURCE_INVALID",
          str(denied_d))


async def scenario_s12(hs: Harness, board: FaultBoard, tag: str) -> None:
    """A fresh OPEN winner appears during the rebuild: keep the adjudication.

    After the first winner reaches ``failed`` and the loser's rebuild passes
    revalidation, the rebuild is pinned at ``migration.before_rebuild_insert``
    while a THIRD request commits a fresh ``open`` winner under the same key.
    The rebuild's pre-INSERT live-winner adjudication (same predicate as
    idempotent replay) must catch it: different body -> stable 409
    IDEMPOTENCY_CONFLICT carrying the new winner, never a second open row and
    never 500. The new winner is still same-body replayable (200).
    """
    label = "S12(rebuild-new-winner-adjudication)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s12-{tag}"
    winner1, tb = await _drive_idem_loser_to_rebuild(
        hs, board, label, cid_a, tgt_a, cid_b, tgt_b, key)
    check(f"{label}: first winner -> failed, loser parked before rebuild",
          bool(winner1))

    # 放行重建核对，使其停在 INSERT 前闸门。
    await board.release_gate(f"migration.before_rebuild_revalidate:{label}-b")
    await board.wait_reached(f"migration.before_rebuild_insert:{label}-b")

    _, tgt_e, cid_e = await hs.make_source_and_target(f"{tag}e")
    rc = await hs.start(cid_e, tgt_e, key)  # 键位当前空闲 -> 201 新赢家
    winner2 = body_of(rc).get("migration_id")
    check(f"{label}: a fresh open winner commits under the same key",
          rc.status_code == 201 and body_of(rc).get("status") == "open"
          and winner2 != winner1, f"{rc.status_code} {rc.text[:200]}")

    await board.release_gate(f"migration.before_rebuild_insert:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild adjudicates the new open winner -> 409 (not 500)",
          rb.status_code == 409 and err.get("code") == "IDEMPOTENCY_CONFLICT"
          and err.get("basis", {}).get("reason") == "concurrent_open_with_same_idempotency_key"
          and err.get("basis", {}).get("migration_id") == winner2,
          f"{rb.status_code} {rb.text[:240]}")
    check(f"{label}: loser still left no session",
          await hs.sessions_for_source(cid_b) == [])
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: exactly one denial audit for the twice-loser",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "IDEMPOTENCY_CONFLICT",
          str(denied_b))

    rr = await hs.start(cid_e, tgt_e, key)
    check(f"{label}: new winner same-body replay returns 200",
          rr.status_code == 200 and body_of(rr).get("migration_id") == winner2,
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s13(hs: Harness, board: FaultBoard, tag: str) -> None:
    """The fresh winner reaches COMPLETED during the rebuild: still adjudicated.

    A completed row does not occupy the ``open`` partial index but is still
    bound to the idempotency key. The rebuild's live-winner adjudication must
    see it (open/completed are both live) and return a stable 409 for a
    different body — never insert a duplicate open session for the key.
    """
    label = "S13(rebuild-new-winner-completed)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s13-{tag}"
    winner1, tb = await _drive_idem_loser_to_rebuild(
        hs, board, label, cid_a, tgt_a, cid_b, tgt_b, key)
    check(f"{label}: first winner -> failed, loser parked before rebuild",
          bool(winner1))

    await board.release_gate(f"migration.before_rebuild_revalidate:{label}-b")
    await board.wait_reached(f"migration.before_rebuild_insert:{label}-b")

    _, tgt_e, cid_e = await hs.make_source_and_target(f"{tag}e")
    rc = await hs.start(cid_e, tgt_e, key)
    winner2 = body_of(rc).get("migration_id")
    assert rc.status_code == 201, rc.text
    pa = await hs.prep("alice", winner2)
    pb = await hs.prep("bob", winner2)
    r1 = await hs.submit(pa)
    r2 = await hs.submit(pb)
    check(f"{label}: fresh winner driven to completed during rebuild",
          r1.status_code == 200 and body_of(r2).get("completed") is True
          and bool(body_of(r2).get("new_custody_id")), r2.text[:200])

    await board.release_gate(f"migration.before_rebuild_insert:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild adjudicates completed new winner -> 409 (not 500/201)",
          rb.status_code == 409 and err.get("code") == "IDEMPOTENCY_CONFLICT"
          and err.get("basis", {}).get("migration_id") == winner2,
          f"{rb.status_code} {rb.text[:240]}")
    check(f"{label}: loser left no session",
          await hs.sessions_for_source(cid_b) == [])
    # completed 赢家同请求体可重放（200，含同一新 custody）。
    rr = await hs.start(cid_e, tgt_e, key)
    check(f"{label}: completed winner same-body replay returns 200 + same custody",
          rr.status_code == 200 and body_of(rr).get("migration_id") == winner2
          and body_of(rr).get("status") == "completed",
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s14(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Non-target database failures during the rebuild insert are raw 500s.

    Injected at ``migration.before_rebuild_insert`` (rebuild attempt only):
    a generic RuntimeError and a non-target 23505 both surface as 500, never
    misreported as an idempotency conflict; nothing is inserted and the same
    key retries cleanly afterwards.
    """
    for fault, sub in (("RAISE", "generic"),
                       ("UNIQUE:migration_sessions_pkey", "nontarget23505")):
        label = f"S14(rebuild-db-error-{sub})"
        _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}{sub}a")
        _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}{sub}b")
        key = f"s14-{tag}-{sub}"
        winner_id, tb = await _drive_idem_loser_to_rebuild(
            hs, board, label, cid_a, tgt_a, cid_b, tgt_b, key,
            fail_extra={"X-Fault-Fail": f"migration.before_rebuild_insert:{fault}"})
        check(f"{label}: winner created then driven failed", bool(winner_id))
        await board.release_gate(f"migration.before_rebuild_revalidate:{label}-b")
        # 重建核对通过，停在 INSERT 前闸门，注入的故障在该点触发。
        rb = await tb
        check(f"{label}: rebuild-insert {sub} failure surfaces as 500 (never 409)",
              rb.status_code == 500, f"{rb.status_code} {rb.text[:160]}")
        check(f"{label}: no open session / no denial audit after the 500",
              await hs.sessions_for_source(cid_b) == []
              and await hs.open_count_for_key(key) == 0
              and await hs.denied_audits(cid_b) == [])
        rr = await hs.start(cid_b, tgt_b, key)
        check(f"{label}: same key retries cleanly -> 201 after the 500",
              rr.status_code == 201 and body_of(rr).get("status") == "open"
              and body_of(rr).get("source_custody_id") == cid_b,
              f"{rr.status_code} {rr.text[:200]}")




async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        suffix = os.urandom(4).hex()
        await scenario_s1(hs, board, f"{suffix}1")
        await scenario_s2(hs, board, f"{suffix}2")
        await scenario_s3(hs, board, f"{suffix}3")
        await scenario_s4(hs, board, f"{suffix}4")
        await scenario_s5(hs, f"{suffix}5")
        await scenario_s6(hs, f"{suffix}6")
        await scenario_s7(hs, board, f"{suffix}7")
        await scenario_s8(hs, board, f"{suffix}8")
        await scenario_s9(hs, board, f"{suffix}9")
        await scenario_s10(hs, board, f"{suffix}10")
        await scenario_s11(hs, board, f"{suffix}11")
        await scenario_s12(hs, board, f"{suffix}12")
        await scenario_s13(hs, board, f"{suffix}13")
        await scenario_s14(hs, board, f"{suffix}14")

        r = await http.get("/audit/replay", headers=auth(hs.tenant_key))
        check("final: audit hash chain valid across start-race scenarios",
              r.json().get("valid") is True)

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} migration-start checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("MIGRATION START IDEMPOTENCY CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
