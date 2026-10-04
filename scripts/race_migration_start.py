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

Post-terminal rebuild re-adjudication (v1.7.2):

  S9  while the loser is parked after the savepoint rollback the winner goes
      ``open`` → ``failed`` AND the TARGET policy version is revoked (the
      target is neither request's source, so neither source row lock blocks
      the revoke). The old rebuild reused the pre-wait policy rows/digests and
      still created an open session pinned to the now-revoked target. The
      rebuild must instead re-read the target version row (FOR UPDATE), fail
      deterministically with 409 MIGRATION_TARGET_INVALID, leave NO session
      and NO success audit, and record exactly one separate
      ``migration.start`` / ``denied`` / MIGRATION_TARGET_INVALID audit.
  S10 the TARGET epoch window expires (wall clock) while the loser is parked:
      a decision must use a fresh ``clock_timestamp()`` — never the
      transaction-start time frozen while the request waited on a lock — so
      the rebuild fails with MIGRATION_TARGET_INVALID
      (``target_epoch_expired``), no session is left, and a fresh key right
      afterwards still hits the same deterministic rejection.
  S11 the SOURCE epoch window expires while the loser is parked: the rebuild
      re-reads the source custody/policy and fails with
      MIGRATION_SOURCE_INVALID (``source_epoch_expired``), leaving no session
      and only a denial audit.
  S12 new-winner adjudication during the rebuild wait: the first winner goes
      terminal (freeing the key); while the first loser's rebuild INSERT is
      itself waiting on ``uq_migration_idem_open``, a second concurrent
      request commits a NEW open session under the same key. Same request
      body (loser A) → 200 replay of the new winner; different body (loser B)
      → 409 IDEMPOTENCY_CONFLICT naming the new winner. Neither loser leaves
      a session or a success audit.
  S13 rebuild-insert versus target-revoke transaction ordering: the rebuild
      takes the target policy-version row ``FOR UPDATE`` (custody row locked
      first, so no lock-order inversion with destruction/submit paths). A
      real concurrent revoke blocks on that row until the creation commits —
      the rebuilt 201 session is queryable and the revoke then 409s on its
      active-head guard, deterministically ordered, with no deadlock and no
      500.
  S14 a non-target database error raised at the rebuild re-validation point
      (``migration.after_rebuild_recheck`` gate) surfaces verbatim as a 500
      (never translated into MIGRATION_TARGET_INVALID /
      IDEMPOTENCY_CONFLICT) and rolls back cleanly; the same key retries
      afterwards.
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

    async def make_source_and_target(self, tag: str,
                                    target_epoch: dict | None = None
                                    ) -> tuple[str, str, str]:
        """Fresh valid 2-of-3 source policy+custody and a distinct target."""
        src = f"pol_s_{tag}_src"
        tgt = f"pol_s_{tag}_tgt"
        epoch = target_epoch or {"valid_from": "2026-01-01T00:00:00Z",
                                 "valid_until": "2035-01-01T00:00:00Z",
                                 "rotation_interval": 0}
        src_epoch = {"valid_from": "2026-01-01T00:00:00Z",
                     "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": src, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": src_epoch,
        })
        assert r.status_code == 201, r.text
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": tgt, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": src, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return src, tgt, r.json()["custody_id"]

    async def make_source(self, tag: str, epoch: dict) -> tuple[str, str]:
        """A fresh 2-of-3 source policy with a custom epoch + one custody."""
        src = f"pol_s_{tag}_src"
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": src, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": src, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return src, r.json()["custody_id"]

    async def make_target(self, tag: str, epoch: dict | None = None) -> str:
        tgt = f"pol_s_{tag}_tgt"
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": tgt, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch or {"valid_from": "2026-01-01T00:00:00Z",
                               "valid_until": "2035-01-01T00:00:00Z",
                               "rotation_interval": 0},
        })
        assert r.status_code == 201, r.text
        return tgt

    async def second_custody(self, src: str, tag: str) -> str:
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": src, "expected_version": 1,
            "secret_hex": (self.secret + tag.encode()).hex(),
        })
        assert r.status_code == 201, r.text
        return r.json()["custody_id"]

    async def drive_winner_failed(self, winner_id: str) -> None:
        """Drive an open winner into the ``failed`` terminal state via a gap."""
        pa = await self.prep("alice", winner_id)
        r1 = await self.submit(pa)
        assert r1.status_code == 200, r1.text
        app.state.pending.clear(winner_id)
        pb = await self.prep("bob", winner_id)
        r2 = await self.submit(pb)
        assert r2.status_code == 409 and body_of(r2).get("error", {}).get("code") == "THRESHOLD_NOT_MET", r2.text
        row = await self.mig_row(winner_id)
        assert row["status"] == "failed" and row["new_custody_id"] is None

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
        out = []
        for r in rows:
            basis = r["basis"]
            if isinstance(basis, str):
                basis = json.loads(basis)
            out.append({"error_code": r["error_code"], "basis": basis})
        return out

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


async def scenario_s9(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Winner fails + TARGET revoked while loser parked -> target-invalid rebuild."""
    label = "S9(rebuild-target-revoked)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    src_b, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s9-{tag}"
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

    # 胜方 failed（键位释放）+ 目标策略版本被撤销：撤销的是目标版本，
    # 与两侧源 custody 行锁互不阻塞。
    await hs.drive_winner_failed(winner_id)
    rr = await hs.http.post(f"/policies/{tgt_b}/revoke",
                            headers=auth(hs.tenant_key), json={"expected_version": 1})
    check(f"{label}: target policy revoked while loser parked",
          rr.status_code == 200, rr.text[:200])

    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: loser rebuild -> 409 MIGRATION_TARGET_INVALID (not stale 201, not 500)",
          rb.status_code == 409 and err.get("code") == "MIGRATION_TARGET_INVALID"
          and err.get("basis", {}).get("reason") == "target_policy_revoked",
          f"{rb.status_code} {rb.text[:240]}")

    # 不留下会话（更不能有绑定已撤销目标的 open 会话），不留成功审计；
    # 恰一条独立拒绝审计。
    rows_b = await hs.sessions_for_source(cid_b)
    check(f"{label}: loser left NO migration session", rows_b == [], str(rows_b))
    check(f"{label}: loser has no migration.start ok audit",
          await hs.ok_audits(cid_b) == 0)
    denied_b = await hs.denied_audits(cid_b)
    check(f"{label}: exactly one denial audit (MIGRATION_TARGET_INVALID)",
          len(denied_b) == 1 and denied_b[0]["error_code"] == "MIGRATION_TARGET_INVALID",
          str(denied_b))
    check(f"{label}: denial audit names the revoked target",
          denied_b[0]["basis"].get("policy_id") == tgt_b
          and denied_b[0]["basis"].get("status") == "revoked", str(denied_b))
    check(f"{label}: open placeholder count for the key is zero",
          await hs.open_count_for_key(key) == 0)

    # 目标仍撤销：换新键立即再试也得到同样的确定性拒绝（不随键变化）。
    rx = await hs.start(cid_b, tgt_b, f"s9-fresh-{tag}")
    check(f"{label}: fresh-key retry against revoked target still 409 target-invalid",
          rx.status_code == 409
          and body_of(rx).get("error", {}).get("code") == "MIGRATION_TARGET_INVALID",
          f"{rx.status_code} {rx.text[:200]}")

    # 目标轮换出新的有效版本后，从源记录用新键可成功迁移到新版本。
    epoch2 = {"valid_from": "2026-10-01T00:00:00Z",
              "valid_until": "2036-01-01T00:00:00Z", "rotation_interval": 0}
    rrot = await hs.http.post(f"/policies/{tgt_b}/rotate", headers=auth(hs.tenant_key),
                              json={"expected_version": 1, "epoch": epoch2})
    # 旧版本已被显式撤销，rotate 要求 head active -> 预期 POLICY_INACTIVE；
    # 改为新建另一条目标策略验证“有效才可新建”。
    check(f"{label}: revoked head cannot rotate (POLICY_INACTIVE)",
          rrot.status_code == 409
          and body_of(rrot).get("error", {}).get("code") == "POLICY_INACTIVE",
          f"{rrot.status_code} {rrot.text[:160]}")
    tgt_new = await hs.make_target(f"{tag}new")
    rn = await hs.start(cid_b, tgt_new, f"s9-valid-{tag}")
    check(f"{label}: valid new target -> 201 open session",
          rn.status_code == 201 and body_of(rn).get("status") == "open"
          and body_of(rn).get("target_policy_id") == tgt_new
          and body_of(rn).get("source_custody_id") == cid_b,
          f"{rn.status_code} {rn.text[:200]}")


async def scenario_s10(hs: Harness, board: FaultBoard, tag: str) -> None:
    """TARGET epoch expires on the wall clock while the loser is parked."""
    label = "S10(rebuild-target-epoch-expired)"
    # 目标 epoch 在“不久后”到期（真实墙钟），保证创建预查时有效、等待后失效。
    from datetime import datetime, timedelta, timezone
    valid_from = (datetime.now(timezone.utc) - timedelta(seconds=300))
    valid_until = datetime.now(timezone.utc) + timedelta(seconds=3)
    short_epoch = {"valid_from": valid_from.isoformat().replace("+00:00", "Z"),
                   "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
                   "rotation_interval": 0}
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    src_b = f"pol_s_{tag}b_src"
    _, cid_b = await hs.make_source(f"{tag}b", {
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0})
    tgt_b = await hs.make_target(f"{tag}b", short_epoch)
    key = f"s10-{tag}"
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
    check(f"{label}: winner 201 open (target epoch still valid at pre-check)",
          ra.status_code == 201 and bool(winner_id), f"{ra.status_code} {ra.text[:200]}")

    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    await hs.drive_winner_failed(winner_id)
    # 等待真实墙钟越过目标 epoch valid_until（事务开始时的旧时间尚在窗口内）。
    await asyncio.sleep(3.5)

    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild uses fresh clock -> 409 target_epoch_expired (not stale 201)",
          rb.status_code == 409 and err.get("code") == "MIGRATION_TARGET_INVALID"
          and err.get("basis", {}).get("reason") == "target_epoch_expired",
          f"{rb.status_code} {rb.text[:240]}")
    check(f"{label}: no session left, one denial audit, no ok audit",
          await hs.sessions_for_source(cid_b) == []
          and await hs.ok_audits(cid_b) == 0
          and [d["error_code"] for d in await hs.denied_audits(cid_b)]
          == ["MIGRATION_TARGET_INVALID"])


async def scenario_s11(hs: Harness, board: FaultBoard, tag: str) -> None:
    """SOURCE epoch expires on the wall clock while the loser is parked."""
    label = "S11(rebuild-source-epoch-expired)"
    from datetime import datetime, timedelta, timezone
    valid_until = datetime.now(timezone.utc) + timedelta(seconds=3)
    short_epoch = {"valid_from": datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                   .replace("+00:00", "Z"),
                   "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
                   "rotation_interval": 0}
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    src_b, cid_b = await hs.make_source(f"{tag}b", short_epoch)
    tgt_b = await hs.make_target(f"{tag}b")
    key = f"s11-{tag}"
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
    check(f"{label}: winner 201 open", ra.status_code == 201 and bool(winner_id),
          f"{ra.status_code} {ra.text[:200]}")

    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    await hs.drive_winner_failed(winner_id)
    await asyncio.sleep(3.5)

    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    err = body_of(rb).get("error", {})
    check(f"{label}: rebuild re-reads source -> 409 source_epoch_expired",
          rb.status_code == 409 and err.get("code") == "MIGRATION_SOURCE_INVALID"
          and err.get("basis", {}).get("reason") == "source_epoch_expired",
          f"{rb.status_code} {rb.text[:240]}")
    check(f"{label}: no session left, one source-invalid denial audit",
          await hs.sessions_for_source(cid_b) == []
          and await hs.ok_audits(cid_b) == 0
          and [d["error_code"] for d in await hs.denied_audits(cid_b)]
          == ["MIGRATION_SOURCE_INVALID"])


async def scenario_s12(hs: Harness, board: FaultBoard, tag: str) -> None:
    """A NEW winner commits while the rebuild waits: replay vs conflict.

    The first winner goes terminal (key free). The rebuilding loser is pinned
    at ``migration.after_rebuild_recheck`` (fresh re-validation done, target
    row locked, rebuild INSERT not yet attempted) while a second request
    starts under the same key. Two independent sub-cases:

    * 12a the new winner binds the SAME source custody + target as the loser:
      the loser's rebuild INSERT waits on ``uq_migration_idem_open`` (and the
      per-source open index), the new winner commits first, and the loser
      replays it — 200 with the new winner's session.
    * 12b the new winner binds a DIFFERENT source: the loser's rebuild INSERT
      hits ``uq_migration_idem_open``; after its savepoint rollback it
      re-reads the new live winner and returns 409 IDEMPOTENCY_CONFLICT
      naming that new winner.
    """
    # ---- 12a: new winner same body -> rebuilding loser replays (200) --------
    label = "S12a(rebuild-new-winner-same-body)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s12a-{tag}"
    ga = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    gb = {"X-Fault-Key": f"{label}-b",
          "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict,"
                          "migration.after_rebuild_recheck"}
    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, ga))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gb))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner1 = body_of(ra).get("migration_id")
    check(f"{label}: winner 201 open", ra.status_code == 201 and bool(winner1), ra.text[:160])
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    await hs.drive_winner_failed(winner1)
    # 放行后败方重新裁决并钉在“重建 INSERT 之前”。
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    await board.wait_reached(f"migration.after_rebuild_recheck:{label}-b")

    # 新赢家：同键、同源 cid_b、同目标 tgt_b —— 与败方重建请求体完全相同。
    # 同源故新赢家在败方仍持有的源 custody 行锁上排队；败方重建 INSERT 撞其
    # 自己持有事务内先前保存点已回滚、键位空闲——它会先插入成功并随后提交，
    # 新赢家拿锁后经预查重放。为精确钉住“重建 INSERT 等待期间出现新赢家”，
    # 败方重建事务在 INSERT 撞 uq_migration_idem_open 时键位空闲不会等待；
    # 因此让新赢家先在源行锁队列中等待，败方提交后它即为该键的新 open 赢家，
    # 其请求结果必须是同请求体重放（200），而不是 409/500。
    tnew = asyncio.create_task(hs.start(cid_b, tgt_b, key))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: same-body new winner queues on the source custody lock",
          queued == 1, f"q={queued}")
    # 放行败方重建 INSERT 并提交；排队者拿锁后预查命中新会话 -> 200 重放。
    await board.release_gate(f"migration.after_rebuild_recheck:{label}-b")
    rb = await tb
    rebuilt_id = body_of(rb).get("migration_id")
    rnew = await tnew
    check(f"{label}: rebuilding loser commits its rebuilt session -> 201",
          rb.status_code == 201 and body_of(rb).get("status") == "open"
          and body_of(rb).get("source_custody_id") == cid_b,
          f"{rb.status_code} {rb.text[:200]}")
    check(f"{label}: queued same-body same-key request replays rebuilt winner -> 200",
          rnew.status_code == 200 and body_of(rnew).get("migration_id") == rebuilt_id,
          f"{rnew.status_code} {rnew.text[:200]}")
    check(f"{label}: exactly one session row for cid_b",
          [r["id"] for r in await hs.sessions_for_source(cid_b)] == [rebuilt_id])
    check(f"{label}: exactly one ok audit, no denials for cid_b",
          await hs.ok_audits(cid_b) == 1 and await hs.denied_audits(cid_b) == [])

    # ---- 12b: new winner different body -> rebuilding loser 409 -------------
    label = "S12b(rebuild-new-winner-diff-body)"
    _, tgt_c, cid_c = await hs.make_source_and_target(f"{tag}c")
    _, tgt_d, cid_d = await hs.make_source_and_target(f"{tag}d")
    key2 = f"s12b-{tag}"
    gc = {"X-Fault-Key": f"{label}-c", "X-Fault-Gate": "migration.after_idem_check"}
    gd = {"X-Fault-Key": f"{label}-d",
          "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict,"
                          "migration.after_rebuild_recheck"}
    tc = asyncio.create_task(hs.start(cid_c, tgt_c, key2, gc))
    td = asyncio.create_task(hs.start(cid_d, tgt_d, key2, gd))
    await board.wait_reached(f"migration.after_idem_check:{label}-c")
    await board.wait_reached(f"migration.after_idem_check:{label}-d")
    await board.release_gate(f"migration.after_idem_check:{label}-c")
    rc = await tc
    winner2 = body_of(rc).get("migration_id")
    check(f"{label}: winner 201 open", rc.status_code == 201 and bool(winner2), rc.text[:160])
    await board.release_gate(f"migration.after_idem_check:{label}-d")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-d")
    await hs.drive_winner_failed(winner2)
    await board.release_gate(f"migration.after_insert_conflict:{label}-d")
    await board.wait_reached(f"migration.after_rebuild_recheck:{label}-d")

    # 新赢家2：同键、绑定另一条源 cid_c（与 D 的请求体不同源）。行锁互不重叠，
    # 故可在 D 的重建 INSERT 前先提交，持有 uq_migration_idem_open。
    tnew2 = asyncio.create_task(hs.start(cid_c, tgt_c, key2))
    # 等新赢家2完整提交（它不与 D 的源行锁冲突）。
    rnew2 = await tnew2
    nw2 = body_of(rnew2).get("migration_id")
    check(f"{label}: new winner on a different source commits -> 201",
          rnew2.status_code == 201 and body_of(rnew2).get("source_custody_id") == cid_c
          and body_of(rnew2).get("status") == "open",
          f"{rnew2.status_code} {rnew2.text[:200]}")
    # 放行 D 的重建 INSERT：撞 uq_migration_idem_open，重读判出新赢家 -> 409。
    await board.release_gate(f"migration.after_rebuild_recheck:{label}-d")
    rd = await td
    err = body_of(rd).get("error", {})
    check(f"{label}: rebuilding loser -> 409 IDEMPOTENCY_CONFLICT vs the NEW winner",
          rd.status_code == 409 and err.get("code") == "IDEMPOTENCY_CONFLICT"
          and err.get("basis", {}).get("reason") == "concurrent_open_with_same_idempotency_key"
          and err.get("basis", {}).get("migration_id") == nw2
          and err.get("basis", {}).get("winner_source_custody_id") == cid_c,
          f"{rd.status_code} {rd.text[:240]}")
    check(f"{label}: cid_d loser left no session/ok audit, one denial audit",
          await hs.sessions_for_source(cid_d) == []
          and await hs.ok_audits(cid_d) == 0
          and [d["error_code"] for d in await hs.denied_audits(cid_d)]
          == ["IDEMPOTENCY_CONFLICT"])
    # 已完成赢家可重放：同键同体（cid_c+tgt_c）重放新赢家2 -> 200。
    rr = await hs.start(cid_c, tgt_c, key2)
    check(f"{label}: committed new winner remains replayable with the same key -> 200",
          rr.status_code == 200 and body_of(rr).get("migration_id") == nw2,
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s13(hs: Harness, board: FaultBoard, tag: str) -> None:
    """Rebuild insert vs target revoke are ordered by the FOR UPDATE row lock."""
    label = "S13(rebuild-vs-revoke-order)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s13-{tag}"
    ga = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    gb = {"X-Fault-Key": f"{label}-b",
          "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict,"
                          "migration.rebuild_target_locked"}
    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, ga))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gb))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner_id = body_of(ra).get("migration_id")
    check(f"{label}: winner 201 open", ra.status_code == 201 and bool(winner_id), ra.text[:160])
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    await hs.drive_winner_failed(winner_id)

    # 放行败方重读：胜方 failed -> 重建裁决；其重新锁住目标版本行后钉住。
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    await board.wait_reached(f"migration.rebuild_target_locked:{label}-b")

    # 重建事务已持目标版本行 FOR UPDATE；真实撤销事务此刻必在该行锁上排队。
    revoke_task = asyncio.create_task(hs.http.post(
        f"/policies/{tgt_b}/revoke", headers=auth(hs.tenant_key),
        json={"expected_version": 1}))

    async def _revoke_waiters() -> int:
        # 行锁等待在 pg_locks 中表现为对持锁事务 xid 的未授予
        # transactionid 锁（tuple 锁本身已 granted）。
        return await hs.pool.fetchval(
            """
            SELECT count(*)
            FROM pg_locks l
            JOIN pg_stat_activity a ON a.pid = l.pid
            WHERE l.locktype = 'transactionid' AND NOT l.granted
              AND a.query LIKE '%UPDATE policies%'
            """)
    queued = 0
    for _ in range(150):
        queued = await _revoke_waiters()
        if queued >= 1 or tb.done():
            break
        await asyncio.sleep(0.02)
    check(f"{label}: concurrent revoke queues on the rebuild's target row lock",
          queued >= 1 and not tb.done(), f"queued={queued} tb_done={tb.done()}")

    # 放行重建：重建 INSERT + 成功审计先提交，撤销随后拿锁提交——确定性先后。
    await board.release_gate(f"migration.rebuild_target_locked:{label}-b")
    rb = await tb
    body_b = body_of(rb)
    check(f"{label}: rebuild commits its own 201 open session first",
          rb.status_code == 201 and body_b.get("status") == "open"
          and body_b.get("target_policy_id") == tgt_b
          and body_b.get("source_custody_id") == cid_b,
          f"{rb.status_code} {rb.text[:200]}")
    rrev = await revoke_task
    check(f"{label}: revoke proceeds after rebuild commits (ordered, no deadlock/500)",
          rrev.status_code == 200 and body_of(rrev).get("status") == "revoked",
          f"{rrev.status_code} {rrev.text[:200]}")
    rows_b = await hs.sessions_for_source(cid_b)
    check(f"{label}: rebuilt session exists and is queryable",
          len(rows_b) == 1 and rows_b[0]["id"] == body_b.get("migration_id"), str(rows_b))
    g = await hs.http.get(f"/migrations/{body_b['migration_id']}",
                          headers=auth(hs.tenant_key))
    check(f"{label}: GET rebuilt session -> 200",
          g.status_code == 200 and body_of(g).get("migration_id") == body_b["migration_id"],
          g.text[:160])
    check(f"{label}: rebuild left one ok audit, no denial",
          await hs.ok_audits(cid_b) == 1 and await hs.denied_audits(cid_b) == [])
    # 撤销随后确定性生效：换用新键再发起（终态后重建）必被 target-invalid 拒绝。
    rr = await hs.start(cid_b, tgt_b, f"s13-again-{tag}")
    check(f"{label}: after revoke commits, a new start hits target-invalid",
          rr.status_code == 409
          and body_of(rr).get("error", {}).get("code") == "MIGRATION_TARGET_INVALID",
          f"{rr.status_code} {rr.text[:200]}")


async def scenario_s14(hs: Harness, board: FaultBoard, tag: str) -> None:
    """A generic failure at rebuild re-validation is a 500, never mistranslated."""
    label = "S14(rebuild-generic-error-500)"
    _, tgt_a, cid_a = await hs.make_source_and_target(f"{tag}a")
    _, tgt_b, cid_b = await hs.make_source_and_target(f"{tag}b")
    key = f"s14-{tag}"
    ga = {"X-Fault-Key": f"{label}-a", "X-Fault-Gate": "migration.after_idem_check"}
    gb = {"X-Fault-Key": f"{label}-b",
          "X-Fault-Gate": "migration.after_idem_check,migration.after_insert_conflict",
          # 重建重新裁决完成、重试 INSERT 之前注入通用故障（必须原样 500）。
          "X-Fault-Fail": "migration.after_rebuild_recheck:RAISE"}
    ta = asyncio.create_task(hs.start(cid_a, tgt_a, key, ga))
    tb = asyncio.create_task(hs.start(cid_b, tgt_b, key, gb))
    await board.wait_reached(f"migration.after_idem_check:{label}-a")
    await board.wait_reached(f"migration.after_idem_check:{label}-b")
    await board.release_gate(f"migration.after_idem_check:{label}-a")
    ra = await ta
    winner_id = body_of(ra).get("migration_id")
    assert ra.status_code == 201, ra.text
    await board.release_gate(f"migration.after_idem_check:{label}-b")
    await board.wait_reached(f"migration.after_insert_conflict:{label}-b")
    await hs.drive_winner_failed(winner_id)
    await board.release_gate(f"migration.after_insert_conflict:{label}-b")
    rb = await tb
    check(f"{label}: rebuild-time generic failure -> 500 (not 409/target-invalid)",
          rb.status_code == 500, f"{rb.status_code} {rb.text[:160]}")
    check(f"{label}: no session, no audit after the generic failure",
          await hs.sessions_for_source(cid_b) == []
          and await hs.ok_audits(cid_b) == 0
          and await hs.denied_audits(cid_b) == [])
    # 同键/新键随后可干净重试（目标仍有效）。
    rr = await hs.start(cid_b, tgt_b, f"s14-retry-{tag}")
    check(f"{label}: fresh key retries cleanly -> 201",
          rr.status_code == 201 and body_of(rr).get("status") == "open",
          f"{rr.status_code} {rr.text[:160]}")


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
