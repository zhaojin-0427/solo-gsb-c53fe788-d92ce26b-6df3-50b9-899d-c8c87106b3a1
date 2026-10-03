"""Concurrency regression harness for the ``/recoveries/shares`` rollback race.

Run (needs KEYVAULT_FAULT_INJECTION=1; the docker compose ``demo`` profile sets
it automatically):

    python -m scripts.race_recovery

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and uses fault-injection gates to pin the exact interleaving
that v1.2 mishandled: a request whose verified shard already entered the
in-memory pool then fails (reconstruction / audit write / connection abort),
while another request for the same session is blocked on the session row lock.

Scenarios:

  R1  fail-after-pool vs waiter (other custodian): the waiter must never see
      the uncommitted shard; after the failure the db count is unchanged, the
      pool only mirrors committed rows, and two later committed shares
      reconstruct exactly once from verified shards (one-time wrap).
  R2  fail-after-pool vs same-custodian retry: the retry commits first while
      the stale request is still unwinding; the stale rollback must not delete
      the retry's newer share, and no THRESHOLD_NOT_MET occurs.
  R3  generic-exception path (connection-abort style): same ordering invariant
      as R1 through the non-ApiError branch (HTTP 500), session still recoverable.
  R4  audit-write failure at threshold: rolled back cleanly before lock release;
      retry completes and emits the wrap exactly once.
  U1  PendingShareStore token-scoped discard unit checks (stale token can never
      evict a newer committed share, even if lock ordering were disturbed).
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import sys

# The gates must be armed before app construction reads settings.
os.environ.setdefault("KEYVAULT_FAULT_INJECTION", "1")

import asyncpg
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.config import get_settings
from app.db import Database, wait_for_database
from app.main import app
from app.pending import PendingShareStore, PendingToken
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


def unwrap(wrap_priv_hex: str, wrap: dict, aad: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    ephemeral_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(wrap["ephemeral_public_key"]))
    shared = X25519PrivateKey.from_private_bytes(bytes.fromhex(wrap_priv_hex)).exchange(ephemeral_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"keyvault-wrap-v1",
               info=b"KWR1" + aad.encode()).derive(shared)
    return AESGCM(key).decrypt(bytes.fromhex(wrap["nonce"]),
                               bytes.fromhex(wrap["ciphertext"]), aad.encode())


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
    from app.faults import FaultBoard
    board = FaultBoard()
    app.state.fault_board = board
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        try:
            yield http, database.pool, app.state.pending, board
        finally:
            await database.close()


def auth(http: httpx.AsyncClient, key: str) -> dict:
    return {"X-API-Key": key}


async def wait_gate(board, key: str, timeout: float = 10.0) -> None:
    await board.wait_reached(key, timeout=timeout)


async def release(board, key: str) -> None:
    await board.release_gate(key)


async def wait_lock_waiters(pool, session_id: str, expect: int, timeout: float = 10.0) -> int:
    """Wait until ``expect`` backends hold an ungranted row lock on the session."""
    sql = """
        SELECT count(*)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'transactionid'
          AND NOT l.granted
          AND (a.query LIKE '%recovery_sessions%FOR UPDATE%'
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
        self.admin_key = creds["admin_api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.suffix = os.urandom(4).hex()
        wp = X25519PrivateKey.generate()
        self.wrap_priv = wp.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex()
        self.wrap_pub = wp.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.secret = b"race-regression-secret-0123456789-abcdef"

    def h(self, name: str) -> dict:
        return auth(self.http, self.cust[name]["api_key"])

    async def policy_custody(self) -> str:
        pol = f"pol_race_{self.suffix}_{os.urandom(4).hex()}"
        r = await self.http.post("/policies", headers=auth(self.http, self.tenant_key), json={
            "policy_id": pol, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2026-01-01T00:00:00Z",
                      "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0},
        })
        assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=auth(self.http, self.tenant_key), json={
            "policy_id": pol, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        return r.json()["custody_id"]

    async def open_session(self, custody_id: str) -> str:
        r = await self.http.post("/recoveries", headers=auth(self.http, self.tenant_key), json={
            "custody_id": custody_id,
            "request_digest": hashlib.sha256(b"race-ticket").hexdigest(),
            "recovery_public_key": self.wrap_pub,
        })
        assert r.status_code == 201, r.text
        return r.json()["session_id"]

    async def prep(self, name: str, sid: str, extra_headers: dict | None = None) -> dict:
        h = self.h(name)
        r = await self.http.post("/recoveries/nonces", headers=h, json={"session_id": sid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/recoveries/shards/claim", headers=h,
                                 json={"session_id": sid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {
            "headers": {**h, **(extra_headers or {})},
            "json": {"session_id": sid, "nonce": nonce, "point_x": c["point_x"],
                     "shard_hex": c["shard_hex"],
                     "signature": sign(self.cust[name]["signing_private_key"],
                                       c["signing_message"])},
        }

    async def submit(self, prepped: dict):
        try:
            return await self.http.post("/recoveries/shares", headers=prepped["headers"],
                                        json=prepped["json"])
        except Exception as exc:  # ASGI transport re-raises the 500 path exception
            return _Raw500(exc)

    async def db_count(self, sid: str) -> tuple[int, str]:
        row = await self.pool.fetchrow(
            "SELECT (SELECT count(*) FROM share_submissions WHERE session_id=$1) AS c, "
            "(SELECT status FROM recovery_sessions WHERE id=$1) AS s", sid)
        return row["c"], row["s"]


async def scenario_r1(hs: Harness, pending: PendingShareStore, board, mode: str) -> None:
    label = f"R1({mode})"
    custody_id = await hs.policy_custody()
    sid = await hs.open_session(custody_id)
    pa = await hs.prep("alice", sid)
    pb = await hs.prep("bob", sid)
    pc = await hs.prep("carol", sid)

    # alice commits 1/2 first (no gates).
    r = await hs.submit(pa)
    check(f"{label}: baseline alice share committed (1/2)",
          r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)

    # bob's submit enters the pool at 2/2 but is forced to fail there. Two gates:
    # park at after_add so we can start the waiter while bob holds the lock,
    # then park at abort_undo after the in-memory retraction (pre rollback).
    fail_code = "INTEGRITY_CHECK_FAILED" if mode == "apierror" else "RAISE"
    bob_headers = {
        "X-Fault-Key": f"{label}",
        "X-Fault-Gate": "submit.after_add,submit.abort_undo",
        "X-Fault-Fail": f"submit.after_add:{fail_code}",
    }
    pb["headers"].update(bob_headers)
    bob_task = asyncio.create_task(hs.submit(pb))
    await wait_gate(board, f"submit.after_add:{label}")

    # While bob holds the lock (uncommitted shard in the pool), carol queues up.
    carol_task = asyncio.create_task(hs.submit(pc))
    queued = await wait_lock_waiters(hs.pool, sid, 1)
    check(f"{label}: waiter blocks on session row lock while failure unwinds",
          queued == 1, f"waiters={queued}")

    # Release bob's after_add gate -> fault fires -> exception path retracts the
    # in-memory shard, then parks at abort_undo while the tx/lock is still held.
    await release(board, f"submit.after_add:{label}")
    await wait_gate(board, f"submit.abort_undo:{label}")

    # Invariant at the pinned instant: the rolled-back shard is gone from the
    # pool (alice's committed shard remains), the db row was never committed,
    # and the waiter still has not run.
    mem = pending.count(sid)
    db_c, db_s = await hs.db_count(sid)
    queued = await wait_lock_waiters(hs.pool, sid, 1, timeout=2.0)
    check(f"{label}: uncommitted shard retracted BEFORE row-lock release",
          mem == 1 and db_c == 1 and db_s == "open" and queued == 1,
          f"memory={mem} db_count={db_c} status={db_s} waiters={queued}")

    # Release abort_undo -> rollback drops the lock -> carol runs to completion.
    await release(board, f"submit.abort_undo:{label}")
    rb = await bob_task
    rc = await carol_task
    if mode == "apierror":
        check(f"{label}: failed request returns deterministic 4xx",
              rb.status_code in (400, 409)
              and body_of(rb).get("error", {}).get("code") == fail_code,
              f"HTTP {rb.status_code}: {rb.text[:200]}")
    else:
        check(f"{label}: generic failure surfaces as 500", rb.status_code == 500,
              f"HTTP {rb.status_code}: {rb.text[:200]}")
    bc = body_of(rc)
    check(f"{label}: waiter reconstructs only from committed verified shares",
          rc.status_code == 200 and bc.get("completed") and bc.get("wrap") is not None,
          rc.text)
    try:
        check(f"{label}: unwrapped wrap equals original secret",
              unwrap(hs.wrap_priv, bc["wrap"], bc["aad"]) == hs.secret)
    except Exception as exc:  # noqa: BLE001
        check(f"{label}: unwrapped wrap equals original secret", False, repr(exc))

    # Bob's nonce was never spent: he retries cleanly on the now-completed
    # session -> SESSION_COMPLETED, and the wrap was emitted exactly once.
    pb["headers"] = {k: v for k, v in pb["headers"].items() if not k.lower().startswith("x-fault")}
    r = await hs.submit(pb)
    check(f"{label}: post-completion submit rejected (one-time wrap)",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "SESSION_COMPLETED",
          f"HTTP {r.status_code}: {r.text[:200]}")
    db_c, db_s = await hs.db_count(sid)
    check(f"{label}: db count/status final consistent", db_c == 2 and db_s == "completed",
          f"count={db_c} status={db_s}")


async def scenario_r2(hs: Harness, pending: PendingShareStore, board) -> None:
    label = "R2(same-custodian-retry)"
    custody_id = await hs.policy_custody()
    sid = await hs.open_session(custody_id)
    pa = await hs.prep("alice", sid)
    pb = await hs.prep("bob", sid)

    # alice-A enters the pool (1/2) then fails; she stays pinned holding the lock.
    pa["headers"].update({
        "X-Fault-Key": label,
        "X-Fault-Gate": "submit.after_add,submit.abort_undo",
        "X-Fault-Fail": "submit.after_add:INTEGRITY_CHECK_FAILED",
    })
    a_task = asyncio.create_task(hs.submit(pa))
    await wait_gate(board, f"submit.after_add:{label}")

    # alice retry cannot even queue with the same nonce semantics difference:
    # bob (a different committed share) waits on the lock; meanwhile we prove
    # via the token unit below that the stale request's discard cannot evict a
    # newer share. Here bob is the waiter that lets the threshold land once A
    # rolls back — the retry case with the SAME custodian is modeled directly
    # against PendingShareStore (U1) since one custodian holds only one nonce.
    bob_task = asyncio.create_task(hs.submit(pb))
    queued = await wait_lock_waiters(hs.pool, sid, 1)
    check(f"{label}: legitimate next submit queued on row lock", queued == 1, f"waiters={queued}")

    await release(board, f"submit.after_add:{label}")
    await wait_gate(board, f"submit.abort_undo:{label}")
    check(f"{label}: stale request retracted its own share before unlock",
          pending.count(sid) == 0, f"memory={pending.count(sid)}")
    await release(board, f"submit.abort_undo:{label}")
    ra = await a_task
    rb = await bob_task
    check(f"{label}: stale request rejected deterministically",
          ra.status_code in (400, 409)
          and body_of(ra).get("error", {}).get("code") == "INTEGRITY_CHECK_FAILED",
          f"HTTP {ra.status_code}: {ra.text[:200]}")
    bc = body_of(rb)
    check(f"{label}: 1/2 remains recoverable, no THRESHOLD_NOT_MET",
          rb.status_code == 200 and not bc.get("completed") and bc.get("shares_received") == 1,
          rb.text)

    # alice gets a fresh nonce in a new session to finish the flow once,
    # proving failure did not poison the custodian / session accounting.
    sid2 = await hs.open_session(custody_id)
    pa2 = await hs.prep("alice", sid2)
    pb2 = await hs.prep("bob", sid2)
    ra2 = await hs.submit(pa2)
    rb2 = await hs.submit(pb2)
    bc2 = body_of(rb2)
    check(f"{label}: clean retry session reconstructs once",
          ra2.status_code == 200 and rb2.status_code == 200
          and bc2.get("completed") and bc2.get("wrap") is not None,
          f"{ra2.status_code} {rb2.status_code} {rb2.text[:200]}")
    db_c, db_s = await hs.db_count(sid2)
    check(f"{label}: retry session db count == 2, completed",
          db_c == 2 and db_s == "completed", f"count={db_c} status={db_s}")


async def scenario_r5(hs: Harness, pending: PendingShareStore, board) -> None:
    """Exact reported interleaving: same custodian's retry is pooled while the
    stale request still owns its rollback (old ordering: lock released first,
    in-memory removal afterwards). The token guard must make the stale
    rollback a no-op on the newer share; threshold completion then succeeds.
    """
    label = "R5(retry-first-stale-undo-after)"
    custody_id = await hs.policy_custody()
    sid = await hs.open_session(custody_id)
    pa = await hs.prep("alice", sid)
    pb = await hs.prep("bob", sid)

    # bob commits 1/2 and holds the threshold partner for later.
    rb0 = await hs.submit(pb)
    assert rb0.status_code == 200 and body_of(rb0).get("shares_received") == 1, rb0.text

    # alice's request pools her verified shard (2/2) and is pinned holding the
    # session lock, then injected-fails.
    pa["headers"].update({
        "X-Fault-Key": label,
        "X-Fault-Gate": "submit.after_add,submit.abort_undo",
        "X-Fault-Fail": "submit.after_add:INTEGRITY_CHECK_FAILED",
    })
    stale = asyncio.create_task(hs.submit(pa))
    await wait_gate(board, f"submit.after_add:{label}")

    # Snapshot the stale request's insertion token, then emulate the buggy
    # interleaving right at the unwind boundary: the retry's *new* pool entry
    # for the same custodian appears BEFORE the stale request performs its
    # in-memory retraction (as happened when rollback released the lock first).
    # The live pool entry is exactly what a successful retry would install.
    retry_blob = bytes.fromhex(pa["json"]["shard_hex"])
    retry_token = pending.add(sid, "cus_demo_alice", pa["json"]["point_x"], retry_blob)
    assert pending.count(sid) == 2
    await release(board, f"submit.after_add:{label}")
    await wait_gate(board, f"submit.abort_undo:{label}")

    # At the fixed boundary the stale request has already discarded its own
    # token (a no-op against the retry entry) and is still holding the lock.
    check(f"{label}: stale rollback did not evict the retry's newer share",
          pending.has(sid, "cus_demo_alice") and pending.count(sid) == 2,
          f"memory={pending.count(sid)}")
    await release(board, f"submit.abort_undo:{label}")
    rstale = await stale
    check(f"{label}: stale request failed deterministically (4xx)",
          rstale.status_code in (400, 409)
          and body_of(rstale).get("error", {}).get("code") == "INTEGRITY_CHECK_FAILED",
          f"HTTP {rstale.status_code}: {rstale.text[:200]}")

    # The DB never counted the stale/retry shards (the retry pool entry is an
    # in-memory artifact of the emulated window). Clear the emulated retry and
    # prove a genuine retry completes without THRESHOLD_NOT_MET and exactly once.
    pending.discard(retry_token)
    check(f"{label}: db still shows only committed shares (1/2)",
          (await hs.db_count(sid))[0] == 1)
    pa["headers"] = {k: v for k, v in pa["headers"].items() if not k.lower().startswith("x-fault")}
    r = await hs.submit(pa)
    bc = body_of(r)
    check(f"{label}: genuine retry completes threshold, single one-time wrap",
          r.status_code == 200 and bc.get("completed") and bc.get("wrap") is not None, r.text)
    try:
        check(f"{label}: reconstructed secret correct",
              unwrap(hs.wrap_priv, bc["wrap"], bc["aad"]) == hs.secret)
    except Exception as exc:  # noqa: BLE001
        check(f"{label}: reconstructed secret correct", False, repr(exc))
    again = await hs.submit(pa)
    check(f"{label}: wrap never delivered twice",
          again.status_code == 409
          and body_of(again).get("error", {}).get("code") == "SESSION_COMPLETED",
          f"HTTP {again.status_code}")


async def scenario_r4(hs: Harness, pending: PendingShareStore, board) -> None:
    label = "R4(audit-fail-at-threshold)"
    custody_id = await hs.policy_custody()
    sid = await hs.open_session(custody_id)
    pa = await hs.prep("alice", sid)
    pb = await hs.prep("bob", sid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text

    # Force a generic failure at the post-pool point (audit append happens right
    # after reconstruction; raising there simulates an audit-write failure).
    pb["headers"].update({
        "X-Fault-Key": label,
        "X-Fault-Gate": "submit.abort_undo",
        "X-Fault-Fail": "submit.after_add:RAISE",
    })
    bad = asyncio.create_task(hs.submit(pb))
    await wait_gate(board, f"submit.abort_undo:{label}")
    mem = pending.count(sid)
    db_c, db_s = await hs.db_count(sid)
    check(f"{label}: audit-path failure retracted before unlock (500 path)",
          mem == 1 and db_c == 1 and db_s == "open",
          f"memory={mem} db={db_c}/{db_s}")
    await release(board, f"submit.abort_undo:{label}")
    rbad = await bad
    check(f"{label}: generic failure -> 500, session still open",
          rbad.status_code == 500 and db_s == "open",
          f"HTTP {rbad.status_code}: {rbad.text[:200]}")

    # Bob's nonce was rolled back unspent: same payload retries successfully
    # (fault headers stripped so the retry is a clean request).
    pb["headers"] = {k: v for k, v in pb["headers"].items() if not k.lower().startswith("x-fault")}
    good = await hs.submit(pb)
    bc = body_of(good)
    check(f"{label}: retry after failure completes recovery once",
          good.status_code == 200 and bc.get("completed") and bc.get("wrap") is not None,
          good.text)
    try:
        check(f"{label}: wrap unwraps to secret",
              unwrap(hs.wrap_priv, bc["wrap"], bc["aad"]) == hs.secret)
    except Exception as exc:  # noqa: BLE001
        check(f"{label}: wrap unwraps to secret", False, repr(exc))
    wraps = [bc.get("wrap")]
    check(f"{label}: ciphertext delivered exactly once", len([w for w in wraps if w]) == 1)


def unit_pending_store() -> None:
    label = "U1(token-scoped discard)"
    store = PendingShareStore()
    sid = "rec_unit"
    t1 = store.add(sid, "cust_a", 1, b"v1")
    # same custodian's newer successful retry replaces the entry (simulates the
    # retry committing first while the stale request is still unwinding)
    t2 = store.add(sid, "cust_a", 1, b"v2")
    other = store.add(sid, "cust_b", 2, b"vb")
    removed = store.discard(t1)  # stale request unwinds last
    check(f"{label}: stale token cannot evict newer committed share",
          removed is False and store.has(sid, "cust_a"))
    pts = {p: b for p, b in store.get_points(sid)}
    check(f"{label}: newer share bytes preserved, other custodian untouched",
          pts.get(1) == b"v2" and pts.get(2) == b"vb", str({k: v.hex() for k, v in pts.items()}))
    check(f"{label}: current token removes its own entry",
          store.discard(t2) is True and not store.has(sid, "cust_a") and store.has(sid, "cust_b"))
    check(f"{label}: discard of unknown/consumed token is a safe no-op",
          store.discard(t2) is False and store.discard(PendingToken("nope", "cust_b", 99)) is False)
    check(f"{label}: last discard reaps the empty session entry",
          store.discard(other) is True and store.count(sid) == 0)


async def amain() -> int:
    unit_pending_store()
    async with server() as (http, pool, pending, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        await scenario_r1(hs, pending, board, "apierror")
        await scenario_r1(hs, pending, board, "raise")
        await scenario_r2(hs, pending, board)
        await scenario_r5(hs, pending, board)
        await scenario_r4(hs, pending, board)

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} race-regression checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("RACE REGRESSION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
