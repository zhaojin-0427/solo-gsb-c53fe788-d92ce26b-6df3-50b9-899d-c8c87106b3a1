"""Deterministic fault-injection gates for concurrency regression verification.

Disabled unless ``KEYVAULT_FAULT_INJECTION=1`` **and** the request carries the
matching test headers; in a normal deployment every call is a constant-time
no-op. The gates let the regression harness (``scripts/race_recovery.py``)
pin the exact interleaving that previously corrupted ``/recoveries/shares``:

* one request parked **while holding the session row lock** after its verified
  shard entered the in-memory pool (another request is then queued on the lock);
* that request failing from the audit-write / reconstruction path;
* a second request parked right after it acquires the released lock — i.e. at
  the precise point where, in the buggy build, it could observe the first
  request's uncommitted in-memory share, or replace it and have a stale rollback
  delete the newer share.

Gate names used by the share-submit flow:

* ``submit.after_add``   — after the verified shard was put in the pending
                          pool, still inside the transaction, row lock held.
* ``submit.abort_undo`` — on the exception path, **after** this request's own
                          in-memory insertion was retracted but still inside
                          the transaction (the row lock is not yet released).
* ``submit.after_lock`` — immediately after acquiring the session row lock.
* ``submit.before_reconstruct`` — threshold reached, right before combining.

The same gates exist for the cross-policy migration share flow under the
``migration.*`` prefix (``migration.after_lock`` / ``migration.after_add`` /
``migration.before_resplit``), pinning the identical rollback/lock interleaving
on in-memory source-shard accumulation and target re-sharding.
``scripts/race_migration.py`` additionally parks a threshold-reaching submit at
``migration.before_resplit`` (row lock held, pending shares lost) while a
second submitter queues on the lock, proving the queued request can only fail
fast with ``MIGRATION_FAILED`` once the gap detector commits the ``failed``
terminal state — never complete the doomed session.

Logical-destruction interleavings (v1.6, ``scripts/race_destruction.py``) add:

* ``destruction.after_lineage_lock`` — after every custody row of the migration
  lineage is locked but before the in-flight recovery/migration session rows are
  locked. A request parked here lets a migration-completing share submit or a
  recovery shard claim queue on its locks, pinning the deterministic ordering of
  destruction versus in-flight recovery/migration and proving the queued, older
  session can no longer hand out shard plaintext / wrapped ciphertext nor insert
  a missed descendant once destruction wins.
* ``destruction.after_receipt_check`` — after the idempotency-keyed receipt
  pre-check found no existing receipt but before lineage expansion. Two
  concurrent requests reusing one ``Idempotency-Key`` for **unrelated** roots
  park here together (their root row locks do not overlap), so both pass the
  pre-check and the later receipt insert hits ``uq_destruction_idem`` — pinning
  the exact interleaving that used to surface as an unhandled database error,
  and proving the loser now gets a deterministic ``IDEMPOTENCY_CONFLICT`` (409)
  with its lineage destruction / shard deletion / session blocking / completion
  audit fully rolled back. ``X-Fault-Fail: destruction.after_receipt_check:RAISE``
  additionally proves a generic mid-transaction failure is *not* misreported as
  an idempotency conflict.

Migration-session creation (v1.7, ``scripts.race_migration_start.py``) adds:

* ``migration.after_idem_check`` — after every migration pre-check (idempotency
  lookup, source/target validity, per-source open-session blocker) found no
  blocker, but before the session insert. Two concurrent requests reusing one
  ``Idempotency-Key`` for **two different valid source custody records** park
  here together (their source custody row locks do not overlap), both pass the
  pre-check, and the later session insert hits ``uq_migration_idem_open`` —
  pinning the exact interleaving whose 23505 used to be re-raised as an
  unhandled database error with no denial audit. ``X-Fault-Fail`` values
  ``:RAISE`` and ``:UNIQUE:<non-target-constraint>`` at the same gate prove
  other failures are never misread as that conflict.
* ``migration.after_insert_conflict`` — after the loser's session insert hit
  ``uq_migration_idem_open`` and the savepoint rolled back, but **before** the
  committed winner is re-read. Parking the loser here while the winner's
  session is driven ``open`` → ``completed`` (real custodian share submits)
  or into a terminal state pins the completed-winner race: the re-read must
  adjudicate the committed winner by source custody + target policy version
  (same body → 200 replay, different body → 409 ``IDEMPOTENCY_CONFLICT`` with
  a separate denial audit), and a winner that reached a terminal state
  (``expired``/``failed``/``destroyed``) must not win — the creation is
  re-validated under the post-terminal rebuild rules instead of leaking the
  raw database exception.
* ``migration.before_rebuild_revalidate`` — on the bounded rebuild retry
  (post-terminal winner), after the savepoint rolled back and the conflict
  re-read chose rebuild, but **before** source/target are re-locked and
  revalidated. At this point the request holds only the outer source-custody
  row lock (the policy ``FOR UPDATE`` locks lived inside the rolled-back
  savepoint), so pinning here lets a real target-policy revoke / epoch expiry
  commit first and proves the rebuild rejects with a fresh
  ``clock_timestamp()`` instead of reusing the stale pre-wait policy/time.
* ``migration.before_rebuild_insert`` — on the rebuild retry, after
  revalidation + live-winner/source-blocker checks pass but before the INSERT.
  Pinning here lets a *fresh* open/completed winner appear (or be completed)
  under the same key, and ``X-Fault-Fail`` here injects a rebuild-INSERT
  generic / non-target-23505 failure that must surface as a raw 500.

Each gate is a fresh reached/release event pair per park cycle, so a request
that lists several sequentially-visited gates cannot have one release fall
through into a later listed gate.

Header protocol (only honored when fault injection is enabled):

* ``X-Fault-Gate: <name>``        park at that gate until released
* ``X-Fault-Fail: <name>:<code>`` at that gate raise ``ApiError(code)`` before
                                  parking (used with a gate name that is
                                  visited by the same request; the harness
                                  typically pairs fail-at after_add with
                                  park-at abort_undo).
* ``X-Fault-Fail: <name>:UNIQUE:<constraint>`` raises an
  ``asyncpg.UniqueViolationError`` (SQLSTATE 23505) tagged with the given
  ``constraint_name`` — used to prove that a 23505 from a *non-target*
  constraint is never misclassified as an idempotency / migration conflict.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import asyncpg
from fastapi import Request

from .errors import ApiError, E_INTEGRITY


@dataclass
class _Gate:
    # A fresh ``reached`` event per park cycle. ``park`` publishes a new event
    # (signaling the harness) and waits on a paired ``release`` event; the harness
    # waits on the current reached event and sets the release event. Because each
    # cycle uses brand-new events, a release can never fall through into a later
    # gate that merely shares the request's gate list.
    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


class FaultBoard:
    """Per-process gate registry; one gate per (name, token) pair.

    Gates are **reusable across park/release cycles**, and a request may list
    several gates visited sequentially (e.g. the migration creation loser parks
    at ``after_insert_conflict``, is released, rebuilds, then parks at
    ``before_rebuild_revalidate`` / ``before_rebuild_insert``). Every park
    publishes a *fresh* reached/release event pair under the gate lock, so each
    reached→release handshake is independent: a release at one cycle can never
    fall through into a later gate that merely happens to be listed by the same
    request.
    """

    def __init__(self) -> None:
        self._gates: dict[str, _Gate] = {}
        self._lock = asyncio.Lock()

    async def _gate(self, key: str) -> _Gate:
        """Return the gate for ``key``, creating it on first use.

        The caller must already hold ``self._lock``.
        """
        gate = self._gates.get(key)
        if gate is None:
            gate = _Gate()
            self._gates[key] = gate
        return gate

    async def wait_reached(self, key: str, timeout: float = 10.0) -> None:
        """Wait until the next park cycle at ``key`` signals reached.

        The harness always calls this before releasing that cycle, so it may run
        either after the coroutine parked (the current reached event is already
        set → returns at once) or before (it waits on that same current event).
        """
        async with self._lock:
            gate = await self._gate(key)
            event = gate.reached
        await asyncio.wait_for(event.wait(), timeout=timeout)

    async def release_gate(self, key: str) -> None:
        """Release the park cycle currently parked at ``key`` and arm a fresh pair."""
        async with self._lock:
            gate = self._gates[key]
            gate.release.set()
            # Arm the next cycle with brand-new events, so the following park() blocks
            # independently (a release can never satisfy a later, still-listed gate).
            gate.reached = asyncio.Event()
            gate.release = asyncio.Event()

    async def park(self, key: str, timeout: float = 30.0) -> None:
        """Block at gate ``key`` until :meth:`release_gate` releases this cycle."""
        async with self._lock:
            gate = await self._gate(key)  # creates the gate on first park
            reached = gate.reached
            release = gate.release
            reached.set()
        # Wait on the events captured for THIS cycle; a concurrent release_gate
        # rotates gate.reached/release but cannot affect these captured objects.
        await asyncio.wait_for(release.wait(), timeout=timeout)


def enabled(request: Request) -> bool:
    settings = getattr(request.app.state, "fault_enabled", False)
    return bool(settings)


async def maybe_raise(request: Request, gate: str) -> None:
    """Raise the injected fault when X-Fault-Fail points at ``gate``.

    Spec ``<gate>:<ERROR_CODE>`` raises a deterministic ``ApiError`` (mirrors a
    failed audit append / reconstruction); ``<gate>:RAISE`` raises a plain
    ``RuntimeError`` (mirrors a connection abort hitting the generic path);
    ``<gate>:UNIQUE:<constraint>`` raises an ``asyncpg.UniqueViolationError``
    carrying that (possibly non-target) constraint name (mirrors an unrelated
    unique index hit that must never be misreported as an idempotency conflict).
    """
    if not enabled(request):
        return
    spec = request.headers.get("x-fault-fail")
    if not spec:
        return
    name, _, rest = spec.partition(":")
    if name != gate:
        return
    if rest == "RAISE":
        raise RuntimeError(f"injected generic fault at {gate}")
    if rest.startswith("UNIQUE:"):
        exc = asyncpg.UniqueViolationError(
            f"duplicate key value violates synthetic constraint at {gate}"
        )
        exc.constraint_name = rest[len("UNIQUE:"):]
        raise exc
    raise ApiError(rest or E_INTEGRITY, basis={"reason": "injected_fault", "gate": gate})


async def maybe_park(request: Request, gate: str) -> None:
    """Park when X-Fault-Gate names ``gate``; keyed by X-Fault-Key for isolation.

    The header may list several gates, comma-separated, so one request can be
    pinned at more than one point of its lifecycle (e.g. ``after_add`` and the
    later ``abort_undo`` on the failure path).
    """
    if not enabled(request):
        return
    wanted = {g.strip() for g in request.headers.get("x-fault-gate", "").split(",") if g.strip()}
    if gate not in wanted:
        return
    board: FaultBoard = request.app.state.fault_board
    token = request.headers.get("x-fault-key", "default")
    await board.park(f"{gate}:{token}")
