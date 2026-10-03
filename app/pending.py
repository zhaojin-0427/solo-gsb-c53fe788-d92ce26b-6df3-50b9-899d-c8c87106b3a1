"""In-memory accumulation of verified submitted shard blobs.

Security properties:

* Only blobs whose ownership / point / inventory-digest were checked and whose
  custodian signature was verified ever reach this store.
* Blobs are **never persisted**: nothing is written to disk, logs or audit rows
  beyond the shard digest. A process restart simply loses the pending blobs;
  the caller then starts a fresh recovery session.
* Submissions to one session are serialized by a ``recovery_sessions`` row lock
  in the router, so no locking is required here.

Withdrawal boundary (v1.3):

* ``add`` returns an opaque, per-insertion **token**. On a failed transaction
  the router may only ``discard`` its *own* token. A stale request (e.g. one
  whose rollback races a successful retry by the same custodian) therefore can
  never remove a newer committed share — even if the ordering between the
  in-memory retraction and the lock release were ever disturbed.
* Reconstruction only ever reads ``get_points``; the router guarantees that,
  while it holds the session row lock, every entry in the store is backed by a
  committed ``share_submissions`` row of the same transaction.
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class PendingToken:
    """Identity of one request's single pending insertion.

    A request discards exactly the entry it created — never another request's
    entry for the same custodian (e.g. a committed retry).
    """

    session_id: str
    custodian_id: str
    serial: int


class PendingShareStore:
    def __init__(self, ttl_seconds: int = 900, max_sessions: int = 10_000) -> None:
        self._sessions: dict[str, dict] = {}
        self._ttl = ttl_seconds
        self._max = max_sessions
        self._next_serial = 0

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    def add(self, session_id: str, custodian_id: str, point_x: int, blob: bytes) -> PendingToken:
        sess = self._sessions.get(session_id)
        if sess is None:
            self._evict_if_full()
            sess = {"shares": {}, "added_at": self._now()}
            self._sessions[session_id] = sess
        self._next_serial += 1
        token = PendingToken(session_id, custodian_id, self._next_serial)
        sess["shares"][custodian_id] = (point_x, blob, token)
        return token

    def get_points(self, session_id: str) -> list[tuple[int, bytes]]:
        sess = self._sessions.get(session_id)
        if sess is None:
            return []
        return [(point_x, blob) for point_x, blob, _ in sess["shares"].values()]

    def count(self, session_id: str) -> int:
        sess = self._sessions.get(session_id)
        return 0 if sess is None else len(sess["shares"])

    def has(self, session_id: str, custodian_id: str) -> bool:
        sess = self._sessions.get(session_id)
        return sess is not None and custodian_id in sess["shares"]

    def discard(self, token: PendingToken) -> bool:
        """Retract exactly this request's insertion.

        Returns ``True`` only when the live entry still belonged to ``token``.
        If a newer request (a committed retry by the same custodian) replaced
        the entry meanwhile, that newer share is preserved untouched.
        """
        sess = self._sessions.get(token.session_id)
        if sess is None:
            return False
        entry = sess["shares"].get(token.custodian_id)
        if entry is None or entry[2] != token:
            # 不是本次插入（已被同托管人重试的新分片替换）：保留新分片。
            return False
        del sess["shares"][token.custodian_id]
        if not sess["shares"]:
            self._sessions.pop(token.session_id, None)
        return True

    def clear(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def _evict_if_full(self) -> None:
        if len(self._sessions) < self._max:
            return
        oldest = min(self._sessions, key=lambda sid: self._sessions[sid]["added_at"])
        self._sessions.pop(oldest, None)

    def sweep(self) -> int:
        """Drop pending blobs for sessions whose accumulation window elapsed."""
        deadline = self._now() - self._ttl
        stale = [sid for sid, sess in self._sessions.items() if sess["added_at"] < deadline]
        for sid in stale:
            self._sessions.pop(sid, None)
        return len(stale)
