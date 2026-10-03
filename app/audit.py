from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import asyncpg


def canon_ts(value: Any) -> str:
    """时间戳的唯一规范化表示（UTC，微秒精度），保证哈希可复现。"""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if isinstance(value, datetime):
        value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)

# 全局串行化审计追加，防止哈希链分叉（事务级咨询锁）。
AUDIT_LOCK_KEY = 0x4B564C54  # "KVLT"

CANONICAL_FIELDS = (
    "created_at",
    "tenant_id",
    "actor_type",
    "actor_id",
    "action",
    "resource",
    "result",
    "error_code",
    "basis",
    "prev_hash",
)


def canonical_entry(entry: dict[str, Any]) -> bytes:
    return json.dumps(
        {k: entry.get(k) for k in CANONICAL_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode()


def _hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_entry(entry)).hexdigest()


async def append_audit(
    conn: asyncpg.Connection,
    *,
    tenant_id: str | None,
    actor_type: str,
    actor_id: str | None,
    action: str,
    resource: str | None,
    result: str,
    error_code: str | None = None,
    basis: dict[str, Any] | None = None,
    created_at: Any = None,  # timestamp; caller may pass now()::text for determinism
) -> int:
    """Append inside the caller's transaction. Never include secret material."""
    await conn.execute("SELECT pg_advisory_xact_lock($1)", AUDIT_LOCK_KEY)
    # 注意：不要把 MAX(seq) 与另一个含 ORDER BY seq 的标量子查询合并到同一 SELECT——
    # 在空表上会触发 PG min/max 聚合优化与子查询排序路径的列解析冲突
    # ("column seq does not exist")。两条独立查询即可。
    max_seq = await conn.fetchval("SELECT COALESCE(MAX(seq), 0) FROM audit_log")
    # 哈希链按作用域（租户）分别衔接；seq 仍全局单调，保证整体按序可重放。
    prev_hash = await conn.fetchval(
        """
        SELECT COALESCE((
            SELECT entry_hash FROM audit_log
            WHERE tenant_id IS NOT DISTINCT FROM $1
            ORDER BY seq DESC LIMIT 1
        ), '')
        """,
        tenant_id,
    )
    if created_at is None:
        created_at = await conn.fetchval("SELECT now()")
    ts_canonical = canon_ts(created_at)
    entry = {
        "created_at": ts_canonical,
        "tenant_id": tenant_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "resource": resource,
        "result": result,
        "error_code": error_code,
        "basis": _scrub(basis or {}),
        "prev_hash": prev_hash,
    }
    entry_hash = _hash(entry)
    await conn.execute(
        """
        INSERT INTO audit_log
            (seq, tenant_id, actor_type, actor_id, action, resource, result,
             error_code, basis, prev_hash, entry_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12::timestamptz)
        """,
        max_seq + 1,
        entry["tenant_id"],
        entry["actor_type"],
        entry["actor_id"],
        entry["action"],
        entry["resource"],
        entry["result"],
        entry["error_code"],
        json.dumps(entry["basis"], sort_keys=True, separators=(",", ":")),
        entry["prev_hash"],
        entry_hash,
        datetime.strptime(ts_canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc),
    )
    return max_seq + 1


_SECRET_KEY_HINTS = ("secret", "private", "ciphertext", "plaintext", "share_blob", "nonce", "key")


def _scrub(basis: dict[str, Any]) -> dict[str, Any]:
    """Defense in depth: drop fields whose name looks secret-bearing."""
    clean: dict[str, Any] = {}
    for k, v in basis.items():
        if any(hint in k.lower() for hint in _SECRET_KEY_HINTS):
            continue
        clean[k] = v
    return clean


async def replay(conn: asyncpg.Connection, tenant_id: str | None = None) -> dict[str, Any]:
    """重放并校验。tenant_id 非空时只校验该租户链；否则校验全部作用域链。"""
    if tenant_id is not None:
        rows = await conn.fetch(
            "SELECT * FROM audit_log WHERE tenant_id = $1 ORDER BY seq", tenant_id
        )
    else:
        rows = await conn.fetch("SELECT * FROM audit_log ORDER BY seq")
    # 每个作用域各自的链头
    heads: dict[str | None, str] = {}
    entries = []
    for r in rows:
        scope = r["tenant_id"]
        prev = heads.get(scope, "")
        entry = {
            "created_at": canon_ts(r["created_at"]),
            "tenant_id": r["tenant_id"],
            "actor_type": r["actor_type"],
            "actor_id": r["actor_id"],
            "action": r["action"],
            "resource": r["resource"],
            "result": r["result"],
            "error_code": r["error_code"],
            "basis": json.loads(r["basis"] or "{}"),
            "prev_hash": r["prev_hash"],
        }
        expect = _hash(entry)
        ok = r["prev_hash"] == prev and r["entry_hash"] == expect
        entries.append({"seq": r["seq"], "action": r["action"],
                        "tenant_id": r["tenant_id"],
                        "entry_hash": r["entry_hash"], "chain_valid": ok})
        if not ok:
            return {"valid": False, "broken_at_seq": r["seq"], "entries": entries}
        heads[scope] = r["entry_hash"]
    return {"valid": True, "entries": entries,
            "heads": {("__system__" if k is None else k): v for k, v in heads.items()}}
