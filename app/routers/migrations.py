"""Cross-policy key migration sessions.

Flow (mirrors the recovery protocol, minus the one-time wrap):

1. Tenant creates a migration session for a still-valid custody record, naming
   another valid policy version, supplying an **idempotency key** header. The
   session binds both the source and the target policy-version **digests**.
2. Source-policy custodians obtain a one-time nonce, claim their own source
   shard (plaintext appears only in that response), sign the migration
   canonical message and submit shard + signature.
3. When the source threshold is reached the server reconstructs the secret
   **in request memory only** from verified submitted shards, immediately
   re-shards under the target policy, and writes the new custody + encrypted
   shard rows in the **same transaction**; the source record is never touched.
4. If the in-memory pending shards were lost meanwhile (process restart or
   pool eviction) the session can never reach the threshold again — committed
   submissions cannot be re-sent (unique constraint + spent nonces). The
   submission that first detects the gap therefore, **while still holding the
   session row lock**, retracts its own in-memory/DB share, marks the session
   ``failed`` (a queryable terminal state that frees the open-place unique
   indexes) and appends a plaintext-free audit entry — all in one transaction.
   Waiting submitters then fail fast with ``MIGRATION_FAILED`` instead of
   completing, and the tenant can immediately re-start the migration from the
   source record with a fresh (or the same) idempotency key.

Plaintext (secret / submitted shard / nonce) never appears in responses beyond
the existing claim channel, never in the database (only digests) and never in
audit rows. Revoked/expired versions, cross-tenant references, concurrent and
repeated migrations are rejected; distinct idempotency keys can never migrate
the same custody twice; deterministic failures are safe retries.

Concurrent first-time uses of one ``Idempotency-Key`` against **two different
valid source custody records** cannot be serialized by the source row locks
(they are disjoint), so both requests can pass every pre-check; the loser's
session insert then hits ``uq_migration_idem_open``. The unique-violation
handler classifies by the **actual constraint name** (never by SQLSTATE
alone): that partial index with a committed winner bound to a different
request degrades to a deterministic 409 ``IDEMPOTENCY_CONFLICT`` and a
separate ``migration.start`` denial audit, with the loser's session insert and
success audit rolled back (it leaves no session); the same key with the same
request body replays the committed winner (200); the per-source open/completed
indexes yield 409 ``MIGRATION_CONFLICT``; any other 23505 or database error is
re-raised verbatim and never misreported as a conflict.

The winner re-read after the savepoint rollback uses the **same liveness
predicate as the idempotent-replay lookup** (``open`` and ``completed`` both
count as live winners): the winner's session may transition ``open`` →
``completed`` (source threshold reached) between its commit and the loser's
re-read, and a completed session is still bound to the idempotency key —
reading only ``open`` rows would miss that committed winner and re-raise the
database exception with no denial audit. Rows in a terminal state
(``expired``/``failed``/``destroyed``) never act as the winner: if the row
that held the index has since terminated, the key placeholder is free and the
creation is **re-adjudicated as a brand-new request arriving after the
terminal transition** — not retried with the transaction's pre-wait snapshot.
The source custody row and both immutable policy-version rows are re-read,
the target version row is taken ``FOR UPDATE`` so the rebuild insert and a
concurrent target revoke are ordered by their commits (custody row locked
first, per the global order), every validity/epoch check uses a fresh
``clock_timestamp()`` (epoch windows expiring while the request waited on a
lock can never pass on the transaction's frozen start time), and the bound
policy digests are recomputed. A target that was revoked/expired during the
wait fails the rebuild with ``MIGRATION_TARGET_INVALID`` and a separate
denial audit — no open session and no success audit are ever left behind;
only a still-valid request creates the rebuilt session. A *new* winner that
appears during the rebuild wait keeps the standard adjudication: same
request body replays it (200), a different body gets
``IDEMPOTENCY_CONFLICT`` (409), a committed winner is replayable, and
non-target database errors propagate verbatim.
"""
from __future__ import annotations

import datetime

import asyncpg
from fastapi import APIRouter, Header, Request, Response

from .. import audit, crypto, deps, faults, repo
from ..config import get_settings
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_BAD_SIGNATURE,
    E_CROSS_POLICY_SHARE,
    E_CUSTODY_DESTROYED,
    E_DUPLICATE_SHARE,
    E_EPOCH_EXPIRED,
    E_EPOCH_REVOKED,
    E_FORBIDDEN,
    E_IDEMPOTENCY_CONFLICT,
    E_INTEGRITY,
    E_MIGRATION_COMPLETED,
    E_MIGRATION_CONFLICT,
    E_MIGRATION_DIGEST_MISMATCH,
    E_MIGRATION_FAILED,
    E_MIGRATION_SOURCE_INVALID,
    E_MIGRATION_TARGET_INVALID,
    E_NONCE_USED,
    E_NOT_FOUND,
    E_SESSION_EXPIRED,
    E_SHARE_DIGEST,
    E_SHARE_POINT,
    E_THRESHOLD_NOT_MET,
)
from ..schemas import (
    MigrationNonceOut,
    MigrationNonceRequestIn,
    MigrationSessionOut,
    MigrationShardClaimIn,
    MigrationShardClaimOut,
    MigrationShareSubmitIn,
    MigrationShareSubmitOut,
    MigrationStartIn,
)

router = APIRouter(tags=["migrations"])


def _digest_of_policy(p) -> str:
    """Digest of an immutable policy version row (timestamps canonicalized)."""
    return crypto.policy_version_digest(
        policy_id=p["id"],
        version=p["version"],
        tenant_id=p["tenant_id"],
        threshold=p["threshold"],
        custodian_ids=list(p["custodian_ids"]),
        epoch_index=p["epoch_index"],
        epoch_valid_from=audit.canon_ts(p["epoch_valid_from"]),
        epoch_valid_until=audit.canon_ts(p["epoch_valid_until"]),
        rotation_interval=p["rotation_interval"],
    )


def _session_out(mig, shares_received: int, source_threshold: int,
                 new_shard_count: int | None = None,
                 new_shard_digests: list[str] | None = None) -> MigrationSessionOut:
    return MigrationSessionOut(
        migration_id=mig["id"],
        source_custody_id=mig["source_custody_id"],
        source_policy_id=mig["source_policy_id"],
        source_version=mig["source_version"],
        source_digest=mig["source_digest"],
        target_policy_id=mig["target_policy_id"],
        target_version=mig["target_version"],
        target_digest=mig["target_digest"],
        status=mig["status"],
        valid_until=mig["valid_until"],
        shares_received=shares_received,
        threshold=source_threshold,
        new_custody_id=mig["new_custody_id"],
        new_shard_count=new_shard_count,
        new_shard_digests=new_shard_digests,
    )


async def _source_shard(conn, custody_id: str, custodian_id: str):
    return await conn.fetchrow(
        "SELECT id, point_x, ciphertext, shard_digest FROM shards "
        "WHERE custody_id=$1 AND custodian_id=$2",
        custody_id, custodian_id,
    )


async def _lock_source_custody(conn, mig):
    """Lock the lineage source custody in the global order and detect destruction.

    Every migration gate (nonce / claim / submit) takes the source custody row
    lock before acting, so a concurrent logical destruction has a deterministic
    ordering: once it commits, a queued gate re-reads ``destroyed`` and fails
    with CUSTODY_DESTROYED instead of issuing a nonce or handing out a shard.
    """
    row = await conn.fetchrow(
        "SELECT id, status FROM key_custodies WHERE id=$1 FOR UPDATE",
        mig["source_custody_id"],
    )
    if row is None:
        raise ApiError(
            E_INTEGRITY,
            basis={"reason": "source_custody_missing",
                   "source_custody_id": mig["source_custody_id"]},
        )
    if row["status"] == "destroyed":
        raise ApiError(
            E_CUSTODY_DESTROYED,
            basis={"migration_id": mig["id"], "source_custody_id": mig["source_custody_id"],
                   "reason": "source_custody_destroyed"},
        )
    return row


async def _resolve_nonce(conn, migration_id: str, nonce_hex: str, custodian_id: str):
    try:
        nonce_hash = crypto.sha256_hex(bytes.fromhex(nonce_hex))
    except ValueError:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_malformed"})
    nonce_row = await conn.fetchrow(
        "SELECT * FROM migration_nonces WHERE nonce_hash=$1 FOR UPDATE", nonce_hash
    )
    if nonce_row is None:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_unknown"})
    if nonce_row["migration_id"] != migration_id or nonce_row["custodian_id"] != custodian_id:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"reason": "nonce_binding_mismatch", "migration_id": migration_id,
                   "custodian_id": custodian_id},
        )
    return nonce_row


def _check_digests(mig, source_policy, target_policy) -> None:
    """Re-verify the bound source/target version digests against immutable rows."""
    source_digest = _digest_of_policy(source_policy)
    if not crypto.constant_time_hex_equal(source_digest, mig["source_digest"]):
        raise ApiError(
            E_MIGRATION_DIGEST_MISMATCH,
            basis={"which": "source", "policy_id": mig["source_policy_id"],
                   "version": mig["source_version"], "bound_digest": mig["source_digest"],
                   "actual_digest": source_digest},
        )
    target_digest = _digest_of_policy(target_policy)
    if not crypto.constant_time_hex_equal(target_digest, mig["target_digest"]):
        raise ApiError(
            E_MIGRATION_DIGEST_MISMATCH,
            basis={"which": "target", "policy_id": mig["target_policy_id"],
                   "version": mig["target_version"], "bound_digest": mig["target_digest"],
                   "actual_digest": target_digest},
        )


async def _guard_migration(conn, mig, source_policy, target_policy, now,
                           custodian_id: str | None) -> None:
    """Gates shared by nonce issue / shard claim / share submit."""
    # 逻辑销毁终态：源记录谱系的在线分片已删除、迁移已被显式阻断。
    # 销毁提交后旧会话的一切请求确定性拒绝——绝不再下发源分片，也绝不可能
    # 完成迁移而生成“漏删的后代记录”。
    if mig["status"] == "destroyed":
        raise ApiError(
            E_CUSTODY_DESTROYED,
            basis={"migration_id": mig["id"], "reason": "migration_session_destroyed",
                   "source_custody_id": mig["source_custody_id"]},
        )
    if mig["status"] == "completed":
        raise ApiError(E_MIGRATION_COMPLETED, basis={"migration_id": mig["id"]})
    if mig["status"] == "failed":
        # 缺片终态：已计数分片的内存明文曾丢失，会话永远无法再凑齐门限。
        # 任何在途/后续请求一律确定性拒绝，调用方用新会话重来。
        raise ApiError(
            E_MIGRATION_FAILED,
            basis={"migration_id": mig["id"], "reason": "migration_session_failed",
                   "source_custody_id": mig["source_custody_id"]},
        )
    if mig["status"] == "expired" or now >= mig["valid_until"]:
        raise ApiError(E_SESSION_EXPIRED,
                       basis={"valid_until": str(mig["valid_until"]), "now": str(now)})
    _check_digests(mig, source_policy, target_policy)
    # 迁移进行中源策略版本被撤销/过期：在途份额一律拒绝。
    if source_policy["status"] == "revoked":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["source_policy_id"], "version": mig["source_version"],
                   "epoch": source_policy["epoch_index"]},
        )
    if now >= source_policy["epoch_valid_until"]:
        raise ApiError(E_EPOCH_EXPIRED, basis={"epoch": source_policy["epoch_index"]})
    # 目标版本同样必须在迁移完成前保持有效（已撤销则迁移不再有意义）。
    if target_policy["status"] == "revoked":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["target_policy_id"], "version": mig["target_version"],
                   "epoch": target_policy["epoch_index"], "which": "target"},
        )
    if now >= target_policy["epoch_valid_until"]:
        raise ApiError(
            E_EPOCH_EXPIRED,
            basis={"epoch": target_policy["epoch_index"], "which": "target"},
        )
    if custodian_id is not None and custodian_id not in source_policy["custodian_ids"]:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"custodian_id": custodian_id, "policy_id": mig["source_policy_id"],
                   "policy_version": mig["source_version"],
                   "reason": "not_member_of_source_policy_version"},
        )


# ---------------------------------------------------------------------------
# Tenant endpoints
# ---------------------------------------------------------------------------

@router.post("/migrations", response_model=MigrationSessionOut, status_code=201)
async def start_migration(
    body: MigrationStartIn,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant=deps.Tenant,
):
    settings = get_settings()
    if not idempotency_key or not 1 <= len(idempotency_key) <= 200:
        raise ApiError(E_BAD_REQUEST,
                       basis={"reason": "missing_or_malformed_idempotency_key",
                              "header": "Idempotency-Key", "max_length": 200})
    idem_hash = crypto.sha256_hex(idempotency_key.encode())
    pool = request.app.state.db.pool
    ttl = body.ttl_seconds or settings.recovery_default_ttl
    ttl = min(ttl, settings.recovery_max_ttl)

    mig_row = None
    source_threshold = 0
    out_count = 0
    out_new_digests: list[str] | None = None
    replayed = False

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():

                async def _clock_now():
                    # 决策时间必须取“语句当前时间”而非事务开始时间：请求在源
                    # custody 行锁/唯一索引冲突上等待期间 epoch 可能恰好到期，
                    # now()/transaction_timestamp() 在整个事务内冻结为开始时刻，
                    # 会用旧时间把等待后才失效的源/目标误放行。重建裁决的每次
                    # 尝试都重新取时钟。
                    return await conn.fetchval("SELECT clock_timestamp()")

                async def _expire_stale_open(custody):
                    # 惰性过期：超过 TTL、或源侧已失效（custody 被轮换/撤销、源
                    # 策略版本被撤销/过期）的 open 会话在同源新事务（本事务随后
                    # 提交）中置 expired，释放两条部分唯一索引——失败后可用同键
                    # 或新键安全重试，且不会被一个“永远无法再完成”的 open 会话
                    # 无限占位。判据一律用 clock_timestamp()，等待期间跨过 TTL /
                    # epoch 边界不会被事务开始时的旧时间放行。
                    await conn.execute(
                        """
                        UPDATE migration_sessions m SET status='expired'
                        FROM key_custodies kc
                        JOIN policies p ON p.id = kc.policy_id AND p.version = kc.policy_version
                        WHERE m.source_custody_id = $1 AND m.status = 'open'
                          AND kc.id = m.source_custody_id
                          AND (clock_timestamp() >= m.valid_until
                               OR kc.status <> 'active'
                               OR p.status = 'revoked'
                               OR clock_timestamp() >= p.epoch_valid_until)
                        """,
                        custody["id"],
                    )

                async def _prepare_creation(*, lock_target: bool):
                    """Re-validate the creation and return the insert inputs.

                    ``lock_target`` is only set on a **post-terminal rebuild**
                    attempt (the savepoint rolled back after the unique-index
                    race and the key placeholder is free again). The rebuild is
                    a brand-new creation decision arriving after a wait: source
                    custody / source policy version / target policy version are
                    all re-read fresh, the target policy version row is taken
                    ``FOR UPDATE`` to arbitrate the rebuild-insert versus a
                    concurrent policy revoke (their commit order then decides
                    deterministically, in the custody-row-before-other-row lock
                    order), and every validity / epoch check uses a fresh
                    ``clock_timestamp()`` — never the policy rows, policy
                    digests or wall time captured at the transaction's start.

                    The first attempt deliberately does not lock the target
                    row, so a tenant revoking a still-unreferenced target
                    version is not blocked behind creation requests parked at
                    test gates; the rebuild path is the only path whose
                    decision happens after a blocking wait.
                    """
                    custody = await conn.fetchrow(
                        "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE",
                        body.source_custody_id,
                    )
                    if custody is None:
                        raise ApiError(E_NOT_FOUND, basis={"custody_id": body.source_custody_id})
                    if custody["tenant_id"] != tenant["id"]:
                        raise ApiError(E_FORBIDDEN,
                                       basis={"reason": "custody_belongs_to_other_tenant"})
                    if custody["status"] == "destroyed":
                        raise ApiError(
                            E_CUSTODY_DESTROYED,
                            basis={"custody_id": custody["id"], "custody_status": custody["status"]},
                        )
                    await _expire_stale_open(custody)
                    source_policy = await repo.get_policy_version(
                        conn, custody["policy_id"], custody["policy_version"]
                    )
                    now = await _clock_now()

                    # 幂等重放优先：同键的已有会话（open/completed）原样返回；
                    # expired/failed/destroyed 行不占位（唯一索引不含三者），
                    # 终态后允许用同一幂等键（或新键）从源记录安全重新发起。
                    existing = await conn.fetchrow(
                        "SELECT * FROM migration_sessions "
                        "WHERE tenant_id=$1 AND idempotency_key_hash=$2 "
                        "AND status NOT IN ('expired','failed','destroyed') "
                        "ORDER BY created_at DESC LIMIT 1",
                        tenant["id"], idem_hash,
                    )
                    if existing is not None:
                        return ("existing", existing)

                    # 源必须仍有效：托管记录 active 且其策略版本未撤销/未过期。
                    # 重建尝试时这些行全部按等待后的新状态重读——绝不复用事务
                    # 开始时（可能更早的裁决前）的旧快照与旧时间。
                    if custody["status"] != "active" or source_policy["status"] == "revoked":
                        raise ApiError(
                            E_MIGRATION_SOURCE_INVALID,
                            basis={"custody_id": custody["id"],
                                   "custody_status": custody["status"],
                                   "policy_id": custody["policy_id"],
                                   "version": custody["policy_version"],
                                   "policy_status": source_policy["status"]},
                        )
                    if now >= source_policy["epoch_valid_until"]:
                        raise ApiError(
                            E_MIGRATION_SOURCE_INVALID,
                            basis={"reason": "source_epoch_expired",
                                   "valid_until": str(source_policy["epoch_valid_until"]),
                                   "now": str(now)},
                        )

                    # 目标必须是另一条有效策略版本，且属于同一租户。
                    if (
                        body.target_policy_id == custody["policy_id"]
                        and body.target_version == custody["policy_version"]
                    ):
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_identical_to_source",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version},
                        )
                    if lock_target:
                        # 重建裁决：锁住目标不可变版本行，与并发的策略撤销/轮换
                        # 以提交先后确定性裁决——先提交撤销则下面只读到 revoked
                        # 并以 MIGRATION_TARGET_INVALID 拒绝；先提交本插入则撤销
                        # 等待，新会话按其创建时刻的有效版本固化摘要。锁序上
                        # 源 custody 行已先行持有（custody 先于其它行），不会与
                        # 销毁/提交路径形成锁序反转。
                        target_policy = await conn.fetchrow(
                            "SELECT * FROM policies WHERE id=$1 AND version=$2 FOR UPDATE",
                            body.target_policy_id, body.target_version,
                        )
                        # 回归闸门：重建已持目标版本行锁、尚未完成裁决与重试
                        # INSERT（仅测试构建启用）——钉住“重建插入 × 目标撤销”
                        # 的真实行锁排队，验证二者提交先后的确定性。
                        await faults.maybe_park(
                            request, "migration.rebuild_target_locked")
                    else:
                        target_policy = await repo.get_policy_version(
                            conn, body.target_policy_id, body.target_version
                        )
                    if target_policy is None:
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_version_not_found",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version},
                        )
                    if target_policy["tenant_id"] != tenant["id"]:
                        raise ApiError(
                            E_FORBIDDEN,
                            basis={"reason": "target_policy_belongs_to_other_tenant"},
                        )
                    if target_policy["status"] != "active":
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_policy_revoked",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version,
                                   "status": target_policy["status"]},
                        )
                    if now >= target_policy["epoch_valid_until"]:
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_epoch_expired",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version,
                                   "valid_until": str(target_policy["epoch_valid_until"]),
                                   "now": str(now)},
                        )

                    # 参数全部合法后再判“重复”：同 custody 的其他 open 会话，或
                    # 已迁移完成。重建尝试时同样重读，等待期间源上出现的新赢家
                    # 在此被确定性拦截。不同幂等键不得重复迁移。
                    blocker = await conn.fetchrow(
                        "SELECT id, status, new_custody_id FROM migration_sessions "
                        "WHERE source_custody_id=$1 AND "
                        "(status='open' OR new_custody_id IS NOT NULL) "
                        "ORDER BY created_at DESC LIMIT 1",
                        custody["id"],
                    )
                    if blocker is not None:
                        if blocker["new_custody_id"] is not None:
                            raise ApiError(
                                E_MIGRATION_CONFLICT,
                                basis={"reason": "custody_already_migrated",
                                       "migration_id": blocker["id"],
                                       "source_custody_id": custody["id"]},
                            )
                        raise ApiError(
                            E_MIGRATION_CONFLICT,
                            basis={"reason": "open_migration_exists_for_custody",
                                   "migration_id": blocker["id"],
                                   "source_custody_id": custody["id"]},
                        )

                    # 摘要必须在每次裁决时由刚读取（重建时为持锁读取）的不可变
                    # 版本行重新计算：等待期间目标被轮换/撤销后，旧快照旧摘要
                    # 绝不能被复用进新会话。
                    source_digest = _digest_of_policy(source_policy)
                    target_digest = _digest_of_policy(target_policy)
                    valid_until = now + datetime.timedelta(seconds=ttl)
                    return ("create", {
                        "custody": custody,
                        "source_policy": source_policy,
                        "source_digest": source_digest,
                        "target_digest": target_digest,
                        "valid_until": valid_until,
                    })

                prepared = await _prepare_creation(lock_target=False)
                if prepared[0] == "existing":
                    existing = prepared[1]
                    if (
                        existing["source_custody_id"] != body.source_custody_id
                        or existing["target_policy_id"] != body.target_policy_id
                        or existing["target_version"] != body.target_version
                    ):
                        raise ApiError(
                            E_IDEMPOTENCY_CONFLICT,
                            basis={"reason": "key_bound_to_different_request",
                                   "idempotency_key_digest": idem_hash},
                        )
                    count = await conn.fetchval(
                        "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1",
                        existing["id"],
                    )
                    new_digests = None
                    if existing["new_custody_id"] is not None:
                        rows = await conn.fetch(
                            "SELECT shard_digest FROM shards "
                            "WHERE custody_id=$1 ORDER BY point_x",
                            existing["new_custody_id"],
                        )
                        new_digests = [r["shard_digest"] for r in rows]
                    mig_row = existing
                    out_count = count
                    out_new_digests = new_digests
                    replayed = True
                    source_threshold = (
                        await repo.get_policy_version(
                            conn, mig_row["source_policy_id"], mig_row["source_version"]
                        )
                    )["threshold"]
                else:
                    inputs = prepared[1]

                    # 回归闸门：全部预查（幂等键、源/目标有效性、同源在途/
                    # 已完成拦截）均未命中之后、首次 INSERT 之前（仅测试构建启用）。
                    await faults.maybe_park(request, "migration.after_idem_check")
                    await faults.maybe_raise(request, "migration.after_idem_check")

                    migration_id = deps.new_id("mig")
                    # savepoint：唯一索引兜底命中后外层事务仍可用于留痕/返回。
                    # 有界重试：撞 uq_migration_idem_open 的胜方若在重读前已转入
                    # expired/failed/destroyed 终态，则键位已释放——终态行不充当
                    # 赢家，重建必须把请求当作“终态后新到”重新裁决：重新核对源
                    # custody 与源/目标版本行（持目标版本行锁与撤销/轮换排先后），
                    # 用新的 clock_timestamp() 复核有效期并重算摘要；目标已失效则
                    # MIGRATION_TARGET_INVALID、不留会话/成功审计（拒绝由外层独立
                    # 审计事务落库），全部有效才新建。连续 churn 耗尽重试则原样
                    # 上抛最后一次违规，绝不误判。
                    replay_row = None
                    last_exc: asyncpg.UniqueViolationError | None = None
                    for attempt in range(3):
                        try:
                            async with conn.transaction():
                                await conn.execute(
                                    """
                                    INSERT INTO migration_sessions
                                      (id, tenant_id, source_custody_id, source_policy_id,
                                       source_version, source_digest, target_policy_id,
                                       target_version, target_digest, idempotency_key_hash,
                                       status, valid_until)
                                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11)
                                    """,
                                    migration_id, tenant["id"],
                                    inputs["custody"]["id"],
                                    inputs["custody"]["policy_id"],
                                    inputs["custody"]["policy_version"],
                                    inputs["source_digest"],
                                    body.target_policy_id, body.target_version,
                                    inputs["target_digest"], idem_hash,
                                    inputs["valid_until"],
                                )
                        except asyncpg.UniqueViolationError as exc:
                            # 并发兜底：同键 open / 同源 open / 同源已完成都可能在此。
                            # 必须按“实际命中的约束名”分派，绝不能只凭 SQLSTATE=23505：
                            # 其它唯一约束（主键、注入的非目标 23505）必须原样上抛。
                            # 唯一索引的等待解析时胜方事务必然已提交（见
                            # _resolve_unique_conflict 内的可见性复核）。
                            last_exc = exc
                            replay_row = await _resolve_unique_conflict(
                                conn,
                                request=request,
                                exc=exc,
                                tenant_id=tenant["id"],
                                idem_hash=idem_hash,
                                source_custody_id=body.source_custody_id,
                                target_policy_id=body.target_policy_id,
                                target_version=body.target_version,
                            )
                            if replay_row is _RETRY_INSERT:
                                replay_row = None
                                # 终态后重建：按等待后的新状态完整重新裁决。
                                revalidated = await _prepare_creation(lock_target=True)
                                # 重建裁决后、重试 INSERT 之前的专用回归闸门：
                                # 可钉住“重建与撤销/新赢家交错”，也可在该点注入
                                # 非目标数据库错误（必须原样上抛，绝不翻译成目标
                                # 失效或幂等冲突）。
                                await faults.maybe_park(
                                    request, "migration.after_rebuild_recheck")
                                await faults.maybe_raise(
                                    request, "migration.after_rebuild_recheck")
                                if revalidated[0] == "existing":
                                    # 等待期间出现了新的在途/完成赢家：交由循环外
                                    # 的重放逻辑按“同请求重放 / 异请求冲突”裁决。
                                    replay_row = revalidated[1]
                                    break
                                inputs = revalidated[1]
                                continue
                            break
                        else:
                            replay_row = None
                            break
                    else:
                        # 连续重试仍撞索引（病态 churn）：原样上抛，绝不误判。
                        raise last_exc
                    if replay_row is not None:
                        # 同键同请求的并发创建（含重建等待期间出现的新赢家）：
                        # 胜方会话已提交，按幂等重放返回那同一份（200，不新建、
                        # 不重复留痕）。
                        if (
                            replay_row["source_custody_id"] != body.source_custody_id
                            or replay_row["target_policy_id"] != body.target_policy_id
                            or replay_row["target_version"] != body.target_version
                        ):
                            raise ApiError(
                                E_IDEMPOTENCY_CONFLICT,
                                basis={"reason": "concurrent_open_with_same_idempotency_key",
                                       "idempotency_key_digest": idem_hash,
                                       "migration_id": replay_row["id"],
                                       "winner_source_custody_id":
                                           replay_row["source_custody_id"]},
                            )
                        count = await conn.fetchval(
                            "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1",
                            replay_row["id"],
                        )
                        replay_digests = None
                        if replay_row["new_custody_id"] is not None:
                            rows = await conn.fetch(
                                "SELECT shard_digest FROM shards "
                                "WHERE custody_id=$1 ORDER BY point_x",
                                replay_row["new_custody_id"],
                            )
                            replay_digests = [r["shard_digest"] for r in rows]
                        mig_row = replay_row
                        out_count = count
                        out_new_digests = replay_digests
                        replayed = True
                        source_threshold = (
                            await repo.get_policy_version(
                                conn, mig_row["source_policy_id"], mig_row["source_version"]
                            )
                        )["threshold"]
                    else:
                        await audit.append_audit(
                            conn, tenant_id=tenant["id"], actor_type="tenant",
                            actor_id=tenant["id"],
                            action="migration.start", resource=migration_id, result="ok",
                            basis={
                                "source_custody_id": inputs["custody"]["id"],
                                "source_policy_id": inputs["custody"]["policy_id"],
                                "source_version": inputs["custody"]["policy_version"],
                                "source_digest": inputs["source_digest"],
                                "target_policy_id": body.target_policy_id,
                                "target_version": body.target_version,
                                "target_digest": inputs["target_digest"],
                                "ttl_seconds": ttl,
                                "idempotency_key_digest": idem_hash,
                            },
                        )
                        mig_row = await conn.fetchrow(
                            "SELECT * FROM migration_sessions WHERE id=$1", migration_id
                        )
                        out_count, out_new_digests = 0, None
                        source_threshold = inputs["source_policy"]["threshold"]
        except ApiError as exc:
            # 拒绝同样留痕（独立事务），形成可重放审计；不含任何秘密材料。
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="migration.start", resource=body.source_custody_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise

    out = _session_out(mig_row, out_count, source_threshold,
                       new_shard_digests=out_new_digests)
    if replayed:
        # 幂等重放返回同一份结果（200，不新建、不重复留痕）。
        response.status_code = 200
    return out


#: Sentinel returned by :func:`_resolve_unique_conflict` when the row that won
#: the unique race has since reached a terminal state (expired / failed /
#: destroyed): terminal rows never act as the idempotency winner, the key
#: placeholder is free, and the creation is re-validated under the
#: post-terminal rebuild rules (the caller retries the insert, bounded).
_RETRY_INSERT: object = object()


async def _resolve_unique_conflict(
    conn,
    *,
    request: Request,
    exc: asyncpg.UniqueViolationError,
    tenant_id: str,
    idem_hash: str,
    source_custody_id: str,
    target_policy_id: str,
    target_version: int,
):
    """Resolve a session-INSERT unique violation after the savepoint rolled back.

    Classification is driven by the **actual constraint name** carried by the
    database error, never by SQLSTATE alone:

    * ``uq_migration_idem_open`` — another request already committed a session
      under the same ``(tenant, idempotency_key)``. The committed winner is
      re-read with the **same liveness predicate as the idempotent-replay
      lookup** (``open`` and ``completed``; the winner may have transitioned
      ``open`` → ``completed`` between its commit and this re-read, and a
      completed session is still bound to the key). Same request body →
      replay that winner (returns its row, HTTP 200); different source/target
      → deterministic 409 ``IDEMPOTENCY_CONFLICT``. A winner that has since
      reached a terminal state (``expired``/``failed``/``destroyed``) never
      counts: the placeholder is free, so the caller returns
      :data:`_RETRY_INSERT` and **re-adjudicates the creation from scratch** —
      source custody and both policy version rows are re-read, the target
      version row is locked ``FOR UPDATE`` to order the rebuild insert against
      a concurrent policy revoke, validity/epoch windows are checked against a
      fresh ``clock_timestamp()`` and the bound digests are recomputed. A
      target that has meanwhile been revoked/expired therefore fails the
      rebuild deterministically with ``MIGRATION_TARGET_INVALID`` (separate
      denial audit, no session, no success audit) instead of creating an open
      session pinned to a stale target and stale digests.
    * ``uq_migration_source_open`` / ``uq_migration_source_completed`` —
      another open / already-completed session for the same source custody →
      deterministic 409 ``MIGRATION_CONFLICT``.
    * anything else (primary key, unrelated index, synthetic non-target 23505)
      is re-raised verbatim so it can never be misreported as a conflict.

    A partial-unique-index conflict in READ COMMITTED only resolves once the
    winning transaction has committed, so every winner lookup here observes the
    committed row; a missing live row (winner terminated meanwhile) is handled
    as described above instead of leaking the raw database exception.
    """
    constraint = getattr(exc, "constraint_name", None)
    if constraint not in (
        "uq_migration_idem_open",
        "uq_migration_source_open",
        "uq_migration_source_completed",
    ):
        raise exc

    if constraint == "uq_migration_idem_open":
        # 保存点已回滚、重读已提交胜方之前：测试可在此钉住“胜方由 open 转
        # completed / 终态”的交错（仅测试构建启用，见 race_migration_start）。
        await faults.maybe_park(request, "migration.after_insert_conflict")
        # 与主流程幂等重放同一判定：open 与 completed 都是有效赢家（completed
        # 仍绑定该幂等键，可重放）；expired/failed/destroyed 终态行不充当赢家。
        # 只读 status='open' 会漏掉“重读前已由 open 转 completed”的已提交赢家，
        # 把确定性的幂等冲突误判成未处理的数据库异常（500）并漏记拒绝审计。
        winner = await conn.fetchrow(
            "SELECT * FROM migration_sessions "
            "WHERE tenant_id=$1 AND idempotency_key_hash=$2 "
            "AND status NOT IN ('expired','failed','destroyed') "
            "ORDER BY created_at DESC LIMIT 1",
            tenant_id, idem_hash,
        )
        if winner is None:
            # 撞索引的行已转入终态（expired/failed/destroyed）：键位已释放，
            # 终态行不充当赢家——按终态后重建规则重新校验创建（有界重试）。
            return _RETRY_INSERT
        if (
            winner["source_custody_id"] == source_custody_id
            and winner["target_policy_id"] == target_policy_id
            and winner["target_version"] == target_version
        ):
            # 同键同请求的并发创建：重放胜方那一份会话（200，含已完成态）。
            return winner
        raise ApiError(
            E_IDEMPOTENCY_CONFLICT,
            basis={"reason": "concurrent_open_with_same_idempotency_key",
                   "idempotency_key_digest": idem_hash,
                   "migration_id": winner["id"],
                   "winner_source_custody_id": winner["source_custody_id"]},
        )

    if constraint == "uq_migration_source_open":
        other_open = await conn.fetchrow(
            "SELECT id FROM migration_sessions "
            "WHERE source_custody_id=$1 AND status='open' "
            "ORDER BY created_at DESC LIMIT 1",
            source_custody_id,
        )
        if other_open is None:
            raise exc
        raise ApiError(
            E_MIGRATION_CONFLICT,
            basis={"reason": "open_migration_exists_for_custody",
                   "migration_id": other_open["id"],
                   "source_custody_id": source_custody_id},
        )

    done = await conn.fetchrow(
        "SELECT id FROM migration_sessions "
        "WHERE source_custody_id=$1 AND new_custody_id IS NOT NULL "
        "ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1",
        source_custody_id,
    )
    if done is None:
        raise exc
    raise ApiError(
        E_MIGRATION_CONFLICT,
        basis={"reason": "custody_already_migrated", "migration_id": done["id"],
               "source_custody_id": source_custody_id},
    )


@router.get("/migrations/{migration_id}", response_model=MigrationSessionOut)
async def get_migration(migration_id: str, request: Request, tenant=deps.Tenant) -> MigrationSessionOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        mig = await conn.fetchrow("SELECT * FROM migration_sessions WHERE id=$1", migration_id)
        if mig is None:
            raise ApiError(E_NOT_FOUND, basis={"migration_id": migration_id})
        if mig["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "migration_belongs_to_other_tenant"})
        source_policy = await repo.get_policy_version(conn, mig["source_policy_id"], mig["source_version"])
        count = await conn.fetchval(
            "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1", migration_id
        )
        new_digests = None
        if mig["new_custody_id"] is not None:
            new_digests = [
                r["shard_digest"]
                for r in await conn.fetch(
                    "SELECT shard_digest FROM shards WHERE custody_id=$1 ORDER BY point_x",
                    mig["new_custody_id"],
                )
            ]
    return _session_out(mig, count, source_policy["threshold"],
                        new_shard_count=len(new_digests) if new_digests is not None else None,
                        new_shard_digests=new_digests)


# ---------------------------------------------------------------------------
# Custodian endpoints
# ---------------------------------------------------------------------------

@router.post("/migrations/nonces", response_model=MigrationNonceOut)
async def issue_nonce(body: MigrationNonceRequestIn, request: Request,
                      custodian=deps.Custodian) -> MigrationNonceOut:
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    nonce = nonce_id = ""
    point_x = 0
    shard_digest = ""
    mig_row = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            # 全局锁序：源 custody 行先于 migration 会话行（与销毁/提交一致，
            # 杜绝销毁 × nonce 发放的锁序反转死锁）。
            mig_row = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1", body.migration_id
            )
            if mig_row is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            await _lock_source_custody(conn, mig_row)
            mig_row = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            sess_tenant = mig_row["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig_row["source_policy_id"], mig_row["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig_row["target_policy_id"], mig_row["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig_row, source_policy, target_policy, now,
                                   custodian_id=custodian["id"])

            shard = await _source_shard(conn, mig_row["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            point_x = shard["point_x"]
            shard_digest = shard["shard_digest"]

            existing = await conn.fetchrow(
                "SELECT * FROM migration_nonces WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if existing is not None:
                raise ApiError(
                    E_NONCE_USED,
                    basis={
                        "migration_id": body.migration_id,
                        "custodian_id": custodian["id"],
                        "spent": existing["spent"],
                        "reason": "nonce_already_issued" if not existing["spent"] else "nonce_spent",
                    },
                )
            nonce = deps.new_nonce()
            nonce_id = deps.new_id("non")
            await conn.execute(
                """
                INSERT INTO migration_nonces (id, migration_id, custodian_id, nonce_hash, spent)
                VALUES ($1,$2,$3,$4, FALSE)
                """,
                nonce_id, body.migration_id, custodian["id"],
                crypto.sha256_hex(bytes.fromhex(nonce)),
            )
            await audit.append_audit(
                conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.nonce.issue", resource=nonce_id, result="ok",
                basis={"migration_id": body.migration_id,
                       "source_version": mig_row["source_version"],
                       "point_x": point_x, "shard_digest": shard_digest},
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.nonce.issue", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return MigrationNonceOut(
        nonce_id=nonce_id, nonce=nonce, migration_id=body.migration_id,
        custodian_id=custodian["id"],
        source_policy_id=mig_row["source_policy_id"], source_version=mig_row["source_version"],
        source_digest=mig_row["source_digest"],
        target_policy_id=mig_row["target_policy_id"], target_version=mig_row["target_version"],
        target_digest=mig_row["target_digest"],
        point_x=point_x, shard_digest=shard_digest,
    )


@router.post("/migrations/shards/claim", response_model=MigrationShardClaimOut)
async def claim_shard(body: MigrationShardClaimIn, request: Request,
                      custodian=deps.Custodian) -> MigrationShardClaimOut:
    """Authenticated source-policy custodian claims its own source shard.

    Plaintext appears only in this response — never logged, audited or cached.
    """
    settings = get_settings()
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            # 全局锁序：源 custody 行先于 migration 会话行（与销毁/提交一致，
            # 杜绝销毁 × 领片的锁序反转死锁；排队领片在销毁后只得到 410）。
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            await _lock_source_custody(conn, mig)
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            sess_tenant = mig["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig["source_policy_id"], mig["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig["target_policy_id"], mig["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig, source_policy, target_policy, now, custodian["id"])

            nonce_row = await _resolve_nonce(conn, body.migration_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"],
                                                    "reason": "nonce_spent"})

            shard = await _source_shard(conn, mig["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            try:
                blob = crypto.decrypt_shard(
                    settings.shard_master_key_bytes, shard["id"], bytes(shard["ciphertext"])
                )
            except Exception:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_decrypt_failed",
                           "custodian_id": custodian["id"]},
                )
            if not crypto.constant_time_hex_equal(crypto.sha256_hex(blob), shard["shard_digest"]):
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_digest_mismatch",
                           "custodian_id": custodian["id"]},
                )
            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                custodian_id=custodian["id"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
            )
            await audit.append_audit(
                conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id, result="ok",
                basis={"nonce_id": nonce_row["id"], "point_x": shard["point_x"],
                       "shard_digest": shard["shard_digest"]},
            )
            out = MigrationShardClaimOut(
                migration_id=body.migration_id,
                nonce_id=nonce_row["id"],
                custodian_id=custodian["id"],
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_custody_id=mig["source_custody_id"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
                shard_hex=blob.hex(),
                signing_message=message.decode(),
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return out


@router.post("/migrations/shares", response_model=MigrationShareSubmitOut)
async def submit_share(body: MigrationShareSubmitIn, request: Request,
                       custodian=deps.Custodian) -> MigrationShareSubmitOut:
    pool = request.app.state.db.pool
    pending = request.app.state.pending
    sess_tenant: str | None = None
    pending_token = None
    completed = False
    count = 0
    threshold = 0
    new_custody_id: str | None = None
    new_shard_count: int | None = None
    new_shard_digests: list[str] | None = None
    gap_error: ApiError | None = None

    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()

        async def _undo() -> None:
            # 与恢复流程相同的双重撤销边界：行锁仍持有时先凭本次 token
            # 精确撤回内存分片，再回滚；等待者拿锁时内存与数据库已一致。
            nonlocal pending_token
            if pending_token is not None:
                pending.discard(pending_token)
                pending_token = None
            await tx.rollback()

        try:
            # 全局锁序：源 custody 行先于 migration 会话行——与逻辑销毁、恢复
            # 提交路径完全一致，销毁 × 迁移完成永不死锁：销毁先拿到源 custody
            # 则本路径等锁，拿锁后只得到 CUSTODY_DESTROYED；本路径先拿锁则
            # 销毁等待迁移提交完成，随后谱系展开把新后代一并纳入销毁（不漏删）。
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            await _lock_source_custody(conn, mig)
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            await faults.maybe_park(request, "migration.after_lock")
            sess_tenant = mig["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig["source_policy_id"], mig["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig["target_policy_id"], mig["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig, source_policy, target_policy, now, custodian["id"])

            nonce_row = await _resolve_nonce(conn, body.migration_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"]})

            dup = await conn.fetchrow(
                "SELECT 1 FROM migration_share_submissions WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if dup:
                raise ApiError(E_DUPLICATE_SHARE,
                               basis={"migration_id": body.migration_id,
                                      "custodian_id": custodian["id"]})

            shard = await _source_shard(conn, mig["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )

            blob = bytes.fromhex(body.shard_hex)
            if len(blob) > 8192:
                raise ApiError(E_BAD_REQUEST, basis={"reason": "shard_too_large", "bytes": len(blob)})
            if body.point_x != shard["point_x"]:
                raise ApiError(
                    E_SHARE_POINT,
                    basis={"custodian_id": custodian["id"],
                           "submitted_point_x": body.point_x,
                           "expected_point_x": shard["point_x"]},
                )
            submitted_digest = crypto.sha256_hex(blob)
            if not crypto.constant_time_hex_equal(submitted_digest, shard["shard_digest"]):
                raise ApiError(
                    E_SHARE_DIGEST,
                    basis={"custodian_id": custodian["id"], "point_x": body.point_x,
                           "submitted_shard_digest": submitted_digest,
                           "expected_shard_digest": shard["shard_digest"]},
                )

            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                custodian_id=custodian["id"],
                point_x=body.point_x,
                shard_digest=shard["shard_digest"],
            )
            if not crypto.verify_signature(custodian["signing_pubkey"], message,
                                           bytes.fromhex(body.signature)):
                raise ApiError(
                    E_BAD_SIGNATURE,
                    basis={"custodian_id": custodian["id"], "reason": "ed25519_verify_failed",
                           "expected_signing_message": message.decode()},
                )

            await conn.execute(
                "UPDATE migration_nonces SET spent=TRUE WHERE id=$1", nonce_row["id"]
            )
            sub_id = deps.new_id("msub")
            try:
                await conn.execute(
                    """
                    INSERT INTO migration_share_submissions
                      (id, migration_id, custodian_id, nonce_id, point_x, shard_digest)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    sub_id, body.migration_id, custodian["id"], nonce_row["id"],
                    body.point_x, shard["shard_digest"],
                )
            except Exception as exc:
                if getattr(exc, "pgcode", None) == "23505":
                    raise ApiError(E_DUPLICATE_SHARE,
                                   basis={"migration_id": body.migration_id,
                                          "custodian_id": custodian["id"]})
                raise

            pending_token = pending.add(body.migration_id, custodian["id"], body.point_x, blob)
            await faults.maybe_park(request, "migration.after_add")
            await faults.maybe_raise(request, "migration.after_add")

            count = await conn.fetchval(
                "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1",
                body.migration_id,
            )
            threshold = source_policy["threshold"]

            if count >= threshold:
                await faults.maybe_park(request, "migration.before_resplit")
                try:
                    completed, new_custody_id, new_shard_count, new_shard_digests = (
                        await _resplit(conn, pending, mig, source_policy, target_policy)
                    )
                except ApiError as exc:
                    if not (
                        exc.code == E_THRESHOLD_NOT_MET
                        and exc.basis.get("reason") == "pending_shares_unavailable"
                    ):
                        raise
                    # ---- 缺片不可恢复：数据库计数已达源门限，但部分已提交分片
                    # 的内存明文丢失（进程重启/内存池淘汰）。已计数的托管人受
                    # 唯一约束与已花费 nonce 限制永远无法补交，会话不可能再
                    # 凑齐门限——不能让它以 open 状态占位到 TTL。
                    # 行锁仍持有，在同一事务内依次完成：
                    #   ① 凭本次 token 撤回内存分片（v1.3 撤销边界不变）；
                    #   ② 撤销本次库写入（提交记录删除、nonce 恢复未花费）；
                    #   ③ 会话置 failed 终态——释放 open 占位（两条部分唯一
                    #      索引均不含 failed），等待者拿锁即得 MIGRATION_FAILED；
                    #   ④ 追加无明文 migration.fail 审计。
                    # 随后整体提交；提交成功才清理内存池并返回确定性错误。
                    if pending_token is not None:
                        pending.discard(pending_token)
                        pending_token = None
                    await conn.execute(
                        "UPDATE migration_nonces SET spent=FALSE WHERE id=$1", nonce_row["id"]
                    )
                    await conn.execute(
                        "DELETE FROM migration_share_submissions WHERE id=$1", sub_id
                    )
                    await conn.execute(
                        "UPDATE migration_sessions SET status='failed' "
                        "WHERE id=$1 AND status='open'",
                        mig["id"],
                    )
                    committed = await conn.fetchval(
                        "SELECT count(*) FROM migration_share_submissions "
                        "WHERE migration_id=$1",
                        mig["id"],
                    )
                    exc.basis["migration_id"] = mig["id"]
                    exc.basis["migration_status"] = "failed"
                    await audit.append_audit(
                        conn, tenant_id=sess_tenant, actor_type="system", actor_id=None,
                        action="migration.fail", resource=mig["id"], result="error",
                        error_code=E_THRESHOLD_NOT_MET,
                        basis={
                            "reason": "pending_shares_unavailable",
                            "shares_committed": committed,
                            "threshold": threshold,
                            "source_custody_id": mig["source_custody_id"],
                            "source_policy_id": mig["source_policy_id"],
                            "source_version": mig["source_version"],
                            "target_policy_id": mig["target_policy_id"],
                            "target_version": mig["target_version"],
                        },
                    )
                    gap_error = exc

            if gap_error is None:
                await audit.append_audit(
                    conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                    action="migration.share.submit", resource=body.migration_id, result="ok",
                    basis={"shares_after": count, "threshold": threshold, "completed": completed,
                           "point_x": body.point_x, "shard_digest": shard["shard_digest"]},
                )
            try:
                await tx.commit()
            except Exception:
                await _undo()
                raise
        except ApiError as exc:
            await _undo()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.share.submit", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
        except Exception:
            await _undo()
            raise

    if gap_error is not None:
        # failed 终态已提交：会话再不可能完成，销毁其全部残留内存分片；
        # 本次提交已被撤销，补一条确定性拒绝留痕后向调用方返回错误。
        pending.clear(body.migration_id)
        await repo.audit_denied(
            pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
            action="migration.share.submit", resource=body.migration_id,
            error_code=gap_error.code, basis=gap_error.basis,
        )
        raise gap_error
    if completed:
        # 事务提交成功后立即销毁内存中的源分片与重组秘密。
        pending.clear(body.migration_id)
    return MigrationShareSubmitOut(
        migration_id=body.migration_id,
        status="completed" if completed else "open",
        shares_received=count,
        threshold=threshold,
        completed=completed,
        new_custody_id=new_custody_id,
        new_shard_count=new_shard_count,
        new_shard_digests=new_shard_digests,
    )


async def _resplit(conn, pending, mig, source_policy, target_policy):
    """Reconstruct in memory from verified source shares, re-shard to target.

    Everything (new custody row + new encrypted shards + session completion +
    audit) happens in the caller's single transaction; the secret lives only on
    this request's stack and is dropped as soon as the new shards are encrypted.
    """
    settings = get_settings()
    points = sorted(pending.get_points(mig["id"]), key=lambda p: p[0])
    if len(points) < source_policy["threshold"]:
        # 进程重启等导致内存待累计分片丢失：绝不回退到解密库存分片。
        raise ApiError(
            E_THRESHOLD_NOT_MET,
            basis={"reason": "pending_shares_unavailable",
                   "pending_in_memory": len(points),
                   "threshold": source_policy["threshold"]},
        )
    points = points[: source_policy["threshold"]]
    # 源 custody 行锁已由 submit_share 按全局锁序先行持有（此处 FOR UPDATE
    # 为锁内重读，幂等无等待）：迁移提交与逻辑销毁据此确定唯一先后。
    source_custody = await conn.fetchrow(
        "SELECT * FROM key_custodies WHERE id=$1 FOR UPDATE", mig["source_custody_id"]
    )
    try:
        secret = crypto.shamir_combine(points, source_custody["secret_length"])
    except ValueError as exc:
        raise ApiError(E_INTEGRITY, basis={"reason": "shamir_combine_failed", "detail": str(exc)})
    if not crypto.constant_time_hex_equal(
        crypto.sha256_hex(secret), source_custody["secret_digest"]
    ):
        raise ApiError(E_INTEGRITY,
                       basis={"reason": "secret_digest_mismatch_after_reconstruction"})

    target_custodian_ids = list(target_policy["custodian_ids"])
    new_points = crypto.shamir_split(secret, target_policy["threshold"], len(target_custodian_ids))
    # 秘密字节在重组作用域内即用即弃；新分片已生成，显式删除栈引用。
    del secret

    new_custody_id = deps.new_id("cus_secret")
    await conn.execute(
        """
        INSERT INTO key_custodies
          (id, tenant_id, policy_id, policy_version, secret_digest, secret_length,
           epoch_index, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'active')
        """,
        new_custody_id, mig["tenant_id"], mig["target_policy_id"], mig["target_version"],
        source_custody["secret_digest"], source_custody["secret_length"],
        target_policy["epoch_index"],
    )

    new_shard_digests: list[str] = []
    for (x, blob), custodian_id in zip(new_points, target_custodian_ids):
        shard_id = deps.new_id("shd")
        ct = crypto.encrypt_shard(settings.shard_master_key_bytes, shard_id, blob)
        shard_digest = crypto.sha256_hex(blob)
        new_shard_digests.append(shard_digest)
        await conn.execute(
            """
            INSERT INTO shards (id, custody_id, custodian_id, point_x, ciphertext, shard_digest)
            VALUES ($1,$2,$3,$4,$5,$6)
            """,
            shard_id, new_custody_id, custodian_id, x, ct, shard_digest,
        )

    await conn.execute(
        """
        UPDATE migration_sessions
           SET status='completed', new_custody_id=$2, completed_at=now()
         WHERE id=$1
        """,
        mig["id"], new_custody_id,
    )
    await audit.append_audit(
        conn, tenant_id=mig["tenant_id"], actor_type="system", actor_id=None,
        action="migration.complete", resource=mig["id"], result="ok",
        basis={
            "source_custody_id": mig["source_custody_id"],
            "source_policy_id": mig["source_policy_id"],
            "source_version": mig["source_version"],
            "source_digest": mig["source_digest"],
            "target_policy_id": mig["target_policy_id"],
            "target_version": mig["target_version"],
            "target_digest": mig["target_digest"],
            "new_custody_id": new_custody_id,
            "new_shard_count": len(target_custodian_ids),
            "new_shard_digests": new_shard_digests,
        },
    )
    return True, new_custody_id, len(target_custodian_ids), new_shard_digests
