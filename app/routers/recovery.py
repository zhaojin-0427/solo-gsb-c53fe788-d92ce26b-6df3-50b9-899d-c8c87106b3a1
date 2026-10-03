from __future__ import annotations

import json

from fastapi import APIRouter, Request

from .. import audit, crypto, deps, repo
from .. import faults
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
    E_INTEGRITY,
    E_NONCE_USED,
    E_NOT_FOUND,
    E_SESSION_COMPLETED,
    E_SESSION_EXPIRED,
    E_SHARE_DIGEST,
    E_SHARE_POINT,
    E_THRESHOLD_NOT_MET,
)
from ..schemas import (
    NonceOut,
    NonceRequestIn,
    RecoverySessionOut,
    RecoveryStartIn,
    ShardClaimIn,
    ShardClaimOut,
    ShareSubmitIn,
    ShareSubmitOut,
)

router = APIRouter(tags=["recovery"])


def _session_out(row, shares_received: int, threshold: int) -> RecoverySessionOut:
    return RecoverySessionOut(
        session_id=row["id"],
        custody_id=row["custody_id"],
        policy_id=row["policy_id"],
        policy_version=row["policy_version"],
        epoch_index=row["epoch_index"],
        request_digest=row["request_digest"],
        status=row["status"],
        valid_until=row["valid_until"],
        shares_received=shares_received,
        threshold=threshold,
    )


async def _load_session_for_tenant(conn, session_id: str, tenant_id: str):
    row = await conn.fetchrow("SELECT * FROM recovery_sessions WHERE id = $1", session_id)
    if row is None:
        raise ApiError(E_NOT_FOUND, basis={"session_id": session_id})
    if row["tenant_id"] != tenant_id:
        raise ApiError(E_FORBIDDEN, basis={"reason": "session_belongs_to_other_tenant"})
    policy = await repo.get_policy_version(conn, row["policy_id"], row["policy_version"])
    return row, policy


async def _custody_shard(conn, custody_id: str, custodian_id: str):
    """The inventory shard (ciphertext + point + digest) assigned to a custodian."""
    return await conn.fetchrow(
        "SELECT id, point_x, ciphertext, shard_digest FROM shards "
        "WHERE custody_id=$1 AND custodian_id=$2",
        custody_id, custodian_id,
    )


async def _guard_open_session(conn, sess, policy, custody, now, custodian_id: str) -> None:
    """All gates shared by nonce issue / shard claim / share submit."""
    # 逻辑销毁终态：该会话（及其谱系）的在线分片已删除，任何旧会话请求
    # （nonce/claim/submit）确定性拒绝，绝不再下发分片或密文。
    if sess["status"] == "destroyed" or (custody is not None and custody["status"] == "destroyed"):
        raise ApiError(
            E_CUSTODY_DESTROYED,
            basis={"session_id": sess["id"], "custody_id": sess["custody_id"],
                   "session_status": sess["status"],
                   "custody_status": custody["status"] if custody is not None else "missing"},
        )
    if sess["status"] == "completed":
        raise ApiError(E_SESSION_COMPLETED, basis={"session_id": sess["id"]})
    if now >= sess["valid_until"]:
        raise ApiError(E_SESSION_EXPIRED,
                       basis={"valid_until": str(sess["valid_until"]), "now": str(now)})
    if policy["status"] == "revoked" or custody["status"] in ("revoked", "rotated"):
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": sess["policy_id"], "version": sess["policy_version"],
                   "epoch": sess["epoch_index"]},
        )
    if now >= policy["epoch_valid_until"]:
        raise ApiError(E_EPOCH_EXPIRED, basis={"epoch": sess["epoch_index"]})
    if custodian_id not in policy["custodian_ids"]:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"custodian_id": custodian_id, "policy_id": sess["policy_id"],
                   "policy_version": sess["policy_version"], "reason": "not_member_of_policy_version"},
        )


async def _resolve_nonce(conn, body_session_id: str, nonce_hex: str, custodian_id: str):
    try:
        nonce_hash = crypto.sha256_hex(bytes.fromhex(nonce_hex))
    except ValueError:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_malformed"})
    nonce_row = await conn.fetchrow(
        "SELECT * FROM session_nonces WHERE nonce_hash=$1 FOR UPDATE", nonce_hash
    )
    if nonce_row is None:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_unknown"})
    if nonce_row["session_id"] != body_session_id or nonce_row["custodian_id"] != custodian_id:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"reason": "nonce_binding_mismatch", "session_id": body_session_id,
                   "custodian_id": custodian_id},
        )
    return nonce_row


@router.post("/recoveries", response_model=RecoverySessionOut, status_code=201)
async def start_recovery(body: RecoveryStartIn, request: Request, tenant=deps.Tenant) -> RecoverySessionOut:
    settings = get_settings()
    pool = request.app.state.db.pool
    ttl = body.ttl_seconds or settings.recovery_default_ttl
    ttl = min(ttl, settings.recovery_max_ttl)
    async with pool.acquire() as conn:
        async with conn.transaction():
            # custody 行锁：与逻辑销毁同序串行，销毁提交后不得再建恢复会话。
            custody = await conn.fetchrow(
                "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", body.custody_id
            )
            if custody is None:
                raise ApiError(E_NOT_FOUND, basis={"custody_id": body.custody_id})
            if custody["tenant_id"] != tenant["id"]:
                raise ApiError(E_FORBIDDEN, basis={"reason": "custody_belongs_to_other_tenant"})
            policy = await repo.get_policy_version(conn, custody["policy_id"], custody["policy_version"])
            now = await conn.fetchval("SELECT now()")
            if custody["status"] == "destroyed":
                raise ApiError(
                    E_CUSTODY_DESTROYED,
                    basis={"custody_id": custody["id"], "custody_status": custody["status"]},
                )
            if policy["status"] == "revoked" or custody["status"] == "revoked":
                raise ApiError(
                    E_EPOCH_REVOKED,
                    basis={
                        "policy_id": custody["policy_id"],
                        "version": custody["policy_version"],
                        "epoch": custody["epoch_index"],
                    },
                )
            if now >= policy["epoch_valid_until"]:
                raise ApiError(
                    E_EPOCH_EXPIRED,
                    basis={"epoch": policy["epoch_index"], "valid_until": str(policy["epoch_valid_until"])},
                )
            session_id = deps.new_id("rec")
            await conn.execute(
                """
                INSERT INTO recovery_sessions
                  (id, tenant_id, custody_id, policy_id, policy_version, epoch_index,
                   request_digest, status, recovery_pubkey, valid_until)
                VALUES ($1,$2,$3,$4,$5,$6,$7,'open',$8, now() + ($9 || ' seconds')::interval)
                """,
                session_id, tenant["id"], body.custody_id, custody["policy_id"],
                custody["policy_version"], custody["epoch_index"], body.request_digest,
                body.recovery_public_key, str(ttl),
            )
            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="recovery.start", resource=session_id, result="ok",
                basis={
                    "custody_id": body.custody_id,
                    "policy_version": custody["policy_version"],
                    "epoch": custody["epoch_index"],
                    "request_digest": body.request_digest,
                    "ttl_seconds": ttl,
                },
            )
            row = await conn.fetchrow("SELECT * FROM recovery_sessions WHERE id = $1", session_id)
    return _session_out(row, 0, policy["threshold"])


@router.get("/recoveries/{session_id}", response_model=RecoverySessionOut)
async def get_recovery(session_id: str, request: Request, tenant=deps.Tenant) -> RecoverySessionOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        row, policy = await _load_session_for_tenant(conn, session_id, tenant["id"])
        count = await conn.fetchval(
            "SELECT count(*) FROM share_submissions WHERE session_id=$1", session_id
        )
    return _session_out(row, count, policy["threshold"])


@router.post("/recoveries/nonces", response_model=NonceOut)
async def issue_nonce(body: NonceRequestIn, request: Request, custodian=deps.Custodian) -> NonceOut:
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    nonce = ""
    nonce_id = ""
    point_x = 0
    shard_digest = ""
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            # 全局锁序：custody 行先于 recovery 会话行（与销毁/提交一致，
            # 杜绝销毁 × nonce 发放的锁序反转死锁）。
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1", body.session_id
            )
            if sess is None:
                raise ApiError(E_NOT_FOUND, basis={"session_id": body.session_id})
            custody = await conn.fetchrow(
                "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", sess["custody_id"]
            )
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1 FOR UPDATE", body.session_id
            )
            sess_tenant = sess["tenant_id"]
            policy = await repo.get_policy_version(conn, sess["policy_id"], sess["policy_version"])
            now = await conn.fetchval("SELECT now()")
            await _guard_open_session(conn, sess, policy, custody, now, custodian["id"])

            shard = await _custody_shard(conn, sess["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            point_x = shard["point_x"]
            shard_digest = shard["shard_digest"]

            existing = await conn.fetchrow(
                "SELECT * FROM session_nonces WHERE session_id=$1 AND custodian_id=$2",
                body.session_id, custodian["id"],
            )
            if existing is not None:
                # nonce 仅在签发响应中明文下发一次（库中只存摘要）。
                # 重复请求给出确定性依据：未花费请复用原 nonce，已花费须等门限流程结束。
                raise ApiError(
                    E_NONCE_USED,
                    basis={
                        "session_id": body.session_id,
                        "custodian_id": custodian["id"],
                        "spent": existing["spent"],
                        "reason": "nonce_already_issued" if not existing["spent"] else "nonce_spent",
                    },
                )
            nonce = deps.new_nonce()
            nonce_id = deps.new_id("non")
            await conn.execute(
                """
                INSERT INTO session_nonces (id, session_id, custodian_id, nonce_hash, spent)
                VALUES ($1,$2,$3,$4, FALSE)
                """,
                nonce_id, body.session_id, custodian["id"], crypto.sha256_hex(bytes.fromhex(nonce)),
            )
            await audit.append_audit(
                conn, tenant_id=sess["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="recovery.nonce.issue", resource=nonce_id, result="ok",
                basis={"session_id": body.session_id, "policy_version": sess["policy_version"],
                       "point_x": point_x, "shard_digest": shard_digest},
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="recovery.nonce.issue", resource=body.session_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return NonceOut(
        nonce_id=nonce_id,
        nonce=nonce,
        session_id=body.session_id,
        custodian_id=custodian["id"],
        policy_id=sess["policy_id"],
        policy_version=sess["policy_version"],
        point_x=point_x,
        shard_digest=shard_digest,
    )


@router.post("/recoveries/shards/claim", response_model=ShardClaimOut)
async def claim_shard(body: ShardClaimIn, request: Request, custodian=deps.Custodian) -> ShardClaimOut:
    """Authenticated custodian claims its own shard for an open recovery session.

    The plaintext shard appears only in this response: it is not logged, not
    audited and not cached. The claim binds the outstanding nonce; the shard
    itself is not spent here (submit spends the nonce after full verification).
    """
    settings = get_settings()
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            # 全局锁序：custody 行先于 recovery 会话行（与销毁/提交一致，
            # 杜绝销毁 × 领片的锁序反转死锁；排队领片在销毁后只得到 410）。
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1", body.session_id
            )
            if sess is None:
                raise ApiError(E_NOT_FOUND, basis={"session_id": body.session_id})
            custody = await conn.fetchrow(
                "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", sess["custody_id"]
            )
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1 FOR UPDATE", body.session_id
            )
            sess_tenant = sess["tenant_id"]
            policy = await repo.get_policy_version(conn, sess["policy_id"], sess["policy_version"])
            now = await conn.fetchval("SELECT now()")
            await _guard_open_session(conn, sess, policy, custody, now, custodian["id"])

            nonce_row = await _resolve_nonce(conn, body.session_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"], "reason": "nonce_spent"})

            shard = await _custody_shard(conn, sess["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            # 服务端自检：库存密文必须能解开且摘要自洽
            try:
                blob = crypto.decrypt_shard(
                    settings.shard_master_key_bytes, shard["id"], bytes(shard["ciphertext"])
                )
            except Exception:  # AEAD tag failure / malformed inventory ciphertext
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
            message = crypto.custodian_signing_message(
                nonce=body.nonce,
                session_id=body.session_id,
                policy_id=sess["policy_id"],
                policy_version=sess["policy_version"],
                custodian_id=custodian["id"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
            )
            await audit.append_audit(
                conn, tenant_id=sess["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="recovery.shard.claim", resource=body.session_id, result="ok",
                basis={"nonce_id": nonce_row["id"], "point_x": shard["point_x"],
                       "shard_digest": shard["shard_digest"]},
            )
            out = ShardClaimOut(
                session_id=body.session_id,
                nonce_id=nonce_row["id"],
                custodian_id=custodian["id"],
                policy_id=sess["policy_id"],
                policy_version=sess["policy_version"],
                custody_id=sess["custody_id"],
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
                action="recovery.shard.claim", resource=body.session_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return out


@router.post("/recoveries/shares", response_model=ShareSubmitOut)
async def submit_share(body: ShareSubmitIn, request: Request, custodian=deps.Custodian) -> ShareSubmitOut:
    pool = request.app.state.db.pool
    pending = request.app.state.pending
    actor_basis_session = body.session_id
    sess_tenant: str | None = None

    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        # 撤销边界：只持有“本请求自己的入池凭证”。
        # * 校验拒绝全部发生在 token 产生（入池）之前，异常路径绝不触碰内存池；
        # * 入池后的任何失败（重组失败、审计写入失败、连接中断……）都在
        #   **行锁仍持有时**凭 token 精确撤回本次新增——等待者拿锁时内存与
        #   数据库已重新一致，读不到未提交分片；
        # * 即使该顺序被意外破坏，discard(token) 也只会删掉本次插入：
        #   同托管人的成功重试先入池时，旧请求无法误删新分片。
        pending_token = None
        completed = False
        wrap = None
        aad = None
        count = 0
        threshold = 0

        async def _undo() -> None:
            """Retract this request's in-memory share BEFORE the row lock drops.

            The database transaction is still open here, so any request blocked
            on the session row lock cannot run until the in-memory retraction is
            finished; the store and the committed share count stay in agreement.
            """
            nonlocal pending_token
            if pending_token is not None:
                # 先凭 token 精确撤回本次内存新增……
                pending.discard(pending_token)
                pending_token = None
                # 回归闸门：本次分片已撤回、事务（行锁）尚未释放。
                # 等待者此刻仍在锁队列里，拿锁时读到的内存池已不含未提交分片。
                await faults.maybe_park(request, "submit.abort_undo")
            await tx.rollback()

        try:
            # 全局锁序：custody 行先于 recovery 会话行——与逻辑销毁路径一致，
            # 销毁 × 提交永不死锁：销毁已把该 custody 谱系的会话行锁定并置
            # destroyed 后，本路径只能在 guard 上得到确定性 CUSTODY_DESTROYED。
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1", body.session_id
            )
            if sess is None:
                raise ApiError(E_NOT_FOUND, basis={"session_id": body.session_id})
            custody = await conn.fetchrow(
                "SELECT * FROM key_custodies WHERE id=$1 FOR UPDATE", sess["custody_id"]
            )
            # 会话行锁：同一会话的所有提交完全串行，消除并发竞态。
            sess = await conn.fetchrow(
                "SELECT * FROM recovery_sessions WHERE id=$1 FOR UPDATE", body.session_id
            )
            await faults.maybe_park(request, "submit.after_lock")
            sess_tenant = sess["tenant_id"]
            policy = await repo.get_policy_version(conn, sess["policy_id"], sess["policy_version"])
            now = await conn.fetchval("SELECT now()")

            # 1) 会话状态/时效 + epoch + 策略成员
            await _guard_open_session(conn, sess, policy, custody, now, custodian["id"])

            # 2) nonce：存在、归属匹配、未花费（一次性）
            nonce_row = await _resolve_nonce(conn, body.session_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"]})

            # 3) 重复份额（唯一约束兜底，显式判定给出确定性依据）
            dup = await conn.fetchrow(
                "SELECT 1 FROM share_submissions WHERE session_id=$1 AND custodian_id=$2",
                body.session_id, custodian["id"],
            )
            if dup:
                raise ApiError(E_DUPLICATE_SHARE,
                               basis={"session_id": body.session_id, "custodian_id": custodian["id"]})

            # 4) 分片归属：提交者在该托管下必须有且仅有自己点位的库存分片
            shard = await _custody_shard(conn, sess["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )

            # 5) 点位与库存摘要：先验“货”再花钱（nonce），错误分片有确定性依据
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

            # 6) Ed25519 验签：报文绑定 nonce+会话+策略版本+托管人+点位+实际分片摘要。
            #    只签名不交货（不提交自己的分片字节）无法通过 5)，计数无从谈起。
            message = crypto.custodian_signing_message(
                nonce=body.nonce,
                session_id=body.session_id,
                policy_id=sess["policy_id"],
                policy_version=sess["policy_version"],
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

            # --- 全部校验通过：花费 nonce，登记“已验签的分片” ---
            await conn.execute(
                "UPDATE session_nonces SET spent=TRUE WHERE id=$1", nonce_row["id"]
            )
            sub_id = deps.new_id("sub")
            try:
                await conn.execute(
                    """
                    INSERT INTO share_submissions
                      (id, session_id, custodian_id, nonce_id, point_x, shard_digest)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    sub_id, body.session_id, custodian["id"], nonce_row["id"],
                    body.point_x, shard["shard_digest"],
                )
            except Exception as exc:  # unique_violation under race
                if getattr(exc, "pgcode", None) == "23505":
                    raise ApiError(E_DUPLICATE_SHARE,
                                   basis={"session_id": body.session_id,
                                          "custodian_id": custodian["id"]})
                raise

            # 已验签分片只在内存累计，明文绝不落盘。
            # token 唯一标识“本次插入”，异常撤销时只能动它。
            pending_token = pending.add(body.session_id, custodian["id"], body.point_x, blob)

            # 回归闸门：分片已入池、行锁仍持有（仅测试构建启用）。
            # 先 park 后 fail：测试可在“已入池、未失败”的瞬间放入等待者，
            # 放行后再注入审计/重组类失败。
            await faults.maybe_park(request, "submit.after_add")
            await faults.maybe_raise(request, "submit.after_add")

            count = await conn.fetchval(
                "SELECT count(*) FROM share_submissions WHERE session_id=$1", body.session_id
            )
            threshold = policy["threshold"]

            if count >= threshold:
                # 门限满足：只凭“已验签的提交分片”在请求内存中重组，
                # 服务端不再解密库存分片来凑数。
                await faults.maybe_park(request, "submit.before_reconstruct")
                completed, wrap, aad = await _reconstruct(conn, pending, sess, custody, threshold)

            await audit.append_audit(
                conn, tenant_id=sess["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="recovery.share.submit", resource=body.session_id, result="ok",
                basis={"shares_after": count, "threshold": threshold, "completed": completed,
                       "point_x": body.point_x, "shard_digest": shard["shard_digest"]},
            )
            try:
                await tx.commit()
            except Exception:
                # 提交本身失败（网络/服务端中止）：提交结果未知，同样在行锁
                # 释放前撤回本次内存新增，随后由上层 500 处理；调用方可凭
                # 确定性错误/会话状态安全重试。
                await _undo()
                raise
        except ApiError as exc:
            # 校验失败不花费 nonce、不计数；入池后的失败则凭 token 精确撤回。
            # 撤回发生在 tx 回滚（行锁释放）**之前**：等待者拿锁时内存池里
            # 绝不会残留本次未提交分片，也不可能由旧请求删掉别人的新分片。
            await _undo()
            # 拒绝本身留痕（独立事务），不泄露签名/nonce/分片内容
            await repo.audit_denied(
                pool,
                tenant_id=sess_tenant,
                actor_type="custodian",
                actor_id=custodian["id"],
                action="recovery.share.submit",
                resource=actor_basis_session,
                error_code=exc.code,
                basis=exc.basis,
            )
            raise
        except Exception:
            # 非确定性失败（连接中断等）：同样先撤回再释放行锁。
            await _undo()
            raise

    # 事务提交成功后再销毁内存待累计分片；失败已在上面整体回滚。
    if completed:
        pending.clear(body.session_id)
    return ShareSubmitOut(
        session_id=body.session_id,
        status="completed" if completed else "open",
        shares_received=count,
        threshold=threshold,
        completed=completed,
        wrap=wrap,
        aad=aad,
    )


async def _reconstruct(conn, pending, sess, custody, threshold: int):
    """Reconstruct exclusively from verified submitted blobs held in memory."""
    points = sorted(pending.get_points(sess["id"]), key=lambda p: p[0])
    if len(points) < threshold:
        # 进程重启等情况下内存累计已丢失：不回退到解密库存分片，
        # 给出确定性依据，请调用方另开会话重来。
        raise ApiError(
            E_THRESHOLD_NOT_MET,
            basis={"reason": "pending_shares_unavailable",
                   "pending_in_memory": len(points), "threshold": threshold},
        )
    points = points[:threshold]
    try:
        secret = crypto.shamir_combine(points, custody["secret_length"])
    except ValueError as exc:
        raise ApiError(E_INTEGRITY, basis={"reason": "shamir_combine_failed", "detail": str(exc)})
    if not crypto.constant_time_hex_equal(crypto.sha256_hex(secret), custody["secret_digest"]):
        raise ApiError(E_INTEGRITY, basis={"reason": "secret_digest_mismatch_after_reconstruction"})

    aad = json.dumps(
        {
            "protocol": "keyvault.recovery.v1",
            "session_id": sess["id"],
            "custody_id": sess["custody_id"],
            "policy_id": sess["policy_id"],
            "policy_version": sess["policy_version"],
            "epoch_index": sess["epoch_index"],
            "request_digest": sess["request_digest"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    wrap = crypto.wrap_secret(sess["recovery_pubkey"], secret, aad.encode())
    # 同一事务内将会话置 completed（行锁保证串行）：密文只随本次响应下发一次。
    # 内存中的待累计分片在事务提交成功后由 submit_share 统一销毁。
    await conn.execute("UPDATE recovery_sessions SET status='completed' WHERE id=$1", sess["id"])
    return True, wrap, aad
