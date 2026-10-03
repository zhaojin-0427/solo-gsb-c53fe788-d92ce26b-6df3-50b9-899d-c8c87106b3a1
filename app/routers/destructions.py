"""Logical destruction of a custody-record lineage (v1.6).

A tenant points at a custody record; the service follows **completed**
migration edges (``migration_sessions.new_custody_id``) to collect that record
and every forward descendant, then — in a **single transaction**, while holding
row locks that serialize against every in-flight recovery and migration —

1. marks every custody row in the lineage ``destroyed`` (a secret-free
   tombstone: id / policy coordinates / digests / counts remain, the online
   encrypted shard rows are deleted outright);
2. blocks the lineage's in-flight recoveries and migrations by moving their
   ``open`` sessions to a non-revivable ``destroyed`` terminal state;
3. records a plaintext-free, replayable ``destruction.complete`` audit entry
   and a durable, idempotency-keyed destruction receipt.

Concurrency ordering is made deterministic by a single global lock order —
**custody rows (id order) before session rows (id order)** — shared with the
migration share-submit and recovery-session paths, so destruction versus
migration completion / shard claim / share submission can never deadlock and
exactly one side wins; after the destruction commit, an old session can no
longer hand out shard plaintext or the wrapped ciphertext, and a migration that
lost the race can no longer insert a "missed" descendant record (its new
custody insert is FK-rejected because the whole transaction rolled back, and
the lineage custody is locked until the destruction commits).

Retries carrying the same ``Idempotency-Key`` return the same receipt (200),
even against an already-destroyed root; cross-tenant callers are rejected.
Destruction covers **online service data only** — it never claims to erase
external backups.

Concurrent first-time uses of one key against **unrelated** roots cannot be
serialized by the root row locks (they are disjoint), so both requests can
pass the receipt pre-check; the loser's receipt insert then hits
``uq_destruction_idem``. That unique-violation — and only that constraint —
is translated into the deterministic ``IDEMPOTENCY_CONFLICT`` (409): the
loser's whole transaction (lineage tombstones, shard deletion, session
blocking, completion audit) rolls back, and the denial is audited in its own
transaction, exactly as if the pre-check had seen the winner's receipt.
"""
from __future__ import annotations

import json

import asyncpg
from fastapi import APIRouter, Header, Request, Response

from .. import audit, crypto, deps, faults, repo
from ..errors import ApiError, E_BAD_REQUEST, E_FORBIDDEN, E_IDEMPOTENCY_CONFLICT, E_NOT_FOUND
from ..schemas import DestructionReceiptOut, DestructionStartIn

router = APIRouter(tags=["destructions"])


def _receipt_out(row) -> DestructionReceiptOut:
    custody_ids = row["custody_ids"]
    if isinstance(custody_ids, str):
        custody_ids = json.loads(custody_ids)
    return DestructionReceiptOut(
        destruction_id=row["id"],
        status=row["status"],
        root_custody_id=row["root_custody_id"],
        idempotency_key_digest=row["idempotency_key_hash"],
        custody_count=row["custody_count"],
        recovery_blocked=row["recovery_blocked"],
        migration_blocked=row["migration_blocked"],
        shards_deleted=row["shards_deleted"],
        custody_ids=list(custody_ids),
        created_at=row["created_at"],
    )


@router.post("/destructions", response_model=DestructionReceiptOut, status_code=201)
async def destroy_lineage(
    body: DestructionStartIn,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant=deps.Tenant,
):
    if not idempotency_key or not 1 <= len(idempotency_key) <= 200:
        raise ApiError(E_BAD_REQUEST,
                       basis={"reason": "missing_or_malformed_idempotency_key",
                              "header": "Idempotency-Key", "max_length": 200})
    idem_hash = crypto.sha256_hex(idempotency_key.encode())
    pool = request.app.state.db.pool
    pending = request.app.state.pending

    receipt_row = None
    replayed = False
    # 事务提交后要清理的进程内待累计分片（只可能含在途会话键）。
    open_recovery_ids: list[str] = []
    open_migration_ids: list[str] = []

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # ① 根托管记录行锁：跨租户拒绝、幂等检查与谱系展开都在锁内。
                root = await conn.fetchrow(
                    "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", body.root_custody_id
                )
                if root is None:
                    raise ApiError(E_NOT_FOUND, basis={"custody_id": body.root_custody_id})
                if root["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN,
                                   basis={"reason": "custody_belongs_to_other_tenant"})

                # 幂等优先：同键（无论绑定哪个根）已有回执则必须原样返回；
                # 同键不同根属于冲突，不产生第二份销毁。
                existing = await conn.fetchrow(
                    "SELECT * FROM destructions WHERE tenant_id=$1 AND idempotency_key_hash=$2",
                    tenant["id"], idem_hash,
                )
                if existing is not None:
                    if existing["root_custody_id"] != body.root_custody_id:
                        raise ApiError(
                            E_IDEMPOTENCY_CONFLICT,
                            basis={"reason": "key_bound_to_different_request",
                                   "idempotency_key_digest": idem_hash},
                        )
                    receipt_row = existing
                    replayed = True
                else:
                    # 回归闸门：回执预查通过（无既有回执）之后、谱系展开之前
                    # （仅测试构建启用）。两个并发请求同键对不同根时，根行锁
                    # 互不重叠，可能双双通过预查——钉住该交错可验证后插入者
                    # 撞 uq_destruction_idem 后的确定性 409 与整体回滚。
                    await faults.maybe_park(request, "destruction.after_receipt_check")
                    await faults.maybe_raise(request, "destruction.after_receipt_check")
                    # ② 谱系展开 + 锁定（不动点）：每轮先按 id 顺序锁定
                    # “新发现的已完成迁移后代” custody 行，再沿其出边扩展。
                    # 与迁移完成路径同一全局锁序（custody 先于 migration 行），
                    # 因此销毁 × 迁移完成永远不死锁，且必有确定性的先后：
                    # 若有迁移正持有子 custody 行锁（提交临界区），销毁在此等待；
                    # 它一旦提交，下一轮展开必能看到新后代并纳入销毁——绝不漏删。
                    lineage: list[str] = []
                    frontier = [root["id"]]
                    locked: set[str] = set()
                    while frontier:
                        frontier = sorted(set(frontier) - locked)
                        if not frontier:
                            break
                        rows = await conn.fetch(
                            "SELECT id FROM key_custodies WHERE id = ANY($1::text[]) "
                            "ORDER BY id FOR UPDATE",
                            frontier,
                        )
                        got = [r["id"] for r in rows]
                        locked.update(got)
                        lineage.extend(got)
                        # 仅沿“已完成迁移关系”前进（new_custody_id 非空的会话）。
                        children = await conn.fetch(
                            "SELECT new_custody_id AS cid FROM migration_sessions "
                            "WHERE source_custody_id = ANY($1::text[]) "
                            "AND new_custody_id IS NOT NULL",
                            got,
                        )
                        frontier = [r["cid"] for r in children if r["cid"] not in locked]

                    # 回归闸门：谱系 custody 行锁已全部持有、会话尚未锁定
                    # （仅测试构建启用，用来钉住“销毁 × 在途会话”的交错）。
                    await faults.maybe_park(request, "destruction.after_lineage_lock")

                    # ③ 锁定谱系上的全部迁移会话（按 id 序，死锁安全）。
                    #     open 会话与迁移提交争同一把行锁，先后在此确定。
                    mig_rows = await conn.fetch(
                        "SELECT id, status FROM migration_sessions "
                        "WHERE source_custody_id = ANY($1::text[]) ORDER BY id FOR UPDATE",
                        lineage,
                    )
                    open_migration_ids = [r["id"] for r in mig_rows if r["status"] == "open"]

                    # ④ 锁定谱系上的全部恢复会话（按 id 序，死锁安全）。
                    rec_rows = await conn.fetch(
                        "SELECT id, status FROM recovery_sessions "
                        "WHERE custody_id = ANY($1::text[]) ORDER BY id FOR UPDATE",
                        lineage,
                    )
                    open_recovery_ids = [r["id"] for r in rec_rows if r["status"] == "open"]

                    # ⑤ 阻断在途恢复/迁移：open 会话进入不可复活的 destroyed
                    #     终态。completed/failed/expired 终态保持原样；随后旧
                    #     会话的 nonce/claim/submit 在各自行锁上只得到确定性
                    #     CUSTODY_DESTROYED，绝不再下发分片或密文。
                    await conn.execute(
                        "UPDATE recovery_sessions SET status='destroyed' "
                        "WHERE custody_id = ANY($1::text[]) AND status='open'",
                        lineage,
                    )
                    await conn.execute(
                        "UPDATE migration_sessions SET status='destroyed' "
                        "WHERE source_custody_id = ANY($1::text[]) AND status='open'",
                        lineage,
                    )
                    # 行锁在握：锁定快照后 open 集合不可能再被他人改变。
                    recovery_blocked = len(open_recovery_ids)
                    migration_blocked = len(open_migration_ids)

                    # ⑥ 标记记录已销毁：保留无秘密的墓碑（id/策略坐标/摘要/
                    #     长度/epoch），仅置状态与销毁时刻。
                    await conn.execute(
                        "UPDATE key_custodies SET status='destroyed', destroyed_at=now() "
                        "WHERE id = ANY($1::text[])",
                        lineage,
                    )

                    # ⑦ 删除在线库中的加密分片（密文本体），RETURNING 计数。
                    shards_deleted = await conn.fetchval(
                        "WITH d AS (DELETE FROM shards WHERE custody_id = ANY($1::text[]) "
                        "RETURNING 1) SELECT count(*) FROM d",
                        lineage,
                    )

                    # ⑧ 幂等销毁回执（只含 ID/计数，无任何秘密材料）。
                    destruction_id = deps.new_id("des")
                    await conn.execute(
                        """
                        INSERT INTO destructions
                          (id, tenant_id, root_custody_id, idempotency_key_hash,
                           custody_count, recovery_blocked, migration_blocked,
                           shards_deleted, custody_ids, status)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'completed')
                        """,
                        destruction_id, tenant["id"], root["id"], idem_hash,
                        len(lineage), recovery_blocked, migration_blocked,
                        shards_deleted, json.dumps(lineage),
                    )

                    # ⑨ 可重放审计：无明文（分片/秘密/nonce 均不入 basis）。
                    await audit.append_audit(
                        conn, tenant_id=tenant["id"], actor_type="tenant",
                        actor_id=tenant["id"],
                        action="destruction.complete", resource=destruction_id, result="ok",
                        basis={
                            "destruction_id": destruction_id,
                            "root_custody_id": root["id"],
                            "custody_count": len(lineage),
                            "custody_ids": lineage,
                            "recovery_blocked": recovery_blocked,
                            "migration_blocked": migration_blocked,
                            "shards_deleted": shards_deleted,
                            "scope": "online_service_data_only",
                            "idempotency_key_digest": idem_hash,
                        },
                    )
                    receipt_row = await conn.fetchrow(
                        "SELECT * FROM destructions WHERE id=$1", destruction_id
                    )
        except asyncpg.UniqueViolationError as exc:
            # 并发同键回执插入兜底：两个请求可能双双通过回执预查（不同根的
            # 行锁互不重叠），后插入者撞上 uq_destruction_idem。唯一索引的
            # 等待已解析，胜方回执必然已提交；本事务（谱系销毁、分片删除、
            # 会话阻断、完成审计）已随事务上下文整体回滚。
            if getattr(exc, "constraint_name", None) != "uq_destruction_idem":
                # 其它唯一约束冲突（如回执主键）不是幂等冲突：原样上抛，
                # 绝不误判为 IDEMPOTENCY_CONFLICT。
                raise
            # 事务已回滚：这些会话仍是 open，不得清理其进程内待累计分片。
            open_recovery_ids = []
            open_migration_ids = []
            winner = await conn.fetchrow(
                "SELECT * FROM destructions WHERE tenant_id=$1 AND idempotency_key_hash=$2",
                tenant["id"], idem_hash,
            )
            if winner is None:
                # 胜方也已回滚（回执不可见）：不是幂等冲突，原样上抛。
                raise
            if winner["root_custody_id"] == body.root_custody_id:
                # 同键同根的并发重试：返回胜方那一份回执（200）。
                receipt_row = winner
                replayed = True
            else:
                # 同键不同根：与预查冲突路径同一确定性结果——409 + 拒绝审计；
                # 失败方的谱系销毁/分片删除/会话阻断/完成审计已全部回滚。
                conflict = ApiError(
                    E_IDEMPOTENCY_CONFLICT,
                    basis={"reason": "key_bound_to_different_request",
                           "idempotency_key_digest": idem_hash},
                )
                await repo.audit_denied(
                    pool, tenant_id=tenant["id"], actor_type="tenant",
                    actor_id=tenant["id"],
                    action="destruction.start", resource=body.root_custody_id,
                    error_code=conflict.code, basis=conflict.basis,
                )
                raise conflict
        except ApiError as exc:
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="destruction.start", resource=body.root_custody_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise

    # 事务成功提交后再清理进程内待累计分片（明文绝不留在内存）。
    # completed 等终态会话本就无待累计条目，clear 为安全 no-op。
    for sid in open_recovery_ids:
        pending.clear(sid)
    for mid in open_migration_ids:
        pending.clear(mid)

    if replayed:
        response.status_code = 200
    return _receipt_out(receipt_row)


@router.get("/destructions/{destruction_id}", response_model=DestructionReceiptOut)
async def get_destruction(destruction_id: str, request: Request,
                          tenant=deps.Tenant) -> DestructionReceiptOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM destructions WHERE id=$1", destruction_id)
        if row is None:
            raise ApiError(E_NOT_FOUND, basis={"destruction_id": destruction_id})
        if row["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "destruction_belongs_to_other_tenant"})
    return _receipt_out(row)
