from __future__ import annotations

from fastapi import APIRouter, Request

from .. import audit, deps, repo
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_FORBIDDEN,
    E_NOT_FOUND,
    E_POLICY_INACTIVE,
    E_POLICY_PARAMS,
    E_VERSION_CONFLICT,
)
from ..schemas import PolicyCreateIn, PolicyOut, RevokeEpochIn, RotateIn

router = APIRouter(prefix="/policies", tags=["policies"])


def _policy_out(row) -> PolicyOut:
    return PolicyOut(
        policy_id=row["id"],
        version=row["version"],
        threshold=row["threshold"],
        custodian_ids=list(row["custodian_ids"]),
        epoch_index=row["epoch_index"],
        epoch_valid_from=row["epoch_valid_from"],
        epoch_valid_until=row["epoch_valid_until"],
        rotation_interval=row["rotation_interval"],
        status=row["status"],
        created_at=row["created_at"],
    )


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(body: PolicyCreateIn, request: Request, tenant=deps.Tenant) -> PolicyOut:
    if not 1 <= body.threshold <= len(body.custodian_ids):
        raise ApiError(
            E_POLICY_PARAMS,
            basis={
                "threshold": body.threshold,
                "custodian_count": len(body.custodian_ids),
                "rule": "1 <= threshold <= custodian_count",
            },
        )
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", body.policy_id)
            existing = await conn.fetchrow("SELECT 1 FROM policy_heads WHERE policy_id = $1", body.policy_id)
            if existing:
                raise ApiError(E_BAD_REQUEST, basis={"policy_id": body.policy_id, "reason": "already_exists"})
            await repo.resolve_custodian_ids(conn, body.custodian_ids)
            await conn.execute(
                """
                INSERT INTO policies
                  (id, version, tenant_id, threshold, custodian_ids, epoch_index,
                   epoch_valid_from, epoch_valid_until, rotation_interval, status)
                VALUES ($1, 1, $2, $3, $4, 0, $5, $6, $7, 'active')
                """,
                body.policy_id,
                tenant["id"],
                body.threshold,
                body.custodian_ids,
                body.epoch.valid_from,
                body.epoch.valid_until,
                body.epoch.rotation_interval,
            )
            await conn.execute(
                "INSERT INTO policy_heads (policy_id, tenant_id, current_version) VALUES ($1, $2, 1)",
                body.policy_id, tenant["id"],
            )
            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="policy.create", resource=f"{body.policy_id}:1", result="ok",
                basis={"threshold": body.threshold, "custodian_count": len(body.custodian_ids)},
            )
        row = await repo.get_policy_version(conn, body.policy_id, 1)
    return _policy_out(row)


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: str, request: Request, tenant=deps.Tenant, version: int | None = None) -> PolicyOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        ver = version if version is not None else await repo.get_head_version(conn, policy_id)
        if ver is None:
            raise ApiError(E_NOT_FOUND, basis={"policy_id": policy_id})
        row = await repo.get_policy_version(conn, policy_id, ver)
    if row is None:
        raise ApiError(E_NOT_FOUND, basis={"policy_id": policy_id, "version": ver})
    if row["tenant_id"] != tenant["id"]:
        raise ApiError(E_FORBIDDEN, basis={"reason": "policy_belongs_to_other_tenant"})
    return _policy_out(row)


async def _load_owned_active_head(conn, tenant_id: str, policy_id: str, expected_version: int):
    head = await conn.fetchrow(
        """
        SELECT h.current_version, p.*
        FROM policy_heads h
        JOIN policies p ON p.id = h.policy_id AND p.version = h.current_version
        WHERE h.policy_id = $1 AND h.tenant_id = $2
        """,
        policy_id, tenant_id,
    )
    if head is None:
        raise ApiError(E_NOT_FOUND, basis={"policy_id": policy_id})
    if head["current_version"] != expected_version:
        raise ApiError(
            E_VERSION_CONFLICT,
            basis={"expected_version": expected_version, "current_version": head["current_version"]},
        )
    if head["status"] != "active":
        raise ApiError(E_POLICY_INACTIVE, basis={"policy_id": policy_id, "status": head["status"]})
    return head


@router.post("/{policy_id}/rotate", response_model=PolicyOut)
async def rotate_policy(policy_id: str, body: RotateIn, request: Request, tenant=deps.Tenant) -> PolicyOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", policy_id)
            head = await _load_owned_active_head(conn, tenant["id"], policy_id, body.expected_version)

            # 全局行锁序：custody 行先于 policy 行。先按 id 序锁定该旧版本下的
            # 全部 custody 行（含非 active 的，保证锁集是迁移创建源锁的超集），
            # 随后才 UPDATE policy 版本行——与迁移创建（源 custody 行锁 → 源/
            # 目标 policy 版本行 FOR UPDATE）及销毁/提交路径的加锁顺序完全一致。
            # 否则 rotate 持 policy 行锁等 custody、而并发迁移创建持 custody 等
            # policy 行锁会形成锁序反转死锁；统一顺序后“策略撤销 × 重建插入”
            # 必有确定性先后：谁先持锁谁决定。
            await conn.fetch(
                "SELECT id FROM key_custodies "
                "WHERE policy_id=$1 AND policy_version=$2 ORDER BY id FOR UPDATE",
                policy_id, head["current_version"],
            )

            custodian_ids = body.custodian_ids if body.custodian_ids is not None else list(head["custodian_ids"])
            threshold = body.threshold if body.threshold is not None else head["threshold"]
            if not 1 <= threshold <= len(custodian_ids):
                raise ApiError(
                    E_POLICY_PARAMS,
                    basis={
                        "threshold": threshold,
                        "custodian_count": len(custodian_ids),
                        "rule": "1 <= threshold <= custodian_count",
                    },
                )
            await repo.resolve_custodian_ids(conn, custodian_ids)

            new_version = head["current_version"] + 1
            new_epoch = head["epoch_index"] + 1
            await conn.execute(
                """
                INSERT INTO policies
                  (id, version, tenant_id, threshold, custodian_ids, epoch_index,
                   epoch_valid_from, epoch_valid_until, rotation_interval, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active')
                """,
                policy_id, new_version, tenant["id"], threshold, custodian_ids, new_epoch,
                body.epoch.valid_from, body.epoch.valid_until, body.epoch.rotation_interval,
            )
            # 旧版本原子转为 revoked（其 epoch 不再可用于新的托管/恢复）
            await conn.execute(
                "UPDATE policies SET status='revoked' WHERE id=$1 AND version=$2",
                policy_id, head["current_version"],
            )
            await conn.execute(
                "UPDATE key_custodies SET status='rotated' WHERE policy_id=$1 AND policy_version=$2 AND status='active'",
                policy_id, head["current_version"],
            )
            await conn.execute(
                "UPDATE policy_heads SET current_version=$2, updated_at=now() WHERE policy_id=$1",
                policy_id, new_version,
            )
            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="policy.rotate", resource=f"{policy_id}:{new_version}", result="ok",
                basis={
                    "from_version": head["current_version"],
                    "to_version": new_version,
                    "new_epoch": new_epoch,
                    "threshold": threshold,
                    "custodian_count": len(custodian_ids),
                },
            )
            row = await repo.get_policy_version(conn, policy_id, new_version)
    return _policy_out(row)


@router.post("/{policy_id}/revoke", response_model=PolicyOut)
async def revoke_epoch(policy_id: str, body: RevokeEpochIn, request: Request, tenant=deps.Tenant) -> PolicyOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", policy_id)
            head = await _load_owned_active_head(conn, tenant["id"], policy_id, body.expected_version)
            # 全局行锁序（custody 先于 policy）：先锁定该版本下的全部 custody
            # 行再置 policy 行为 revoked，与迁移创建/轮换同一加锁顺序，杜绝
            # “目标撤销 × 迁移（重建）插入”的锁序反转死锁，先后确定。
            await conn.fetch(
                "SELECT id FROM key_custodies "
                "WHERE policy_id=$1 AND policy_version=$2 ORDER BY id FOR UPDATE",
                policy_id, head["current_version"],
            )
            await conn.execute(
                "UPDATE policies SET status='revoked' WHERE id=$1 AND version=$2",
                policy_id, head["current_version"],
            )
            await conn.execute(
                "UPDATE key_custodies SET status='revoked' WHERE policy_id=$1 AND policy_version=$2 AND status='active'",
                policy_id, head["current_version"],
            )
            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="policy.epoch.revoke", resource=f"{policy_id}:{head['current_version']}",
                result="ok",
                basis={"version": head["current_version"], "epoch": head["epoch_index"]},
            )
            row = await repo.get_policy_version(conn, policy_id, head["current_version"])
    return _policy_out(row)
