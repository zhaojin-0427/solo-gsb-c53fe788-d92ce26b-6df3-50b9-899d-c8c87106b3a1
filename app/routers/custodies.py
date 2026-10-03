from __future__ import annotations

from fastapi import APIRouter, Request

from .. import audit, crypto, deps, repo
from ..config import get_settings
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_EPOCH_EXPIRED,
    E_EPOCH_REVOKED,
    E_FORBIDDEN,
    E_NOT_FOUND,
    E_POLICY_INACTIVE,
    E_VERSION_CONFLICT,
)
from ..schemas import CustodyIn, CustodyOut

router = APIRouter(prefix="/custodies", tags=["custodies"])


@router.post("", response_model=CustodyOut, status_code=201)
async def submit_secret(body: CustodyIn, request: Request, tenant=deps.Tenant) -> CustodyOut:
    settings = get_settings()
    secret = bytes.fromhex(body.secret_hex)
    if not secret:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "empty_secret"})
    if len(secret) > settings.max_secret_bytes:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "secret_too_large", "max": settings.max_secret_bytes})

    secret_digest = crypto.sha256_hex(secret)
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", body.policy_id)
            head_ver = await repo.get_head_version(conn, body.policy_id)
            if head_ver is None:
                raise ApiError(E_NOT_FOUND, basis={"policy_id": body.policy_id})
            if head_ver != body.expected_version:
                raise ApiError(
                    E_VERSION_CONFLICT,
                    basis={"expected_version": body.expected_version, "current_version": head_ver},
                )
            policy = await repo.get_policy_version(conn, body.policy_id, head_ver)
            if policy["tenant_id"] != tenant["id"]:
                raise ApiError(E_FORBIDDEN, basis={"reason": "policy_belongs_to_other_tenant"})
            if policy["status"] == "revoked":
                raise ApiError(
                    E_EPOCH_REVOKED,
                    basis={"policy_id": body.policy_id, "version": head_ver, "epoch": policy["epoch_index"]},
                )
            if policy["status"] != "active":
                raise ApiError(E_POLICY_INACTIVE, basis={"status": policy["status"]})
            now = await conn.fetchval("SELECT now()")
            if now >= policy["epoch_valid_until"]:
                raise ApiError(
                    E_EPOCH_EXPIRED,
                    basis={
                        "epoch": policy["epoch_index"],
                        "valid_until": str(policy["epoch_valid_until"]),
                        "now": str(now),
                    },
                )

            custodian_ids = list(policy["custodian_ids"])
            points = crypto.shamir_split(secret, policy["threshold"], len(custodian_ids))

            custody_id = deps.new_id("cus_secret")
            await conn.execute(
                """
                INSERT INTO key_custodies
                  (id, tenant_id, policy_id, policy_version, secret_digest, secret_length,
                   epoch_index, status)
                VALUES ($1,$2,$3,$4,$5,$6,$7,'active')
                """,
                custody_id, tenant["id"], body.policy_id, head_ver,
                secret_digest, len(secret), policy["epoch_index"],
            )

            shard_digests: list[str] = []
            for (x, blob), custodian_id in zip(points, custodian_ids):
                shard_id = deps.new_id("shd")
                ct = crypto.encrypt_shard(settings.shard_master_key_bytes, shard_id, blob)
                shard_digest = crypto.sha256_hex(blob)
                shard_digests.append(shard_digest)
                await conn.execute(
                    """
                    INSERT INTO shards (id, custody_id, custodian_id, point_x, ciphertext, shard_digest)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    shard_id, custody_id, custodian_id, x, ct, shard_digest,
                )

            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="custody.create", resource=custody_id, result="ok",
                basis={
                    "policy_id": body.policy_id,
                    "policy_version": head_ver,
                    "epoch": policy["epoch_index"],
                    "secret_digest": secret_digest,
                    "shard_count": len(custodian_ids),
                },
            )

    return CustodyOut(
        custody_id=custody_id,
        policy_id=body.policy_id,
        policy_version=head_ver,
        epoch_index=policy["epoch_index"],
        secret_digest=secret_digest,
        shard_count=len(custodian_ids),
        shard_digests=shard_digests,
    )
