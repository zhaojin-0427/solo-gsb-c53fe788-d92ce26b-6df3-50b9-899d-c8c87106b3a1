from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from .. import audit, crypto, deps
from ..schemas import (
    RegisterCustodianIn,
    RegisterCustodianOut,
    RegisterTenantIn,
    RegisterTenantOut,
)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/tenants", response_model=RegisterTenantOut, status_code=201,
             dependencies=[Depends(deps.require_admin)])
async def register_tenant(body: RegisterTenantIn, request: Request) -> RegisterTenantOut:
    pool = request.app.state.db.pool
    tenant_id = deps.new_id("ten")
    api_key, api_key_hash = deps.new_api_key("tsec")
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, $2, $3)",
                tenant_id, body.name, api_key_hash,
            )
            await audit.append_audit(
                conn, tenant_id=tenant_id, actor_type="admin", actor_id=None,
                action="tenant.register", resource=tenant_id, result="ok",
            )
    return RegisterTenantOut(
        tenant_id=tenant_id, name=body.name, api_key=api_key, api_key_hint=api_key[:9] + "…"
    )


@router.post("/custodians", response_model=RegisterCustodianOut, status_code=201,
             dependencies=[Depends(deps.require_admin)])
async def register_custodian(body: RegisterCustodianIn, request: Request) -> RegisterCustodianOut:
    pool = request.app.state.db.pool
    custodian_id = deps.new_id("cus")
    api_key, api_key_hash = deps.new_api_key("csec")
    priv_raw, pub_raw = crypto.generate_signing_keypair()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO custodians (id, name, api_key_hash, signing_pubkey) VALUES ($1, $2, $3, $4)",
                custodian_id, body.name, api_key_hash, pub_raw,
            )
            await audit.append_audit(
                conn, tenant_id=None, actor_type="admin", actor_id=None,
                action="custodian.register", resource=custodian_id, result="ok",
            )
    return RegisterCustodianOut(
        custodian_id=custodian_id,
        name=body.name,
        api_key=api_key,
        signing_public_key=pub_raw.hex(),
        signing_private_key=priv_raw.hex(),
    )
