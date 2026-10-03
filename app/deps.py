from __future__ import annotations

import os

from fastapi import Depends, Header, Request

from . import crypto
from .errors import ApiError, E_FORBIDDEN, E_UNAUTHORIZED


def new_id(prefix: str) -> str:
    return f"{prefix}_{os.urandom(12).hex()}"


def new_api_key(prefix: str) -> tuple[str, str]:
    """Return (plaintext_key, sha256_hex)."""
    key = f"{prefix}_{os.urandom(32).hex()}"
    return key, crypto.sha256_hex(key.encode())


def new_nonce() -> str:
    return os.urandom(32).hex()


async def require_tenant(request: Request, x_api_key: str | None = Header(default=None)) -> dict:
    if not x_api_key:
        raise ApiError(E_UNAUTHORIZED, basis={"missing_header": "X-API-Key"})
    pool = request.app.state.db.pool
    row = await pool.fetchrow(
        "SELECT id, name FROM tenants WHERE api_key_hash = $1",
        crypto.sha256_hex(x_api_key.encode()),
    )
    if not row:
        raise ApiError(E_UNAUTHORIZED, basis={"reason": "api_key_unknown"})
    return {"id": row["id"], "name": row["name"], "actor_type": "tenant"}


async def require_custodian(request: Request, x_api_key: str | None = Header(default=None)) -> dict:
    if not x_api_key:
        raise ApiError(E_UNAUTHORIZED, basis={"missing_header": "X-API-Key"})
    pool = request.app.state.db.pool
    row = await pool.fetchrow(
        "SELECT id, name, signing_pubkey FROM custodians WHERE api_key_hash = $1",
        crypto.sha256_hex(x_api_key.encode()),
    )
    if not row:
        raise ApiError(E_UNAUTHORIZED, basis={"reason": "api_key_unknown"})
    return {
        "id": row["id"],
        "name": row["name"],
        "signing_pubkey": bytes(row["signing_pubkey"]),
        "actor_type": "custodian",
    }


async def require_admin(x_api_key: str | None = Header(default=None)) -> None:
    from .config import get_settings

    expected = get_settings().admin_api_key
    if not x_api_key or not __import__("hmac").compare_digest(x_api_key, expected):
        raise ApiError(E_FORBIDDEN, basis={"required_role": "admin"})


Tenant = Depends(require_tenant)
Custodian = Depends(require_custodian)
Admin = Depends(require_admin)
