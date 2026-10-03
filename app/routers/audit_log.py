from __future__ import annotations

from fastapi import APIRouter, Request

from .. import audit, deps

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/replay")
async def replay(request: Request, tenant=deps.Tenant) -> dict:
    """重放租户可见的哈希链，验证审计日志按序、未被篡改。"""
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        return await audit.replay(conn, tenant_id=tenant["id"])
