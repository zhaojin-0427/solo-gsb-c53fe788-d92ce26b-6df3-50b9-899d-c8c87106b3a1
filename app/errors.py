from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# 确定性错误码：调用方依据 code + basis 可程序化判定拒绝原因，不依赖 message 文本。
# ---------------------------------------------------------------------------

E_BAD_REQUEST = "BAD_REQUEST"
E_UNAUTHORIZED = "UNAUTHORIZED"
E_FORBIDDEN = "FORBIDDEN"
E_NOT_FOUND = "NOT_FOUND"
E_VALIDATION = "VALIDATION_FAILED"
E_POLICY_PARAMS = "POLICY_PARAMS_INVALID"
E_POLICY_INACTIVE = "POLICY_INACTIVE"
E_VERSION_CONFLICT = "VERSION_CONFLICT"
E_EPOCH_REVOKED = "EPOCH_REVOKED"
E_EPOCH_EXPIRED = "EPOCH_EXPIRED"
E_NONCE_USED = "NONCE_ALREADY_USED"
E_BAD_SIGNATURE = "BAD_SIGNATURE"
E_DUPLICATE_SHARE = "DUPLICATE_SHARE"
E_CROSS_POLICY_SHARE = "CROSS_POLICY_SHARE"
E_SESSION_COMPLETED = "SESSION_COMPLETED"
E_SESSION_EXPIRED = "SESSION_EXPIRED"
E_THRESHOLD_NOT_MET = "THRESHOLD_NOT_MET"
E_INTEGRITY = "INTEGRITY_CHECK_FAILED"
E_SHARE_POINT = "SHARE_POINT_MISMATCH"
E_SHARE_DIGEST = "SHARE_DIGEST_MISMATCH"
E_RATE_LIMITED = "RATE_LIMITED"
E_INTERNAL = "INTERNAL_ERROR"
# 跨策略密钥迁移
E_IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
E_MIGRATION_TARGET_INVALID = "MIGRATION_TARGET_INVALID"
E_MIGRATION_SOURCE_INVALID = "MIGRATION_SOURCE_INVALID"
E_MIGRATION_DIGEST_MISMATCH = "MIGRATION_DIGEST_MISMATCH"
E_MIGRATION_CONFLICT = "MIGRATION_CONFLICT"
E_MIGRATION_COMPLETED = "MIGRATION_COMPLETED"
E_MIGRATION_FAILED = "MIGRATION_FAILED"
# v1.6 托管记录谱系逻辑销毁
E_CUSTODY_DESTROYED = "CUSTODY_DESTROYED"

_STATUS = {
    E_BAD_REQUEST: 400,
    E_UNAUTHORIZED: 401,
    E_FORBIDDEN: 403,
    E_NOT_FOUND: 404,
    E_VALIDATION: 400,
    E_POLICY_PARAMS: 400,
    E_POLICY_INACTIVE: 409,
    E_VERSION_CONFLICT: 409,
    E_EPOCH_REVOKED: 409,
    E_EPOCH_EXPIRED: 409,
    E_NONCE_USED: 409,
    E_BAD_SIGNATURE: 400,
    E_DUPLICATE_SHARE: 409,
    E_CROSS_POLICY_SHARE: 409,
    E_SESSION_COMPLETED: 409,
    E_SESSION_EXPIRED: 409,
    E_THRESHOLD_NOT_MET: 409,
    E_INTEGRITY: 409,
    E_SHARE_POINT: 400,
    E_SHARE_DIGEST: 400,
    E_RATE_LIMITED: 400,
    E_INTERNAL: 500,
    E_IDEMPOTENCY_CONFLICT: 409,
    E_MIGRATION_TARGET_INVALID: 409,
    E_MIGRATION_SOURCE_INVALID: 409,
    E_MIGRATION_DIGEST_MISMATCH: 409,
    E_MIGRATION_CONFLICT: 409,
    E_MIGRATION_COMPLETED: 409,
    E_MIGRATION_FAILED: 409,
    E_CUSTODY_DESTROYED: 410,
}

_MESSAGES = {
    E_BAD_REQUEST: "malformed request",
    E_UNAUTHORIZED: "missing or invalid api key",
    E_FORBIDDEN: "caller is not allowed to access this resource",
    E_NOT_FOUND: "resource not found",
    E_VALIDATION: "request validation failed",
    E_POLICY_PARAMS: "policy parameters invalid (require 1 <= threshold <= custodians)",
    E_POLICY_INACTIVE: "policy head is not active",
    E_VERSION_CONFLICT: "expected_version does not match current head",
    E_EPOCH_REVOKED: "epoch has been revoked",
    E_EPOCH_EXPIRED: "epoch validity window has expired",
    E_NONCE_USED: "nonce has already been spent",
    E_BAD_SIGNATURE: "custodian signature verification failed",
    E_DUPLICATE_SHARE: "custodian already submitted a share for this session",
    E_CROSS_POLICY_SHARE: "share does not bind to this policy version",
    E_SESSION_COMPLETED: "recovery session is already completed",
    E_SESSION_EXPIRED: "recovery session has expired",
    E_THRESHOLD_NOT_MET: "not enough valid shares to reconstruct",
    E_INTEGRITY: "stored digest mismatch; secret or shard integrity violated",
    E_SHARE_POINT: "submitted shard point does not match this custodian's assigned point",
    E_SHARE_DIGEST: "digest of submitted shard does not match inventory digest for this custodian",
    E_RATE_LIMITED: "too many requests",
    E_INTERNAL: "internal error",
    E_IDEMPOTENCY_CONFLICT: "idempotency key is already bound to a different request",
    E_MIGRATION_TARGET_INVALID: "target policy version is revoked, expired, cross-tenant or identical to the source",
    E_MIGRATION_SOURCE_INVALID: "source custody record is not valid for migration (not active or its policy version revoked/expired)",
    E_MIGRATION_DIGEST_MISMATCH: "bound source/target policy version digest no longer matches the immutable record",
    E_MIGRATION_CONFLICT: "a different open migration already exists for this custody, or the same custody is already migrated",
    E_MIGRATION_COMPLETED: "migration session is already completed",
    E_MIGRATION_FAILED: "migration session has terminally failed (committed shares lost from memory); start a new migration session",
    E_CUSTODY_DESTROYED: "custody record (or its migration lineage) has been logically destroyed; online shards are deleted and in-flight recovery/migration is blocked",
}


class ApiError(Exception):
    def __init__(self, code: str, *, basis: dict[str, Any] | None = None, message: str | None = None):
        self.code = code
        self.basis = basis or {}
        self.message = message or _MESSAGES.get(code, code)
        super().__init__(self.message)

    @property
    def status_code(self) -> int:
        return _STATUS.get(self.code, 500)


def error_response(exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "basis": exc.basis}},
    )


def install_exception_handlers(app) -> None:  # noqa: ANN001
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": E_VALIDATION,
                    "message": _MESSAGES[E_VALIDATION],
                    "basis": {
                        "fields": [
                            {"loc": ".".join(str(p) for p in e["loc"] if p != "body"),
                             "type": e["type"], "msg": e["msg"]}
                            for e in exc.errors()
                        ]
                    },
                }
            },
        )
