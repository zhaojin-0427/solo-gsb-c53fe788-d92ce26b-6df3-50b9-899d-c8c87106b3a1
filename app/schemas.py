from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_SIG = re.compile(r"^[0-9a-fA-F]{128}$")
_HEX32_PUB = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_EVEN = re.compile(r"^(0x)?[0-9a-fA-F]*$")


class RegisterTenantIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class RegisterTenantOut(BaseModel):
    tenant_id: str
    name: str
    api_key: str
    api_key_hint: str


class RegisterCustodianIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class RegisterCustodianOut(BaseModel):
    custodian_id: str
    name: str
    api_key: str
    signing_public_key: str
    signing_private_key: str  # 仅创建时返回一次


class EpochSpec(BaseModel):
    valid_from: datetime
    valid_until: datetime
    rotation_interval: int = Field(ge=0, le=365 * 24 * 3600)

    @field_validator("valid_until")
    @classmethod
    def _order(cls, v: datetime, info):
        start = info.data.get("valid_from")
        if start and v <= start:
            raise ValueError("valid_until must be after valid_from")
        return v


class PolicyCreateIn(BaseModel):
    policy_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    threshold: int = Field(ge=1, le=255)
    custodian_ids: list[str] = Field(min_length=1, max_length=255)
    epoch: EpochSpec


class PolicyOut(BaseModel):
    policy_id: str
    version: int
    threshold: int
    custodian_ids: list[str]
    epoch_index: int
    epoch_valid_from: datetime
    epoch_valid_until: datetime
    rotation_interval: int
    status: str
    created_at: datetime


class RotateIn(BaseModel):
    expected_version: int = Field(ge=1)
    custodian_ids: list[str] | None = Field(default=None, max_length=255)
    threshold: int | None = Field(default=None, ge=1, le=255)
    epoch: EpochSpec


class RevokeEpochIn(BaseModel):
    expected_version: int = Field(ge=1)


class CustodyIn(BaseModel):
    policy_id: str
    expected_version: int = Field(ge=1)
    secret_hex: str = Field(min_length=2, max_length=8194)

    @field_validator("secret_hex")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(r"(0x)?[0-9a-fA-F]+", v) or len(v) % 2 != 0:
            raise ValueError("secret_hex must be even-length hex (optional 0x prefix)")
        return v.removeprefix("0x").removeprefix("0X")


class CustodyOut(BaseModel):
    custody_id: str
    policy_id: str
    policy_version: int
    epoch_index: int
    secret_digest: str
    shard_count: int
    shard_digests: list[str]


class RecoveryStartIn(BaseModel):
    custody_id: str
    request_digest: str = Field(pattern=_HEX32)
    recovery_public_key: str = Field(pattern=_HEX32_PUB)
    ttl_seconds: int | None = Field(default=None, ge=10, le=600)


class RecoverySessionOut(BaseModel):
    session_id: str
    custody_id: str
    policy_id: str
    policy_version: int
    epoch_index: int
    request_digest: str
    status: str
    valid_until: datetime
    shares_received: int
    threshold: int


class NonceRequestIn(BaseModel):
    session_id: str


class NonceOut(BaseModel):
    nonce_id: str
    nonce: str
    session_id: str
    custodian_id: str
    policy_id: str
    policy_version: int
    point_x: int
    shard_digest: str
    # 领取本人分片后再对 signing_message 签名：
    # 该报文绑定 nonce/会话/策略版本/托管人/点位/分片摘要。
    next_step: str = "claim your shard at POST /recoveries/shards/claim, then sign signing_message and POST /recoveries/shares"


class ShardClaimIn(BaseModel):
    session_id: str
    nonce: str = Field(pattern=_HEX32)


class ShardClaimOut(BaseModel):
    session_id: str
    nonce_id: str
    custodian_id: str
    policy_id: str
    policy_version: int
    custody_id: str
    point_x: int
    shard_digest: str
    # 本人分片明文（仅在本次 HTTPS 响应中出现；服务端从不记录它）
    shard_hex: str
    # 待签名的规范报文（包含 point 与 shard_digest）
    signing_message: str


class ShareSubmitIn(BaseModel):
    # shard blob = 32 字节/块 * ceil(max_secret/31)；max_secret=4096 时上限 4256 字节
    session_id: str
    nonce: str = Field(pattern=_HEX32)
    point_x: int = Field(ge=1, le=65535)
    shard_hex: str = Field(min_length=2, max_length=8512)
    signature: str = Field(pattern=_HEX_SIG)

    @field_validator("shard_hex")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(_HEX_EVEN, v) or len(v) % 2 != 0:
            raise ValueError("shard_hex must be even-length hex (optional 0x prefix)")
        return v.removeprefix("0x").removeprefix("0X")


class ShareSubmitOut(BaseModel):
    session_id: str
    status: str
    shares_received: int
    threshold: int
    completed: bool
    wrap: dict | None = None
    aad: str | None = None


# ---------------------------------------------------------------------------
# Cross-policy key migration
# ---------------------------------------------------------------------------

class MigrationStartIn(BaseModel):
    source_custody_id: str
    target_policy_id: str = Field(min_length=1, max_length=64)
    target_version: int = Field(ge=1)
    ttl_seconds: int | None = Field(default=None, ge=10, le=600)


class MigrationSessionOut(BaseModel):
    migration_id: str
    source_custody_id: str
    source_policy_id: str
    source_version: int
    source_digest: str
    target_policy_id: str
    target_version: int
    target_digest: str
    status: str
    valid_until: datetime
    shares_received: int
    threshold: int
    new_custody_id: str | None = None
    new_shard_count: int | None = None
    new_shard_digests: list[str] | None = None


class MigrationNonceRequestIn(BaseModel):
    migration_id: str


class MigrationNonceOut(BaseModel):
    nonce_id: str
    nonce: str
    migration_id: str
    custodian_id: str
    source_policy_id: str
    source_version: int
    source_digest: str
    target_policy_id: str
    target_version: int
    target_digest: str
    point_x: int
    shard_digest: str
    next_step: str = "claim your shard at POST /migrations/shards/claim, then sign signing_message and POST /migrations/shares"


class MigrationShardClaimIn(BaseModel):
    migration_id: str
    nonce: str = Field(pattern=_HEX32)


class MigrationShardClaimOut(BaseModel):
    migration_id: str
    nonce_id: str
    custodian_id: str
    source_policy_id: str
    source_version: int
    source_custody_id: str
    source_digest: str
    target_policy_id: str
    target_version: int
    target_digest: str
    point_x: int
    shard_digest: str
    # 本人源分片明文（仅在本次 HTTPS 响应中出现；服务端从不记录它）
    shard_hex: str
    signing_message: str


class MigrationShareSubmitIn(BaseModel):
    migration_id: str
    nonce: str = Field(pattern=_HEX32)
    point_x: int = Field(ge=1, le=65535)
    shard_hex: str = Field(min_length=2, max_length=8512)
    signature: str = Field(pattern=_HEX_SIG)

    @field_validator("shard_hex")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(_HEX_EVEN, v) or len(v) % 2 != 0:
            raise ValueError("shard_hex must be even-length hex (optional 0x prefix)")
        return v.removeprefix("0x").removeprefix("0X")


class MigrationShareSubmitOut(BaseModel):
    migration_id: str
    status: str
    shares_received: int
    threshold: int
    completed: bool
    # 门限达成的那一次：新托管记录标识与新分片摘要（全程无明文）
    new_custody_id: str | None = None
    new_shard_count: int | None = None
    new_shard_digests: list[str] | None = None


# ---------------------------------------------------------------------------
# Logical record-lineage destruction (v1.6)
# ---------------------------------------------------------------------------

class DestructionStartIn(BaseModel):
    # 待销毁谱系的根托管记录：销毁覆盖该记录及其沿“已完成迁移关系”的全部后代
    root_custody_id: str


class DestructionReceiptOut(BaseModel):
    destruction_id: str
    status: str
    root_custody_id: str
    # 幂等键只回显其 sha256 摘要；同键重试返回同一份回执
    idempotency_key_digest: str
    custody_count: int
    recovery_blocked: int
    migration_blocked: int
    shards_deleted: int
    custody_ids: list[str]
    created_at: datetime
    # 销毁边界：仅擦除服务在线数据，不宣称擦除外部备份
    scope: str = "online_service_data_only"
