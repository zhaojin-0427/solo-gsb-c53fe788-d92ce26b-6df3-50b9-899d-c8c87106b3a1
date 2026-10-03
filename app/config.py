from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KEYVAULT_", env_file=".env", extra="ignore")

    database_url: str = "postgresql://keyvault:keyvault@db:5432/keyvault"
    # 32-byte key (hex or raw). 仅用于加密静态分片；分片本身仍由 n-of-m 门限保护。
    shard_master_key: str = "dev-only-shard-master-key-32bytes"
    admin_api_key: str = "admin-dev-key"
    # 恢复会话默认/上限（秒）
    recovery_default_ttl: int = 300
    recovery_max_ttl: int = 600
    # 待托管密钥上限（字节）
    max_secret_bytes: int = 4096
    # 仅测试：开启并发交错故障注入闸门（生产保持关闭，关闭时零开销）
    fault_injection: bool = False

    @property
    def shard_master_key_bytes(self) -> bytes:
        raw = self.shard_master_key
        try:
            data = bytes.fromhex(raw)
            if len(data) == 32:
                return data
        except ValueError:
            pass
        if len(raw) < 32:
            raise ValueError("KEYVAULT_SHARD_MASTER_KEY must be >= 32 bytes (or 64 hex chars)")
        return raw[:32].encode()


@lru_cache
def get_settings() -> Settings:
    return Settings()
