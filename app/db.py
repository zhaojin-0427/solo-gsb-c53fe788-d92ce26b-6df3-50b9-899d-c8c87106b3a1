from __future__ import annotations

import asyncio

import asyncpg

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS custodians (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL UNIQUE,
    signing_pubkey  BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 不可变策略版本：policy_id + version 唯一，一经写入永不修改。
CREATE TABLE IF NOT EXISTS policies (
    id                  TEXT NOT NULL,
    version             INTEGER NOT NULL,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    threshold           INTEGER NOT NULL CHECK (threshold BETWEEN 1 AND 1024),
    custodian_ids       TEXT[] NOT NULL,
    epoch_index         INTEGER NOT NULL DEFAULT 0,
    epoch_valid_from    TIMESTAMPTZ NOT NULL,
    epoch_valid_until   TIMESTAMPTZ NOT NULL,
    rotation_interval   INTEGER NOT NULL,           -- 秒；0 表示不自动轮换
    status              TEXT NOT NULL DEFAULT 'active',  -- active | revoked
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, version),
    CHECK (threshold <= array_length(custodian_ids, 1))
);

-- 每租户策略头：指针式版本推进，配合行锁原子轮换/撤销。
CREATE TABLE IF NOT EXISTS policy_heads (
    policy_id       TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    current_version INTEGER NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 复合外键指向不可变版本行；CREATE TABLE 中不能声明单列外键（policies 为复合主键）。
ALTER TABLE policy_heads DROP CONSTRAINT IF EXISTS policy_heads_current_version_fkey;
ALTER TABLE policy_heads
    ADD CONSTRAINT policy_heads_current_version_fkey
    FOREIGN KEY (policy_id, current_version) REFERENCES policies(id, version);

CREATE TABLE IF NOT EXISTS key_custodies (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    policy_id         TEXT NOT NULL,
    policy_version    INTEGER NOT NULL,
    secret_digest     TEXT NOT NULL,
    secret_length     INTEGER NOT NULL,
    epoch_index       INTEGER NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active',  -- active | rotated | revoked | destroyed
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    destroyed_at      TIMESTAMPTZ,
    FOREIGN KEY (policy_id, policy_version) REFERENCES policies(id, version)
);
CREATE INDEX IF NOT EXISTS idx_custody_tenant ON key_custodies(tenant_id);
-- 旧库平滑升级：destroyed_at 随 v1.6 逻辑销毁引入。
ALTER TABLE key_custodies ADD COLUMN IF NOT EXISTS destroyed_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS shards (
    id              TEXT PRIMARY KEY,
    custody_id      TEXT NOT NULL REFERENCES key_custodies(id) ON DELETE CASCADE,
    custodian_id    TEXT NOT NULL,
    point_x         INTEGER NOT NULL,
    ciphertext      BYTEA NOT NULL,
    shard_digest    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (custody_id, custodian_id)
);
CREATE INDEX IF NOT EXISTS idx_shards_custody ON shards(custody_id);

CREATE TABLE IF NOT EXISTS recovery_sessions (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    custody_id        TEXT NOT NULL REFERENCES key_custodies(id),
    policy_id         TEXT NOT NULL,
    policy_version    INTEGER NOT NULL,
    epoch_index       INTEGER NOT NULL,
    request_digest    TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open',  -- open | completed | destroyed
    recovery_pubkey   TEXT NOT NULL,
    valid_until       TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_tenant ON recovery_sessions(tenant_id);

CREATE TABLE IF NOT EXISTS session_nonces (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES recovery_sessions(id) ON DELETE CASCADE,
    custodian_id  TEXT NOT NULL,
    nonce_hash    TEXT NOT NULL UNIQUE,          -- 一次性：全局唯一
    spent         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, custodian_id)            -- 每会话每托管人至多一张
);

CREATE TABLE IF NOT EXISTS share_submissions (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES recovery_sessions(id) ON DELETE CASCADE,
    custodian_id    TEXT NOT NULL,
    nonce_id        TEXT NOT NULL REFERENCES session_nonces(id),
    point_x         INTEGER NOT NULL,            -- 托管人在该策略版本中的分片点位
    shard_digest    TEXT NOT NULL,               -- 已验签提交分片的摘要（绝不存明文）
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, custodian_id)            -- 拒绝重复提交
);
CREATE INDEX IF NOT EXISTS idx_share_session ON share_submissions(session_id);

-- 旧库平滑升级（IF NOT EXISTS 对列同样幂等）；新库这两列已随建表存在。
ALTER TABLE share_submissions ADD COLUMN IF NOT EXISTS point_x INTEGER;
ALTER TABLE share_submissions ADD COLUMN IF NOT EXISTS shard_digest TEXT;

-- 跨策略密钥迁移会话：租户以幂等键创建，绑定源 custody 与源/目标“策略版本摘要”。
-- 源门限达成后秘密仅在内存重组、立即按目标策略重新分片，新托管记录同事务写入；
-- 源记录保持 active 不变。已计数分片的内存明文丢失（重启/淘汰）时，检出缺片的
-- 提交在同一事务里把会话置 failed 终态，释放 open 占位供重新发起。
CREATE TABLE IF NOT EXISTS migration_sessions (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    source_custody_id   TEXT NOT NULL REFERENCES key_custodies(id),
    source_policy_id    TEXT NOT NULL,
    source_version      INTEGER NOT NULL,
    source_digest       TEXT NOT NULL,          -- 创建时固化的源策略版本摘要
    target_policy_id    TEXT NOT NULL,
    target_version      INTEGER NOT NULL,
    target_digest       TEXT NOT NULL,          -- 创建时固化的目标策略版本摘要
    idempotency_key_hash TEXT NOT NULL,         -- 只存幂等键摘要
    status              TEXT NOT NULL DEFAULT 'open',  -- open | completed | expired | failed | destroyed
    new_custody_id      TEXT REFERENCES key_custodies(id),
    valid_until         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_migration_tenant ON migration_sessions(tenant_id);
-- 幂等：同租户同一幂等键的“有效(open)”会话唯一；completed 行保留以便幂等重放，
-- expired/failed 行不占位（终态后允许用同一键或新键安全重试）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_idem_open
    ON migration_sessions(tenant_id, idempotency_key_hash)
    WHERE status = 'open';
-- 并发/重复迁移拦截：同一源托管记录至多一个 open 会话（failed 终态立即释放占位）；
-- 已完成迁移（new_custody_id 非空）全局唯一——不同幂等键也不得重复迁移。
CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_source_open
    ON migration_sessions(source_custody_id) WHERE status = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_source_completed
    ON migration_sessions(source_custody_id) WHERE new_custody_id IS NOT NULL;

-- 迁移一次性 nonce：库里只存摘要，UNIQUE(nonce_hash) + UNIQUE(migration_id, custodian_id)。
CREATE TABLE IF NOT EXISTS migration_nonces (
    id            TEXT PRIMARY KEY,
    migration_id  TEXT NOT NULL REFERENCES migration_sessions(id) ON DELETE CASCADE,
    custodian_id  TEXT NOT NULL,
    nonce_hash    TEXT NOT NULL UNIQUE,
    spent         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (migration_id, custodian_id)
);

-- 迁移过程中已验签的提交（只存点位与摘要，绝不存分片明文/重组秘密）。
CREATE TABLE IF NOT EXISTS migration_share_submissions (
    id              TEXT PRIMARY KEY,
    migration_id    TEXT NOT NULL REFERENCES migration_sessions(id) ON DELETE CASCADE,
    custodian_id    TEXT NOT NULL,
    nonce_id        TEXT NOT NULL REFERENCES migration_nonces(id),
    point_x         INTEGER NOT NULL,
    shard_digest    TEXT NOT NULL,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (migration_id, custodian_id)
);
CREATE INDEX IF NOT EXISTS idx_migration_share_session ON migration_share_submissions(migration_id);
ALTER TABLE migration_share_submissions ADD COLUMN IF NOT EXISTS point_x INTEGER;
ALTER TABLE migration_share_submissions ADD COLUMN IF NOT EXISTS shard_digest TEXT;

-- 逻辑销毁回执：租户以幂等键发起，对指定托管记录沿“已完成迁移关系”
-- 找出全部后代，在同一事务内阻断在途恢复/迁移、标记记录已销毁并删除在线
-- 加密分片；本表只保存无秘密的回执（ID/摘要/计数），不保存任何分片或秘密。
-- 销毁仅覆盖服务在线数据，不宣称擦除外部备份。
CREATE TABLE IF NOT EXISTS destructions (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants(id),
    root_custody_id       TEXT NOT NULL REFERENCES key_custodies(id),
    idempotency_key_hash  TEXT NOT NULL,            -- 只存幂等键摘要
    custody_count         INTEGER NOT NULL,         -- 本次覆盖的谱系记录数
    recovery_blocked      INTEGER NOT NULL,         -- 置 destroyed 的在途恢复会话数
    migration_blocked     INTEGER NOT NULL,         -- 置 destroyed 的在途迁移会话数
    shards_deleted        INTEGER NOT NULL,         -- 删除的在线加密分片数
    custody_ids           JSONB NOT NULL,           -- 谱系全部 custody id（含根）
    status                TEXT NOT NULL DEFAULT 'completed',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_destruction_tenant ON destructions(tenant_id);
-- 幂等回执：同租户同一幂等键至多一份销毁回执（重放返回同一销毁回执）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_destruction_idem
    ON destructions(tenant_id, idempotency_key_hash);

-- 仅追加、哈希链审计日志（不含任何秘密材料）。
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT,
    actor_type   TEXT NOT NULL,                  -- tenant | custodian | admin | system
    actor_id     TEXT,
    action       TEXT NOT NULL,
    resource     TEXT,
    result       TEXT NOT NULL,                  -- ok | denied | error
    error_code   TEXT,
    basis        JSONB NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL DEFAULT '',
    entry_hash   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_seq ON audit_log(tenant_id, seq);
"""


class Database:
    def __init__(self, url: str):
        self._url = url
        self.pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        async def _init(conn: asyncpg.Connection) -> None:
            await conn.set_type_codec("jsonb", encoder=str, decoder=str, schema="pg_catalog")

        self.pool = await asyncpg.create_pool(self._url, init=_init, min_size=2, max_size=20)
        await self.init_schema()

    async def init_schema(self) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(SCHEMA)

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()


db = Database("postgresql://localhost")  # url replaced in app startup


async def wait_for_database(url: str, attempts: int = 30, delay: float = 1.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            conn = await asyncpg.connect(url)
            await conn.close()
            return
        except Exception as exc:  # noqa: BLE001 - DB may still be starting
            last = exc
            await asyncio.sleep(delay)
    raise RuntimeError(f"database not reachable: {last}")
