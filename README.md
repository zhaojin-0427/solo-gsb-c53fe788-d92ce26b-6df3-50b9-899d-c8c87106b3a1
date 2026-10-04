# 多方密钥分片托管、门限恢复与跨策略迁移 API

租户把待托管密钥交给服务后，服务按 **Shamir 门限秘密分享 (n-of-m)** 切成多份，每份独立加密落盘，
任何单一托管人（甚至数据库运维）都无法还原秘密。恢复时托管人须**先经身份验证领取本人分片**，
再对**一次性 nonce + 会话 + 策略版本 + 托管人 + 分片点位 + 分片摘要**签名，连同**自己的分片字节**
一并提交；服务校验**分片归属、点位与库存摘要**通过后才花费 nonce 并计数。达到门限后，秘密**只由
这些已验签的提交分片在请求内存中重组**（服务端不再解密自己的库存分片来凑数），并用恢复方临时公钥
包装成**一次性密文**返回。

v1.4 新增**跨策略密钥迁移**：租户对仍有效的托管记录指定另一条有效策略版本、携带**幂等键**创建
迁移会话（会话固化源/目标**策略版本摘要**）；旧策略托管人按一次性挑战值领取并提交本人分片及签名，
达到**源门限**后秘密仅在内存重组、**立即按目标策略重新分片**，在**同一事务**写入新托管记录并返回
其标识——**源记录保持不变**；响应、数据库与审计全程无明文。

技术栈：Python 3.12 · FastAPI · PostgreSQL 16 · `cryptography` · Docker Compose。

> **新功能（v1.6）托管记录谱系逻辑销毁**：租户对任一托管记录携带**幂等键**发起逻辑销毁
> （`POST /destructions`）。服务沿**已完成的迁移关系**（`migration_sessions.new_custody_id`）
> 找出指定记录及其**全部后代**，在**同一事务**、按与迁移/恢复路径一致的全局行锁序
> （custody 行先于会话行）内：① 把谱系上的**在途恢复/迁移会话**置为不可复活的
> `destroyed` 终态，阻断其在途恢复与迁移；② 把全部托管记录置 `destroyed`（保留**无秘密的
> 墓碑**：id、策略坐标、`secret_digest`、长度/epoch）；③ **删除在线库中的加密分片**
> （`shards` 密文行）；④ 写入无明文、可重放的 `destruction.complete` 审计与一份**幂等销毁
> 回执**。事务**提交成功后**再清理这些会话在进程内的待累计分片。销毁与迁移完成、分片领取
> 或份额提交并发时先后由行锁**确定性**地决定：销毁提交后，旧会话不得再下发分片明文或一次性
> 密文（统一 `CUSTODY_DESTROYED`/410），输掉交错的迁移也不可能插入“漏删的后代”——若迁移先
> 提交，销毁的谱系展开会把新生后代一并纳入并删除其分片。同键重试返回**同一份销毁回执**
> （200），同键换根为 `IDEMPOTENCY_CONFLICT`，跨租户请求一律 `FORBIDDEN`。销毁**仅覆盖服务
> 在线数据**（回执 `scope=online_service_data_only`），**不宣称擦除数据库/存储的外部备份**。
> 并发交错的回归验证见 `scripts/race_destruction.py`（D1–D9）。

> **修复要点（v1.6.1）**：修复**并发复用同一幂等键发起销毁**时的未处理数据库错误。
> 同一租户以相同 `Idempotency-Key` 对**互不相关**的两个根托管记录并发调用
> `POST /destructions` 时，两个请求的根行锁互不重叠，可能**双双通过回执预查**
> （都查不到既有回执）；后插入者随后撞上 `uq_destruction_idem` 唯一索引——旧代码让
> `UniqueViolationError` 直接冒出：调用方得到未处理的 500，也不留约定的拒绝审计。
> 现改为：只把 **`uq_destruction_idem` 这一条唯一约束**的冲突翻译为确定性结果（其它
> 约束或数据库错误原样上抛，**绝不误判为幂等冲突**）——后插入者的事务（谱系墓碑、
> 分片删除、会话阻断、`destruction.complete` 完成审计）**整体回滚**，随后重新读取
> 胜方已提交的回执：同键同根按重放返回**同一回执**（200）；同键不同根返回
> **409 `IDEMPOTENCY_CONFLICT`**，并在独立事务留下与实际结果一致的
> `destruction.start` denied 审计。败方谱系记录保持 `active`、在线分片一片不删、
> 在途会话仍 `open`、进程内待累计分片不清空；**换新幂等键即可安全重试**。
> 回归验证见 `scripts/race_destruction.py` 的 D9（预查交错双双通过 → 恰一次 201、
> 另一次稳定 409）、D9b（同键同根并发重试得同一回执）、D9c（双闸门同时放行，
> 结果集合恒为 {201, 409}）、D9d（通用故障仍是 500，不误判为幂等冲突）。

> **修复要点（v1.7.2）**：修复 `POST /migrations` 终态重试**沿用旧策略与旧摘要**的问题。
> 同租户两条有效源以同一 `Idempotency-Key` 并发创建时，败方 INSERT 撞
> `uq_migration_idem_open`，savepoint 回滚后进入“等待—重读”；这期间胜方会话可能由
> `open` 转 **`failed`**（源门限提交后缺片），其**目标策略版本也可能恰被撤销或 epoch
> 到期**。旧实现在重建时复用了**事务开始时**的非锁校验结果、旧 `now()` 与旧目标摘要，
> 可能为已失效目标再插一个 `open` 会话。现改为：
> ① **每次尝试都在同一个 savepoint 内**重新核对——对源 custody 行与源/目标不可变策略版本
> 行按规范顺序取 `FOR UPDATE`（custody 先于 policy 的全局锁序；轮换/撤销也先锁 custody
> 再改 policy），savepoint 因唯一冲突回滚时这些策略行锁一并释放，等待期间败方只持源
> custody 锁，与目标撤销的真实事务不死锁、先后确定；② epoch 有效期一律用核对时刻新取的
> **`clock_timestamp()`** 判定，等待中到期绝不以事务开始时的旧时间放行；③ 目标失效确定性
> 返回 **409 `MIGRATION_TARGET_INVALID`**（源失效为 `MIGRATION_SOURCE_INVALID`），随
> savepoint 回滚——**不留下会话、不留成功审计**，由独立事务单独记一条
> `migration.start` denied 审计；源/目标都仍有效才用新的 `valid_until` 新建 open 会话；
> ④ 重建 INSERT 前再按与幂等重放一致的存活判定裁决——等待期间出现的**新赢家**：同请求
> **200 重放**、异请求 **409 `IDEMPOTENCY_CONFLICT`**、赢家已 **completed 仍可重放**
> （completed 不占 open 索引，必须显式判出，不能靠 INSERT 碰运气）；非目标约束 23505 与
> 其它数据库错误**原样上抛、绝不误判**。回归验证见 `scripts/race_migration_start.py`
> 新增 S9–S14（可控交错：`migration.before_rebuild_revalidate` /
> `migration.before_rebuild_insert` 两个仅测试构建启用的闸门）。
>
> **修复要点（v1.7.1）**：修复 `POST /migrations` 并发创建兜底里的**已完成赢家漏判**。
> 同一租户用同一 `Idempotency-Key` 对两条不同且有效的源记录并发创建时，败方 INSERT 撞
> `uq_migration_idem_open`、savepoint 回滚后需要**重读已提交的胜方会话**来裁决；但胜方会话
> 可能在其提交与败方重读之间已由 `open` 转 **`completed`**（源门限达成、同事务置完成）。
> 旧查询只读 `status='open'`，把这份已提交的完成态赢家当成“不存在”而**原样上抛数据库
> 异常**：调用方得到未处理的 **500**，也**漏记拒绝审计**。现改为：保存点回滚后按**实际约束
> 名**重读已提交会话，并使用与主流程幂等重放**完全一致的存活判定**（`open` 与 `completed`
> 都是有效赢家；`expired`/`failed`/`destroyed` 终态行**不充当赢家**），再按**源记录 + 目标
> 策略版本**裁决——同请求 **200 重放**原会话（含完成态与同一新 custody），异请求 **409
> `IDEMPOTENCY_CONFLICT`** 并由独立事务**单独补一条 `migration.start` denied 审计**；败方
> 的会话插入与成功审计随 savepoint 回滚，**不留下会话或成功审计**。若撞索引的行已转入终态
> （键位已释放），则按**终态后重建规则**重新校验创建（有界重试 INSERT，与“终态后到达的
> 请求可安全重建”语义一致）；同源异键仍报 `MIGRATION_CONFLICT`，非目标约束的 23505 与其它
> 数据库错误**原样上抛、绝不误判**。回归验证见 `scripts/race_migration_start.py` 新增的
> S7（败方在重读前被钉住、胜方由真实提交驱动 `open→completed`：败方稳定 409 且只留拒绝
> 审计）与 S8（胜方在重读前转入 `failed` 终态：终态行不占位，败方按重建规则 201 建成）。
>
> **修复要点（v1.7）**：修复 `POST /migrations` **并发创建迁移会话的幂等错误**。
> 同一租户用同一个 `Idempotency-Key` **同时**为**两条不同且有效**的源托管记录发起迁移时，
> 两侧源 custody 行锁互不重叠，可能**双双通过预查**（幂等键、源/目标有效性、同源在途拦截
> 均未命中）；后插入者随即撞上 `uq_migration_idem_open`。旧代码只用
> `getattr(exc, "pgcode", None) != "23505"` 判别——而 asyncpg 的异常对象**并不带
> `pgcode` 属性**（SQLSTATE 在 `sqlstate` 上，且更可靠的判别是实际约束名），导致任何
> 唯一违规都被原样上抛：调用方得到未处理的 **500**，也**漏记拒绝审计**。现改为在
> savepoint 捕获 `asyncpg.UniqueViolationError`，按**实际命中的约束名**分派：
> `uq_migration_idem_open` 且胜方已提交、请求体不同 → **409 `IDEMPOTENCY_CONFLICT`**
> （basis 带胜方 `migration_id`），请求体相同 → **200 重放胜方会话**；
> `uq_migration_source_open` / `uq_migration_source_completed` → **409
> `MIGRATION_CONFLICT`**；**非目标约束的 23505 与其它数据库错误原样上抛为 500，绝不误判**。
> 败方的会话插入与成功审计随 savepoint 回滚（**不留下迁移会话**），409 由独立事务**单独
> 补一条 `migration.start` denied 审计**；胜方会话提交后可 `GET /migrations/{id}` 查询。
> 回归验证见 `scripts/race_migration_start.py` 的 S1/S2（预查后交错：恰一次 201、败方稳定
> 409 且只留拒绝审计）、S3（同键同源并发得 200 同一份）、S4（异键同源得
> `MIGRATION_CONFLICT`）、S5/S6（非目标约束 23505 与通用故障仍为 500，可干净重试）。

> **修复要点（v1.5）**：修复**跨策略迁移在待累计分片丢失后卡死**的问题。旧代码里，首名托管人
> 已提交分片（数据库计数=1）后若 API 进程重启或内存池淘汰该分片，另一名托管人的提交会让
> 数据库计数达到源门限、内存分片却不足——`/migrations/shares` 返回 `THRESHOLD_NOT_MET`
> 并**仅回滚本次提交**：旧提交与 `UNIQUE(migration_id, custodian_id)` 约束仍在，原托管人
> 永远无法补交，会话保持 `open` 却又永远凑不齐门限；同时 `uq_migration_source_open` /
> `uq_migration_idem_open` 两条部分唯一索引被这个“僵尸 open 会话”占位，新幂等键在会话
> TTL 过期前无法重建迁移。现改为：检出缺片的那次提交在**会话行锁仍持有**时，于**同一事务**
> 内协调三件事——① 凭本次 token 撤回内存分片并撤销本次库写入（提交记录删除、nonce 恢复
> 未花费）；② 把会话置为可查询的 **`failed` 终态**（`GET /migrations/{id}` 可见，保留已
> 提交历史），两条 open 占位索引立即释放；③ 追加无明文 `migration.fail` 审计——然后整体
> 提交。在锁队列中等待的旧会话请求拿锁即得确定性的 `MIGRATION_FAILED`，**绝不可能再把
> 旧会话迁移完成**；租户随后可用**新幂等键（或同一键）**从源记录重新发起，失败会话
> `new_custody_id` 为空、`uq_migration_source_completed` 兜底不变，**绝不可能产生重复的
> 新托管记录**。重启/清空内存池的回归验证见 `scripts/race_migration.py`（37 项，
> `M1`–`M6`：重启终态、新键重发、同键重试、行锁等待者不得完成、内存池淘汰等价场景、
> 瞬时故障不误判 failed）。

> **新功能（v1.4）跨策略密钥迁移**：在不改写、不删除源托管记录的前提下，把一份托管秘密迁移到
> **另一条有效策略版本**（可同时更换托管人集合与门限）。租户 `POST /migrations`（必须带
> `Idempotency-Key` 头）创建会话，响应固化 `source_digest/target_digest`（不可变策略版本行的
> 规范化 SHA256）。旧策略托管人走与恢复同构的 **nonce → claim → sign → submit** 流程，但签名报文
> 换成迁移专用的 `keyvault.migration.v1`，逐行绑定
> 迁移会话/源版本摘要/目标版本摘要/nonce/托管人/点位/分片摘要。达到源门限的那一次提交：
> ① 秘密**只由已验签提交分片**在请求内存中插值重组（服务端不碰库存分片），校验 `secret_digest`；
> ② **立即**按目标策略 `shamir_split` 并逐片 AES-GCM 加密；③ 新 `key_custodies` + 新 `shards`、
> 会话置 `completed`、审计 `migration.complete` **同一事务**提交，源 custody/shards 一行不改。
> 幂等与并发：幂等键只存 `sha256`；同键同请求重放返回同一会话（200，完成态含同一新 custody），
> 同键不同请求 `IDEMPOTENCY_CONFLICT`；不同键迁移同一 custody 一律 `MIGRATION_CONFLICT`
> （`open_migration_exists_for_custody` / `custody_already_migrated`），由源 custody 行锁 +
> 部分唯一索引兜底，**不同幂等键绝不可能把同一记录迁移两次**。源/目标被撤销或过期、跨租户、
> 目标=源均被拒；会话 TTL 或源侧失效后旧 open 会话惰性置 `expired`，调用方可安全重试。
> 确定性拒绝（验签/点位/摘要/nonce/成员）不花费 nonce；入池后的失败沿用 v1.3 的双重撤销边界
> （行锁释放前先凭 token 撤回内存分片再回滚）。端到端与存储层断言见 `scripts/demo.py`
> （108 项，迁移用例覆盖正常流程、每类拒绝依据、并发重复、TTL 安全重试与存储层无明文）。

> **修复要点（v1.3）**：修复 `/recoveries/shares` 在“分片**已入内存池之后**异常回滚”时的交错竞态
> （重组失败、审计写入失败、连接中止等）。旧代码在异常路径上**先 `ROLLBACK` 释放会话行锁、
> 再移除本次内存分片**：① 同会话正在锁队列里等待的请求可能在这一瞬间读到未提交分片；
> ② 同一托管人重试先成功入池时，旧请求随后的无条件 `remove(custodian)` 会**误删掉新分片**——
> 数据库计数保留、内存缺片，后续门限满足时报 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现划定双重撤销边界：
> 1. **顺序**：异常路径在事务仍打开（行锁仍持有）时先撤回本次内存分片，再 `ROLLBACK`——
>    等待者拿锁时内存池与数据库已重新一致，绝不可能读到未提交分片；
> 2. **凭证**：`pending.add()` 返回仅属于本次插入的 token，回滚只能 `discard(本 token)`，
>    即使撤销顺序被任何改动意外打破，旧请求也无法删除同托管人成功重试产生的新分片。
>
> 由此保证：并发重试后重组**只使用已提交且验签通过的分片**（服务端绝不拿库存分片凑数），
> 门限达成只发生一次，**一次性密文只下发一次**；确定性校验拒绝（验签/点位/摘要/nonce 等）
> 全发生在入池之前，异常路径根本不触碰内存池。可精确钉住该交错的回归验证见
> `scripts/race_recovery.py`（38 项断言，`regression/R1·R2·R4·R5/U1`），
> 与原有 `scripts/demo.py` 一起由 demo 容器一键执行。
>
> **修复要点（v1.2）**：修复 `/recoveries/shares` 的跨请求状态损坏。旧实现的拒绝路径无条件
> 从内存分片池移除“本托管人”的分片：未达门限的会话已接受某托管人的有效分片后，该托管人重放
> 已花费 nonce（返回 `NONCE_ALREADY_USED`）会把**先前已验签的内存分片**一并删掉，而数据库提交
> 计数保留——随后其他托管人补足门限时内存分片不足，得到 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现明确提交事务与进程内分片池的撤销边界：**校验拒绝发生在分片入池之前，绝不触碰已提交分片；
> 事务回滚只撤回本次请求新增的分片**。并发重放与合法提交交错时，数据库计数与内存内容始终对应，
> 门限满足时仅用已验签分片重组、密文只下发一次。同批修正若干拒绝路径上 `ApiError` 的位置参数
> 调用（会把确定性 4xx 拒绝变成 500）。回归验证见 `scripts/demo.py` 中 `regression:` 前缀用例。
>
> **修复要点（v1.1）**：旧实现里托管人取得 nonce 后只交签名、不交分片也会计入份额，凑满门限即由
> 服务端解密库存分片重组——托管人无需真正持有自己的分片即可“代表”本人。现改为**凭本人已领取分片
> 的点位与字节提交**，签名绑定该分片摘要；归属/点位/库存摘要校验全部通过后才花费 nonce 计数，
> 待累计分片只在内存中保存、绝不明文落盘。

---

## 1. 一键启动

```bash
docker compose up --build
```

- API：<http://localhost:8000>
- Swagger 交互文档：<http://localhost:8000/docs>
- OpenAPI JSON：<http://localhost:8000/openapi.json>
- 健康检查：<http://localhost:8000/health>
- PostgreSQL：`localhost:5432`（用户/库/密码均为 `keyvault`）

首次启动会自动建表并写入一组**演示身份**（1 个租户 + 3 个托管人，仅用于本地联调，密钥是确定性的，
**严禁用于生产**）。演示凭据可随时打印：

```bash
docker compose exec api python -m app.seed
```

生产部署通过环境变量覆盖（见 `.env.example`）：

| 变量 | 说明 |
| --- | --- |
| `KEYVAULT_DATABASE_URL` | PostgreSQL DSN |
| `KEYVAULT_SHARD_MASTER_KEY` | ≥32 字节字符串或 64 位 hex，用于 HKDF 派生分片加密密钥 |
| `KEYVAULT_ADMIN_API_KEY` | 管理端注册身份用的 API Key |
| `KEYVAULT_RECOVERY_DEFAULT_TTL` / `KEYVAULT_RECOVERY_MAX_TTL` | 恢复会话默认/上限 TTL（秒） |
| `KEYVAULT_FAULT_INJECTION` | 仅测试：`1` 开启并发交错故障注入闸门；默认 `0`（关闭时零开销，切勿在生产开启） |

---

## 2. 快速体验（端到端）

容器自带完整验收脚本，覆盖正常恢复、每一种拒绝依据、并发竞态、跨策略迁移、
迁移创建并发幂等、迁移缺片故障转移、**托管记录谱系逻辑销毁**与审计链重放：

```bash
# 1) 并发回滚竞态回归（scripts.race_recovery，38 项）
# 2) 迁移缺片故障转移回归（scripts.race_migration，37 项）
# 3) 迁移创建并发幂等回归（scripts.race_migration_start，S1–S14）
# 4) 谱系逻辑销毁回归（scripts.race_destruction，D1–D9）
# 5) 端到端验收（scripts.demo，含销毁全流程）
docker compose --profile demo run --rm demo
```

期望依次输出 `RACE REGRESSION CHECKS PASSED`、`MIGRATION FAILOVER CHECKS PASSED`、
`MIGRATION START IDEMPOTENCY CHECKS PASSED`、`DESTRUCTION CHECKS PASSED` 与 `ALL CHECKS PASSED`。

`scripts.race_recovery.py` 在进程内以真实 ASGI + 真实 PostgreSQL 行锁运行，通过仅测试构建启用的
故障注入闸门（`KEYVAULT_FAULT_INJECTION=1`，API 服务默认关闭、关闭时零开销）精确钉住交错点：
一个请求的已验签分片已入内存池、行锁仍持有时注入重组/审计/连接类失败，另一个请求正排队等待行锁；
断言**未提交分片在行锁释放前撤回**、等待者读不到它、同托管人重试的新分片不会被旧回滚误删，
且门限只按已提交且验签的分片达成一次、密文只下发一次。

`scripts.race_migration.py` 以同样方式模拟 **API 进程重启 / 内存池淘汰**（直接置换或清空进程内
`PendingShareStore`，数据库提交计数保留）：断言检出缺片的提交把迁移会话同事务置为可查询的
`failed` 终态、本次分片完整撤销（计数/nonce/内存）、行锁等待者只得 `MIGRATION_FAILED`、
新幂等键与同一键都能从源记录安全重新发起且只产生一个新托管记录、`migration.fail` 无明文入审计链。
`scripts.race_migration_start.py` 以 `migration.after_idem_check` 闸门钉住**同一租户用同一
幂等键同时为两条不同且有效的源托管记录发起迁移**的预查后交错（S1/S2）：两侧源 custody 行锁互不
重叠、双双通过幂等/同源预查，后插入者撞 `uq_migration_idem_open`——断言恰一次 201、败方稳定
409 `IDEMPOTENCY_CONFLICT`（响应 basis 带胜方 `migration_id`），败方**不留下迁移会话也不留成功
审计**、单独补一条 `migration.start`/`denied` 审计，胜方会话可 GET 查询；同键同源的并发创建在源
行锁上排队后按幂等重放返回 **200 同一份会话**（S3）；不同键同源排队者得 409
`MIGRATION_CONFLICT`（S4）；预查后注入的**非目标约束 23505**（S5）与通用故障（S6）一律 500，
绝不误判为幂等冲突，回滚后同键可干净重试。新增的 `migration.after_insert_conflict` 闸门把败方
钉在**保存点回滚后、重读已提交胜方之前**（S7/S8）：S7 期间胜方被真实托管人提交驱动
`open→completed`，败方重读仍按源记录+目标策略版本判出已提交赢家——稳定 409 且只留拒绝审计，
绝不冒出 500；S8 期间胜方转入 `failed` 终态，终态行不充当赢家，败方按终态后重建规则 201 建成
自己的会话。S9–S14 进一步钉住**终态后重建沿用旧策略/旧时间**的交错（v1.7.2 修复）：
`migration.before_rebuild_revalidate` 闸门把败方钉在 savepoint 已回滚、重新核对源/目标之前
（此时只持源 custody 锁、不持 policy 行锁），`migration.before_rebuild_insert` 闸门把败方钉在
重新核对通过、INSERT 之前——S9 等待期间真实撤销败方**目标**策略版本 → 重建确定性
`MIGRATION_TARGET_INVALID`、不留会话/成功审计、只留一条独立拒绝审计，另配有效目标后可干净发起；
S10 等待期间目标 **epoch 到期**（以核对时刻新取的 `clock_timestamp()` 判定，绝不以事务开始的旧
`now()` 放行）→ 同样拒绝；S11/S11b 覆盖等待期间**源**被撤销/源 epoch 到期 →
`MIGRATION_SOURCE_INVALID`；S12/S13 在重建 INSERT 前让**新赢家**用同键提交，甚至驱动到
`completed`——重建 INSERT 前按存活判定（open/completed 均为有效赢家）裁决，异请求稳定 409、
同请求 200 重放（含已完成态与同一新 custody），绝不为 completed 赢家再建同键 open 会话；
S14 在重建 INSERT 点注入通用故障与非目标 23505，一律原样 500、不误判，回滚后同键干净重试。
`scripts.race_destruction.py` 钉住**逻辑销毁 × 迁移完成/分片领取/份额提交**的行锁交错
（销毁在持谱系 custody 锁、会话锁前 park，使在途请求排队）：断言先后确定、输掉交错的旧会话
只得到 `CUSTODY_DESTROYED`（不再下发分片/密文、不产生漏删后代）、迁移先赢时新后代必被纳入
销毁、同键返回同一回执、跨租户拒绝、待累计分片在提交后清空；并以 `destruction.after_receipt_check`
闸门钉住**并发复用同一幂等键的回执预查交错**（D9）：两个请求双双通过预查后，恰一次 201、
另一次稳定 409 `IDEMPOTENCY_CONFLICT`，败方谱系销毁/分片删除/会话阻断/完成审计整体回滚、
拒绝审计与实际结果一致，通用故障仍表现为 500 而**不误判**为幂等冲突。
本地单独运行：

```bash
KEYVAULT_FAULT_INJECTION=1 \
KEYVAULT_DATABASE_URL=postgresql://keyvault:keyvault@localhost:5432/keyvault \
python -m scripts.race_recovery            # 并发回滚竞态
python -m scripts.race_migration           # 迁移缺片故障转移
python -m scripts.race_migration_start     # 迁移创建并发幂等（同键/同源/非目标约束）
python -m scripts.race_destruction         # 谱系逻辑销毁并发交错
```

以下用 curl 走一遍核心流程（演示凭据见 `python -m app.seed` 输出）：

```bash
TENANT=tsec_01ea27eafbe8e5c6c1fb1c6a4f9c18b5ae9a3a4b6d7e8f9a0b1c2d3e4f506172   # 以实际输出为准
ADMIN=admin-dev-key

# 2.1 管理员创建托管人（已由 seed 预置 alice/bob/carol，也可新建）
curl -s -X POST localhost:8000/admin/custodians -H "X-API-Key: $ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"dave"}'
# -> custodian_id / api_key / signing_private_key(仅返回一次) / signing_public_key

# 2.2 创建不可变策略 2-of-3，带 epoch 有效期与轮换间隔
curl -s -X POST localhost:8000/policies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id": "pol_main",
  "threshold": 2,
  "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
  "epoch": {"valid_from":"2026-01-01T00:00:00Z","valid_until":"2030-01-01T00:00:00Z","rotation_interval":0}
}'

# 2.3 托管密钥（hex），服务立即 Shamir 分片 + AES-GCM 加密落盘
curl -s -X POST localhost:8000/custodies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id":"pol_main","expected_version":1,"secret_hex":"7468652d736563726574"}'
# -> custody_id、secret_digest、各分片 shard_digest（响应不含任何明文）

# 2.4 租户凭申请摘要 + 恢复方 X25519 公钥发起恢复会话（绑定策略版本，带过期时间）
curl -s -X POST localhost:8000/recoveries -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "custody_id":"cus_secret_...",
  "request_digest":"<sha256(ticket|purpose)>",
  "recovery_public_key":"<32B X25519 公钥 hex>",
  "ttl_seconds": 300
}'

# 2.5 托管人领取一次性 nonce（返回 nonce、本人分片点位与分片摘要；此时还没有签名报文）
curl -s -X POST localhost:8000/recoveries/nonces \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_..."}'
# -> nonce + point_x + shard_digest（绑定 custodian/policy/version/session）

# 2.6 托管人凭该 nonce 领取“本人分片”（明文仅在本次响应出现，服务端不落盘、不入审计）
curl -s -X POST localhost:8000/recoveries/shards/claim \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"..."}'
# -> point_x / shard_hex / shard_digest / signing_message
#    signing_message 绑定 nonce+会话+策略版本+托管人+点位+分片摘要

# 2.7 托管人用 Ed25519 私钥对 signing_message 签名，连同点位与分片字节提交；
#     归属/点位/库存摘要/验签全部通过才花费 nonce；达到门限的那一次返回一次性密文
curl -s -X POST localhost:8000/recoveries/shares \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"...","point_x":1,
       "shard_hex":"<领取到的本人分片 hex>","signature":"<64B ed25519 hex>"}'
# -> completed=true 时附带 wrap：X25519 临时 ECDH + HKDF-SHA256 + AES-256-GCM
```

客户端解包（Python 示例见 `scripts/demo.py` 的 `unwrap()`）：用本地 X25519 私钥与
`wrap.ephemeral_public_key` 做 ECDH，HKDF 的 info 为 `b"KWR1" + aad`，AAD 即响应中的 `aad`
（内含 session/policy/version/epoch/request_digest，防密文被挪用）。

### 2.8 托管人领取与提交分片（分步说明）

恢复不是“签个名就行”，托管人必须真正交出自己的分片，步骤固定为 **nonce → claim → sign → submit**：

1. **领 nonce**：`POST /recoveries/nonces`，仅会话成员、且会话处于 open 且未过期时可领。
   响应含 `nonce`、该托管人在此托管下的 `point_x` 与 `shard_digest`（每会话每人至多一张，明文仅此次下发）。
2. **领本人分片**：`POST /recoveries/shards/claim`，携带 `session_id + nonce`。
   服务端校验身份、会话状态、nonce 归属与未花费后，解密**该托管人名下**的库存分片，自检摘要自洽，
   返回 `shard_hex`（明文仅存在于这一次 HTTPS 响应）与待签名的 `signing_message`。
   - nonce 未花费前可重复领取（幂等，返回同一片）；nonce 一旦花费，领取返回 `NONCE_ALREADY_USED`。
   - 不属于该策略版本 / nonce 不属于本人或会话 / 会话已完成或过期，一律拒绝，拿不到分片。
3. **本地签名**：对 `signing_message`（`keyvault.share.v2`，逐行绑定
   custodian/policy/version/session/nonce/**point**/**shard_digest**）做 Ed25519 签名。
4. **提交分片**：`POST /recoveries/shares`，携带 `nonce + point_x + shard_hex + signature`。
   服务端依次校验：会话/epoch 状态 → nonce 归属与未花费 → 未重复提交 → **分片归属**（该托管人名下确有其片）
   → **点位一致** → **`sha256(shard_hex)` 与库存 `shard_digest` 一致** → Ed25519 验签；
   **全部通过才花费 nonce 并计数**。点位不符返回 `SHARE_POINT_MISMATCH`，字节被改返回
   `SHARE_DIGEST_MISMATCH`，验签失败返回 `BAD_SIGNATURE`——三者都**不花费 nonce**，basis 给出确定性事实。
5. **门限重组**：有效提交数达到门限时，服务端只用**这些已验签的提交分片**在内存中插值重组，
   校验 `secret_digest` 后包装成一次性密文；同事务把会话置 `completed`，并立即销毁内存中的待累计分片。
   重复提交、会话撤销/过期、并发双发都只会得到拒绝，密文**全局只下发一次**。

**异常与重试语义**（客户端可据此安全重试）：

- 验签/点位/摘要/nonce/重复/会话状态等**确定性拒绝**全部发生在花费 nonce 与分片入池**之前**：
  nonce 未花费、计数不变、内存池不被触碰，客户端修正后用同一 nonce 重试即可。
- 分片入池**之后**才可能失败的环节（门限重组、审计写入、连接中止）一律在**会话行锁仍持有时**
  先凭本次插入凭证撤回内存分片，再回滚事务释放锁：等待锁的并发请求拿锁时内存与数据库计数必然一致，
  读不到任何未提交分片；同托管人的重试即使先成功，旧请求的回滚也只能撤回自己的插入，**绝不会误删
  新分片**。因此任何 4xx/500 之后，调用方查询 `GET /recoveries/{id}` 看到的 `shares_received`
  就是内存中可用于重组的已验签分片数——重试只会得到干净结果，不会出现 `THRESHOLD_NOT_MET` 卡死。
- nonce 已花费后该 nonce 不可再用；需要继续补片时沿用已领取的其他 nonce，或另开恢复会话。
- 进程重启丢失内存待累计分片时，达到门限的提交返回确定性的 `THRESHOLD_NOT_MET`
  （basis.reason=`pending_shares_unavailable`），此时另开恢复会话重来。

> 待累计分片**只存进程内存**（`app/pending.py`），不写库、不写日志、不进审计；进程重启后内存清空，
> 已计数的恢复会话无法继续重组，需另开恢复会话（提交接口此时返回 `THRESHOLD_NOT_MET`，basis.reason 为
> `pending_shares_unavailable`）。这是本演示基线在“明文不落盘”与“多副本部署”之间的明确取舍。
> 迁移会话的待累计源分片复用同一内存池（以 migration_id 为键）；不同的是迁移有唯一约束占位，
> 不能让会话卡死——检出缺片的提交会在同一事务里把会话置为可查询的 `failed` 终态并释放占位，
> 调用方随即可用新（或同一）幂等键重新发起（见 2.9 与 v1.5 修复要点）。

### 2.9 跨策略密钥迁移（curl 流程）

目标：把一份仍有效托管（源策略 `pol_main:v1`，2-of-3）迁移到**另一条有效策略版本**
（`pol_next:v1`，可换托管人集合/门限）。源记录全程保持 `active` 不变。

```bash
TENANT=tsec_...   # python -m app.seed 输出

# (1) 租户创建迁移会话：必须带 Idempotency-Key；绑定源 custody 与目标策略版本
curl -s -X POST localhost:8000/migrations -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: migrate-2026-09-26-0001' -d '{
    "source_custody_id":"cus_secret_30bf8fa9491b0fa26a9c66a2",
    "target_policy_id":"pol_next",
    "target_version":1,
    "ttl_seconds":300
  }'
```

首次创建返回 **201**（下例来自真实运行；`migration_id`/各 id/时间戳随环境变化）：

```json
{
  "migration_id": "mig_2933ebd24b57824c53eca9b7",
  "source_custody_id": "cus_secret_30bf8fa9491b0fa26a9c66a2",
  "source_policy_id": "pol_next_src",
  "source_version": 1,
  "source_digest": "f932550b58806031a97d22bc41b28aba913d206fbcdfa6c6b67a6f752b1bbebc",
  "target_policy_id": "pol_next",
  "target_version": 1,
  "target_digest": "46c8ef322c25f0242d528f220273e82b5962abbe67071ed54f3c4eba51d83a43",
  "status": "open",
  "valid_until": "2026-10-02T11:34:13.593542Z",
  "shares_received": 0,
  "threshold": 2,
  "new_custody_id": null,
  "new_shard_count": null,
  "new_shard_digests": null
}
```

同键同体重放（含并发的在途重试）返回 **200 + 同一会话**（不新建、不重复留痕）：

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8000/migrations \
  -H "X-API-Key: $TENANT" -H 'Idempotency-Key: migrate-2026-09-26-0001' \
  -H 'Content-Type: application/json' -d '{
    "source_custody_id":"cus_secret_30bf8fa9491b0fa26a9c66a2",
    "target_policy_id":"pol_next","target_version":1,"ttl_seconds":300}'
# -> 200（响应体 migration_id 与 201 那一份完全一致）
```

同键绑定到**另一条源记录**（串行预查命中，或两侧源行锁互不重叠时由
`uq_migration_idem_open` 兜底）返回 **409 `IDEMPOTENCY_CONFLICT`**：

```json
{
  "error": {
    "code": "IDEMPOTENCY_CONFLICT",
    "message": "idempotency key is already bound to a different request",
    "basis": {
      "reason": "concurrent_open_with_same_idempotency_key",
      "idempotency_key_digest": "d2e9dd221ece913ad8eced5511edc37f7514aa7bc532b4434ad98e61519249c8",
      "migration_id": "mig_2933ebd24b57824c53eca9b7",
      "winner_source_custody_id": "cus_secret_30bf8fa9491b0fa26a9c66a2"
    }
  }
}
```

> 串行预查命中时 `reason` 为 `key_bound_to_different_request`；并发后插入者的 basis 为
> `concurrent_open_with_same_idempotency_key` 并带胜方 `migration_id`。败方会话插入随
> savepoint 回滚——**不留下迁移会话、不留成功审计**，拒绝由独立事务单独记一条
> `migration.start` / `denied` / `IDEMPOTENCY_CONFLICT` 审计；换新幂等键即可从该源记录重试。

不同键对同一源 custody 发起（在途）返回 **409 `MIGRATION_CONFLICT`**：

```json
{
  "error": {
    "code": "MIGRATION_CONFLICT",
    "message": "a different open migration already exists for this custody, or the same custody is already migrated",
    "basis": {
      "reason": "open_migration_exists_for_custody",
      "migration_id": "mig_2933ebd24b57824c53eca9b7",
      "source_custody_id": "cus_secret_30bf8fa9491b0fa26a9c66a2"
    }
  }
}
```

```bash
# (2) 源策略托管人领取一次性挑战值（与恢复同构）
curl -s -X POST localhost:8000/migrations/nonces -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{"migration_id":"mig_2933ebd24b57824c53eca9b7"}'
# -> nonce + point_x + shard_digest + source/target_digest

# (3) 托管人领取本人“源分片”（明文仅在本次响应出现，不落盘/不入审计）
curl -s -X POST localhost:8000/migrations/shards/claim -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{"migration_id":"mig_2933ebd24b57824c53eca9b7","nonce":"..."}'
# -> shard_hex + signing_message（keyvault.migration.v1：逐行绑定
#    migration/source_digest/target_digest/nonce/custodian/point/shard_digest）

# (4) 托管人本地 Ed25519 签名后，提交本人源分片 + 签名
curl -s -X POST localhost:8000/migrations/shares -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{
    "migration_id":"mig_2933ebd24b57824c53eca9b7","nonce":"...","point_x":1,
    "shard_hex":"<领取到的本人源分片 hex>","signature":"<64B ed25519 hex>"}'

# (5) 达到源门限的那一次（如 2-of-3 的第 2 份）真实响应：
```

```json
{
  "migration_id": "mig_2933ebd24b57824c53eca9b7",
  "status": "completed",
  "shares_received": 2,
  "threshold": 2,
  "completed": true,
  "new_custody_id": "cus_secret_92f675f9bb33ad116648e5fc",
  "new_shard_count": 3,
  "new_shard_digests": [
    "a647cb33cca79fb88a11878d47ad14bfabe34f76210ca571dcc8821c17a530c3",
    "b0fca4208d87cdf3186c7263704d49d65187afb4cb17e1e3164298581c8259d0",
    "12ae68c015aee369f32f12be55b9a2a3ff0662a1c464a54d0db2376645b83ec8"
  ]
}
```

```bash
#    服务端仅用已验签源分片在内存重组 -> 立即按目标策略重新分片 ->
#    新托管记录 + 新加密分片在同一事务写入；源 custody/shards 一行未改，
#    响应不含秘密或分片明文。新记录此后即可按目标策略正常 POST /recoveries。

# 查询迁移会话（幂等/排障）
curl -s localhost:8000/migrations/mig_2933ebd24b57824c53eca9b7 -H "X-API-Key: $TENANT"
# -> status(open|completed|expired|failed)、shares_received、threshold、new_custody_id
#    完成后 GET 的真实响应与上例结构一致：status="completed"、shares_received=2、
#    new_custody_id="cus_secret_92f675f9bb33ad116648e5fc"、new_shard_count=3
```

**迁移的拒绝与重试语义**：

- 必须携带 `Idempotency-Key`（缺失/超长 → `BAD_REQUEST`）；幂等键与 nonce 都只存 SHA256 摘要。
- 同键不同请求体（换源 custody 或换目标版本）→ `IDEMPOTENCY_CONFLICT`；
  不同幂等键迁移同一 custody → `MIGRATION_CONFLICT`
 （`open_migration_exists_for_custody` / `custody_already_migrated`）——
  完成迁移的 custody 再用任何键发起都会被拒，**不同键不可能迁移两次**。
- 源 custody 非 active 或源版本已撤销/过期 → `MIGRATION_SOURCE_INVALID`；
  目标版本不存在、已撤销、已过期、属于别的租户、或与源完全相同 →
  `MIGRATION_TARGET_INVALID` / `FORBIDDEN`。
- 托管人侧拒绝码与恢复一致：非源策略成员 `CROSS_POLICY_SHARE`、验签失败 `BAD_SIGNATURE`、
  点位/摘要不符 `SHARE_POINT_MISMATCH`/`SHARE_DIGEST_MISMATCH`（均不花费 nonce）、
  nonce 重放 `NONCE_ALREADY_USED`、重复提交 `DUPLICATE_SHARE`、
  会话完成 `MIGRATION_COMPLETED`、会话 TTL 失效或源侧在途被撤销/过期
  `SESSION_EXPIRED` / `EPOCH_REVOKED` / `EPOCH_EXPIRED`。
- 每次 nonce/claim/submit 都重新校验源/目标**版本摘要**与会话绑定一致，
  若不可变版本行与固化摘要不符 → `MIGRATION_DIGEST_MISMATCH`（完整性兜底）。
- 会话超过 TTL、或源侧在途失效后，旧 open 会话在该 custody 下一次请求时被惰性置 `expired`，
  随后可用同一幂等键（也可用新键）安全重试；确定性 4xx 不花费 nonce，可直接用原 nonce 重领重试。
- **缺片终态（failed）**：已计数分片的内存明文丢失（进程重启/内存池淘汰）时，使数据库计数
  达到源门限的那次提交返回 `THRESHOLD_NOT_MET`（basis.reason=`pending_shares_unavailable`，
  并带 `migration_status=failed`）；该提交已在持有会话行锁的同一事务里撤销自身分片、把会话
  置为可查询的 `failed` 终态并写入 `migration.fail` 审计。此后旧会话的一切 nonce/claim/submit
  均得 `MIGRATION_FAILED`（绝不可能再完成），`failed` 不占 open 唯一索引——**失败重试**：
  直接换新幂等键（或沿用同一键）重新 `POST /migrations` 即可从源记录再发起；
  失败会话没有 `new_custody_id`，重试完成前不会产生任何新托管记录，完成后也全局唯一。
- 并发创建由源 custody 行锁串行化 + 部分唯一索引兜底。唯一违规按**实际命中的约束名**分派
  （绝不只凭 SQLSTATE=23505）：
  - 同键**同源**并发：后到者在源行锁上排队，胜方提交后经预查重放，返回 **200 同一份会话**；
  - 同键**异源**并发（行锁互不重叠、双双通过预查）：后插入者撞 `uq_migration_idem_open`，
    保存点回滚后按实际约束**重读已提交胜方**（存活判定与幂等重放一致：`open`/`completed`
    都是有效赢家，`expired`/`failed`/`destroyed` 终态行不充当赢家），再按源记录+目标策略
    版本裁决——同请求 **200 重放**（含胜方已完成的形态），异请求 409 `IDEMPOTENCY_CONFLICT`
    （reason=`concurrent_open_with_same_idempotency_key`，basis 带胜方 `migration_id`）；
    即使胜方在重读前刚由 `open` 转 `completed` 也同样判出，**绝不冒出 500**；败方不留下
    会话/成功审计，单独补拒绝审计，换新键可重试。若撞索引的行已转入终态（键位释放），
    败方按**终态后重建规则**处理（见下一条）；
  - **终态后重建（v1.7.2）**：胜方转入 `expired`/`failed`/`destroyed` 后键位释放，败方**不复用**
    等待前的旧校验结果/旧摘要/旧时间，而是在**同一个 savepoint 内**（① 唯一冲突回滚会把该
    savepoint 内取的源/目标 policy `FOR UPDATE` 行锁一并释放，等待期间败方只持外层源 custody
    锁，与目标撤销的真实事务按 custody→policy 全局锁序决出确定先后、不死锁）重新核对源 custody
    与源/目标不可变策略版本，有效期一律以核对时刻新取的 **`clock_timestamp()`** 判定——等待中
    epoch 到期也绝不放行；**目标失效 → 409 `MIGRATION_TARGET_INVALID`、源失效 → 409
    `MIGRATION_SOURCE_INVALID`**，随 savepoint 回滚（**不留下会话、不留成功审计**），由独立事务
    单独补一条 `migration.start` denied 审计；源/目标都仍有效才用新的 `valid_until` 新建 open
    会话（有界重试）。重建 INSERT 前再按与幂等重放一致的存活判定裁决等待期间出现的**新赢家**
    （`open`/`completed` 均有效，终态行不占位）：同请求 **200 重放**（含已完成态/同一新 custody）、
    异请求 409 `IDEMPOTENCY_CONFLICT`——completed 赢家不占 open 索引，必须显式判出而不是靠 INSERT
    碰运气，绝不重建出同键第二个 open 会话；
  - 不同键同源并发：排队者预查命中在途会话，返回 409 `MIGRATION_CONFLICT`
    （`open_migration_exists_for_custody`；已完成则 `custody_already_migrated`）；
  - 非目标约束的 23505（如主键冲突）或其它数据库错误**原样上抛为 500，绝不误判**为冲突。

### 2.10 托管记录谱系逻辑销毁（curl 流程）

对一份托管记录（无论它是否迁移过、迁移了几代）发起逻辑销毁：服务沿**已完成迁移关系**找出
该记录及全部后代，在同一事务阻断在途、删除在线加密分片。

```bash
TENANT=tsec_...   # python -m app.seed 输出

# (1) 发起销毁：必须带 Idempotency-Key；root_custody_id 为谱系中任意一代记录
curl -s -X POST localhost:8000/destructions -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: destroy-2026-09-29-0001' \
  -d '{"root_custody_id":"cus_secret_..."}'
# -> 201 销毁回执：
# {
#   "destruction_id": "des_...",
#   "status": "completed",
#   "root_custody_id": "cus_secret_...",
#   "idempotency_key_digest": "<sha256(Idempotency-Key)>",
#   "custody_count": 3,            # 覆盖的谱系记录数（根 + 全部后代）
#   "recovery_blocked": 1,         # 被置 destroyed 的在途恢复会话数
#   "migration_blocked": 1,        # 被置 destroyed 的在途迁移会话数
#   "shards_deleted": 9,           # 删除的在线加密分片数（3 代 × 每代 3 片）
#   "custody_ids": ["cus_secret_...", "...", "..."],
#   "scope": "online_service_data_only"   # 仅在线数据；不宣称擦除外部备份
# }

# (2) 同键重试（网络抖动/客户端重放）-> 200 + 同一份回执，不重复销毁、不重复留痕
curl -s -X POST localhost:8000/destructions -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: destroy-2026-09-29-0001' \
  -d '{"root_custody_id":"cus_secret_..."}'

# (3) 查询销毁回执（排障/合规留存）
curl -s localhost:8000/destructions/des_... -H "X-API-Key: $TENANT"

# (4) 同键换根（含并发同键首次使用不同根）-> 409 IDEMPOTENCY_CONFLICT；
#     失败方未产生任何销毁效果（谱系/分片/在途会话原样），更换新幂等键即可安全重试
curl -s -X POST localhost:8000/destructions -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: destroy-2026-09-29-0001' \
  -d '{"root_custody_id":"cus_secret_<另一根>"}'
# -> {"error":{"code":"IDEMPOTENCY_CONFLICT","message":"idempotency key is already bound to a different request", ...}}
curl -s -X POST localhost:8000/destructions -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: destroy-2026-09-29-0002' \
  -d '{"root_custody_id":"cus_secret_<另一根>"}'
# -> 201 新回执（败方回执不占位，新键立即可用）
```

销毁提交后，谱系上旧会话的一切请求确定性返回 `CUSTODY_DESTROYED`（HTTP 410），
`GET /recoveries/{id}` / `GET /migrations/{id}` 可见 `status=destroyed`：

```bash
# 旧恢复会话：nonce/claim/submit 全部 410，不再下发分片明文或一次性密文
curl -s -X POST localhost:8000/recoveries/nonces -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{"session_id":"rec_..."}'
# -> {"error":{"code":"CUSTODY_DESTROYED", ...}}

# 旧迁移会话：nonce/claim/submit 全部 410，不可能完成迁移或生成漏删的后代
# 对已销毁记录再发起恢复/迁移同样 410；不同幂等键重复销毁已毁根 -> 零增量回执
```

**销毁语义与边界**：

- 必须携带 `Idempotency-Key`（缺失/超长 → `BAD_REQUEST`）；幂等键只存 SHA256 摘要。
  同键同体重放返回 200 同回执；同键换根 → `IDEMPOTENCY_CONFLICT`；不同键对已销毁根
  再次销毁返回一份零增量回执（`shards_deleted=0`、谱系仍完整列出），销毁天然幂等收敛。
- **并发同键**：两个请求以同一幂等键同时销毁**互不相关**的根时，根行锁互不重叠，
  可能双双通过回执预查；后插入者撞 `uq_destruction_idem` 唯一索引后**整体回滚**
  （谱系墓碑/分片删除/会话阻断/完成审计全部还原，进程内待累计分片不动），稳定返回
  409 `IDEMPOTENCY_CONFLICT` 并留下与实际结果一致的拒绝审计——绝不冒出未处理的
  数据库错误；其它约束或数据库错误不会被误判为幂等冲突（仍按原错误上抛）。
- **冲突后的重试**：409 `IDEMPOTENCY_CONFLICT` 表示该幂等键已绑定另一个根——
  调用方应**更换新的幂等键**重新 `POST /destructions` 销毁自己的目标根
  （败方回执不占位，新键立即可得 201）；若本来就是同一根的重试，沿用同键重发即可，
  返回 200 与**同一份回执**（并发下同根重试由根行锁串行化后经预查重放）。
- 谱系**只沿已完成迁移关系前进**：`open`/`failed`/`expired` 的迁移没有 `new_custody_id`，
  不会产生后代，故不影响展开；被纳入的在途（open）恢复/迁移会话在同一事务内置 `destroyed`。
- **并发确定性**：迁移完成、分片领取、份额提交与销毁共用同一全局行锁序
  （custody 行按 id、会话行按 id）。迁移提交先持锁则销毁等待其提交，随后把新生后代一并
  纳入销毁（后代分片同样删除，绝不漏删）；销毁先持锁则在途提交/领取排队后只得 410，
  既不下发分片/密文，也不产生新托管记录。事务提交后才清理这些会话的进程内待累计分片。
- 销毁只删除在线库 `shards` 密文与标记托管记录；墓碑（id、策略版本坐标、`secret_digest`、
  长度、epoch、销毁时刻）与全部既有审计行保留，审计哈希链继续可重放、可校验。
- **边界声明**：`scope=online_service_data_only`——仅擦除本服务在线数据库中的加密分片与
  在途会话，不宣称、也无法擦除数据库快照、备份磁带、对象存储版本、网关/客户端缓存等
  **外部副本**；合规上的“彻底擦除”需由底层备份生命周期与介质策略另行保证。

轮换 / 撤销：

```bash
# 原子推进到 v2（乐观锁 expected_version；可同时改托管集合/门限/epoch）
curl -s -X POST localhost:8000/policies/pol_main/rotate -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' \
  -d '{"expected_version":1,"epoch":{"valid_from":"2027-01-01T00:00:00Z",
        "valid_until":"2031-01-01T00:00:00Z","rotation_interval":0}}'

# 撤销当前 epoch（原子；之后新托管/恢复一律 EPOCH_REVOKED）
curl -s -X POST localhost:8000/policies/pol_main/revoke -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -d '{"expected_version":2}'

# 审计哈希链按序重放并自校验
curl -s localhost:8000/audit/replay -H "X-API-Key: $TENANT"
```

---

## 3. API 总览

| 方法 & 路径 | 调用方 | 说明 |
| --- | --- | --- |
| `POST /admin/tenants` | admin | 注册租户，返回 API Key（仅一次） |
| `POST /admin/custodians` | admin | 注册托管人，返回 API Key 与 Ed25519 签名私钥（仅一次） |
| `POST /policies` | 租户 | 创建不可变策略 v1：n-of-m、epoch、轮换间隔 |
| `GET /policies/{id}?version=` | 租户 | 读取头版本或任意历史版本（版本永不修改） |
| `POST /policies/{id}/rotate` | 租户 | 原子推进版本（写入新版本 + 旧版本置 revoked + 头指针前移） |
| `POST /policies/{id}/revoke` | 租户 | 原子撤销当前 epoch |
| `POST /custodies` | 租户 | 提交待托管密钥，返回 custody_id 与各分片摘要 |
| `POST /recoveries` | 租户 | 创建恢复会话（绑定策略版本 + 申请摘要 + TTL） |
| `GET /recoveries/{id}` | 租户 | 查询会话状态与已收份额数 |
| `POST /recoveries/nonces` | 托管人 | 领取一次性 nonce（含本人分片点位与摘要） |
| `POST /recoveries/shards/claim` | 托管人 | 验身份后领取**本人分片**明文 + 待签名报文（绑定 nonce） |
| `POST /recoveries/shares` | 托管人 | 提交**本人分片点位+字节**与 Ed25519 签名；门限满足时返回一次性密文 |
| `POST /migrations` | 租户 | 携带 `Idempotency-Key` 创建跨策略迁移会话（绑定源/目标策略版本摘要） |
| `GET /migrations/{id}` | 租户 | 查询迁移状态、已收源分片数、完成后的新托管记录标识 |
| `POST /migrations/nonces` | 托管人 | 领取迁移一次性挑战值 nonce（仅源策略成员） |
| `POST /migrations/shards/claim` | 托管人 | 验身份后领取**本人源分片**明文 + 迁移待签名报文 |
| `POST /migrations/shares` | 托管人 | 提交本人源分片+签名；源门限满足时同事务按目标策略重新分片并返回新 custody |
| `POST /destructions` | 租户 | 携带 `Idempotency-Key`，沿已完成迁移关系逻辑销毁指定记录及全部后代（阻断在途、删除在线分片、幂等回执） |
| `GET /destructions/{id}` | 租户 | 查询销毁回执（覆盖谱系、阻断计数、删除分片数、销毁边界） |
| `GET /audit/replay` | 租户 | 重放哈希链并验证完整性 |

所有拒绝响应结构统一且确定性：

```json
{"error": {"code": "NONCE_ALREADY_USED",
           "message": "nonce has already been spent",
           "basis": {"nonce_id": "non_...", "...": "机器可判定的事实依据"}}}
```

调用方应依据 `code`（稳定）而非 `message`（可读）做分支。

| code | 含义 |
| --- | --- |
| `VALIDATION_FAILED` / `BAD_REQUEST` | 报文格式/取值非法（basis.fields 给出字段级原因） |
| `UNAUTHORIZED` / `FORBIDDEN` | 缺 Key、Key 无效或资源属于其他租户 |
| `NOT_FOUND` | 资源不存在 |
| `POLICY_PARAMS_INVALID` | 不满足 1 ≤ threshold ≤ 托管人数 |
| `VERSION_CONFLICT` | `expected_version` 与当前头版本不符（乐观锁） |
| `POLICY_INACTIVE` | 头版本已撤销，不能再轮换 |
| `EPOCH_REVOKED` / `EPOCH_EXPIRED` | epoch 已撤销 / 已过 `valid_until` |
| `NONCE_ALREADY_USED` | nonce 重复领取、已花费或持已花费 nonce 再领片（一次性） |
| `BAD_SIGNATURE` | Ed25519 验签失败（验签失败不花费 nonce） |
| `SHARE_POINT_MISMATCH` | 提交分片的点位不是该托管人在该托管下被分配的点位（不花费 nonce） |
| `SHARE_DIGEST_MISMATCH` | `sha256(提交分片)` 与库存 `shard_digest` 不符，分片被改/非本人片（不花费 nonce） |
| `DUPLICATE_SHARE` | 同一托管人对同一会话重复提交 |
| `CROSS_POLICY_SHARE` | 托管人不属于该策略版本，或 nonce/领取/提交绑定的会话、托管人不匹配 |
| `SESSION_COMPLETED` / `SESSION_EXPIRED` | 会话已完成（密文只下发一次）/ 已过 TTL |
| `THRESHOLD_NOT_MET` / `INTEGRITY_CHECK_FAILED` | 有效分片不足（含重启后内存待累计分片丢失 `pending_shares_unavailable`）/ 重组结果摘要不匹配 |
| `IDEMPOTENCY_CONFLICT` | `Idempotency-Key` 已绑定另一个不同的迁移/销毁请求（换源、换目标或换根），或同键并发首次使用只有一次成功 |
| `MIGRATION_TARGET_INVALID` | 目标策略版本不存在、已撤销/已过期、属于其他租户，或与源版本相同 |
| `MIGRATION_SOURCE_INVALID` | 源托管记录非 active（已轮换/撤销）或源策略版本已撤销/过期，不能发起迁移 |
| `MIGRATION_DIGEST_MISMATCH` | 会话绑定的源/目标策略版本摘要与不可变版本行不符（完整性兜底） |
| `MIGRATION_CONFLICT` | 同一 custody 存在其他 open 迁移会话，或该 custody 已迁移完成（不同幂等键不得重复迁移） |
| `MIGRATION_COMPLETED` | 迁移会话已完成（新托管记录只生成一次） |
| `MIGRATION_FAILED` | 迁移会话已因内存待累计分片丢失进入 failed 终态；用新（或同一）幂等键重新发起迁移 |
| `CUSTODY_DESTROYED` | 托管记录（或其迁移谱系）已逻辑销毁：在线分片已删除、在途恢复/迁移已阻断；旧会话不再下发分片或密文（HTTP 410） |

---

## 4. 安全设计要点

**不可变策略 + 版本/epoch 推进**
`policies` 以 `(policy_id, version)` 为复合主键，只 INSERT、永不 UPDATE 内容；
`policy_heads` 保存当前头指针。轮换与撤销在**单事务**内完成（行级 advisory lock + 头行 `FOR UPDATE`）：
插入新版本 → 旧版本置 `revoked`、其下 custody 置 `rotated/revoked` → 前移指针。
并发轮换只有一方成功，另一方得到 `VERSION_CONFLICT`。所有写入接口都要求 `expected_version` 乐观锁。

**Shamir 分片（GF(p)，p = 2²⁵⁶−2³²−977）**
秘密按 31 字节分块，每块构造独立的 `(threshold−1)` 次多项式；分片点 x 为托管人序号，
y 拼接编码。任意 ≥ threshold 个分片可插值还原，少于门限不提供任何信息（50 组随机参数性质测试见
`scripts/demo.py`）。每个分片以 `HKDF(master_key, shard_id)` 派生独立密钥，AES-256-GCM 加密落盘；
数据库同时保存 `secret_digest` 与各 `shard_digest`，重组后做常量时间比对。

**领取本人分片 + 一次性 nonce + 签名绑定实际分片**
nonce 是 32 字节随机数，库里只存 `sha256(nonce)`，且有 `UNIQUE(nonce_hash)` 与
`UNIQUE(session_id, custodian_id)` 两重约束。托管人**先用 nonce 领取本人分片**，
再对规范报文（`keyvault.share.v2`）签名，报文逐行绑定
`custodian / policy_id / policy_version / session_id / nonce / point_x / shard_digest`。
提交时必须同时给出 `point_x` 与 `shard_hex`，因此：

- 只拿到 nonce 就签名、不交自己的分片 → 无法计数（点位/摘要校验过不了），凑门限无从谈起；
- 提交别人的点位或被篡改的分片字节 → 分别得到 `SHARE_POINT_MISMATCH` / `SHARE_DIGEST_MISMATCH`；
- 同一 nonce 用两次 → 第二次 `NONCE_ALREADY_USED`；
- 把别的托管人/别的会话的 nonce 拿来用 → `CROSS_POLICY_SHARE`；
- 策略轮换后重放旧版本场景的 nonce → 版本不匹配，且会话侧直接 `EPOCH_REVOKED`；
- 归属、点位、摘要、验签任一失败都**不花费 nonce**（合法网络重试不会锁死托管人）；
  全部通过后才在同一事务内花费 nonce、写入计数。

**并发竞态**
nonce 签发、分片领取与份额提交都先对 `recovery_sessions` 行 `SELECT ... FOR UPDATE`，
同一会话完全串行化；重复提交再由唯一约束兜底。内存待累计分片在全部校验通过、数据库写入
完成后才入池，其撤销边界有双重保证：**校验拒绝发生在入池之前，回滚时绝不触碰已提交的内存分片；
入池后的任何失败（重组/审计写入/连接中止）都在行锁释放之前、凭本次插入的私有 token 精确撤回
本次新增**——token 不匹配（例如同托管人的成功重试已先把新分片放入池中）时撤销为安全 no-op。
因此即使在“失败回滚 × 锁等待者 × 同托管人重试”的交错下，数据库提交计数与内存内容始终对应，
等待者拿锁时绝不会读到未提交分片，旧请求也无法误删新分片；门限只按**已提交且验签**的分片
达成一次，重放已花费 nonce 等拒绝不会破坏进行中的会话。演示脚本用 `asyncio.gather` 双发验证：
同一份额并发提交恰好一次 200、一次 409，份额计数不重复；另有“重放 × 合法提交”交错用例，
验证合法分片补足门限恰好完成一次、密文只下发一次；`scripts/race_recovery.py` 进一步用故障注入
闸门钉住行锁等待与回滚的精确交错（38 项断言）。

**恢复会话与一次性密文**
会话绑定 `custody/policy_version/epoch_index/request_digest/valid_until`；提交时实时校验
会话未完成、未过期、epoch 未被撤销或过期——即使会话进行中租户突然轮换/撤销，在途份额也会被拒。
门限满足后秘密只存在于当前请求栈内存，且**只由托管人实际提交、并已通过归属/点位/摘要/验签的
分片**插值得到（服务端**不**解密自己的库存分片来凑数）→ 校验 `secret_digest` →
X25519 临时 ECDH + HKDF + AES-GCM 包装 → 同事务把会话置 `completed`，提交成功后立即清空内存待累计分片，
密文不再可获取（重复提交、撤销、并发下都只返回这一次）。
AAD 绑定会话全部要素，密文无法被挪到别的会话复用。待累计分片明文绝不落盘（见 `app/pending.py`）。

**跨策略密钥迁移（v1.4）**
迁移会话 `migration_sessions` 与恢复表结构同构（独立的 `migration_nonces` /
`migration_share_submissions`），额外固化 `source_digest/target_digest` 与只存摘要的
`idempotency_key_hash`。三重部分唯一约束保证“不重复迁移”：

- `UNIQUE(tenant_id, idempotency_key_hash) WHERE status='open'`：同键有效会话唯一；
- `UNIQUE(source_custody_id) WHERE status='open'`：同一 custody 至多一个进行中迁移；
- `UNIQUE(source_custody_id) WHERE new_custody_id IS NOT NULL`：已迁移 custody 全局唯一。

创建在源 custody 行 `FOR UPDATE` 锁内完成，并发被串行化，索引再兜底。每个关口（nonce/claim/submit）
都在迁移行锁内重新校验：会话未完成/未过期、绑定的源/目标**版本摘要**与不可变版本行逐字节一致、
源与目标版本均未撤销/未过期、提交者确属**源**策略成员。签名协议独立为 `keyvault.migration.v1`，
与恢复报文互不兼容，签名逐行绑定源/目标摘要，无法把迁移签名挪去恢复、也无法跨目标版本重放。

门限达成后的关键路径与恢复同样严格：秘密**只由已验签提交源分片在请求栈内存插值**得到
（绝不解密库存源分片凑数），校验 `secret_digest` 后**立即**按目标策略重新 `shamir_split`、
逐片以独立 HKDF 密钥 AES-GCM 加密；随后 **新 `key_custodies` + 新 `shards` + 会话置 completed +
`migration.complete` 审计** 在**同一事务**提交，重组秘密在作用域结束即丢弃。源 custody 与源 shards
**一行不改**（不 UPDATE 状态、不删除、不置 rotated）；迁移不改变源记录，源门限恢复仍可独立进行。
入池后失败沿用 v1.3 双重撤销边界；TTL 或源侧失效的 open 会话在同源下一次创建时惰性置 `expired`
以释放唯一索引，之后同键/新键均可安全重试。已计数源分片的内存明文丢失（重启/淘汰）时，检出缺片
的提交在**行锁仍持有的同一事务**里撤销自身分片（内存 token + 提交记录 + nonce）、把会话置
`failed` 终态并追加无明文 `migration.fail` 审计后整体提交：`failed` 与 `expired` 一样不占两条
open 唯一索引，等待中的旧会话请求只得 `MIGRATION_FAILED`，租户可立即用新（或同一）幂等键从源
记录重新发起；失败会话 `new_custody_id` 为空，配合 `uq_migration_source_completed` 保证
**新托管记录全局至多一条**。幂等重放（含完成态）返回 200 与同一新 custody 标识，
迁移全过程的响应、数据库与审计只出现 ID、版本摘要、点位和分片/秘密摘要，不出现任何明文。

**托管记录谱系逻辑销毁（v1.6）**
销毁是一次**单事务、行锁串行**的在线逻辑擦除。谱系只沿**已完成迁移边**
（`migration_sessions.new_custody_id IS NOT NULL`）向前展开：`open/failed/expired` 迁移不产生
后代，故不存在“通过在途迁移绕过销毁”的后代。展开以**不动点逐轮加锁**完成——每轮先按 id 顺序
`SELECT … FOR UPDATE` 锁定新发现的后代 custody 行，再沿其出边扩展，直到集合收敛；这与迁移门限
提交、恢复份额提交共用同一全局锁序（**custody 行先于会话行**），因此销毁 × 迁移完成 × 分片领取
× 份额提交**不可能死锁**，且交错结果只有两种确定性结局：迁移先提交则销毁在下一轮展开中看到
新后代并把其分片一并删除（**绝不漏删**）；销毁先提交则排队中的旧会话拿锁后经守卫只得到
`CUSTODY_DESTROYED`，既不再下发分片明文/一次性密文，其事务也已整体回滚、**插不进漏删后代**。
同一事务内：谱系 custody 置 `destroyed`（保留无秘密墓碑）、在线 `shards` 密文行 `DELETE`、
谱系上 `open` 的恢复/迁移会话置 `destroyed` 终态、写 `destruction.complete` 审计与幂等回执；
事务**提交成功后**才按会话键 `pending.clear()` 清掉进程内待累计分片（沿用“提交后清内存”的边界，
失败整体回滚则不清）。销毁回执 `destructions` 以 `(tenant_id, idempotency_key_hash)` 唯一约束
保证同键重试永远返回同一份回执；并发复用同一键销毁**互不相关**的根时，两个请求可能双双通过
回执预查，后插入者撞该唯一索引——仅此约束（`uq_destruction_idem`）被翻译为确定性结果：
事务整体回滚后重读胜方回执，同根按重放返回同一回执（200），不同根返回 409
`IDEMPOTENCY_CONFLICT` 并独立留痕拒绝审计；其它约束/数据库错误原样上抛，绝不误判。
销毁只覆盖**在线服务数据**（回执
`scope=online_service_data_only`），**不宣称擦除外部备份**——快照/备份/对象存储版本/客户端缓存
等副本的擦除须由其自身生命周期与介质策略保证。

**审计：按序、可重放、不泄密**
`audit_log` 仅追加，每条记录 `seq`（事务级 advisory lock 串行分配）与
`entry_hash = SHA256(规范字段 || prev_hash)`，形成哈希链；`GET /audit/replay`
逐条复算并报告首个断裂点。审计内容只含 ID、版本、epoch、**分片点位与摘要**、计数等事实，
写入口还会按字段名（secret/private/ciphertext/plaintext/share_blob/nonce/key…）二次过滤，
拒绝事件同样留痕（含 `migration.start/nonce.issue/shard.claim/share.submit/complete`
及其 denied 记录）。

---

## 5. 本地开发（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# 准备一个 PostgreSQL 16，设置 KEYVAULT_DATABASE_URL 后：
python -m app.seed                      # 建表 + 演示身份
uvicorn app.main:app --reload --port 8000
KEYVAULT_BASE_URL=http://localhost:8000 python -m scripts.demo       # 端到端验收（含跨策略迁移与谱系销毁）
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_recovery           # 并发回滚竞态回归（38 项）
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_migration          # 迁移缺片故障转移回归（37 项）
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_migration_start    # 迁移创建并发幂等回归（S1–S14）
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_destruction        # 谱系逻辑销毁并发回归（D1–D9）
```

## 6. 生产注意（本仓库为演示强化基线，上线前至少完成）

- 替换全部演示密钥；分片主密钥建议接入 KMS，进程只持有短期解封装后的密钥；
- 启用 TLS；为管理端与租户/托管人端分离网关与限流；
- `pgcrypto`/列级权限或独立加密服务进一步隔离分片；按租户评估分片落盘地域；
- 轮换主密钥时需要对分片做 rewrap（数据模型中 `shards.id` 即派生密钥标识，可据此迁移）。
