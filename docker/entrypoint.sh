#!/bin/sh
set -e

# 等待数据库就绪、建表（幂等）、写入演示身份，然后启动服务
echo "[entrypoint] seeding schema + demo identities"
python - <<'PY'
import asyncio
from app.config import get_settings
from app.db import wait_for_database, Database
from app.seed import seed

async def main():
    s = get_settings()
    await wait_for_database(s.database_url, attempts=60, delay=1.0)
    db = Database(s.database_url)
    await db.connect()
    await seed()
    await db.close()

asyncio.run(main())
PY
echo "[entrypoint] starting API"
exec "$@"
