"""Deterministic demo identities (NOT for production).

Run after startup (docker compose runs it automatically):
    python -m app.seed
"""
from __future__ import annotations

import asyncio
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto
from .config import get_settings

DEMO_TENANT = {"id": "ten_demo", "name": "demo-acme"}
DEMO_CUSTODIANS = [
    {"id": "cus_demo_alice", "name": "alice"},
    {"id": "cus_demo_bob", "name": "bob"},
    {"id": "cus_demo_carol", "name": "carol"},
]


def _tenant_api_key() -> str:
    return "tsec_" + hashlib.sha256(b"demo-tenant-key").hexdigest()


def _custodian_api_key(name: str) -> str:
    return "csec_" + hashlib.sha256(f"demo-custodian-key:{name}".encode()).hexdigest()


def _custodian_signing_seed(name: str) -> bytes:
    return hashlib.sha256(f"demo-custodian-signing:{name}".encode()).digest()


def demo_credentials() -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    custodians = []
    for c in DEMO_CUSTODIANS:
        seed = _custodian_signing_seed(c["name"])
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        custodians.append(
            {
                "custodian_id": c["id"],
                "name": c["name"],
                "api_key": _custodian_api_key(c["name"]),
                "signing_private_key": seed.hex(),
                "signing_public_key": pub,
            }
        )
    return {
        "admin_api_key": get_settings().admin_api_key,
        "tenant": {
            "tenant_id": DEMO_TENANT["id"],
            "name": DEMO_TENANT["name"],
            "api_key": _tenant_api_key(),
        },
        "custodians": custodians,
    }


async def seed() -> None:
    settings = get_settings()
    from .db import Database, wait_for_database

    await wait_for_database(settings.database_url)
    db = Database(settings.database_url)
    await db.connect()
    try:
        async with db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO tenants (id, name, api_key_hash) VALUES ($1,$2,$3)
                ON CONFLICT (id) DO NOTHING
                """,
                DEMO_TENANT["id"],
                DEMO_TENANT["name"],
                crypto.sha256_hex(_tenant_api_key().encode()),
            )
            for c in DEMO_CUSTODIANS:
                pub = Ed25519PrivateKey.from_private_bytes(
                    _custodian_signing_seed(c["name"])
                ).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                await conn.execute(
                    """
                    INSERT INTO custodians (id, name, api_key_hash, signing_pubkey)
                    VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING
                    """,
                    c["id"], c["name"], crypto.sha256_hex(_custodian_api_key(c["name"]).encode()), pub,
                )
    finally:
        await db.close()


if __name__ == "__main__":
    import json

    asyncio.run(seed())
    print(json.dumps(demo_credentials(), indent=2, ensure_ascii=False))
