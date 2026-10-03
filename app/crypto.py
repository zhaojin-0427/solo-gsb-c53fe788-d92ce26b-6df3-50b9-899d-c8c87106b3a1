"""Cryptographic primitives.

* Shamir secret sharing over the 256-bit prime field (P = 2^256 - 2^32 - 977).
  Secrets are split into <=31-byte blocks so each block coefficient fits below P.
* HKDF-SHA256 + AES-256-GCM for shard encryption at rest.
* Ed25519 custodian signatures.
* One-time X25519/ECDH + HKDF + AES-256-GCM wrap of reconstructed secrets.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Field arithmetic (secp256k1 prime).  Shares evaluate y for custodian index x.
# ---------------------------------------------------------------------------
P = (1 << 256) - (1 << 32) - 977
BLOCK = 31  # bytes per block, < P


def _rand_below_p() -> int:
    while True:
        v = int.from_bytes(os.urandom(32), "little")
        if v < P:
            return v


def _eval_poly(coeffs: list[int], x: int) -> int:
    # Horner
    y = 0
    for a in reversed(coeffs):
        y = (y * x + a) % P
    return y


def _lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj % P)) % P
            den = (den * (xi - xj)) % P
        total = (total + yi * num * pow(den, P - 2, P)) % P
    return total


def _blocks(secret: bytes) -> list[int]:
    out = []
    for i in range(0, len(secret), BLOCK):
        chunk = secret[i : i + BLOCK]
        out.append(int.from_bytes(chunk, "little"))
    return out


def shamir_split(secret: bytes, threshold: int, shares: int) -> list[tuple[int, bytes]]:
    """Return list of (x, encoded_y_blob). x in 1..shares."""
    if not 1 <= threshold <= shares:
        raise ValueError("invalid threshold/shares")
    blocks = _blocks(secret)
    if not blocks:
        blocks = [0]
    # 每个块一条多项式；所有 x 必须求值同一条多项式（系数只生成一次）。
    polynomials = [
        [block_int] + [_rand_below_p() for _ in range(threshold - 1)]
        for block_int in blocks
    ]
    result: list[tuple[int, bytes]] = []
    for x in range(1, shares + 1):
        blob = b"".join(_eval_poly(c, x).to_bytes(32, "big") for c in polynomials)
        result.append((x, blob))
    return result


def shamir_combine(points: list[tuple[int, bytes]], secret_len: int) -> bytes:
    """points: list of (x, encoded_y_blob). Returns the reconstructed secret."""
    if not points:
        raise ValueError("no points")
    width = len(points[0][1])
    if width % 32 != 0:
        raise ValueError("malformed share blob")
    nblocks = width // 32
    if any(len(blob) != width for _, blob in points):
        raise ValueError("inconsistent share sizes (cross-policy share)")
    out = bytearray()
    for b in range(nblocks):
        pts: list[tuple[int, int]] = []
        seen_x: set[int] = set()
        for x, blob in points:
            if x in seen_x:
                raise ValueError("duplicate point")
            seen_x.add(x)
            y = int.from_bytes(blob[b * 32 : (b + 1) * 32], "big")
            if y >= P:
                raise ValueError("point out of field")
            pts.append((x, y))
        block_int = _lagrange_interpolate_at_zero(pts)
        if block_int >= 1 << (BLOCK * 8):
            raise ValueError("reconstructed block out of range (inconsistent or forged shares)")
        out += block_int.to_bytes(BLOCK, "little")
    return bytes(out[:secret_len])


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_hex_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Shard at rest: HKDF(master, shard_id) -> AES-256-GCM key
# ---------------------------------------------------------------------------

def _shard_key(master: bytes, shard_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"keyvault-shard-v1",
        info=shard_id.encode(),
    ).derive(master)


def encrypt_shard(master: bytes, shard_id: str, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(_shard_key(master, shard_id)).encrypt(nonce, plaintext, b"shard")
    return nonce + ct


def decrypt_shard(master: bytes, shard_id: str, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(_shard_key(master, shard_id)).decrypt(nonce, ct, b"shard")


# ---------------------------------------------------------------------------
# Custodian signing keys (Ed25519)
# ---------------------------------------------------------------------------

def generate_signing_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv_raw, pub_raw


def verify_signature(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_message(private_key_raw: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_key_raw).sign(message)


# Canonical message a custodian signs.  policy_version binds the share so a
# signature cannot be replayed against a different (e.g. rotated) policy.
# point_x + shard_digest bind the signature to the *actual shard blob* being
# submitted: a signature on a nonce alone is never sufficient — the verifier
# must confirm the signer actually holds the shard it claims to contribute.
def custodian_signing_message(
    *,
    nonce: str,
    session_id: str,
    policy_id: str,
    policy_version: int,
    custodian_id: str,
    point_x: int,
    shard_digest: str,
) -> bytes:
    fields = [
        "keyvault.share.v2",
        f"custodian={custodian_id}",
        f"policy={policy_id}",
        f"version={policy_version}",
        f"session={session_id}",
        f"nonce={nonce}",
        f"point={point_x}",
        f"shard_digest={shard_digest}",
    ]
    return "\n".join(fields).encode()


# ---------------------------------------------------------------------------
# Cross-policy migration
# ---------------------------------------------------------------------------

# 迁移会话/签名全程绑定的不可变策略版本摘要：对版本行全部不变要素做规范化哈希。
# 迁移会话创建时把源/目标摘要固化下来，此后每个关口复核——即使底层数据异常，
# 迁移也不会在“换了一个版本”的情况下继续。
def policy_version_digest(
    *,
    policy_id: str,
    version: int,
    tenant_id: str,
    threshold: int,
    custodian_ids: list[str],
    epoch_index: int,
    epoch_valid_from: str,
    epoch_valid_until: str,
    rotation_interval: int,
) -> str:
    import json

    canonical = json.dumps(
        {
            "protocol": "keyvault.policy.v1",
            "policy_id": policy_id,
            "version": version,
            "tenant_id": tenant_id,
            "threshold": threshold,
            "custodian_ids": list(custodian_ids),
            "epoch_index": epoch_index,
            "epoch_valid_from": epoch_valid_from,
            "epoch_valid_until": epoch_valid_until,
            "rotation_interval": rotation_interval,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


# 迁移专用签名报文（与恢复的 keyvault.share.v2 区分，杜绝跨协议重放）：
# 逐行绑定 迁移会话/源策略版本摘要/目标策略版本摘要/nonce/托管人/点位/分片摘要。
def migration_signing_message(
    *,
    nonce: str,
    migration_id: str,
    source_policy_id: str,
    source_version: int,
    source_digest: str,
    target_policy_id: str,
    target_version: int,
    target_digest: str,
    custodian_id: str,
    point_x: int,
    shard_digest: str,
) -> bytes:
    fields = [
        "keyvault.migration.v1",
        f"migration={migration_id}",
        f"custodian={custodian_id}",
        f"source_policy={source_policy_id}",
        f"source_version={source_version}",
        f"source_digest={source_digest}",
        f"target_policy={target_policy_id}",
        f"target_version={target_version}",
        f"target_digest={target_digest}",
        f"nonce={nonce}",
        f"point={point_x}",
        f"shard_digest={shard_digest}",
    ]
    return "\n".join(fields).encode()
# Returned ciphertext can only be unwrapped by the requester's private key.
# ---------------------------------------------------------------------------
WRAP_PREFIX = b"KWR1"


def generate_wrap_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv_raw, pub_raw


def wrap_secret(recipient_x25519_public_key_hex: str, secret: bytes, aad: bytes) -> dict:
    recipient_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_x25519_public_key_hex))
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient_pub)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"keyvault-wrap-v1",
        info=WRAP_PREFIX + aad,
    ).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, secret, aad)
    return {
        "algorithm": "X25519-Ephemeral-HKDF-SHA256-AES256GCM",
        "ephemeral_public_key": ephemeral.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "aad": aad.decode(),
    }
