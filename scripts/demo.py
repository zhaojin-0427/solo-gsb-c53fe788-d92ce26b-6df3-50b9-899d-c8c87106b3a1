"""End-to-end demonstration and acceptance check.

Usage:
    KEYVAULT_BASE_URL=http://localhost:8000 python -m scripts.demo

Verifies:
  1. policy creation / immutable versions / atomic rotation & revocation
  2. Shamir n-of-m custody, shard digests, secret never returned in plaintext
  3. threshold recovery with one-time X25519 wrapped ciphertext, client unwrap
  4. deterministic rejections: bad signature, wrong shard point, tampered
     shard digest, nonce reuse / claim with spent nonce, duplicate share,
     cross-policy share, revoked/expired epoch, session completed/expired,
     optimistic version conflict, concurrent duplicate race
  5. cross-request state consistency: spent-nonce replay after a partial
     session must not evict already-committed in-memory shares; interleaved
     replays and legitimate submits keep db count and memory in agreement;
     the wrapped ciphertext is returned exactly once
  6. cross-policy key migration: idempotent session create bound to
     source/target version digests; nonce -> claim -> sign -> submit of source
     shards; in-memory reconstruct + target re-shard in one transaction;
     source record untouched; no plaintext in response/db/audit; revoked,
     expired, cross-tenant, concurrent and duplicate attempts rejected;
     idempotent replay and safe retry after failure/TTL
  7. audit hash-chain replay valid and contains no secret material
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.seed import demo_credentials
from app.crypto import custodian_signing_message as crypto_signing_message

BASE = os.environ.get("KEYVAULT_BASE_URL", "http://localhost:8000")
PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail and not ok else ""))


def body_of(r) -> dict:
    """Tolerate non-JSON (e.g. 500) responses so failures report cleanly."""
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {}


class Client:
    def __init__(self, name: str, key: str):
        self.name = name
        self.http = httpx.AsyncClient(
            base_url=BASE,
            headers={"X-API-Key": key},
            timeout=30,
        )

    async def call(self, method: str, path: str, **kw):
        r = await self.http.request(method, path, **kw)
        return r

    async def close(self):
        await self.http.aclose()


def sign(sign_priv_hex: str, message: str | bytes) -> str:
    data = message.encode() if isinstance(message, str) else message
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sign_priv_hex)).sign(
        data
    ).hex()


def unwrap(wrap_priv_hex: str, wrap: dict, aad: str) -> bytes:
    ephemeral_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(wrap["ephemeral_public_key"]))
    shared = X25519PrivateKey.from_private_bytes(bytes.fromhex(wrap_priv_hex)).exchange(ephemeral_pub)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"keyvault-wrap-v1",
        info=b"KWR1" + aad.encode(),
    ).derive(shared)
    return AESGCM(key).decrypt(bytes.fromhex(wrap["nonce"]), bytes.fromhex(wrap["ciphertext"]), aad.encode())


async def expect_error(cli: Client, name: str, method: str, path: str, code: str, **kw):
    r = await cli.call(method, path, **kw)
    body = body_of(r)
    ok = body.get("error", {}).get("code") == code
    check(f"{name} -> {code}", ok,
          json.dumps(body, ensure_ascii=False) if body else f"HTTP {r.status_code}: {r.text[:200]}")
    return body


async def main() -> int:
    creds = demo_credentials()
    tenant = Client("tenant", creds["tenant"]["api_key"])
    cuds = {c["name"]: Client(c["name"], c["api_key"]) for c in creds["custodians"]}
    ckeys = {c["name"]: c for c in creds["custodians"]}
    admin = Client("admin", creds["admin_api_key"])
    dest_other = None

    try:
        # 每次运行使用唯一策略后缀，保证脚本在持久库上可重复执行
        suffix = os.urandom(4).hex()
        pol_main = f"pol_main_{suffix}"
        pol_bad = f"pol_bad_{suffix}"
        pol_exp = f"pol_exp_{suffix}"
        pol_ttl = f"pol_ttl_{suffix}"
        pol_live = f"pol_live_{suffix}"

        # --- 健康检查 ------------------------------------------------------
        r = await tenant.call("GET", "/health")
        check("health", r.status_code == 200 and r.json()["status"] == "ok")

        # --- 认证 ----------------------------------------------------------
        anon = httpx.AsyncClient(base_url=BASE)
        r = await anon.get("/policies/p1")
        check("no api key -> 401", r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED")
        await anon.aclose()

        # --- 策略参数校验 --------------------------------------------------
        bad = {
            "policy_id": pol_bad,
            "threshold": 5,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob"],
            "epoch": {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z",
                      "rotation_interval": 0},
        }
        await expect_error(tenant, "threshold > custodians", "POST", "/policies",
                           "POLICY_PARAMS_INVALID", json=bad)

        # --- 创建 2-of-3 策略 ----------------------------------------------
        epoch = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z",
                 "rotation_interval": 0}
        pol = {
            "policy_id": pol_main,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        }
        r = await tenant.call("POST", "/policies", json=pol)
        check("create policy v1 (2-of-3)", r.status_code == 201 and r.json()["version"] == 1,
              r.text)
        await expect_error(tenant, "create same policy twice", "POST", "/policies",
                           "BAD_REQUEST", json=pol)

        # 策略版本不可变：没有任何修改接口，GET 历史版本
        r = await tenant.call("GET", f"/policies/{pol_main}?version=1")
        check("read immutable v1", r.json()["status"] == "active")

        # --- 托管密钥（Shamir 分片） ---------------------------------------
        secret = b"the-quick-brown-fox-master-key-0123456789"
        secret_hex = secret.hex()
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_main, "expected_version": 1,
                                    "secret_hex": secret_hex})
        custody = r.json()
        check("custody: 3 encrypted shards + digests",
              r.status_code == 201 and custody["shard_count"] == 3
              and len(custody["shard_digests"]) == 3
              and all(len(d) == 64 for d in custody["shard_digests"]), r.text)
        check("custody response contains no plaintext", secret_hex not in r.text)

        # expected_version 不匹配
        await expect_error(tenant, "custody stale version", "POST", "/custodies",
                           "VERSION_CONFLICT",
                           json={"policy_id": pol_main, "expected_version": 99, "secret_hex": "00"})

        # --- 恢复会话 ------------------------------------------------------
        wrap_priv, wrap_pub = None, None
        # X25519 keypair
        wp = X25519PrivateKey.generate()
        wrap_priv = wp.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()).hex()
        wrap_pub = wp.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw).hex()
        request_digest = hashlib.sha256(b"ticket-4242|purpose=daily-rotation").hexdigest()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        session = r.json()
        check("open recovery session", r.status_code == 201 and session["status"] == "open", r.text)

        # --- 托管人获取 nonce（只发 nonce + 绑定要素，签名对象在领取分片后给出） -
        async def get_nonce(cname: str, sid: str | None = None):
            r = await cuds[cname].call("POST", "/recoveries/nonces",
                                       json={"session_id": sid or session["session_id"]})
            return r

        async def claim(cname: str, sid: str, nonce: str):
            return await cuds[cname].call("POST", "/recoveries/shards/claim",
                                          json={"session_id": sid, "nonce": nonce})

        async def submit(cname: str, sid: str, nonce: str, point_x: int, shard_hex: str, sig: str):
            return await cuds[cname].call("POST", "/recoveries/shares", json={
                "session_id": sid, "nonce": nonce, "point_x": point_x,
                "shard_hex": shard_hex, "signature": sig})

        r_alice = await get_nonce("alice")
        nonce_alice = r_alice.json()
        check("alice gets one-time nonce", r_alice.status_code == 200, r_alice.text)
        check("nonce binds policy version",
              "signing_message" not in nonce_alice and nonce_alice["point_x"] >= 1
              and len(nonce_alice["shard_digest"]) == 64)

        # 重复申请 nonce -> NONCE_ALREADY_USED
        await expect_error(cuds["alice"], "re-request nonce", "POST", "/recoveries/nonces",
                           "NONCE_ALREADY_USED", json={"session_id": session["session_id"]})

        # --- 外部托管人（不属于本策略版本）：连 nonce 都拿不到 ----------------
        r = await admin.call("POST", "/admin/custodians", json={"name": f"outsider-{suffix}"})
        outsider = r.json()
        check("admin registers outsider custodian", r.status_code == 201, r.text)
        outsider_cli = Client(outsider["name"], outsider["api_key"])
        await expect_error(outsider_cli, "outsider nonce on policy", "POST",
                           "/recoveries/nonces", "CROSS_POLICY_SHARE",
                           json={"session_id": session["session_id"]})
        await outsider_cli.close()

        # --- 领取本人分片（验过身份的托管人） --------------------------------
        # 未知 nonce / 伪造 nonce 领取 -> BAD_REQUEST，不泄露分片
        await expect_error(cuds["alice"], "claim with unknown nonce", "POST",
                           "/recoveries/shards/claim", "BAD_REQUEST",
                           json={"session_id": session["session_id"], "nonce": "00" * 32})

        c_alice = (await claim("alice", session["session_id"], nonce_alice["nonce"])).json()
        check("alice claims own shard (point+bytes+digest)",
              c_alice["point_x"] == nonce_alice["point_x"]
              and len(bytes.fromhex(c_alice["shard_hex"])) > 0
              and c_alice["shard_digest"] == nonce_alice["shard_digest"],
              json.dumps({k: v for k, v in c_alice.items() if k != "shard_hex"}))
        check("claimed shard alone does not reveal the secret",
              secret_hex not in c_alice["shard_hex"] and secret.decode() not in c_alice["shard_hex"])
        check("signing message binds nonce/session/version/point/digest",
              f"nonce={nonce_alice['nonce']}" in c_alice["signing_message"]
              and f"session={session['session_id']}" in c_alice["signing_message"]
              and f"version=1" in c_alice["signing_message"]
              and f"point={c_alice['point_x']}" in c_alice["signing_message"]
              and f"shard_digest={c_alice['shard_digest']}" in c_alice["signing_message"]
              and "keyvault.share.v2" in c_alice["signing_message"])
        # 同一未花费 nonce 可重复领取（幂等），返回同一片
        c_alice_again = (await claim("alice", session["session_id"], nonce_alice["nonce"])).json()
        check("claim is idempotent before spend",
              c_alice_again["shard_hex"] == c_alice["shard_hex"]
              and c_alice_again["signing_message"] == c_alice["signing_message"])

        # --- 错误分片：点位不对 / 字节被改，均不花费 nonce，依据确定 ----------
        # 先领 bob 的分片
        nonce_bob = (await get_nonce("bob")).json()
        c_bob = (await claim("bob", session["session_id"], nonce_bob["nonce"])).json()
        sig_a = sign(ckeys["alice"]["signing_private_key"], c_alice["signing_message"])

        # alice 提交 bob 的点位 -> SHARE_POINT_MISMATCH（归属点位校验先于花钱）
        wrong_point_body = {
            "session_id": session["session_id"], "nonce": nonce_alice["nonce"],
            "point_x": c_bob["point_x"], "shard_hex": c_alice["shard_hex"], "signature": sig_a,
        }
        await expect_error(cuds["alice"], "wrong point submitted", "POST",
                           "/recoveries/shares", "SHARE_POINT_MISMATCH", json=wrong_point_body)

        # alice 篡改自己的分片字节 -> SHARE_DIGEST_MISMATCH（与库存摘要不符）
        blob = bytearray(bytes.fromhex(c_alice["shard_hex"]))
        blob[0] ^= 0x01
        tampered = blob.hex()
        bad_digest = hashlib.sha256(bytes.fromhex(tampered)).hexdigest()
        msg_tampered = crypto_signing_message(
            nonce=nonce_alice["nonce"], session_id=session["session_id"],
            policy_id=session["policy_id"], policy_version=1,
            custodian_id="cus_demo_alice", point_x=c_alice["point_x"], shard_digest=bad_digest)
        sig_tampered = sign(ckeys["alice"]["signing_private_key"], msg_tampered)
        await expect_error(cuds["alice"], "tampered shard bytes", "POST",
                           "/recoveries/shares", "SHARE_DIGEST_MISMATCH", json={
                               "session_id": session["session_id"], "nonce": nonce_alice["nonce"],
                               "point_x": c_alice["point_x"], "shard_hex": tampered,
                               "signature": sig_tampered})
        # 错误分片未花费 nonce：随后用正确分片仍可提交
        check("bad shard did not spend nonce", True)

        # --- 错误签名被拒 ---------------------------------------------------
        await expect_error(cuds["alice"], "bad signature", "POST",
                           "/recoveries/shares", "BAD_SIGNATURE",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_alice["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": "00" * 64})

        # 正确分片 + 正确签名提交（alice），尚不足门限
        r = await submit("alice", session["session_id"], nonce_alice["nonce"],
                         c_alice["point_x"], c_alice["shard_hex"], sig_a)
        body = r.json()
        check("alice share accepted (1/2), no wrap yet",
              r.status_code == 200 and body["shares_received"] == 1 and body["wrap"] is None, r.text)

        # nonce 一次性：重放同一 nonce
        await expect_error(cuds["alice"], "reuse spent nonce", "POST", "/recoveries/shares",
                           "NONCE_ALREADY_USED",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_alice["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": sig_a})

        # nonce 已花费：再次领取分片被拒
        await expect_error(cuds["alice"], "claim with spent nonce", "POST",
                           "/recoveries/shards/claim", "NONCE_ALREADY_USED",
                           json={"session_id": session["session_id"], "nonce": nonce_alice["nonce"]})

        sig_b = sign(ckeys["bob"]["signing_private_key"], c_bob["signing_message"])

        # --- 跨策略/跨会话 nonce 绑定 --------------------------------------
        # alice 用 bob 的 nonce 提交 -> 绑定不匹配 CROSS_POLICY_SHARE
        sig_for_bob_nonce = sign(ckeys["alice"]["signing_private_key"], c_bob["signing_message"])
        await expect_error(cuds["alice"], "use another custodian nonce", "POST",
                           "/recoveries/shares", "CROSS_POLICY_SHARE",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_bob["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": sig_for_bob_nonce})

        # --- 门限满足：bob 提交本人分片 -> 重组 + 一次性密文 ------------------
        r = await submit("bob", session["session_id"], nonce_bob["nonce"],
                         c_bob["point_x"], c_bob["shard_hex"], sig_b)
        body = r.json()
        check("bob share -> threshold met, completed",
              r.status_code == 200 and body["completed"] and body["status"] == "completed"
              and body["wrap"] is not None, r.text)

        # 客户端用私钥解开密文并校验
        try:
            recovered = unwrap(wrap_priv, body["wrap"], body["aad"])
            check("unwrap one-time ciphertext == original secret", recovered == secret)
        except Exception as exc:  # noqa: BLE001
            check("unwrap one-time ciphertext == original secret", False, repr(exc))

        # 门限满足后继续提交 -> SESSION_COMPLETED
        nonce_carol = await get_nonce("carol")
        check("nonce after completion -> SESSION_COMPLETED",
              nonce_carol.status_code == 409
              and nonce_carol.json()["error"]["code"] == "SESSION_COMPLETED",
              nonce_carol.text)

        # --- 并发竞态：同一份额并发双发，恰好一次 200、一次 409，计数不重复 --
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s2 = r.json()
        n2 = (await cuds["bob"].call("POST", "/recoveries/nonces",
                                     json={"session_id": s2["session_id"]})).json()
        c2 = (await claim("bob", s2["session_id"], n2["nonce"])).json()
        sig2 = sign(ckeys["bob"]["signing_private_key"], c2["signing_message"])
        payload = {"session_id": s2["session_id"], "nonce": n2["nonce"],
                   "point_x": c2["point_x"], "shard_hex": c2["shard_hex"], "signature": sig2}
        rs = await asyncio.gather(
            cuds["bob"].call("POST", "/recoveries/shares", json=payload),
            cuds["bob"].call("POST", "/recoveries/shares", json=payload),
        )
        codes = sorted(body_of(x).get("error", {}).get("code", "OK") for x in rs)
        statuses = sorted(x.status_code for x in rs)
        check("concurrent duplicate: exactly one accepted, other 409",
              statuses == [200, 409] and "OK" in codes,
              f"{statuses} {codes}")
        count_after = (await tenant.call("GET", f"/recoveries/{s2['session_id']}")).json()["shares_received"]
        check("no double counting under race", count_after == 1, str(count_after))

        # --- 回归：跨请求状态一致性 ----------------------------------------
        # 未达门限的会话已接受 alice 的有效分片后，alice 重放已花费 nonce 必须
        # 得到确定性 NONCE_ALREADY_USED，且拒绝路径不得撤销已提交的内存分片
        # （数据库计数与内存内容保持对应）；bob 随后补足门限必须仅凭已验签
        # 分片重组成功，密文全局只下发一次。
        async def prep_share(name: str, sid: str) -> dict:
            n = (await cuds[name].call("POST", "/recoveries/nonces",
                                       json={"session_id": sid})).json()
            c = (await claim(name, sid, n["nonce"])).json()
            return {"session_id": sid, "nonce": n["nonce"], "point_x": c["point_x"],
                    "shard_hex": c["shard_hex"],
                    "signature": sign(ckeys[name]["signing_private_key"], c["signing_message"])}

        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s3 = r.json()
        pa3 = await prep_share("alice", s3["session_id"])
        pb3 = await prep_share("bob", s3["session_id"])
        r = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: partial session accepts alice share (1/2)",
              r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)
        replay = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: spent-nonce replay -> 409 NONCE_ALREADY_USED",
              replay.status_code == 409
              and body_of(replay).get("error", {}).get("code") == "NONCE_ALREADY_USED",
              f"HTTP {replay.status_code}: {replay.text[:200]}")
        again = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: repeated replay still clean 409 (no state damage)",
              again.status_code == 409
              and body_of(again).get("error", {}).get("code") == "NONCE_ALREADY_USED",
              f"HTTP {again.status_code}: {again.text[:200]}")
        st3 = body_of(await tenant.call("GET", f"/recoveries/{s3['session_id']}"))
        check("regression: db count intact after replays",
              st3.get("shares_received") == 1 and st3.get("status") == "open", json.dumps(st3))
        r = await cuds["bob"].call("POST", "/recoveries/shares", json=pb3)
        body = body_of(r)
        check("regression: bob completes threshold after replays (no THRESHOLD_NOT_MET)",
              r.status_code == 200 and body.get("completed") and body.get("wrap") is not None,
              r.text)
        if body.get("wrap"):
            try:
                check("regression: reconstructed only from verified shares == secret",
                      unwrap(wrap_priv, body["wrap"], body["aad"]) == secret)
            except Exception as exc:  # noqa: BLE001
                check("regression: reconstructed only from verified shares == secret",
                      False, repr(exc))

        # --- 回归：并发重放与合法提交交错 ------------------------------------
        # alice 已提交（1/2）后，并发混入两条已花费 nonce 的重放与 bob 的合法提交：
        # 重放不得触碰内存中已提交分片，bob 必须完成门限；数据库计数=2、
        # 密文恰好下发一次。
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s4 = r.json()
        pa4 = await prep_share("alice", s4["session_id"])
        pb4 = await prep_share("bob", s4["session_id"])
        r = await cuds["alice"].call("POST", "/recoveries/shares", json=pa4)
        assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text
        rs = await asyncio.gather(
            cuds["alice"].call("POST", "/recoveries/shares", json=pa4),
            cuds["alice"].call("POST", "/recoveries/shares", json=pa4),
            cuds["bob"].call("POST", "/recoveries/shares", json=pb4),
        )
        bodies4 = [body_of(x) for x in rs]
        codes4 = sorted(b.get("error", {}).get("code", "OK") for b in bodies4)
        wraps4 = [b for b in bodies4 if b.get("wrap")]
        rejected4 = [c for c in codes4 if c != "OK"]
        # 重放先于 bob 完成则 NONCE_ALREADY_USED，晚于则 SESSION_COMPLETED；
        # 两者都是干净的 409 拒绝，关键是合法提交不受重放影响、恰好完成一次。
        check("regression: interleaved replays rejected, legit submit completes",
              sorted(x.status_code for x in rs) == [200, 409, 409]
              and codes4.count("OK") == 1
              and all(c in ("NONCE_ALREADY_USED", "SESSION_COMPLETED") for c in rejected4)
              and len(wraps4) == 1 and wraps4[0].get("completed"),
              f"{sorted(x.status_code for x in rs)} {codes4}")
        check("regression: ciphertext returned exactly once under interleaving",
              len(wraps4) == 1, f"wraps={len(wraps4)}")
        st4 = body_of(await tenant.call("GET", f"/recoveries/{s4['session_id']}"))
        check("regression: db count matches verified shares after interleaving",
              st4.get("shares_received") == 2 and st4.get("status") == "completed",
              json.dumps(st4))
        if wraps4:
            try:
                check("regression: interleaved unwrap == secret",
                      unwrap(wrap_priv, wraps4[0]["wrap"], wraps4[0]["aad"]) == secret)
            except Exception as exc:  # noqa: BLE001
                check("regression: interleaved unwrap == secret", False, repr(exc))

        # --- 原子轮换：旧版本不可变且变为 revoked ---------------------------
        new_epoch = {"valid_from": "2027-01-01T00:00:00Z", "valid_until": "2031-01-01T00:00:00Z",
                     "rotation_interval": 0}
        # 乐观版本冲突
        await expect_error(tenant, "rotate with stale expected_version", "POST",
                           f"/policies/{pol_main}/rotate", "VERSION_CONFLICT",
                           json={"expected_version": 99, "epoch": new_epoch})
        r = await tenant.call("POST", f"/policies/{pol_main}/rotate",
                              json={"expected_version": 1, "threshold": 3,
                                    "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                                    "epoch": new_epoch})
        check("rotate -> immutable v2, threshold=3, new epoch",
              r.status_code == 200 and r.json()["version"] == 2 and r.json()["threshold"] == 3
              and r.json()["epoch_index"] == 1, r.text)
        r_old = (await tenant.call("GET", f"/policies/{pol_main}?version=1")).json()
        check("v1 immutable record now revoked", r_old["status"] == "revoked", r_old["status"])

        # 轮换后不能用旧版本托管
        await expect_error(tenant, "custody on stale v1 after rotate", "POST", "/custodies",
                           "VERSION_CONFLICT",
                           json={"policy_id": pol_main, "expected_version": 1,
                                 "secret_hex": "aabb"})

        # --- 会话进行中 epoch 被轮换撤销：在途份额必须被拒 ------------------
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_live,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_live, "expected_version": 1, "secret_hex": secret_hex})
        c_live = r.json()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": c_live["custody_id"],
                                    "request_digest": request_digest, "recovery_public_key": wrap_pub})
        s_live = r.json()
        n_live = (await cuds["alice"].call("POST", "/recoveries/nonces",
                                           json={"session_id": s_live["session_id"]})).json()
        c_live_shard = (await claim("alice", s_live["session_id"], n_live["nonce"])).json()
        # 门限恢复进行中，租户轮换策略 -> 旧 epoch 原子撤销
        r = await tenant.call("POST", f"/policies/{pol_live}/rotate",
                              json={"expected_version": 1, "epoch": new_epoch})
        check("rotate live policy mid-session", r.status_code == 200 and r.json()["version"] == 2, r.text)
        sig_live = sign(ckeys["alice"]["signing_private_key"], c_live_shard["signing_message"])
        await expect_error(cuds["alice"], "share after mid-session rotation", "POST",
                           "/recoveries/shares", "EPOCH_REVOKED",
                           json={"session_id": s_live["session_id"],
                                 "nonce": n_live["nonce"], "point_x": c_live_shard["point_x"],
                                 "shard_hex": c_live_shard["shard_hex"], "signature": sig_live})

        # 并发轮换竞态：两个 expected_version=2 同时推进，只有一个成功
        e3 = {"valid_from": "2028-01-01T00:00:00Z", "valid_until": "2032-01-01T00:00:00Z",
              "rotation_interval": 0}
        body_rot = {"expected_version": 2, "epoch": e3}
        rr = await asyncio.gather(
            tenant.call("POST", f"/policies/{pol_main}/rotate", json=body_rot),
            tenant.call("POST", f"/policies/{pol_main}/rotate", json=body_rot),
        )
        rot_status = sorted(x.status_code for x in rr)
        check("concurrent rotate: exactly one winner", rot_status == [200, 409], str(rot_status))
        head = (await tenant.call("GET", f"/policies/{pol_main}")).json()
        current_v = head["version"]

        # --- 撤销 epoch -----------------------------------------------------
        await expect_error(tenant, "revoke with stale version", "POST",
                           f"/policies/{pol_main}/revoke", "VERSION_CONFLICT",
                           json={"expected_version": 2})
        r = await tenant.call("POST", f"/policies/{pol_main}/revoke",
                              json={"expected_version": current_v})
        check("revoke current epoch atomic", r.status_code == 200 and r.json()["status"] == "revoked",
              r.text)
        # 已撤销上再撤销 -> POLICY_INACTIVE
        await expect_error(tenant, "revoke revoked epoch", "POST",
                           f"/policies/{pol_main}/revoke", "POLICY_INACTIVE",
                           json={"expected_version": current_v})

        # 头版本自身被撤销：托管命中 EPOCH_REVOKED（版本匹配但 epoch 已撤销）
        await expect_error(tenant, "custody on revoked head epoch", "POST", "/custodies",
                           "EPOCH_REVOKED",
                           json={"policy_id": pol_main, "expected_version": current_v,
                                 "secret_hex": "aabb"})

        # 撤销后恢复旧 custody -> EPOCH_REVOKED（v2 上也有 custody 吗？为覆盖路径，
        # 先在 v3 活跃时托管；这里直接对 v1 custody 开恢复：其策略版本 v1 已 revoked）
        await expect_error(tenant, "recovery on revoked epoch", "POST", "/recoveries",
                           "EPOCH_REVOKED",
                           json={"custody_id": custody["custody_id"],
                                 "request_digest": request_digest, "recovery_public_key": wrap_pub})

        # --- epoch 过期 -----------------------------------------------------
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_exp,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2020-01-01T00:00:00Z",
                      "valid_until": "2020-02-01T00:00:00Z", "rotation_interval": 0},
        })
        check("create policy with past epoch ok (immutable record)", r.status_code == 201, r.text)
        await expect_error(tenant, "custody on expired epoch", "POST", "/custodies",
                           "EPOCH_EXPIRED",
                           json={"policy_id": pol_exp, "expected_version": 1, "secret_hex": "aabb"})

        # --- 会话过期（TTL 10s 上限内最小值 10s；为省时直接演示 expired 判定路径，
        # 等待 10 秒）-------------------------------------------------------
        # 先把主策略重新恢复可用：创建新策略新 custody
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_ttl,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2026-01-01T00:00:00Z",
                      "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0},
        })
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_ttl, "expected_version": 1,
                                    "secret_hex": secret_hex})
        c_ttl = r.json()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": c_ttl["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub, "ttl_seconds": 10})
        s_ttl = r.json()
        check("session with 10s ttl created", s_ttl["valid_until"] is not None)
        print("... waiting 11s for session expiry ...")
        await asyncio.sleep(11)
        await expect_error(cuds["alice"], "nonce on expired session", "POST",
                           "/recoveries/nonces", "SESSION_EXPIRED",
                           json={"session_id": s_ttl["session_id"]})

        # ==================================================================
        # 跨策略密钥迁移（v1.4）
        # ==================================================================
        # 源策略 2-of-3（alice/bob/carol），目标策略更换托管集合与门限：
        # bob/carol/dave 2-of-3——演示门限与托管人集合都可以跨策略变更。
        r = await admin.call("POST", "/admin/custodians", json={"name": f"dave-{suffix}"})
        dave = r.json()
        check("admin registers dave custodian", r.status_code == 201, r.text)
        cuds["dave"] = Client("dave", dave["api_key"])
        ckeys["dave"] = dave
        pol_mig = f"pol_mig_{suffix}"
        pol_mig2 = f"pol_mig2_{suffix}"
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig2, "threshold": 2,
            "custodian_ids": ["cus_demo_bob", "cus_demo_carol", dave["custodian_id"]],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        mig_secret = b"cross-policy-migration-master-secret-0123"
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_mig, "expected_version": 1,
                                    "secret_hex": mig_secret.hex()})
        assert r.status_code == 201, r.text
        mig_custody = r.json()
        check("migration source custody created",
              mig_custody["shard_count"] == 3, r.text)
        mig_cid = mig_custody["custody_id"]
        idem1 = f"mig-idem-{suffix}"
        mig_start = {
            "source_custody_id": mig_cid,
            "target_policy_id": pol_mig2, "target_version": 1,
        }

        # 缺少幂等键 -> BAD_REQUEST
        await expect_error(tenant, "migration without idempotency key", "POST",
                           "/migrations", "BAD_REQUEST", json=mig_start)

        # 创建迁移会话：绑定源/目标版本摘要
        r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": idem1},
                              json=mig_start)
        m1 = body_of(r)
        check("migration session created (201)",
              r.status_code == 201 and m1["status"] == "open" and m1["threshold"] == 2
              and len(m1["source_digest"]) == 64 and len(m1["target_digest"]) == 64,
              r.text)
        mig_id = m1["migration_id"]

        # 同一幂等键重放 -> 200 + 同一会话，不新建
        r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": idem1},
                              json=mig_start)
        check("migration create idempotent replay -> 200 same id",
              r.status_code == 200 and body_of(r)["migration_id"] == mig_id, r.text)

        # 同一幂等键但参数不同 -> IDEMPOTENCY_CONFLICT
        r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": idem1},
                              json={"source_custody_id": mig_cid,
                                    "target_policy_id": pol_mig, "target_version": 1})
        check("same idempotency key different request rejected",
              r.status_code == 409 and body_of(r)["error"]["code"] == "IDEMPOTENCY_CONFLICT",
              r.text)

        # 不同幂等键迁移同一 custody -> MIGRATION_CONFLICT（不得重复迁移）
        r = await tenant.call("POST", "/migrations",
                              headers={"Idempotency-Key": f"mig-other-{suffix}"},
                              json=mig_start)
        check("different idempotency key same custody rejected",
              r.status_code == 409 and body_of(r)["error"]["code"] == "MIGRATION_CONFLICT",
              r.text)

        # 目标=源同一版本 / 不存在版本 -> MIGRATION_TARGET_INVALID
        await expect_error(tenant, "migration target identical to source", "POST",
                           "/migrations", "MIGRATION_TARGET_INVALID",
                           headers={"Idempotency-Key": f"self-{suffix}"},
                           json={"source_custody_id": mig_cid,
                                 "target_policy_id": pol_mig, "target_version": 1})
        await expect_error(tenant, "migration missing target version", "POST",
                           "/migrations", "MIGRATION_TARGET_INVALID",
                           headers={"Idempotency-Key": f"missing-{suffix}"},
                           json={"source_custody_id": mig_cid,
                                 "target_policy_id": pol_mig2, "target_version": 42})

        # 跨租户：第二个租户不能操作该 custody，也不能把 custody 迁到自己的策略
        r = await admin.call("POST", "/admin/tenants", json={"name": f"migration-tenant-{suffix}"})
        check("admin registers migration tenant", r.status_code == 201, r.text)
        other_tenant = Client("migration-tenant", r.json()["api_key"])
        await expect_error(other_tenant, "cross-tenant migration custody", "POST",
                           "/migrations", "FORBIDDEN",
                           headers={"Idempotency-Key": f"xt-{suffix}"}, json=mig_start)
        r = await other_tenant.call("POST", "/policies", json={
            "policy_id": f"pol_other_{suffix}", "threshold": 1,
            "custodian_ids": ["cus_demo_bob"], "epoch": epoch})
        check("other tenant creates own policy", r.status_code == 201, r.text)
        await expect_error(tenant, "migration to other tenant's policy", "POST",
                           "/migrations", "FORBIDDEN",
                           headers={"Idempotency-Key": f"xt2-{suffix}"},
                           json={"source_custody_id": mig_cid,
                                 "target_policy_id": f"pol_other_{suffix}", "target_version": 1})
        await expect_error(other_tenant, "cross-tenant GET migration", "GET",
                           f"/migrations/{mig_id}", "FORBIDDEN")
        await other_tenant.close()

        # 撤销/过期目标策略拒绝（另一组 custody 避免干扰主迁移）
        pol_mx = f"pol_mx_{suffix}"; pol_mr = f"pol_mr_{suffix}"; pol_me = f"pol_me_{suffix}"
        for pid, thr, cids_x in (
            (pol_mx, 2, ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"]),
            (pol_mr, 2, ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"]),
        ):
            r = await tenant.call("POST", "/policies", json={
                "policy_id": pid, "threshold": thr, "custodian_ids": cids_x, "epoch": epoch})
            assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_me, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2020-01-01T00:00:00Z",
                      "valid_until": "2020-02-01T00:00:00Z", "rotation_interval": 0}})
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_mx, "expected_version": 1,
                                    "secret_hex": mig_secret.hex()})
        mx_cid = r.json()["custody_id"]
        await expect_error(tenant, "migration to expired epoch", "POST", "/migrations",
                           "MIGRATION_TARGET_INVALID",
                           headers={"Idempotency-Key": f"me-{suffix}"},
                           json={"source_custody_id": mx_cid,
                                 "target_policy_id": pol_me, "target_version": 1})
        # 撤销目标头版本（rotate 使 v1 revoked）
        r = await tenant.call("POST", f"/policies/{pol_mr}/rotate",
                              json={"expected_version": 1, "epoch": new_epoch})
        assert r.status_code == 200, r.text
        await expect_error(tenant, "migration to revoked version", "POST", "/migrations",
                           "MIGRATION_TARGET_INVALID",
                           headers={"Idempotency-Key": f"mr-{suffix}"},
                           json={"source_custody_id": mx_cid,
                                 "target_policy_id": pol_mr, "target_version": 1})

        # --- 托管人 nonce → claim → sign → submit（源 2-of-3） --------------
        async def mig_prep(cname: str, mid: str) -> dict:
            n = (await cuds[cname].call("POST", "/migrations/nonces",
                                        json={"migration_id": mid})).json()
            cl = await cuds[cname].call("POST", "/migrations/shards/claim",
                                        json={"migration_id": mid, "nonce": n["nonce"]})
            c = cl.json()
            return {"nonce": n["nonce"], "claim": c,
                    "signature": sign(ckeys[cname]["signing_private_key"], c["signing_message"])}

        # 非源策略成员（dave 只在目标策略）拿不到 nonce -> CROSS_POLICY_SHARE
        await expect_error(cuds["dave"], "target-only custodian nonce on source migration",
                           "POST", "/migrations/nonces", "CROSS_POLICY_SHARE",
                           json={"migration_id": mig_id})

        pa = await mig_prep("alice", mig_id)
        check("migration nonce binds source/target digests",
              f"source_digest={m1['source_digest']}" in pa["claim"]["signing_message"]
              and f"target_digest={m1['target_digest']}" in pa["claim"]["signing_message"]
              and "keyvault.migration.v1" in pa["claim"]["signing_message"]
              and f"migration={mig_id}" in pa["claim"]["signing_message"])
        check("migration claim response contains source shard only",
              mig_secret.hex() not in pa["claim"]["shard_hex"])

        # 验签失败不花费 nonce
        await expect_error(cuds["alice"], "migration bad signature", "POST",
                           "/migrations/shares", "BAD_SIGNATURE", json={
                               "migration_id": mig_id, "nonce": pa["nonce"],
                               "point_x": pa["claim"]["point_x"],
                               "shard_hex": pa["claim"]["shard_hex"], "signature": "00" * 64})
        # 篡改分片 -> SHARE_DIGEST_MISMATCH（不花费 nonce）
        tampered_blob = bytearray(bytes.fromhex(pa["claim"]["shard_hex"]))
        tampered_blob[0] ^= 0x01
        await expect_error(cuds["alice"], "migration tampered shard", "POST",
                           "/migrations/shares", "SHARE_DIGEST_MISMATCH", json={
                               "migration_id": mig_id, "nonce": pa["nonce"],
                               "point_x": pa["claim"]["point_x"],
                               "shard_hex": tampered_blob.hex(),
                               "signature": "00" * 64})
        # 正确提交 alice（1/2）
        r = await cuds["alice"].call("POST", "/migrations/shares", json={
            "migration_id": mig_id, "nonce": pa["nonce"],
            "point_x": pa["claim"]["point_x"], "shard_hex": pa["claim"]["shard_hex"],
            "signature": pa["signature"]})
        check("migration alice share accepted (1/2), no new custody yet",
              r.status_code == 200 and body_of(r)["shares_received"] == 1
              and body_of(r)["completed"] is False
              and body_of(r)["new_custody_id"] is None, r.text)
        # nonce 一次性
        await expect_error(cuds["alice"], "migration nonce reuse", "POST",
                           "/migrations/shares", "NONCE_ALREADY_USED", json={
                               "migration_id": mig_id, "nonce": pa["nonce"],
                               "point_x": pa["claim"]["point_x"],
                               "shard_hex": pa["claim"]["shard_hex"],
                               "signature": pa["signature"]})
        # 重复提交
        await expect_error(cuds["alice"], "migration duplicate share", "POST",
                           "/migrations/nonces", "NONCE_ALREADY_USED",
                           json={"migration_id": mig_id})

        # 迁移进行中源策略被撤销：在途份额被拒（独立 custody）
        pol_live2 = f"pol_live2_{suffix}"; pol_live2t = f"pol_live2t_{suffix}"
        for pid in (pol_live2, pol_live2t):
            r = await tenant.call("POST", "/policies", json={
                "policy_id": pid, "threshold": 2,
                "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                "epoch": epoch})
            assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_live2, "expected_version": 1,
                                    "secret_hex": "1234"})
        live2_cid = r.json()["custody_id"]
        r = await tenant.call("POST", "/migrations",
                              headers={"Idempotency-Key": f"live2-{suffix}"},
                              json={"source_custody_id": live2_cid,
                                    "target_policy_id": pol_live2t, "target_version": 1})
        live2_mid = body_of(r)["migration_id"]
        n_live = (await cuds["alice"].call("POST", "/migrations/nonces",
                                           json={"migration_id": live2_mid})).json()
        c_live = (await cuds["alice"].call("POST", "/migrations/shards/claim",
                                           json={"migration_id": live2_mid,
                                                 "nonce": n_live["nonce"]})).json()
        r = await tenant.call("POST", f"/policies/{pol_live2}/rotate",
                              json={"expected_version": 1, "epoch": new_epoch})
        check("rotate source policy mid-migration", r.status_code == 200, r.text)
        await expect_error(cuds["alice"], "migration share after source revoke", "POST",
                           "/migrations/shares", "EPOCH_REVOKED", json={
                               "migration_id": live2_mid, "nonce": n_live["nonce"],
                               "point_x": c_live["point_x"],
                               "shard_hex": c_live["shard_hex"],
                               "signature": sign(ckeys["alice"]["signing_private_key"],
                                                 c_live["signing_message"])})
        # 已轮换（rotated）的 custody 不能再发起迁移 -> MIGRATION_SOURCE_INVALID
        await expect_error(tenant, "migration from rotated custody", "POST", "/migrations",
                           "MIGRATION_SOURCE_INVALID",
                           headers={"Idempotency-Key": f"live2b-{suffix}"},
                           json={"source_custody_id": live2_cid,
                                 "target_policy_id": pol_live2t, "target_version": 1})

        # bob 补足源门限 -> 内存重组 + 按目标策略重新分片，同事务写入新托管记录
        pb = await mig_prep("bob", mig_id)
        r = await cuds["bob"].call("POST", "/migrations/shares", json={
            "migration_id": mig_id, "nonce": pb["nonce"],
            "point_x": pb["claim"]["point_x"], "shard_hex": pb["claim"]["shard_hex"],
            "signature": pb["signature"]})
        mc = body_of(r)
        check("migration threshold reached -> new custody in same response",
              r.status_code == 200 and mc["completed"] and mc["new_custody_id"]
              and mc["new_shard_count"] == 3
              and len(mc["new_shard_digests"]) == 3, r.text)
        check("migration response leaks no plaintext",
              mig_secret.hex() not in r.text and pb["claim"]["shard_hex"] not in r.text)
        new_cid = mc["new_custody_id"]

        # 完成后操作 -> MIGRATION_COMPLETED
        await expect_error(cuds["carol"], "nonce on completed migration", "POST",
                           "/migrations/nonces", "MIGRATION_COMPLETED",
                           json={"migration_id": mig_id})

        # 幂等键重放完成态 -> 200 + 同一新 custody；不同键仍被拒
        r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": idem1},
                              json=mig_start)
        check("replay completed migration returns same new custody",
              r.status_code == 200 and body_of(r)["status"] == "completed"
              and body_of(r)["new_custody_id"] == new_cid, r.text)
        await expect_error(tenant, "re-migrate with new key rejected", "POST",
                           "/migrations", "MIGRATION_CONFLICT",
                           headers={"Idempotency-Key": f"mig-again-{suffix}"}, json=mig_start)

        # GET 迁移会话状态
        r = await tenant.call("GET", f"/migrations/{mig_id}")
        check("GET migration completed with new custody",
              r.status_code == 200 and body_of(r)["new_custody_id"] == new_cid
              and body_of(r)["shares_received"] == 2, r.text)

        # 源记录保持 active、仍绑定旧策略版本；新记录绑定目标策略
        r = await tenant.call("GET", f"/migrations/{mig_id}")
        check("source custody untouched (metadata view)",
              body_of(r)["source_policy_id"] == pol_mig
              and body_of(r)["source_version"] == 1)

        # 新托管记录可按目标策略（bob/carol/dave 2-of-3）正常门限恢复出原秘密
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": new_cid,
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        rec_m = r.json()
        check("recovery session on migrated custody", r.status_code == 201, r.text)
        recovered_ok = False
        first_two = {}
        for cname in ("bob", "carol"):
            n = (await cuds[cname].call("POST", "/recoveries/nonces",
                                        json={"session_id": rec_m["session_id"]})).json()["nonce"]
            cl = (await cuds[cname].call("POST", "/recoveries/shards/claim",
                                         json={"session_id": rec_m["session_id"],
                                               "nonce": n})).json()
            sg = sign(ckeys[cname]["signing_private_key"], cl["signing_message"])
            first_two[cname] = (n, cl, sg)
        last_r = None
        for cname, (n, cl, sg) in first_two.items():
            last_r = await cuds[cname].call("POST", "/recoveries/shares", json={
                "session_id": rec_m["session_id"], "nonce": n, "point_x": cl["point_x"],
                "shard_hex": cl["shard_hex"], "signature": sg})
        mb = body_of(last_r)
        check("target-policy recovery completes on migrated custody",
              last_r.status_code == 200 and mb.get("completed") and mb.get("wrap"), last_r.text)
        if mb.get("wrap"):
            try:
                recovered_ok = unwrap(wrap_priv, mb["wrap"], mb["aad"]) == mig_secret
            except Exception as exc:  # noqa: BLE001
                check("migrated custody unwraps to original secret", False, repr(exc))
        check("migrated custody unwraps to original secret", recovered_ok)

        # 审计：迁移动作入链、链完整、无任何明文（响应与库均不存）
        r = await tenant.call("GET", "/audit/replay")
        mchain = r.json()
        check("audit chain valid after migrations", mchain.get("valid") is True,
              json.dumps(mchain)[:300])
        mraw = json.dumps(mchain)
        check("audit leaks no migration secret/shards",
              mig_secret.hex() not in mraw
              and pa["claim"]["shard_hex"] not in mraw
              and pb["claim"]["shard_hex"] not in mraw)
        mactions = {e["action"] for e in mchain["entries"]}
        expect_mig_actions = {
            "migration.start", "migration.nonce.issue", "migration.shard.claim",
            "migration.share.submit", "migration.complete",
        }
        check("audit covers migration lifecycle",
              expect_mig_actions.issubset(mactions),
              str(sorted(expect_mig_actions - mactions)))

        # 存储层终检：迁移相关表里绝不能出现明文秘密、分片字节或未哈希 nonce。
        # 直连数据库（Docker 内 DSN 为环境变量；本地默认走同一 PostgreSQL）。
        try:
            import asyncpg

            dsn = os.environ.get("KEYVAULT_DATABASE_URL", "postgresql://keyvault@db:5432/keyvault")
            try:
                conn = await asyncpg.connect(dsn)
            except Exception:
                # 本地无 TCP（仅 unix socket）时的回退
                conn = await asyncpg.connect(host="/tmp", user="keyvault", database="keyvault")
            try:
                secret_present = await conn.fetchval(
                    "SELECT count(*) FROM audit_log WHERE basis::text LIKE '%' || $1 || '%'",
                    mig_secret.hex(),
                )
                check("db: secret hex absent from audit basis", secret_present == 0,
                      str(secret_present))
                blob_leak = 0
                for label, shard_hex in (("alice", pa["claim"]["shard_hex"]),
                                         ("bob", pb["claim"]["shard_hex"])):
                    n_hit = await conn.fetchval(
                        "SELECT count(*) FROM migration_share_submissions WHERE shard_digest = $1",
                        shard_hex,  # 若存了明文，会等于 hex 串；正常只存 sha256 摘要
                    )
                    blob_leak += n_hit
                check("db: migration submissions store digests not shard bytes", blob_leak == 0)
                # 迁移表只存 idempotency/nonce 的 sha256 摘要（64 hex），无明文键
                raw_keys = await conn.fetchval(
                    "SELECT count(*) FROM migration_sessions WHERE idempotency_key_hash = $1",
                    idem1,
                )
                check("db: idempotency key stored as digest only", raw_keys == 0)
                nonce_plain = await conn.fetchval(
                    "SELECT count(*) FROM migration_nonces WHERE nonce_hash = $1",
                    pa["nonce"],
                )
                check("db: migration nonce stored as digest only", nonce_plain == 0)
            finally:
                await conn.close()
        except Exception as exc:  # noqa: BLE001
            check("db: migration tables contain no plaintext", False, repr(exc))

        # ==================================================================
        # 托管记录谱系逻辑销毁（v1.6）
        # ==================================================================
        # 构造一条“已完成迁移链”：c0 --migrate--> c1 --migrate--> c2，
        # 销毁根 c0 必须沿迁移关系覆盖 c0/c1/c2 全部三代；同时在 c1 上挂一个
        # 在途恢复会话、在 c2 上挂一个在途迁移会话，验证同事务阻断。
        dpol0 = f"pol_d0_{suffix}"
        dpol1 = f"pol_d1_{suffix}"
        dpol2 = f"pol_d2_{suffix}"
        dpol3 = f"pol_d3_{suffix}"
        for pid in (dpol0, dpol1, dpol2, dpol3):
            r = await tenant.call("POST", "/policies", json={
                "policy_id": pid, "threshold": 2,
                "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                "epoch": epoch})
            assert r.status_code == 201, r.text

        async def full_migrate(src_cid: str, tgt_pol: str, idem: str) -> str:
            r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": idem},
                                  json={"source_custody_id": src_cid,
                                        "target_policy_id": tgt_pol, "target_version": 1})
            assert r.status_code == 201, r.text
            mid = body_of(r)["migration_id"]
            for cname in ("alice", "bob"):
                prepped = await mig_prep(cname, mid)
                rr = await cuds[cname].call("POST", "/migrations/shares", json={
                    "migration_id": mid, "nonce": prepped["nonce"],
                    "point_x": prepped["claim"]["point_x"],
                    "shard_hex": prepped["claim"]["shard_hex"],
                    "signature": prepped["signature"]})
                assert rr.status_code == 200, rr.text
            return body_of(rr)["new_custody_id"]

        destroy_secret = b"lineage-destruction-secret-0123456789"
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": dpol0, "expected_version": 1,
                                    "secret_hex": destroy_secret.hex()})
        c0 = r.json()["custody_id"]
        c1 = await full_migrate(c0, dpol1, f"d-hop1-{suffix}")
        c2 = await full_migrate(c1, dpol2, f"d-hop2-{suffix}")
        lineage = {c0, c1, c2}

        # 在途恢复（c1）与在途迁移（c2 -> dpol3）
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": c1, "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        d_rec = r.json()
        assert r.status_code == 201, r.text
        d_nonce = (await cuds["alice"].call("POST", "/recoveries/nonces",
                                            json={"session_id": d_rec["session_id"]})).json()["nonce"]
        d_claim = (await claim("alice", d_rec["session_id"], d_nonce)).json()
        r = await tenant.call("POST", "/migrations", headers={"Idempotency-Key": f"d-open-{suffix}"},
                              json={"source_custody_id": c2, "target_policy_id": dpol3,
                                    "target_version": 1})
        d_mig = body_of(r)["migration_id"]
        assert r.status_code == 201, r.text

        # 缺少幂等键 -> BAD_REQUEST
        await expect_error(tenant, "destruction without idempotency key", "POST",
                           "/destructions", "BAD_REQUEST", json={"root_custody_id": c0})

        # 跨租户销毁 -> FORBIDDEN（独立租户）
        r = await admin.call("POST", "/admin/tenants", json={"name": f"dest-tenant-{suffix}"})
        check("admin registers destruction tenant", r.status_code == 201, r.text)
        dest_other = Client("dest-tenant", r.json()["api_key"])
        await expect_error(dest_other, "cross-tenant destruction", "POST", "/destructions",
                           "FORBIDDEN", headers={"Idempotency-Key": f"d-xt-{suffix}"},
                           json={"root_custody_id": c0})

        # 执行谱系销毁
        idem_d = f"destroy-{suffix}"
        r = await tenant.call("POST", "/destructions", headers={"Idempotency-Key": idem_d},
                              json={"root_custody_id": c0})
        rcpt = body_of(r)
        check("destruction 201 receipt covers 3-generation lineage",
              r.status_code == 201 and rcpt["custody_count"] == 3
              and set(rcpt["custody_ids"]) == lineage
              and rcpt["shards_deleted"] == 9
              and rcpt["recovery_blocked"] == 1 and rcpt["migration_blocked"] == 1
              and rcpt["scope"] == "online_service_data_only", r.text)
        check("destruction response leaks no secret",
              destroy_secret.hex() not in r.text)
        des_id = rcpt["destruction_id"]

        # 同键重试 -> 200 同一回执
        r = await tenant.call("POST", "/destructions", headers={"Idempotency-Key": idem_d},
                              json={"root_custody_id": c0})
        check("destruction idempotent replay -> 200 same receipt",
              r.status_code == 200 and body_of(r)["destruction_id"] == des_id
              and body_of(r)["custody_ids"] == rcpt["custody_ids"], r.text)
        # GET 销毁回执
        r = await tenant.call("GET", f"/destructions/{des_id}")
        check("GET destruction receipt by id",
              r.status_code == 200 and body_of(r)["destruction_id"] == des_id
              and body_of(r)["shards_deleted"] == 9, r.text)
        await expect_error(dest_other, "cross-tenant GET receipt", "GET",
                           f"/destructions/{des_id}", "FORBIDDEN")

        # 同键不同根 -> IDEMPOTENCY_CONFLICT
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": dpol3, "expected_version": 1, "secret_hex": "ab"})
        d_extra = r.json()["custody_id"]
        await expect_error(tenant, "destruction same key different root", "POST",
                           "/destructions", "IDEMPOTENCY_CONFLICT",
                           headers={"Idempotency-Key": idem_d},
                           json={"root_custody_id": d_extra})
        # 不同键对已毁根再销毁：零增量回执（幂等收敛，不报错）
        r = await tenant.call("POST", "/destructions",
                              headers={"Idempotency-Key": f"destroy-again-{suffix}"},
                              json={"root_custody_id": c0})
        ra = body_of(r)
        check("re-destroy destroyed root with new key -> zero-effect receipt",
              r.status_code == 201 and ra["shards_deleted"] == 0
              and ra["custody_count"] == 3 and ra["recovery_blocked"] == 0, r.text)

        # 在途恢复/迁移已被阻断：旧会话一切操作 -> CUSTODY_DESTROYED(410)
        for cname, method, path, payload in (
            ("alice", "POST", "/recoveries/shares", {
                "session_id": d_rec["session_id"], "nonce": d_nonce,
                "point_x": d_claim["point_x"], "shard_hex": d_claim["shard_hex"],
                "signature": sign(ckeys["alice"]["signing_private_key"], d_claim["signing_message"])}),
            ("bob", "POST", "/recoveries/nonces", {"session_id": d_rec["session_id"]}),
            ("bob", "POST", "/migrations/nonces", {"migration_id": d_mig}),
        ):
            rr = await cuds[cname].call(method, path, json=payload)
            check(f"{path} on destroyed lineage -> CUSTODY_DESTROYED",
                  rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED",
                  rr.text[:200])
        r = await tenant.call("GET", f"/recoveries/{d_rec['session_id']}")
        check("destroyed recovery session shows destroyed status",
              body_of(r).get("status") == "destroyed", r.text)
        r = await tenant.call("GET", f"/migrations/{d_mig}")
        check("destroyed migration session shows destroyed status",
              body_of(r).get("status") == "destroyed", r.text)
        # 销毁后不得新建恢复/迁移
        await expect_error(tenant, "recovery on destroyed custody", "POST", "/recoveries",
                           "CUSTODY_DESTROYED",
                           json={"custody_id": c2, "request_digest": request_digest,
                                 "recovery_public_key": wrap_pub})
        await expect_error(tenant, "migration on destroyed custody", "POST", "/migrations",
                           "CUSTODY_DESTROYED",
                           headers={"Idempotency-Key": f"d-m-{suffix}"},
                           json={"source_custody_id": c1, "target_policy_id": dpol3,
                                 "target_version": 1})
        # 存储层：在线分片密文已删除，墓碑保留（无秘密）
        try:
            import asyncpg

            dsn = os.environ.get("KEYVAULT_DATABASE_URL", "postgresql://keyvault@db:5432/keyvault")
            try:
                conn = await asyncpg.connect(dsn)
            except Exception:
                conn = await asyncpg.connect(host="/tmp", user="keyvault", database="keyvault")
            try:
                n_shards = await conn.fetchval(
                    "SELECT count(*) FROM shards WHERE custody_id = ANY($1::text[])",
                    list(lineage))
                check("db: online encrypted shards deleted for full lineage", n_shards == 0,
                      str(n_shards))
                n_tomb = await conn.fetchval(
                    "SELECT count(*) FROM key_custodies WHERE id = ANY($1::text[]) "
                    "AND status='destroyed' AND destroyed_at IS NOT NULL", list(lineage))
                check("db: secret-free tombstones retained", n_tomb == 3, str(n_tomb))
                n_receipt = await conn.fetchval(
                    "SELECT count(*) FROM destructions WHERE id=$1 AND custody_count=3", des_id)
                check("db: destruction receipt persisted", n_receipt == 1, str(n_receipt))
            finally:
                await conn.close()
        except Exception as exc:  # noqa: BLE001
            check("db: destruction storage assertions", False, repr(exc))

        # --- 审计哈希链重放 -------------------------------------------------
        r = await tenant.call("GET", "/audit/replay")
        chain = r.json()
        check("audit chain replay valid", chain.get("valid") is True, json.dumps(chain)[:300])
        raw = json.dumps(chain)
        check("audit log leaks no secret", secret_hex not in raw and secret.decode() not in raw)
        # 已领取分片明文绝不进审计
        check("audit log leaks no claimed shard", c_alice["shard_hex"] not in raw)
        actions = {e["action"] for e in chain["entries"]}
        expect_actions = {
            "policy.create", "policy.rotate", "policy.epoch.revoke",
            "custody.create", "recovery.start", "recovery.nonce.issue",
            "recovery.shard.claim", "recovery.share.submit",
            "migration.start", "migration.nonce.issue", "migration.shard.claim",
            "migration.share.submit", "migration.complete",
            "destruction.complete",
        }
        check("audit covers key lifecycle actions", expect_actions.issubset(actions),
              str(sorted(expect_actions - actions)))

        # admin 注册新身份可用（名字带唯一后缀，可重复运行）
        r = await admin.call("POST", "/admin/tenants", json={"name": f"second-tenant-{suffix}"})
        check("admin can register tenant", r.status_code == 201 and r.json()["api_key"].startswith("tsec_"),
              r.text)
    finally:
        await tenant.close()
        for c in cuds.values():
            await c.close()
        await admin.close()
        try:
            await dest_other.close()
        except Exception:  # noqa: BLE001
            pass

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
