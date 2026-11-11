# -*- coding: utf-8 -*-
"""
HPKE Auth 模式能否替代数字签名？——可运行反例演示（基于本仓库 PyHPKE）

结论先行：不能。本脚本用 DHKEM(X25519, HKDF-SHA256) 展示：
  1. Auth 模式的 shared_secret = ExtractAndExpand(DH(enc,skR) || DH(pkS,skR), ...)，
     合法接收者仅凭自己的 skR 即可完整重算（见 src/pyhpke/kem.py 的 decap），
     因此接收者可以伪造任意"看似来自指定发送者"的密文记录；
  2. 第三方不持有 skR / shared_secret，连 AEAD tag 都无法验证；
     即使接收者交出 shared_secret，第三方也无法区分记录出自发送者还是接收者；
  3. 要获得可转交证据，必须引入只有发送者能产生的公开可验证对象（如 Ed25519 签名）。

运行：.venv/bin/python examples/hpke_auth_not_signature.py
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair
from pyhpke.consts import Mode
from pyhpke.kdf import KDF
from pyhpke.keys.aes_gcm_key import AESGCMKey

KEM_ID = KEMId.DHKEM_X25519_HKDF_SHA256
KDF_ID = KDFId.HKDF_SHA256
AEAD_ID = AEADId.AES128_GCM

INFO = b"settlement-msg/2026-11-11"
AAD = b"msg-id:0042"

# ---------------------------------------------------------------------------
# 测试密钥（确定性派生，便于复现；仅用于演示）
# ---------------------------------------------------------------------------
suite = CipherSuite.new(KEM_ID, KDF_ID, AEAD_ID)

skr_pair: KEMKeyPair = suite.kem.derive_key_pair(b"R" * 32)   # 接收者密钥对
sks_pair: KEMKeyPair = suite.kem.derive_key_pair(b"S" * 32)   # 发送者密钥对
skr, pkr = skr_pair.private_key, skr_pair.public_key
sks, pks = sks_pair.private_key, sks_pair.public_key

print("== 角色与持有材料 ==")
print("外部攻击者 : pkS, pkR, enc, ct, info, aad（无任何秘密）")
print("合法接收者 : 上述全部 + skR")
print("第三方审计 : 上述全部（+ 事后可能被'移交'的 shared_secret / key）")
print("发送者     : skS, pkR（以及自己生成的临时密钥 ek）")
print()


def show(tag: str, ok: bool):
    print(f"  [{'PASS' if ok else 'FAIL'}] {tag}")


# ---------------------------------------------------------------------------
# 场景 1：Auth 模式 —— 发送者正常加密，接收者正常解密
# ---------------------------------------------------------------------------
print("== 场景 1：Auth 模式正常收发 ==")
pt = b"pay 100 CNY to carol"
enc, ctx_s = suite.create_sender_context(pkr, info=INFO, sks=sks)
ct = ctx_s.seal(pt, aad=AAD)
ctx_r = suite.create_recipient_context(enc, skr, info=INFO, pks=pks)
opened = ctx_r.open(ct, aad=AAD)
show("接收者 open 成功且明文一致", opened == pt)
print(f"  enc = {enc.hex()}")
print(f"  ct  = {ct.hex()}")
print()

# ---------------------------------------------------------------------------
# 场景 2：Base 模式 —— 根本没有发送者认证
# ---------------------------------------------------------------------------
print("== 场景 2：Base 模式（对照） ==")
enc_b, ctx_sb = suite.create_sender_context(pkr, info=INFO)  # 不传 sks
ct_b = ctx_sb.seal(pt, aad=AAD)
ctx_rb = suite.create_recipient_context(enc_b, skr, info=INFO)  # 不传 pks
show("Base 模式可解密，但不绑定任何发送者身份", ctx_rb.open(ct_b, aad=AAD) == pt)
# Base 密文用 Auth 方式（带 pks）解密会失败，因为 kem_context 不同 -> 密钥不同
try:
    suite.create_recipient_context(enc_b, skr, info=INFO, pks=pks).open(ct_b, aad=AAD)
    show("Base 密文被误当作 Auth 解密", False)
except Exception:
    show("Base 密文无法通过 Auth 上下文解密（kem_context 不含 pkS）", True)
print()

# ---------------------------------------------------------------------------
# 场景 3：关键反例 —— 合法接收者伪造"发送者记录"
#   接收者只用 skR + 公开数据，重算 shared_secret 并加密任意伪造明文。
#   这复现的正是 kem.py decap 的第 100-103 行：
#       dh1 = DH(skR, enc); dh2 = DH(skR, pkS); dh = dh1 || dh2
# ---------------------------------------------------------------------------
print("== 场景 3：接收者伪造仅对自己有效的'发送者记录' ==")
shared_secret = suite.kem.decap(enc, skr, pks)  # 接收者自己就能算出 shared_secret

# 用与 CipherSuite._key_schedule 相同的公开构件重放 key schedule，
# 得到一个"发送者侧"上下文，对任意伪造明文加密。
suite_id = b"HPKE" + KEM_ID.value.to_bytes(2, "big") + KDF_ID.value.to_bytes(2, "big") + AEAD_ID.value.to_bytes(2, "big")
kdf = KDF(KDF_ID, suite_id)
psk_id_hash = kdf.labeled_extract(b"", b"psk_id_hash", b"")
info_hash = kdf.labeled_extract(b"", b"info_hash", INFO)
ks_ctx = bytes([Mode.AUTH.value]) + psk_id_hash + info_hash
secret = kdf.labeled_extract(shared_secret, b"secret", b"")
key = kdf.labeled_expand(secret, b"key", ks_ctx, suite.aead.key_size)
nonce = kdf.labeled_expand(secret, b"base_nonce", ks_ctx, suite.aead.nonce_size)

forged_pt = b"pay 1000000 CNY to attacker-controlled-account"
forged_ct = AESGCMKey(key, len(key)).seal(forged_pt, nonce, AAD)

# 这条"伪造记录" (enc, forged_ct) 用标准接收流程验证：通过。
ctx_verify = suite.create_recipient_context(enc, skr, info=INFO, pks=pks)
forged_opened = ctx_verify.open(forged_ct, aad=AAD)
show("伪造记录通过标准 Auth open 验证", forged_opened == forged_pt)
show("伪造明文 ≠ 真实明文（接收者写出了发送者从未发送的内容）", forged_opened != pt)
print(f"  forged_ct = {forged_ct.hex()}")
print()

# ---------------------------------------------------------------------------
# 场景 4：第三方视角 —— 即使移交 shared_secret 也无法归因
# ---------------------------------------------------------------------------
print("== 场景 4：第三方拿到 (enc, ct, forged_ct, shared_secret) 后 ==")
# 第三方能用 shared_secret 验证两条记录都"密码学有效"……
k_third = kdf.labeled_expand(secret, b"key", ks_ctx, suite.aead.key_size)
n_third = kdf.labeled_expand(secret, b"base_nonce", ks_ctx, suite.aead.nonce_size)
ok_real = AESGCMKey(k_third, len(k_third)).open(ct, n_third, AAD) == pt
ok_fake = AESGCMKey(k_third, len(k_third)).open(forged_ct, n_third, AAD) == forged_pt
show("真实记录对第三方'验证通过'", ok_real)
show("伪造记录对第三方同样'验证通过'", ok_fake)
print("  => 两条记录使用同一把对称 key；发送者（持 skS）与接收者（持 skR）")
print("     都能算出它。第三方无法区分作者 —— 认证是'指定验证者'性质，")
print("     不是公开可验证签名。")
print()

# ---------------------------------------------------------------------------
# 场景 5：可转交证据需要什么 —— 发送者对记录做 Ed25519 签名
# ---------------------------------------------------------------------------
print("== 场景 5：对照——真正的可转交证据 ==")
sig_sk = Ed25519PrivateKey.generate()
sig_pk: Ed25519PublicKey = sig_sk.public_key()
transcript = b"HPKE-RECORD" + enc + ct + INFO + AAD  # 绑定整条记录与上下文
sig = sig_sk.sign(transcript)
try:
    sig_pk.verify(sig, transcript)
    show("第三方用发送者签名公钥验证记录签名", True)
except Exception:
    show("第三方验证签名", False)
try:
    sig_pk.verify(sig, b"HPKE-RECORD" + enc + forged_ct + INFO + AAD)
    show("伪造记录上的签名验证", False)
except Exception:
    show("接收者无法为伪造记录产出签名（不持有签名私钥）", True)
print()
print("结论：HPKE Auth 的 open 成功只向接收者本人证明来源；")
print("可转交证据 = HPKE 记录 + 发送者签名密钥对 transcript 的签名。")
