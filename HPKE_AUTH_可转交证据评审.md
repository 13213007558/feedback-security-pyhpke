# HPKE Auth 解密记录能否作为可转交证据 —— 接口设计评审说明

## 结论（TL;DR）

**不能。** HPKE Auth 模式的 `open()` 成功，只向**持有接收者私钥 `skR` 的一方**证明"消息来自持有 `skS` 的一方"。
这是一种**指定验证者（designated-verifier）认证**，性质接近 MAC，而非数字签名。
把 Auth 解密成功的记录移交第三方，不构成"消息一定由指定发送者发出"的证据，
因为**合法接收者自己就能伪造出同样验证通过的记录**（本仓库 `examples/hpke_auth_not_signature.py` 场景 3 可复现）。

## 1. 各方持有的材料

| 材料 | 外部攻击者 | 第三方审计 | 合法接收者 | 发送者 |
|---|---|---|---|---|
| `pkS`, `pkR`, `enc`, `ct`, `info`, `aad` | ✔ | ✔ | ✔ | ✔ |
| `skR`（接收者私钥） | ✘ | ✘ | ✔ | ✘ |
| `skS`（发送者私钥） | ✘ | ✘ | ✘ | ✔ |
| `shared_secret` / AEAD `key`（派生对称秘密） | ✘ | 仅当被事后移交 | ✔（可自行算出） | ✔ |

关键事实：`shared_secret` 是**对称**秘密，发送者与接收者双方都能独立算出，没有任何一方独占。

## 2. DHKEM 实现分析（PyHPKE）

Auth 模式的封装/解封在 `src/pyhpke/kem.py`：

- 发送侧 `KEM.encap()`（kem.py:83-87）：
  `dh = DH(ek, pkR) || DH(skS, pkR)`，`kem_context = enc || pkR || pkS`
- 接收侧 `KEM.decap()`（kem.py:100-103）：
  `dh = DH(skR, enc) || DH(skR, pkS)`，`kem_context` 同上

由 DH 交换性，`DH(ek, pkR) = DH(skR, enc)`、`DH(skS, pkR) = DH(skR, pkS)`，
两侧得到**同一个** `shared_secret`（kem.py:58-61 `extract_and_expand`）。
随后 `CipherSuite._key_schedule()`（cipher_suite.py:133-153）把它派生成
AEAD `key` / `base_nonce` —— 全部是确定性的对称运算。

推论：
- **认证来源**：只有 `skS` 持有者能贡献 `DH(skS, pkR)`，所以接收者解密成功 ⇒ 确信对方持有 `skS`。这一保证**仅对接收者成立**。
- **可伪造性**：接收者用 `skR` 算出的 `shared_secret` 与发送者完全相同，因此可以重放 key schedule、用同一把 AEAD key 加密**任意明文**，产出与真实记录在密码学上不可区分的"发送者记录"。演示脚本场景 3 正是用 `suite.kem.decap(enc, skr, pks)` + 公开 KDF 构件完成伪造，并通过标准 `create_recipient_context(...).open()` 验证。
- **第三方盲区**：不持有 `skR`（或未被移交 `shared_secret`）的第三方连 AEAD tag 都无法验证；即使被移交 `shared_secret`，也无法区分记录作者（场景 4）。移交 `skR` 同样无效——`skR` 本来就是接收者持有的，反而进一步污染证据链。

## 3. Auth 与 Base 的区别

| | Base 模式 | Auth 模式 |
|---|---|---|
| 调用 | `create_sender_context(pkr)`（不传 `sks`） | `create_sender_context(pkr, sks=sks)` |
| KEM 输入 | `dh = DH(ek, pkR)` 一段 | `dh = DH(ek,pkR) ‖ DH(skS,pkR)` 两段 |
| `kem_context` | `enc ‖ pkR` | `enc ‖ pkR ‖ pkS` |
| 接收者获得 | 仅机密性 | 机密性 + **对本人**的来源认证 |
| 第三方获得 | 无 | **同样没有**可验证证据 |

Base 密文无法通过 Auth 上下文解密（`kem_context` 不同 ⇒ 派生密钥不同），见演示场景 2。

## 4. 要获得可转交证据，还缺少什么

HPKE（含 Auth 模式）在协议设计上就**不提供**该要素，需要在接口层补充：

1. **发送者独占的签名能力**：引入独立签名密钥（如 Ed25519），由发送者对
   `transcript = 域分离串 ‖ suite 标识 ‖ info ‖ aad ‖ enc ‖ ct` 签名，
   第三方用发送者签名公钥即可离线验证（演示场景 5）。
   签名密钥必须与 HPKE 的 `skS` **分离**，避免复用 KEM 私钥。
2. **上下文绑定**：签名必须覆盖 `info`/`aad`/`enc`，否则签名可被嫁接到其他密文或会话。
3. **新鲜性与抗重放**：`info`/`aad` 中携带消息 ID、时间戳或挑战值，并纳入签名。
4. **术语纪律**：接口与文档中不得把 Auth 模式的认证结果标注为
   "签名""公开可验证""不可否认"；建议命名为 `sender_authenticated`（对接收者而言）。

## 5. 结论到调用/协议步骤的映射

- `CipherSuite.create_sender_context(pkr, sks=sks)` / `create_recipient_context(enc, skr, pks=pks)`：
  提供的是**点对点对等认证**，任何一方都能算出同一把密钥 —— 不能作为归因证据输出。
- `KEM.decap(enc, skr, pks)`（kem.py:92）：接收者**自己**就能重算 `shared_secret`，
  这是"接收者可伪造仅对自己有效的记录"的根因，也是本评审的核心证据。
- 可转交证据的协议步骤应为：`seal` → 对 `(enc, ct, info, aad)` **签名** → 移交
  `(enc, ct, info, aad, signature, 发送者签名公钥)` → 第三方 `verify`。
  HPKE 记录本身只是被签名的对象，不是证据。

## 附：复现

```bash
.venv/bin/python examples/hpke_auth_not_signature.py
```

场景 1/2：Auth 正常收发、Base 对照；场景 3：接收者伪造记录并通过标准 `open`；
场景 4：第三方对真实/伪造记录均"验证通过"，无法归因；场景 5：Ed25519 签名提供真正的可转交证据。
