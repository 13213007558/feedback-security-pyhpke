"""Human-readable verification report for PyHPKE ``Context.Export``.

Run with::

    .venv/bin/python -m tests.export_verification_report

The report prints PASS/FAIL findings and short SHA-256 fingerprints of derived
secrets only. It never prints a raw key, shared secret, exporter secret, or
exported value, so it is safe to share. All inputs come from the public RFC 9180
test vectors or fixed deterministic test IKM, never from business key material.
"""

import hashlib

from pyhpke import AEADId, KDFId, KEMId
from tests import rfc9180_oracle as oracle
from tests.test_export_verification import (
    TEST_LABEL,
    VECTORS,
    _build_contexts,
    _fresh_session,
    _vector_inputs,
)


def _fp(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    line = f"[{status}] {name}"
    if detail:
        line += f"  -- {detail}"
    print(line)
    return ok


def main() -> int:
    results: list[bool] = []
    print("=== PyHPKE Context.Export verification (RFC 9180 Sec. 5.3) ===")
    print(f"vectors loaded: {len(VECTORS)} (modes 0-3, 4 KEMs, 2 KDFs, 4 AEADs incl. export-only)")
    print("secrets shown only as sha256[:16] fingerprints; no raw key material is printed\n")

    # 1. RFC vectors vs independent oracle, across every mode and cipher suite.
    mismatch = 0
    export_only_checked = 0
    for v in VECTORS:
        sender, recipient = _build_contexts(v)
        inputs = _vector_inputs(v)
        for ve in v["exports"]:
            ctx = bytes.fromhex(ve["exporter_context"])
            rfc = bytes.fromhex(ve["exported_value"])
            got_s = sender.export(ctx, ve["L"])
            got_r = recipient.export(ctx, ve["L"])
            got_o = oracle.expected_export(exporter_context=ctx, length=ve["L"], **inputs)
            if not (got_s == got_r == got_o == rfc):
                mismatch += 1
            if v["aead_id"] == 0xFFFF:
                export_only_checked += 1
    results.append(
        _check(
            "RFC vectors == PyHPKE(sender/recipient) == independent HKDF oracle",
            mismatch == 0,
            f"{sum(len(v['exports']) for v in VECTORS)} export cases, {export_only_checked} export-only",
        )
    )

    # 2. exporter_context distinction.
    v0 = VECTORS[0]
    sender0, _ = _build_contexts(v0)
    ctx_values = {sender0.export(c, 32) for c in (b"", b"\x00", b"TestContext", TEST_LABEL)}
    results.append(_check("exporter_context is domain-separated", len(ctx_values) == 4))

    # 3. setup info distinction.
    _, _, sa, _ = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM, b"info-a")
    _, _, sb, _ = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM, b"info-b")
    results.append(_check("setup info changes export", sa.export(TEST_LABEL, 32) != sb.export(TEST_LABEL, 32)))

    # 4. mode distinction (one vector per mode, same KEM/KDF/AEAD).
    per_mode: dict[int, bytes] = {}
    for v in VECTORS:
        if v["kem_id"] == 0x0020 and v["kdf_id"] == 0x0001 and v["aead_id"] == 0x0001:
            s, _ = _build_contexts(v)
            per_mode[v["mode"]] = s.export(TEST_LABEL, 32)
    results.append(_check("mode (base/psk/auth/auth-psk) is bound into export", len(set(per_mode.values())) == 4))

    # 5. cipher suite distinction.
    suite_values = set()
    for kem_id, kdf_id, aead_id in [
        (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM),
        (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM),
        (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA512, AEADId.AES128_GCM),
        (KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM),
    ]:
        _, _, s, _ = _fresh_session(kem_id, kdf_id, aead_id, b"suite-binding")
        suite_values.add(s.export(TEST_LABEL, 32))
    results.append(_check("cipher suite (KEM/KDF/AEAD) is bound into export", len(suite_values) == 4))

    # 6a. AAD independence.
    _, _, snd, rcv = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    base = snd.export(TEST_LABEL, 32)
    aad_ok = True
    for aad in (b"", b"aad-x", b"aad-y"):
        ct = snd.seal(b"pt", aad)
        if rcv.open(ct, aad) != b"pt":
            aad_ok = False
        aad_ok &= snd.export(TEST_LABEL, 32) == base and rcv.export(TEST_LABEL, 32) == base
    results.append(_check("per-message AAD does not affect export", aad_ok, f"fp={_fp(base)}"))

    # 6b. Export must not advance the sequence; only seal/open increments it.
    _, _, seq_snd, seq_rcv = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    assert (seq_snd._seq, seq_rcv._seq) == (0, 0)  # noqa: SLF001
    for _ in range(4):
        seq_snd.export(TEST_LABEL, 32)
        seq_rcv.export(TEST_LABEL, 32)
    after_exports = (seq_snd._seq, seq_rcv._seq)  # noqa: SLF001
    ct = seq_snd.seal(b"pt")
    assert seq_rcv.open(ct) == b"pt"
    after_seal = (seq_snd._seq, seq_rcv._seq)  # noqa: SLF001
    results.append(
        _check(
            "export does not advance seal/open sequence (only seal/open does)",
            after_exports == (0, 0) and after_seal == (1, 1),
            f"after_exports={after_exports} after_seal={after_seal}",
        )
    )

    # 7. length boundaries.
    kdf_id = KDFId.HKDF_SHA256
    max_len = oracle.max_export_length(kdf_id.value)
    _, _, slen, _ = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, kdf_id, AEADId.AES128_GCM)
    zero_ok = slen.export(TEST_LABEL, 0) == b""
    max_ok = len(slen.export(TEST_LABEL, max_len)) == max_len
    try:
        slen.export(TEST_LABEL, max_len + 1)
        boundary_ok = False
    except ValueError:
        boundary_ok = True
    results.append(_check("export length boundaries (L=0, L=255*Nh, L=255*Nh+1 rejected)", zero_ok and max_ok and boundary_ok))

    # 8. repeated export deterministic + empty context distinct.
    repeat_ok = slen.export(TEST_LABEL, 32) == slen.export(TEST_LABEL, 32)
    empty_distinct = sender0.export(b"", 32) != sender0.export(b"\x00", 32)
    results.append(_check("repeated export is deterministic; empty context distinct", repeat_ok and empty_distinct))

    # 9. The mutual-wrong-label trap: sender==recipient is not enough.
    wt = next(x for x in VECTORS if x["mode"] == 0 and x["aead_id"] != 0xFFFF)
    ws, wr = _build_contexts(wt)
    correct = ws.export(TEST_LABEL, 32)
    wrong_s = ws.export(b"backend-key/v0-wrong", 32)
    wrong_r = wr.export(b"backend-key/v0-wrong", 32)
    oracle_correct = oracle.expected_export(exporter_context=TEST_LABEL, length=32, **_vector_inputs(wt))
    trap_demonstrated = wrong_s == wrong_r and wrong_s != correct and correct == oracle_correct
    results.append(
        _check(
            "mutual wrong-label stays peer-consistent but is caught by the oracle",
            trap_demonstrated,
            f"correct_fp={_fp(correct)} wrong_fp={_fp(wrong_s)}",
        )
    )

    print("\n=== SUMMARY ===")
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
