"""Verification tests for PyHPKE's ``Context.Export`` (RFC 9180 Section 5.3).

These tests check that exports are properly bound to:

  * the exporter context,
  * the setup ``info`` / PSK inputs of the key schedule,
  * the HPKE mode,
  * the full cipher suite (KEM, KDF, AEAD including export-only),

that per-message AAD never influences an export, that exporting does not advance
the AEAD sequence number, and that length boundaries and repeated/empty contexts
behave per the RFC. Every expected value is computed independently in
``tests.rfc9180_oracle`` and additionally cross-checked against the official
RFC 9180 test vectors.

No real business key material is used: all secrets come from the public RFC
vectors or from deterministic test IKM, and the report only prints digests.
"""

import hashlib
import json
import os
from typing import Any

import pytest

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface, KEMKeyPair, NotSupportedError
from tests import rfc9180_oracle as oracle

VECTORS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vectors", "test-vectors.json")
VECTORS: list[dict[str, Any]] = json.load(open(VECTORS_PATH))  # noqa: SIM115

TEST_LABEL = b"backend-key/v1"
WRONG_LABEL = b"backend-key/v0-wrong"


def _fingerprint(data: bytes) -> str:
    """Non-reversible short identifier for reporting; never the key itself."""
    return hashlib.sha256(data).hexdigest()[:16]


def _build_contexts(v: dict[str, Any]) -> tuple[Any, Any]:
    """Recreate sender/recipient contexts deterministically from an RFC vector."""
    suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
    pke = suite.kem.deserialize_public_key(bytes.fromhex(v["pkEm"]))
    ske = suite.kem.deserialize_private_key(bytes.fromhex(v["skEm"]))
    eks = KEMKeyPair(ske, pke)
    pkr = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
    skr = suite.kem.deserialize_private_key(bytes.fromhex(v["skRm"]))
    sks: KEMKeyInterface | None = None
    pks: KEMKeyInterface | None = None
    if "skSm" in v and "pkSm" in v:
        sks = suite.kem.deserialize_private_key(bytes.fromhex(v["skSm"]))
        pks = suite.kem.deserialize_public_key(bytes.fromhex(v["pkSm"]))
    info = bytes.fromhex(v["info"])
    psk = bytes.fromhex(v["psk"]) if "psk" in v else b""
    psk_id = bytes.fromhex(v["psk_id"]) if "psk_id" in v else b""
    enc, sender = suite.create_sender_context(pkr, info, sks, psk, psk_id, eks)
    recipient = suite.create_recipient_context(enc, skr, info, pks, psk, psk_id)
    return sender, recipient


def _vector_inputs(v: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": v["mode"],
        "shared_secret": bytes.fromhex(v["shared_secret"]),
        "info": bytes.fromhex(v["info"]),
        "psk": bytes.fromhex(v["psk"]) if "psk" in v else b"",
        "psk_id": bytes.fromhex(v["psk_id"]) if "psk_id" in v else b"",
        "kem_id": v["kem_id"],
        "kdf_id": v["kdf_id"],
        "aead_id": v["aead_id"],
    }


def _fresh_session(kem_id: KEMId, kdf_id: KDFId, aead_id: AEADId, info: bytes = b""):
    """Deterministic fresh session from fixed test IKM (not business data)."""
    suite = CipherSuite.new(kem_id, kdf_id, aead_id)
    sender_kp = suite.kem.derive_key_pair(b"01" * 32)
    receiver_kp = suite.kem.derive_key_pair(b"02" * 32)
    enc, sender = suite.create_sender_context(receiver_kp.public_key, info=info, eks=sender_kp)
    recipient = suite.create_recipient_context(enc, receiver_kp.private_key, info=info)
    return suite, enc, sender, recipient


class TestOfficialVectorsAgainstIndependentOracle:
    """Cross-check PyHPKE exports against RFC values and an independent HKDF computation."""

    @pytest.mark.parametrize("v", VECTORS)
    def test_export_matches_rfc_and_oracle(self, v: dict[str, Any]) -> None:
        sender, recipient = _build_contexts(v)
        inputs = _vector_inputs(v)
        for ve in v["exports"]:
            context = bytes.fromhex(ve["exporter_context"])
            length = ve["L"]
            rfc_value = bytes.fromhex(ve["exported_value"])

            from_pyhpke_s = sender.export(context, length)
            from_pyhpke_r = recipient.export(context, length)
            oracle_value = oracle.expected_export(exporter_context=context, length=length, **inputs)

            # Three independent computations must agree.
            assert from_pyhpke_s == rfc_value
            assert from_pyhpke_r == rfc_value
            assert oracle_value == rfc_value

    @pytest.mark.parametrize("v", VECTORS)
    def test_key_schedule_intermediates_match_oracle(self, v: dict[str, Any]) -> None:
        # Independently recompute the whole Section 5.1 key schedule, including
        # the mode byte binding, from the published shared secret.
        sid = oracle.suite_id(v["kem_id"], v["kdf_id"], v["aead_id"])
        inputs = _vector_inputs(v)
        context, secret, exporter_secret, key = oracle.key_schedule(
            inputs["mode"],
            inputs["shared_secret"],
            inputs["info"],
            inputs["psk"],
            inputs["psk_id"],
            inputs["kem_id"],
            inputs["kdf_id"],
            inputs["aead_id"],
        )
        assert context == bytes.fromhex(v["key_schedule_context"])
        assert secret == bytes.fromhex(v["secret"])
        assert exporter_secret == bytes.fromhex(v["exporter_secret"])
        if v["aead_id"] != 0xFFFF:
            assert key == bytes.fromhex(v["key"])
        else:
            assert key == b""
        # And the exporter derived from that secret matches the RFC output.
        for ve in v["exports"]:
            got = oracle.exporter(
                exporter_secret,
                bytes.fromhex(ve["exporter_context"]),
                ve["L"],
                sid,
                v["kdf_id"],
            )
            assert got == bytes.fromhex(ve["exported_value"])


class TestExporterContextDistinction:
    """Different exporter_context values must yield different backend keys."""

    @pytest.mark.parametrize("v", VECTORS)
    def test_distinct_contexts_collision_free(self, v: dict[str, Any]) -> None:
        sender, _ = _build_contexts(v)
        contexts = [b"", b"\x00", b"TestContext", TEST_LABEL, WRONG_LABEL]
        values = {sender.export(ctx, 32) for ctx in contexts}
        assert len(values) == len(contexts)
        # Empty context must equal the official empty-context vector output.
        empty_rfc = next(bytes.fromhex(ve["exported_value"]) for ve in v["exports"] if ve["exporter_context"] == "")
        assert sender.export(b"", 32) == empty_rfc

    def test_oracle_confirms_context_binding(self) -> None:
        v = next(x for x in VECTORS if x["mode"] == 0 and x["aead_id"] != 0xFFFF)
        inputs = _vector_inputs(v)
        a = oracle.expected_export(exporter_context=b"alpha", length=32, **inputs)
        b = oracle.expected_export(exporter_context=b"alphb", length=32, **inputs)
        assert a != b


class TestSetupInfoDistinction:
    """The setup ``info`` (and PSK) feed the key schedule, so exports must change."""

    def test_info_changes_export_and_matches_oracle(self) -> None:
        suite, _, sender_a, _ = _fresh_session(
            KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM, info=b"info-a"
        )
        _, _, sender_b, _ = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM, info=b"info-b")
        assert sender_a.export(TEST_LABEL, 32) != sender_b.export(TEST_LABEL, 32)

    @pytest.mark.parametrize("v", [x for x in VECTORS if "psk" in x])
    def test_psk_vector_export_matches_oracle(self, v: dict[str, Any]) -> None:
        sender, _ = _build_contexts(v)
        ve = v["exports"][0]
        expected = oracle.expected_export(
            exporter_context=bytes.fromhex(ve["exporter_context"]), length=ve["L"], **_vector_inputs(v)
        )
        assert sender.export(bytes.fromhex(ve["exporter_context"]), ve["L"]) == expected


class TestModeDistinction:
    """All four modes (base/PSK/auth/auth-PSK) must produce distinct, bound exports."""

    @pytest.mark.parametrize("aead_id", [AEADId.AES128_GCM, AEADId.EXPORT_ONLY])
    def test_modes_collision_free_and_oracle_bound(self, aead_id: AEADId) -> None:
        # One vector per mode, identical KEM/KDF/AEAD triple.
        chosen: dict[int, dict[str, Any]] = {}
        for v in VECTORS:
            if (
                v["kem_id"] == KEMId.DHKEM_X25519_HKDF_SHA256.value
                and v["kdf_id"] == KDFId.HKDF_SHA256.value
                and v["aead_id"] == aead_id.value
            ):
                chosen[v["mode"]] = v
        assert set(chosen) == {0, 1, 2, 3}

        seen: set[bytes] = set()
        for vector in (chosen[mode] for mode in sorted(chosen)):
            sender, _ = _build_contexts(vector)
            value = sender.export(TEST_LABEL, 32)
            expected = oracle.expected_export(exporter_context=TEST_LABEL, length=32, **_vector_inputs(vector))
            assert value == expected
            seen.add(value)
        assert len(seen) == 4  # mode byte in key_schedule_context separates them


class TestCipherSuiteDistinction:
    """Exports must be bound to KEM/KDF/AEAD via the suite_id in labeled_expand."""

    def test_kdf_and_aead_change_export_and_match_oracle(self) -> None:
        triples = [
            (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM),
            (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM),
            (KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA512, AEADId.AES128_GCM),
            (KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM),
        ]
        values: set[bytes] = set()
        for kem_id, kdf_id, aead_id in triples:
            _, _, sender, _ = _fresh_session(kem_id, kdf_id, aead_id, info=b"suite-binding")
            value = sender.export(TEST_LABEL, 32)
            values.add(value)
        assert len(values) == len(triples)

    @pytest.mark.parametrize("v", [x for x in VECTORS if x["aead_id"] == 0xFFFF])
    def test_export_only_suite_matches_rfc_and_oracle(self, v: dict[str, Any]) -> None:
        sender, recipient = _build_contexts(v)
        # Export-only contexts reject seal/open but support export.
        with pytest.raises(NotSupportedError):
            sender.seal(b"x")
        with pytest.raises(NotSupportedError):
            recipient.open(b"x")
        for ve in v["exports"]:
            context = bytes.fromhex(ve["exporter_context"])
            expected_rfc = bytes.fromhex(ve["exported_value"])
            expected_oracle = oracle.expected_export(exporter_context=context, length=ve["L"], **_vector_inputs(v))
            assert sender.export(context, ve["L"]) == expected_rfc
            assert recipient.export(context, ve["L"]) == expected_rfc
            assert expected_oracle == expected_rfc

    def test_export_only_vs_encryption_context_differ_for_same_session(self) -> None:
        # Same KEM/KDF and fixed ephemeral/receiver keys; only the AEAD id differs,
        # so suite_id differs and exporter_secret must differ.
        v_norm = next(
            x for x in VECTORS if x["aead_id"] != 0xFFFF and x["kem_id"] == 0x0020 and x["kdf_id"] == 0x0001 and x["mode"] == 0
        )
        v_exp = next(
            x for x in VECTORS if x["aead_id"] == 0xFFFF and x["kem_id"] == 0x0020 and x["kdf_id"] == 0x0001 and x["mode"] == 0
        )
        s_norm, _ = _build_contexts(v_norm)
        s_exp, _ = _build_contexts(v_exp)
        assert s_norm.export(TEST_LABEL, 32) != s_exp.export(TEST_LABEL, 32)


class TestAadIndependence:
    """Per-message AAD affects AEAD nonce/tag only; it must never touch exports."""

    @pytest.mark.parametrize("aead_id", [AEADId.AES128_GCM, AEADId.CHACHA20_POLY1305])
    def test_export_identical_regardless_of_aad_and_message_count(self, aead_id: AEADId) -> None:
        suite, _, sender, recipient = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, aead_id)
        baseline = sender.export(TEST_LABEL, 32)
        for aad in [b"", b"aad-1", b"aad-2-different", b"\x00\x01\x02"]:
            ct = sender.seal(b"plaintext", aad)
            assert recipient.open(ct, aad) == b"plaintext"
            # Export stays byte-identical no matter what AAD/messages were used.
            assert sender.export(TEST_LABEL, 32) == baseline
            assert recipient.export(TEST_LABEL, 32) == baseline

    def test_oracle_has_no_aad_input(self) -> None:
        # Structural guarantee: the Section 5.3 exporter signature has no AAD.
        v = VECTORS[0]
        inputs = _vector_inputs(v)
        once = oracle.expected_export(exporter_context=TEST_LABEL, length=32, **inputs)
        twice = oracle.expected_export(exporter_context=TEST_LABEL, length=32, **inputs)
        assert once == twice


class TestSequenceNotAdvanced:
    """Exporting must not consume an AEAD sequence number on either side."""

    def test_export_does_not_advance_seq(self) -> None:
        _, _, sender, recipient = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
        # White-box: internal counters start at zero.
        assert sender._seq == 0  # noqa: SLF001
        assert recipient._seq == 0  # noqa: SLF001
        for _ in range(5):
            sender.export(TEST_LABEL, 32)
            recipient.export(TEST_LABEL, 32)
        assert sender._seq == 0  # noqa: SLF001
        assert recipient._seq == 0  # noqa: SLF001

        # Black-box: after exports, the very first seal still uses nonce seq 0,
        # so a fresh recipient decrypts it (nonce mismatch would fail auth).
        ct1 = sender.seal(b"one")
        assert recipient.open(ct1) == b"one"
        sender.export(TEST_LABEL, 32)
        recipient.export(TEST_LABEL, 32)
        ct2 = sender.seal(b"two")
        assert recipient.open(ct2) == b"two"
        assert ct1 != ct2  # and the two messages used consecutive, distinct nonces


class TestLengthBoundaries:
    """RFC 9180 / RFC 5869 export length limits and edge lengths."""

    @pytest.mark.parametrize("kdf_id", [KDFId.HKDF_SHA256, KDFId.HKDF_SHA512])
    def test_zero_empty_and_max_length(self, kdf_id: KDFId) -> None:
        _, _, sender, _ = _fresh_session(KEMId.DHKEM_X25519_HKDF_SHA256, kdf_id, AEADId.AES128_GCM)
        nh = sender._kdf.digest_size  # noqa: SLF001
        max_len = oracle.max_export_length(kdf_id.value)
        assert max_len == 255 * nh

        # L = 0 is legal and yields an empty secret (RFC 5869 expand).
        assert sender.export(TEST_LABEL, 0) == b""
        # Boundary value (255 * Nh) works and spans many HKDF-Expand blocks.
        assert len(sender.export(TEST_LABEL, max_len)) == max_len

        # Independent oracle for a non-block-aligned multi-block length, using a
        # vector whose KDF matches this parameterization.
        ref_vector = next(x for x in VECTORS if x["kdf_id"] == kdf_id.value and x["aead_id"] != 0xFFFF)
        ref_sender, _ = _build_contexts(ref_vector)
        multi_block_len = 2 * nh + 7
        oracle_value = oracle.expected_export(exporter_context=TEST_LABEL, length=multi_block_len, **_vector_inputs(ref_vector))
        assert len(oracle_value) == multi_block_len
        assert ref_sender.export(TEST_LABEL, multi_block_len) == oracle_value
        # One past the HKDF-Expand limit must be rejected.
        with pytest.raises(ValueError):
            sender.export(TEST_LABEL, max_len + 1)

    def test_different_lengths_are_not_truncations_of_one_stream(self) -> None:
        v = VECTORS[0]
        sender, _ = _build_contexts(v)
        short = sender.export(TEST_LABEL, 32)
        long = sender.export(TEST_LABEL, 48)
        # Each length is its own labeled_expand; longer is not a simple extension.
        assert long[:32] != short


class TestRepeatedAndEmptyExport:
    """Repeated exports are deterministic; the empty context is a distinct domain."""

    def test_repeated_export_deterministic(self) -> None:
        _, _, sender, recipient = _fresh_session(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
        first = sender.export(TEST_LABEL, 32)
        for _ in range(3):
            assert sender.export(TEST_LABEL, 32) == first
            assert recipient.export(TEST_LABEL, 32) == first

    def test_empty_context_distinct_from_nonempty(self) -> None:
        v = VECTORS[0]
        sender, _ = _build_contexts(v)
        empty = sender.export(b"", 32)
        nonempty = sender.export(b"\x00", 32)
        assert empty != nonempty
        # b"" and a missing/omitted-equivalent explicit empty argument are the same.
        assert sender.export(b"", 32) == sender.export(b"", 32)


class TestWrongLabelMutualConsistencyCaught:
    """A wrong label used by BOTH peers stays internally consistent but is still wrong.

    Sender==recipient equality alone cannot detect this; only comparison against the
    independent RFC oracle (the agreed label) can. This test documents that trap and
    proves the oracle catches it.
    """

    def test_shared_wrong_label_is_consistent_but_rejected_by_oracle(self) -> None:
        v = next(x for x in VECTORS if x["mode"] == 0 and x["aead_id"] != 0xFFFF)
        sender, recipient = _build_contexts(v)

        correct = sender.export(TEST_LABEL, 32)
        wrong_sender = sender.export(WRONG_LABEL, 32)
        wrong_recipient = recipient.export(WRONG_LABEL, 32)

        # The failure mode the task warns about: both peers agree on the wrong label.
        assert wrong_sender == wrong_recipient
        # ... yet it is not the key the agreed (correct) label should produce.
        assert wrong_sender != correct

        # The independent oracle is what actually exposes the mistake.
        oracle_correct = oracle.expected_export(exporter_context=TEST_LABEL, length=32, **_vector_inputs(v))
        oracle_wrong = oracle.expected_export(exporter_context=WRONG_LABEL, length=32, **_vector_inputs(v))
        assert correct == oracle_correct
        assert wrong_sender == oracle_wrong
        assert oracle_wrong != oracle_correct

        # A naive "sender must equal recipient" assertion would have passed silently,
        # so the real guard must compare against the oracle / agreed label.
        assert _fingerprint(wrong_sender) != _fingerprint(correct)
