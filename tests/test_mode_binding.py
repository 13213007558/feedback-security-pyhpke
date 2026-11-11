import json
import os
from typing import Any

import pytest

from pyhpke import (
    AEADId,
    CipherSuite,
    InvalidModeError,
    KDFId,
    KEMId,
    KEMKeyInterface,
    KEMKeyPair,
    Mode,
)

VECTORS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vectors", "test-vectors.json")


def _load_vectors() -> list[dict[str, Any]]:
    with open(VECTORS_PATH) as f:  # noqa: PTH123, SIM115
        return json.load(f)  # type: ignore[no-any-return]


VECTORS = _load_vectors()
MODES = [Mode.BASE, Mode.PSK, Mode.AUTH, Mode.AUTH_PSK]


class _VectorFixture:
    """Keys and parameters parsed from one official RFC 9180 test vector."""

    def __init__(self, suite: CipherSuite, v: dict[str, Any]):
        pke = suite.kem.deserialize_public_key(bytes.fromhex(v["pkEm"]))
        ske = suite.kem.deserialize_private_key(bytes.fromhex(v["skEm"]))
        self.eks = KEMKeyPair(ske, pke)
        self.pkr: KEMKeyInterface = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
        self.skr: KEMKeyInterface = suite.kem.deserialize_private_key(bytes.fromhex(v["skRm"]))
        self.sks: KEMKeyInterface | None = None
        self.pks: KEMKeyInterface | None = None
        if "skSm" in v and "pkSm" in v:
            self.sks = suite.kem.deserialize_private_key(bytes.fromhex(v["skSm"]))
            self.pks = suite.kem.deserialize_public_key(bytes.fromhex(v["pkSm"]))
        self.info = bytes.fromhex(v["info"])
        self.psk = bytes.fromhex(v["psk"]) if "psk" in v else b""
        self.psk_id = bytes.fromhex(v["psk_id"]) if "psk_id" in v else b""


class TestStrictModeBindingWithVectors:
    """
    Mode binding proven with the RFC 9180 official test vectors.

    The strict entries reproduce the vector outputs only for the mode the
    vector belongs to, and reject the same parameters under every other mode.
    Outputs (enc, ciphertext, exported secrets) are compared against the vector
    values rather than checking the returned object's class.
    """

    @pytest.mark.parametrize("v", VECTORS)
    def test_matching_mode_reproduces_vector(self, v: dict[str, Any]) -> None:
        suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
        fx = _VectorFixture(suite, v)
        mode = Mode(v["mode"])

        enc, sender = suite.create_sender_context_strict(mode, fx.pkr, fx.info, fx.sks, fx.psk, fx.psk_id, fx.eks)
        assert enc == bytes.fromhex(v["enc"])

        recipient = suite.create_recipient_context_strict(mode, enc, fx.skr, fx.info, fx.pks, fx.psk, fx.psk_id)

        if v["aead_id"] != 0xFFFF:
            for ve in v["encryptions"]:
                pt = bytes.fromhex(ve["pt"])
                aad = bytes.fromhex(ve["aad"])
                sealed = sender.seal(pt, aad)
                assert sealed == bytes.fromhex(ve["ct"])
                assert recipient.open(sealed, aad) == pt
        else:
            for ve in v["exports"]:
                ec = bytes.fromhex(ve["exporter_context"]) if len(ve["exporter_context"]) > 0 else b""
                expected = bytes.fromhex(ve["exported_value"])
                assert sender.export(ec, ve["L"]) == expected
                assert recipient.export(ec, ve["L"]) == expected

    @pytest.mark.parametrize("v", VECTORS)
    @pytest.mark.parametrize("wrong_mode", MODES)
    def test_wrong_mode_is_rejected_sender(self, v: dict[str, Any], wrong_mode: Mode) -> None:
        suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
        fx = _VectorFixture(suite, v)
        actual_mode = Mode(v["mode"])
        if wrong_mode == actual_mode:
            return
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(wrong_mode, fx.pkr, fx.info, fx.sks, fx.psk, fx.psk_id, fx.eks)

    @pytest.mark.parametrize("v", VECTORS)
    @pytest.mark.parametrize("wrong_mode", MODES)
    def test_wrong_mode_is_rejected_recipient(self, v: dict[str, Any], wrong_mode: Mode) -> None:
        suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
        fx = _VectorFixture(suite, v)
        actual_mode = Mode(v["mode"])
        if wrong_mode == actual_mode:
            return
        enc = bytes.fromhex(v["enc"])
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(wrong_mode, enc, fx.skr, fx.info, fx.pks, fx.psk, fx.psk_id)


def _authpsk_suite_and_keys() -> tuple[CipherSuite, _VectorFixture]:
    v = next(x for x in VECTORS if x["mode"] == Mode.AUTH_PSK.value)
    suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
    return suite, _VectorFixture(suite, v)


@pytest.fixture(scope="module")
def authpsk_suite_and_keys() -> tuple[CipherSuite, _VectorFixture]:
    return _authpsk_suite_and_keys()


class TestNegativeParameterMatrix:
    """
    Negative matrix over the two boolean mode dimensions defined by RFC 9180:
    PSK present/absent and static authentication key present/absent.
    """

    @pytest.mark.parametrize(
        "mode, use_psk, use_auth",
        [
            (Mode.BASE, True, False),
            (Mode.BASE, False, True),
            (Mode.BASE, True, True),
            (Mode.PSK, False, False),
            (Mode.PSK, False, True),
            (Mode.PSK, True, True),
            (Mode.AUTH, True, False),
            (Mode.AUTH, False, False),
            (Mode.AUTH, True, True),
            (Mode.AUTH_PSK, True, False),
            (Mode.AUTH_PSK, False, True),
            (Mode.AUTH_PSK, False, False),
        ],
    )
    def test_sender_matrix(
        self,
        authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture],
        mode: Mode,
        use_psk: bool,
        use_auth: bool,
    ) -> None:
        suite, fx = authpsk_suite_and_keys
        psk, psk_id = (fx.psk, fx.psk_id) if use_psk else (b"", b"")
        sks = fx.sks if use_auth else None
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(mode, fx.pkr, fx.info, sks, psk, psk_id, fx.eks)

    @pytest.mark.parametrize(
        "mode, use_psk, use_auth",
        [
            (Mode.BASE, True, False),
            (Mode.BASE, False, True),
            (Mode.BASE, True, True),
            (Mode.PSK, False, False),
            (Mode.PSK, False, True),
            (Mode.PSK, True, True),
            (Mode.AUTH, True, False),
            (Mode.AUTH, False, False),
            (Mode.AUTH, True, True),
            (Mode.AUTH_PSK, True, False),
            (Mode.AUTH_PSK, False, True),
            (Mode.AUTH_PSK, False, False),
        ],
    )
    def test_recipient_matrix(
        self,
        authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture],
        mode: Mode,
        use_psk: bool,
        use_auth: bool,
    ) -> None:
        suite, fx = authpsk_suite_and_keys
        psk, psk_id = (fx.psk, fx.psk_id) if use_psk else (b"", b"")
        pks = fx.pks if use_auth else None
        dummy_enc = b"\x00" * len(fx.pkr.to_public_bytes())
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(mode, dummy_enc, fx.skr, fx.info, pks, psk, psk_id)

    @pytest.mark.parametrize("mode", MODES)
    def test_psk_without_psk_id_is_rejected(
        self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture], mode: Mode
    ) -> None:
        suite, fx = authpsk_suite_and_keys
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(mode, fx.pkr, fx.info, fx.sks, fx.psk, b"", fx.eks)

    @pytest.mark.parametrize("mode", MODES)
    def test_psk_id_without_psk_is_rejected(
        self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture], mode: Mode
    ) -> None:
        suite, fx = authpsk_suite_and_keys
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(mode, fx.pkr, fx.info, fx.sks, b"", fx.psk_id, fx.eks)

    def test_mode_must_be_mode_enum(self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]) -> None:
        suite, fx = authpsk_suite_and_keys
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(0, fx.pkr, fx.info, None, b"", b"", fx.eks)  # type: ignore[arg-type]
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(0, b"", fx.skr, fx.info, None, b"", b"")  # type: ignore[arg-type]


class TestStaticAuthenticationKeyRoles:
    """
    The static keys must have the role required by each side:
    sender holds a private ``sks``/public ``pkr``, recipient holds a private
    ``skr``/public ``pks``.
    """

    def test_sender_rejects_public_sks(self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]) -> None:
        suite, fx = authpsk_suite_and_keys
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(Mode.AUTH, fx.pkr, fx.info, fx.pks, b"", b"", fx.eks)

    def test_sender_rejects_private_pkr(self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]) -> None:
        suite, fx = authpsk_suite_and_keys
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(Mode.BASE, fx.skr, fx.info, None, b"", b"", fx.eks)

    def test_recipient_rejects_public_skr(self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]) -> None:
        suite, fx = authpsk_suite_and_keys
        dummy_enc = b"\x00" * len(fx.pkr.to_public_bytes())
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(Mode.BASE, dummy_enc, fx.pkr, fx.info, None, b"", b"")

    def test_recipient_rejects_private_pks(self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]) -> None:
        suite, fx = authpsk_suite_and_keys
        dummy_enc = b"\x00" * len(fx.pkr.to_public_bytes())
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(Mode.AUTH, dummy_enc, fx.skr, fx.info, fx.sks, b"", b"")


class TestValidationRunsBeforeKem:
    """
    Inconsistent input must be rejected before the KEM runs or random ephemeral
    material is generated. The instrumented KEM raises if it is ever touched.
    """

    @staticmethod
    def _booby_trapped_kem(suite: CipherSuite, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("KEM must not be executed on invalid input.")

        monkeypatch.setattr(suite.kem, "encap", fail)
        monkeypatch.setattr(suite.kem, "decap", fail)

    def test_sender_rejects_before_kem(self, monkeypatch: pytest.MonkeyPatch) -> None:
        v = next(x for x in VECTORS if x["mode"] == Mode.AUTH_PSK.value)
        suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
        fx = _VectorFixture(suite, v)
        self._booby_trapped_kem(suite, monkeypatch)

        # No ephemeral key pair supplied: the legacy path would generate random
        # material here; the strict path must fail while validating the mode.
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(Mode.BASE, fx.pkr, fx.info, fx.sks, fx.psk, fx.psk_id)
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(Mode.AUTH, fx.pkr, fx.info, None, b"", b"")

    def test_recipient_rejects_before_kem(self, monkeypatch: pytest.MonkeyPatch) -> None:
        v = next(x for x in VECTORS if x["mode"] == Mode.AUTH_PSK.value)
        suite = CipherSuite.new(KEMId(v["kem_id"]), KDFId(v["kdf_id"]), AEADId(v["aead_id"]))
        fx = _VectorFixture(suite, v)
        self._booby_trapped_kem(suite, monkeypatch)

        enc = bytes.fromhex(v["enc"])
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(Mode.BASE, enc, fx.skr, fx.info, fx.pks, fx.psk, fx.psk_id)
        with pytest.raises(InvalidModeError):
            suite.create_recipient_context_strict(Mode.PSK, enc, fx.skr, fx.info, None, b"", b"")


class TestLegacyInferenceKept:
    """
    The legacy entries keep their original behavior: they infer the mode from
    the parameters instead of failing, which is exactly the silent downgrade
    the strict entries protect against.
    """

    def test_legacy_silently_downgrades_authpsk_to_psk(
        self, authpsk_suite_and_keys: tuple[CipherSuite, _VectorFixture]
    ) -> None:
        suite, fx = authpsk_suite_and_keys
        # psk/psk_id present, sks omitted: legacy inference selects PSK mode.
        enc, sender = suite.create_sender_context(fx.pkr, fx.info, None, fx.psk, fx.psk_id, fx.eks)
        recipient = suite.create_recipient_context(enc, fx.skr, fx.info, None, fx.psk, fx.psk_id)
        ct = sender.seal(b"legacy inference")
        assert recipient.open(ct) == b"legacy inference"

        # The same omission must fail loudly on the strict AuthPSK entry...
        with pytest.raises(InvalidModeError):
            suite.create_sender_context_strict(Mode.AUTH_PSK, fx.pkr, fx.info, None, fx.psk, fx.psk_id, fx.eks)
        # ...and succeed when the explicitly selected mode matches the inputs.
        enc_strict, sender_strict = suite.create_sender_context_strict(
            Mode.PSK, fx.pkr, fx.info, None, fx.psk, fx.psk_id, fx.eks
        )
        assert enc_strict == enc
        assert sender_strict.seal(b"legacy inference") == ct
