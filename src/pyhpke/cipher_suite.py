import struct

from .aead import AEAD, AEADParams
from .aead_interface import AEADInterface
from .consts import AEADId, KDFId, KEMId, Mode
from .context_interface import ContextInterface
from .exceptions import InvalidModeError
from .exporter_context import ExporterContext
from .kdf import KDF
from .kdf_interface import KDFInterface
from .kem import KEM
from .kem_interface import KEMInterface
from .kem_key import KEMKeyPair
from .kem_key_interface import KEMKeyInterface
from .recipient_context import RecipientContext
from .sender_context import SenderContext


class CipherSuite:
    """
    An HPKE cipher suite which consists of KEM, KDF and AEAD.
    """

    def __init__(self, kem: KEMInterface, kdf: KDFInterface, aead: AEADInterface):
        self._kem = kem
        self._kdf = kdf
        self._aead = aead
        return

    @classmethod
    def new(cls, kem_id: KEMId, kdf_id: KDFId, aead_id: AEADId) -> "CipherSuite":
        """
        Constructor of HPKE cipher suite.

        Args:
            kem_id (KEMId): A KEM (Key Encapsulation Mechanism) identifier.
            kdf_id (KDFId): A KDF (Key Derivation Function) identifier.
            aead_id (AEADId): An AEAD (Authenticated Encryption with Additional Data) identifier.
        Returns:
            CipherSuite: A CipherSuite object.
        """
        suite_id = b"HPKE" + struct.pack(">HHH", kem_id.value, kdf_id.value, aead_id.value)
        kem = KEM(kem_id)
        kdf = KDF(kdf_id, suite_id)
        aead = AEAD(aead_id)
        return cls(kem, kdf, aead)

    @property
    def kem(self) -> KEMInterface:
        """
        The KEM context in the cipher suite.
        """
        return self._kem

    @property
    def kdf(self) -> KDFInterface:
        """
        The KDF context in the cipher suite.
        """
        return self._kdf

    @property
    def aead(self) -> AEADInterface:
        """
        The AEAD context in the cipher suite.
        """
        return self._aead

    def create_sender_context(
        self,
        pkr: KEMKeyInterface,
        info: bytes = b"",
        sks: KEMKeyInterface | None = None,
        psk: bytes = b"",
        psk_id: bytes = b"",
        eks: KEMKeyPair | None = None,
    ) -> tuple[bytes, ContextInterface]:
        """
        Creates a sender context.

        .. note::
            **Legacy entry point.**

            The HPKE mode is inferred from the supplied parameters. A missing
            parameter (e.g. an omitted ``psk_id``) therefore silently selects a
            different mode instead of failing. New code should use
            :meth:`create_sender_context_strict`, which binds the context to an
            explicitly selected :class:`Mode <pyhpke.Mode>` and rejects any
            parameter that does not match it.
        """
        mode: Mode = (Mode.BASE if sks is None else Mode.AUTH) if psk == b"" else (Mode.PSK if sks is None else Mode.AUTH_PSK)

        shared_secret, enc = self._kem.encap(pkr, sks, eks)
        return enc, self._key_schedule_s(mode, shared_secret, info, psk, psk_id)

    def create_sender_context_strict(
        self,
        mode: Mode,
        pkr: KEMKeyInterface,
        info: bytes = b"",
        sks: KEMKeyInterface | None = None,
        psk: bytes = b"",
        psk_id: bytes = b"",
        eks: KEMKeyPair | None = None,
    ) -> tuple[bytes, ContextInterface]:
        """
        Creates a sender context bound to an explicitly selected mode.

        Unlike :meth:`create_sender_context`, the mode is never inferred: every
        parameter is checked against ``mode`` and an
        :class:`InvalidModeError <pyhpke.InvalidModeError>` is raised before the
        KEM is executed or any ephemeral key material is generated when:

        * ``mode`` is not a :class:`Mode <pyhpke.Mode>`,
        * exactly one of ``psk``/``psk_id`` is provided (they must be both set
          in the PSK modes and both empty in the non-PSK modes),
        * ``sks`` (the sender's static private key) is present for a non-auth
          mode or missing for an auth mode,
        * ``pkr`` is not a public key or ``sks`` is not a private key.

        Args:
            mode (Mode): The HPKE mode to bind the context to.
            pkr (KEMKeyInterface): The recipient's static public key.
            info (bytes): A byte string of additional contextual information.
            sks (KEMKeyInterface | None): The sender's static private key,
                required for the Auth and AuthPSK modes.
            psk (bytes): The pre-shared key, required for the PSK and AuthPSK
                modes.
            psk_id (bytes): The pre-shared key identifier, required together
                with ``psk`` for the PSK and AuthPSK modes.
            eks (KEMKeyPair | None): An optional ephemeral key pair, mainly used
                with test vectors.
        Returns:
            tuple[bytes, ContextInterface]: A tuple of the encapsulated key
            (``enc``) and the sender context.
        """
        self._validate_mode(mode, psk, psk_id, sks is not None)
        if pkr.is_public is False:
            raise InvalidModeError("pkr must be a public key.")
        if sks is not None and sks.is_public:
            raise InvalidModeError("sks must be a private key.")

        shared_secret, enc = self._kem.encap(pkr, sks, eks)
        return enc, self._key_schedule_s(mode, shared_secret, info, psk, psk_id)

    def create_recipient_context(
        self,
        enc: bytes,
        skr: KEMKeyInterface,
        info: bytes = b"",
        pks: KEMKeyInterface | None = None,
        psk: bytes = b"",
        psk_id: bytes = b"",
    ) -> ContextInterface:
        """
        Creates a recipient context.

        .. note::
            **Legacy entry point.**

            The HPKE mode is inferred from the supplied parameters. A missing
            parameter (e.g. an omitted ``psk_id``) therefore silently selects a
            different mode instead of failing. New code should use
            :meth:`create_recipient_context_strict`, which binds the context to
            an explicitly selected :class:`Mode <pyhpke.Mode>` and rejects any
            parameter that does not match it.
        """
        mode: Mode = (Mode.BASE if pks is None else Mode.AUTH) if psk == b"" else (Mode.PSK if pks is None else Mode.AUTH_PSK)

        shared_secret = self._kem.decap(enc, skr, pks)
        return self._key_schedule_r(mode, shared_secret, info, psk, psk_id)

    def create_recipient_context_strict(
        self,
        mode: Mode,
        enc: bytes,
        skr: KEMKeyInterface,
        info: bytes = b"",
        pks: KEMKeyInterface | None = None,
        psk: bytes = b"",
        psk_id: bytes = b"",
    ) -> ContextInterface:
        """
        Creates a recipient context bound to an explicitly selected mode.

        Unlike :meth:`create_recipient_context`, the mode is never inferred:
        every parameter is checked against ``mode`` and an
        :class:`InvalidModeError <pyhpke.InvalidModeError>` is raised before the
        KEM is executed when:

        * ``mode`` is not a :class:`Mode <pyhpke.Mode>`,
        * exactly one of ``psk``/``psk_id`` is provided (they must be both set
          in the PSK modes and both empty in the non-PSK modes),
        * ``pks`` (the sender's static public key) is present for a non-auth
          mode or missing for an auth mode,
        * ``skr`` is not a private key or ``pks`` is not a public key.

        Args:
            mode (Mode): The HPKE mode to bind the context to.
            enc (bytes): The encapsulated key produced by the sender.
            skr (KEMKeyInterface): The recipient's static private key.
            info (bytes): A byte string of additional contextual information.
            pks (KEMKeyInterface | None): The sender's static public key,
                required for the Auth and AuthPSK modes.
            psk (bytes): The pre-shared key, required for the PSK and AuthPSK
                modes.
            psk_id (bytes): The pre-shared key identifier, required together
                with ``psk`` for the PSK and AuthPSK modes.
        Returns:
            ContextInterface: The recipient context.
        """
        self._validate_mode(mode, psk, psk_id, pks is not None)
        if skr.is_public:
            raise InvalidModeError("skr must be a private key.")
        if pks is not None and pks.is_public is False:
            raise InvalidModeError("pks must be a public key.")

        shared_secret = self._kem.decap(enc, skr, pks)
        return self._key_schedule_r(mode, shared_secret, info, psk, psk_id)

    @staticmethod
    def _validate_mode(mode: Mode, psk: bytes, psk_id: bytes, uses_auth_key: bool) -> None:
        if not isinstance(mode, Mode):
            raise InvalidModeError("mode must be a Mode.")
        if (psk == b"") != (psk_id == b""):
            raise InvalidModeError("psk and psk_id must be both provided or both omitted.")
        if mode in (Mode.PSK, Mode.AUTH_PSK):
            if psk == b"":
                raise InvalidModeError(f"psk and psk_id are required for the {mode.name} mode.")
        elif psk != b"":
            raise InvalidModeError(f"psk and psk_id are not allowed for the {mode.name} mode.")
        if mode in (Mode.AUTH, Mode.AUTH_PSK):
            if not uses_auth_key:
                raise InvalidModeError(f"A static authentication key is required for the {mode.name} mode.")
        elif uses_auth_key:
            raise InvalidModeError(f"A static authentication key is not allowed for the {mode.name} mode.")
        return

    def seal(
        self,
        pkr: KEMKeyInterface,
        pt: bytes,
        info: bytes = b"",
        aad: bytes = b"",
        psk: bytes = b"",
        psk_id: bytes = b"",
        sks: KEMKeyInterface | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Does a single-shot encryption.
        """
        raise NotImplementedError()

    def open(
        self,
        enc: bytes,
        skr: KEMKeyInterface,
        ct: bytes,
        info: bytes = b"",
        aad: bytes = b"",
        psk: bytes = b"",
        psk_id: bytes = b"",
        pks: KEMKeyInterface | None = None,
    ) -> bytes:
        """
        Does a single-shot decryption.
        """
        raise NotImplementedError()

    def _key_schedule(
        self,
        mode: Mode,
        shared_secret: bytes,
        info: bytes,
        psk: bytes,
        psk_id: bytes,
    ) -> tuple[KDF, AEADParams]:
        suite_id = b"HPKE" + struct.pack(">HHH", self._kem.id.value, self._kdf.id.value, self._aead.id.value)
        kdf = KDF(self._kdf.id, suite_id)

        psk_id_hash = kdf.labeled_extract(b"", b"psk_id_hash", psk_id)
        info_hash = kdf.labeled_extract(b"", b"info_hash", info)
        key_schedule_context = bytes([mode.value]) + psk_id_hash + info_hash

        secret = kdf.labeled_extract(shared_secret, b"secret", psk)

        key = kdf.labeled_expand(secret, b"key", key_schedule_context, self._aead.key_size)
        base_nonce = kdf.labeled_expand(secret, b"base_nonce", key_schedule_context, self._aead.nonce_size)
        exporter_secret = kdf.labeled_expand(secret, b"exp", key_schedule_context, kdf.digest_size)
        return kdf, AEADParams(self._aead, key, base_nonce, 0, exporter_secret)

    def _key_schedule_s(
        self,
        mode: Mode,
        shared_secret: bytes,
        info: bytes,
        psk: bytes,
        psk_id: bytes,
    ) -> ContextInterface:
        kdf, params = self._key_schedule(mode, shared_secret, info, psk, psk_id)
        if params.key == b"":
            return ExporterContext(kdf, params.exporter_secret)
        return SenderContext(kdf, params)

    def _key_schedule_r(
        self,
        mode: Mode,
        shared_secret: bytes,
        info: bytes,
        psk: bytes,
        psk_id: bytes,
    ) -> ContextInterface:
        kdf, params = self._key_schedule(mode, shared_secret, info, psk, psk_id)
        if params.key == b"":
            return ExporterContext(kdf, params.exporter_secret)
        return RecipientContext(kdf, params)
