from .encryption_context import EncryptionContext
from .exceptions import NotSupportedError, SealError


class SenderContext(EncryptionContext):
    def seal(self, pt: bytes, aad: bytes = b"") -> bytes:
        def _seal(nonce: bytes) -> bytes:
            try:
                return self._key.seal(pt, nonce, aad)
            except Exception as err:
                raise SealError("Failed to seal.") from err

        return self._dispatch(_seal)

    def open(self, ct: bytes, aad: bytes = b"") -> bytes:  # noqa: ARG002
        raise NotSupportedError("Not available for sender.")
