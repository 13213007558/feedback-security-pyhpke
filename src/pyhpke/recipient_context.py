from .encryption_context import EncryptionContext
from .exceptions import NotSupportedError, OpenError


class RecipientContext(EncryptionContext):
    def seal(self, pt: bytes, aad: bytes = b"") -> bytes:  # noqa: ARG002
        raise NotSupportedError("Not available for recipient.")

    def open(self, ct: bytes, aad: bytes = b"") -> bytes:
        def _open(nonce: bytes) -> bytes:
            try:
                return self._key.open(ct, nonce, aad)
            except Exception as err:
                raise OpenError("Failed to open.") from err

        return self._dispatch(_open)
