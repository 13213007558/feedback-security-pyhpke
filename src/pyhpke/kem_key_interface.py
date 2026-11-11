from typing import Any


class KEMKeyInterface:
    """
    The KEM key interface.
    """

    _is_public: bool

    def __init__(self, key: Any):
        self._key = key

    @property
    def raw(self) -> Any:
        return self._key

    @property
    def is_public(self) -> bool:
        """
        Returns ``True`` if the key is a public key, and ``False`` if it is a
        private key.
        """
        return self._is_public

    def to_private_bytes(self) -> bytes:
        """
        Serializes the key to a byte string if it is private.
        """
        raise NotImplementedError()

    def to_public_bytes(self) -> bytes:
        """
        Serializes the key to a byte string if it is public.
        """
        raise NotImplementedError()
