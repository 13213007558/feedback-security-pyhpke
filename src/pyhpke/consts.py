import enum

HPKE_VERSION = b"HPKE-v1"


class Mode(enum.Enum):
    BASE = 0
    PSK = 1
    AUTH = 2
    AUTH_PSK = 3


class ConcurrencyMode(enum.Enum):
    """
    The concurrency policy applied to a sender/recipient context.

    - ``NONE``: No synchronization. This is the default and keeps the
      historical behavior. A context must not be shared between threads.
    - ``LOCKED``: A per-context lock serializes ``seal``/``open`` calls so
      that nonce derivation, the AEAD operation and the sequence number
      commit are executed atomically. Only this context is serialized;
      unrelated contexts are never blocked.
    - ``STRICT``: Like ``LOCKED``, but instead of waiting, a concurrent
      call fails immediately with
      :class:`pyhpke.ConcurrentUseError`. The state is left untouched so
      the caller can retry later.
    """

    NONE = 0
    LOCKED = 1
    STRICT = 2


class KEMId(enum.Enum):
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021


class KDFId(enum.Enum):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AEADId(enum.Enum):
    AES128_GCM = 0x0001
    AES256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003
    EXPORT_ONLY = 0xFFFF


HPKE_SUPPORTED_JWK_KTYS = ["EC", "OKP"]
HPKE_SUPPORTED_JWK_EC_CRVS = ["P-256", "P-384", "P-521"]
