"""Independent RFC 9180 reference oracle for verifying ``Context.Export``.

This module re-implements the RFC 9180 (HPKE) key schedule and exporter from
the RFC text, using only ``cryptography``'s raw HMAC primitive. It deliberately
imports nothing from :mod:`pyhpke`, so a shared bug in the implementation under
test cannot also corrupt the expected value.

RFC 9184 references:
  * Section 4 "Labeled Extract-and-Expand Functions"
  * Section 5.1 "Key Schedule"
  * Section 5.3 "Secret Export"
"""

import hashlib
import hmac
import struct

VERSION = b"HPKE-v1"

# RFC 9180 Section 7.1/7.2/7.3 identifiers.
KEM_IDS = {
    0x0010: 32,  # DHKEM(P-256, HKDF-SHA256)
    0x0011: 48,  # DHKEM(P-384, HKDF-SHA384)
    0x0012: 64,  # DHKEM(P-521, HKDF-SHA512)
    0x0020: 32,  # DHKEM(X25519, HKDF-SHA256)
    0x0021: 64,  # DHKEM(X448, HKDF-SHA512)
}
KDF_HASHES = {0x0001: hashlib.sha256, 0x0002: hashlib.sha384, 0x0003: hashlib.sha512}
EXPORT_ONLY = 0xFFFF


def _hash(kdf_id: int):
    return KDF_HASHES[kdf_id]


def digest_size(kdf_id: int) -> int:
    return _hash(kdf_id)().digest_size


def max_export_length(kdf_id: int) -> int:
    # HKDF-Expand (RFC 5869) hard limit: 255 * Nh.
    return 255 * digest_size(kdf_id)


def suite_id(kem_id: int, kdf_id: int, aead_id: int) -> bytes:
    return b"HPKE" + struct.pack(">HHH", kem_id, kdf_id, aead_id)


def hkdf_extract(salt: bytes, ikm: bytes, kdf_id: int) -> bytes:
    return hmac.new(salt, ikm, _hash(kdf_id)).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, kdf_id: int) -> bytes:
    nh = digest_size(kdf_id)
    if length > 255 * nh:
        raise ValueError(f"length ({length}) exceeds HKDF-Expand limit {255 * nh}")
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), _hash(kdf_id)).digest()
        output += previous
        counter += 1
    return output[:length]


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, sid: bytes, kdf_id: int) -> bytes:
    labeled_ikm = VERSION + sid + label + ikm
    return hkdf_extract(salt, labeled_ikm, kdf_id)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, sid: bytes, kdf_id: int) -> bytes:
    labeled_info = struct.pack(">H", length) + VERSION + sid + label + info
    return hkdf_expand(prk, labeled_info, length, kdf_id)


def key_schedule_context(mode: int, psk_id: bytes, info: bytes, sid: bytes, kdf_id: int) -> bytes:
    # RFC 9180 Section 5.1: mode || psk_id_hash || info_hash.
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", psk_id, sid, kdf_id)
    info_hash = labeled_extract(b"", b"info_hash", info, sid, kdf_id)
    return bytes([mode]) + psk_id_hash + info_hash


def key_schedule(
    mode: int,
    shared_secret: bytes,
    info: bytes,
    psk: bytes,
    psk_id: bytes,
    kem_id: int,
    kdf_id: int,
    aead_id: int,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (key_schedule_context, secret, exporter_secret, key) per Section 5.1."""
    sid = suite_id(kem_id, kdf_id, aead_id)
    context = key_schedule_context(mode, psk_id, info, sid, kdf_id)
    secret = labeled_extract(shared_secret, b"secret", psk, sid, kdf_id)
    key = b""
    if aead_id != EXPORT_ONLY:
        from tests.aead_params import aead_key_size

        key = labeled_expand(secret, b"key", context, aead_key_size(aead_id), sid, kdf_id)
    exporter_secret = labeled_expand(secret, b"exp", context, digest_size(kdf_id), sid, kdf_id)
    return context, secret, exporter_secret, key


def exporter(exporter_secret: bytes, exporter_context: bytes, length: int, sid: bytes, kdf_id: int) -> bytes:
    # RFC 9180 Section 5.3: Export(secret, context, L) = Labeled-Expand(secret, "sec", context, L).
    return labeled_expand(exporter_secret, b"sec", exporter_context, length, sid, kdf_id)


def expected_export(
    mode: int,
    shared_secret: bytes,
    info: bytes,
    psk: bytes,
    psk_id: bytes,
    exporter_context: bytes,
    length: int,
    kem_id: int,
    kdf_id: int,
    aead_id: int,
) -> bytes:
    sid = suite_id(kem_id, kdf_id, aead_id)
    _, _, exporter_secret, _ = key_schedule(mode, shared_secret, info, psk, psk_id, kem_id, kdf_id, aead_id)
    return exporter(exporter_secret, exporter_context, length, sid, kdf_id)
