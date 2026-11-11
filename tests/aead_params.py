"""AEAD parameter table from RFC 9180 Section 7.3 (Nk/Nn/Nt)."""

# aead_id -> (Nk key size, Nn nonce size, Nt tag size)
AEAD_PARAMS = {
    0x0001: (16, 12, 16),  # AES-128-GCM
    0x0002: (32, 12, 16),  # AES-256-GCM
    0x0003: (32, 12, 16),  # ChaCha20Poly1305
    0xFFFF: (0, 0, 0),  # export-only
}


def aead_key_size(aead_id: int) -> int:
    return AEAD_PARAMS[aead_id][0]
