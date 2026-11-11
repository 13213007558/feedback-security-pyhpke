# PyHPKE - A Python implementation of HPKE

[![PyPI version](https://badge.fury.io/py/pyhpke.svg)](https://badge.fury.io/py/pyhpke)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyhpke)
[![Documentation Status](https://readthedocs.org/projects/pyhpke/badge/?version=latest)](https://pyhpke.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/pyhpke/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/pyhpke/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/pyhpke)
[![Known Vulnerabilities](https://snyk.io/test/github/dajiaji/pyhpke/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dajiaji/pyhpke?targetFile=requirements.txt)

PyHPKE is a [HPKE (Hybrid Public Key Encryption)](https://www.rfc-editor.org/rfc/rfc9180.html) implementation written in Python.

You can install PyHPKE with pip:

```sh
$ pip install pyhpke
```

And then, you can use it as follows:


```py
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

# The sender side:
suite_s = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)
pkr = KEMKey.from_jwk(  # from_pem is also available.
    {
        "kid": "01",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
enc, sender = suite_s.create_sender_context(pkr)
ct = sender.seal(b"Hello world!")

# The recipient side:
suite_r = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)
skr = KEMKey.from_jwk(
    {
        "kid": "01",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
recipient = suite_r.create_recipient_context(enc, skr)
pt = recipient.open(ct)

assert pt == b"Hello world!"


# deriving a KEMKeyPair
keypair = suite_s.kem.derive_key_pair(b"some_ikm_bytes_used_for_key_derivation")
```

## Index

- [Installation](#installation)
- [Supported HPKE Modes and Cipher Suites](#supported-hpke-modes-and-cipher-suites)
- [Warnings and Restrictions](#warnings-and-restrictions)
- [Usage](#usage)
- [Thread Safety and State Commit](#thread-safety-and-state-commit)
- [API Reference](#api-reference)
- [Test](#test)
- [Security](#security)
- [Contributing](#contributing)

## Installation

You can install PyHPKE with pip:

```sh
$ pip install pyhpke
```

## Supported HPKE Modes and Cipher Suites

PyHPKE supports all of the HPKE modes and cipher suites defined in RFC9180 below.

- modes
    - ✅ Base
    - ✅ PSK
    - ✅ Auth
    - ✅ AuthPSK
- KEMs (Key Encapsulation Machanisms)
    - ✅ DHKEM (P-256, HKDF-SHA256)
    - ✅ DHKEM (P-384, HKDF-SHA384)
    - ✅ DHKEM (P-521, HKDF-SHA512)
    - ✅ DHKEM (X25519, HKDF-SHA256)
    - ✅ DHKEM (X448, HKDF-SHA512)
- KDFs (Key Derivation Functions)
    - ✅ HKDF-SHA256
    - ✅ HKDF-SHA384
    - ✅ HKDF-SHA512
- AEADs (Authenticated Encryption with Associated Data)
    - ✅ AES-128-GCM
    - ✅ AES-256-GCM
    - ✅ ChaCha20Poly1305
    - ✅ Export Only

## Warnings and Restrictions

Although this library has been passed all of the following official test vectors, it has not been formally audited.
- [RFC9180 official test vectors provided on github.com/cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json)

## Usage

```py
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

# The sender side:
suite_s = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)
pkr = KEMKey.from_jwk(
    {
        "kid": "01",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
enc, sender = suite_s.create_sender_context(pkr)
ct = sender.seal(b"Hello world!")

# The recipient side:
suite_r = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)
skr = KEMKey.from_jwk(
    {
        "kid": "01",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
recipient = suite_r.create_recipient_context(enc, skr)
pt = recipient.open(ct)

assert pt == b"Hello world!"
```

## Thread Safety and State Commit

A sender/recipient context keeps a sequence number which is XORed with the
base nonce to derive the per-message nonce (RFC 9180, Section 5.2). PyHPKE
commits the state transition exactly as the RFC defines it:

- The sequence number is incremented **only after** the AEAD operation
  succeeded. A failed `seal`/`open` (e.g. an authentication failure) never
  consumes a sequence number, so the corresponding legitimate ciphertext can
  be decrypted by simply calling `open` again.
- When the sequence number reaches the RFC 9180 limit, `seal`/`open` raise
  `MessageLimitReachedError` and the context state is left unchanged.
- `export` never consumes a sequence number.

By default (`ConcurrencyMode.NONE`) a context performs no synchronization and
must not be shared between threads, which keeps the historical behavior. If a
context is shared between threads (e.g. a worker pool), opt into one of the
following policies via the `concurrency` argument of
`create_sender_context`/`create_recipient_context`:

- `ConcurrencyMode.LOCKED`: a **per-context** lock serializes
  `seal`/`open` calls so that nonce derivation, the AEAD operation and the
  sequence number commit are executed atomically. Unrelated contexts are
  never blocked by each other.
- `ConcurrencyMode.STRICT`: like `LOCKED`, but a concurrent call fails
  immediately with `ConcurrentUseError` instead of waiting. The state is
  left untouched and the call can be retried later.

Note that on the recipient side these policies only make each `open` call
atomic; they do not reorder messages. Ciphertexts must still be passed to
`open` in the order the sender produced them (e.g. via an ordered queue),
because each `open` consumes the next sequence number in arrival order.

```py
enc, sender = suite_s.create_sender_context(pkr, concurrency=ConcurrencyMode.LOCKED)
recipient = suite_r.create_recipient_context(enc, skr, concurrency=ConcurrencyMode.LOCKED)
```

## API Reference

See [Documentation](https://pyhpke.readthedocs.io/en/stable/api.html).

## Test

You can run tests from the project root after cloning with:

```sh
$ tox
```

## Security

If you discover a security issue, please report it via a GitHub issue and avoid disclosing exploit details publicly until we respond.

This project has not been formally audited; use it according to your risk assessment.

The Snyk badge reports results based on `requirements.txt` exported from `uv.lock` and reflects dependency scanning only.

See [SECURITY.md](SECURITY.md) for our security policy and reporting guidance.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.

### Development environment

```sh
$ uv sync --frozen
$ uv run pre-commit install
```

### Dependency updates

`[tool.uv]` in `pyproject.toml` pins `exclude-newer = "2 days"`, so resolution only
considers packages uploaded more than two days ago. This gives newly published
releases a verification window before we depend on them, and it applies to every
`uv` command automatically — no extra flags needed.

After changing dependencies, re-export `requirements.txt`, which is what the
dependency scanners read:

```sh
$ uv add <package>          # or: uv lock --upgrade
$ uv export --format requirements-txt --locked -o requirements.txt
```

### Scanning

```sh
$ uv run pip-audit
$ uv run pip-licenses
$ trivy fs --severity HIGH,CRITICAL .
```
