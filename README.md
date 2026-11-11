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
- [Explicit Mode Selection](#explicit-mode-selection)
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

## Explicit Mode Selection

`create_sender_context()` and `create_recipient_context()` keep their original
calling convention for backwards compatibility, but they **infer** the HPKE
mode from the supplied parameters. If a configuration entry is missing (for
example `psk_id` is omitted while `psk` is set), the mode is silently
re-derived instead of failing — an AuthPSK deployment can therefore be reduced
to PSK or Base without any error.

For new code, use the strict entries `create_sender_context_strict()` and
`create_recipient_context_strict()`, which take an explicit `Mode` and reject
any parameter that does not match it with an `InvalidModeError` **before** the
KEM is executed or any ephemeral key material is generated:

```py
from pyhpke import AEADId, CipherSuite, InvalidModeError, KDFId, KEMId, Mode

suite = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)

# Bind the context to a mode instead of letting it be inferred.
enc, sender = suite.create_sender_context_strict(
    Mode.AUTH_PSK, pkr, info, sks, psk, psk_id
)
recipient = suite.create_recipient_context_strict(
    Mode.AUTH_PSK, enc, skr, info, pks, psk, psk_id
)

# A missing psk_id now fails immediately instead of downgrading to Auth mode.
try:
    suite.create_sender_context_strict(Mode.AUTH_PSK, pkr, info, sks, psk, b"")
except InvalidModeError as e:
    print(e)  # psk and psk_id must be both provided or both omitted.
```

The strict entries validate, for each of the four modes (`BASE`, `PSK`,
`AUTH`, `AUTH_PSK`):

- `psk` and `psk_id` must be provided together in the PSK modes and omitted
  together in the non-PSK modes;
- the static authentication key (`sks` on the sender, `pks` on the recipient)
  is required in the Auth/AuthPSK modes and forbidden in Base/PSK;
- the key roles are correct: public `pkr`/`pks`, private `skr`/`sks`.

The legacy `create_sender_context()`/`create_recipient_context()` remain
available unchanged; only use them when the inferred-mode behavior is
acceptable. Prefer the strict entries for security-sensitive configurations.

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
