Welcome to PyHPKE
=================

PyHPKE is a `HPKE (Hybrid Public Key Encryption)`_ implementation written in Python.

You can install PyHPKE with pip:

.. code-block:: console

    $ pip install pyhpke

And then, you can use it as follows:


.. code-block:: pycon

    >>> from pyhpke import CipherSuite, KEMKey, KEMId, KDFId, AEADId
    >>> public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAoMfvlI5DN08JRFP2fhWvZ6vBEl28yFeS9O9YQUjNyCY=\n-----END PUBLIC KEY-----"
    >>> pkr = KEMKey.from_pem(public_key_pem)
    >>> suite = CipherSuite.new(
    ...     KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
    ... )
    >>> enc, sender = suite.create_sender_context(pkr)
    >>> ct = sender.seal(b"Hello world!")
    >>>
    >>> private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMAXvyHjAeXy9x4MXF6rwGbDKw7crgDriFTFXO+XsS1F\n-----END PRIVATE KEY-----"
    >>> skr = KEMKey.from_pem(private_key_pem)
    >>> recipient = suite.create_recipient_context(enc, skr)
    >>> pt = recipient.open(ct)
    >>> pt
    b'Hello world!'

You can find other samples in `PyHPKE README`_.

Explicit Mode Selection
-----------------------

``create_sender_context()`` and ``create_recipient_context()`` infer the HPKE
mode from the supplied parameters, so a missing configuration entry (e.g. an
omitted ``psk_id``) silently selects a different mode instead of failing.

New code should use the strict entry points
:meth:`CipherSuite.create_sender_context_strict` and
:meth:`CipherSuite.create_recipient_context_strict`, which bind the context to
an explicit :class:`~pyhpke.Mode` and raise
:class:`~pyhpke.InvalidModeError` before the KEM runs whenever the PSK/PSK-id
pairing, the presence of a static authentication key, or a key role does not
match the selected mode.

.. code-block:: pycon

    >>> from pyhpke import Mode
    >>> enc, sender = suite.create_sender_context_strict(
    ...     Mode.AUTH_PSK, pkr, info, sks, psk, psk_id
    ... )
    >>> recipient = suite.create_recipient_context_strict(
    ...     Mode.AUTH_PSK, enc, skr, info, pks, psk, psk_id
    ... )

The legacy inferring entry points remain supported for backwards
compatibility; see :class:`CipherSuite <pyhpke.CipherSuite>` for the full API.

Index
-----

.. toctree::
   :maxdepth: 2

   installation
   api
   changes

.. _`HPKE (Hybrid Public Key Encryption)`: https://www.rfc-editor.org/rfc/rfc9180.html
.. _`PyHPKE README`: https://github.com/dajiaji/pyhpke#readme
