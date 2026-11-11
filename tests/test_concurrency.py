import queue
import struct
import threading

import pytest

from pyhpke import (
    AEADId,
    CipherSuite,
    ConcurrencyMode,
    ConcurrentUseError,
    KDFId,
    KEMId,
    KEMKey,
    MessageLimitReachedError,
    OpenError,
    SealError,
)
from pyhpke.aead import AEADParams
from pyhpke.aead_interface import AEADInterface
from pyhpke.aead_key_interface import AEADKeyInterface
from pyhpke.kdf import KDF
from pyhpke.recipient_context import RecipientContext
from pyhpke.sender_context import SenderContext
from pyhpke.utils import xor_bytes

BASE_NONCE = bytes(range(12))


def expected_nonce(seq: int) -> bytes:
    return xor_bytes(BASE_NONCE, seq.to_bytes(12, byteorder="big"))


class ControlledAEADKey(AEADKeyInterface):
    """
    An AEAD key double which records every nonce it is called with and
    can be instructed to fail or to block inside the AEAD operation.
    """

    def __init__(self):
        self.seal_nonces: list[bytes] = []
        self.open_nonces: list[bytes] = []
        self.fail_seal = False
        self.reject_ct: bytes | None = None
        self.on_seal = None
        self.on_open = None
        self._record_lock = threading.Lock()

    def seal(self, pt: bytes, nonce: bytes, aad: bytes = b"") -> bytes:  # noqa: ARG002
        with self._record_lock:
            self.seal_nonces.append(nonce)
        if self.on_seal is not None:
            self.on_seal()
        if self.fail_seal:
            raise ValueError("controlled seal failure.")
        return pt + b"|" + nonce

    def open(self, ct: bytes, nonce: bytes, aad: bytes = b"") -> bytes:  # noqa: ARG002
        with self._record_lock:
            self.open_nonces.append(nonce)
        if self.on_open is not None:
            self.on_open()
        if self.reject_ct is not None and ct == self.reject_ct:
            raise ValueError("controlled open failure.")
        pt, sep, used_nonce = ct.rpartition(b"|")
        if sep == b"" or used_nonce != nonce:
            raise ValueError("ciphertext does not match the nonce.")
        return pt


class ControlledAEAD(AEADInterface):
    def __init__(self, key: ControlledAEADKey):
        self._key = key

    @property
    def id(self) -> AEADId:
        return AEADId.AES128_GCM

    @property
    def key_size(self) -> int:
        return 16

    @property
    def nonce_size(self) -> int:
        return 12

    @property
    def tag_size(self) -> int:
        return 16

    def import_key(self, key: bytes) -> AEADKeyInterface:  # noqa: ARG002
        return self._key


def make_contexts(concurrency: ConcurrencyMode, key: ControlledAEADKey | None = None):
    key = key or ControlledAEADKey()
    aead = ControlledAEAD(key)
    kdf = KDF(KDFId.HKDF_SHA256, b"HPKE" + struct.pack(">HHH", 0x0020, 0x0001, 0x0001))
    sender = SenderContext(kdf, AEADParams(aead, b"\x00" * 16, BASE_NONCE, 0, b"\x00" * 32), concurrency)
    recipient = RecipientContext(kdf, AEADParams(aead, b"\x00" * 16, BASE_NONCE, 0, b"\x00" * 32), concurrency)
    return key, sender, recipient


class TestConcurrency:
    """
    Tests for the RFC 9180 state commit and the concurrency policies.
    """

    def test_locked_serializes_two_concurrent_seals(self):
        key, sender, _ = make_contexts(ConcurrencyMode.LOCKED)
        barrier = threading.Barrier(2)
        results: list[bytes] = []
        errors: list[Exception] = []

        def worker():
            barrier.wait(timeout=5)
            try:
                results.append(sender.seal(b"concurrent"))
            except Exception as err:
                errors.append(err)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == []
        assert len(results) == 2
        # Both calls succeeded and the two nonces actually used by the AEAD
        # are exactly the ones for seq 0 and 1: no reuse, no gap.
        assert sorted(key.seal_nonces) == sorted([expected_nonce(0), expected_nonce(1)])
        assert sender._seq == 2

    def test_locked_does_not_block_unrelated_contexts(self):
        # If a global lock were used, the two contexts below could never be
        # inside the AEAD operation at the same time and the barrier would
        # time out.
        barrier = threading.Barrier(2)
        key_a, sender_a, _ = make_contexts(ConcurrencyMode.LOCKED)
        key_b, sender_b, _ = make_contexts(ConcurrencyMode.LOCKED)
        key_a.on_seal = lambda: barrier.wait(timeout=5)
        key_b.on_seal = lambda: barrier.wait(timeout=5)
        errors: list[Exception] = []

        def worker(sender):
            try:
                sender.seal(b"parallel")
            except Exception as err:
                errors.append(err)

        threads = [threading.Thread(target=worker, args=(sender_a,)), threading.Thread(target=worker, args=(sender_b,))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == []
        assert sender_a._seq == 1
        assert sender_b._seq == 1

    def test_strict_rejects_concurrent_use_and_recovers(self):
        key, sender, _ = make_contexts(ConcurrencyMode.STRICT)
        entered = threading.Event()
        release = threading.Event()
        key.on_seal = lambda: (entered.set(), release.wait(timeout=5))
        errors: list[Exception] = []

        def worker():
            try:
                sender.seal(b"first")
            except Exception as err:
                errors.append(err)

        t = threading.Thread(target=worker)
        t.start()
        assert entered.wait(timeout=5)
        # The first call is inside the AEAD operation: a concurrent call is
        # rejected explicitly instead of being serialized or corrupting state.
        with pytest.raises(ConcurrentUseError):
            sender.seal(b"second")
        assert sender._seq == 0
        release.set()
        t.join(timeout=10)

        assert errors == []
        assert sender._seq == 1
        # The context is still usable afterwards and continues at seq 1.
        sender.seal(b"third")
        assert sender._seq == 2
        assert key.seal_nonces == [expected_nonce(0), expected_nonce(1)]

    def test_open_auth_failure_allows_retry_of_legitimate_ciphertext(self):
        key, sender, recipient = make_contexts(ConcurrencyMode.LOCKED)
        key.reject_ct = b"forged"

        with pytest.raises(OpenError):
            recipient.open(b"forged")
        # The failed attempt must not consume a sequence number.
        assert recipient._seq == 0

        ct = sender.seal(b"legitimate")
        assert recipient.open(ct) == b"legitimate"
        assert recipient._seq == 1
        # The retried legitimate ciphertext was decrypted with the nonce for
        # seq 0, the same one the failed attempt used.
        assert key.open_nonces == [expected_nonce(0), expected_nonce(0)]

    def test_seal_aead_failure_leaves_no_gap(self):
        key, sender, _ = make_contexts(ConcurrencyMode.LOCKED)
        key.fail_seal = True

        with pytest.raises(SealError):
            sender.seal(b"msg")
        assert sender._seq == 0

        key.fail_seal = False
        sender.seal(b"msg")
        assert sender._seq == 1
        # The retry reuses the sequence number of the failed attempt.
        assert key.seal_nonces == [expected_nonce(0), expected_nonce(0)]

    def test_message_limit_reached(self):
        _, sender, recipient = make_contexts(ConcurrencyMode.LOCKED)
        sender._seq = sender._seq_limit
        recipient._seq = recipient._seq_limit

        with pytest.raises(MessageLimitReachedError):
            sender.seal(b"msg")
        with pytest.raises(MessageLimitReachedError):
            recipient.open(b"ct")
        # The state is untouched and the error is repeatable.
        assert sender._seq == sender._seq_limit
        assert recipient._seq == recipient._seq_limit
        with pytest.raises(MessageLimitReachedError):
            sender.seal(b"msg")
        # export does not depend on the sequence number and still works.
        assert len(sender.export(b"ctx", 32)) == 32

    def test_export_does_not_consume_seq(self):
        key, sender, _ = make_contexts(ConcurrencyMode.LOCKED)
        assert sender.export(b"ctx", 32) != sender.export(b"other", 32)
        assert sender.export(b"ctx", 32) == sender.export(b"ctx", 32)
        assert sender._seq == 0
        sender.seal(b"msg")
        assert key.seal_nonces == [expected_nonce(0)]

    def test_default_mode_has_no_lock(self):
        _, sender, recipient = make_contexts(ConcurrencyMode.NONE)
        assert sender._lock is None
        ct = sender.seal(b"hello")
        assert recipient.open(ct) == b"hello"

    def test_real_cipher_consecutive_messages_interop(self):
        # Real cipher algorithms: a producer thread seals consecutive
        # messages while a consumer thread opens them in the same order.
        pkr = KEMKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
            }
        )
        skr = KEMKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        suite_s = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
        suite_r = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
        enc, sender = suite_s.create_sender_context(pkr, concurrency=ConcurrencyMode.LOCKED)
        recipient = suite_r.create_recipient_context(enc, skr, concurrency=ConcurrencyMode.LOCKED)

        messages = [f"msg-{i}".encode() for i in range(100)]
        channel: queue.Queue = queue.Queue()
        received: list[bytes] = []
        errors: list[Exception] = []

        def producer():
            try:
                for m in messages:
                    channel.put(sender.seal(m))
                channel.put(None)
            except Exception as err:
                errors.append(err)

        def consumer():
            try:
                while True:
                    ct = channel.get(timeout=10)
                    if ct is None:
                        return
                    received.append(recipient.open(ct))
            except Exception as err:
                errors.append(err)

        threads = [threading.Thread(target=producer), threading.Thread(target=consumer)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == []
        assert received == messages
