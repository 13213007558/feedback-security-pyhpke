import threading
from collections.abc import Callable

from .aead import AEADParams
from .consts import ConcurrencyMode
from .exceptions import ConcurrentUseError, MessageLimitReachedError
from .exporter_context import ExporterContext
from .kdf import KDF
from .utils import xor_bytes


class EncryptionContext(ExporterContext):
    def __init__(self, kdf: KDF, aead_params: AEADParams, concurrency: ConcurrencyMode = ConcurrencyMode.NONE):
        self._key = aead_params.ctx.import_key(aead_params.key)
        self._seq = aead_params.seq
        self._nonce = aead_params.base_nonce
        self._nn = aead_params.ctx.nonce_size
        # RFC 9180 Section 5.2: the sequence number must not exceed
        # (1 << (8 * Nn)) - 1, so the last usable value is one below it.
        self._seq_limit = (1 << (8 * self._nn)) - 1
        self._concurrency = concurrency
        # A per-context lock: only calls on this context are serialized,
        # unrelated contexts are never blocked by it.
        self._lock = threading.Lock() if concurrency != ConcurrencyMode.NONE else None
        super().__init__(kdf, aead_params.exporter_secret)
        return

    def _compute_nonce(self) -> bytes:
        if self._seq >= self._seq_limit:
            raise MessageLimitReachedError("Message limit reached.")
        return xor_bytes(self._nonce, self._seq.to_bytes(self._nn, byteorder="big"))

    def _run(self, op: Callable[[bytes], bytes]) -> bytes:
        # RFC 9180 Section 5.2 state transition: the sequence number is
        # committed only after the AEAD operation succeeded, so a failure
        # never consumes a sequence number and the operation can be
        # retried with the same nonce.
        nonce = self._compute_nonce()
        out = op(nonce)
        self._seq += 1
        return out

    def _dispatch(self, op: Callable[[bytes], bytes]) -> bytes:
        if self._lock is None:
            return self._run(op)
        if self._concurrency == ConcurrencyMode.STRICT:
            if not self._lock.acquire(blocking=False):
                raise ConcurrentUseError("The context is in use by another thread.")
            try:
                return self._run(op)
            finally:
                self._lock.release()
        with self._lock:
            return self._run(op)
