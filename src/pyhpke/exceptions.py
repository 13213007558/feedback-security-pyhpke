class PyHPKEError(Exception):
    """
    Base class for all exceptions.
    """

    pass


class NotSupportedError(PyHPKEError):
    """
    An Exception occurred when the function is not supported.
    """

    pass


class SealError(PyHPKEError):
    """
    An Exception occurred when an encryption process failed.
    """

    pass


class OpenError(PyHPKEError):
    """
    An Exception occurred when an decryption process failed.
    """

    pass


class MessageLimitReachedError(PyHPKEError):
    """
    An Exception occurred when the sequence number of a context reached
    the limit defined in RFC 9180 and no further messages can be
    encrypted or decrypted with it. The context state is left unchanged.
    """

    pass


class ConcurrentUseError(PyHPKEError):
    """
    An Exception occurred when a context configured with
    ``ConcurrencyMode.STRICT`` is used concurrently. The context state
    is left unchanged and the operation can be retried later.
    """

    pass
