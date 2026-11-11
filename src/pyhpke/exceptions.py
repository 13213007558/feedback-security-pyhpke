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


class InvalidModeError(PyHPKEError):
    """
    An Exception occurred when the explicitly selected HPKE mode does not match
    the supplied parameters (PSK/PSK id pairing or static authentication keys).
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
