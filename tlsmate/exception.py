# -*- coding: utf-8 -*-
"""Module containing exception definitions
"""


class TlsmateException(Exception):
    """A class all exception for tlsmate are based on
    """


class FatalAlert(TlsmateException):
    """Exception which leads to the closure of the TLS connection with a fatal alert.

    Attributes:
        message (str): A human readable string providing the cause
        description (:obj:`tlsmate.constants.AlertDescription`): an enum used in the
            alert sent to the peer.
    """

    def __init__(self, message, description):
        self.description = description
        self.message = message


class TlsConnectionClosedError(TlsmateException):
    """Exception raised when the TLS connection is closed.
    """

    pass


class TlsMsgTimeoutError(TlsmateException):
    """Exception raised when message is not received within timeout
    """

    pass


class CurveNotSupportedError(TlsmateException):
    """Exception if a curve is negotiated which we do not support

    Attributes:
        message (str): A human readable string providing the cause
        curve (:class:`tlsmate.constants.SupportedGroups`): The curve has been
            offered by the client, and selected by the server, but it is not
            supported for a full key exchange.
    """

    def __init__(self, message, curve):
        self.message = message
        self.curve = curve


class ScanError(TlsmateException):
    """Exception which might occur during a scan.

    The exception will be raised if an abnormal condition during a scan is
    detected.

    Attributes:
        message (str): A human readable string describing the cause.
    """

    def __init__(self, message):
        self.message = message


class CertValidationError(TlsmateException):
    """Exception for certificate validation errors

    Attributes:
        issue (str): A human readable string describing the cause.
    """

    def __init__(self, issue):
        self.issue = issue


class CertChainValidationError(TlsmateException):
    """Exception for certificate chain validation errors

    Attributes:
        issue (str): A human readable string describing the cause.
    """

    def __init__(self, issue):
        self.issue = issue


class ServerParmsSignatureInvalid(TlsmateException):
    """More user friendly exception than cryptography.exception.InvalidSignature
    """

    pass
