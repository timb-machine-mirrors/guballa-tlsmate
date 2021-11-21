# -*- coding: utf-8 -*-
"""Module containing exception definitions
"""


class TlsmateException(Exception):
    """A class all exception for tlsmate are based on.
    """


class ServerMalfunction(TlsmateException):
    """Exception raised in case the server response contains unrecoverable errors.

    This exception basically indicates a specification violation by the server.

    Attributes:
        issue (:obj:`tlsmate.tls.ServerIssue`): the reason for the exception
        message (:obj:`tlsmate.tls.HandshakeType`): the message, if applicable
        extension (:obj:`tlsmate.tls.Extension`): the extension, if applicable
    """

    def __init__(self, issue, message=None, extension=None):
        super().__init__(issue.value)
        self.issue = issue
        self.message = message
        self.extension = extension


class TlsConnectionClosedError(TlsmateException):
    """Exception raised when the TLS connection is closed unexpectedly.

    Attributes:
        exc(Exception): the original exception
    """

    def __init__(self, exc=None):
        self.exc = exc


class TlsMsgTimeoutError(TlsmateException):
    """Exception raised when a message is not received within a given timeout.
    """

    pass


class CurveNotSupportedError(TlsmateException):
    """Exception raised when a curve is negotiated which is not supported.

    Attributes:
        message (str): A human readable string providing the cause
        curve (:class:`tlsmate.tls.SupportedGroups`): The curve has been
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


class OcspError(TlsmateException):
    """Exception for OCSP errors

    Attributes:
        issue (str): A human readable string describing the cause.
    """

    def __init__(self, issue):
        self.issue = issue


class UntrustedCertificate(TlsmateException):
    """Exception for unsuccessful certificate (chain) validation.

    Attributes:
        issue (str): A human readable string describing the cause.
    """

    def __init__(self, issue):
        self.issue = issue


class ServerParmsSignatureInvalid(TlsmateException):
    """More user friendly exception than cryptography.exception.InvalidSignature
    """
