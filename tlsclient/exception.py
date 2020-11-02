# -*- coding: utf-8 -*-
"""Module containing exception definitions
"""


class FatalAlert(Exception):
    """Exception which leads to the closure of the TLS connection with a fatal alert.

    Attributes:
        message (str): A human readable string providing the cause
        description (:obj:`tlsclient.constants.AlertDescription`): an enum used in the
            alert sent to the peer.
    """

    def __init__(self, message, description):
        self.description = description
        self.message = message


class TLSConnectionClosedError(Exception):
    """Exception raised when the TLS connection is closed.
    """
    pass


class CurveNotSupportedError(Exception):
    """Exception if a curve is negotiated which we do not support

    Attributes:
        message (str): A human readable string providing the cause
        curve (:class:`tlsclient.constants.SupportedGroups`): The curve has been
            offered by the client, and selected by the server, but it is not
            supported for a full key exchange.
    """

    def __init__(self, message, curve):
        self.message = message
        self.curve = curve


class ScanError(Exception):
    """Execption which might occur during a scan.

    The exception will be raised if an abnormal condition during a scan is
    detected.

    Attributes:
        message (str): A human readable string describing the cause.
    """

    def __init__(self, message):
        self.message = message
