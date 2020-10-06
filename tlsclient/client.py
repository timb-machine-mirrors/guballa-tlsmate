# -*- coding: utf-8 -*-
"""Module containing the class for the client client
"""
import tlsclient.constants as tls
import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData
from tlsclient.messages import ClientHello


class Client(object):
    """The class representing a TLS client

    Connections are inititiated by the TLS client, and it also stores
    data across several connections, like session tickets.

    A TLS client has a dedicated profile which controls the TLS connections,
    e.g. the supported TLS versions, the supported cipher suites and other
    attributes are defined there (e.g. set of supported groups, whether
    encrypt-then-mac is supported, etc.)

    The profile is used for setting up TLS messages in case only the message class
    and not a message instance is provided in the test case.

    Attributes:
        compression_methods (list of :obj:`CompressionMethod`): a list of
            supported compression methods. This list will be used to populate
            the compression list in the ClientHello message.
            Default: [CompressionMethod.NULL]
        support_session_id (bool): An indication if the client supports resumption
            via the session id.
        session_state_id (:obj:`SessionStateId`): the stored sessions state usable to
            resume a session with the session_id
        support_session_ticket: (bool): An indication if the client supports
            resumption via the session_ticket extension
        session_state_ticket (:obj`SessionStateTicket`): the stored sessions state
            usable to resume a session with the session_ticket extension
        support_sni (bool): an indication if the SNI extension is supported
        server_name (str): the server name which will included in the SNI extension
        support_extended_master_secret (bool): an indication if the client supports
            the extensions EXTENDED_MASTER_SECRET
        support_ec_point_formats (bool): an indication if the client supports
            the extension EC_POINT_FORMATS
        ec_point_formats (list of :obj:`EcPointFormat`): the list of supported
            ec-point formats supported by the client. Default:
            EcPointFormat.UNCOMPRESSED
        support_supported_groups (bool): an indication if the client supports the
            supported-group extension.
        supported_groups (list of :obj:`SupportedGroups`): the list of supported
            groups supported by the client
        support_signature_algorithms (bool): an indication if the client supports the
            signature_algorithms extensions.
        signature_algorithms (list of :obj:`SignatureScheme`): the list of
            signature algorithms supported by the client
        support_encrypt_then_mac (bool): an indication if the client supports the
            encrypt-then-mac extension
    """

    def __init__(self, connection_factory, server_name):
        """Initialize the client object

        Args:
            connection_factory: method used to create a new connction object
            server_name: the name of the server to connect to
        """
        self.connection_factory = connection_factory
        self.versions = [tls.Version.TLS12]
        self.cipher_suites = [
            tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        ]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.support_session_id = False
        self.session_state_id = None

        self.support_session_ticket = False
        self.session_state_ticket = None

        self.support_sni = True
        self.server_name = server_name

        self.support_extended_master_secret = False

        self.support_ec_point_formats = False
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]

        self.support_supported_groups = True
        self.supported_groups = [tls.SupportedGroups.SECP256R1]

        self.support_signature_algorithms = True
        self.signature_algorithms = [tls.SignatureScheme.RSA_PSS_RSAE_SHA256]

        self.support_encrypt_then_mac = False

    def create_connection(self):
        """Create a new connection object

        Returns:
            :obj:`TlsConnection`: the created connection object
        """
        return self.connection_factory().set_client(self)

    def save_session_state_id(self, session_state):
        """Save a session state

        Args:
            session_state (:obj:`SessionStateId`): A session state to be stored on
                the client level, usable to resume connections using the session_id
        """
        self.session_state_id = session_state

    def get_session_state_id(self):
        """Get the session state (id)

        Returns:
            :obj:`SessionStateId`: the session state to resume a session from
        """
        return self.session_state_id

    def save_session_state_ticket(self, session_state):
        """Save a session state

        Args:
            session_state (:obj:`SessionStateId`): A session state to be stored on
                the client level, usable to resume connections using the session ticket.
        """
        self.session_state_ticket = session_state

    def get_session_state_ticket(self):
        """Get the session state (ticket)

        Returns:
            :obj:`SessionStateTicket`: the session state to resume a session from
        """
        return self.session_state_ticket

    def client_hello(self):
        """Populate a ClientHello message according to the current client profile

        Returns:
            :obj:`ClientHello`: the ClientHello object
        """
        msg = ClientHello()
        msg.client_version = max(self.versions)
        msg.random = None  # will be provided autonomously

        if self.support_session_ticket and self.session_state_ticket is not None:
            msg.session_id = ProtocolData().fromhex("dead beaf")
        elif self.support_session_id and self.session_state_id is not None:
            msg.session_id = self.session_state_id.session_id
        else:
            msg.session_id = ProtocolData()
        msg.cipher_suites = self.cipher_suites
        msg.compression_methods = self.compression_methods
        if msg.client_version == tls.Version.SSL30:
            msg.extensions = None
        else:
            if self.support_sni:
                msg.extensions.append(
                    ext.ExtServerNameIndication(host_name=self.server_name)
                )
            if self.support_extended_master_secret:
                msg.extensions.append(ext.ExtExtendedMasterSecret())
            if self.support_ec_point_formats:
                msg.extensions.append(
                    ext.ExtEcPointFormats(ec_point_formats=self.ec_point_formats)
                )
            if self.support_supported_groups:
                msg.extensions.append(
                    ext.ExtSupportedGroups(supported_groups=self.supported_groups)
                )
            if self.support_signature_algorithms:
                msg.extensions.append(
                    ext.ExtSignatureAlgorithms(
                        signature_algorithms=self.signature_algorithms
                    )
                )
            if self.support_encrypt_then_mac:
                msg.extensions.append(ext.ExtEncryptThenMac())
            if self.support_session_ticket:
                kwargs = {}
                if self.session_state_ticket is not None:
                    kwargs["ticket"] = self.session_state_ticket.ticket
                msg.extensions.append(ext.ExtSessionTicket(**kwargs))
        return msg
