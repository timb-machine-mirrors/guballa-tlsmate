# -*- coding: utf-8 -*-
"""Module containing the class for the client client
"""
import tlsmate.constants as tls
import tlsmate.extensions as ext
from tlsmate.messages import ClientHello
from tlsmate.cert import TrustStore, CertChain
import pem
from cryptography.hazmat.primitives import serialization


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
        config (dict): contains the configuration
        compression_methods (list of :obj:`CompressionMethod`):
            a list of supported compression methods. This list will be used to
            populate the compression list in the ClientHello message.
            Default: [CompressionMethod.NULL]

        support_session_id (bool): An indication if the client supports resumption
            via the session id.

        session_state_id (:obj:`SessionStateId`): the stored sessions state usable to
            resume a session with the session_id
        support_session_ticket: (bool): An indication if the client supports
            resumption via the session_ticket extension
        session_state_ticket (:obj`SessionStateTicket`): the stored sessions state
            usable to resume a session with the session_ticket extension
        support_sni (bool):
            an indication if the SNI extension is supported
        server_name (str):
            the server name which will included in the SNI extension
        support_extended_master_secret (bool): an indication if the client supports
            the extensions EXTENDED_MASTER_SECRET
        support_ec_point_formats (bool): an indication if the client supports
            the extension EC_POINT_FORMATS
        ec_point_formats (list of :obj:`EcPointFormat`): the list of supported
            ec-point formats supported by the client. Default:
            EcPointFormat.UNCOMPRESSED
        supported_groups (list of :obj:`SupportedGroups`): the list of supported
            groups supported by the client. If set to [] or None, the extension
            will not be present in the ClientHello message.
        signature_algorithms (list of :obj:`SignatureScheme`): the list of
            signature algorithms supported by the client. If set to [] or None, the
            extension will not be present in the ClientHello message.
        support_encrypt_then_mac (bool): an indication if the client supports the
            encrypt-then-mac extension
        key_shares (list of :obj:`SupportedGroups`): this list of key share ob
            supported for TLS1.3.
        support_psk (bool): and indication whether the client offers a PSK with
            the ClientHello (i.e. NewSessionTicket message have been received before).
        psks (list of :obj:`Psk`): The TLS1.3 PSKs
        psk_key_exchange_modes (list of :obj:`tlsmate.constants.PskKeyExchangeMode`):
            the list of PSK key exchange modes used in the extension
            psk_key_exchange_modes.
        early_data (bytes): The application data to be sent with 0-RTT. TLS1.3 only.
            If None, then no early data will be sent.
        alert_on_invalid_cert (bool): Controls the behavior in case a certificate or
            the complete certificate chain cannot successfully be validated.
            If True, the connected will be closed with a fatal alert. If False,
            the connection continues. The latter is useful for scanning a server, as
            the scan would be aborted otherwise.
    """

    def __init__(self, connection_factory, config):
        """Initialize the client object

        Args:
            connection_factory: method used to create a new connction object
            config: the configuration object
        """
        self.connection_factory = connection_factory
        self.config = config
        self.reset_profile()
        ca_files = config["ca_certs"]
        self.trust_store = TrustStore(ca_files=ca_files)
        self.client_keys = []
        self.client_chains = []
        self._read_client_files(config)

    def _read_client_files(self, config):
        if config["client_key"] is not None:
            for key_file in config["client_key"]:
                with open(key_file, "rb") as fd:
                    self.client_keys.append(
                        serialization.load_pem_private_key(fd.read(), password=None)
                    )

        if config["client_chain"] is not None:
            for chain_file in config["client_chain"]:
                client_chain = CertChain()
                pem_list = pem.parse_file(chain_file)
                for pem_item in pem_list:
                    client_chain.append_pem_cert(pem_item.as_bytes())
                self.client_chains.append(client_chain)

    def reset_profile(self):
        """Resets the client profile to a very basic state

        :note:
            At least the versions and the cipher_suite list must be provided before
            this profile can be used.

        Compression methods is set to [tls.CompressionMethod.NULL], and by default
        the sni extention is enabled. Everything else is empty or disabled.
        """
        self.versions = []
        self.cipher_suites = []
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.support_session_id = False
        self.session_state_id = None

        self.support_session_ticket = False
        self.session_state_ticket = None

        self.support_sni = True
        self.server_name = self.config["server"]

        self.support_extended_master_secret = False

        self.support_ec_point_formats = False
        self.ec_point_formats = []

        self.supported_groups = None

        self.signature_algorithms = None

        # TLS13
        self.key_shares = []
        self.support_psk = False
        self.psks = []
        self.psk_key_exchange_modes = []
        self.early_data = None

        self.support_encrypt_then_mac = False
        self.alert_on_invalid_cert = True

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

    def save_psk(self, psk):
        """Save a TLS1.3 PSK

        Args:
            psk (:obj:`Psk`): A pre-shared key be stored on the client level, usable
            to resume connections using the pre-shared key extension.
        """
        self.psks.append(psk)

    def client_hello(self):
        """Populate a ClientHello message according to the current client profile

        Returns:
            :obj:`ClientHello`: the ClientHello object
        """
        msg = ClientHello()
        max_version = max(self.versions)
        if max_version is tls.Version.TLS13:
            msg.version = tls.Version.TLS12

        else:
            msg.version = max_version

        msg.random = None  # will be provided autonomously

        if self.support_session_ticket and self.session_state_ticket is not None:
            msg.session_id = bytes.fromhex("dead beaf")

        elif self.support_session_id and self.session_state_id is not None:
            msg.session_id = self.session_state_id.session_id

        else:
            msg.session_id = b""

        msg.cipher_suites = self.cipher_suites
        msg.compression_methods = self.compression_methods
        if msg.version == tls.Version.SSL30:
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

            if self.supported_groups:
                msg.extensions.append(
                    ext.ExtSupportedGroups(supported_groups=self.supported_groups)
                )

            # RFC5246, 7.4.1.4.1.: Clients prior to TLS12 MUST NOT send this extension
            if self.signature_algorithms and max_version >= tls.Version.TLS12:
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

            if tls.Version.TLS13 in self.versions:
                if self.client_keys:
                    msg.extensions.append(ext.ExtPostHandshakeAuth())

                self._key_share_objects = []
                msg.extensions.append(ext.ExtSupportedVersions(versions=self.versions))
                # TLS13 key shares: enforce the same sequence as in supported groups
                key_shares = []
                if not self.key_shares:
                    self.key_shares = self.supported_groups

                for group in self.supported_groups:
                    if group in self.key_shares:
                        key_shares.append(group)

                msg.extensions.append(ext.ExtKeyShare(key_shares=key_shares))
                if self.early_data is not None:
                    msg.extensions.append(ext.ExtEarlyData())

                if self.support_psk and self.psks:
                    msg.extensions.append(
                        ext.ExtPskKeyExchangeMode(modes=self.psk_key_exchange_modes)
                    )
                    msg.extensions.append(ext.ExtPreSharedKey(psks=self.psks[:1]))

        return msg
