# -*- coding: utf-8 -*-
"""Module containing the class for the client
"""
# import basic stuff
import time
from dataclasses import dataclass, field
from typing import List

# import own stuff
from tlsmate import tls
from tlsmate import ext
from tlsmate import structs
from tlsmate import utils
from tlsmate.msg import ClientHello
from tlsmate.connection import TlsConnection

# import other stuff


@dataclass
class ClientProfile(object):
    """Data class defining the TLS profile of the client.

    The client profile defines the protocol parameters, extensions and features
    which are supported by the client. The data is used when ``tlsmate`` generates
    the ClientHello message autonomously, e.g., when using::

        conn.send(msg.ClientHello)

        or

        conn.handshake()

    The client profile is used as well to check a received ServerHello for
    consistency, e.g., the version provided by the server must be in the
    version list of the client profile.

    Attributes:
        versions (list (:obj:`tlsmate.tls.Version` or int)): The list of protocol
            versions the client shall support. Note, that the highest version
            will be picked to offer it in a ClientHello. For the extension
            SupportedVersions this list will be ordered, so that the highest
            version comes first. Arbitrary integer values can be provided in the
            list as well, allowing to check if the server ignores unknown values.
            Default: []
        compression_methods (list (:obj:`tlsmate.tls.CompressionMethod`)):
            A list of supported compression methods. This list will be used to
            populate the compression list in the ClientHello message.
            Default: [:obj:`tlsmate.tls.CompressionMethod.NULL`]
        cipher_suites (list (:obj:`tlsmate.tls.CipherSuite` or int)):
            A list of cipher suites which will be offered to the server in the
            sequence given. Note, that arbitrary integer values are supported
            as well, allowing to check if the server ignores unknown values.
            Default: []
        support_sni (bool):
            An indication if the SNI extension shall be supported. If True, the SNI
            will be taken from the CLI parameter ``--sni`` or (if not given), from
            the host name. Default: True
        ec_point_formats (list (:obj:`tlsmate.tls.EcPointFormat` or int)): The list
            of ec-point formats supported by the client. If set to None, the
            extension will not be generated. Default: None
        supported_groups (list (:obj:`tlsmate.tls.SupportedGroups` or int)): The list
            of named groups supported by the client. If set to None, the
            extension will not be present in the ClientHello message. Note,
            that arbitrary integer values are supported as well, allowing to
            check if the server ignores unknown values. Default: None
        signature_algorithms (list (:obj:`tlsmate.tls.SignatureScheme` or int)):
            The list of signature algorithms supported by the client. If
            set to None, the extension will not be present in the ClientHello
            message. Note, that arbitrary integer values are supported as
            well, allowing to check if the server ignores unknown values.
            Default: None
        heartbeat_mode (:class:`tlsmate.tls.HeartbeatMode` or None): The mode which is
            offered in the heartbeat extension. If set to None, the extension
            will not be setup when using the :meth:`Client.client_hello`
            method. Default: None
        support_session_id (bool): An indication if the client shall support resumption
            via the session id. Received session ids from the server will be offered
            in subsequent handshakes. Default: False
        support_session_ticket (bool): An indication if the client shall
            support resumption via the extensions SessionTicket. Received
            session tickets from the server will be offered in subsequent
            handshakes. Default: False
        support_extended_master_secret (bool): An indication if the client shall support
            the extensions ExtendedMasterSecret. Default: False
        support_encrypt_then_mac (bool): An indication if the client shall support the
            EncryptThenMac extension. Default: False
        support_secure_renegotiation (bool): An indication if the client shall support
            secure renegotiation. This will generate the RenegotiationInfo extension.
            Default: False
        support_scsv_renegotiation (bool): An indication, if the cipher suite value
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV shall be added to the cipher
            suite list. Only applicable if support_secure_renegotiation is
            True. Default: False
        support_psk (bool): An indication whether the client offers a PSK with
            the ClientHello (i.e. NewSessionTicket message have been received
            before). Default: False
        support_status_request (bool): An indication, if the extensions status request
            shall be supported. Default: False
        support_status_request_v2 (:obj:`tlsmate.tls.StatusType`): The status type of
            the request. NONE is used to suppress the extension.
            Default: NONE
        key_shares (list (:obj:`tlsmate.tls.SupportedGroups` or int)): The list
            of key shares supported for TLS1.3. Note, that arbitrary integer
            values are supported as well, allowing to check if the server
            ignores unknown values. Default: None
        psk_key_exchange_modes (list (:obj:`tlsmate.tls.PskKeyExchangeMode` or int)):
            The list of PSK key exchange modes used in the extension
            psk_key_exchange_modes. Note, that arbitrary integer values are
            supported as well, allowing to check if the server ignores unknown
            values. Default: None
        early_data (bytes): The application data to be sent with 0-RTT. TLS1.3 only.
            If None, then no early data will be sent. Early data can only be sent
            in subsequent abbreviated handshakes. Default: None
    """

    # common for all versions
    versions: List = field(default_factory=lambda: [])
    compression_methods: List = field(
        default_factory=lambda: [tls.CompressionMethod.NULL]
    )
    cipher_suites: List = field(default_factory=lambda: [])

    support_sni: bool = True
    ec_point_formats: List = None
    supported_groups: List = None
    signature_algorithms: List = None
    heartbeat_mode: tls.HeartbeatMode = None
    support_status_request: bool = False
    support_status_request_v2: tls.StatusType = tls.StatusType.NONE

    # TLS1.2 and below
    support_session_id: bool = False
    support_session_ticket: bool = False
    support_extended_master_secret: bool = False
    support_encrypt_then_mac: bool = False
    support_secure_renegotiation: bool = False
    support_scsv_renegotiation: bool = False

    # TLS1.3 specific
    support_psk: bool = False
    key_shares: List = None
    psk_key_exchange_modes: List = None
    early_data: bytes = None


class Client(object):
    """The class representing a TLS client

    Connections are initiated by the TLS client, and it also stores data across
    several connections, like session tickets.

    A TLS client has a dedicated client profile (:obj:`ClientProfile`) which
    controls the TLS connections, e.g. the supported TLS versions, the
    supported cipher suites and other attributes are defined there (e.g. set of
    supported groups, whether encrypt-then-mac is supported, etc.)

    The client profile is used for setting up TLS messages in case only the
    message class and not a message instance is provided in the test case.

    Attributes:
        config (:obj:`tlsmate.config.Configuration`): the configuration object
        session_state_id (:obj:`tlsmate.structs.SessionStateId`): the stored sessions
            state usable to resume a session with the session_id
        session_state_ticket (:obj:`tlsmate.structs.SessionStateTicket`): the stored
            sessions state usable to resume a session with the session_ticket extension
        psks (list of :obj:`tlsmate.structs.Psk`): The TLS1.3 PSKs
        alert_on_invalid_cert (bool): Controls the behavior in case a certificate or
            the complete certificate chain cannot successfully be validated.
            If True, the connection will be closed with a fatal alert. If False,
            the connection continues. The latter is useful for scanning a server, as
            the handshake would be aborted prematurely otherwise.
        server_issues (list of :obj:`tlsmate.tls.ServerIssue`): a list of severe server
            issues.
    """

    def __init__(self, tlsmate):
        """Initialize the client object

        Args:
            tlsmate (:obj:`tlsmate.tlsmate.TlsMate`): the tlsmate application object.
        """
        self._tlsmate = tlsmate
        self.config = tlsmate.config
        self._set_profile_modern()
        self.alert_on_invalid_cert = True
        self.session_state_ticket = None
        self.session_state_id = None
        self.psks = []
        self._host = None
        self.server_issues = []

    def report_server_issue(self, issue, message=None, extension=None):
        """Store a server issue, if not done

        Arguments:
            issue (:obj:tlsmate.tls.`ServerMalfunction`): the reason for the exception
            message (:obj:`tlsmate.tls.HandshakeType`): the message, if applicable
            extension (:obj:`tlsmate.tls.Extension`): the extension, if applicable
        """

        malfunction = structs.Malfunction(
            issue=issue, message=message, extension=extension
        )

        if malfunction not in self.server_issues:
            self.server_issues.append(malfunction)

    def init_profile(self, profile_values=None):
        """Resets the client profile to a very basic state

        :note:
            At least the versions and the cipher_suite list must be provided before
            this profile can be used.

        Compression methods is set to [:obj:`tlsmate.tls.CompressionMethod.NULL`], and
        by default the sni extension is enabled. Everything else is empty or disabled.

        Arguments:
            profile_values (:obj:`tlsmate.structs.ProfileValues`): the profile
                values to additionally use to initialize the client profile
        """

        self.profile = ClientProfile()
        if profile_values is not None:
            self.profile.versions = profile_values.versions[:]
            self.profile.cipher_suites = profile_values.cipher_suites[:]
            if profile_values.supported_groups:
                self.profile.supported_groups = profile_values.supported_groups[:]

            if profile_values.signature_algorithms:
                self.profile.signature_algorithms = profile_values.signature_algorithms[
                    :
                ]

            if profile_values.key_shares:
                self.profile.key_shares = profile_values.key_shares[:]

    def _set_profile_interoperability(self):
        """Define profile for interoperability, like used in modern browsers

        :note:
            This method is deprecated. Use :meth:`Client.set_profile` instead.

        Profile properties:
          - TLS Versions 1.0 - 1.3
          - ECDHE cipher & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-master-secret
          - pskmode psk_dhe
        """
        self.profile = ClientProfile(
            versions=[
                tls.Version.TLS10,
                tls.Version.TLS11,
                tls.Version.TLS12,
                tls.Version.TLS13,
            ],
            cipher_suites=[
                tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            ],
            supported_groups=[
                tls.SupportedGroups.X25519,
                tls.SupportedGroups.SECP256R1,
                tls.SupportedGroups.SECP384R1,
                tls.SupportedGroups.SECP521R1,
            ],
            signature_algorithms=[
                tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.RSA_PKCS1_SHA256,
                tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.RSA_PKCS1_SHA384,
                tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
                tls.SignatureScheme.RSA_PKCS1_SHA512,
                tls.SignatureScheme.ECDSA_SHA1,
                tls.SignatureScheme.RSA_PKCS1_SHA1,
            ],
            key_shares=[tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1],
            psk_key_exchange_modes=[tls.PskKeyExchangeMode.PSK_DHE_KE],
            ec_point_formats=[tls.EcPointFormat.UNCOMPRESSED],
            support_extended_master_secret=True,
            support_session_id=True,
            support_session_ticket=True,
            support_encrypt_then_mac=True,
        )

    def _set_profile_legacy(self):
        """Define profile for legacy like client

        :note:
            This method is deprecated. Use :meth:`Client.set_profile` instead.

        Profile properties:
          - TLS Versions 1.0 - 1.2
          - ECDHE cipher & DHE & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-master-secret
        """

        self.profile = ClientProfile(
            versions=[tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12],
            cipher_suites=[
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            ],
            supported_groups=[
                tls.SupportedGroups.X25519,
                tls.SupportedGroups.SECP256R1,
                tls.SupportedGroups.SECP384R1,
                tls.SupportedGroups.SECP521R1,
            ],
            signature_algorithms=[
                tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.RSA_PKCS1_SHA256,
                tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.RSA_PKCS1_SHA384,
                tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
                tls.SignatureScheme.RSA_PKCS1_SHA512,
                tls.SignatureScheme.ECDSA_SHA1,
                tls.SignatureScheme.RSA_PKCS1_SHA1,
            ],
            ec_point_formats=[tls.EcPointFormat.UNCOMPRESSED],
            support_extended_master_secret=True,
            support_session_id=True,
            support_session_ticket=True,
            support_encrypt_then_mac=True,
        )

    def _set_profile_modern(self):
        """Define profile for "modern" configurations

        :note:
            This method is deprecated. Use :meth:`Client.set_profile` instead.

        Profile properties:
          - TLS Versions 1.2 + 1.3
          - ECDHE cipher
          - AESGCM, CHACHA_POLY
          - signatures: ECDSA + PSS_RSAE
          - Resumption, encrypt-then-mac, extended-master-secret
          - pskmode psk_dhe
        """

        self.profile = ClientProfile(
            versions=[tls.Version.TLS12, tls.Version.TLS13],
            cipher_suites=[
                tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            supported_groups=[
                tls.SupportedGroups.X25519,
                tls.SupportedGroups.SECP256R1,
                tls.SupportedGroups.SECP384R1,
                tls.SupportedGroups.SECP521R1,
            ],
            signature_algorithms=[
                tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            ],
            key_shares=[tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1],
            psk_key_exchange_modes=[tls.PskKeyExchangeMode.PSK_DHE_KE],
            ec_point_formats=[tls.EcPointFormat.UNCOMPRESSED],
            support_sni=True,
            support_extended_master_secret=True,
            support_session_id=True,
            support_session_ticket=True,
        )

    def _set_profile_tls13(self):
        """Define profile for TLS1.3 only.

        :note:
            This method is deprecated. Use :meth:`Client.set_profile` instead.

        Profile properties:
          - TLS Version 1.3
          - AESGCM + CHACHA_POLY
          - pskmode psk_dhe
        """

        self.profile = ClientProfile(
            versions=[tls.Version.TLS13],
            cipher_suites=[
                tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            ],
            supported_groups=[
                tls.SupportedGroups.X25519,
                tls.SupportedGroups.SECP256R1,
                tls.SupportedGroups.SECP384R1,
                tls.SupportedGroups.SECP521R1,
            ],
            signature_algorithms=[
                tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.RSA_PKCS1_SHA256,
                tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.RSA_PKCS1_SHA384,
                tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
                tls.SignatureScheme.RSA_PKCS1_SHA512,
            ],
            key_shares=[tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1],
            psk_key_exchange_modes=[tls.PskKeyExchangeMode.PSK_DHE_KE],
            ec_point_formats=[tls.EcPointFormat.UNCOMPRESSED],
            support_sni=True,
        )

    def set_profile(self, profile):
        """Initializes the client according to the given profile.

        The following profiles are supported:

        - :obj:`tlsmate.tls.Profile.INTEROPERABILITY`

          - TLS Versions 1.0 - 1.3
          - ECDHE cipher & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-master-secret
          - pskmode psk_dhe

        - :obj:`tlsmate.tls.Profile.LEGACY`

          - TLS Versions 1.0 - 1.2
          - ECDHE cipher & DHE & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-master-secret

        - :obj:`tlsmate.tls.Profile.MODERN`

          - TLS Versions 1.2 + 1.3
          - ECDHE cipher
          - AESGCM, CHACHA_POLY
          - signatures: ECDSA + PSS_RSAE
          - Resumption, encrypt-then-mac, extended-master-secret
          - pskmode psk_dhe

        - :obj:`tlsmate.tls.Profile.TLS13`

          - TLS Version 1.3
          - AESGCM + CHACHA_POLY
          - pskmode psk_dhe

        Arguments:
            profile (:obj:`tlsmate.tls.Profile`): the profile to which the client
                shall be initialized.
        """
        if profile is tls.Profile.INTEROPERABILITY:
            self._set_profile_interoperability()
        elif profile is tls.Profile.TLS13:
            self._set_profile_tls13()
        elif profile is tls.Profile.MODERN:
            self._set_profile_modern()
        elif profile is tls.Profile.LEGACY:
            self._set_profile_legacy()
        else:
            raise ValueError(f"client profile {profile} unknown")

    def create_connection(self, host=None, port=None):
        """Create a new connection object

        Arguments:
            host (str): the host to contact. If not given, the host
                is taken from the configuration. The given string can be
                a URL or an IP address.
            port (int): the port number

        Returns:
            :obj:`tlsmate.connection.TlsConnection`: the created connection object
        """

        self._host = host if host is not None else self.config.get("host")

        interval = self.config.get("interval")
        if interval:
            time.sleep(interval / 1000)

        return TlsConnection(self._tlsmate, self._host)

    def save_session_state_id(self, session_state):
        """Save a session state

        Args:
            session_state (:obj:`tlsmate.structs.SessionStateId`): A session
                state to be stored on the client level, usable to resume
                connections using the session_id
        """
        self.session_state_id = session_state

    def get_session_state_id(self):
        """Get the session state (id)

        Returns:
            :obj:`tlsmate.structs.SessionStateId`: the session state to resume a
            session from
        """
        return self.session_state_id

    def save_session_state_ticket(self, session_state):
        """Save a session state

        Args:
            session_state (:obj:`tlsmate.structs.SessionStateId`): A session state to be
                stored on the client level, usable to resume connections using the
                session ticket.
        """
        self.session_state_ticket = session_state

    def get_session_state_ticket(self):
        """Get the session state (ticket)

        Returns:
            :obj:`tlsmate.structs.SessionStateTicket`: the session state to resume a
            session from
        """
        return self.session_state_ticket

    def save_psk(self, psk):
        """Save a TLS1.3 PSK

        Arguments:
            psk (:obj:`tlsmate.structs.Psk`): A pre-shared key be stored on the
                client level, usable to resume connections using the pre-shared key
                extension.
        """
        self.psks.append(psk)

    def get_sni(self):
        """Get the current SNI

        Returns:
            str: the SNI

        Raises:
            ValueError: if no SNI can be determined
        """

        sni = self.config.get("sni")
        if sni is not None:
            return sni

        sni = self._host
        if sni is not None:
            return sni

        return self.config.get("host")

    def client_hello(self):
        """Populate a ClientHello message according to the current client profile

        Returns:
            :obj:`tlsmate.msg.ClientHello`: the ClientHello object
        """
        msg = ClientHello()
        max_version = max(self.profile.versions)
        if max_version is tls.Version.TLS13:
            msg.version = tls.Version.TLS12

        else:
            msg.version = max_version

        msg.random = None  # will be provided autonomously

        if (
            self.profile.support_session_ticket
            and self.session_state_ticket is not None
        ):
            msg.session_id = bytes.fromhex("dead beef")

        elif self.profile.support_session_id and self.session_state_id is not None:
            msg.session_id = self.session_state_id.session_id

        else:
            msg.session_id = b""

        msg.cipher_suites = self.profile.cipher_suites[:]

        msg.compression_methods = self.profile.compression_methods
        if msg.version == tls.Version.SSL30:
            msg.extensions = None

        else:
            if self.profile.support_sni:
                msg.extensions.append(
                    ext.ExtServerNameIndication(host_name=self.get_sni())
                )

            if self.profile.support_extended_master_secret:
                msg.extensions.append(ext.ExtExtendedMasterSecret())

            if self.profile.ec_point_formats is not None:
                msg.extensions.append(
                    ext.ExtEcPointFormats(
                        ec_point_formats=self.profile.ec_point_formats
                    )
                )

            if self.profile.supported_groups is not None:
                if max_version is tls.Version.TLS13 or bool(
                    utils.filter_cipher_suites(
                        msg.cipher_suites, key_exch=[tls.KeyExchangeType.ECDH]
                    )
                ):
                    msg.extensions.append(
                        ext.ExtSupportedGroups(
                            supported_groups=self.profile.supported_groups
                        )
                    )

            if self.profile.support_status_request_v2 is not tls.StatusType.NONE:
                msg.extensions.append(
                    ext.ExtStatusRequestV2(
                        status_type=self.profile.support_status_request_v2
                    )
                )

            if self.profile.support_status_request:
                msg.extensions.append(ext.ExtStatusRequest())

            # RFC5246, 7.4.1.4.1.: Clients prior to TLS12 MUST NOT send this extension
            if (
                self.profile.signature_algorithms is not None
                and max_version >= tls.Version.TLS12
            ):
                msg.extensions.append(
                    ext.ExtSignatureAlgorithms(
                        signature_algorithms=self.profile.signature_algorithms
                    )
                )

            if self.profile.support_encrypt_then_mac:
                msg.extensions.append(ext.ExtEncryptThenMac())

            if self.profile.support_session_ticket:
                kwargs = {}
                if self.session_state_ticket is not None:
                    kwargs["ticket"] = self.session_state_ticket.ticket

                msg.extensions.append(ext.ExtSessionTicket(**kwargs))

            if self.profile.heartbeat_mode:
                msg.extensions.append(
                    ext.ExtHeartbeat(heartbeat_mode=self.profile.heartbeat_mode)
                )

            if tls.Version.TLS13 in self.profile.versions:
                if self._tlsmate.recorder.inject(
                    client_auth=self._tlsmate.client_auth.supported()
                ):
                    msg.extensions.append(ext.ExtPostHandshakeAuth())

                self._key_share_objects = []

                msg.extensions.append(
                    ext.ExtSupportedVersions(
                        versions=sorted(self.profile.versions, reverse=True)
                    )
                )
                # TLS13 key shares: enforce the same sequence as in supported groups
                if self.profile.key_shares:
                    key_shares = [
                        group
                        for group in self.profile.supported_groups
                        if group in self.profile.key_shares
                    ]
                    msg.extensions.append(ext.ExtKeyShare(key_shares=key_shares))

                if self.profile.early_data is not None:
                    msg.extensions.append(ext.ExtEarlyData())

                if self.profile.support_psk and self.psks:
                    msg.extensions.append(
                        ext.ExtPskKeyExchangeMode(
                            modes=self.profile.psk_key_exchange_modes
                        )
                    )
                    msg.extensions.append(ext.ExtPreSharedKey(psks=self.psks[:1]))

        return msg
