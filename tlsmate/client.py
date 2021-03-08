# -*- coding: utf-8 -*-
"""Module containing the class for the client client
"""
# import basic stuff
# import own stuff
from tlsmate import tls
from tlsmate import ext
from tlsmate import resolver
from tlsmate.msg import ClientHello
from tlsmate.connection import TlsConnection

# import other stuff


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
        sni (str):
            the SNI to use in the ClientHello. If None, the value will be taken from
            the configuration (config["sni"]). If this is None as well, it will be
            the host_name of the server.
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

    def __init__(self, tlsmate):
        # TODO: Update
        """Initialize the client object

        Args:
            connection_factory: method used to create a new connction object
            config: the configuration object
        """
        self._tlsmate = tlsmate
        self.config = tlsmate.config
        self.set_profile_modern()

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
        self.sni = None

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
        self.support_secure_renegotiation = False
        self.support_scsv_renegotiation = False

    def set_profile_interoperability(self):
        """Define profile for interoperability, like used in modern browsers

        Properties:
          - TLS Versions 1.0 - 1.3
          - ECDHE cipher & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-mastersecret
          - pskmode psk_dhe
        """
        self.reset_profile()
        self.versions = [
            tls.Version.TLS10,
            tls.Version.TLS11,
            tls.Version.TLS12,
            tls.Version.TLS13,
        ]
        self.cipher_suites = [
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
        ]
        self.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
        ]
        self.key_shares = [tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1]
        self.psk_key_exchange_modes = [tls.PskKeyExchangeMode.PSK_DHE_KE]
        self.signature_algorithms = [
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
        ]
        self.support_ec_point_formats = True
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]
        self.support_sni = True
        self.support_extended_master_secret = True
        self.support_session_id = True
        self.support_session_ticket = True
        self.support_encrypt_then_mac = True

    def set_profile_legacy(self):
        """Define profile for legacy like client

        Properties:
          - TLS Versions 1.0 - 1.2
          - ECDHE cipher & DHE & RSA-based key transport
          - AESGCM, AES, CHACHA_POLY and 3DES as last resort
          - Signature algorithms: ECDSA+SHA1, RSA PKCS1+SHA1 as last resort
          - Resumption, encrypt-then-mac, extended-mastersecret
        """
        self.reset_profile()
        self.versions = [
            tls.Version.TLS10,
            tls.Version.TLS11,
            tls.Version.TLS12,
        ]
        self.cipher_suites = [
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
        ]
        self.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
        ]
        self.signature_algorithms = [
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
        ]
        self.support_ec_point_formats = True
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]
        self.support_sni = True
        self.support_extended_master_secret = True
        self.support_session_id = True
        self.support_session_ticket = True
        self.support_encrypt_then_mac = True

    def set_profile_modern(self):
        """Define profile for "modern" configurations

        Properties:
          - TLS Versions 1.2 + 1.3
          - ECDHE cipher
          - AESGCM, CHACHA_POLY
          - signatures: ECDSA + PSS_RSAE
          - Resumption, encrypt-then-mac, extended-mastersecret
          - pskmode psk_dhe
        """
        self.reset_profile()
        self.versions = [tls.Version.TLS12, tls.Version.TLS13]
        self.cipher_suites = [
            tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]
        self.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
        ]
        self.key_shares = [tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1]
        self.psk_key_exchange_modes = [tls.PskKeyExchangeMode.PSK_DHE_KE]
        self.signature_algorithms = [
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
        ]
        self.support_ec_point_formats = True
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]
        self.support_sni = True
        self.support_extended_master_secret = True
        self.support_session_id = True
        self.support_session_ticket = True

    def set_profile_tls13(self):
        """Define profile for TLS1.3 only.

        Properties:
          - TLS Version 1.3
          - AESGCM + CHACHA_POLY
          - pskmode psk_dhe
        """
        self.reset_profile()
        self.versions = [tls.Version.TLS13]
        self.cipher_suites = [
            tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            tls.CipherSuite.TLS_AES_256_GCM_SHA384,
        ]
        self.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
        ]
        self.key_shares = [tls.SupportedGroups.X25519, tls.SupportedGroups.SECP256R1]
        self.psk_key_exchange_modes = [tls.PskKeyExchangeMode.PSK_DHE_KE]
        self.signature_algorithms = [
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.RSA_PKCS1_SHA384,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            tls.SignatureScheme.RSA_PKCS1_SHA512,
        ]
        self.support_ec_point_formats = True
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]
        self.support_sni = True

    def set_profile(self, profile):
        if profile is tls.Profile.INTEROPERABILITY:
            self.set_profile_interoperability()
        elif profile is tls.Profile.TLS13:
            self.set_profile_tls13()
        elif profile is tls.Profile.MODERN:
            self.set_profile_modern()
        elif profile is tls.Profile.LEGACY:
            self.set_profile_legacy()
        else:
            raise ValueError(f"client profile {profile} unknown")

    def create_connection(self, server=None):
        """Create a new connection object

        Returns:
            :obj:`TlsConnection`: the created connection object
        """
        if server is None:
            server = self.config["endpoint"]

        return TlsConnection(self._tlsmate, server)

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

    def get_sni(self):
        """Get the current SNI

        Returns:
            str: the SNI

        Raises:
            ValueError: if no SNI can be determined
        """
        if self.sni is not None:
            return self.sni

        elif self.config["sni"] is not None:
            return self.config["sni"]

        else:
            endp = resolver.determine_transport_endpoint(self.config["endpoint"])
            if endp.host_type is tls.HostType.HOST:
                return endp.host

        raise ValueError("No SNI defined")

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

        msg.cipher_suites = self.cipher_suites.copy()

        msg.compression_methods = self.compression_methods
        if msg.version == tls.Version.SSL30:
            msg.extensions = None

        else:
            if self.support_sni:
                msg.extensions.append(
                    ext.ExtServerNameIndication(host_name=self.get_sni())
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
                if self._tlsmate.recorder.inject(
                    client_auth=self._tlsmate.client_auth.supported()
                ):
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
