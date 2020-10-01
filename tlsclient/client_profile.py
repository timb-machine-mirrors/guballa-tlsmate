# -*- coding: utf-8 -*-
"""Module containing the class for the client profile
"""
import tlsclient.constants as tls
import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData
from tlsclient.messages import ClientHello


class ClientProfile(object):
    def __init__(self, connection_factory, server_name):
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
        return self.connection_factory().set_profile(self)

    def save_session_state_id(self, session_state):
        self.session_state_id = session_state

    def get_session_state_id(self):
        return self.session_state_id

    def save_session_state_ticket(self, session_state):
        self.session_state_ticket = session_state

    def client_hello(self):
        """Returns an instance of the ClientHello, populated according to the profile
        """
        msg = ClientHello()
        msg.client_version = max(self.versions)
        msg.random = None  # will be provided autonomously
        if self.session_state_id is None:
            msg.session_id = ProtocolData()
        else:
            msg.session_id = self.session_state_id.session_id
        msg.cipher_suites = self.cipher_suites
        msg.compression_methods = self.compression_methods
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
        return msg
