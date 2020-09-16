# -*- coding: utf-8 -*-
"""Module containing the class for the client profile
"""
import tlsclient.constants as tls
from tlsclient.protocol import ProtocolData


class ClientProfile(object):
    def __init__(self, tls_connection_factory, server_name):
        self.tls_connection_factory = tls_connection_factory
        self.versions = [tls.Version.TLS12]
        self.cipher_suites = [
            tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        ]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.support_session_id = False

        self.support_session_ticket = False
        self.session_id = ProtocolData()

        self.support_sni = True
        self.server_name = server_name

        self.support_extended_master_secret = False

        self.support_ec_point_formats = False
        self.ec_point_formats = [tls.EcPointFormat.UNCOMPRESSED]

        self.support_supported_groups = True
        self.supported_groups = [tls.SupportedGroups.SECP256R1]

        self.support_signature_algorithms = True
        self.signature_algorithms = [tls.SignatureScheme.RSA_PSS_RSAE_SHA256]

    def create_connection(self):
        return self.tls_connection_factory().set_profile(self)
