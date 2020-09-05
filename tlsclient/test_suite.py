# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import tlsclient.tls_message as msg
import tlsclient.constants as tls
import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData

class TestSuite(object):
    def __init__(self, logger, server_profile, tls_connection_factory):
        self.logger = logger
        self.server_profile = server_profile
        self.create_connection = tls_connection_factory

    def run(self):
        print("Ok, we run")
        client_hello = msg.ClientHello()
        client_hello.client_version = tls.Version.TLS12
        client_hello.cipher_suites = [
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
        client_hello.compression_methods = [tls.CompressionMethod.NULL]
        client_hello.extensions = [
                ext.ExtServerNameIndication(host_name="localhost"),
                ext.ExtExtendedMasterSecret(),
                ext.ExtRenegotiationInfo(opaque=ProtocolData(b"\0")),
                ext.ExtEcPointFormats(),
                ext.ExtSupportedGroups(supported_groups=[
                    tls.SupportedGroups.X25519,
                    tls.SupportedGroups.SECP256R1,
                    tls.SupportedGroups.SECP384R1,
                    tls.SupportedGroups.SECP521R1,
                    tls.SupportedGroups.FFDHE2048,
                    tls.SupportedGroups.FFDHE4096
                    ]),
                ext.ExtSignatureAlgorithms(signature_algorithms=[
                    tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                    tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                    tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
                    tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                    tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                    tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
                    tls.SignatureScheme.RSA_PKCS1_SHA256,
                    tls.SignatureScheme.RSA_PKCS1_SHA384,
                    tls.SignatureScheme.RSA_PKCS1_SHA512,
                    tls.SignatureScheme.ECDSA_SHA1,
                    tls.SignatureScheme.RSA_PKCS1_SHA1
                    ])
                ]

        with self.create_connection() as conn:
            conn.send(client_hello)
