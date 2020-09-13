# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import tlsclient.tls_message as msg
import tlsclient.constants as tls
import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData

class TestSuite(object):
    def __init__(self, logger, server_profile, client_profile_factory):
        self.logger = logger
        self.server_profile = server_profile
        self.create_client_profile = client_profile_factory


    def run(self):
        print("Ok, we run")

        client_profile = self.create_client_profile()
        client_profile.tls_versions = [tls.Version.TLS12]
        client_profile.cipher_suites = [
            #tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            #tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            #tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            #tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            #tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            #tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            #tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            #tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            #tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            #tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            #tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            #tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            #tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ]
        client_profile.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
            tls.SupportedGroups.FFDHE2048,
            tls.SupportedGroups.FFDHE4096
        ]
        client_profile.signature_algorithms = [
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
        ]

        with client_profile.create_connection() as conn:
            # conn.open_socket()
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            conn.wait(msg.ServerKeyExchange, optional=True)
            conn.wait(msg.ServerHelloDone)
            conn.tls_connection_state.update_keys()
            conn.send(msg.ClientKeyExchange, msg.ChangeCipherSpec, msg.Finished)
            #conn.send(msg.ClientKeyExchange)
            #conn.send(msg.ChangeCipherSpec)

