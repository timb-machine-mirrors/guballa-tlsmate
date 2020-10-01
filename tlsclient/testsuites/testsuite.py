# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import logging
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite


@TestManager.register
class MyTestSuite(TestSuite):
    name = "My private Test"
    prio = 10

    def run(self):
        client_profile = self.client_profile
        client_profile.versions = [tls.Version.TLS12]
        client_profile.cipher_suites = [
            # tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            # tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA,
            # tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        ]
        client_profile.supported_groups = [
            # tls.SupportedGroups.X25519,
            # tls.SupportedGroups.X448,
            # tls.SupportedGroups.SECT163K1,
            # tls.SupportedGroups.SECT163R2,
            # tls.SupportedGroups.SECT233K1,
            # tls.SupportedGroups.SECT233R1,
            # tls.SupportedGroups.SECT283K1,
            # tls.SupportedGroups.SECT283R1,
            # tls.SupportedGroups.SECT409K1,
            # tls.SupportedGroups.SECT409R1,
            # tls.SupportedGroups.SECT571K1,
            # tls.SupportedGroups.SECT571R1,
            # tls.SupportedGroups.SECP224R1,
            # tls.SupportedGroups.SECP256K1,
            # tls.SupportedGroups.BRAINPOOLP256R1,
            # tls.SupportedGroups.BRAINPOOLP384R1,
            # tls.SupportedGroups.BRAINPOOLP512R1,
            tls.SupportedGroups.SECP256R1,
            # tls.SupportedGroups.SECP384R1,
            # tls.SupportedGroups.SECP521R1,
            # tls.SupportedGroups.FFDHE2048,
            # tls.SupportedGroups.FFDHE4096,
        ]
        client_profile.signature_algorithms = [
            tls.SignatureScheme.ED25519,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA384,
            tls.SignatureScheme.RSA_PKCS1_SHA512,
            tls.SignatureScheme.ECDSA_SHA1,
            tls.SignatureScheme.RSA_PKCS1_SHA1,
        ]
        # client_profile.support_encrypt_then_mac = True
        # client_profile.support_extended_master_secret = True

        with client_profile.create_connection() as conn:

            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            conn.wait(msg.ServerKeyExchange, optional=True)
            conn.wait(msg.ServerHelloDone)
            conn.send(msg.ClientKeyExchange, msg.ChangeCipherSpec, msg.Finished)
            conn.wait(msg.ChangeCipherSpec)
            conn.wait(msg.Finished)
            conn.send(msg.AppData(b"GET / HTTP/1.1\n"))
            while True:
                app_data = conn.wait(msg.AppData)
                if len(app_data.data):
                    break
            for line in app_data.data.decode("utf-8").split("\n"):
                if line.startswith("s_server"):
                    logging.debug("openssl_command: " + line)

        client_profile.support_session_id = True
        with client_profile.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec)
            conn.wait(msg.Finished)
            conn.send(msg.ChangeCipherSpec, msg.Finished)
            conn.send(msg.AppData(b"GET / HTTP/1.1\n"))
            while True:
                app_data = conn.wait(msg.AppData)
                if len(app_data.data):
                    break
            for line in app_data.data.decode("utf-8").split("\n"):
                if line.startswith("s_server"):
                    logging.debug("openssl_command: " + line)
