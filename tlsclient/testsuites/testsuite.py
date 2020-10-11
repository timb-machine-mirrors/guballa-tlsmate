# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import logging
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite


@TestManager.register
class MyTestSuite(TestSuite):
    name = "test"
    descr = "Scratch test suite"
    prio = 100

    def run(self):
        client = self.client
        client.versions = [tls.Version.TLS12]
        client.cipher_suites = [
            tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            #tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            #tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            # tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            # tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
            # tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        ]
        client.supported_groups = [
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
        client.signature_algorithms = [
            tls.SignatureScheme.RSA_PKCS1_SHA1,
            tls.SignatureScheme.ECDSA_SHA1,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA256_LEGACY,
            tls.SignatureScheme.RSA_PKCS1_SHA384,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.RSA_PKCS1_SHA384_LEGACY,
            tls.SignatureScheme.RSA_PKCS1_SHA512,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PKCS1_SHA512_LEGACY,
            tls.SignatureScheme.ECCSI_SHA256,
            tls.SignatureScheme.ISO_IBS1,
            tls.SignatureScheme.ISO_IBS2,
            tls.SignatureScheme.ISO_CHINESE_IBS,
            tls.SignatureScheme.SM2SIG_SM3,
            tls.SignatureScheme.GOSTR34102012_256A,
            tls.SignatureScheme.GOSTR34102012_256B,
            tls.SignatureScheme.GOSTR34102012_256C,
            tls.SignatureScheme.GOSTR34102012_256D,
            tls.SignatureScheme.GOSTR34102012_512A,
            tls.SignatureScheme.GOSTR34102012_512B,
            tls.SignatureScheme.GOSTR34102012_512C,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            tls.SignatureScheme.ED25519,
            tls.SignatureScheme.ED448,
            tls.SignatureScheme.RSA_PSS_PSS_SHA256,
            tls.SignatureScheme.RSA_PSS_PSS_SHA384,
            tls.SignatureScheme.RSA_PSS_PSS_SHA512,
            tls.SignatureScheme.ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            tls.SignatureScheme.ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            tls.SignatureScheme.ECDSA_BRAINPOOLP512R1TLS13_SHA512,
        ]
        # client.support_encrypt_then_mac = True
        # client.support_extended_master_secret = True

        #client.support_session_ticket = True
        with client.create_connection() as conn:

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
