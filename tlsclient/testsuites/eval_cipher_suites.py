# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import logging
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite


@TestManager.register
class MyTestSuite(TestSuite):
    name = "enum"
    descr = "enumerate TLS versions and cipher suites"
    prio = 10

    def enum_version(self, version, cipher_suites):
        print(f"starting to enumerate {version.name}")
        logging.info(f"starting to enumerate {version.name}")
        self.client.versions = [version]

        max_items = 32
        while len(cipher_suites) > 0:
            sub_set = cipher_suites[:max_items]
            cipher_suites = cipher_suites[max_items:]

            while sub_set:
                self.client.cipher_suites = sub_set
                with self.client.create_connection() as conn:
                    conn.send(msg.ClientHello)
                    message = conn.wait(msg.Any)
                if isinstance(message, msg.ServerHello):
                    if message.cipher_suite not in sub_set:
                        raise ValueError("Hey, what's going on???")
                    sub_set.remove(message.cipher_suite)
                    print(message.cipher_suite.name)
                else:
                    sub_set = []
        logging.info(f"enumeration for {version.name} finished")

    def run(self):
        self.client.versions = [tls.Version.TLS12]
        self.client.supported_groups = [
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.X448,
            tls.SupportedGroups.SECT163K1,
            tls.SupportedGroups.SECT163R2,
            tls.SupportedGroups.SECT233K1,
            tls.SupportedGroups.SECT233R1,
            tls.SupportedGroups.SECT283K1,
            tls.SupportedGroups.SECT283R1,
            tls.SupportedGroups.SECT409K1,
            tls.SupportedGroups.SECT409R1,
            tls.SupportedGroups.SECT571K1,
            tls.SupportedGroups.SECT571R1,
            tls.SupportedGroups.SECP224R1,
            tls.SupportedGroups.SECP256K1,
            tls.SupportedGroups.BRAINPOOLP256R1,
            tls.SupportedGroups.BRAINPOOLP384R1,
            tls.SupportedGroups.BRAINPOOLP512R1,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
            tls.SupportedGroups.FFDHE2048,
            tls.SupportedGroups.FFDHE4096,
        ]
        self.client.signature_algorithms = [
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
        cipher_suites = list(tls.CipherSuite.__members__.values())
        cipher_suites.remove(tls.CipherSuite.TLS_FALLBACK_SCSV)
        cipher_suites.remove(tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)

        self.enum_version(tls.Version.TLS10, cipher_suites[:])
        self.enum_version(tls.Version.TLS11, cipher_suites[:])
        self.enum_version(tls.Version.TLS12, cipher_suites[:])

