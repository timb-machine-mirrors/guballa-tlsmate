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

    def get_server_cs(self):
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            server_hello = conn.wait(msg.Any)
        try:
            return server_hello.cipher_suite
        except:
            return None

    def get_server_preference(self, cipher_suites):
        self.client.cipher_suites = cipher_suites
        server_pref = []
        while self.client.cipher_suites:
            server_cs = self.get_server_cs()
            server_pref.append(server_cs)
            self.client.cipher_suites.remove(server_cs)
        return server_pref

    def enum_version(self, version, cipher_suites):
        print(f"starting to enumerate {version.name}")
        logging.info(f"starting to enumerate {version.name}")
        self.client.versions = [version]
        supported_cs = []

        # get a list of all supported cipher suites, don't send more than
        # max_items cipher suites in the ClientHello
        max_items = 32
        while len(cipher_suites) > 0:
            sub_set = cipher_suites[:max_items]
            cipher_suites = cipher_suites[max_items:]

            while sub_set:
                self.client.cipher_suites = sub_set
                server_cs = self.get_server_cs()
                if server_cs is not None:
                    sub_set.remove(server_cs)
                    supported_cs.append(server_cs)
                else:
                    sub_set = []

        # check if server enforce the cipher suite prio
        server_prio = False
        self.client.cipher_suites = supported_cs
        server_cs = self.get_server_cs()
        if server_cs != supported_cs[0]:
            server_prio = True
        else:
            supported_cs.append(supported_cs.pop(0))
            server_cs = self.get_server_cs()
            if server_cs != supported_cs[0]:
                server_prio = True

        # determine order cipher suites on server side, if applicable
        if server_prio:
            supported_cs = self.get_server_preference(supported_cs)
        else:
            # esthetical: restore original order, which means the cipher suites
            # are ordered according to the binary representation
            supported_cs.insert(0, supported_cs.pop())

        print(f"TLS Version {version.name}: server_prio: {server_prio}")
        for cipher_suite in supported_cs:
            print(f"0x{cipher_suite.value:04x} {cipher_suite.name}")

        logging.info(f"enumeration for {version.name} finished")
        return supported_cs

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
