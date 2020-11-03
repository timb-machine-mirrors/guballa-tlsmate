# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import logging
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestSuite
import tlsclient.utils as utils
from tlsclient.server_profile import SPEnum, SPVersions


class ScanCipherSuites(TestSuite):
    name = "basic"
    prio = 10

    def get_server_cs_and_cert(self, version):
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            server_hello = conn.wait(msg.ServerHello)
            if server_hello is None:
                return None
            if version is tls.Version.TLS13:
                ext = server_hello.get_extension(tls.Extension.SUPPORTED_VERSIONS)
                if ext.versions[0] != version:
                    return None
                conn.wait(msg.ChangeCipherSpec, optional=True)
                conn.wait(msg.EncryptedExtensions)
            else:
                if server_hello.version != version:
                    return None
            certificate = conn.wait(msg.Certificate, optional=True)
            if certificate is not None:
                self.server_profile.cert_chain.append_unique(certificate.certificates)
            return server_hello.cipher_suite
        return None

    def get_server_cs(self):
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            server_hello = conn.wait(msg.Any)
        try:
            return server_hello.cipher_suite
        except AttributeError:
            return None

    def get_server_preference(self, cipher_suites):
        self.client.cipher_suites = cipher_suites
        server_pref = []
        while self.client.cipher_suites:
            server_cs = self.get_server_cs()
            server_pref.append(server_cs)
            self.client.cipher_suites.remove(server_cs)
        return server_pref

    def tls_enum_version(self, version):
        cipher_suites = utils.filter_cipher_suites(
            tls.CipherSuite.all(), version=version
        )
        logging.info(f"starting to enumerate {version.name}")
        self.client.versions = [version]
        supported_cs = []

        # get a list of all supported cipher suites, don't send more than
        # max_items cipher suites in the ClientHello
        max_items = 32
        while cipher_suites:
            sub_set = cipher_suites[:max_items]
            cipher_suites = cipher_suites[max_items:]

            while sub_set:
                self.client.cipher_suites = sub_set
                cipher_suite = self.get_server_cs_and_cert(version)
                if cipher_suite is not None:
                    sub_set.remove(cipher_suite)
                    supported_cs.append(cipher_suite)
                else:
                    sub_set = []

        if supported_cs:
            profile_version = self.server_profile.versions.append(
                SPVersions(version, tls.SPBool.C_UNDETERMINED)
            )
            if len(supported_cs) == 1:
                server_prio = tls.SPBool.C_NA
            else:
                server_prio = tls.SPBool.C_FALSE
                # check if server enforce the cipher suite prio
                self.client.cipher_suites = supported_cs
                if self.get_server_cs() != supported_cs[0]:
                    server_prio = tls.SPBool.C_TRUE
                else:
                    supported_cs.append(supported_cs.pop(0))
                    if self.get_server_cs() != supported_cs[0]:
                        server_prio = tls.SPBool.C_TRUE

                # determine the order of cipher suites on server side, if applicable
                if server_prio == tls.SPBool.C_TRUE:
                    supported_cs = self.get_server_preference(supported_cs)
                else:
                    # esthetical: restore original order, which means the cipher suites
                    # are ordered according to the binary representation
                    supported_cs.insert(0, supported_cs.pop())

            profile_version.server_preference = server_prio
            for cs in supported_cs:
                profile_version.cipher_suites.append(SPEnum(cs))

        logging.info(f"enumeration for {version} finished")

    def ssl2_enum_version(self):
        with self.client.create_connection() as conn:
            conn.send(msg.SSL2ClientHello)
            server_hello = conn.wait(msg.SSL2ServerHello)
            if server_hello is not None:
                cert_chain_id = 0
                if server_hello.certificate is not None:
                    cert_chain_id = self.server_profile.cert_chain.append_unique(
                        [server_hello.certificate]
                    )
                prof_version = SPEnum(tls.Version.SSL20, tls.SPBool.C_UNDETERMINED)
                for cs in server_hello.cipher_specs:
                    prof_version.cipher_suites.append(SPEnum(cs, cert_chain_id))
                self.server_profile.versions.append(prof_version)

    def enum_version(self, version):
        if version is tls.Version.SSL20:
            self.ssl2_enum_version()
        else:
            self.tls_enum_version(version)

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
            tls.SignatureScheme.ED448,
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

        for version in tls.Version.all():
            self.enum_version(version)
