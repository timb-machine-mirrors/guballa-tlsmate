# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff
import logging

# import own stuff
from tlsmate import msg
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin
from tlsmate import utils
from tlsmate.server_profile import SPVersion, SPCiphers

# import other stuff


class ScanCipherSuites(WorkerPlugin):
    """Scans for the supported versions, cipher suites and certificate chains.

    The results are stored in the server profile.
    """

    name = "basic"
    prio = 10

    def _get_server_cs_and_cert(self, version):
        """Performs a handshake and retieves the cipher suite and certificate chain.

        The certificate chain received from the server is added to the server profile.

        Arguments:
            version (:obj:`tlsmate.tls.Version`): The TLS version

        Returns:
            :obj:`tlsmate.tls.CipherSuite`: the cipher suite selected by the server.
                None, if no SeverHello was received.
        """
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            server_hello = conn.wait(msg.ServerHello)
            if server_hello is None:
                return None

            if version is not server_hello.get_version():
                return None

            if version is tls.Version.TLS13:
                conn.wait(msg.ChangeCipherSpec, optional=True)
                conn.wait(msg.EncryptedExtensions)

            certificate = conn.wait(msg.Certificate, optional=True)
            if certificate is not None:
                self.server_profile.append_unique_cert_chain(certificate.chain)
            return server_hello.cipher_suite
        return None

    def _get_server_cs(self):
        """Performs a handshake and returns the ciper suite selected by the server.

        Returns:
            :obj:`tlsmate.tls.CipherSuite`: the cipher suite selected by the server.
                None, if no SeverHello was received.
        """
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            server_hello = conn.wait(msg.Any)
        try:
            return server_hello.cipher_suite
        except AttributeError:
            return None

    def _get_server_preference(self, cipher_suites):
        """Determine the server preference order of supported cipher suites.

        Arguments:
            cipher_suites (list of :obj:`tlsmate.tls.CipherSuite`): the list of
                cipher suites support by the server in arbitrary order.

        Returns:
            list of :obj:`tlsmate.tls.CipherSuite`: the cipher suites supported by
                the server in the order of preference.
        """
        self.client.profile.cipher_suites = cipher_suites
        server_pref = []
        while self.client.profile.cipher_suites:
            server_cs = self._get_server_cs()
            server_pref.append(server_cs)
            self.client.profile.cipher_suites.remove(server_cs)
        return server_pref

    def _tls_enum_version(self, version):
        """Determines the supported cipher suites and other stuff for a given version.

        Determines the supported cipher suites, if the server enforces the priority
        (and if so, determines the order of cipher suites according to their priority)
        and extracts the certificate chains and stores them in the server profile.

        Arguments:
            version (:obj:`tlsmate.tls.Version`): The TLS version to enumerate.
        """
        cipher_suites = utils.filter_cipher_suites(
            tls.CipherSuite.all(), version=version
        )
        logging.info(f"starting to enumerate {version.name}")
        self.client.profile.versions = [version]
        supported_cs = []

        # get a list of all supported cipher suites, don't send more than
        # max_items cipher suites in the ClientHello
        max_items = 32
        while cipher_suites:
            sub_set = cipher_suites[:max_items]
            cipher_suites = cipher_suites[max_items:]

            while sub_set:
                self.client.profile.cipher_suites = sub_set
                cipher_suite = self._get_server_cs_and_cert(version)
                if cipher_suite not in (None, tls.CipherSuite.TLS_NULL_WITH_NULL_NULL):
                    sub_set.remove(cipher_suite)
                    supported_cs.append(cipher_suite)
                else:
                    sub_set = []

        if supported_cs:
            if len(supported_cs) == 1:
                server_prio = tls.SPBool.C_NA
            else:
                server_prio = tls.SPBool.C_FALSE
                # check if server enforce the cipher suite prio
                self.client.profile.cipher_suites = supported_cs
                if self._get_server_cs() != supported_cs[0]:
                    server_prio = tls.SPBool.C_TRUE
                else:
                    supported_cs.append(supported_cs.pop(0))
                    if self._get_server_cs() != supported_cs[0]:
                        server_prio = tls.SPBool.C_TRUE

                # determine the order of cipher suites on server side, if applicable
                if server_prio == tls.SPBool.C_TRUE:
                    supported_cs = self._get_server_preference(supported_cs)
                else:
                    # esthetical: restore original order, which means the cipher suites
                    # are ordered according to the binary representation
                    supported_cs.insert(0, supported_cs.pop())

            ciphers = SPCiphers(
                server_preference=server_prio, cipher_suites=supported_cs
            )
            self.server_profile.versions.append(
                SPVersion(version=version, ciphers=ciphers)
            )

        logging.info(f"enumeration for {version} finished")

    def _ssl2_enum_version(self):
        """Minimal support to determine if SSLv2 is supported.
        """
        with self.client.create_connection() as conn:
            conn.send(msg.SSL2ClientHello)
            server_hello = conn.wait(msg.SSL2ServerHello)
            if server_hello is not None:
                if server_hello.certificate is not None:
                    # self.server_profile.get("cert_chain").append_unique(
                    #     [server_hello.certificate]
                    # )
                    """"""

                prof_version = SPVersion()
                prof_version.cipher_kinds = server_hello.cipher_specs
                prof_version.server_preference = tls.SPBool.C_UNDETERMINED
                prof_version.version = tls.Version.SSL20
                self.server_profile.versions.append(prof_version)

    def _enum_version(self, version):
        """Scan a specific TLS version.

        Arguments:
            version (:obj:`tlsmate.tls.Version`): The TLS version to enumerate.
        """
        if version is tls.Version.SSL20:
            self._ssl2_enum_version()
        else:
            self._tls_enum_version(version)

    def run(self):
        """The entry point for the worker.
        """

        self.client.alert_on_invalid_cert = False
        self.client.profile.versions = [tls.Version.TLS12]
        self.client.profile.supported_groups = [
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
        self.client.profile.key_shares = tls.SupportedGroups.all_tls13()
        self.client.profile.signature_algorithms = [
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

        mapping = {
            tls.Version.SSL20: "sslv2",
            tls.Version.SSL30: "sslv3",
            tls.Version.TLS10: "tls10",
            tls.Version.TLS11: "tls11",
            tls.Version.TLS12: "tls12",
            tls.Version.TLS13: "tls13",
        }

        for version in tls.Version.all():
            if self.config.get(mapping[version]):
                self._enum_version(version)
