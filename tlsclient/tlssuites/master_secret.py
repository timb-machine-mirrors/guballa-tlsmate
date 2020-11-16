# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsclient.constants as tls
from tlsclient.tlssuite import TlsSuite
from tlsclient.server_profile import ProfileBasicEnum
from tlsclient import utils


class ScanExtendedMasterSecret(TlsSuite):
    name = "master_secret"
    descr = "check if the extension extended_master_secret is supported"
    prio = 30

    def extended_master_secret(self):
        state = tls.SPBool.C_UNDETERMINED
        cipher_suites = []
        groups = []
        sig_algs = []
        versions = []
        for version in self.server_profile.get_versions():
            if version not in [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]:
                continue
            versions.append(version)
            cipher_suites.extend(self.server_profile.get_cipher_suites(version))
            sig_algs.extend(self.server_profile.get_signature_algorithms(version))
            groups.extend(self.server_profile.get_supported_groups(version))
        if not cipher_suites:
            # no CBC cipher suite supported
            state = tls.SPBool.C_NA
        else:
            cipher_suites = utils.filter_cipher_suites(cipher_suites, full_hs=True)
            self.client.reset_profile()
            self.client.versions = versions
            self.client.cipher_suites = set(cipher_suites)
            self.client.supported_groups = set(groups)
            self.client.signature_algorithms = set(sig_algs)
            self.client.support_extended_master_secret = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if conn.msg.server_hello.get_extension(
                    tls.Extension.EXTENDED_MASTER_SECRET
                ):
                    state = tls.SPBool.C_TRUE
                else:
                    state = tls.SPBool.C_FALSE
        prof_features = self.server_profile.get("features")
        prof_features.add("extended_master_secret", ProfileBasicEnum(state))

    def run(self):
        self.extended_master_secret()
