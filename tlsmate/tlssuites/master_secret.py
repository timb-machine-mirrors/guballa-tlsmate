# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsmate.constants as tls
from tlsmate.tlssuite import TlsSuite


class ScanExtendedMasterSecret(TlsSuite):
    name = "master_secret"
    descr = "check if the extension extended_master_secret is supported"
    prio = 30

    def extended_master_secret(self):
        state = tls.SPBool.C_UNDETERMINED
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.verions:
            state = tls.SPBool.C_NA
        else:
            self.client.reset_profile()
            self.client.versions = prof_values.versions
            self.client.cipher_suites = prof_values.cipher_suites
            self.client.supported_groups = prof_values.supported_groups
            self.client.signature_algorithms = prof_values.signature_algorithms
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
        self.server_profile.features.extended_master_secret = state

    def run(self):
        self.extended_master_secret()
