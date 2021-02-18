# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.tlssuite import TlsSuite

# import other stuff


class ScanRenegotiation(TlsSuite):
    name = "renegotiation"
    descr = "check which kind of renegotiations are supported by the server"
    prio = 30

    def run(self):

        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.versions:
            self.server_profile.features.insecure_renegotiation = tls.SPBool.C_NA
            self.server_profile.features.secure_renegotation = tls.SPBool.C_NA
            self.server_profile.features.scsv_renegotiation = tls.SPBool.C_NA
            return

        self.server_profile.features.insecure_renegotiation = tls.SPBool.C_UNDETERMINED
        self.server_profile.features.secure_renegotation = tls.SPBool.C_UNDETERMINED
        self.server_profile.features.scsv_renegotiation = tls.SPBool.C_UNDETERMINED
        self.client.reset_profile()
        self.client.versions = prof_values.versions
        self.client.cipher_suites = prof_values.cipher_suites
        self.client.supported_groups = prof_values.supported_groups
        self.client.signature_algorithms = prof_values.signature_algorithms
        self.server_profile.features.insecure_renegotiation = tls.SPBool.C_FALSE
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.insecure_renegotiation = tls.SPBool.C_TRUE

        self.server_profile.features.secure_renegotation = tls.SPBool.C_FALSE
        self.client.support_secure_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.secure_renegotation = tls.SPBool.C_TRUE

        self.server_profile.features.scsv_renegotiation = tls.SPBool.C_FALSE
        self.client.support_secure_renegotiation = False
        self.client.support_scsv_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.scsv_renegotiation = tls.SPBool.C_TRUE
