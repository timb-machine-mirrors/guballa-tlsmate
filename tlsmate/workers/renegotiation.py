# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import Worker

# import other stuff


class ScanRenegotiation(Worker):
    name = "renegotiation"
    descr = "scan for renegotiation support"
    prio = 30

    def run(self):

        self.server_profile.allocate_features()
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.versions:
            self.server_profile.features.insecure_renegotiation = tls.SPBool.NA
            self.server_profile.features.secure_renegotation = tls.SPBool.NA
            self.server_profile.features.scsv_renegotiation = tls.SPBool.NA
            return

        self.server_profile.features.insecure_renegotiation = tls.SPBool.UNDETERMINED
        self.server_profile.features.secure_renegotation = tls.SPBool.UNDETERMINED
        self.server_profile.features.scsv_renegotiation = tls.SPBool.UNDETERMINED
        self.client.init_profile(profile_values=prof_values)
        self.server_profile.features.insecure_renegotiation = tls.SPBool.FALSE
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.insecure_renegotiation = tls.SPBool.TRUE

        self.server_profile.features.secure_renegotation = tls.SPBool.FALSE
        self.client.profile.support_secure_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.secure_renegotation = tls.SPBool.TRUE

        self.server_profile.features.scsv_renegotiation = tls.SPBool.FALSE
        self.client.profile.support_secure_renegotiation = False
        self.client.profile.support_scsv_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.scsv_renegotiation = tls.SPBool.TRUE
