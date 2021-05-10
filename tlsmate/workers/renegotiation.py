# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanRenegotiation(WorkerPlugin):
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
        self.client.init_profile(profile_values=prof_values)
        self.server_profile.features.insecure_renegotiation = tls.SPBool.C_FALSE
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.insecure_renegotiation = tls.SPBool.C_TRUE

        self.server_profile.features.secure_renegotation = tls.SPBool.C_FALSE
        self.client.profile.support_secure_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.secure_renegotation = tls.SPBool.C_TRUE

        self.server_profile.features.scsv_renegotiation = tls.SPBool.C_FALSE
        self.client.profile.support_secure_renegotiation = False
        self.client.profile.support_scsv_renegotiation = True
        with self.client.create_connection() as conn:
            conn.handshake()
            conn.handshake()
            if conn.handshake_completed:
                self.server_profile.features.scsv_renegotiation = tls.SPBool.C_TRUE
