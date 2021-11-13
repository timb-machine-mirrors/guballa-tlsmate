# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import Worker

# import other stuff


class ScanExtendedMasterSecret(Worker):
    name = "master_secret"
    descr = "scan for extension extended_master_secret support"
    prio = 30

    def run(self):
        state = tls.SPBool.UNDETERMINED
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.versions:
            state = tls.SPBool.NA
        else:
            self.client.init_profile(profile_values=prof_values)
            self.client.profile.support_extended_master_secret = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if conn.msg.server_hello.get_extension(
                    tls.Extension.EXTENDED_MASTER_SECRET
                ):
                    state = tls.SPBool.TRUE
                else:
                    state = tls.SPBool.FALSE

        self.server_profile.allocate_features()
        self.server_profile.features.extended_master_secret = state
