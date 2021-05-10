# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin
from tlsmate import utils

# import other stuff


class ScanEncryptThenMac(WorkerPlugin):
    name = "encrypt_then_mac"
    descr = "check if the extension encrypt_then_mac is supported"
    prio = 30

    def run(self):
        state = tls.SPBool.C_UNDETERMINED
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]

        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        cipher_suites = utils.filter_cipher_suites(
            prof_values.cipher_suites, cipher_type=[tls.CipherType.BLOCK]
        )

        if not cipher_suites:
            # no CBC cipher suite supported
            state = tls.SPBool.C_NA
        else:
            self.client.init_profile(profile_values=prof_values)
            self.client.profile.cipher_suites = cipher_suites
            self.client.profile.support_encrypt_then_mac = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if conn.msg.server_hello.get_extension(tls.Extension.ENCRYPT_THEN_MAC):
                    state = tls.SPBool.C_TRUE
                else:
                    state = tls.SPBool.C_FALSE
        self.server_profile.features.encrypt_then_mac = state
