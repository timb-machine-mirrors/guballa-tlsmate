# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin
from tlsmate import msg

# import other stuff


class ScanResumption(WorkerPlugin):
    name = "resumption"
    descr = "check if the server supports resumption via (session_id and ticket)"
    prio = 30

    def resumption_tls12(self, prof_vals, session_ticket=False):
        if not prof_vals.cipher_suites:
            # no cipher suite, for which a hull handshake is supported.
            state = tls.SPBool.C_UNDETERMINED
        else:
            state = tls.SPBool.C_FALSE
            self.client.init_profile(profile_values=prof_vals)
            if session_ticket:
                self.client.profile.support_session_ticket = True
            else:
                self.client.profile.support_session_id = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if session_ticket:
                    resumption_possible = ...
                else:
                    resumption_possible = bool(len(conn.msg.server_hello.session_id))
                if resumption_possible:
                    self.client.profile.cipher_suites = [
                        conn.msg.server_hello.cipher_suite
                    ]
                    with self.client.create_connection() as conn2:
                        conn2.handshake()
                    if conn2.handshake_completed and conn2.abbreviated_hs:
                        state = tls.SPBool.C_TRUE
        return state

    def run_tls12(self):
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_vals = self.server_profile.get_profile_values(versions, full_hs=True)
        prof_features = self.server_profile.features

        session_id_support = tls.SPBool.C_NA
        session_ticket_support = tls.SPBool.C_NA
        if prof_vals.versions:
            session_id_support = self.resumption_tls12(prof_vals, session_ticket=False)
            session_ticket_support = self.resumption_tls12(
                prof_vals, session_ticket=True
            )

        prof_features.session_ticket = session_ticket_support
        prof_features.session_id = session_id_support
        if session_ticket_support is tls.SPBool.C_TRUE:
            prof_features.session_ticket_lifetime = (
                self.client.session_state_ticket.lifetime
            )

    def run_tls13(self):
        resumption_psk = tls.SPBool.C_NA
        early_data = tls.SPBool.C_NA
        psk_lifetime = None
        prof_vals = self.server_profile.get_profile_values(
            [tls.Version.TLS13], full_hs=True
        )
        if prof_vals.versions:
            self.client.init_profile(profile_values=prof_vals)
            self.client.profile.support_psk = True
            self.client.profile.psk_key_exchange_modes = [
                tls.PskKeyExchangeMode.PSK_DHE_KE,
                tls.PskKeyExchangeMode.PSK_KE,
            ]
            ticket_msg = None
            with self.client.create_connection() as conn:
                conn.handshake()
                ticket_msg = conn.wait(msg.NewSessionTicket, optional=True, timeout=200)
                if ticket_msg is not None:
                    psk_lifetime = ticket_msg.lifetime
                else:
                    resumption_psk = tls.SPBool.C_FALSE

            if ticket_msg:
                resumption_psk = tls.SPBool.C_TRUE
                early_data = tls.SPBool.C_FALSE

                self.client.profile.early_data = b"This is EarlyData (0-RTT)"
                with self.client.create_connection() as conn:
                    conn.handshake()

                if conn.early_data_accepted:
                    early_data = tls.SPBool.C_TRUE

        self.server_profile.features.resumption_psk = resumption_psk
        self.server_profile.features.early_data = early_data
        if psk_lifetime is not None:
            self.server_profile.features.psk_lifetime = psk_lifetime

    def run(self):
        self.run_tls12()
        self.run_tls13()
