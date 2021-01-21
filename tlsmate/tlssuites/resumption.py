# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsmate.constants as tls
from tlsmate.tlssuite import TlsSuite

# from tlsmate.server_profile import ProfileBasic, ProfileBasicEnum


class ScanResumption(TlsSuite):
    name = "resumption"
    descr = "check if the server supports resumption via (session_id and ticket)"
    prio = 30

    def resumption_tls12(self, prof_vals, session_ticket=False):
        if not prof_vals.versions:
            state = tls.SPBool.C_NA
        elif not prof_vals.cipher_suites:
            # no cipher suite, for which a hull handshake is supported.
            state = tls.SPBool.C_UNDETERMINED
        else:
            state = tls.SPBool.C_FALSE
            self.client.reset_profile()
            self.client.versions = prof_vals.versions
            self.client.cipher_suites = prof_vals.cipher_suites
            self.client.supported_groups = prof_vals.supported_groups
            self.client.signature_algorithms = prof_vals.signature_algorithms
            if session_ticket:
                self.client.support_session_ticket = True
            else:
                self.client.support_session_id = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if session_ticket:
                    resumption_possible = ...
                else:
                    resumption_possible = bool(len(conn.msg.server_hello.session_id))
                if resumption_possible:
                    self.client.cipher_suites = [conn.msg.server_hello.cipher_suite]
                    with self.client.create_connection() as conn2:
                        conn2.handshake()
                    if conn2.handshake_completed and conn2.abbreviated_hs:
                        state = tls.SPBool.C_TRUE
        return state

    def run(self):
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        prof_vals = self.server_profile.get_profile_values(versions, full_hs=True)
        prof_features = self.server_profile.features

        session_id_support = self.resumption_tls12(prof_vals, session_ticket=False)
        prof_features.session_id = session_id_support

        session_ticket_support = self.resumption_tls12(prof_vals, session_ticket=True)
        prof_features.session_ticket = session_ticket_support
        if session_ticket_support is tls.SPBool.C_TRUE:
            prof_features.session_ticket_lifetime = (
                self.client.session_state_ticket.lifetime
            )  # noqa: 501
