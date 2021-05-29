# -*- coding: utf-8 -*-
"""Module containing implementing the worker for DH group scanning
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin
from tlsmate import msg
from tlsmate import utils
from tlsmate.dh_numbers import DHNumbers, KnownDhGroups
from tlsmate.server_profile import SPDhGroup

# import other stuff


class ScanDhGroups(WorkerPlugin):
    name = "dh_groups"
    descr = "check for DH groups"
    prio = 30

    def _update_profile(self, version, g_val, p_val):
        version_prof = self.server_profile.get_version_profile(version)
        group = KnownDhGroups.get_known_group(g_val, p_val)
        if group is None:
            size = len(p_val) * 8
            group = DHNumbers(g_val=g_val, p_val=p_val, size=size)
        version_prof.dh_group = SPDhGroup(
            name=group.name, size=group.size, g_value=group.g_val, p_value=group.p_val,
        )

    def run(self):
        """Entry point for the worker.

        We don't cover TLS13 here, as the groups are scanned as part of the
        supported groups scan. TLS13 only supports well known groups.
        """
        versions = [
            tls.Version.SSL30,
            tls.Version.TLS10,
            tls.Version.TLS11,
            tls.Version.TLS12,
        ]
        for version in versions:
            prof_vals = self.server_profile.get_profile_values([version], full_hs=False)
            if version in prof_vals.versions:
                self.client.init_profile(profile_values=prof_vals)
                dh_cs = utils.filter_cipher_suites(
                    prof_vals.cipher_suites,
                    key_algo=[
                        tls.KeyExchangeAlgorithm.DHE_DSS,
                        tls.KeyExchangeAlgorithm.DHE_DSS_EXPORT,
                        tls.KeyExchangeAlgorithm.DHE_RSA,
                        tls.KeyExchangeAlgorithm.DHE_RSA_EXPORT,
                        tls.KeyExchangeAlgorithm.DH_ANON,
                    ],
                )
                if dh_cs:
                    self.client.profile.cipher_suites = dh_cs
                    with self.client.create_connection() as conn:
                        conn.send(msg.ClientHello)
                        conn.wait(msg.ServerHello)
                        conn.wait(msg.Certificate, optional=True)
                        ske = conn.wait(msg.ServerKeyExchange)
                        self._update_profile(version, ske.dh.g_val, ske.dh.p_val)
