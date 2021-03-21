# -*- coding: utf-8 -*-
"""Module containing implementing the worker for DH group scanning
"""
# import basic stuff
from typing import NamedTuple

# import own stuff
from tlsmate import tls
from tlsmate.plugin import Worker
from tlsmate import msg
from tlsmate import utils
from tlsmate.dh_numbers import DHNumbers, KnownDhGroups, dh_number_digest
from tlsmate.server_profile import SPDhGroup

# import other stuff


class _DhGroupEntry(NamedTuple):
    """A struct to store the cipher suites used with the DH group.
    """
    group: DHNumbers
    cipher_suites: list


class _DhGroupCache(object):
    """Class which caches the DH-groups and the cipher suites using it
    """

    def __init__(self):
        self._cache = {}

    def add_dh_group(self, cipher_suite, g_val, p_val):
        """Check if group is in the cache and add it if it is not.

        Arguments:
            cipher_suite (:obj:`tls.CipherSuite`): the cipher suite that is used
                for the given DH group
            g_val (int): the generator g of the group
            p_val (bytes): the prime p of the group
        """
        digest = dh_number_digest(g_val, p_val)
        if digest not in self._cache:
            group = KnownDhGroups.get_known_group(g_val, p_val)
            if group is None:
                size = len(p_val) * 8
                group = DHNumbers(g_val=g_val, p_val=p_val, size=size)
            self._cache[digest] = _DhGroupEntry(group=group, cipher_suites=[])
        self._cache[digest].cipher_suites.append(cipher_suite)

    def update_server_profile(self, version_prof):
        """Dump the cache to the server profile

        Arguments:
            version_prof: the version object of the server profile
        """
        groups_prof = []
        for group in self._cache.values():
            group_obj = SPDhGroup(
                name=group.group.name,
                size=group.group.size,
                g_value=group.group.g_val,
                p_value=group.group.p_val,
                cipher_suites=[],
            )
            for cs in group.cipher_suites:
                group_obj.cipher_suites.append(cs)
            groups_prof.append(group_obj)

        version_prof.dh_groups = groups_prof


class ScanDhGroups(Worker):
    name = "dh_groups"
    descr = "check for DH groups"
    prio = 30

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
                group_cache = _DhGroupCache()
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
                self.client.init_profile(profile_values=prof_vals)
                for cs in dh_cs:
                    self.client.cipher_suites = [cs]
                    with self.client.create_connection() as conn:
                        conn.send(msg.ClientHello)
                        conn.wait(msg.ServerHello)
                        conn.wait(msg.Certificate, optional=True)
                        ske = conn.wait(msg.ServerKeyExchange)
                        group_cache.add_dh_group(cs, ske.dh.g_val, ske.dh.p_val)

                version_prof = self.server_profile.get_version_profile(version)
                group_cache.update_server_profile(version_prof)
