# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite
from tlsclient import mappings
from tlsclient.server_profile import Serializable
from tlsclient import structures as structs

class DHProfile(Serializable):

    node_name = "dh_info"

    serialize_map = {
        "named_groups_supported": lambda x: x.name,
        "named_groups": lambda groups: None if not groups else [
            {
                "name": group.value,
                "id": group.name,
            } for group in groups
        ],
        "ephemeral_key_reuse": lambda x: x.name,
    }

    def __init__(self, vers_prof):
        super().__init__()
        self.named_groups_supported = tls.SPBool.C_UNDETERMINED
        self.named_groups = None
        self.ephemeral_key_reuse = tls.SPBool.C_UNDETERMINED
        self.bit_length = None
        vers_prof.register_node_name(self.node_name, self)


@TestManager.register
class MyTestSuite(TestSuite):
    name = "groups"
    descr = "check for FF-DH and EC groups"
    prio = 20

    bitlen_mapping = {
        2048: tls.SupportedGroups.FFDHE2048,
        3072: tls.SupportedGroups.FFDHE3072,
        4096: tls.SupportedGroups.FFDHE4096,
        6144: tls.SupportedGroups.FFDHE6144,
        8192: tls.SupportedGroups.FFDHE8192,
    }

    def scenario_dhe(self):
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            return conn.wait(msg.ServerKeyExchange)
        return None

    def get_named_group(self, gval, pval):
        bits = len(pval) * 8
        group = self.bitlen_mapping.get(bits)
        if group is not None:
            params = mappings.dh_numbers[group]
            if params.g_val == gval and params.p_val == pval:
                return group
        return None

    def run_version_dhe(self, version):
        vers_prof = self.server_profile.get_version(version)
        if vers_prof is None:
            return
        prof = DHProfile(vers_prof)
        cipher_suite = vers_prof.get_dhe_cipher_suite()
        if cipher_suite is None:
            prof.named_groups_supported = tls.SPBool.C_NA
            return
        groups = [
            tls.SupportedGroups.FFDHE2048,
            tls.SupportedGroups.FFDHE3072,
            tls.SupportedGroups.FFDHE4096,
            tls.SupportedGroups.FFDHE6144,
            tls.SupportedGroups.FFDHE8192,
        ]
        self.client.cipher_suites = [cipher_suite]
        self.client.supported_groups = groups
        supported_groups = []
        while len(groups):
            ske = self.scenario_dhe()
            if ske is None or ske.dh is None:
                return
            public_key = ske.dh.public_key
            named_group = self.get_named_group(ske.dh.g_val, ske.dh.p_val)
            if named_group is None or named_group not in groups:
                dh_params = structs.DHNumbers(g_val=ske.dh.g_val, p_val=ske.dh.p_val)
                prof.named_groups_supported = tls.SPBool.C_FALSE
                prof.bit_length = len(ske.dh.p_val) * 8
                break
            groups.remove(named_group)
            supported_groups.append(named_group)
        if supported_groups:
            prof.named_groups_supported = tls.SPBool.C_TRUE
            prof.named_groups = supported_groups
            self.client.supported_groups = supported_groups
        else:
            self.client.support_supported_groups = False

        for _ in range(5):
            ske = self.scenario_dhe()
            if ske is None or ske.dh is None:
                continue
            if ske.dh.public_key == public_key:
                prof.ephemeral_key_reuse = tls.SPBool.C_TRUE
                return
        prof.ephemeral_key_reuse = tls.SPBool.C_FALSE


    def run(self):
        self.client.signature_algorithms = [
            tls.SignatureScheme.ED25519,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA384,
            tls.SignatureScheme.RSA_PKCS1_SHA512,
            tls.SignatureScheme.ECDSA_SHA1,
            tls.SignatureScheme.RSA_PKCS1_SHA1,
        ]

        for version in [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]:
            self.run_version_dhe(version)
            # self.run_version_ecdhe(version)
