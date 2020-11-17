# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import logging
import abc
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite, ScanError
from tlsclient import mappings
from tlsclient.server_profile import Serializable
import tlsclient.extensions as ext


class DHProfile(Serializable):

    node_name = "dh_info"

    serialize_map = {
        "named_groups_supported": lambda x: x.name,
        "named_groups": lambda groups: None
        if not groups
        else [{"name": group.value, "id": group.name} for group in groups],
        "ephemeral_key_reuse": lambda x: x.name,
    }

    def __init__(self, vers_prof):
        super().__init__()
        self.named_groups_supported = tls.SPBool.C_UNDETERMINED
        self.named_groups = None
        self.ephemeral_key_reuse = tls.SPBool.C_UNDETERMINED
        self.bit_length = None
        vers_prof.register_node_name(self.node_name, self)


class ECDHProfile(Serializable):

    node_name = "ecdh_info"

    serialize_map = {
        "named_groups_supported": lambda x: x.name,
        "named_groups": lambda groups: None
        if not groups
        else [{"name": group.value, "id": group.name} for group in groups],
        "ecdhe_key_reuse": lambda x: x.name,
        "dhe_key_reuse": lambda x: x.name,
        "server_preference": lambda x: x.name,
        "groups_advertised": lambda x: x.name,
    }

    def __init__(self, vers_prof):
        super().__init__()
        self.named_groups_supported = tls.SPBool.C_UNDETERMINED
        self.named_groups = None
        self.dhe_key_reuse = tls.SPBool.C_UNDETERMINED
        self.ecdhe_key_reuse = tls.SPBool.C_UNDETERMINED
        self.server_preference = tls.SPBool.C_UNDETERMINED
        self.groups_advertised = tls.SPBool.C_UNDETERMINED
        vers_prof.register_node_name(self.node_name, self)



class _GroupsProfile(Serializable):

    node_name = "named_groups"

    serialize_map = {
        "named_groups_supported": lambda x: x.name,
        "groups": lambda groups: None
        if not groups
        else [{"name": group.name, "id": group.value} for group in groups],
        "ecdhe_key_reuse": lambda x: x.name,
        "dhe_key_reuse": lambda x: x.name,
        "server_preference": lambda x: x.name,
        "groups_advertised": lambda x: x.name,
        "ext_supp_groups_supported": lambda x: x.name,
    }

    def __init__(self, vers_prof, version, testsuite):
        super().__init__()
        self.ext_supp_groups_supported = tls.SPBool.C_UNDETERMINED
        self.groups = None
        self.dhe_key_reuse = tls.SPBool.C_UNDETERMINED
        self.ecdhe_key_reuse = tls.SPBool.C_UNDETERMINED
        self.server_preference = tls.SPBool.C_UNDETERMINED
        self.groups_advertised = tls.SPBool.C_UNDETERMINED
        self._version = version
        self._client = testsuite.client
        self._version_prof = vers_prof
        vers_prof.register_node_name(self.node_name, self)

    @abc.abstractmethod
    def _get_cipher_suites(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _get_group_from_server(self, offered_groups):
        raise NotImplementedError

    def _determine_supported_groups(self):
        offered_groups = self._offered_groups[:]
        supported_groups = []
        while len(offered_groups):
            server_group = self._get_group_from_server(offered_groups)
            if server_group is None:
                break
            if server_group not in offered_groups:
                self.ext_supp_groups_supported = tls.SPBool.C_FALSE
                return
            supported_groups.append(server_group)
            offered_groups.remove(server_group)
        if not supported_groups:
            raise ScanError("no groups supported at all")
        self.ext_supp_groups_supported = tls.SPBool.C_TRUE
        self.groups = supported_groups

    def _determine_server_preference(self):
        if len(self.groups) > 1:
            ref_group = self.groups[0]
            self.groups.append(self.groups.pop(0))
            server_group = self._get_group_from_server(self.groups)
            self.groups.insert(0, self.groups.pop())
            if server_group is not None:
                if server_group is ref_group:
                    self.server_preference = tls.SPBool.C_TRUE
                else:
                    self.server_preference = tls.SPBool.C_FALSE
        else:
            self.server_preference = tls.SPBool.C_NA

    @abc.abstractmethod
    def _determine_advertised_group(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _determine_key_reuse(self):
        raise NotImplementedError

    def scan(self):
        self._client.versions = [self._version]
        self._client.signature_algorithms = [
            tls.SignatureScheme.ED25519,
            tls.SignatureScheme.ED448,
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
        self._client.cipher_suites = self._get_cipher_suites()
        self._determine_supported_groups()
        if self.ext_supp_groups_supported is tls.SPBool.C_TRUE:
            self._determine_server_preference()
            self._determine_advertised_group()
        self._determine_key_reuse()

class _TLS12_GroupsProfile(_GroupsProfile):

    _offered_groups = tls.SupportedGroups.all()

    def _get_cipher_suites(self):
        filtered_cs = []
        for cipher in self._version_prof.get_cipher_suites():
            cs = mappings.supported_cipher_suites.get(cipher)
            if cs is not None:
                if cs.key_ex in [
                    tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
                    tls.KeyExchangeAlgorithm.ECDHE_RSA,
                    tls.KeyExchangeAlgorithm.ECDH_ECDSA,
                    tls.KeyExchangeAlgorithm.ECDH_RSA,
                ]:
                    filtered_cs.append(cipher)
        return filtered_cs

    def _get_server_key_exchange_from_server(self, offered_groups):
        self._client.support_supported_groups = True
        self._client.supported_groups = offered_groups
        with self._client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            return conn.wait(msg.ServerKeyExchange)
        return None

    def _get_group_from_server(self, offered_groups):
        msg_ske = self._get_server_key_exchange_from_server(offered_groups)
        if msg_ske is None or msg_ske.ec is None:
            return None
        return msg_ske.ec.named_curve

    def _get_remote_key_from_server(self, offered_groups):
        msg_ske = self._get_server_key_exchange_from_server(offered_groups)
        if msg_ske is None or msg_ske.ec is None:
            return None
        return msg_ske.ec.public

    def _determine_advertised_group(self):
        self.groups_advertised = tls.SPBool.C_NA

    # TODO: Move this to the base class
    def _determine_key_reuse_type(self, groups):
        if not groups:
            return tls.SPBool.C_NA
        for group in groups:
            key_pool = []
            for _ in range(5):
                key = self._get_remote_key_from_server([group])
                if key is None:
                    return
                if key in key_pool:
                    return tls.SPBool.C_TRUE
        return tls.SPBool.C_FALSE

    def _determine_key_reuse(self):
        ecdhe_groups = []
        dhe_groups = []
        for group in self.groups:
            if group.value >= 256 and group.value <= 511:
                dhe_groups.append(group)
            else:
                ecdhe_groups.append(group)
        self.ecdhe_key_reuse = self._determine_key_reuse_type(ecdhe_groups)
        #self.dhe_key_reuse = self._determine_key_reuse_type(dhe_groups)

class _TLS13_GroupsProfile(_GroupsProfile):

    _offered_groups = [
        tls.SupportedGroups.SECP256R1,
        tls.SupportedGroups.SECP384R1,
        tls.SupportedGroups.SECP521R1,
        tls.SupportedGroups.X25519,
        tls.SupportedGroups.X448,
        tls.SupportedGroups.FFDHE2048,
        tls.SupportedGroups.FFDHE3072,
        tls.SupportedGroups.FFDHE4096,
        tls.SupportedGroups.FFDHE6144,
        tls.SupportedGroups.FFDHE8192,
    ]

    def _get_cipher_suites(self):
        return self._version_prof.get_cipher_suites()

    def _get_share_from_server(self, offered_groups):
        self._client.support_supported_groups = True
        self._client.supported_groups = offered_groups
        self._client.key_shares = offered_groups
        with self._client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
        if conn.msg.server_hello is None:
            return None
        try:
            key_share_ext = ext.get_extension(
                conn.msg.server_hello.extensions, tls.Extension.KEY_SHARE
            )
            key_share = key_share_ext.key_shares[0]
            if key_share.group not in offered_groups:
                raise ScanError("selected group was not offered")
        except AttributeError as exc:
            raise ScanError("cannot get selected group from server_hello") from exc
        return key_share


    def _get_group_from_server(self, offered_groups):
        return self._get_share_from_server(offered_groups).group

    def _determine_advertised_group(self):
        self._client.supported_groups = self.groups[:1]
        self._client.key_shares = self.groups[:1]
        encrypted_extensions = None
        with self._client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec, optional=True)
            encrypted_extensions = conn.wait(msg.EncryptedExtensions)
        if encrypted_extensions is not None:
            supported_group_ext = ext.get_extension(
                encrypted_extensions.extensions, tls.Extension.SUPPORTED_GROUPS
            )
            if supported_group_ext is not None:
                advertised_groups = supported_group_ext.supported_groups
                if set(advertised_groups) == set(self.groups):
                    self.groups = advertised_groups
                    self.groups_advertised = tls.SPBool.C_TRUE
                else:
                    raise ScanError("server's advertised groups differ from accepted groups")

    def _determine_key_reuse_type(self, groups):
        if not groups:
            return tls.SPBool.C_NA
        for group in groups:
            key_pool = []
            for _ in range(5):
                key = self._get_share_from_server([group]).key_exchange
                if key is None:
                    return
                if key in key_pool:
                    return tls.SPBool.C_TRUE
        return tls.SPBool.C_FALSE

    def _determine_key_reuse(self):
        ecdhe_groups = []
        dhe_groups = []
        for group in self.groups:
            if group.value >= 256 and group.value <= 511:
                dhe_groups.append(group)
            else:
                ecdhe_groups.append(group)
        self.ecdhe_key_reuse = self._determine_key_reuse_type(ecdhe_groups)
        self.dhe_key_reuse = self._determine_key_reuse_type(dhe_groups)


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

    def scenario_tls13(self):
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
        return conn

    def get_share_from_server(self, offered_groups):
        self.client.support_supported_groups = True
        self.client.supported_groups = offered_groups
        self.client.key_shares = offered_groups
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
        if conn.msg.server_hello is None:
            return None
        try:
            key_share_ext = ext.get_extension(
                conn.msg.server_hello.extensions, tls.Extension.KEY_SHARE
            )
            key_share = key_share_ext.key_shares[0]
            if key_share.group not in offered_groups:
                raise ScanError("selected group was not offered")
        except AttributeError as exc:
            raise ScanError("cannot get selected group from server_hello") from exc
        return key_share

    def scan_tls13_group_support(self, group_prof, vers_prof):
        self.client.versions = [tls.Version.TLS13]
        self.client.cipher_suites = vers_prof.get_cipher_suites()
        offered_groups = [
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.X448,
            tls.SupportedGroups.FFDHE2048,
            tls.SupportedGroups.FFDHE3072,
            tls.SupportedGroups.FFDHE4096,
            tls.SupportedGroups.FFDHE6144,
            tls.SupportedGroups.FFDHE8192,
        ]
        supported_groups = []
        while len(offered_groups):
            server_group = self.get_share_from_server(offered_groups).group
            if server_group is None:
                break
            supported_groups.append(server_group)
            offered_groups.remove(server_group)

        if not supported_groups:
            raise ScanError("no groups supported at all")
        if len(supported_groups) > 1:
            ref_group = supported_groups[0]
            supported_groups.append(supported_groups.pop(0))
            server_group = self.get_share_from_server(supported_groups).group
            supported_groups.insert(0, supported_groups.pop())
            if server_group is not None:
                if server_group is ref_group:
                    group_prof.server_preference = tls.SPBool.C_TRUE
                else:
                    group_prof.server_preference = tls.SPBool.C_FALSE
        else:
            group_prof.server_preference = tls.SPBool.C_NA
        group_prof.named_groups_supported = tls.SPBool.C_TRUE
        group_prof.named_groups = supported_groups

    def scan_tls13_advertised_groups(self, prof):
        self.client.supported_groups = prof.named_groups[:1]
        self.client.key_shares = prof.named_groups[:1]
        encrypted_extensions = None
        with self.client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec, optional=True)
            encrypted_extensions = conn.wait(msg.EncryptedExtensions)
        if encrypted_extensions is not None:
            supported_group_ext = ext.get_extension(
                encrypted_extensions.extensions, tls.Extension.SUPPORTED_GROUPS
            )
            if supported_group_ext is not None:
                advertised_groups = supported_group_ext.supported_groups
                if set(advertised_groups) == set(prof.named_groups):
                    prof.named_groups = advertised_groups
                    prof.groups_advertised = tls.SPBool.C_TRUE
                else:
                    raise ScanError("server's advertised groups differ from accepted groups")

    def scan_tls13_key_reuse_type(self, groups):
        if not groups:
            return tls.SPBool.C_NA
        for group in groups:
            key_pool = []
            for _ in range(5):
                key = self.get_share_from_server([group]).key_exchange
                if key is None:
                    return
                if key in key_pool:
                    return tls.SPBool.C_TRUE
        return tls.SPBool.C_FALSE

    def scan_tls13_key_reuse(self, prof):
        ecdhe_groups = []
        dhe_groups = []
        for group in prof.named_groups:
            if group.value >= 256 and group.value <= 511:
                dhe_groups.append(group)
            else:
                ecdhe_groups.append(group)
        prof.ecdhe_key_reuse = self.scan_tls13_key_reuse_type(ecdhe_groups)
        prof.dhe_key_reuse = self.scan_tls13_key_reuse_type(dhe_groups)

    def scan_tls13_groups(self):
        vers_prof = self.server_profile.get_version(tls.Version.TLS13)
        if vers_prof is None:
            return
        prof = ECDHProfile(vers_prof)
        try:
            self.scan_tls13_group_support(prof, vers_prof)
        except ScanError as exc:
            logging.info(f'scan error in "{self.name}": {exc.message}')
            prof.set_error(exc.message)
        else:
            self.scan_tls13_advertised_groups(prof)
            self.scan_tls13_key_reuse(prof)


    def run(self):

        for version in [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12, tls.Version.TLS13]:
            vers_prof = self.server_profile.get_version(version)
            if vers_prof is not None:
                if version is tls.Version.TLS13:
                    cls = _TLS13_GroupsProfile
                else:
                    cls = _TLS12_GroupsProfile
                group_profile = cls(vers_prof, version, self)
                try:
                    group_profile.scan()
                except ScanError as exc:
                    logging.info(f'scan error in "{self.name}": {exc.message}')
                    group_profile.set_error(exc.message)

