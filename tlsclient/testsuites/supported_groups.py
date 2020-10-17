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


class _GroupsProfile(Serializable):

    node_name = "named_groups"

    serialize_map = {
        "named_groups_supported": lambda x: x.name,
        "groups": lambda groups: None
        if not groups
        else [{"name": group.name, "id": group.value} for group in groups],
        "server_preference": lambda x: x.name,
        "groups_advertised": lambda x: x.name,
        "ext_supp_groups_supported": lambda x: x.name,
    }

    def __init__(self, vers_prof, version, testsuite):
        super().__init__()
        self.ext_supp_groups_supported = tls.SPBool.C_UNDETERMINED
        self.groups = None
        self.server_preference = tls.SPBool.C_UNDETERMINED
        self.groups_advertised = tls.SPBool.C_UNDETERMINED
        self._version = version
        self._client = testsuite.client
        self._version_prof = vers_prof
        vers_prof.register(self)

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
                    raise ScanError(
                        "server's advertised groups differ from accepted groups"
                    )


class ScanSupportedGroups(TestSuite):
    name = "groups"
    descr = "check for FF-DH and EC groups"
    prio = 20

    def run(self):

        versions = tls.Version.all()
        versions.remove(tls.Version.SSL20)
        for version in versions:
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
