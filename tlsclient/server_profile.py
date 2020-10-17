# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
from tlsclient import constants as tls
from tlsclient import mappings


class Serializable(metaclass=abc.ABCMeta):

    serialize_map = {}

    def __init__(self):
        self._plugins = {}
        self._error = None

    @staticmethod
    def serialize(item):
        try:
            return item.serialize_obj()
        except AttributeError:
            if isinstance(item, (list, tuple)):
                return [Serializable.serialize(elem) for elem in item]
            elif isinstance(item, dict):
                return {key: Serializable.serialize(val) for key, val in item.items()}
            else:
                return item

    def serialize_obj(self):
        if self._error is not None:
            return {"error": self._error}
        obj = {}
        for attr, val in self.__dict__.items():
            if attr.startswith("_"):
                continue
            if attr in self.serialize_map:
                func = self.serialize_map[attr]
                if func is None:
                    continue
                else:
                    val = func(val)
            res = Serializable.serialize(val)
            if res is not None:
                obj[attr] = res
        for name, plugin in self._plugins.items():
            if name in obj:
                raise ValueError(f"Node name {name} already in use")
            res = plugin.serialize_obj()
            if res is not None:
                obj[name] = res
        return obj

    def register(self, serializable_obj):
        node_name = serializable_obj.node_name
        if node_name in self._plugins:
            raise ValueError(
                f"Cannot register plugin: node name {node_name} already in use"
            )
        self._plugins[node_name] = serializable_obj

    def set_error(self, message):
        self._error = message


class SPVersions(Serializable):

    serialize_map = {
        "version": lambda x: {"name": x.name, "id": x.value},
        "server_preference": lambda x: x.name,
        "cipher_suites": lambda suites: [
            {
                "name": cs.cipher_suite.name,
                "id": cs.cipher_suite.value,
                "cert_chain_id": cs.cert_chain_id,
            }
            for cs in suites
        ],
    }

    def __init__(self, version, preference):
        super().__init__()
        self.version = version
        self.cipher_suites = []
        self.server_preference = preference

    # TODO: check if this logic should be moved to where it is actually needed.
    def get_dhe_cipher_suite(self):
        for cipher in self.cipher_suites:
            cs = mappings.supported_cipher_suites.get(cipher.cipher_suite)
            if cs is not None:
                if cs.key_ex in [
                    tls.KeyExchangeAlgorithm.DHE_DSS,
                    tls.KeyExchangeAlgorithm.DHE_RSA,
                ]:
                    return cipher.cipher_suite
        return None

    def get_cipher_suites(self):
        return [cs.cipher_suite for cs in self.cipher_suites]


class SPCertificateChain(Serializable):
    next_id = 0

    serialize_map = {
        "hash_val": None,
        "cert_chain": lambda cc: [cert.hex() for cert in cc],
    }

    @classmethod
    def get_next_id(cls):
        cls.next_id += 1
        return cls.next_id

    def __init__(self, hash_val, cert_chain):
        super().__init__()
        self.id = self.get_next_id()
        self.hash_val = hash_val
        self.cert_chain = cert_chain


class ServerProfile(Serializable):
    def __init__(self):
        super().__init__()
        self.versions = []
        self.certificate_chains = []

    def get_cert_chain_id(self, cert_chain):
        hash_val = hash(tuple(bytes(cert) for cert in cert_chain))
        for chain in self.certificate_chains:
            if hash_val == chain.hash_val:
                return chain.id
        new_chain = SPCertificateChain(hash_val, cert_chain)
        self.certificate_chains.append(new_chain)
        return new_chain.id

    def new_version(self, version, server_pref):
        if version in [vers.version for vers in self.versions]:
            raise ValueError(f"server profile: version {version.name} already present")
        self.versions.append(SPVersions(version, server_pref))

    def get_version(self, version):
        for vers in self.versions:
            if vers.version is version:
                return vers
        return None

    def add_cipher_suite(self, version, cs_tuple):
        for vers in self.versions:
            if vers.version == version:
                vers.cipher_suites.append(cs_tuple)
