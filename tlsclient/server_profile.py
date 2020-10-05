# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
import enum
import collections


class Serializable(metaclass=abc.ABCMeta):

    serialize_map = {}

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
        obj = {}
        for attr, val in self.__dict__.items():
            if attr in self.serialize_map:
                func = self.serialize_map[attr]
                if func is None:
                    continue
                else:
                    val = func(val)
            obj[attr] = Serializable.serialize(val)
        return obj


SPCipherSuite = collections.namedtuple("SPCipherSuite", "cipher_suite cert_chain_id")


class SPBool(enum.Enum):
    C_FALSE = 0
    C_TRUE = 1
    C_NA = 2
    C_UNDETERMINED = 3


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
        self.version = version
        self.cipher_suites = []
        self.server_preference = preference


class SPCertificateChain(Serializable):
    next_identifier = 0

    serialize_map = {
        "hash_val": None,
        "cert_chain": lambda cc: [cert.hex() for cert in cc],
    }

    @classmethod
    def get_next_identifier(cls):
        cls.next_identifier += 1
        return cls.next_identifier

    def __init__(self, hash_val, cert_chain):
        self.identifier = self.get_next_identifier()
        self.hash_val = hash_val
        self.cert_chain = cert_chain


class ServerProfile(Serializable):
    def __init__(self):
        self.versions = []
        self.certificate_chains = []

    def get_cert_chain_id(self, cert_chain):
        hash_val = hash(tuple(bytes(cert) for cert in cert_chain))
        for chain in self.certificate_chains:
            if hash_val == chain.hash_val:
                return chain.identifier
        new_chain = SPCertificateChain(hash_val, cert_chain)
        self.certificate_chains.append(new_chain)
        return new_chain.identifier

    def new_version(self, version, server_pref):
        if version in [vers.version for vers in self.versions]:
            raise ValueError(f"server profile: version {version.name} already present")
        self.versions.append(SPVersions(version, server_pref))

    def add_cipher_suite(self, version, cs_tuple):
        for vers in self.versions:
            if vers.version == version:
                vers.cipher_suites.append(cs_tuple)
