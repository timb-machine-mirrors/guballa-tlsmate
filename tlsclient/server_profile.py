# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
from collections import OrderedDict
from tlsclient import constants as tls


class ProfileObject(metaclass=abc.ABCMeta):
    def serialize(self):
        raise NotImplementedError


class ProfileBasic(ProfileObject):
    def __init__(self, value):
        self._value = value

    def serialize(self):
        return self._value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class ProfileBasicEnum(ProfileBasic):
    def serialize(self):
        return self._value.name


class ProfileDict(ProfileObject):
    def __init__(self):
        self._dict = {}

    def add(self, name, obj, keep_existing=False):
        if obj is None:
            # it is more a documentational feature than a functional one
            return
        if not isinstance(obj, ProfileObject):
            raise TypeError("only ProfileObject can be added to a profile object")
        if name in self._dict:
            if keep_existing:
                return
            raise ValueError(f"cannot use the same name {name} twice in the profile")
        self._dict[name] = obj

    def serialize(self):
        obj = {}
        for key, prof_obj in self._dict.items():
            val = prof_obj.serialize()
            if val is not None:
                obj[key] = val
        return obj

    def get(self, name):
        return self._dict.get(name)


class ProfileEnum(ProfileDict):
    def __init__(self, enum):
        super().__init__()
        self.add("name", ProfileBasic(enum.name))
        self.add("id", ProfileBasic(enum.value))
        self._enum = enum

    def get_enum(self):
        return self._enum

    def set(self, value):
        self._value = value


class ProfileList(ProfileObject):
    def __init__(self, key_func):
        self._dict = OrderedDict()
        self._key_func = key_func

    def serialize(self):
        return [item.serialize() for item in self._dict.values()]

    def append(self, obj, keep_existing=False):
        if not isinstance(obj, ProfileObject):
            raise TypeError("only ProfileObject can be added to a profile list")
        key = self._key_func(obj)
        if key in self._dict:
            if keep_existing:
                return
            raise ValueError(f"element {key} already present in profile list")
        self._dict[key] = obj

    def key(self, key):
        return self._dict.get(key)

    def all(self):
        return list(self._dict.keys())


class SPSignatureAlgorithms(ProfileDict):
    def __init__(self):
        super().__init__()
        self.add("server_preference", ProfileBasicEnum(tls.SPBool.C_NA))
        self.add("algorithms", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("info", None)


class SPSupportedGroups(ProfileDict):
    def __init__(self):
        super().__init__()
        self.add("extension_supported", ProfileBasicEnum(tls.SPBool.C_UNDETERMINED))
        self.add("groups", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("groups_advertised", None)
        self.add("extension_supported", None)


class SPFeatures(ProfileDict):
    def __init__(self):
        super().__init__()
        self.add("compression", None)
        self.add("encrypt_then_mac", None)


class SPVersions(ProfileDict):
    def __init__(self, version, server_pref):
        super().__init__()
        self.add("version", ProfileEnum(version))
        self.add("server_preference", ProfileBasicEnum(server_pref))
        self.add("cipher_suites", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("supported_groups", SPSupportedGroups())
        self.add("signature_algorithms", None)


class SPCertificateChain(ProfileDict):
    def __init__(self, chain, idx):
        super().__init__()
        self.add("id", ProfileBasic(idx))
        cert_list = ProfileList(key_func=lambda x: x.get())
        self.add("cert_chain", cert_list)
        for cert in chain:
            cert_list.append(ProfileBasic(cert.hex()))


class SPCertificateChainList(ProfileList):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hash = {}

    def append_unique(self, chain):
        hash_val = hash(tuple(chain))
        if hash_val in self._hash:
            return self._hash[hash_val]
        idx = len(self._hash) + 1
        self._hash[hash_val] = idx
        self.append(SPCertificateChain(chain, idx))
        return idx


class ServerProfile(ProfileDict):
    def __init__(self):
        super().__init__()
        self.add(
            "versions", ProfileList(key_func=lambda x: x.get("version").get_enum())
        )
        self.add("cert_chain", SPCertificateChainList(key_func=lambda x: x.get("id")))
        self.add("features", SPFeatures())

    def get_supported_groups(self, version):
        prof_version = self.get("versions").key(version)
        return prof_version.get("supported_groups").get("groups").all()

    def get_signature_algorithms(self, version):
        prof_version = self.get("versions").key(version)
        sig_algs = prof_version.get("signature_algorithms")
        if sig_algs is None:
            return []
        return sig_algs.get("algorithms").all()

    def get_versions(self):
        return self.get("versions").all()

    def get_cipher_suites(self, version):
        prof_version = self.get("versions").key(version)
        return prof_version.get("cipher_suites").all()
