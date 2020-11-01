# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
import sys
import time
import datetime
from collections import OrderedDict
from typing import NamedTuple
from tlsclient import constants as tls
from tlsclient.version import __version__


class _Plugin(NamedTuple):
    obj: type
    as_child: str


class Serializable(metaclass=abc.ABCMeta):

    serialize_map = {}

    def __init__(self):
        self._plugins = {}

    def register(self, obj, as_child=None):
        if obj.name in self._plugins:
            raise ValueError(
                f"Serializable {self}: cannot register Serializable {obj.name}: "
                f"name already in use"
            )
        self._plugins[obj.name] = _Plugin(obj=obj, as_child=as_child)

    def plugin(self, name):
        plugin_struct = self._plugins.get(name)
        if plugin_struct is None:
            return None
        return plugin_struct.obj

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
        status = getattr(self, "_status", None)
        if status is not None:
            return {"status": status}
        obj = {}
        for attr, func in self.serialize_map.items():
            try:
                val = func(self)
            except AttributeError:
                pass
            else:
                res = Serializable.serialize(val)
                if res is not None:
                    obj[attr] = res
        for name, plugin_struct in self._plugins.items():
            obj2 = plugin_struct.obj.serialize_obj()
            if plugin_struct.as_child is not None:
                if plugin_struct.as_child in obj:
                    raise ValueError(f"Serializable {name}: conflicting attribute name")
                obj[plugin_struct.as_child] = obj2
            else:
                if set(obj).intersection(set(obj2)):
                    raise ValueError(f"Serializable {name}: conflicting attribute name")
                obj.update(obj2)
        return obj

    def set_status(self, message):
        self._status = message


class SerializableList(object):
    def __init__(self, key_property=None, key_func=None):
        self._key_property = key_property
        self._key_func = key_func
        self._list = OrderedDict()

    def key(self, key):
        return self._list.get(key)

    def serialize_obj(self):
        return [Serializable.serialize(obj) for obj in self._list.values()]

    def all(self):
        return list(self._list.keys())

    def append(self, data, keep_existing=False):
        if self._key_func is not None:
            key = self._key_func(data)
        else:
            key = getattr(data, self._key_property)
        if key in self._list:
            if not keep_existing:
                raise ValueError(
                    f"conflict for appending list: element {key} already existing"
                )
        else:
            self._list[key] = data
        return self._list[key]


class SPSigAlgo(Serializable):

    serialize_map = {
        "name": lambda self: self.algorithm.name,
        "id": lambda self: self.algorithm.value,
    }

    def __init__(self, sig_algo):
        super().__init__()
        self.algorithm = sig_algo


class SPSignatureAlgorithms(Serializable):

    serialize_map = {
        "server_preference": lambda self: self.server_preference.name,
        "algorithms": lambda self: self.algorithms,
        "info": lambda self: self.info,
    }

    def __init__(self):
        super().__init__()
        self.server_preference = tls.SPBool.C_NA
        self.algorithms = SerializableList(key_property="algorithm")
        self.info = None


class SPCipherSuite(Serializable):
    serialize_map = {
        "name": lambda self: self.cipher_suite.name,
        "id": lambda self: self.cipher_suite.value,
    }

    def __init__(self, struct):
        super().__init__()
        self.cipher_suite = struct.cipher_suite


class SPGroup(Serializable):

    serialize_map = {
        "name": lambda self: self.group.name,
        "id": lambda self: self.group.value,
    }

    def __init__(self, group):
        super().__init__()
        self.group = group


class SPSupportedGroups(Serializable):

    serialize_map = {
        "groups": lambda self: self.groups,
        "server_preference": lambda self: self.server_preference.name,
        "groups_advertised": lambda self: self.groups_advertised.name,
        "extension_supported": lambda self: self.extension_supported.name,
    }

    def __init__(self):
        super().__init__()
        self.extension_supported = tls.SPBool.C_UNDETERMINED
        self.groups = SerializableList(key_property="group")
        self.server_preference = tls.SPBool.C_UNDETERMINED
        self.groups_advertised = tls.SPBool.C_UNDETERMINED


class SPVersion(Serializable):

    serialize_map = {
        "name": lambda self: self.version.name,
        "id": lambda self: self.version.value,
    }

    def __init__(self, version):
        super().__init__()
        self.version = version


class SPVersions(Serializable):

    serialize_map = {
        "server_preference": lambda self: self.server_preference.name,
        "version": lambda self: self.version,
        "cipher_suites": lambda self: self.cipher_suites,
        "supported_groups": lambda self: self.supported_groups,
        "signature_algorithms": lambda self: self.signature_algorithms,
    }

    def __init__(self, version, server_pref):
        super().__init__()
        self.version = SPVersion(version)
        self.server_preference = server_pref
        self.cipher_suites = SerializableList(key_property="cipher_suite")
        self.supported_groups = SPSupportedGroups()
        self.signature_algorithms = None


class SPCertificateChain(Serializable):
    serialize_map = {
        "id": lambda self: self.id,
        "cert_chain": lambda self: [cert.hex() for cert in self.cert_chain],
    }

    def __init__(self, chain, idx):
        super().__init__()
        self.id = idx
        self.cert_chain = chain


class SPCertificateChainList(SerializableList):
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


class SPScanner(Serializable):
    name = "scan_info"

    serialize_map = {
        "command": lambda self: self.command,
        "version": lambda self: self.version,
        "start_time": lambda self: self.start_timestamp,
        "start_date": lambda self: self.start_date,
        "stop_timestamp": lambda self: self.stop_timestamp,
        "stop_date": lambda self: self.stop_date,
        "run_time": lambda self: self.run_time,
    }

    def __init__(self):
        super().__init__()
        self.command = " ".join(sys.argv)
        self.version = __version__
        self.start_timestamp = time.time()
        self.start_date = datetime.datetime.fromtimestamp(int(self.start_timestamp))
        self.stop_timestamp = None
        self.stop_date = None
        self.run_time = None

    def end(self):
        self.stop_timestamp = time.time()
        self.stop_date = datetime.datetime.fromtimestamp(int(self.stop_timestamp))
        self.run_time = float(f"{self.stop_timestamp - self.start_timestamp:.3f}")


class ServerProfile(Serializable):
    serialize_map = {
        "versions": lambda self: self.versions,
        "cert_chain": lambda self: self.cert_chain,
        "scan_info": lambda self: self.scan_info,
    }

    def __init__(self):
        super().__init__()
        self.versions = SerializableList(key_func=lambda obj: obj.version.version)
        self.cert_chain = SPCertificateChainList(key_property="id")
        self.scan_info = None
