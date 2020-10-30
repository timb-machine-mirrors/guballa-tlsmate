# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
from collections import OrderedDict
from typing import NamedTuple


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
    def __init__(self, key):
        self._key_property = key
        self._list = OrderedDict()

    def key(self, key):
        return self._list.get(key)

    def serialize_obj(self):
        return [Serializable.serialize(obj) for obj in self._list.values()]

    def all(self):
        return list(self._list.keys())

    def append(self, data, keep_existing=False):
        key = getattr(data, self._key_property)
        if key in self._list:
            if not keep_existing:
                raise ValueError(
                    f"conflict for appending list: element {key} already existing"
                )
        else:
            self._list[key] = data
        return self._list[key]


class SPCipherSuite(Serializable):
    serialize_map = {
        "cert_chain_id": lambda self: self.cert_chain_id,
        "name": lambda self: self.cs.name,
        "id": lambda self: self.cs.value,
    }

    def __init__(self, struct):
        super().__init__()
        self.cs = struct.cipher_suite
        self.cert_chain_id = struct.cert_chain_id


class SPVersions(Serializable):

    serialize_map = {
        "server_preference": lambda self: self.server_preference.name,
        "version": lambda self: {"name": self.version.name, "id": self.version.value},
        "cipher_suites": lambda self: self.cipher_suites,
    }

    def __init__(self, version, server_pref):
        super().__init__()
        self.version = version
        self.server_preference = server_pref
        self.cipher_suites = SerializableList("cs")


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


class ServerProfile(Serializable):
    serialize_map = {
        "versions": lambda self: self.versions,
        "cert_chain": lambda self: self.cert_chain,
    }

    def __init__(self):
        super().__init__()
        self.versions = SerializableList(key="version")
        self.cert_chain = SPCertificateChainList(key="id")
