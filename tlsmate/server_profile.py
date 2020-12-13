# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
from collections import OrderedDict
from tlsmate import constants as tls
from tlsmate import structures as structs
from tlsmate import utils
from cryptography.hazmat.primitives.serialization import Encoding


class YamlBlockStyle(str):
    """Class used to indicate that a string shall be serialized using the block style.
    """

    pass


class ProfileObject(metaclass=abc.ABCMeta):
    """Abstract base class to derive profile classes from
    """

    def serialize(self):
        raise NotImplementedError


class ProfileBasic(ProfileObject):
    """Profile class for a simple object (!= lists, dicts)

    Arguments:
        value: the value of the simple object
    """

    def __init__(self, value):
        self._value = value

    def serialize(self):
        """Serializes the object.

        Returns:
            type: the value of the object
        """
        return self._value

    def get(self):
        """Synonym for serialize.
        """
        return self._value

    def set(self, value):
        """Sets the object to a given value

        Arguments:
            value: The new value of the object
        """
        self._value = value


class ProfileBasicEnum(ProfileBasic):
    """Class for a Enum object, which will be represented by its name
    """

    def serialize(self):
        """Serializes the name of the enum.

        Returns:
            str: the enum's name
        """
        return self._value.name


class ProfileDict(ProfileObject):
    """Class representing a dict.

    All entries in the dict must have the type :class:`ProfileObject`.
    """

    def __init__(self):
        self._dict = {}

    def add(self, name, obj, keep_existing=False):
        """Add an object to the dict.

        Arguments:
            name (str): the name for the dict key
            obj: the object/value for the new dict entry
            keep_existing (bool): An indication, if an existing entry shall be replaced
                or not. Default is False.

        Raises:
            TypeError: if the object is not a :class:`ProfileObject`
            ValueError: if the entry is already present and keep_existing is False
        """
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
        """Serializes the object

        Returns:
            dict: the serialized object
        """
        obj = {}
        for key, prof_obj in self._dict.items():
            val = prof_obj.serialize()
            if val is not None:
                obj[key] = val
        return obj

    def get(self, name):
        """Return the value for a given key

        Arguments:
            name (str): the key

        Returns:
            type: the value, of None if the key is not present
        """
        return self._dict.get(name)


class ProfileEnum(ProfileDict):
    """Class for an Enum.

    Difference to "ProfileBasicEnum": It is a dict containing the id and the name.
    """

    def __init__(self, enum):
        super().__init__()
        self.add("name", ProfileBasic(enum.name))
        self.add("id", ProfileBasic(enum.value))
        self._enum = enum

    def get_enum(self):
        """Return the enum

        Return:
            (type): the enum
        """
        return self._enum

    def set(self, value):
        """Set the enum

        Arguments:
            value: the enum
        """
        self._value = value


class ProfileList(ProfileObject):
    """Class for a list. The items within the list must be unique.

    Note, that each item in the list must have an identifier, thus it is rather
    similiar to a dict (indeed, internally a dict is used to store the values).
    The main difference is, when it comes to serialization, here a list is returned.
    """

    def __init__(self, key_func):
        self._dict = OrderedDict()
        self._key_func = key_func

    def serialize(self):
        """Serialize the list

        Returns:
            list: the list
        """
        return [item.serialize() for item in self._dict.values()]

    def append(self, obj, keep_existing=False):
        """Appends an item to the list

        Arguments:
            obj: the item to append
            keep_existing (bool): An indication, if an existing entry shall be replaced
                or not. Default is False.

        Raises:
            TypeError: if the object is not a :class:`ProfileObject`
            ValueError: if the entry is already present and keep_existing is False
        """
        if not isinstance(obj, ProfileObject):
            raise TypeError("only ProfileObject can be added to a profile list")
        key = self._key_func(obj)
        if key in self._dict:
            if keep_existing:
                return
            raise ValueError(f"element {key} already present in profile list")
        self._dict[key] = obj

    def key(self, key):
        """Get the item for a given key.

        Arguments:
            key: the key to retrieve

        Returns:
            type: the object of the list
        """
        return self._dict.get(key)

    def all(self):
        """Returns all keys.

        Returns:
            list: a list of all keys
        """
        return list(self._dict.keys())


class SPSignatureAlgorithms(ProfileDict):
    """Class to represent the SignatureAlgorithms in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("server_preference", ProfileBasicEnum(tls.SPBool.C_NA))
        self.add("algorithms", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("info", None)


class SPSupportedGroups(ProfileDict):
    """Class to represent the SupportedGroups in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("extension_supported", ProfileBasicEnum(tls.SPBool.C_UNDETERMINED))
        self.add("groups", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("groups_advertised", None)
        self.add("extension_supported", None)


class SPFeatures(ProfileDict):
    """Class to represent the features/procedures in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("compression", None)
        self.add("encrypt_then_mac", None)


class SPVersions(ProfileDict):
    """Class to represent the TLS versions in the server profile.
    """

    def __init__(self, version, server_pref):
        super().__init__()
        self.add("version", ProfileEnum(version))
        self.add("server_preference", ProfileBasicEnum(server_pref))
        self.add("cipher_suites", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("supported_groups", SPSupportedGroups())
        self.add("signature_algorithms", None)


class SPCertificateChain(ProfileDict):
    """Class to represent a certificate chain in the server profile.
    """

    def __init__(self, chain, idx):
        super().__init__()
        self.add("id", ProfileBasic(idx))
        cert_list = ProfileList(key_func=lambda x: x.get())
        self.add("cert_chain", cert_list)
        for cert in chain:
            string = cert.public_bytes(Encoding.PEM).decode()
            cert_list.append(ProfileBasic(YamlBlockStyle(string)))


class SPCertificateChainList(ProfileList):
    """Class to represent a list of certificate chains in the server profile.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hash = {}

    def append_unique(self, chain):
        """Append a chain only, if not yet present.

        Arguments:
            chain (bytes): the chain to add

        Returns:
            int: the index of the chain, which may be created newly, or it might have
                been present already.
        """
        hash_val = hash(tuple(chain))
        if hash_val in self._hash:
            return self._hash[hash_val]
        idx = len(self._hash) + 1
        self._hash[hash_val] = idx
        self.append(SPCertificateChain(chain, idx))
        return idx


class ServerProfile(ProfileDict):
    """Class for the base (root) server profile object.
    """

    def __init__(self):
        super().__init__()
        self.add(
            "versions", ProfileList(key_func=lambda x: x.get("version").get_enum())
        )
        self.add("cert_chain", SPCertificateChainList(key_func=lambda x: x.get("id")))
        self.add("features", SPFeatures())

    def get_supported_groups(self, version):
        """Get all supported groups for a given TLS version.

        Arguments:
            version (:class:`tlsmate.constants.Version`): the TLS version to use

        Returns:
            list: a list of all supported groups supported by the server for the given
                TLS version.
        """
        prof_version = self.get("versions").key(version)
        return prof_version.get("supported_groups").get("groups").all()

    def get_signature_algorithms(self, version):
        """Get all signature algorithms for a given TLS version.

        Arguments:
            version (:class:`tlsmate.constants.Version`): the TLS version to use

        Returns:
            list: a list of all signature algorithms supported by the server for the
                given TLS version.
        """
        prof_version = self.get("versions").key(version)
        sig_algs = prof_version.get("signature_algorithms")
        if sig_algs is None:
            return []
        return sig_algs.get("algorithms").all()

    def get_versions(self):
        """Get the supported TLS versions from the profile.

        Returns:
            list of :class:`tlsmate.constants.Version`: all TLS versions supported
                by the server
        """
        return self.get("versions").all()

    def get_cipher_suites(self, version):
        """Get the supported cipher suites from the profile for a given TLS version.

        Returns:
            list of :class:`tlsmate.constants.CipherSuite`: all cipher suites supported
                by the server for the given TLS version
        """
        prof_version = self.get("versions").key(version)
        return prof_version.get("cipher_suites").all()

    def get_profile_values(self, filter_versions, full_hs=False):
        """Get a set of some common attributes for the given TLS version(s).

        Arguments:
            filter_versions (list of :class:`tlsmate.constants.Version`): the list of
                TLS versions to retrieve the data for
            full_hs (bool): an indication if only those cipher suites shall be returned
                for which a full handshake is supported. Defaults to False.

        Returns:
            :obj:`tlsmate.structures.ProfileValues`: a structure that provides a list of
                the versions, the cipher suites, the supported groups and the
                signature algorithms
        """
        versions = []
        cipher_suites = set()
        sig_algos = set()
        groups = set()
        for version in self.get_versions():
            if version not in filter_versions:
                continue
            versions.append(version)
            cipher_suites = cipher_suites.union(set(self.get_cipher_suites(version)))
            sig_algos = sig_algos.union(set(self.get_signature_algorithms(version)))
            groups = groups.union(set(self.get_supported_groups(version)))
        if full_hs:
            cipher_suites = utils.filter_cipher_suites(cipher_suites, full_hs=True)
        return structs.ProfileValues(
            versions=versions,
            cipher_suites=cipher_suites,
            supported_groups=list(groups),
            signature_algorithms=list(sig_algos),
        )
