# -*- coding: utf-8 -*-
"""Module containing classes for the key exchange
"""

import abc
import collections
import os
from tlsclient.protocol import ProtocolData
from tlsclient import mappings
import tlsclient.constants as tls

from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448, dh
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


def instantiate_named_group(group_name, conn, recorder):
    group = _supported_groups.get(group_name)
    if group is None:
        raise ValueError(f"the group {group_name} is not supported")
    kwargs = {"group_name": group_name}
    if group.algo is not None:
        kwargs["algo"] = group.algo
    return group.cls(conn, recorder, **kwargs)


class KeyExchange(metaclass=abc.ABCMeta):
    """The abstract class to derive different key exchange classes from
    """

    def __init__(self, conn, recorder, **kwargs):
        self._group_name = kwargs.get("group_name")
        self._conn = conn
        self._recorder = recorder

    @abc.abstractmethod
    def set_remote_key(self, rem_pub_key, **kwargs):
        """Store the remote public key
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_transferable_key(self):
        """Returns the ProtocolData for whatever is transferred to the peer
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_shared_secret(self):
        """Do everything needed to provide the premaster secret
        """
        raise NotImplementedError


class RsaKeyExchange(KeyExchange):
    """Implement an RSA based key transport
    """

    def __init__(self, *args, **kwargs):
        self._pms = None
        super().__init__(*args, **kwargs)

    def set_remote_key(self, rem_pub_key):
        """Not applicable for RSA based ley transport
        """
        raise NotImplementedError

    def _create_pms(self):
        """Build the premaster secret

        The client selects a random number, preceeded by the TLS version as sent in
        the ClientHello.
        """
        pms = ProtocolData()
        pms.append_uint16(self._conn.client_version_sent)
        random = self._recorder.inject(pms_rsa=os.urandom(46))
        pms.extend(random)
        self._pms = pms

    def get_transferable_key(self):
        if self._pms is None:
            self._create_pms()
        bin_cert = self._conn.msg.server_certificate.certificates[0]
        cert = x509.load_der_x509_certificate(bin_cert)
        pub_key = cert.public_key()
        ciphered_key = pub_key.encrypt(bytes(self._pms), padding.PKCS1v15())
        # injecting the encrypted key to the recorder is required, as the
        # padding scheme PKCS1v15 produces non-deterministic cipher text.
        return self._recorder.inject(rsa_enciphered=ciphered_key)

    def get_shared_secret(self):
        if self._pms is None:
            self._create_pms()
        return self._pms


class DhKeyExchange(KeyExchange):
    """Implement Diffie-Hellman key exchange
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._group_name is not None:
            dh_numbers = mappings.dh_numbers.get(self._group_name)
            if dh_numbers is None:
                raise ValueError(
                    f"No numbers defined for DH-group {self._group_name.name}"
                )
            self._gval = dh_numbers.g_val
            self._pval = int.from_bytes(dh_numbers.p_val, "big")
        else:
            self._pval = None
            self._gval = None
        self._rem_pub_key = None
        self._priv_key = None
        self._pub_key = None
        self._dh_group = None

    def _create_key_pair(self):
        self._dh_group = dh.DHParameterNumbers(self._pval, self._gval)
        if self._recorder.is_injecting():
            x_val = self._recorder.inject(x_val=None)
            y_val = self._recorder.inject(y_val=None)
            pub_numbers = dh.DHPublicNumbers(y_val, self._dh_group)
            priv_numbers = dh.DHPrivateNumbers(x_val, pub_numbers)
            self._priv_key = priv_numbers.private_key()
        else:
            self._priv_key = self._dh_group.parameters().generate_private_key()
        self._pub_key = self._priv_key.public_key()

    def get_shared_secret(self):
        if self._priv_key is None:
            self._create_key_pair()
        rem_pub_numbers = dh.DHPublicNumbers(self._rem_pub_key, self._dh_group)
        rem_pub_key = rem_pub_numbers.public_key()
        y_val = self._pub_key.public_numbers().y
        if self._recorder.is_recording():
            self._recorder.trace(x_val=self._priv_key.private_numbers().x)
            self._recorder.trace(y_val=y_val)
        return ProtocolData(self._priv_key.exchange(rem_pub_key).lstrip(b"\0"))

    def set_remote_key(self, rem_pub_key, g_val=None, p_val=None):
        self._pval = int.from_bytes(p_val, "big")
        self._gval = g_val
        self._rem_pub_key = int.from_bytes(rem_pub_key, "big")

    def get_transferable_key(self):
        if self._pub_key is None:
            self._create_key_pair()
        y_val = self._pub_key.public_numbers().y
        return y_val.to_bytes(int(self._pub_key.key_size / 8), "big")

    def get_key_share(self):
        return self.get_transferable_key()


class EcdhKeyExchange(KeyExchange):
    """Implement an ECDHE key exchange
    """

    def __init__(self, *args, **kwargs):
        self._algo = kwargs.get("algo")
        self._priv_key = None
        self._pub_key = None
        self._rem_pub_key = None
        super().__init__(*args, **kwargs)

    def _create_key_pair(self):
        seed = int.from_bytes(os.urandom(10), "big")
        seed = self._recorder.inject(ec_seed=seed)
        self._priv_key = ec.derive_private_key(seed, self._algo())
        pub_key = self._priv_key.public_key()
        self._pub_key = pub_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    def get_shared_secret(self):
        if self._priv_key is None:
            self._create_key_pair()
        rem_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self._algo(), bytes(self._rem_pub_key)
        )
        return ProtocolData(self._priv_key.exchange(ec.ECDH(), rem_pub_key))

    def set_remote_key(self, rem_pub_key):
        self._rem_pub_key = rem_pub_key

    def get_transferable_key(self):
        if self._pub_key is None:
            self._create_key_pair()
        return self._pub_key

    def get_key_share(self):
        if self._pub_key is None:
            self._create_key_pair()
        return self._pub_key


class XKeyExchange(KeyExchange):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._priv_key = None
        self._pub_key = None
        self._rem_pub_key = None
        if self._group_name is tls.SupportedGroups.X25519:
            self._private_key_lib = x25519.X25519PrivateKey
            self._public_key_lib = x25519.X25519PublicKey
        elif self._group_name is tls.SupportedGroups.X448:
            self._private_key_lib = x448.X448PrivateKey
            self._public_key_lib = x448.X448PublicKey
        else:
            raise ValueError(f"the group name {self._group_name.name} is not expected")

    def _create_key_pair(self):
        if self._recorder.is_injecting():
            priv_bytes = self._recorder.inject(private_key=None)
            self._priv_key = self._private_key_lib.from_private_bytes(priv_bytes)
        else:
            self._priv_key = self._private_key_lib.generate()
            if self._recorder.is_recording():
                priv_bytes = self._priv_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )
                self._recorder.trace(private_key=priv_bytes)
        pub_key = self._priv_key.public_key()
        self._pub_key = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def get_shared_secret(self):
        if self._priv_key is None:
            self._create_key_pair()
        rem_pub_key = self._public_key_lib.from_public_bytes(bytes(self._rem_pub_key))
        return ProtocolData(self._priv_key.exchange(rem_pub_key))

    def set_remote_key(self, rem_pub_key):
        self._rem_pub_key = rem_pub_key

    def get_transferable_key(self):
        if self._priv_key is None:
            self._create_key_pair()
        return self._pub_key

    def get_key_share(self):
        return self.get_transferable_key()


Group = collections.namedtuple("Group", "cls algo")

_supported_groups = {
    tls.SupportedGroups.SECT163K1: Group(cls=EcdhKeyExchange, algo=ec.SECT163K1),
    tls.SupportedGroups.SECT163R2: Group(cls=EcdhKeyExchange, algo=ec.SECT163R2),
    tls.SupportedGroups.SECT233K1: Group(cls=EcdhKeyExchange, algo=ec.SECT233K1),
    tls.SupportedGroups.SECT233R1: Group(cls=EcdhKeyExchange, algo=ec.SECT233R1),
    tls.SupportedGroups.SECT283K1: Group(cls=EcdhKeyExchange, algo=ec.SECT283K1),
    tls.SupportedGroups.SECT283R1: Group(cls=EcdhKeyExchange, algo=ec.SECT283R1),
    tls.SupportedGroups.SECT409K1: Group(cls=EcdhKeyExchange, algo=ec.SECT409K1),
    tls.SupportedGroups.SECT409R1: Group(cls=EcdhKeyExchange, algo=ec.SECT409R1),
    tls.SupportedGroups.SECT571K1: Group(cls=EcdhKeyExchange, algo=ec.SECT571K1),
    tls.SupportedGroups.SECT571R1: Group(cls=EcdhKeyExchange, algo=ec.SECT571R1),
    tls.SupportedGroups.SECP192R1: Group(cls=EcdhKeyExchange, algo=ec.SECP192R1),
    tls.SupportedGroups.SECP224R1: Group(cls=EcdhKeyExchange, algo=ec.SECP224R1),
    tls.SupportedGroups.SECP256K1: Group(cls=EcdhKeyExchange, algo=ec.SECP256K1),
    tls.SupportedGroups.SECP256R1: Group(cls=EcdhKeyExchange, algo=ec.SECP256R1),
    tls.SupportedGroups.SECP384R1: Group(cls=EcdhKeyExchange, algo=ec.SECP384R1),
    tls.SupportedGroups.SECP521R1: Group(cls=EcdhKeyExchange, algo=ec.SECP521R1),
    tls.SupportedGroups.BRAINPOOLP256R1: Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP256R1
    ),
    tls.SupportedGroups.BRAINPOOLP384R1: Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP384R1
    ),
    tls.SupportedGroups.BRAINPOOLP512R1: Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP512R1
    ),
    tls.SupportedGroups.X25519: Group(cls=XKeyExchange, algo=None),
    tls.SupportedGroups.X448: Group(cls=XKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE2048: Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE3072: Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE4096: Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE6144: Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE8192: Group(cls=DhKeyExchange, algo=None),
}
