# -*- coding: utf-8 -*-
"""Module containing classes for the key exchange
"""

import abc
import os
import collections
from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls

from cryptography.hazmat.primitives.asymmetric import ec, x25519, dh
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


Groups = collections.namedtuple("Groups", "curve_algo")

class KeyExchange(metaclass=abc.ABCMeta):
    """The abstract class to derive different key exchange classes from
    """

    def __init__(self, conn, recorder):
        self._conn = conn
        self._recorder = recorder

    def inspect_server_key_exchange(self, msg, fragment, offset):
        """Method to retrieve relevant data from a SeverKeyExchange message object
        """
        pass

    @abc.abstractmethod
    def setup_client_key_exchange(self, msg):
        """Method to setup a ClientKeyExchange message object
        """
        raise NotImplementedError

    @abc.abstractmethod
    def agree_on_premaster_secret(self):
        """Method to perform the actual key exchange
        """

class RsaKeyExchange(KeyExchange):
    """Implement an RSA based key transport
    """

    def setup_client_key_exchange(self, msg):
        """Construct the contents for a ClientKeyExchange message
        """
        bin_cert = self._conn.msg.server_certificate.certificates[0]
        cert = x509.load_der_x509_certificate(bin_cert)
        pub_key = cert.public_key()
        ciphered_key = pub_key.encrypt(bytes(self._pms), padding.PKCS1v15())
        # injecting the encrypted key to the recorder is required, as the
        # padding scheme PKCS1v15 produces non-deterministic cipher text.
        msg.encrypted_premaster_secret = self._recorder.inject(rsa_enciphered=ciphered_key)

    def agree_on_premaster_secret(self):
        """Build the premaster secret

        The client selects a random number, preceeded by the TLS version as sent in
        the ClientHello.
        """
        pms = ProtocolData()
        pms.append_uint16(self._conn.client_version_sent)
        random = self._recorder.inject(pms_rsa=os.urandom(46))
        pms.extend(random)
        self._pms = pms
        return pms


class DhKeyExchange(KeyExchange):
    """Implement Diffie-Hellman key exchange
    """

    def inspect_server_key_exchange(self, msg):
        self._p_val = int.from_bytes(msg.dh.p_val, "big")
        self._g_val = msg.dh.g_val
        self._rem_pub_key = int.from_bytes(msg.dh.public_key, "big")

    def setup_client_key_exchange(self, msg):
        msg.client_dh_public = self._local_pub_key

    def agree_on_premaster_secret(self):
        dh_group = dh.DHParameterNumbers(self._p_val, self._g_val)
        if self._recorder.is_injecting():
            x_val = self._recorder.inject(x_val=None)
            y_val = self._recorder.inject(y_val=None)
            pub_numbers = dh.DHPublicNumbers(y_val, dh_group)
            priv_numbers = dh.DHPrivateNumbers(x_val, pub_numbers)
            priv_key = priv_numbers.private_key()
        else:
            priv_key = dh_group.parameters().generate_private_key()
        pub_key = priv_key.public_key()
        rem_pub_numbers = dh.DHPublicNumbers(self._rem_pub_key, dh_group)
        rem_pub_key = rem_pub_numbers.public_key()
        y_val = pub_key.public_numbers().y
        self._recorder.trace(x_val=priv_key.private_numbers().x)
        self._recorder.trace(y_val=y_val)
        self._local_pub_key = y_val.to_bytes(int(pub_key.key_size / 8), "big")
        return ProtocolData(priv_key.exchange(rem_pub_key).lstrip(b"\0"))

class EcdhKeyExchange(KeyExchange):
    """Implement an ECDHE key exchange
    """

    _supported_groups = {
        tls.SupportedGroups.SECT163K1: Groups(curve_algo=ec.SECT163K1),
        tls.SupportedGroups.SECT163R2: Groups(curve_algo=ec.SECT163R2),
        tls.SupportedGroups.SECT233K1: Groups(curve_algo=ec.SECT233K1),
        tls.SupportedGroups.SECT233R1: Groups(curve_algo=ec.SECT233R1),
        tls.SupportedGroups.SECT283K1: Groups(curve_algo=ec.SECT283K1),
        tls.SupportedGroups.SECT283R1: Groups(curve_algo=ec.SECT283R1),
        tls.SupportedGroups.SECT409K1: Groups(curve_algo=ec.SECT409K1),
        tls.SupportedGroups.SECT409R1: Groups(curve_algo=ec.SECT409R1),
        tls.SupportedGroups.SECT571K1: Groups(curve_algo=ec.SECT571K1),
        tls.SupportedGroups.SECT571R1: Groups(curve_algo=ec.SECT571R1),
        tls.SupportedGroups.SECP192R1: Groups(curve_algo=ec.SECP192R1),
        tls.SupportedGroups.SECP224R1: Groups(curve_algo=ec.SECP224R1),
        tls.SupportedGroups.SECP256K1: Groups(curve_algo=ec.SECP256K1),
        tls.SupportedGroups.SECP256R1: Groups(curve_algo=ec.SECP256R1),
        tls.SupportedGroups.SECP384R1: Groups(curve_algo=ec.SECP384R1),
        tls.SupportedGroups.SECP521R1: Groups(curve_algo=ec.SECP521R1),
        tls.SupportedGroups.BRAINPOOLP256R1: Groups(curve_algo=ec.BrainpoolP256R1),
        tls.SupportedGroups.BRAINPOOLP384R1: Groups(curve_algo=ec.BrainpoolP384R1),
        tls.SupportedGroups.BRAINPOOLP512R1: Groups(curve_algo=ec.BrainpoolP512R1),
    }

    def inspect_server_key_exchange(self, msg):
        self._curve_type = msg.ec.curve_type
        self._named_curve = msg.ec.named_curve
        self._rem_key = msg.ec.public
        self._sig_scheme = msg.ec.signature_scheme
        self._signature = msg.ec.signature

    def setup_client_key_exchange(self, msg):
        msg.client_ec_public = self._pub_key


    def _pms_supported_curve(self, curve_algo):
        seed = int.from_bytes(os.urandom(10),"big")
        seed = self._recorder.inject(ec_seed=seed)
        priv_key = ec.derive_private_key(seed, curve_algo())
        pub_key = priv_key.public_key()
        self._pub_key = pub_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        rem_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(curve_algo(), bytes(self._rem_key))
        return ProtocolData(priv_key.exchange(ec.ECDH(), rem_pub_key))

    def _pms_x25519(self):
        if self._recorder.is_injecting():
            priv_bytes = self._recorder.inject(private_key=None)
            priv_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        else:
            priv_key = x25519.X25519PrivateKey.generate()
            if self._recorder.is_recording():
                priv_bytes = priv_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )
                self._recorder.trace(private_key=priv_bytes)
        pub_key = priv_key.public_key()
        self._pub_key = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pass
        rem_pub_key = x25519.X25519PublicKey.from_public_bytes(bytes(self._rem_key))
        pass
        return ProtocolData(priv_key.exchange(rem_pub_key))

    def agree_on_premaster_secret(self):
        if self._curve_type == tls.EcCurveType.NAMED_CURVE:
            if self._named_curve == tls.SupportedGroups.X25519:
                return self._pms_x25519()
            elif self._named_curve == tls.SupportedGroups.X448:
                raise NotImplementedError
            else:
                supported_curve = self._supported_groups.get(self._named_curve)
                if supported_curve is not None:
                    return self._pms_supported_curve(supported_curve.curve_algo)
        raise NotImplementedError
