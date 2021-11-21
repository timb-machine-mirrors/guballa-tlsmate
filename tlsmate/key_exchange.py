# -*- coding: utf-8 -*-
"""Module containing classes for the key exchange
"""
# import basic stuff
import abc
from typing import NamedTuple
import os

# import own stuff
from tlsmate import dh_numbers
from tlsmate import tls
from tlsmate import pdu
from tlsmate.exception import ServerMalfunction, CurveNotSupportedError
from tlsmate import kdf

# import other stuff
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448, dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_der_private_key,
)


def verify_signed_params(prefix, params, cert, default_scheme, version):
    """Verify the signed parameters from a ServerKeyExchange message.

    Arguments:
        prefix (bytes): the bytes to prepend to the data
        params: the parameter block from the ServerKeyExchange message
        cert (:obj:`tlsmate.cert.Certificate`): the certificate used to validate
            the data
        default_scheme (:class:`tlsmate.tls.SignatureScheme`): the default
            signature scheme to use (if not present in the message)
        version (:class:`tlsmate.tls.Version`): the TLS version. For TLS1.1 and below
            the signature is constructed differently (using SHA1 + MD digests)
    Raises:
        cryptography.exceptions.InvalidSignature: If the signature does not
            validate.
    """

    data = prefix + params.signed_params

    if (
        default_scheme is tls.SignatureScheme.RSA_PKCS1_SHA1
        and version is not tls.Version.TLS12
    ):
        # Digest is a combination of MD5 and SHA1
        digest = kdf.Kdf()
        digest.start_msg_digest()
        digest.set_msg_digest_algo(None)
        digest.update_msg_digest(data)
        hashed1 = digest.current_msg_digest(suspend=True)
        key = cert.parsed.public_key()
        hashed2 = key.recover_data_from_signature(
            params.signature, padding.PKCS1v15(), None
        )
        if hashed1 != hashed2:
            raise InvalidSignature

    else:
        sig_scheme = params.sig_scheme or default_scheme
        cert.validate_signature(sig_scheme, data, params.signature)


def verify_certificate_verify(cert_ver, msgs, msg_digest):
    """Validates the CertificateVerify message.

    Arguments:
        cert_ver (:obj:`tlsmate.msg.CertificateVerify`): the CertificateVerify
            message to verify
        msgs (:obj:`tlsmate.connection.TlsConnectionMsgs`): the object storing
            received/sent messages
        msg_digest (bytes): the message digest used to construct the data to validate

    Raises:
        cryptography.exceptions.InvalidSignature: If the signature does not
            validate.
    """

    data = (b" " * 64) + b"TLS 1.3, server CertificateVerify" + b"\0" + msg_digest
    cert = msgs.server_certificate.chain.certificates[0]
    cert.validate_signature(cert_ver.signature_scheme, data, cert_ver.signature)


def _verify_rsa_pkcs(pub_key, signature, data, hash_algo):
    pub_key.verify(signature, data, padding.PKCS1v15(), hash_algo())


def _verify_dsa(pub_key, signature, data, hash_algo):
    pub_key.verify(signature, data, hash_algo())


def _verify_ecdsa(pub_key, signature, data, hash_algo):
    pub_key.verify(signature, data, ec.ECDSA(hash_algo()))


def _verify_xcurve(pub_key, signature, data, hash_algo):
    pub_key.verify(signature, data)


def _verify_rsae_pss(pub_key, signature, data, hash_algo):
    pub_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo()), salt_length=hash_algo.digest_size),
        hash_algo(),
    )


_sig_schemes = {
    tls.SignatureScheme.RSA_PKCS1_MD5: (_verify_rsa_pkcs, hashes.MD5),
    tls.SignatureScheme.RSA_PKCS1_SHA1: (_verify_rsa_pkcs, hashes.SHA1),
    tls.SignatureScheme.RSA_PKCS1_SHA224: (_verify_rsa_pkcs, hashes.SHA224),
    tls.SignatureScheme.RSA_PKCS1_SHA256: (_verify_rsa_pkcs, hashes.SHA256),
    tls.SignatureScheme.RSA_PKCS1_SHA384: (_verify_rsa_pkcs, hashes.SHA384),
    tls.SignatureScheme.RSA_PKCS1_SHA512: (_verify_rsa_pkcs, hashes.SHA512),
    tls.SignatureScheme.DSA_MD5: (_verify_dsa, hashes.MD5),
    tls.SignatureScheme.DSA_SHA1: (_verify_dsa, hashes.SHA1),
    tls.SignatureScheme.DSA_SHA224: (_verify_dsa, hashes.SHA224),
    tls.SignatureScheme.DSA_SHA256: (_verify_dsa, hashes.SHA256),
    tls.SignatureScheme.DSA_SHA384: (_verify_dsa, hashes.SHA384),
    tls.SignatureScheme.DSA_SHA512: (_verify_dsa, hashes.SHA512),
    tls.SignatureScheme.ECDSA_SHA1: (_verify_ecdsa, hashes.SHA1),
    tls.SignatureScheme.ECDSA_SECP256R1_SHA256: (_verify_ecdsa, hashes.SHA256),
    tls.SignatureScheme.ECDSA_SECP384R1_SHA384: (_verify_ecdsa, hashes.SHA384),
    tls.SignatureScheme.ECDSA_SECP521R1_SHA512: (_verify_ecdsa, hashes.SHA512),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA256: (_verify_rsae_pss, hashes.SHA256),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA384: (_verify_rsae_pss, hashes.SHA384),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA512: (_verify_rsae_pss, hashes.SHA512),
    tls.SignatureScheme.ED25519: (_verify_xcurve, None),
    tls.SignatureScheme.ED448: (_verify_xcurve, None),
}


def instantiate_named_group(group_name, conn, recorder):
    """Create a KeyExchange object according to the given group name.

    Arguments:
        group_name (:class:`tlsmate.tls.SupportedGroups`): the group name
        conn (:obj:`tlsmate.connection.TlsConnection`): a connection object
        recorder (:obj:`tlsmate.recorder.Recorder`): the recorder object

    Returns:
        :obj:`KeyExchange`: the created object
    """

    group = _supported_groups.get(group_name)
    if group is None:
        raise CurveNotSupportedError(
            f"the group {group_name} is not supported", group_name
        )

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
        """Returns the pdu-format for whatever is transferred to the peer
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

    def set_remote_key(self, rem_pub_key, **kwargs):
        """Not applicable for RSA based ley transport
        """

        raise NotImplementedError

    def _create_pms(self):
        """Build the premaster secret

        The client selects a random number, preceded by the TLS version as sent in
        the ClientHello.
        """
        pms = bytearray()
        version = self._conn.client_version_sent
        val = getattr(version, "value", version)
        pms.extend(pdu.pack_uint16(val))
        random = self._recorder.inject(pms_rsa=os.urandom(46))
        pms.extend(random)
        self._pms = pms

    def get_transferable_key(self):
        """Returns an RSA-encrypted key

        Returns:
            bytes: the encrypted key
        """

        if self._pms is None:
            self._create_pms()

        cert = self._conn.msg.server_certificate.chain.certificates[0]
        rem_pub_key = cert.parsed.public_key()
        ciphered_key = rem_pub_key.encrypt(bytes(self._pms), padding.PKCS1v15())
        # injecting the encrypted key to the recorder is required, as the
        # padding scheme PKCS1v15 produces non-deterministic cipher text.
        return self._recorder.inject(rsa_enciphered=ciphered_key)

    def get_shared_secret(self):
        """Get the shared key, i.e., the premaster secret.

        Returns:
            bytes: the premaster secret
        """

        if self._pms is None:
            self._create_pms()

        return self._pms


class DhKeyExchange(KeyExchange):
    """Implement Diffie-Hellman key exchange
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._group_name is not None:
            dh_nbrs = dh_numbers.dh_numbers.get(self._group_name)
            if dh_nbrs is None:
                raise ValueError(
                    f"No numbers defined for DH-group {self._group_name.name}"
                )

            self._gval = dh_nbrs.g_val
            self._pval = int.from_bytes(dh_nbrs.p_val, "big")

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
            x = self._recorder.inject(x_val=None)
            self._priv_key = load_der_private_key(x, None)
            self._pub_key = self._priv_key.public_key()

        else:
            self._priv_key = self._dh_group.parameters().generate_private_key()
            self._pub_key = self._priv_key.public_key()
            x = self._priv_key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            self._recorder.trace(x_val=x)

    def get_shared_secret(self):
        """Get the shared key, i.e., the premaster secret.

        Returns:
            bytes: the premaster secret
        """

        if self._priv_key is None:
            self._create_key_pair()

        rem_pub_numbers = dh.DHPublicNumbers(self._rem_pub_key, self._dh_group)
        rem_pub_key = rem_pub_numbers.public_key()
        return self._priv_key.exchange(rem_pub_key).lstrip(b"\0")

    def set_remote_key(self, rem_pub_key, g_val=None, p_val=None, group=None):
        """Sets the remote public key

        Arguments:
            rem_pub_key (bytes): the raw remote public key
            g_val (int): the generator value
            p_val (bytes): the p-value as a byte string
            group (:class:`tlsmate.tls.SupportedGroups`): the supported group
        """

        if group is not None:
            dh_nbrs = dh_numbers.dh_numbers.get(group)
            if dh_nbrs is None:
                raise ServerMalfunction(tls.ServerIssue.FFDH_GROUP_UNKNOWN)

            p_val = dh_nbrs.p_val
            g_val = dh_nbrs.g_val

        self._pval = int.from_bytes(p_val, "big")
        self._gval = g_val
        self._rem_pub_key = int.from_bytes(rem_pub_key, "big")

    def get_transferable_key(self):
        """Get the raw bytes of the key to be sent to the peer.

        Returns:
            bytes: the key to be sent to the peer.
        """

        if self._pub_key is None:
            self._create_key_pair()

        y_val = self._pub_key.public_numbers().y
        return y_val.to_bytes(int(self._pub_key.key_size / 8), "big")

    def get_key_share(self):
        """TLS1.3 alias for get_transferable_key.
        """

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
        """Get the shared key, i.e., the premaster secret.

        Returns:
            bytes: the premaster secret
        """

        if self._priv_key is None:
            self._create_key_pair()

        rem_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self._algo(), bytes(self._rem_pub_key)
        )
        return self._priv_key.exchange(ec.ECDH(), rem_pub_key)

    def set_remote_key(self, rem_pub_key, **kwargs):
        """Sets the remote public key

        Arguments:
            rem_pub_key (bytes): the raw remote public key
            **kwargs: unused
        """

        self._rem_pub_key = rem_pub_key

    def get_transferable_key(self):
        """Get the raw bytes of the key to be sent to the peer.

        Returns:
            bytes: the key to be sent to the peer.
        """

        if self._pub_key is None:
            self._create_key_pair()

        return self._pub_key

    def get_key_share(self):
        """TLS1.3 alias for get_transferable_key.
        """

        if self._pub_key is None:
            self._create_key_pair()

        return self._pub_key


class EcdhKeyExchangeCertificate(object):
    """Implement the key exchange for ECDHE.
    """

    def __init__(self, conn, recorder):
        cert = conn.msg.server_certificate.chain.certificates[0]
        rem_pub_key = cert.parsed.public_key()
        seed = recorder.inject(ec_seed=int.from_bytes(os.urandom(10), "big"))
        priv_key = ec.derive_private_key(seed, rem_pub_key.curve)
        pub_key = priv_key.public_key()
        self._pub_key = pub_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        self._shared_secret = priv_key.exchange(ec.ECDH(), rem_pub_key)

    def set_remote_key(self, rem_pub_key, **kwargs):
        """Sets the remote public key

        Arguments:
            rem_pub_key (bytes): the raw remote public key
            **kwargs: unused
        """

        pass

    def get_transferable_key(self):
        """Get the raw bytes of the key to be sent to the peer.

        Returns:
            bytes: the key to be sent to the peer.
        """

        return self._pub_key

    def get_shared_secret(self):
        """Get the shared key, i.e., the premaster secret.

        Returns:
            bytes: the premaster secret
        """

        return self._shared_secret


class XKeyExchange(KeyExchange):
    """Implement the key exchange for X25519 and X448.
    """

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
        """Get the shared key, i.e., the premaster secret.

        Returns:
            bytes: the premaster secret
        """

        if self._priv_key is None:
            self._create_key_pair()

        rem_pub_key = self._public_key_lib.from_public_bytes(bytes(self._rem_pub_key))
        return self._priv_key.exchange(rem_pub_key)

    def set_remote_key(self, rem_pub_key, **kwargs):
        """Sets the remote public key

        Arguments:
            rem_pub_key (bytes): the raw remote public key
            **kwargs: unused
        """

        self._rem_pub_key = rem_pub_key

    def get_transferable_key(self):
        """Get the raw bytes of the key to be sent to the peer.

        Returns:
            bytes: the key to be sent to the peer.
        """

        if self._priv_key is None:
            self._create_key_pair()

        return self._pub_key

    def get_key_share(self):
        """TLS1.3 alias for get_transferable_key.
        """

        return self.get_transferable_key()


class _Group(NamedTuple):
    """Structure for a group
    """

    cls: type
    algo: type


_supported_groups = {
    tls.SupportedGroups.SECT163K1: _Group(cls=EcdhKeyExchange, algo=ec.SECT163K1),
    tls.SupportedGroups.SECT163R2: _Group(cls=EcdhKeyExchange, algo=ec.SECT163R2),
    tls.SupportedGroups.SECT233K1: _Group(cls=EcdhKeyExchange, algo=ec.SECT233K1),
    tls.SupportedGroups.SECT233R1: _Group(cls=EcdhKeyExchange, algo=ec.SECT233R1),
    tls.SupportedGroups.SECT283K1: _Group(cls=EcdhKeyExchange, algo=ec.SECT283K1),
    tls.SupportedGroups.SECT283R1: _Group(cls=EcdhKeyExchange, algo=ec.SECT283R1),
    tls.SupportedGroups.SECT409K1: _Group(cls=EcdhKeyExchange, algo=ec.SECT409K1),
    tls.SupportedGroups.SECT409R1: _Group(cls=EcdhKeyExchange, algo=ec.SECT409R1),
    tls.SupportedGroups.SECT571K1: _Group(cls=EcdhKeyExchange, algo=ec.SECT571K1),
    tls.SupportedGroups.SECT571R1: _Group(cls=EcdhKeyExchange, algo=ec.SECT571R1),
    tls.SupportedGroups.SECP192R1: _Group(cls=EcdhKeyExchange, algo=ec.SECP192R1),
    tls.SupportedGroups.SECP224R1: _Group(cls=EcdhKeyExchange, algo=ec.SECP224R1),
    tls.SupportedGroups.SECP256K1: _Group(cls=EcdhKeyExchange, algo=ec.SECP256K1),
    tls.SupportedGroups.SECP256R1: _Group(cls=EcdhKeyExchange, algo=ec.SECP256R1),
    tls.SupportedGroups.SECP384R1: _Group(cls=EcdhKeyExchange, algo=ec.SECP384R1),
    tls.SupportedGroups.SECP521R1: _Group(cls=EcdhKeyExchange, algo=ec.SECP521R1),
    tls.SupportedGroups.BRAINPOOLP256R1: _Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP256R1
    ),
    tls.SupportedGroups.BRAINPOOLP384R1: _Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP384R1
    ),
    tls.SupportedGroups.BRAINPOOLP512R1: _Group(
        cls=EcdhKeyExchange, algo=ec.BrainpoolP512R1
    ),
    tls.SupportedGroups.X25519: _Group(cls=XKeyExchange, algo=None),
    tls.SupportedGroups.X448: _Group(cls=XKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE2048: _Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE3072: _Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE4096: _Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE6144: _Group(cls=DhKeyExchange, algo=None),
    tls.SupportedGroups.FFDHE8192: _Group(cls=DhKeyExchange, algo=None),
}
