# -*- coding: utf-8 -*-
"""Module containing the class implementing hashing functions & prf
"""
# import basic stuff
import abc
import math
import struct
import logging

# import own stuff
from tlsmate import pdu

# import other stuff
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class _Backend(metaclass=abc.ABCMeta):
    """Base class for backend implementations

    Arguments:
        algo (:obj:`cryptography.hazmat.primitives.hashes.HashPrimitive`): The hash
            algorithm to be used in the backend.
    """

    @abc.abstractmethod
    def __init__(self, algo):
        raise NotImplementedError

    @staticmethod
    def _hmac_func(secret, msg, hash_algo):
        """Provides HMAC function.

        Arguments:
            secret (bytes): The secret used for the HMAC.
            msg (bytes): The array of bytes for which the HMAC shall be generated.
            hash_algo (:obj:`cryptography.hazmat.primitives.hashes.HashPrimitive`): The
                hash algorithm used in the HMAC function.

        Returns:
            bytes: The calculated HMAC value, having the same length than the output
            of the hash algorithm.
        """

        hmac_object = hmac.HMAC(secret, hash_algo())
        hmac_object.update(msg)
        return hmac_object.finalize()

    @staticmethod
    def _expand(secret, seed, size, hash_algo):
        """Provides an expand funtion.

        This function is used to expand a key with high entropy to a byte string of
        the desired length.

        Arguments:
            secret (bytes): The key used for the expand function.
            seed (bytes): The seed for the function.
            size (int): The desired number of bytes for the output
            hash_algo (:obj:`cryptography.hazmat.primitives.hashes.HashPrimitive`): The
                hash algorithm used in the underlying HMAC function.

        Returns:
            (bytes): An bytearray of the desired length.
        """

        out = b""
        ax = bytes(seed)
        while len(out) < size:
            ax = __class__._hmac_func(secret, ax, hash_algo)
            out = out + __class__._hmac_func(secret, ax + seed, hash_algo)

        return out[:size]

    @abc.abstractmethod
    def update_msg_digest(self, msg):
        """Function to add a message to a message digest.

        Arguments:
            msg (bytes): The message to add.
        """

        raise NotImplementedError

    @abc.abstractmethod
    def current_msg_digest(self):
        """Determine the current value of the message digest.

        Returns:
            bytes: The calculated current  message digest, output has the same length
            than the hash length.
        """

        raise NotImplementedError

    @abc.abstractmethod
    def prf(self, secret, label, seed, size):
        """Provide a PRF.

        Arguments:
            secret (bytes): The key used for the expand function.
            label (bytes): The label as a bytestring.
            seed (bytes): The seed for the function.
            size (int): The desired number of bytes for the output

        Returns:
            (bytes): An bytearray of the desired length.
        """

        raise NotImplementedError


class _BackendTls10(_Backend):
    """Implements a backend for TLS1.0 and TLS1.1.

    The message digest is using a fixed combination of MD5 and SHA.
    """

    def __init__(self, hash_algo):
        self._msg_digest_md5 = hashes.Hash(hashes.MD5())
        self._msg_digest_sha = hashes.Hash(hashes.SHA1())

    def update_msg_digest(self, msg):
        self._msg_digest_md5.update(msg)
        self._msg_digest_sha.update(msg)

    def current_msg_digest(self):
        tmp_digest_md5 = self._msg_digest_md5.copy()
        tmp_digest_sha = self._msg_digest_sha.copy()
        return tmp_digest_md5.finalize() + tmp_digest_sha.finalize()

    def prf(self, secret, label, seed, size):
        length = math.ceil(len(secret) / 2)
        s1_md5 = secret[:length]
        s2_sha = secret[-length:]
        md5_bytes = self._expand(s1_md5, label + seed, size, hashes.MD5)
        sha_bytes = self._expand(s2_sha, label + seed, size, hashes.SHA1)
        result = bytearray(sha_bytes)
        for i, b in enumerate(md5_bytes):
            result[i] ^= b

        return result


class _BackendTls12(_Backend):
    """Implements a backend for TLS1.2 and TLS1.3
    """

    def __init__(self, hash_algo):
        self._hash_algo = hash_algo
        self._msg_digest = hashes.Hash(hash_algo())

    def update_msg_digest(self, msg):
        self._msg_digest.update(msg)

    def current_msg_digest(self):
        return self._msg_digest.copy().finalize()

    def prf(self, secret, label, seed, size):
        return self._expand(secret, label + seed, size, self._hash_algo)

    def hkdf_extract(self, secret, salt):
        """TLS1.3 specific, implements the "hkdf_extract" function.

        Arguments:
            secret (bytes): The secret used for the extract function.
            salt (bytes): The salt for the extract function.

        Returns:
            bytes: The byte sequence generated having the same length than the
            underlying hash algorithm.
        """

        if secret is None:
            secret = b"\0" * self._hash_algo.digest_size

        h = hmac.HMAC(salt, self._hash_algo())
        h.update(secret)
        return h.finalize()

    def _hkdf_expand(self, secret, label, length):
        """TLS1.3 specific, implements the "hkdf_expand" function.

        This function is used to derive keying material as long as needed from a
        strong secret.

        Arguments:
            secret (bytes): The secret used for the expand function.
            label (bytes): The label as a bytestring.
            length (int): The desired number of bytes for the output

        Returns:
            bytes: A bytearray as long as specified by the length parameter.
        """

        hkdf = HKDFExpand(algorithm=self._hash_algo(), length=length, info=label)
        return hkdf.derive(secret)

    def hkdf_expand_label(self, secret, label, context, length):
        """TLS1.3 specific, implements the "hkdf_expand" function.

        This function is used to derive keying material as long as needed from a
        strong secret.

        Arguments:
            secret (bytes): The secret used for the expand function.
            label (bytes): The label as a bytestring.
            context (bytes): handshake context, e.g. the message digest of dedicated
                messages.
            length (int): The desired number of bytes for the output

        Returns:
            bytes: A bytearray as long as specified by the length parameter.
        """

        label_bytes = ("tls13 " + label).encode()
        hkdf_label = (
            struct.pack("!H", length)
            + struct.pack("!B", len(label_bytes))
            + label_bytes
            + struct.pack("!B", len(context))
            + context
        )
        return self._hkdf_expand(secret, hkdf_label, length)


class Kdf(object):
    """Implements several cryptographic functions, mainly intended to derive keys.
    """

    def __init__(self):
        self._backend = None

    def start_msg_digest(self):
        """Get ready to add messages to the message digest

        We start with the client hello, but backend is not defined yet.
        """
        self._msg_digest_queue = None
        self._msg_digest = None
        self._msg_digest_active = True
        self._backend = None
        self._empty_msg_digest = None
        self._all_msgs = bytearray()

    def set_msg_digest_algo(self, hash_algo):
        """Function to set the hash algo for the message digest.

        Note:
            The message digest starts with the ClientHello, but the used hash
            algorithm is only determined when the ServerHello is received, which
            means at least the ClientHello must be queued.

        Arguments:
            hash_algo (:obj:`cryptography.hazmat.primitives.hashes.HashPrimitive`): The
                negotiated hash algorithm implementation, determined with the
                reception of the ServerHello.
        """

        if hash_algo is None:
            self._backend = _BackendTls10(hash_algo)

        else:
            self._backend = _BackendTls12(hash_algo)

        self._empty_msg_digest = self.current_msg_digest()
        if self._msg_digest_queue is not None:
            self._backend.update_msg_digest(self._msg_digest_queue)
            self._msg_digest_queue = None

    def update_msg_digest(self, msg):
        """Add a message to the message digest.

        Note:
            The message might be queued internally until the hash algorithm is
            determined (reception of the ServerHello).

        Arguments:
            msg (bytes): The message to add.
        """

        if not self._msg_digest_active:
            return

        logging.debug(f"add to msg_digest: {pdu.dump_short(msg, start=20)}")
        self._all_msgs.extend(msg)
        if self._backend is None:
            if self._msg_digest_queue is None:
                self._msg_digest_queue = bytearray(msg)

            else:
                self._msg_digest_queue.extend(msg)

        else:
            self._backend.update_msg_digest(msg)

    def get_handshake_messages(self):
        """Get all messages received/sent so far.

        Returns:
            bytes: the concatenation of all messages.
        """

        return self._all_msgs

    def empty_msg_digest(self):
        """Return the message digest for an emty message array.

        Returns:
            bytes: The message digest for no given messages.
        """

        return self._empty_msg_digest

    def current_msg_digest(self, suspend=False):
        """Gets the message digest.

        Arguments:
            suspend (bool): If set to False, provide the message digest in the
                current state, but allow to add more messages to the digest lateron.
                If set to True, provide the messge digest, but do not consider
                further messages.

        Returns:
            bytes: The calculated message digest, output has the same length than
            the hash length.
        """

        if suspend:
            self._msg_digest_active = False

        return self._backend.current_msg_digest()

    def msg_digest_active(self):
        """Returns the state of the message digest.

        Returns:
            bool: an indication if the message digest is suspended or active.
        """

        return self._msg_digest_active

    def resume_msg_digest(self):
        """Change the state of the message digest to active
        """

        self._msg_digest_active = True

    def prf(self, secret, label, seed, size):
        """Implements a pseudo random function.

        Arguments:
            secret (bytes): The secret used for the PRF.
            label (bytes): The label as a bytestring.
            seed (bytes): The seed for the function.
            size (int): The desired number of bytes for the output

        Returns:
            bytes: A bytearray as long as specified by the size parameter.
        """

        return self._backend.prf(secret, label, seed, size)

    def hkdf_extract(self, secret, salt):
        """HKDF-extract function for TLS1.3

        Arguments:
            secret (bytes): The secret used for the extract function.
            salt (bytes): The salt for the extract function.

        Returns:
            bytes: The byte sequence generated having the same length than the
            hash algorithm used in the underlying hash function.
        """

        return self._backend.hkdf_extract(secret, salt)

    def hkdf_expand_label(self, secret, label, msg_digest, length):
        """HKDF-expand-label function for TLS1.3

        Arguments:
            secret (bytes): The secret used for the expand function.
            label (bytes): The label as a bytestring.
            msg_digest (bytes): The message digest value having the same length than
                the underlying hash function.
            length (int): The desired number of bytes for the output

        Returns:
            bytes: A bytearray as long as specified by the length parameter.
        """

        return self._backend.hkdf_expand_label(secret, label, msg_digest, length)
