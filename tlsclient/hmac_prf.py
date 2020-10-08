# -*- coding: utf-8 -*-
"""Module containing the class implementing hashing functions & prf
"""

import abc
import math
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class _Backend(metaclass=abc.ABCMeta):
    @staticmethod
    def _hmac_func(secret, msg, hash_algo):
        hmac_object = hmac.HMAC(secret, hash_algo())
        hmac_object.update(msg)
        return hmac_object.finalize()

    @staticmethod
    def _expand(secret, seed, size, hash_algo):
        out = b""
        ax = bytes(seed)
        while len(out) < size:
            ax = __class__._hmac_func(secret, ax, hash_algo)
            out = out + __class__._hmac_func(secret, ax + seed, hash_algo)
        return out[:size]

    @abc.abstractmethod
    def __init__(self, algo):
        raise NotImplementedError

    @abc.abstractmethod
    def update_msg_digest(self, msg):
        raise NotImplementedError

    @abc.abstractmethod
    def finalize_msg_digest(self, intermediate=False):
        raise NotImplementedError

    @abc.abstractmethod
    def prf(self, secret, label, seed, size):
        raise NotImplementedError


class _BackendTls10(_Backend):
    def __init__(self, hash_algo):
        self._msg_digest_md5 = hashes.Hash(hashes.MD5())
        self._msg_digest_sha = hashes.Hash(hashes.SHA1())

    def update_msg_digest(self, msg):
        self._msg_digest_md5.update(msg)
        self._msg_digest_sha.update(msg)

    def finalize_msg_digest(self, intermediate=False):
        if intermediate:
            tmp_digest_md5 = self._msg_digest_md5.copy()
            tmp_digest_sha = self._msg_digest_sha.copy()
            return tmp_digest_md5.finalize() + tmp_digest_sha.finalize()
        return self._msg_digest_md5.finalize() + self._msg_digest_sha.finalize()

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
    def __init__(self, hash_algo):
        self._hash_algo = hash_algo
        self._msg_digest = hashes.Hash(hash_algo())

    def update_msg_digest(self, msg):
        self._msg_digest.update(msg)

    def finalize_msg_digest(self, intermediate=False):
        if intermediate:
            tmp_digest = self._msg_digest.copy()
            return tmp_digest.finalize()
        return self._msg_digest.finalize()

    def prf(self, secret, label, seed, size):
        return self._expand(secret, label + seed, size, self._hash_algo)

    def hkdf_extract(self, secret, salt):
        if secret is None:
            secret = b"\0" * self._hash_algo.digest_size
        h = hmac.HMAC(salt, self._hash_algo())
        h.update(secret)
        return h.finalize()

    def _hkdf_expand(self, secret, label, length):
        hkdf = HKDFExpand(algorithm=self._hash_algo(), length=length, info=label)
        return hkdf.derive(secret)

    def hkdf_expand_label(self, secret, label, context, length):
        label_bytes = ("tls13 " + label).encode()
        hkdf_label = (
            struct.pack("!H", length)
            + struct.pack("!B", len(label_bytes))
            + label_bytes
            + struct.pack("!B", len(context))
            + context
        )
        return self._hkdf_expand(secret, hkdf_label, length)


class HmacPrf(object):
    def __init__(self):
        self._backend = None

    def start_msg_digest(self):
        """Get ready to add messages to the message digest

        We start with the client hello, but backend is not defined yet
        """
        self._msg_digest_queue = None
        self._msg_digest = None
        self._msg_digest_active = True
        self._backend = None
        self._empty_msg_digest = None

    def set_msg_digest_algo(self, hash_algo):
        if hash_algo is None:
            self._backend = _BackendTls10(hash_algo)
        else:
            self._backend = _BackendTls12(hash_algo)
        self._empty_msg_digest = self.finalize_msg_digest(intermediate=True)
        if self._msg_digest_queue is not None:
            self._backend.update_msg_digest(self._msg_digest_queue)
            self._msg_digest_queue = None

    def update_msg_digest(self, msg):
        if not self._msg_digest_active:
            return
        if self._backend is None:
            if self._msg_digest_queue is None:
                self._msg_digest_queue = msg
            else:
                self._msg_digest_queue.extend(msg)
        else:
            self._backend.update_msg_digest(msg)

    def empty_msg_digest(self):
        return self._empty_msg_digest

    def finalize_msg_digest(self, intermediate=False):
        if not intermediate:
            self._msg_digest_active = False
        return self._backend.finalize_msg_digest(intermediate=intermediate)

    def prf(self, secret, label, seed, size):
        return self._backend.prf(secret, label, seed, size)

    def hkdf_extract(self, secret, salt):
        return self._backend.hkdf_extract(secret, salt)

    def hkdf_expand_label(self, secret, label, msg_digest, length):
        return self._backend.hkdf_expand_label(secret, label, msg_digest, length)
