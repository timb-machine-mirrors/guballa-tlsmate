# -*- coding: utf-8 -*-
"""Module containing the class implementing hashing functions & prf
"""

import abc
from cryptography.hazmat.primitives import hashes, hmac


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

    def set_msg_digest_algo(self, hash_algo):
        if hash_algo is None:
            self._backend = _BackendTls12(hash_algo)
        else:
            self._backend = _BackendTls12(hash_algo)
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

    def finalize_msg_digest(self, intermediate=False):
        if not intermediate:
            self._msg_digest_active = False
        return self._backend.finalize_msg_digest(intermediate=intermediate)

    def prf(self, secret, label, seed, size):
        return self._backend.prf(secret, label, seed, size)
