# -*- coding: utf-8 -*-
"""Module containing the class implementing for security parameters
"""
import time
import os
import re
import tlsclient.constants as tls
from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert

import collections

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import algorithms, aead
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


Cipher = collections.namedtuple(
    "Cipher", "cipher_primitive cipher_algo cipher_type enc_key_len block_size iv_len"
)

Mac = collections.namedtuple("Mac", "hash_algo mac_len mac_key_len")


def get_random_value():
    random = ProtocolData()
    random.append_uint32(int(time.time()))
    random.extend(os.urandom(28))
    return random


class SecurityParameters(object):

    _supported_ciphers = {
        tls.SupportedCipher.AES_128_CBC: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=algorithms.AES,
            cipher_type=tls.CipherType.BLOCK,
            enc_key_len=16,
            block_size=16,
            iv_len=16,
        ),
        tls.SupportedCipher.AES_256_CBC: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=algorithms.AES,
            cipher_type=tls.CipherType.BLOCK,
            enc_key_len=32,
            block_size=32,
            iv_len=32,
        ),
        tls.SupportedCipher.AES_128_GCM: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=aead.AESGCM,
            cipher_type=tls.CipherType.AEAD,
            enc_key_len=16,
            block_size=16,
            iv_len=16,
        ),
        tls.SupportedCipher.AES_256_GCM: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=aead.AESGCM,
            cipher_type=tls.CipherType.AEAD,
            enc_key_len=32,
            block_size=32,
            iv_len=32,
        ),
    }

    _supported_macs = {
        tls.SupportedHash.SHA256: Mac(
            hash_algo=hashes.SHA256, mac_len=32, mac_key_len=32
        ),
        tls.SupportedHash.SHA: Mac(hash_algo=hashes.SHA1, mac_len=20, mac_key_len=20),
        tls.SupportedHash.MD5: Mac(hash_algo=hashes.MD5, mac_len=16, mac_key_len=16),
    }

    def __init__(self, entity):
        # general
        self.entity = entity
        self.version = None
        self.cipher_suite = None
        self.key_exchange_method = None
        self.compression_method = None

        # key exchange
        self.client_random = None
        self.server_random = None
        self.named_curve = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.pre_master_secret = None
        self.master_secret = None

        # for key deriviation
        self.mac_key_len = None
        self.enc_key_len = None
        self.iv_len = None

        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None

        # cipher
        self.cipher_primitive = None
        self.cipher_algo = None
        self.cipher_type = None
        self.block_size = None
        self.cipher_mode = None

        # hash & mac
        self.hash_primitive = None
        self.hash_algo = None
        self.mac_len = None

    def update_cipher_suite(self, cipher_suite):
        if self.version == tls.Version.TLS13:
            pass
        else:
            # Dirty: We extract key exhange method, cipher and hash from
            # the enum name.
            res = re.match(r"TLS_(.*)_WITH_(.+)_([^_]+)", cipher_suite.name)
            if not res:
                raise FatalAlert(
                    "Negotiated cipher suite {} not supported".format(
                        cipher_suite.name
                    ),
                    tls.AlertDescription.HandshakeFailure,
                )
            key_exchange_method = tls.KeyExchangeAlgorithm.str2enum(res.group(1))
            cipher = tls.SupportedCipher.str2enum(res.group(2))
            hash_primitive = tls.SupportedHash.str2enum(res.group(3))
            if key_exchange_method is None or cipher is None or hash_primitive is None:
                raise FatalAlert(
                    "Negotiated cipher suite {} not supported".format(
                        cipher_suite.name
                    ),
                    tls.AlertDescription.HandshakeFailure,
                )
            self.key_exchange_method = key_exchange_method
            self.cipher = cipher
            self.hash_primitive = hash_primitive
            (
                self.cipher_primitive,
                self.cipher_algo,
                self.cipher_type,
                self.enc_key_len,
                self.block_size,
                self.iv_len,
            ) = self._supported_ciphers[cipher]
            (self.hash_algo, self.mac_len, self.mac_key_len) = self._supported_macs[
                hash_primitive
            ]

    def _hmac_func(self, secret, msg):
        hmac_object = hmac.HMAC(secret, self.hash_algo())
        hmac_object.update(msg)
        return hmac_object.finalize()

    def _expand(self, secret, seed, size):
        out = b""
        ax = bytes(seed)
        while len(out) < size:
            ax = self._hmac_func(secret, ax)
            out = out + self._hmac_func(secret, ax + seed)
        return out[:size]

    def prf(self, secret, label, seed, size):
        return self._expand(secret, label + seed, size)

    def generate_master_secret(self):
        if self.key_exchange_method in [
            tls.KeyExchangeAlgorithm.ECDH_ECDSA,
            tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
            tls.KeyExchangeAlgorithm.ECDH_RSA,
            tls.KeyExchangeAlgorithm.ECDHE_RSA,
        ]:
            if self.named_curve == tls.SupportedGroups.X25519:
                self.private_key = X25519PrivateKey.generate()
                public_key = self.private_key.public_key()
                self.public_key = public_key.public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                server_public_key = X25519PublicKey.from_public_bytes(
                    bytes(self.remote_public_key)
                )
                premaster_secret = self.private_key.exchange(server_public_key)
                print("Premaster secret:", ProtocolData.dump(premaster_secret))

        self.master_secret = self.prf(
            premaster_secret,
            b"master secret",
            self.client_random + self.server_random,
            48,
        )
        print("Master secret: ", ProtocolData(self.master_secret).dump())

        return

    def key_deriviation(self):

        key_material = self.prf(
            self.master_secret,
            b"key expansion",
            self.server_random + self.client_random,
            2 * (self.mac_key_len + self.enc_key_len + self.iv_len),
        )
        key_material = ProtocolData(key_material)
        self.client_write_mac_key, offset = key_material.unpack_bytes(
            0, self.mac_key_len
        )
        self.server_write_mac_key, offset = key_material.unpack_bytes(
            offset, self.mac_key_len
        )
        self.client_write_key, offset = key_material.unpack_bytes(
            offset, self.enc_key_len
        )
        self.server_write_key, offset = key_material.unpack_bytes(
            offset, self.enc_key_len
        )
        self.client_write_iv, offset = key_material.unpack_bytes(offset, self.iv_len)
        self.server_write_iv, offset = key_material.unpack_bytes(offset, self.iv_len)
        print("client_write_mac_key: ", self.client_write_mac_key.dump())
        print("server_write_mac_key: ", self.server_write_mac_key.dump())
        print("client_write_key    : ", self.client_write_key.dump())
        print("server_write_key    : ", self.server_write_key.dump())
        print("client_write_iv     : ", self.client_write_iv.dump())
        print("server_write_iv     : ", self.server_write_iv.dump())

    def get_pending_write_state(self, entity):
        if entity == tls.Entity.CLIENT:
            enc_key = self.client_write_key
            mac_key = self.client_write_mac_key
            iv_value = self.client_write_iv
        else:
            enc_key = self.server_write_key
            mac_key = self.server_write_mac_key
            iv_value = self.server_write_iv

        return tls.StateUpdateParams(
            cipher_primitive=self.cipher_primitive,
            cipher_algo=self.cipher_algo,
            cipher_type=self.cipher_type,
            block_size=self.block_size,
            enc_key=enc_key,
            mac_key=mac_key,
            iv_value=iv_value,
            iv_len=self.iv_len,
            mac_len=self.mac_len,
            hash_algo=self.hash_algo,
            compression_method=self.compression_method,
        )
