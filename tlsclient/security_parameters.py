# -*- coding: utf-8 -*-
"""Module containing the class implementing for security parameters
"""
import time
import os
import re
import logging
import tlsclient.constants as tls
from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert

import collections

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import algorithms, aead
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


Cipher = collections.namedtuple(
    "Cipher", "cipher_primitive cipher_algo cipher_type enc_key_len block_size iv_len"
)

Mac = collections.namedtuple("Mac", "hash_algo mac_len mac_key_len hmac_algo")

Groups = collections.namedtuple("Groups", "curve_algo")

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
            block_size=16,
            iv_len=16,
        ),
        tls.SupportedCipher.AES_128_GCM: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=aead.AESGCM,
            cipher_type=tls.CipherType.AEAD,
            enc_key_len=16,
            block_size=16,
            iv_len=4,
        ),
        tls.SupportedCipher.AES_256_GCM: Cipher(
            cipher_primitive=tls.CipherPrimitive.AES,
            cipher_algo=aead.AESGCM,
            cipher_type=tls.CipherType.AEAD,
            enc_key_len=32,
            block_size=16,
            iv_len=4,
        ),
        tls.SupportedCipher.CHACHA20_POLY1305: Cipher(
            cipher_primitive=tls.CipherPrimitive.CHACHA,
            cipher_algo=aead.ChaCha20Poly1305,
            cipher_type=tls.CipherType.AEAD,
            enc_key_len=32,
            block_size=16,
            iv_len=12,
        ),
    }

    _supported_macs = {
        tls.SupportedHash.SHA256: Mac(
            hash_algo=hashes.SHA256, mac_len=32, mac_key_len=32, hmac_algo=hashes.SHA256
        ),
        tls.SupportedHash.SHA: Mac(hash_algo=hashes.SHA1, mac_len=20, mac_key_len=20, hmac_algo=hashes.SHA256),
        tls.SupportedHash.SHA384: Mac(hash_algo=hashes.SHA384, mac_len=48, mac_key_len=48, hmac_algo=hashes.SHA384),
        tls.SupportedHash.MD5: Mac(hash_algo=hashes.MD5, mac_len=16, mac_key_len=16,hmac_algo=hashes.SHA256 ),
    }

    _supported_groups_ec = {
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

    def __init__(self, entity, recorder):
        self.recorder = recorder
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

        # hash & mac
        self.hash_primitive = None
        self.hash_algo = None
        self.mac_len = None
        self.hmac_algo = None

    def set_recorder(self, recorder):
        self.recorder = recorder

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
            (self.hash_algo, self.mac_len, self.mac_key_len, self.hmac_algo) = self._supported_macs[
                hash_primitive
            ]
            if self.cipher_type == tls.CipherType.AEAD:
                self.mac_key_len = 0
        logging.debug("hash_primitive: {}".format(self.hash_primitive.name))
        logging.debug("cipher_primitive: {}".format(self.cipher_primitive.name))

    def _hmac_func(self, secret, msg):
        hmac_object = hmac.HMAC(secret, self.hmac_algo())
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
            named_ec_curve = self._supported_groups_ec.get(self.named_curve)
            if named_ec_curve is not None:
                curve_algo = named_ec_curve.curve_algo
                seed = int.from_bytes(os.urandom(10),"big")
                seed = self.recorder.inject(ec_seed=seed)
                private_key = ec.derive_private_key(seed, curve_algo())
                public_key = private_key.public_key()
                self.public_key = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve_algo(), bytes(self.remote_public_key))
                self.pre_master_secret = ProtocolData(private_key.exchange(ec.ECDH(), server_public_key))

            elif self.named_curve == tls.SupportedGroups.X25519:
                if self.recorder.is_injecting():
                    private_bytes = self.recorder.inject(private_key=None)
                    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
                else:
                    private_key = x25519.X25519PrivateKey.generate()
                    if self.recorder.is_recording():
                        private_bytes = private_key.private_bytes(
                            encoding=Encoding.Raw,
                            format=PrivateFormat.Raw,
                            encryption_algorithm=NoEncryption(),
                        )
                        self.recorder.trace(private_key=private_bytes)
                public_key = private_key.public_key()
                self.public_key = public_key.public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                server_public_key = x25519.X25519PublicKey.from_public_bytes(
                    bytes(self.remote_public_key)
                )
                self.pre_master_secret = ProtocolData(private_key.exchange(server_public_key))

        self.master_secret = ProtocolData(self.prf(
            self.pre_master_secret,
            b"master secret",
            self.client_random + self.server_random,
            48,
        ))
        logging.info("pre_master_secret: {}".format(self.pre_master_secret.dump()))
        logging.info("master_secret: {}".format(self.master_secret.dump()))
        self.recorder.trace(master_secret=self.master_secret)

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

        self.recorder.trace(client_write_mac_key=self.client_write_mac_key)
        self.recorder.trace(server_write_mac_key=self.server_write_mac_key)
        self.recorder.trace(client_write_key=self.client_write_key)
        self.recorder.trace(server_write_key=self.server_write_key)
        self.recorder.trace(client_write_iv=self.client_write_iv)
        self.recorder.trace(server_write_iv=self.server_write_iv)
        logging.info("client_write_mac_key: {}".format(self.client_write_mac_key.dump()))
        logging.info("server_write_mac_key: {}".format(self.server_write_mac_key.dump()))
        logging.info("client_write_key: {}".format(self.client_write_key.dump()))
        logging.info("server_write_key: {}".format(self.server_write_key.dump()))
        logging.info("client_write_iv: {}".format(self.client_write_iv.dump()))
        logging.info("server_write_iv: {}".format(self.server_write_iv.dump()))

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
