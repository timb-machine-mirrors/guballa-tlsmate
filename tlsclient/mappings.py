# -*- coding: utf-8 -*-
"""Module containing various mapping tables
"""
import tlsclient.constants as tls

import collections

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, aead
import tlsclient.key_exchange as keyex

Groups = collections.namedtuple("Groups", "curve_algo")

# map cipher to various parameters relevant for the record layer

Cipher = collections.namedtuple(
    "Cipher", "cipher_primitive cipher_algo cipher_type enc_key_len block_size iv_len"
)

supported_ciphers = {
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
    tls.SupportedCipher.TRIPPLE_DES_EDE_CBC: Cipher(
        cipher_primitive=tls.CipherPrimitive.TRIPPLE_DES,
        cipher_algo=algorithms.TripleDES,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=24,
        block_size=8,
        iv_len=8,
    ),
    tls.SupportedCipher.CAMELLIA_128_CBC: Cipher(
        cipher_primitive=tls.CipherPrimitive.CAMELLIA,
        cipher_algo=algorithms.Camellia,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=16,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.CAMELLIA_256_CBC: Cipher(
        cipher_primitive=tls.CipherPrimitive.CAMELLIA,
        cipher_algo=algorithms.Camellia,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=32,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.IDEA_CBC: Cipher(
        cipher_primitive=tls.CipherPrimitive.IDEA,
        cipher_algo=algorithms.IDEA,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=16,
        block_size=8,
        iv_len=8,
    ),
}

# map hash algorithms to mac parameters

Mac = collections.namedtuple("Mac", "hash_algo mac_len mac_key_len hmac_algo")

supported_macs = {
    tls.SupportedHash.SHA256: Mac(
        hash_algo=hashes.SHA256, mac_len=32, mac_key_len=32, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA: Mac(
        hash_algo=hashes.SHA1, mac_len=20, mac_key_len=20, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA384: Mac(
        hash_algo=hashes.SHA384, mac_len=48, mac_key_len=48, hmac_algo=hashes.SHA384
    ),
    tls.SupportedHash.MD5: Mac(
        hash_algo=hashes.MD5, mac_len=16, mac_key_len=16, hmac_algo=hashes.SHA256
    ),
}

# map key exchange algorithm to the corresponding class

KeyExchangeAlgo = collections.namedtuple("KeyExchangeAlgo", "cls")

key_exchange_algo = {
    tls.KeyExchangeAlgorithm.DHE_DSS: KeyExchangeAlgo(cls=keyex.DhKeyExchange),
    tls.KeyExchangeAlgorithm.DHE_RSA: KeyExchangeAlgo(cls=keyex.DhKeyExchange),
    tls.KeyExchangeAlgorithm.DH_ANON: KeyExchangeAlgo(cls=None),
    tls.KeyExchangeAlgorithm.RSA: KeyExchangeAlgo(cls=keyex.RsaKeyExchange),
    tls.KeyExchangeAlgorithm.DH_DSS: KeyExchangeAlgo(cls=None),
    tls.KeyExchangeAlgorithm.DH_RSA: KeyExchangeAlgo(cls=None),
    tls.KeyExchangeAlgorithm.ECDH_ECDSA: KeyExchangeAlgo(cls=keyex.EcdhKeyExchange),
    tls.KeyExchangeAlgorithm.ECDHE_ECDSA: KeyExchangeAlgo(cls=keyex.EcdhKeyExchange),
    tls.KeyExchangeAlgorithm.ECDH_RSA: KeyExchangeAlgo(cls=keyex.EcdhKeyExchange),
    tls.KeyExchangeAlgorithm.ECDHE_RSA: KeyExchangeAlgo(cls=keyex.EcdhKeyExchange),
    tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN: KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
}
