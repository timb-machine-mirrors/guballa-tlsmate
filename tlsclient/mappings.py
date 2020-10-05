# -*- coding: utf-8 -*-
"""Module containing various mapping tables
"""
import tlsclient.constants as tls

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, aead
import tlsclient.key_exchange as keyex
import tlsclient.structures as structs

# this map contains all cipher suites for which a full handshake is supported,
# i.e., application data can be exchanged encrypted

supported_cipher_suites = {
    tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.IDEA_CBC,
        mac=tls.SupportedHash.SHA,
    ),
    tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.SupportedHash.SHA,
    ),
}


# map cipher to various parameters relevant for the record layer

supported_ciphers = {
    tls.SupportedCipher.AES_128_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.AES,
        cipher_algo=algorithms.AES,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=16,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.AES_256_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.AES,
        cipher_algo=algorithms.AES,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=32,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.AES_128_GCM: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.AES,
        cipher_algo=aead.AESGCM,
        cipher_type=tls.CipherType.AEAD,
        enc_key_len=16,
        block_size=16,
        iv_len=4,
    ),
    tls.SupportedCipher.AES_256_GCM: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.AES,
        cipher_algo=aead.AESGCM,
        cipher_type=tls.CipherType.AEAD,
        enc_key_len=32,
        block_size=16,
        iv_len=4,
    ),
    tls.SupportedCipher.CHACHA20_POLY1305: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.CHACHA,
        cipher_algo=aead.ChaCha20Poly1305,
        cipher_type=tls.CipherType.AEAD,
        enc_key_len=32,
        block_size=16,
        iv_len=12,
    ),
    tls.SupportedCipher.TRIPPLE_DES_EDE_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.TRIPPLE_DES,
        cipher_algo=algorithms.TripleDES,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=24,
        block_size=8,
        iv_len=8,
    ),
    tls.SupportedCipher.CAMELLIA_128_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.CAMELLIA,
        cipher_algo=algorithms.Camellia,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=16,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.CAMELLIA_256_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.CAMELLIA,
        cipher_algo=algorithms.Camellia,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=32,
        block_size=16,
        iv_len=16,
    ),
    tls.SupportedCipher.IDEA_CBC: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.IDEA,
        cipher_algo=algorithms.IDEA,
        cipher_type=tls.CipherType.BLOCK,
        enc_key_len=16,
        block_size=8,
        iv_len=8,
    ),
    tls.SupportedCipher.RC4_128: structs.Cipher(
        cipher_primitive=tls.CipherPrimitive.RC4,
        cipher_algo=algorithms.ARC4,
        cipher_type=tls.CipherType.STREAM,
        enc_key_len=16,
        block_size=None,
        iv_len=0,
    ),
}

# map hash algorithms to mac parameters

supported_macs = {
    tls.SupportedHash.SHA256: structs.Mac(
        hash_algo=hashes.SHA256, mac_len=32, mac_key_len=32, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA: structs.Mac(
        hash_algo=hashes.SHA1, mac_len=20, mac_key_len=20, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA384: structs.Mac(
        hash_algo=hashes.SHA384, mac_len=48, mac_key_len=48, hmac_algo=hashes.SHA384
    ),
    tls.SupportedHash.MD5: structs.Mac(
        hash_algo=hashes.MD5, mac_len=16, mac_key_len=16, hmac_algo=hashes.SHA256
    ),
}

# map key exchange algorithm to the corresponding class

key_exchange_algo = {
    tls.KeyExchangeAlgorithm.DHE_DSS: structs.KeyExchangeAlgo(cls=keyex.DhKeyExchange),
    tls.KeyExchangeAlgorithm.DHE_RSA: structs.KeyExchangeAlgo(cls=keyex.DhKeyExchange),
    tls.KeyExchangeAlgorithm.DH_ANON: structs.KeyExchangeAlgo(cls=keyex.DhKeyExchange),
    tls.KeyExchangeAlgorithm.RSA: structs.KeyExchangeAlgo(cls=keyex.RsaKeyExchange),
    tls.KeyExchangeAlgorithm.DH_DSS: structs.KeyExchangeAlgo(cls=None),
    tls.KeyExchangeAlgorithm.DH_RSA: structs.KeyExchangeAlgo(cls=None),
    tls.KeyExchangeAlgorithm.ECDH_ECDSA: structs.KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
    tls.KeyExchangeAlgorithm.ECDHE_ECDSA: structs.KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
    tls.KeyExchangeAlgorithm.ECDH_RSA: structs.KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
    tls.KeyExchangeAlgorithm.ECDHE_RSA: structs.KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
    tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN: structs.KeyExchangeAlgo(
        cls=keyex.EcdhKeyExchange
    ),
}
