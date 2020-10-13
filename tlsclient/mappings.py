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
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.SupportedHash.SHA256,
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
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
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
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
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
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.SupportedHash.SHA256,
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
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
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
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
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
    # ********************
    # TLS1.3 cipher suites
    # ********************
    tls.CipherSuite.TLS_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.TLS13_AES_128_GCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.TLS13_AES_256_GCM,
        mac=tls.SupportedHash.SHA384,
    ),
    tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.SupportedHash.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_8_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.SupportedHash.SHA256,
    ),
}


# map cipher to various parameters relevant for the record layer

supported_ciphers = {
    tls.SupportedCipher.AES_128_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=algorithms.AES,
        c_type=tls.CipherType.BLOCK,
        key_len=16,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
    ),
    tls.SupportedCipher.AES_256_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=algorithms.AES,
        c_type=tls.CipherType.BLOCK,
        key_len=32,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
    ),
    tls.SupportedCipher.AES_128_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
    ),
    tls.SupportedCipher.AES_256_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
    ),
    tls.SupportedCipher.AES_128_CCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
    ),
    tls.SupportedCipher.AES_128_CCM_8: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=8,
    ),
    tls.SupportedCipher.AES_256_CCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
    ),
    tls.SupportedCipher.AES_256_CCM_8: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=8,
    ),
    tls.SupportedCipher.CHACHA20_POLY1305: structs.Cipher(
        primitive=tls.CipherPrimitive.CHACHA,
        algo=aead.ChaCha20Poly1305,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
    ),
    tls.SupportedCipher.TRIPPLE_DES_EDE_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.TRIPPLE_DES,
        algo=algorithms.TripleDES,
        c_type=tls.CipherType.BLOCK,
        key_len=24,
        block_size=8,
        iv_len=8,
        aead_expansion=None,
    ),
    tls.SupportedCipher.CAMELLIA_128_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.CAMELLIA,
        algo=algorithms.Camellia,
        c_type=tls.CipherType.BLOCK,
        key_len=16,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
    ),
    tls.SupportedCipher.CAMELLIA_256_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.CAMELLIA,
        algo=algorithms.Camellia,
        c_type=tls.CipherType.BLOCK,
        key_len=32,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
    ),
    tls.SupportedCipher.IDEA_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.IDEA,
        algo=algorithms.IDEA,
        c_type=tls.CipherType.BLOCK,
        key_len=16,
        block_size=8,
        iv_len=8,
        aead_expansion=None,
    ),
    tls.SupportedCipher.RC4_128: structs.Cipher(
        primitive=tls.CipherPrimitive.RC4,
        algo=algorithms.ARC4,
        c_type=tls.CipherType.STREAM,
        key_len=16,
        block_size=None,
        iv_len=0,
        aead_expansion=None,
    ),
    tls.SupportedCipher.TLS13_AES_128_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
    ),
    tls.SupportedCipher.TLS13_AES_256_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
    ),
}

# map hash algorithms to mac parameters

supported_macs = {
    tls.SupportedHash.SHA256: structs.Mac(
        hash_algo=hashes.SHA256, mac_len=32, key_len=32, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA: structs.Mac(
        hash_algo=hashes.SHA1, mac_len=20, key_len=20, hmac_algo=hashes.SHA256
    ),
    tls.SupportedHash.SHA384: structs.Mac(
        hash_algo=hashes.SHA384, mac_len=48, key_len=48, hmac_algo=hashes.SHA384
    ),
    tls.SupportedHash.MD5: structs.Mac(
        hash_algo=hashes.MD5, mac_len=16, key_len=16, hmac_algo=hashes.SHA256
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

key_exchange = {
    tls.KeyExchangeAlgorithm.DHE_DSS: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH, key_auth=tls.KeyAuthentication.DSS
    ),
    tls.KeyExchangeAlgorithm.DHE_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH, key_auth=tls.KeyAuthentication.RSA
    ),
    tls.KeyExchangeAlgorithm.DH_ANON: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.RSA, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.DH_DSS: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.DH_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.ECDH_ECDSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.ECDHE_ECDSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH, key_auth=tls.KeyAuthentication.ECDSA
    ),
    tls.KeyExchangeAlgorithm.ECDH_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH, key_auth=tls.KeyAuthentication.NONE
    ),
    tls.KeyExchangeAlgorithm.ECDHE_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH, key_auth=tls.KeyAuthentication.RSA
    ),
}

# RFC7919
dh_numbers = {
    tls.SupportedGroups.FFDHE2048: structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
            "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
            "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
            "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
            "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
            "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
            "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
            "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
            "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
            "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
            "886B4238 61285C97 FFFFFFFF FFFFFFFF"
        ),
    ),
    tls.SupportedGroups.FFDHE3072: structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
            "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
            "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
            "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
            "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
            "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
            "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
            "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
            "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
            "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
            "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
            "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
            "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
            "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
            "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
            "3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF"
        ),
    ),
    tls.SupportedGroups.FFDHE4096: structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
            "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
            "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
            "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
            "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
            "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
            "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
            "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
            "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
            "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
            "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
            "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
            "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
            "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
            "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
            "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
            "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
            "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
            "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
            "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
            "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E655F6A"
            "FFFFFFFF FFFFFFFF"
        ),
    ),
    tls.SupportedGroups.FFDHE6144: structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
            "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
            "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
            "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
            "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
            "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
            "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
            "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
            "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
            "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
            "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
            "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
            "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
            "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
            "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
            "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
            "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
            "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
            "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
            "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
            "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
            "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
            "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
            "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
            "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
            "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
            "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
            "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
            "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
            "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
            "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
            "A41D570D 7938DAD4 A40E329C D0E40E65 FFFFFFFF FFFFFFFF"
        ),
    ),
    tls.SupportedGroups.FFDHE8192: structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
            "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
            "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
            "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
            "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
            "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
            "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
            "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
            "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
            "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
            "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
            "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
            "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
            "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
            "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
            "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
            "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
            "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
            "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
            "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
            "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
            "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
            "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
            "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
            "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
            "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
            "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
            "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
            "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
            "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
            "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
            "A41D570D 7938DAD4 A40E329C CFF46AAA 36AD004C F600C838"
            "1E425A31 D951AE64 FDB23FCE C9509D43 687FEB69 EDD1CC5E"
            "0B8CC3BD F64B10EF 86B63142 A3AB8829 555B2F74 7C932665"
            "CB2C0F1C C01BD702 29388839 D2AF05E4 54504AC7 8B758282"
            "2846C0BA 35C35F5C 59160CC0 46FD8251 541FC68C 9C86B022"
            "BB709987 6A460E74 51A8A931 09703FEE 1C217E6C 3826E52C"
            "51AA691E 0E423CFC 99E9E316 50C1217B 624816CD AD9A95F9"
            "D5B80194 88D9C0A0 A1FE3075 A577E231 83F81D4A 3F2FA457"
            "1EFC8CE0 BA8A4FE8 B6855DFE 72B0A66E DED2FBAB FBE58A30"
            "FAFABE1C 5D71A87E 2F741EF8 C1FE86FE A6BBFDE5 30677F0D"
            "97D11D49 F7A8443D 0822E506 A9F4614E 011E2A94 838FF88C"
            "D68C8BB7 C5C6424C FFFFFFFF FFFFFFFF"
        ),
    ),
}
