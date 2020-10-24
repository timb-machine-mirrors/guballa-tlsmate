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
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.IDEA_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    # ********************
    # TLS1.3 cipher suites
    # ********************
    tls.CipherSuite.TLS_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.TLS13_AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.TLS13_AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_8_SHA256: structs.CipherSuite(
        key_ex=None,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
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
    tls.HashPrimitive.SHA256: structs.Mac(
        hash_algo=hashes.SHA256, mac_len=32, key_len=32, hmac_algo=hashes.SHA256
    ),
    tls.HashPrimitive.SHA1: structs.Mac(
        hash_algo=hashes.SHA1, mac_len=20, key_len=20, hmac_algo=hashes.SHA256
    ),
    tls.HashPrimitive.SHA384: structs.Mac(
        hash_algo=hashes.SHA384, mac_len=48, key_len=48, hmac_algo=hashes.SHA384
    ),
    tls.HashPrimitive.MD5: structs.Mac(
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

# all other well known DH parameters
well_known_dh_params = [
    # RFC2409, First Oakley Default Group, 768 bits
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC2409, Second Oakley Group, 1024 bits
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
            "FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 1536-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 2048-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 3072-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
            "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
            "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
            "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
            "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
            "43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 4096-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
            "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
            "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
            "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
            "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
            "43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
            "88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
            "2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
            "287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
            "1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
            "93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199"
            "FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 6144-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08"
            "8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B"
            "302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9"
            "A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6"
            "49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8"
            "FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C"
            "180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718"
            "3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D"
            "04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D"
            "B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226"
            "1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
            "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC"
            "E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26"
            "99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB"
            "04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2"
            "233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127"
            "D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492"
            "36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406"
            "AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918"
            "DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151"
            "2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03"
            "F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F"
            "BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA"
            "CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B"
            "B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632"
            "387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E"
            "6DCC4024 FFFFFFFF FFFFFFFF"
        ),
    ),
    # RFC3526 8192-bit MODP Group
    structs.DHNumbers(
        g_val=2,
        p_val=bytes.fromhex(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
            "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
            "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
            "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
            "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
            "43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
            "88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
            "2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
            "287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
            "1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
            "93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492"
            "36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD"
            "F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831"
            "179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B"
            "DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF"
            "5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6"
            "D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3"
            "23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA"
            "CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328"
            "06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C"
            "DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE"
            "12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4"
            "38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300"
            "741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568"
            "3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9"
            "22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B"
            "4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A"
            "062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36"
            "4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1"
            "B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92"
            "4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47"
            "9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71"
            "60C980DD 98EDD3DF FFFFFFFF FFFFFFFF"
        ),
    ),
]
