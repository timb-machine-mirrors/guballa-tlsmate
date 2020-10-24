# -*- coding: utf-8 -*-
"""Module containing various mapping tables
"""
import tlsclient.constants as tls

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, aead
import tlsclient.structures as structs

# this map contains all cipher suites for which a full handshake is supported,
# i.e., application data can be exchanged encrypted

supported_cipher_suites = {
    tls.CipherSuite.TLS_NULL_WITH_NULL_NULL: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.NULL,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.NULL,
    ),
    tls.CipherSuite.TLS_RSA_WITH_NULL_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_RSA_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_EXPORT,
        cipher=tls.SupportedCipher.RC4_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_EXPORT,
        cipher=tls.SupportedCipher.RC2_CBC_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.IDEA_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON_EXPORT,
        cipher=tls.SupportedCipher.RC4_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_RC4_128_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON_EXPORT,
        cipher=tls.SupportedCipher.DES40_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_IDEA_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.IDEA_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_DES_CBC_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.DES_CBC,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_RC4_128_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_WITH_IDEA_CBC_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5,
        cipher=tls.SupportedCipher.IDEA_CBC,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.DES_CBC_40,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.RC2_CBC_40,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.RC4_40,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.DES_CBC_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.RC2_CBC_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.KRB5_EXPORT,
        cipher=tls.SupportedCipher.RC4_40,
        mac=tls.HashPrimitive.MD5,
    ),
    tls.CipherSuite.TLS_PSK_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_NULL_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_PSK_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_SEED_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.SEED_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_NULL_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_NULL_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
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
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
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
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ANON_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ANON,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ANON_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ANON,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ANON,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ANON,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDH_ANON_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ANON,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_RSA,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_DSS,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_DSS,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.SRP_SHA_DSS,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.RC4_128,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.TRIPPLE_DES_EDE_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA1,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.NULL,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.ARIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.ARIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.ARIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.ARIA_256_CBC,
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
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
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
    tls.CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_DSS,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DH_ANON,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_ECDSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDH_RSA,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_128_CBC,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.CAMELLIA_256_CBC,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK_DHE,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK_DHE,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.AES_256_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECCPWD,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECCPWD_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECCPWD,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECCPWD_WITH_AES_128_CCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECCPWD,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECCPWD_WITH_AES_256_CCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECCPWD,
        cipher=tls.SupportedCipher.AES_256_CCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_RSA,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.PSK,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.DHE_PSK,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.RSA_PSK,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CCM_8,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.ECDHE_PSK,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    # ********************
    # TLS1.3 cipher suites
    # ********************
    tls.CipherSuite.TLS_AES_128_GCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE,
        cipher=tls.SupportedCipher.TLS13_AES_128_GCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_256_GCM_SHA384: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE,
        cipher=tls.SupportedCipher.TLS13_AES_256_GCM,
        mac=tls.HashPrimitive.SHA384,
    ),
    tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE,
        cipher=tls.SupportedCipher.CHACHA20_POLY1305,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE,
        cipher=tls.SupportedCipher.AES_128_CCM,
        mac=tls.HashPrimitive.SHA256,
    ),
    tls.CipherSuite.TLS_AES_128_CCM_8_SHA256: structs.CipherSuite(
        key_ex=tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE,
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
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_256_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=algorithms.AES,
        c_type=tls.CipherType.BLOCK,
        key_len=32,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_128_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_256_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_128_CCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_128_CCM_8: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=4,
        aead_expansion=8,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_256_CCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.AES_256_CCM_8: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESCCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=4,
        aead_expansion=8,
        cipher_supported=True,
    ),
    tls.SupportedCipher.CHACHA20_POLY1305: structs.Cipher(
        primitive=tls.CipherPrimitive.CHACHA,
        algo=aead.ChaCha20Poly1305,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.TRIPPLE_DES_EDE_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.TRIPPLE_DES,
        algo=algorithms.TripleDES,
        c_type=tls.CipherType.BLOCK,
        key_len=24,
        block_size=8,
        iv_len=8,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.CAMELLIA_128_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.CAMELLIA,
        algo=algorithms.Camellia,
        c_type=tls.CipherType.BLOCK,
        key_len=16,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.CAMELLIA_256_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.CAMELLIA,
        algo=algorithms.Camellia,
        c_type=tls.CipherType.BLOCK,
        key_len=32,
        block_size=16,
        iv_len=16,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.IDEA_CBC: structs.Cipher(
        primitive=tls.CipherPrimitive.IDEA,
        algo=algorithms.IDEA,
        c_type=tls.CipherType.BLOCK,
        key_len=16,
        block_size=8,
        iv_len=8,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.RC4_128: structs.Cipher(
        primitive=tls.CipherPrimitive.RC4,
        algo=algorithms.ARC4,
        c_type=tls.CipherType.STREAM,
        key_len=16,
        block_size=None,
        iv_len=0,
        aead_expansion=None,
        cipher_supported=True,
    ),
    tls.SupportedCipher.TLS13_AES_128_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=16,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
        cipher_supported=True,
    ),
    tls.SupportedCipher.TLS13_AES_256_GCM: structs.Cipher(
        primitive=tls.CipherPrimitive.AES,
        algo=aead.AESGCM,
        c_type=tls.CipherType.AEAD,
        key_len=32,
        block_size=16,
        iv_len=12,
        aead_expansion=16,
        cipher_supported=True,
    ),
    # ***************************
    # List of unsupported ciphers
    # ***************************
    tls.SupportedCipher.ARIA_128_CBC: structs.Cipher(),
    tls.SupportedCipher.ARIA_128_GCM: structs.Cipher(),
    tls.SupportedCipher.ARIA_256_CBC: structs.Cipher(),
    tls.SupportedCipher.ARIA_256_GCM: structs.Cipher(),
    tls.SupportedCipher.CAMELLIA_128_GCM: structs.Cipher(),
    tls.SupportedCipher.CAMELLIA_256_GCM: structs.Cipher(),
    tls.SupportedCipher.DES40_CBC: structs.Cipher(),
    tls.SupportedCipher.DES_CBC: structs.Cipher(),
    tls.SupportedCipher.DES_CBC_40: structs.Cipher(),
    tls.SupportedCipher.NULL: structs.Cipher(),
    tls.SupportedCipher.RC2_CBC_40: structs.Cipher(),
    tls.SupportedCipher.RC4_40: structs.Cipher(),
    tls.SupportedCipher.SEED_CBC: structs.Cipher(),
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

key_exchange = {
    tls.KeyExchangeAlgorithm.DHE_DSS: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH,
        key_auth=tls.KeyAuthentication.DSS,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.DHE_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH,
        key_auth=tls.KeyAuthentication.RSA,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.DH_ANON: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.RSA,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.DH_DSS: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=False,
    ),
    tls.KeyExchangeAlgorithm.DH_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.DH,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=False,
    ),
    tls.KeyExchangeAlgorithm.ECDH_ECDSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.ECDHE_ECDSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH,
        key_auth=tls.KeyAuthentication.ECDSA,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.ECDH_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH,
        key_auth=tls.KeyAuthentication.NONE,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.ECDHE_RSA: structs.KeyExchange(
        key_ex_type=tls.KeyExchangeType.ECDH,
        key_auth=tls.KeyAuthentication.RSA,
        key_ex_supported=True,
    ),
    tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE: structs.KeyExchange(
        key_ex_type=None, key_auth=None, key_ex_supported=True
    ),
}
