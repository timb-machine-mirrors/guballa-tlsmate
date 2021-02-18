# -*- coding: utf-8 -*-
"""Test the cipher suite filter
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.utils import filter_cipher_suites

# import other stuff


def check_presence(cs_list, string_list):
    for cs in cs_list:
        match = False
        for string in string_list:
            if string in cs.name:
                match = True
                break
        assert match is True


def check_absence(cs_list, string):
    for cs in cs_list:
        assert string not in cs.name


def test_filter_cipher_suites():
    """Simple tests, only one filter condition at once
    """
    cs_all = tls.CipherSuite.all()
    cs_all.remove(tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    cs_all.remove(tls.CipherSuite.TLS_FALLBACK_SCSV)

    assert cs_all == filter_cipher_suites(cs_all)

    tls13 = filter_cipher_suites(cs_all, version=tls.Version.TLS13)
    assert set(tls13) == set(
        (
            tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            tls.CipherSuite.TLS_AES_128_CCM_SHA256,
            tls.CipherSuite.TLS_AES_128_CCM_8_SHA256,
        )
    )

    tls12 = filter_cipher_suites(cs_all, version=tls.Version.TLS12)
    assert set(tls12) & set(tls13) == set()
    assert set(tls12) | set(tls13) == set(cs_all)

    tls11 = filter_cipher_suites(cs_all, version=tls.Version.TLS11)
    diff = set(tls12).difference(set(tls11))
    aead = filter_cipher_suites(tls12, cipher_type=[tls.CipherType.AEAD])
    assert diff != set()
    assert set(aead) == set(diff)
    check_presence(aead, ["_GCM_", "_CCM", "_CHACHA20_POLY1305_"])
    check_absence(tls11, "_GCM_")
    check_absence(tls11, "_CCM")
    check_absence(tls11, "_CHACHA20_POLY1305_")

    ecdh_rsa = filter_cipher_suites(
        cs_all, key_algo=[tls.KeyExchangeAlgorithm.ECDH_RSA], remove=True
    )
    check_presence(ecdh_rsa, ["_ECDH_RSA_"])
    check_absence(cs_all, "_ECDH_RSA_")

    cs_all = tls.CipherSuite.all()
    dh = filter_cipher_suites(cs_all, key_exch=[tls.KeyExchangeType.DH], remove=True)
    check_presence(dh, ["_DH_", "_DHE_"])
    check_absence(cs_all, "_DH_")
    check_absence(cs_all, "_DHE_")

    cs_all = tls.CipherSuite.all()
    ecdsa = filter_cipher_suites(
        cs_all, key_auth=[tls.KeyAuthentication.ECDSA], remove=True
    )
    check_presence(ecdsa, ["_ECDSA_"])
    check_absence(cs_all, "_ECDSA_")

    cs_all = tls.CipherSuite.all()
    ecdsa = filter_cipher_suites(
        cs_all, cipher=[tls.SymmetricCipher.AES_128_CBC], remove=True
    )
    check_presence(ecdsa, ["_AES_128_CBC_"])
    check_absence(cs_all, "_AES_128_CBC_")

    cs_all = tls.CipherSuite.all()
    ecdsa = filter_cipher_suites(
        cs_all, cipher_prim=[tls.CipherPrimitive.ARIA], remove=True
    )
    check_presence(ecdsa, ["_WITH_ARIA_"])
    check_absence(cs_all, "_WITH_ARIA_")

    cs_all = tls.CipherSuite.all()
    sha384 = filter_cipher_suites(cs_all, mac=[tls.HashPrimitive.SHA384], remove=True)
    check_presence(sha384, ["_SHA384"])
    check_absence(cs_all, "_SHA384")

    cs_all = tls.CipherSuite.all()
    cs_all.remove(tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    cs_all.remove(tls.CipherSuite.TLS_FALLBACK_SCSV)
    cs_all2 = cs_all[:]
    full_hs = filter_cipher_suites(cs_all, full_hs=True, remove=True)
    not_full_hs = filter_cipher_suites(cs_all2, full_hs=False, remove=True)
    assert set(full_hs) != set()
    assert not_full_hs != set()
    assert cs_all == not_full_hs
    assert cs_all2 == full_hs
