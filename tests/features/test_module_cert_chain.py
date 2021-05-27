# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import datetime
from tlsmate.cert_chain import CertChain
from tlsmate.exception import UntrustedCertificate
from tlsmate import tls
import pytest


def test_revoked_certificate(tlsmate, server_revoked_rsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_revoked_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match=f" {tls.CertCrlStatus.REVOKED}"):
        chain.validate(datetime.datetime.now(), "revoked.localhost", True)


def test_certificate_not_yet_valid(tlsmate, server_rsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match=r"validity period.*not yet reached"):
        chain.validate(datetime.datetime(2000, 2, 27), "localhost", True)


def test_certificate_expired(tlsmate, server_rsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match=r"validity period.*exceeded"):
        chain.validate(datetime.datetime(2200, 2, 27), "localhost", True)


def test_dsa_certificate(tlsmate, server_dsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_dsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert True


def test_ed25519_certificate(tlsmate, server_ed25519_cert, ca_ecdsa_cert):

    chain = CertChain()
    for cert in (server_ed25519_cert, ca_ecdsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert True


def test_ed448_certificate(tlsmate, server_ed448_cert, ca_ecdsa_cert):

    chain = CertChain()
    for cert in (server_ed448_cert, ca_ecdsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert True


def test_rsa_with_root_certificate(
    tlsmate, server_rsa_cert, ca_rsa_cert, root_rsa_cert
):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert, root_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert True


def test_wrong_sni(tlsmate, server_rsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match=r"subject name does not match"):
        chain.validate(datetime.datetime.now(), "example.com", True)


def test_root_not_last_in_chain(
    tlsmate, server_rsa_cert, ca_rsa_cert, ca_ecdsa_cert, root_rsa_cert
):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert, ca_ecdsa_cert, root_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert True


def test_issuer_mismatch(tlsmate, server_rsa_cert, ca_ecdsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_ecdsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match="not found in trust store"):
        chain.validate(datetime.datetime.now(), "localhost", True)


def test_signature_invalid_chain(tlsmate, server_rsa_cert, ca_2nd_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_2nd_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match="not found in trust store"):
        chain.validate(datetime.datetime.now(), "localhost", True)


def test_root_in_chain_not_in_truststore(
    tlsmate, server_rsa_cert, ca_rsa_cert, root_rsa_cert
):

    # hard reset of the trust store
    tlsmate.trust_store._ca_files = None

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert, root_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(
        UntrustedCertificate, match="self-signed certificate not found in trust store"
    ):
        chain.validate(datetime.datetime.now(), "localhost", True)


def test_root_not_in_chain_not_in_truststore(tlsmate, server_rsa_cert, ca_rsa_cert):

    # hard reset of the trust store
    tlsmate.trust_store._ca_files = None

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    with pytest.raises(UntrustedCertificate, match="not found in trust store"):
        chain.validate(datetime.datetime.now(), "localhost", True)


def test_rsa_san(tlsmate, server_rsa_cert, ca_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "test.localhost", True)
    assert True

    chain.validate(datetime.datetime.now(), "hello.wildcard.localhost", True)
    assert True


def test_certs_not_in_sequence(tlsmate, server_rsa_cert, ca_rsa_cert, root_rsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, root_rsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", True)
    assert "certificates of the chain are not in sequence" in chain.issues[0]


def test_gratuitous_certificate(tlsmate, server_rsa_cert, ca_rsa_cert, ca_ecdsa_cert):

    chain = CertChain()
    for cert in (server_rsa_cert, ca_ecdsa_cert, ca_rsa_cert):
        chain.append_pem_cert(cert.as_bytes())

    chain.validate(datetime.datetime.now(), "localhost", False)
    assert (
        "gratuitous certificate, not part of trust chain"
        in chain.certificates[1].issues[0]
    )
