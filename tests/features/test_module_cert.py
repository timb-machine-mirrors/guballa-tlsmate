# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import datetime
from tlsmate.exception import CertChainValidationError, CertValidationError
from tlsmate import tls
import pytest


def test_revoked_certificate(revoked_cert_chain, trust_store, rsa_crl):

    with pytest.raises(CertChainValidationError, match=f" {tls.CertCrlStatus.REVOKED}"):
        revoked_cert_chain.validate(
            datetime.datetime(2021, 2, 27),
            "revoked.localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_certificate_not_yet_valid(rsa_cert_chain, trust_store, rsa_crl):

    with pytest.raises(CertValidationError, match=r"validity period.*not yet reached"):
        rsa_cert_chain.validate(
            datetime.datetime(2000, 2, 27),
            "localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_certificate_expired(rsa_cert_chain, trust_store, rsa_crl):

    with pytest.raises(CertValidationError, match=r"validity period.*exceeded"):
        rsa_cert_chain.validate(
            datetime.datetime(2200, 2, 27),
            "localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_dsa_certificate(dsa_cert_chain, trust_store, rsa_crl):

    dsa_cert_chain.validate(
        datetime.datetime(2021, 2, 27),
        "localhost",
        trust_store,
        rsa_crl,
        raise_on_failure=True,
    )
    assert True


def test_ed25519_certificate(ed25519_cert_chain, trust_store, ecdsa_crl):

    ed25519_cert_chain.validate(
        datetime.datetime(2021, 2, 27),
        "localhost",
        trust_store,
        ecdsa_crl,
        raise_on_failure=True,
    )
    assert True


def test_ed448_certificate(ed448_cert_chain, trust_store, ecdsa_crl):

    ed448_cert_chain.validate(
        datetime.datetime(2021, 2, 27),
        "localhost",
        trust_store,
        ecdsa_crl,
        raise_on_failure=True,
    )
    assert True


def test_rsa_with_root_certificate(rsa_with_root_cert_chain, trust_store, rsa_crl):

    rsa_with_root_cert_chain.validate(
        datetime.datetime(2021, 2, 27),
        "localhost",
        trust_store,
        rsa_crl,
        raise_on_failure=True,
    )
    assert True


def test_wrong_sni(rsa_cert_chain, trust_store, rsa_crl):

    with pytest.raises(CertValidationError, match="subject name does not match"):
        rsa_cert_chain.validate(
            datetime.datetime(2021, 2, 27),
            "example.com",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_root_not_last_in_chain(root_not_last_in_chain, trust_store, rsa_crl):

    with pytest.raises(CertChainValidationError, match="not the last one in the chain"):
        root_not_last_in_chain.validate(
            datetime.datetime(2021, 2, 27),
            "localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_issuer_mismatch(issuer_mismatch_chain, trust_store, rsa_crl):

    with pytest.raises(CertChainValidationError, match="is not issuer of certificate"):
        issuer_mismatch_chain.validate(
            datetime.datetime(2021, 2, 27),
            "localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_signature_invalid_chain(signature_invalid_chain, trust_store, rsa_crl):

    with pytest.raises(
        CertChainValidationError, match="cannot be validated by issuer certificate"
    ):
        signature_invalid_chain.validate(
            datetime.datetime(2021, 2, 28),
            "localhost",
            trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_root_in_chain_not_in_truststore(
    rsa_with_root_cert_chain, empty_trust_store, rsa_crl
):

    with pytest.raises(
        CertChainValidationError, match=r"root certificate.*not found in trust store"
    ):
        rsa_with_root_cert_chain.validate(
            datetime.datetime(2021, 2, 27),
            "localhost",
            empty_trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_root_not_in_chain_not_in_truststore(
    rsa_cert_chain, empty_trust_store, rsa_crl
):

    with pytest.raises(
        CertChainValidationError, match=r"issuer certificate.*not found in trust store"
    ):
        rsa_cert_chain.validate(
            datetime.datetime(2021, 2, 27),
            "localhost",
            empty_trust_store,
            rsa_crl,
            raise_on_failure=True,
        )


def test_ras_san(rsa_san_cert_chain, trust_store, rsa_crl):

    rsa_san_cert_chain.validate(
        datetime.datetime(2021, 3, 27),
        "test.localhost",
        trust_store,
        rsa_crl,
        raise_on_failure=True,
    )
    assert True

    rsa_san_cert_chain.validate(
        datetime.datetime(2021, 3, 27),
        "hello.wildcard.localhost",
        trust_store,
        rsa_crl,
        raise_on_failure=True,
    )
    assert True
