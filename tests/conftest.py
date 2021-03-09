# -*- coding: utf-8 -*-
"""Define common fixtures
"""
import pytest
import pathlib
import pem

from tlsmate.tlsmate import TlsMate
from tlsmate.config import Configuration
from tlsmate.cert import CertChain, CrlManager


@pytest.fixture
def config_no_trust():
    config_file = pathlib.Path(__file__).parent.resolve() / "tlsmate_no_trust.ini"
    return Configuration(ini_file=config_file)


def build_cert_chain(pem_file):
    cert_chain = CertChain()
    certs = pem.parse_file(pem_file)
    for cert in certs:
        cert_chain.append_pem_cert(cert.as_bytes())
    return cert_chain


@pytest.fixture
def tlsmate():
    return TlsMate()


@pytest.fixture
def fixturefiles_dir():
    return pathlib.Path(__file__).parent.resolve() / "fixturefiles"


@pytest.fixture
def trust_store(tlsmate, fixturefiles_dir):
    trust_store = tlsmate.trust_store
    trust_store.set_ca_files([fixturefiles_dir / "trust_store.pem"])
    return trust_store


@pytest.fixture
def empty_trust_store(tlsmate, config_no_trust):
    return TlsMate(config=config_no_trust).trust_store


@pytest.fixture
def revoked_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "revoked_cert_chain.pem")


@pytest.fixture
def rsa_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "rsa_cert_chain.pem")


@pytest.fixture
def rsa_san_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "rsa_san_cert_chain.pem")


@pytest.fixture
def rsa_with_root_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "rsa_with_root_cert_chain.pem")


@pytest.fixture
def dsa_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "dsa_cert_chain.pem")


@pytest.fixture
def ed25519_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "ed25519_cert_chain.pem")


@pytest.fixture
def ed448_cert_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "ed448_cert_chain.pem")


@pytest.fixture
def root_not_last_in_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "too_much_certs.pem")


@pytest.fixture
def issuer_mismatch_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "issuer_mismatch_chain.pem")


@pytest.fixture
def signature_invalid_chain(fixturefiles_dir):
    return build_cert_chain(fixturefiles_dir / "signature_invalid_chain.pem")


@pytest.fixture
def rsa_crl(fixturefiles_dir):
    with open(fixturefiles_dir / "inter-ca-rsa.crl.pem", "rb") as fd:
        crl = fd.read()
    crl_manager = CrlManager()
    crl_manager.add_crl("http://crl.localhost/inter-ca-rsa.crl", pem_crl=crl)
    return crl_manager


@pytest.fixture
def ecdsa_crl(fixturefiles_dir):
    with open(fixturefiles_dir / "inter-ca-ecdsa.crl.pem", "rb") as fd:
        crl = fd.read()
    crl_manager = CrlManager()
    crl_manager.add_crl("http://crl.localhost/inter-ca-ecdsa.crl", pem_crl=crl)
    return crl_manager
