# -*- coding: utf-8 -*-
"""Define common fixtures
"""
import pytest
import pathlib
import pem
import os

from tlsmate.tlsmate import TlsMate


@pytest.fixture
def fixturefiles_dir():
    return pathlib.Path(__file__).parent.resolve() / "fixturefiles"


@pytest.fixture
def trust_store_file(fixturefiles_dir):
    return fixturefiles_dir / "ca/certs/root-certificates.pem"


@pytest.fixture
def ca_rsa_crl_file(fixturefiles_dir):
    return fixturefiles_dir / "ca/crl/ca-rsa.crl.pem"


def init_crl(fixturefiles_dir, crl_manager, ca, port=44400):

    if "TLSMATE_CA_PORT" in os.environ:
        port = os.environ["TLSMATE_CA_PORT"]

    pem_file = fixturefiles_dir / f"ca/crl/{ca}.crl.pem"
    with open(pem_file, "rb") as fd:
        crl = fd.read()
    crl_manager.add_crl(f"http://crl.localhost:{port}/crl/{ca}.crl", pem_crl=crl)


@pytest.fixture
def tlsmate(fixturefiles_dir, trust_store_file):
    mate = TlsMate()
    mate.trust_store.set_ca_files([trust_store_file])
    init_crl(fixturefiles_dir, mate.crl_manager, "ca-rsa")
    init_crl(fixturefiles_dir, mate.crl_manager, "ca-ecdsa")
    mate.config.set("ocsp", False)
    mate.config.set("crl", True)
    mate.config.set("endpoint", "localhost")
    return mate


@pytest.fixture
def server_revoked_rsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/server-revoked-rsa.crt")[0]


@pytest.fixture
def server_rsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/server-rsa.crt")[0]


@pytest.fixture
def server_dsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/server-dsa.crt")[0]


@pytest.fixture
def server_ed25519_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/server-ed25519.crt")[0]


@pytest.fixture
def server_ed448_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/server-ed448.crt")[0]


@pytest.fixture
def ca_rsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/ca-rsa.crt")[0]


@pytest.fixture
def ca_2nd_rsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/ca-2nd-rsa.crt")[0]


@pytest.fixture
def ca_ecdsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/ca-ecdsa.crt")[0]


@pytest.fixture
def root_rsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/root-rsa.crt")[0]


@pytest.fixture
def root_ecdsa_cert(fixturefiles_dir):
    return pem.parse_file(fixturefiles_dir / "ca/certs/root-ecdsa.crt")[0]


@pytest.fixture
def server_profile(fixturefiles_dir):
    return fixturefiles_dir / "server_profile.yaml"


@pytest.fixture
def text_server_profile(fixturefiles_dir):
    return fixturefiles_dir / "text_server_profile.yaml"
