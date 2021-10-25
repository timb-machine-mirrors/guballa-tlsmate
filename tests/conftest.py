# -*- coding: utf-8 -*-
"""Define common fixtures
"""
import pytest
import pathlib
import pem
import os
import datetime

from tlsmate.tlsmate import TlsMate


@pytest.fixture
def valid_time():
    return datetime.datetime(2031, 6, 1)


@pytest.fixture
def style_file():
    return pathlib.Path(__file__).parent.resolve() / "../tlsmate/styles/default.yaml"


@pytest.fixture
def fixturefiles_dir():
    return pathlib.Path(__file__).parent.resolve() / "fixturefiles"


@pytest.fixture
def tlsmate_empty_ini(fixturefiles_dir):
    return fixturefiles_dir / "tlsmate_empty.ini"


@pytest.fixture
def ca_dir(fixturefiles_dir):
    return fixturefiles_dir / "../ca"


@pytest.fixture
def trust_store_file(ca_dir):
    return ca_dir / "certs/root-certificates.pem"


@pytest.fixture
def ca_rsa_crl_file(ca_dir):
    return ca_dir / "crl/ca-rsa.crl.pem"


def init_crl(ca_dir, crl_manager, ca, port=44400):

    if "TLSMATE_CA_PORT" in os.environ:
        port = os.environ["TLSMATE_CA_PORT"]

    pem_file = ca_dir / f"crl/{ca}.crl.pem"
    with open(pem_file, "rb") as fd:
        crl = fd.read()
    crl_manager.add_crl(f"http://crl.localhost:{port}/crl/{ca}.crl", pem_crl=crl)


@pytest.fixture
def tlsmate(ca_dir, trust_store_file):
    mate = TlsMate()
    mate.trust_store.set_ca_files([trust_store_file])
    init_crl(ca_dir, mate.crl_manager, "root-rsa")
    init_crl(ca_dir, mate.crl_manager, "root-ecdsa")
    init_crl(ca_dir, mate.crl_manager, "ca-rsa")
    init_crl(ca_dir, mate.crl_manager, "ca-ecdsa")
    mate.config.set("ocsp", False)
    mate.config.set("crl", True)
    mate.config.set("endpoint", "localhost")
    return mate


@pytest.fixture
def server_revoked_rsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/server-revoked-rsa.pem")[0]


@pytest.fixture
def server_rsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/server-rsa.pem")[0]


@pytest.fixture
def server_dsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/server-dsa.pem")[0]


@pytest.fixture
def server_ed25519_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/server-ed25519.pem")[0]


@pytest.fixture
def server_ed448_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/server-ed448.pem")[0]


@pytest.fixture
def ca_rsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/ca-rsa.pem")[0]


@pytest.fixture
def ca_2nd_rsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/ca-2nd-rsa.pem")[0]


@pytest.fixture
def ca_ecdsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/ca-ecdsa.pem")[0]


@pytest.fixture
def root_rsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/root-rsa.pem")[0]


@pytest.fixture
def root_ecdsa_cert(ca_dir):
    return pem.parse_file(ca_dir / "certs/root-ecdsa.pem")[0]


@pytest.fixture
def server_profile(fixturefiles_dir):
    return fixturefiles_dir / "server_profile.yaml"


@pytest.fixture
def text_server_profile(fixturefiles_dir):
    return fixturefiles_dir / "text_server_profile.yaml"


@pytest.fixture
def full_server_profile(fixturefiles_dir):
    return fixturefiles_dir / "full_server_profile.yaml"
