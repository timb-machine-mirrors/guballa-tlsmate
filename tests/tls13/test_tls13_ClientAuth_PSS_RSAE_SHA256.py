# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
from tlsmate import tls
from tlsmate.tlssuite import TlsLibrary


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.

    Note: The openssl server must be started with "-early_data" and we cannot use
    this option in combination with "-www".
    """

    name = "ClientAuth_PSS_RSAE_SHA256"
    path = pathlib.Path(__file__)
    cipher_suite = tls.CipherSuite.TLS_AES_128_GCM_SHA256
    server_cmd = (
        "utils/start_openssl --version {library} --port {server_port} "
        "--cert1 server-rsa --cert2 server-ecdsa "
        "-- -www -cipher ALL -verify 3 -client_sigalgs rsa_pss_rsae_sha256"
    )
    library = TlsLibrary.openssl1_1_1

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    version = tls.Version.TLS13


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
