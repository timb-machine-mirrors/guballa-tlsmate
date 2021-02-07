# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
import tlsmate.constants as tls
import tlsmate.messages as msg


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.

    Note: The openssl server must be started with "-early_data" and we cannot use
    this option in combination with "-www".
    """

    name = "ClientAuth_PSS_RSAE_SHA256"
    path = pathlib.Path(__file__)
    cipher_suite = tls.CipherSuite.TLS_AES_128_GCM_SHA256

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    version = tls.Version.TLS13


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
