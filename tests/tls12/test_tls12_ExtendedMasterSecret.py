# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
import tlsclient.constants as tls


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.
    """

    path = pathlib.Path(__file__)
    name = "ExtendedMasterSecret"
    cipher_suite = tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    # version = tls.Version.TLS12

    def update_client(self, client):

        client.support_extended_master_secret = True


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
