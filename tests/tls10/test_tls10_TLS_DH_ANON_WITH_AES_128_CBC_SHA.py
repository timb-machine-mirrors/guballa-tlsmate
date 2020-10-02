# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.tc_recorder import TcRecorder
import tlsclient.constants as tls


class TestCase(TcRecorder):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    path = pathlib.Path(__file__)

    cipher_suite = tls.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    version = tls.Version.TLS10


if __name__ == "__main__":
    import logging

    logging.basicConfig(level="DEBUG")
    TestCase().record_testcase()
