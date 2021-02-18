# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""

# import basic stuff

# import own stuff
from tests.tc_recorder import TcRecorder
from tlsmate import tls

# import other stuff
import pathlib


class TestCase(TcRecorder):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    path = pathlib.Path(__file__)

    # replace the XXX of the line below with the desired cipher suite
    cipher_suite = tls.CipherSuite.XXX

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    # version = tls.Version.TLS12


if __name__ == "__main__":
    TestCase().record_testcase()
