# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
from tlsmate import tls
from tlsmate import msg
from tlsmate.tlssuite import TlsLibrary


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    path = pathlib.Path(__file__)
    cipher_suite = tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    server_cmd = (
        "utils/start_openssl --version {library} --port {server_port} "
        "--cert1 server-rsa -- -www -ssl3"
    )
    library = TlsLibrary.openssl1_0_2

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    version = tls.Version.SSL30

    def run(self, tlsmate, is_replaying=False):

        client = tlsmate.client
        client.profile.opensslersions = [tls.Version.SSL30]
        client.profile.cipher_suites = [
            tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        ]

        end_of_tc_reached = False
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate)
            conn.wait(msg.ServerKeyExchange)
            conn.wait(msg.ServerHelloDone)
            end_of_tc_reached = True

        assert end_of_tc_reached is True


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
