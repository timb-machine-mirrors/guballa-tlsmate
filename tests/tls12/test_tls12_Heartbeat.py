# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
from tlsmate import tls
from tlsmate import msg
from tlsmate.tlssuite import OpensslVersion


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.
    """

    path = pathlib.Path(__file__)
    name = "Heartbeat"
    cipher_suite = tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    server_cmd = (
        "utils/start_openssl --prefix {prefix} --port {port} --cert rsa --cert2 ecdsa "
    )
    openssl_version = OpensslVersion.v1_0_2

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    # version = tls.Version.TLS12

    def run(self, tlsmate, is_replaying=False):
        """The basic scenario to be recorded or replayed.
        """
        client = tlsmate.client
        client.init_profile()

        client.versions = [self.version]
        client.cipher_suites = [self.cipher_suite]
        client.supported_groups = self.supported_groups
        client.signature_algorithms = self.signature_algorithms

        end_of_tc_reached = False
        client.heartbeat_mode = tls.HeartBeatMode.PEER_ALLOWED_TO_SEND
        with client.create_connection() as conn:
            conn.handshake()
            self.server_input("B\n", timeout=200)
            conn.timeout(500)
            request = msg.HeartBeatRequest()
            request.payload = b"abracadabra"
            request.payload_length = len(request.payload)
            request.padding = b"\xff" * 16
            conn.send(request)
            response = conn.wait(msg.HeartBeatResponse)
            assert response.payload_length == request.payload_length
            assert response.payload == request.payload
            end_of_tc_reached = True
        assert end_of_tc_reached is True
        return conn


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
