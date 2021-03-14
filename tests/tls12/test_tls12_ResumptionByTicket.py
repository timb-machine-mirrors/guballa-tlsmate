# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
import logging
from tests.cipher_suite_tester import CipherSuiteTester
from tlsmate import tls
from tlsmate import msg
from tlsmate.tlssuite import OpensslVersion


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.
    """

    name = "ResumptionByTicket"
    path = pathlib.Path(__file__)
    server_cmd = (
        "utils/start_openssl --prefix {prefix} --port {port} --cert rsa --cert2 ecdsa "
        "--mode www"
    )
    openssl_version = OpensslVersion.v1_1_1

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    # version = tls.Version.TLS12

    def run(self, tlsmate, is_replaying=False):
        client = tlsmate.client
        client.init_profile()

        client.versions = [tls.Version.TLS12]
        client.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        client.support_supported_groups = True
        client.support_signature_algorithms = True
        client.supported_groups = [
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
        ]
        client.signature_algorithms = [tls.SignatureScheme.RSA_PKCS1_SHA1]
        client.support_session_ticket = True
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.Certificate, optional=True)
            conn.wait(msg.ServerKeyExchange, optional=True)
            conn.wait(msg.ServerHelloDone)
            conn.send(msg.ClientKeyExchange, msg.ChangeCipherSpec, msg.Finished)
            conn.wait(msg.NewSessionTicket, optional=True)
            conn.wait(msg.ChangeCipherSpec)
            conn.wait(msg.Finished)
            conn.send(msg.AppData(b"GET / HTTP/1.1\n"))
            while True:
                app_data = conn.wait(msg.AppData)
                if len(app_data.data):
                    break
            for line in app_data.data.decode("utf-8").split("\n"):
                if line.startswith("s_server"):
                    logging.debug("openssl_command: " + line)

        end_of_tc_reached = False
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec)
            conn.wait(msg.NewSessionTicket, optional=True)
            conn.wait(msg.Finished)
            conn.send(msg.ChangeCipherSpec, msg.Finished)

            conn.send(msg.AppData(b"GET / HTTP/1.1\n"))
            while True:
                app_data = conn.wait(msg.AppData)
                if len(app_data.data):
                    break
            for line in app_data.data.decode("utf-8").split("\n"):
                if line.startswith("s_server"):
                    logging.debug("openssl_command: " + line)
            end_of_tc_reached = True
        assert end_of_tc_reached is True


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
