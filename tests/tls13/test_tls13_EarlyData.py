# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tests.cipher_suite_tester import CipherSuiteTester
from tlsmate import tls
from tlsmate import msg


class TestCase(CipherSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the CipherSuiteTester class.

    Note: The openssl server must be started with "-early_data" and we cannot use
    this option in combination with "-www".
    """

    name = "EarlyData"
    path = pathlib.Path(__file__)

    # Uncomment the line below if you do not want to use the default version and
    # adapt it to your needs.
    # version = tls.Version.TLS12

    def run(self, container, is_replaying=False):
        client = container.client()
        client.reset_profile()

        client.versions = [tls.Version.TLS13]
        client.cipher_suites = [tls.CipherSuite.TLS_AES_128_GCM_SHA256]
        client.support_supported_groups = True
        client.support_signature_algorithms = True
        client.supported_groups = [
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
            tls.SupportedGroups.X25519,
            tls.SupportedGroups.X448,
        ]
        client.signature_algorithms = [
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.RSA_PSS_PSS_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
        ]
        client.support_psk = True
        client.psk_key_exchange_modes = [tls.PskKeyExchangeMode.PSK_DHE_KE]
        end_of_tc_reached = False
        with client.create_connection() as conn:
            conn.handshake()
            conn.wait(msg.NewSessionTicket)
            end_of_tc_reached = True
        assert end_of_tc_reached is True

        client.early_data = b"This is EarlyData (0-RTT)"
        end_of_tc_reached = False
        with client.create_connection() as conn:
            conn.handshake()
            end_of_tc_reached = True
        assert end_of_tc_reached is True
        assert conn.early_data_accepted is True


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
