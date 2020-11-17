# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsmate.tlssuites.sig_algo import ScanSigAlgs
from tlsmate.tlssuite import TlsSuiteTester

sig_algs = [
    "RSA_PKCS1_SHA1",
    "RSA_PKCS1_SHA256",
    "RSA_PKCS1_SHA384",
    "RSA_PKCS1_SHA512",
    "RSA_PKCS1_SHA224",
    "ECDSA_SHA1",
    "ECDSA_SECP256R1_SHA256",
    "ECDSA_SECP384R1_SHA384",
    "ECDSA_SECP521R1_SHA512",
]


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_pickle = "profile_supported_groups_openssl1_0_2"
    sp_out_pickle = "profile_sig_algos_openssl1_0_2"
    recorder_pickle = "recorder_sig_algos_openssl1_0_2"
    path = pathlib.Path(__file__)

    server = "localhost"
    port = 44330

    def check_profile(self, profile):
        assert "signature_algorithms" not in profile["versions"][0]  # SSL30
        assert "signature_algorithms" not in profile["versions"][1]  # TLS10
        assert "signature_algorithms" not in profile["versions"][2]  # TLS11
        prof = profile["versions"][3]  # TLS12
        assert prof["server_preference"] == "C_FALSE"
        for a, b in zip(sig_algs, prof["signature_algorithms"]["algorithms"]):
            assert a == b["name"]

    def run(self, container, is_replaying):
        server_profile = container.server_profile()
        test_suite = ScanSigAlgs()
        test_suite._inject_dependencies(server_profile, container.client())
        test_suite.run()

        self.check_profile(server_profile.serialize())


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
