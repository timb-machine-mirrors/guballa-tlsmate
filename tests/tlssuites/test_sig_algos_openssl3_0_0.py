# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsclient.tlssuites.sig_algo import ScanSigAlgs
from tlsclient.tlssuite import TlsSuiteTester

sig_algs_tls12 = [
    "RSA_PKCS1_SHA256",
    "RSA_PKCS1_SHA384",
    "RSA_PKCS1_SHA512",
    "RSA_PKCS1_SHA224",
    "ECDSA_SECP256R1_SHA256",
    "ECDSA_SECP384R1_SHA384",
    "ECDSA_SECP521R1_SHA512",
]

sig_algs_tls13 = [
    "ECDSA_SECP256R1_SHA256",
    "RSA_PSS_RSAE_SHA256",
    "RSA_PSS_RSAE_SHA384",
    "RSA_PSS_RSAE_SHA512",
]

class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_pickle = "profile_supported_groups_openssl3_0_0"
    sp_out_pickle = "profile_sig_algos_openssl3_0_0"
    recorder_pickle = "recorder_sig_algos_openssl3_0_0"
    path = pathlib.Path(__file__)

    server = "localhost"
    port = 44332

    def check_tls12(self, prof):
        assert prof["server_preference"] == "C_FALSE"
        assert len(prof["algorithms"]) == len(sig_algs_tls12)
        for a, b in zip(sig_algs_tls12, prof["algorithms"]):
            assert a == b["name"]

    def check_tls13(self, prof):
        assert prof["server_preference"] == "C_FALSE"
        assert len(prof["algorithms"]) == len(sig_algs_tls13)
        for a, b in zip(sig_algs_tls13, prof["algorithms"]):
            assert a == b["name"]

    def check_profile(self, profile):
        self.check_tls12(profile["versions"][0]["signature_algorithms"])
        self.check_tls13(profile["versions"][1]["signature_algorithms"])

    def run(self, container, is_replaying):
        server_profile = container.server_profile()
        test_suite = ScanSigAlgs()
        test_suite._inject_dependencies(server_profile, container.client())
        test_suite.run()

        self.check_profile(server_profile.serialize())


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
