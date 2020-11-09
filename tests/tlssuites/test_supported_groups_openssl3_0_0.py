# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsclient.tlssuites.supported_groups import ScanSupportedGroups
from tlsclient.tlssuite import TlsSuiteTester
from dependency_injector import providers


groups_tls12 = [
    "SECP256R1",
    "SECP384R1",
    "SECP521R1",
    "X25519",
    "X448",
]

groups_tls13 = [
    "SECP256R1",
    "SECP384R1",
    "SECP521R1",
    "X25519",
    "X448",
    "FFDHE2048",
    "FFDHE3072",
    "FFDHE4096",
    "FFDHE6144",
    "FFDHE8192",
]

class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_pickle = "profile_basic_openssl3_0_0"
    sp_out_pickle = "profile_supported_groups_openssl3_0_0"
    recorder_pickle = "recorder_supported_groups_openssl3_0_0"
    path = pathlib.Path(__file__)

    server = "localhost"
    port = 44332


    def check_tls12(self, profile):
        assert profile["extension_supported"] == "C_TRUE"
        assert profile["server_preference"] == "C_FALSE"
        assert "groups_advertised" not in profile
        assert len(profile["groups"]) == len(groups_tls12)
        for a, b in zip(groups_tls12, profile["groups"]):
            assert a == b["name"]

    def check_tls13(self, profile):
        assert profile["extension_supported"] == "C_TRUE"
        assert profile["server_preference"] == "C_FALSE"
        assert profile["groups_advertised"] == "C_TRUE"
        assert len(profile["groups"]) == len(groups_tls13)
        for a, b in zip(groups_tls13, profile["groups"]):
            assert a == b["name"]


    def check_profile(self, profile):
        self.check_tls12(profile["versions"][0]["supported_groups"])
        self.check_tls13(profile["versions"][1]["supported_groups"])

    def run(self, container, is_replaying):
        server_profile = container.server_profile()
        test_suite = ScanSupportedGroups()
        test_suite._inject_dependencies(server_profile, container.client())
        test_suite.run()

        self.check_profile(server_profile.serialize())


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
