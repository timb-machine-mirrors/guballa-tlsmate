# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsmate.tlssuites.supported_groups import ScanSupportedGroups
from tlsmate.tlssuite import TlsSuiteTester


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_pickle = "profile_basic_openssl1_0_2"
    sp_out_pickle = "profile_supported_groups_openssl1_0_2"
    recorder_pickle = "recorder_supported_groups_openssl1_0_2"
    path = pathlib.Path(__file__)

    server = "localhost"
    port = 44330

    def check_ssl30(self, profile):
        assert profile["extension_supported"] == "C_FALSE"
        assert len(profile["groups"]) == 1
        assert profile["groups"][0]["name"] == "SECP256R1"

    def check_tls(self, profile):
        assert profile["extension_supported"] == "C_TRUE"
        assert profile["server_preference"] == "C_NA"
        assert len(profile["groups"]) == 1
        assert profile["groups"][0]["name"] == "SECP256R1"

    def check_profile(self, profile):
        self.check_ssl30(profile["versions"][0]["supported_groups"])
        self.check_tls(profile["versions"][1]["supported_groups"])
        self.check_tls(profile["versions"][2]["supported_groups"])
        self.check_tls(profile["versions"][3]["supported_groups"])

    def run(self, container, is_replaying):
        server_profile = container.server_profile()
        test_suite = ScanSupportedGroups()
        test_suite._inject_dependencies(server_profile, container.client())
        test_suite.run()

        self.check_profile(server_profile.serialize())


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
