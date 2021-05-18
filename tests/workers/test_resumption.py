# -*- coding: utf-8 -*-
"""Implements a class to test the resumption worker.
"""
import pathlib
from tlsmate.workers.resumption import ScanResumption
from tlsmate.tlssuite import TlsSuiteTester
from tlsmate.tlssuite import TlsLibrary


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_yaml = "profile_sig_algos_openssl3_0_0"
    sp_out_yaml = "profile_resumption_openssl3_0_0"
    recorder_yaml = "recorder_resumption"
    path = pathlib.Path(__file__)
    server_cmd = (
        "utils/start_openssl --version {library} --port {server_port} "
        "--cert1 server-rsa --cert2 server-ecdsa "
        "-- -www -cipher ALL"
    )
    library = TlsLibrary.openssl3_0_0

    server = "localhost"

    def run(self, tlsmate, is_replaying):
        server_profile = tlsmate.server_profile
        ScanResumption(tlsmate).run()
        profile = server_profile.make_serializable()
        assert profile["features"]["session_id"] == "C_TRUE"
        assert profile["features"]["session_ticket"] == "C_TRUE"
        assert profile["features"]["session_ticket_lifetime"] == 7200
        assert profile["features"]["resumption_psk"] == "C_TRUE"
        assert profile["features"]["psk_lifetime"] == 7200


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
