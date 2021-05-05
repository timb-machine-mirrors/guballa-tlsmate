# -*- coding: utf-8 -*-
"""Implements a class to test the heartbeat worker.
"""
import pathlib
from tlsmate.workers.heartbeat import ScanHeartbeat
from tlsmate.tlssuite import TlsSuiteTester
from tlsmate.tlssuite import OpensslVersion


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_yaml = "profile_sig_algos_openssl1_0_2"
    sp_out_yaml = "profile_heartbeat_openssl1_0_1e"
    recorder_yaml = "heartbeat"
    path = pathlib.Path(__file__)
    server_cmd = (
        "utils/start_openssl --prefix {prefix} --port {port} --cert rsa --cert2 ecdsa "
        "--mode www -- -cipher ALL"
    )
    openssl_version = OpensslVersion.v1_0_2

    server = "localhost"

    def run(self, tlsmate, is_replaying):
        server_profile = tlsmate.server_profile
        ScanHeartbeat(tlsmate).run()
        profile = server_profile.make_serializable()
        assert profile["features"]["heartbeat"] == "C_TRUE"


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
