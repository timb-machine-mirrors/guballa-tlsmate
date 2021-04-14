# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsmate.workers.robot import ScanRobot
from tlsmate.tlssuite import TlsSuiteTester


class TestCaseWeakOracle(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_yaml = "profile_basic_wolfssl"
    recorder_yaml = "recorder_robot_weak_oracle"
    path = pathlib.Path(__file__)
    server_cmd = None
    # We set this command to None, as we have tested the weak ROBOT oracle
    # by using wolfssl.
    # Config: tag v3.12.0-stable was used (vulnerable version),
    # -DWOLFSSL_STATIC_RSA was added to Makefile
    # ./examples/server/server -C 5000 -x -p 44330 -d

    openssl_version = None

    server = "localhost"

    def run(self, tlsmate, is_replaying):
        server_profile = tlsmate.server_profile
        tlsmate.client.alert_on_invalid_cert = False
        ScanRobot(tlsmate).run()
        profile = server_profile.make_serializable()
        assert profile["vulnerabilities"]["robot"] == "WEAK_ORACLE"


if __name__ == "__main__":
    TestCaseWeakOracle().entry(is_replaying=False)
