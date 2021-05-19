# -*- coding: utf-8 -*-
"""Implements a class to test the scanner info workers.
"""
import pathlib
import time
import datetime
from tlsmate.workers.scanner_info import ScanStart, ScanEnd
from tlsmate.tlssuite import TlsSuiteTester, TlsLibrary
from tlsmate.version import __version__


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_in_yaml = "profile_sig_algos_openssl3_0_0"
    recorder_yaml = "recorder_scan_info"
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
        start_timestamp = time.time()
        ScanStart(tlsmate).run()
        ScanEnd(tlsmate).run()
        end_timestamp = time.time()
        date = datetime.datetime.fromtimestamp(int(start_timestamp))
        date_str = date.strftime("%Y-%m-%d")
        profile = server_profile.make_serializable()
        assert profile["scan_info"]["version"] == __version__
        assert type(profile["scan_info"]["command"]) == str
        assert profile["scan_info"]["run_time"] < 0.5
        assert profile["scan_info"]["start_timestamp"] >= start_timestamp
        assert profile["scan_info"]["stop_timestamp"] <= end_timestamp
        assert date_str in profile["scan_info"]["start_date"]
        assert date_str in profile["scan_info"]["stop_date"]

        assert profile["server"]["ip"] == "127.0.0.1"
        assert profile["server"]["sni"] == "localhost"
        assert profile["server"]["port"] == self.config.get("server_port")
        assert profile["server"]["name_resolution"]["domain_name"] == "localhost"
        assert len(profile["server"]["name_resolution"]["ipv4_addresses"]) == 1
        assert profile["server"]["name_resolution"]["ipv4_addresses"][0] == "127.0.0.1"


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
