# -*- coding: utf-8 -*-
"""Implements a class to test the compression worker.
"""
import pathlib
from tlsmate.tlssuite import TlsSuiteTester
import tlsmate.plugin as plg
import tlsmate.tls as tls


class RealTraffic(plg.Worker):
    def run(self):
        self.client.set_profile(tls.Profile.INTEROPERABILITY)
        self.client.alert_on_invalid_cert = False
        with self.client.create_connection(host="google.com", port=443) as conn:
            conn.handshake()

        assert conn.handshake_completed


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    path = pathlib.Path(__file__)

    def run(self, tlsmate, is_replaying):
        tlsmate.recorder.deactivate()
        RealTraffic(tlsmate).run()


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
