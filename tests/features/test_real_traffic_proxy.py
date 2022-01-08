# -*- coding: utf-8 -*-
"""Implements a class to test the compression worker.
"""
import pathlib
from tlsmate.workers.compression import ScanCompression
from tlsmate.tlssuite import TlsSuiteTester
import tlsmate.plugin as plg
import tlsmate.tls as tls

class RealTrafficProxy(plg.Worker):
    def run(self):
        self.client.set_profile(tls.Profile.INTEROPERABILITY)
        self.client.alert_on_invalid_cert = False
        with self.client.create_connection("google.com") as conn:
            conn.handshake()

        assert conn.handshake_completed


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    path = pathlib.Path(__file__)

    def run(self, tlsmate, is_replaying):
        tlsmate.recorder.deactivate()
        tlsmate.config.set("host", "google.com")
        tlsmate.config.set("proxy", "http://localhost:3128")
        tlsmate.config.set("proxy_host", "localhost")
        tlsmate.config.set("proxy_port", 3128)
        RealTrafficProxy(tlsmate).run()

def test_main():
    import tlsmate.tlsmate as tm
    app = tm.TlsMate()
    app.client.set_profile(tls.Profile.INTEROPERABILITY)
    app.client.alert_on_invalid_cert = False
    with app.client.create_connection("google.com") as conn:
        conn.handshake()

    assert conn.handshake_completed


if __name__ == "__main__":
    test_main()
