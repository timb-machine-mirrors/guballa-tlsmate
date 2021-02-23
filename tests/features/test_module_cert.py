# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
import datetime
import pem
from tlsmate.tlssuite import TlsSuiteTester
from tlsmate.cert import CertChain
from tlsmate.exception import CertChainValidationError


class TestCert(TlsSuiteTester):

    server = "dummy"
    port = 0
    recorder_yaml = "recorder_module_cert"
    path = pathlib.Path(__file__)

    def prepare(self, tlsmate):
        cert_dir = self.path.resolve().parent.parent.parent / "certs"
        revoked_chain = cert_dir / "server-revoked-rsa-chain.pem"
        recorder = tlsmate.recorder()
        if recorder.is_injecting():
            self.timestamp = recorder.inject(datetime=None)
        else:
            self.timestamp = datetime.datetime.now()
            recorder.trace(datetime=self.timestamp)
        self.cert_chain = CertChain()
        self.cert_chain.set_recorder(recorder)
        for cert in pem.parse_file(revoked_chain):
            self.cert_chain.append_pem_cert(cert.as_bytes())

    def run(self, tlsmate, is_replaying):
        client = tlsmate.client()
        self.prepare(tlsmate)
        # certificate revoked
        try:
            self.cert_chain.validate(
                self.timestamp, "revoked.localhost", client.trust_store, raise_on_failure=True
            )
            assert False
        except CertChainValidationError as exc:
            assert True


if __name__ == "__main__":
    TestCert().entry(is_replaying=False)
