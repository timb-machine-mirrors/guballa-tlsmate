# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsmate.messages as msg
import tlsmate.constants as tls
from tlsmate.tlssuite import TlsSuite

# from tlsmate.server_profile import ProfileList, ProfileEnum


class ScanCompression(TlsSuite):
    name = "compression"
    descr = "check for compression support"
    prio = 30

    def compression(self, version):
        features = self.server_profile.features
        if not hasattr(features, "compression"):
            features.compression = []
        self.client.reset_profile()
        self.client.versions = [version]
        self.client.cipher_suites = self.server_profile.get_cipher_suites(version)

        prof_version = self.server_profile.get_version_profile(version)
        groups = getattr(prof_version.supported_groups, "groups", None)

        if groups:
            self.client.supported_groups = groups
            self.client.key_share = groups

        sig_algos = getattr(prof_version.supported_groups, "signature_algorithms", None)

        if sig_algos:
            prof = self.server_profile
            self.client.signature_algorithms = prof.get_signature_algorithms(version)
        comp_methods = tls.CompressionMethod.all()

        while comp_methods:
            self.client.compression_methods = comp_methods
            server_hello = None
            with self.client.create_connection() as conn:
                conn.send(msg.ClientHello)
                server_hello = conn.wait(msg.ServerHello)
            if server_hello is None:
                break
            if server_hello.version is not version:
                break
            if server_hello.compression_method not in comp_methods:
                break
            comp_methods.remove(server_hello.compression_method)
            if server_hello.compression_method not in features.compression:
                features.compression.append(server_hello.compression_method)

    def run(self):
        for version in self.server_profile.get_versions():
            self.compression(version)
