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
        values = self.server_profile.get_profile_values([version])

        self.client.cipher_suites = values.cipher_suites
        if values.supported_groups:
            self.client.supported_groups = values.supported_groups
            self.client.supported_groups = values.supported_groups
        if values.signature_algorithms:
            self.client.signature_algorithms = values.signature_algorithms

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
        for version in self.server_profile.get_versions(exclude=[tls.Version.SSL20]):
            self.compression(version)
