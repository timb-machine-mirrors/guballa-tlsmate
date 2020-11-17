# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsmate.messages as msg
import tlsmate.constants as tls
from tlsmate.tlssuite import TlsSuite
from tlsmate.server_profile import ProfileList, ProfileEnum


class ScanCompression(TlsSuite):
    name = "compression"
    descr = "check for compression support"
    prio = 30

    def compression(self, version):
        prof_features = self.server_profile.get("features")
        prof_compression = prof_features.get("compression")
        if prof_compression is None:
            prof_compression = ProfileList(key_func=lambda x: x.get_enum())
            prof_features.add("compression", prof_compression)
        self.client.reset_profile()
        self.client.versions = [version]
        self.client.cipher_suites = self.server_profile.get_cipher_suites(version)
        groups = self.server_profile.get_supported_groups(version)
        if groups:
            self.client.supported_groups = groups
            self.client.key_share = groups
        self.client.signature_algorithms = self.server_profile.get_signature_algorithms(
            version
        )
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
            prof_compression.append(
                ProfileEnum(server_hello.compression_method), keep_existing=True
            )

    def run(self):
        for version in self.server_profile.get_versions():
            self.compression(version)
