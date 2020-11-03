# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestSuite
from tlsclient.server_profile import SPEnum


class ScanFeatures(TestSuite):
    name = "features"
    descr = "check for basic features"
    prio = 30

    def compression(self, version, prof_version):
        self.client.reset_profile()
        self.client.versions = [version]
        self.client.cipher_suites = prof_version.cipher_suites.all()
        groups = prof_version.supported_groups.groups.all()
        if groups:
            self.client.supported_groups = groups
            self.client.key_share = groups
        if prof_version.signature_algorithms is not None:
            self.client.signature_algorithms = (
                prof_version.signature_algorithms.algorithms.all()
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
            self.server_profile.features.compression.append(
                SPEnum(server_hello.compression_method), keep_existing=True
            )

    def run(self):
        for version in self.server_profile.versions.all():
            prof_version = self.server_profile.versions.key(version)
            self.compression(version, prof_version)
