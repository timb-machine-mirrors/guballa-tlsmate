# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import msg
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanCompression(WorkerPlugin):
    name = "compression"
    descr = "check for compression support"
    prio = 30

    def compression(self, version):
        features = self.server_profile.features
        if not hasattr(features, "compression"):
            features.compression = []
        values = self.server_profile.get_profile_values([version])
        self.client.init_profile(profile_values=values)
        comp_methods = tls.CompressionMethod.all()

        while comp_methods:
            self.client.profile.compression_methods = comp_methods
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
