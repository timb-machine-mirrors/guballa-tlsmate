# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.tlssuite import TlsSuite
from tlsclient.server_profile import ProfileList, ProfileEnum, ProfileBasicEnum
from tlsclient import utils


class ScanFeatures(TlsSuite):
    name = "features"
    descr = "check for basic features"
    prio = 30

    def compression(self, version, prof_version):
        prof_features = self.server_profile.get("features")
        prof_compression = prof_features.get("compression")
        if prof_compression is None:
            prof_compression = ProfileList(key_func=lambda x: x.get_enum())
            prof_features.add("compression", prof_compression)
        self.client.reset_profile()
        self.client.versions = [version]
        self.client.cipher_suites = prof_version.get("cipher_suites").all()
        groups = prof_version.get("supported_groups").get("groups").all()
        if groups:
            self.client.supported_groups = groups
            self.client.key_share = groups
        if prof_version.get("signature_algorithms") is not None:
            # TODO: optimize
            self.client.signature_algorithms = (
                prof_version.get("signature_algorithms").get("algorithms").all()
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

    def encrypt_then_mac(self):
        state = tls.SPBool.C_UNDETERMINED
        cipher_suites = []
        groups = []
        sig_algs = []
        versions = []
        for version in self.server_profile.get("versions").all():
            if version not in [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]:
                continue
            versions.append(version)
            prof_version = self.server_profile.get("versions").key(version)
            cs = prof_version.get("cipher_suites").all()
            filt_cs = utils.filter_cipher_suites(cs, cipher_type=[tls.CipherType.BLOCK])
            cipher_suites.extend(filt_cs)
            if prof_version.get("signature_algorithms") is not None:
                sig_algs.extend(
                    prof_version.get("signature_algorithms").get("algorithms").all()
                )
            groups.extend(prof_version.get("supported_groups").get("groups").all())
        if not cipher_suites:
            # no CBC cipher suite supported
            state = tls.SPBool.C_NA
        else:
            self.client.reset_profile()
            self.client.versions = versions
            self.client.cipher_suites = set(cipher_suites)
            self.client.supported_groups = groups
            self.client.signature_algorithms = sig_algs
            self.client.support_encrypt_then_mac = True
            with self.client.create_connection() as conn:
                conn.handshake()
            if conn.handshake_completed:
                if conn.msg.server_hello.get_extension(tls.Extension.ENCRYPT_THEN_MAC):
                    state = tls.SPBool.C_TRUE
                else:
                    state = tls.SPBool.C_FALSE
        prof_features = self.server_profile.get("features")
        prof_features.add("encrypt_then_mac", ProfileBasicEnum(state))

    def run(self):
        for version in self.server_profile.get("versions").all():
            prof_version = self.server_profile.get("versions").key(version)
            self.compression(version, prof_version)
        self.encrypt_then_mac()
