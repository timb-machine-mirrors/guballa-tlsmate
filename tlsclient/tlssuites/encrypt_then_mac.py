# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.tlssuite import TlsSuite
from tlsclient.server_profile import ProfileList, ProfileEnum, ProfileBasicEnum
from tlsclient import utils


class ScanEncryptThenMac(TlsSuite):
    name = "encrypt_then_mac"
    descr = "check if the extension encrypt_then_mac is supported"
    prio = 30

    def encrypt_then_mac(self):
        state = tls.SPBool.C_UNDETERMINED
        cipher_suites = []
        groups = []
        sig_algs = []
        versions = []
        for version in self.server_profile.get_versions():
            if version not in [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]:
                continue
            versions.append(version)
            cs = self.server_profile.get_cipher_suites(version)
            filt_cs = utils.filter_cipher_suites(cs, cipher_type=[tls.CipherType.BLOCK])
            cipher_suites.extend(filt_cs)
            sig_algs.extend(self.server_profile.get_signature_algorithms(version))
            groups.extend(self.server_profile.get_supported_groups(version))
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
        self.encrypt_then_mac()