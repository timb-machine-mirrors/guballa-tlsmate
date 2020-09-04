# -*- coding: utf-8 -*-
"""Module containing the class for the client profile
"""
import struct

class ClientProfile(object):

    def __init__(self):
        self.tls_versions = []
        self.cipher_suites = []

    def set_tls_versions(self, *versions):
        self.tls_versions = []
        for version in versions:
            self.tls_versions.append(version)

    def set_cipher_suites(self, *cipher_suites):
        self.cipher_suites = []
        for cipher_suite in cipher_suites:
            self.cipher_suites.append(cipher_suite)
