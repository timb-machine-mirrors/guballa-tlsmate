# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import protocol
import os
import time

class TlsMessage(metaclass=abc.ABCMeta):
    pass

class ClientHello(TlsMessage):

    def __init__(self):
        self.client_version = None
        self.random = None
        self.session_id = protocol.ProtocolData()
        self.cipher_suites = []
        self.compression_methods = []
        self.extensions = []


    def serialize(self):
        msg = protocol.ProtocolData()

        # version
        if type(self.client_version) == int:
            version = self.client_version
        else
            version = self.client_version.value
        msg.append_uint2(version)

        # random
        if self.random is None:
            msg.append_uint4(int(time.time))
            msg.extend(os.urandom(28))
        else
            msg.extend(self.random)

        # session_id
        msg.append_uint1(len(self.session_id))
        msg.extend(self.session_id)

        # cipher suites
        msg.append_uint2(2*len(self.cipher_suites))
        for cipher_suite in self.cipher_suites:
            if type(cipher_suites) == int:
                msg.append_uint2(cipher_suite)
            else:
                msg.append_uint2(cipher_suite.value)

        # compression methods
        msg.append_uint1(len(self.compression_methods))
        for comp_meth in self.compression_methods:
            if type(comp_meth) == int:
                msg.append_uint1(comp_meth)
            else:
                msg.append_uint1(comp_meth.value)

        # extensions
        ext_bytes = ProtocolData()
        for extension in self.extensions:
            ext_bytes.extend(extension.serialize)
        msg.append_uint2(len(ext_bytes))
        msg.extend(ext_bytes)

        return msg




