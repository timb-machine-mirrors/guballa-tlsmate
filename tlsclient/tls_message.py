# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import os
import time
import tlsclient.constants as tls
import tlsclient.protocol as protocol

class TlsMessage(metaclass=abc.ABCMeta):
    pass

class HandshakeMessage(TlsMessage):

    content_type = tls.ContentType.HANDSHAKE
    msg_type = None

    def serialize_msg_body(self, connection_state):
        raise NotImplementedError("class {} does not implement method serialize_msg_body".format(type(self).__name__))

    def serialize(self, tls_connection_state):
        msg_body = self.serialize_msg_body(tls_connection_state)

        handshake_msg = protocol.ProtocolData()
        handshake_msg.append_uint8(self.msg_type.value)
        handshake_msg.append_uint24(len(msg_body))
        handshake_msg.extend(msg_body)
        return handshake_msg


class ClientHello(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_HELLO


    def __init__(self):
        self.client_version = None
        self.random = None
        self.session_id = protocol.ProtocolData()
        self.cipher_suites = []
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []


    def serialize_msg_body(self, connection_state):
        msg = protocol.ProtocolData()

        # version
        if type(self.client_version) == int:
            version = self.client_version
        else:
            version = self.client_version.value
        msg.append_uint16(version)

        # random
        if self.random is None:
            self.random = connection_state.client_random
        else:
            connection_state.client_random = self.random
        msg.extend(self.random)

        # session_id
        msg.append_uint8(len(self.session_id))
        msg.extend(self.session_id)

        # cipher suites
        msg.append_uint16(2*len(self.cipher_suites))
        for cipher_suite in self.cipher_suites:
            if type(cipher_suite) == int:
                msg.append_uint16(cipher_suite)
            else:
                msg.append_uint16(cipher_suite.value)

        # compression methods
        msg.append_uint8(len(self.compression_methods))
        for comp_meth in self.compression_methods:
            if type(comp_meth) == int:
                msg.append_uint8(comp_meth)
            else:
                msg.append_uint8(comp_meth.value)

        # extensions
        ext_bytes = protocol.ProtocolData()
        for extension in self.extensions:
            ext_bytes.extend(extension.serialize())
        msg.append_uint16(len(ext_bytes))
        msg.extend(ext_bytes)

        return msg




