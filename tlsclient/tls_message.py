# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import os
import time
import tlsclient.constants as tls
import tlsclient.protocol as protocol
from tlsclient.extensions import Extension

class TlsMessage(metaclass=abc.ABCMeta):
    pass


class HandshakeMessage(TlsMessage):

    content_type = tls.ContentType.HANDSHAKE
    msg_type = None

    @classmethod
    def deserialize(cls, fragment):
        msg_type, offset = fragment.unpack_uint8(0)
        msg_type = tls.HandshakeType.int2enum(msg_type, alert_on_failure=True)
        length, offset = fragment.unpack_uint24(offset)
        if length + offset != len(fragment):
            raise FatalAlert(
                "Length of {} incorrect".format(msg_type),
                tls.AlertDescription.DECODE_ERROR,
            )
        cls_name = deserialization_map[msg_type]
        return cls_name().deserialize_msg_body(fragment, offset)

        msg_type, fragment = fragment.unshift_uint8()
        msg_type = tls.HandshakeType.int2enum(msg_type, alert_on_failure=True)
        length, msg_body = fragment.unshift_uint24()
        if length != len(msg_body):
            raise FatalAlert(
                "Length of {} incorrect".format(msg_type),
                tls.AlertDescription.DECODE_ERROR,
            )
        cls_name = deserialization_map[msg_type]
        return cls_name().deserialize_msg_body(msg_body, length)

    def deserialize_msg_body(self, msg_body, length):
        raise NotImplementedError(
            "class {} does not implement method deserialize_msg_body".format(
                type(self).__name__
            )
        )

    def serialize_msg_body(self, connection_state):
        raise NotImplementedError(
            "class {} does not implement method serialize_msg_body".format(
                type(self).__name__
            )
        )

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
        msg.append_uint16(2 * len(self.cipher_suites))
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

    def deserialize_msg_body(self, msg_body, length):
        return self


class ServerHello(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO

    def deserialize_msg_body(self, fragment, offset):

        version, offset = fragment.unpack_uint16(offset)
        self.version = tls.Version.int2enum(version, alert_on_failure=True)
        self.random, offset = fragment.unpack_bytes(offset, 32)
        session_id_len, offset = fragment.unpack_uint8(offset)
        self.session_id, offset = fragment.unpack_bytes(offset, session_id_len)
        cipher_suite, offset = fragment.unpack_uint16(offset)
        self.cipher_suite = tls.CipherSuite.int2enum(
            cipher_suite, alert_on_failure=True
        )
        compression_method, offset = fragment.unpack_uint8(offset)
        self.compression_method = tls.CompressionMethod.int2enum(
            compression_method, alert_on_failure=True
        )
        self.extensions = []
        if offset < len(fragment):
            # extensions present
            ext_length, offset = fragment.unpack_uint16(offset)
            while offset < len(fragment):
                ext_id, offset = fragment.unpack_uint16(offset)
                ext_id = tls.Extension.int2enum(ext_id, alert_on_failure=True)
                ext_length, offset = fragment.unpack_uint16(offset)
                ext_body, offset = fragment.unpack_bytes(offset, ext_length)
                self.extensions.append(Extension.deserialize(ext_id, ext_body))
                # TODO: deserialize extension
        return self


class Alert(TlsMessage):

    content_type = tls.ContentType.ALERT

    def __init__(self, **kwargs):
        self.level = kwargs.get("level", tls.AlertLevel.FATAL)
        self.description = kwargs.get(
            "description", tls.AlertDescription.HANDSHAKE_FAILURE
        )

    def serialize(self, tls_connection_state):
        alert = protocol.ProtocolData()
        if self.level == int:
            alert.append_uint8(self.level)
        else:
            alert.append_uint8(self.level.value)
        if self.description == int:
            alert.append_uint8(self.description)
        else:
            alert.append_uint8(self.description.value)
        return alert


deserialization_map = {
    tls.HandshakeType.CLIENT_HELLO: ClientHello,
    tls.HandshakeType.SERVER_HELLO: ServerHello,
    # tls.HandshakeType.NEW_SESSION_TICKET = 4
    # tls.HandshakeType.END_OF_EARLY_DATA = 5
    # tls.HandshakeType.ENCRYPTED_EXTENSIONS = 8
    # tls.HandshakeType.CERTIFICATE = 11
    # tls.HandshakeType.CERTIFICATE_REQUEST = 13
    # tls.HandshakeType.CERTIFICATE_VERIFY = 15
    # tls.HandshakeType.FINISHED = 20
    # tls.HandshakeType.KEY_UPDATE = 24
    # tls.HandshakeType.COMPRESSED_CERTIFICATE = 25
    # tls.HandshakeType.EKT_KEY = 26
    # tls.HandshakeType.MESSAGE_HASH = 254
}
