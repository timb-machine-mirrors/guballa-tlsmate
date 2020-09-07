# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import os
import time
import socket
import select
import struct

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls
from tlsclient.tls_message import Alert, HandshakeMessage


class TlsConnectionState(object):

    def __init__(self):
        self.entity = tls.Entity.CLIENT
        self.master_secret = None
        client_random = ProtocolData()
        client_random.append_uint32(int(time.time()))
        client_random.extend(os.urandom(28))
        self.client_random = client_random
        self.server_random = None
        self.record_layer_version = tls.Version.TLS10

class TlsConnection(object):

    def __init__(self, tls_connection_state, logger, server, port):
        self.logger = logger
        self.tls_connection_state = tls_connection_state
        self.server = server
        self.port = port
        self.received_data = ProtocolData()

    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            self.send(Alert(level=tls.AlertLevel.FATAL, description=exc_value.description))
            self.socket.close()
            return True
        self.socket.close()
        return False

    def send(self, *messages):
        data = ProtocolData()
        for msg in messages:
            # we will skip fragmentation and compression here.
            msg_data = msg.serialize(self.tls_connection_state)
            # payload protection skip at the moment
            data.append_uint8(msg.content_type.value)
            data.append_uint16(self.tls_connection_state.record_layer_version)
            data.append_uint16(len(msg_data))
            data.extend(msg_data)
        print("Serialized: ", " ".join("{:02x}".format(x) for x in data))
        self.socket.sendall(data)


    def wait(self):
        content_type, version, fragment = self.wait_fragment()
        if content_type is tls.ContentType.HANDSHAKE:
            return HandshakeMessage.deserialize(fragment)
            #return self.deserialize_handshake_msg(length, fragment)
        elif content_type is tls.ContentType.ALERT:
            pass
        elif content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
            pass
        elif content_type is tls.ContentType.APPLICATION_DATA:
            pass

        return fragment

    def wait_fragment(self):
        while len(self.received_data) < 5:
            self.received_data.extend(self.wait_data())

        content_type, offset = self.received_data.unpack_uint8(0)
        content_type = tls.ContentType.int2enum(content_type, alert_on_failure=True)
        version, offset = self.received_data.unpack_uint16(offset)
        version = tls.Version.int2enum(version, alert_on_failure=True)
        length, offset = self.received_data.unpack_uint16(offset)

        while len(self.received_data) < (length + 5):
            self.received_data.extend(self.wait_data())
        msg = ProtocolData(self.received_data[5:5+length])
        self.received_data = ProtocolData(self.received_data[length + 5:])
        return content_type, version, msg

    def wait_data(self):
        rfds, wfds, efds = select.select([self.socket], [], [], 5)
        data = None
        if rfds:
            for fd in rfds:
                if fd is self.socket:
                    data = fd.recv(2048)
        return data

