# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import os
import time
import socket
import select

from tlsclient.protocol import ProtocolData
import tlsclient.constants as tls

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

    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
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

