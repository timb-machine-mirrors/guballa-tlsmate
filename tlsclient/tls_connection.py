# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import os
import time
import socket
import select
import struct
import inspect

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls
from tlsclient.tls_message import Alert, HandshakeMessage


class TlsConnectionState(object):

    cipher_suite2key_exchange = {
        "TLS_DHE_DSS_": tls.KeyExchangeAlgorithm.DHE_DSS,
        "TLS_DHE_RSA_": tls.KeyExchangeAlgorithm.DHE_RSA,
        "TLS_DH_ANON_": tls.KeyExchangeAlgorithm.DH_ANON,
        "TLS_RSA_": tls.KeyExchangeAlgorithm.RSA,
        "TLS_DH_DSS_": tls.KeyExchangeAlgorithm.DH_DSS,
        "TLS_DH_RSA_": tls.KeyExchangeAlgorithm.DH_RSA,
        "TLS_ECDH_ECDSA_": tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
        "TLS_ECDHE_ECDSA_": tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
        "TLS_ECDH_RSA_": tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
        "TLS_ECDHE_RSA_": tls.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    }

    def __init__(self):
        self.entity = tls.Entity.CLIENT
        self.master_secret = None
        client_random = ProtocolData()
        client_random.append_uint32(int(time.time()))
        client_random.extend(os.urandom(28))
        self.client_random = client_random
        self.server_random = None
        self.record_layer_version = tls.Version.TLS10

    def set_version(self, version):
        self.version = version
        # stupid TLS1.3 RFC: let the message look like TLS1.2
        # to support not compliant middleboxes. :-(
        self.record_layer_version = min(version, tls.Version.TLS12)

    def set_server_random(self, random):
        self.server_random = random

    def set_cipher_suite(self, cipher_suite):
        self.cipher_suite = cipher_suite
        for key, val in self.cipher_suite2key_exchange.items():
            if cipher_suite.name.startswith(key):
                self.key_exchange_method = val
                break

class TlsConnectionMsgs(object):

    map_mag2attr = {
        tls.HandshakeType.HELLO_REQUEST: None,
        tls.HandshakeType.CLIENT_HELLO: None,
        tls.HandshakeType.SERVER_HELLO: "server_hello",
        tls.HandshakeType.NEW_SESSION_TICKET: None,
        tls.HandshakeType.END_OF_EARLY_DATA: None,
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: None,
        tls.HandshakeType.CERTIFICATE: "server_certificate",
        tls.HandshakeType.SERVER_KEY_EXCHANGE: "server_key_exchange",
        tls.HandshakeType.CERTIFICATE_REQUEST: None,
        tls.HandshakeType.SERVER_HELLO_DONE: "server_hello_done",
        tls.HandshakeType.CERTIFICATE_VERIFY: None,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: None,
        tls.HandshakeType.FINISHED: "server_finished",
        tls.HandshakeType.KEY_UPDATE: None,
        tls.HandshakeType.COMPRESSED_CERTIFICATE: None,
        tls.HandshakeType.EKT_KEY: None,
        tls.HandshakeType.MESSAGE_HASH: None
    }

    def __init__(self):
        self.client_hello = None
        self.server_hello = None
        self.server_certificate = None
        self.server_key_exchange = None
        self.server_hello_done = None
        self.client_certificate = None
        self.client_key_exchange = None
        self.client_change_cipher_spec = None
        self.client_finished = None
        self.server_change_cipher_spec = None
        self.server_finished = None
        self.client_alert = None
        self.server_alert = None

    def store_received_msg(self, msg):
        if msg.content_type == tls.ContentType.HANDSHAKE:
            attr = self.map_mag2attr.get(msg.msg_type, None)
            if attr is not None:
                setattr(self, attr, msg)
        elif msg.content_type == tls.ContentType.CHANGE_CIPHER_SPEC:
            self.server_change_cipher_spec = msg
        elif msg.content_type == tls.ContentType.ALERT:
            self.server_alert = msg


class TlsConnection(object):

    def __init__(self, tls_connection_state, tls_connection_msgs, logger, server, port):
        self.logger = logger
        self.tls_connection_state = tls_connection_state
        self.msg = tls_connection_msgs
        self.server = server
        self.port = port
        self.received_data = ProtocolData()
        self.queued_msg = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            self.send(Alert(level=tls.AlertLevel.FATAL, description=exc_value.description))
            self.socket.close()
            return True
        self.socket.close()
        return False

    def set_profile(self, client_profile):
        self.client_profile = client_profile
        return self

    def open_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))


    def send(self, *messages):
        data = ProtocolData()
        for msg in messages:
            if inspect.isclass(msg):
                msg = msg().from_profile(self.client_profile)
            # we will skip fragmentation and compression here.
            msg_data = msg.serialize(self.tls_connection_state)
            # payload protection skip at the moment
            data.append_uint8(msg.content_type.value)
            data.append_uint16(self.tls_connection_state.record_layer_version)
            data.append_uint16(len(msg_data))
            data.extend(msg_data)
        print("Serialized: ", " ".join("{:02x}".format(x) for x in data))
        self.socket.sendall(data)


    def wait(self, msg_class, optional=False):
        if self.queued_msg:
            msg = self.queued_msg
            self.queued_msg = None
        else:
            content_type, version, fragment = self.wait_fragment()
            if content_type is tls.ContentType.HANDSHAKE:
                msg = HandshakeMessage.deserialize(fragment, self.tls_connection_state)
            elif content_type is tls.ContentType.ALERT:
                pass
            elif content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                pass
            elif content_type is tls.ContentType.APPLICATION_DATA:
                pass

        self.msg.store_received_msg(msg)

        if isinstance(msg, msg_class):
            return msg
        else:
            if optional:
                self.queued_msg = msg
                return None
            else:
                raise FatalAlert("Unexpected message received: {}, expected: {}".format(type(msg), msg_class), tls.AlertDescription.UNEXPECTED_MESSAGE)

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

    def wait_server_hello_done(self):
        while True:
            self.wait()
