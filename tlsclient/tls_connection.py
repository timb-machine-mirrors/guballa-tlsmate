# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import os
import time
import socket
import select
import struct
import inspect
import re
import collections

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls
from tlsclient.tls_message import Alert, HandshakeMessage, ChangeCipherSpecMessage

from cryptography.hazmat.primitives import hashes, hmac

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def my_hmac(secret, msg, hash_algo):
    h = hmac.HMAC(secret, hash_algo)
    h.update(msg)
    return h.finalize()


def expand(secret, seed, size, hash_algo):
    out = b""
    ax = bytes(seed)
    while len(out) < size:
        ax = my_hmac(secret, ax, hash_algo)
        out = out + my_hmac(secret, ax + seed, hash_algo)
    return out[:size]


def prf(secret, label, seed, size, hash_algo):
    return expand(secret, label + seed, size, hash_algo)


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
        self.named_curve = None
        self.handshake_msgs = ProtocolData()
        self.version = None
        self.cipher_suite = None
        self.mac = None
        self.cipher = None
        self.key_exchange_method = None

    def set_version(self, version):
        self.version = version
        # stupid TLS1.3 RFC: let the message look like TLS1.2
        # to support not compliant middleboxes. :-(
        self.record_layer_version = min(version, tls.Version.TLS12)

    def set_server_random(self, random):
        self.server_random = random

    def get_key_exchange_method(self):
        return self.key_exchange_method

    def update_keys(self):
        self.generate_master_secret()
        self.key_deriviation()

    def update_value(self, attr_name, val):
        setattr(self, attr_name, val)

    def update_handshake_msg(self, argname, handshake_msg):
        self.handshake_msgs.extend(handshake_msg)

    def update_version(self, argname, version):
        self.version = version
        self.sec_param.version = version
        # stupid TLS1.3 RFC: let the message look like TLS1.2
        # to support not compliant middleboxes. :-(
        self.record_layer_version = min(version, tls.Version.TLS12)

    def update(self, **kwargs):
        argname2method = {
            "version": self.update_version,
            "cipher_suite": self.update_cipher_suite,
            "server_random": self.update_value,
            "client_random": self.update_value,
            "handshake_msg": self.update_handshake_msg,
        }
        for argname, val in kwargs.items():
            method = argname2method.get(argname, None)
            if method is None:
                raise ValueError(
                    'Update connection: unknown argument "{}" given'.format(argname)
                )
            method(argname, val)


class TlsConnectionMsgs(object):

    map_msg2attr = {
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
        tls.HandshakeType.MESSAGE_HASH: None,
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
            attr = self.map_msg2attr.get(msg.msg_type, None)
            if attr is not None:
                setattr(self, attr, msg)
        elif msg.content_type == tls.ContentType.CHANGE_CIPHER_SPEC:
            self.server_change_cipher_spec = msg
        elif msg.content_type == tls.ContentType.ALERT:
            self.server_alert = msg


class TlsConnection(object):
    def __init__(
        self,
        tls_connection_state,
        tls_connection_msgs,
        security_parameters,
        record_layer,
        logger,
        server,
        port,
    ):
        self.logger = logger
        self.tls_connection_state = tls_connection_state
        self.msg = tls_connection_msgs
        self.server = server
        self.port = port
        self.received_data = ProtocolData()
        self.queued_msg = None
        self.record_layer = record_layer
        self.sec_param = security_parameters
        self.record_layer_version = tls.Version.TLS10
        self._update_write_state = False
        self._msg_hash = None
        self._msg_hash_queue = None
        self._msg_hash_active = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            self.send(
                Alert(level=tls.AlertLevel.FATAL, description=exc_value.description)
            )
            self.record_layer.close_socket()
            return True
        self.record_layer.close_socket()
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
                msg = msg().init_from_profile(self.client_profile)
            msg_data = msg.serialize(self)

            self.record_layer.send_message(
                tls.MessageBlock(
                    content_type=msg.content_type,
                    version=self.record_layer_version,
                    fragment=msg_data,
                )
            )
            self._check_update_write_state()

        self.record_layer.flush()

    def wait(self, msg_class, optional=False):
        if self.queued_msg:
            msg = self.queued_msg
            self.queued_msg = None
        else:
            content_type, version, fragment = self.record_layer.wait_fragment()
            if content_type is tls.ContentType.HANDSHAKE:
                msg = HandshakeMessage.deserialize(fragment, self)
            elif content_type is tls.ContentType.ALERT:
                raise NotImplementedError("Receiving an Alert is not yet implemented")
            elif content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                msg = ChangeCipherSpecMessage.deserialize(fragment, self)
            elif content_type is tls.ContentType.APPLICATION_DATA:
                pass
            else:
                raise ValueError("Content type unknow")

        self.msg.store_received_msg(msg)

        if isinstance(msg, msg_class):
            return msg
        else:
            if optional:
                self.queued_msg = msg
                return None
            else:
                raise FatalAlert(
                    "Unexpected message received: {}, expected: {}".format(
                        type(msg), msg_class
                    ),
                    tls.AlertDescription.UNEXPECTED_MESSAGE,
                )

    def wait_fragment(self):
        while len(self.received_data) < 5:
            self.received_data.extend(self.wait_data())

        content_type, offset = self.received_data.unpack_uint8(0)
        content_type = tls.ContentType.val2enum(content_type, alert_on_failure=True)
        version, offset = self.received_data.unpack_uint16(offset)
        version = tls.Version.val2enum(version, alert_on_failure=True)
        length, offset = self.received_data.unpack_uint16(offset)

        while len(self.received_data) < (length + 5):
            self.received_data.extend(self.wait_data())
        msg = ProtocolData(self.received_data[5 : 5 + length])
        self.received_data = ProtocolData(self.received_data[length + 5 :])
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

    def update_keys(self):
        self.sec_param.generate_master_secret()
        self.sec_param.key_deriviation()

    def update(self, **kwargs):
        for argname, val in kwargs.items():
            if argname == "version":
                self.version = val
                self.sec_param.version = val
                # stupid TLS1.3 RFC: let the message look like TLS1.2
                # to support not compliant middleboxes. :-(
                self.record_layer_version = min(val, tls.Version.TLS12)
            elif argname == "cipher_suite":
                self.sec_param.update_cipher_suite(val)
            elif argname == "server_random":
                self.sec_param.server_random = val
            elif argname == "client_random":
                self.sec_param.client_random = val
            elif argname == "named_curve":
                self.sec_param.named_curve = val
            elif argname == "remote_public_key":
                self.sec_param.remote_public_key = val
            else:
                raise ValueError(
                    'Update connection: unknown argument "{}" given'.format(argname)
                )

    def _check_update_write_state(self):
        if self._update_write_state:
            state = self.sec_param.get_pending_write_state(self.sec_param.entity)
            self.record_layer.update_write_state(state)
            self._update_write_state = False

    def update_write_state(self):
        self._update_write_state = True

    def update_read_state(self):
        if self.sec_param.entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER
        else:
            entity = tls.Entity.CLIENT
        state = self.sec_param.get_pending_write_state(entity)
        self.record_layer.update_read_state(state)

    def init_msg_hash(self):
        self._msg_hash_queue = ProtocolData()
        self._msg_hash = None
        self._msg_hash_active = True

        self._debug = []

    def update_msg_hash(self, msg):
        self._debug.append(msg)
        if not self._msg_hash_active:
            return
        if self.sec_param.hash_algo is None:
            # cipher suite not yet negotiated, no hash algo available yet
            self._msg_hash_queue.extend(msg)
        else:
            if self._msg_hash is None:
                self._msg_hash = hashes.Hash(self.sec_param.hash_algo())
                self._msg_hash.update(self._msg_hash_queue)
                self._msg_hash_queue = None
            self._msg_hash.update(msg)

    def finalize_msg_hash(self, intermediate=False):
        if intermediate:
            hash_tmp = self._msg_hash.copy()
            return hash_tmp.finalize()
        val = self._msg_hash.finalize()
        self._msg_hash_active = False
        self._msg_hash = None
        self._msg_hash_queue = None
        return val
