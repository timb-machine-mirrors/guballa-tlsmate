# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""
from tlsclient.exception import FatalAlert
import struct
import tlsclient.constants as tls
import tlsclient.structures as structs
from tlsclient import pdu
from tlsclient.record_layer_state import RecordLayerState
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes, aead


class RecordLayer(object):
    """Class implementing the record layer.
    """

    def __init__(self, socket, recorder):
        self._send_buffer = bytearray()
        self._receive_buffer = bytearray()
        self._fragment_max_size = 4 * 4096
        self._write_state = None
        self._read_state = None
        self._socket = socket
        self._flush_each_fragment = False
        self._recorder = recorder
        self._ssl2 = False

    def _add_to_sendbuffer(self, rl_msg):
        """Adds a record layer message to the send queue.
        """
        self._send_buffer.extend(pdu.pack_uint8(rl_msg.content_type.value))
        self._send_buffer.extend(pdu.pack_uint16(rl_msg.version.value))
        self._send_buffer.extend(pdu.pack_uint16(len(rl_msg.fragment)))
        self._send_buffer.extend(rl_msg.fragment)
        if self._flush_each_fragment:
            self.flush()

    def _send_fragment(self, rl_msg):
        if self._write_state is not None:
            rl_msg = self._write_state.protect_msg(rl_msg)
        self._add_to_sendbuffer(rl_msg)

    def _fragment(self, rl_msg):
        if len(rl_msg.fragment) <= self._fragment_max_size:
            self._send_fragment(rl_msg)
            return
        message = rl_msg.fragment
        while len(message) > self._fragment_max_size:
            frag = message[: self._fragment_max_size]
            message = message[self._fragment_max_size :]
            self._send_fragment(
                structs.RecordLayerMsg(
                    content_type=rl_msg.content_type,
                    version=rl_msg.version,
                    fragment=frag,
                )
            )
        if len(message):
            self._send_fragment(
                structs.RecordLayerMsg(
                    content_type=rl_msg.content_type,
                    version=rl_msg.version,
                    fragment=message,
                )
            )


    def send_message(self, message_block):
        if message_block.content_type is tls.ContentType.SSL2:
            self._ssl2 = True
            self._send_buffer.extend(
                pdu.pack_uint16(len(message_block.fragment) | 0x8000)
            )
            self._send_buffer.extend(message_block.fragment)
        else:
            self._fragment(message_block)

    def close_socket(self):
        self._socket.close_socket()

    def flush(self):
        self._socket.sendall(self._send_buffer)
        self._send_buffer = bytearray()

    def wait_fragment(self, timeout=5000):
        # wait for record layer header
        rl_len = 2 if self._ssl2 else 5
        while len(self._receive_buffer) < rl_len:
            data = self._socket.recv_data(timeout=timeout)
            if data is None or not len(data):
                # TODO: timeout
                return None
            self._receive_buffer.extend(data)

        if self._ssl2:
            content_type = tls.ContentType.SSL2
            version = tls.Version.SSL20
            length, offset = pdu.unpack_uint16(self._receive_buffer, 0)
            if (length & 0x8000) == 0:
                length &= 0x3FFF  # don't evaluate is-escape bit
                offset += 1  # skip padding byte
                rl_len = 3
            else:
                length &= 0x7FFF
        else:
            content_type, offset = pdu.unpack_uint8(self._receive_buffer, 0)
            content_type = tls.ContentType.val2enum(content_type, alert_on_failure=True)
            version, offset = pdu.unpack_uint16(self._receive_buffer, offset)
            version = tls.Version.val2enum(version, alert_on_failure=True)
            length, offset = pdu.unpack_uint16(self._receive_buffer, offset)

        while len(self._receive_buffer) < (length + rl_len):
            data = self._socket.recv_data(timeout=timeout)
            if data is None or not len(data):
                # TODO: timeout
                return None
            self._receive_buffer.extend(data)

        # here we have received at least a complete record layer fragment
        fragment = bytes(self._receive_buffer[rl_len : (length + rl_len)])
        self._receive_buffer = self._receive_buffer[(length + rl_len) :]

        rl_msg = structs.RecordLayerMsg(
            content_type=content_type, version=version, fragment=fragment
        )

        if (
            self._read_state is None
            or content_type is tls.ContentType.CHANGE_CIPHER_SPEC
        ):
            return rl_msg
        else:
            return self._read_state.unprotect_msg(rl_msg)

    def update_state(self, new_state):
        state = RecordLayerState(new_state)
        if state.is_write_state:
            self._write_state = state
        else:
            self._read_state = state
