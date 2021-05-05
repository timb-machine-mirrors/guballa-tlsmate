# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""
# import basic stuff
import logging

# import own stuff
from tlsmate import tls
from tlsmate import structs
from tlsmate import pdu
from tlsmate.record_layer_state import RecordLayerState
from tlsmate.socket import Socket

# import other stuff


class RecordLayer(object):
    """Class implementing the record layer.
    """

    def __init__(self, tlsmate, endpoint):
        self.endpoint = endpoint
        self._tlsmate = tlsmate
        self._send_buffer = bytearray()
        self._receive_buffer = bytearray()
        self._fragment_max_size = 4 * 4096
        self._write_state = None
        self._read_state = None
        self._socket = Socket(tlsmate)
        self._flush_each_fragment = False
        self._recorder = tlsmate.recorder
        self._ssl2 = False

    def _send_fragment(self, rl_msg):
        """Protects a fragment and adds it to the send queue.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to be sent.
        """

        if self._write_state is not None:
            rl_msg = self._write_state.protect_msg(rl_msg)

        self._send_buffer.extend(pdu.pack_uint8(rl_msg.content_type.value))
        self._send_buffer.extend(pdu.pack_uint16(rl_msg.version.value))
        self._send_buffer.extend(pdu.pack_uint16(len(rl_msg.fragment)))
        self._send_buffer.extend(rl_msg.fragment)
        if self._flush_each_fragment:
            self.flush()

    def _fragment(self, rl_msg):
        """Fragments a given message according the maximum fragment size.

        Each fragment is then protected (if applicable) and added to the send queue.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The message to be sent.
        """
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

    def send_message(self, message):
        """Does everything the record layer needs to do for sending a message.

        The message is fragmented and protected (i.e. encrypted and authenticated) if
        applicable. Compression is not supported.

        Minimal support for SSL2 is provided as well (no fragmentation, no protection).

        The message may result in multiple fragments to be sent. The fragments are
        added to the send queue but actually not sent to the network yet. Use the
        flush method to do so.

        Arguments:
            message (:obj:`tlsmate.structs.RecordLayerMsg`): The message to send.
        """

        if message.content_type is tls.ContentType.SSL2:
            self._ssl2 = True
            self._send_buffer.extend(pdu.pack_uint16(len(message.fragment) | 0x8000))
            self._send_buffer.extend(message.fragment)

        else:
            self._fragment(message)

    def open_socket(self):
        """Opens the socket
        """

        self._socket.open_socket(self.endpoint)

    def close_socket(self):
        """Closes the socket. Obviously.
        """

        self._socket.close_socket()

    def flush(self):
        """Send all fragments in the send queue.

        This function is useful if e.g. multiple handshake messages shall be sent
        in one record layer message.
        """

        self._socket.sendall(self._send_buffer)
        self._send_buffer = bytearray()

    def wait_rl_msg(self, timeout=5):
        """Wait for a record layer message to be received from the network.

        Arguments:
            timeout (int): The timeout in seconds to wait for the message. This
                parameter is optional and defaults to 5 seconds.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            A complete record layer message. If a timeout occurs, None is returned.

        Raises:
            FatalAlert: If anything went wrong, e.g. message could not be
                authenticated, wrong padding, etc.
        """

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

        if self._read_state is None:
            return rl_msg

        else:
            return self._read_state.unprotect_msg(rl_msg)

    def update_state(self, new_state):
        """Update the record layer state.

        I.e. sent or received fragments are encrypted and authenticated.

        Arguments:
            new_state (:obj:`tlsmate.structs.StateUpdateParams`): A complete
                state (either a read state or a write state), containing the
                keying material for the symmetric ciphers and other relevant elements.
        """

        state = RecordLayerState(new_state)
        if new_state.is_write_state:
            self._write_state = state
            state_type = "WRITE"

        else:
            self._read_state = state
            state_type = "READ"

        logging.debug(f"switching record layer state: {state_type}")
        logging.debug(f"{state_type} enc key: {pdu.dump(state._keys.enc)}")
        if state._iv:
            logging.debug(f"{state_type} iv: {pdu.dump(state._iv)}")

        if state._keys.mac:
            logging.debug(f"{state_type} hmac key: {pdu.dump(state._keys.mac)}")
