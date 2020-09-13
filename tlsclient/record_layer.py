# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""

from tlsclient.protocol import ProtocolData
import collections
import struct
import os
import socket
import select
import tlsclient.constants as tls

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class RecordLayerState(object):


    def __init__(self, param):
        self._seq_nbr = 0
        #self._cipher = tls.cipher2algorithm[param.cipher]
        self._cipher_primitive = param.cipher_primitive
        self._cipher_algp = param.cipher_algo
        self._cipher_type = param.cipher_type
        self._enc_key = param.enc_key
        self._mac_key = param.mac_key
        self._mac_len = param.mac_len
        self._iv_value = param.iv_value
        self._iv_len = param.iv_len
        self._hash_algo = param.hash_algo
        self._compression_method = param.compression_method
        self._socket = None

class RecordLayer(object):


    def __init__(self, server, port, logger):
        self._send_buffer = ProtocolData()
        self._receive_buffer = ProtocolData()
        self._fragment_max_size = 4 * 4096
        self._negotiated_version = tls.Version.TLS10
        self._write_state = None
        self._read_state = None
        self.logger = logger
        self._server = server
        self._port = port
        self._socket = None
        self._flush_each_fragment = False

    def _add_to_sendbuffer(self, content_type, version, fragment):
        self._send_buffer.append_uint8(content_type.value)
        self._send_buffer.append_uint16(version.value)
        self._send_buffer.append_uint16(len(fragment))
        self._send_buffer.extend(fragment)
        if self._flush_each_fragment:
            self.flush()

    def _protect_block_cipher(self, state, content_type, version, fragment):
        # restrictions: only TLS1.2 supported right now (handling of iv has changed),
        # and encrypt_then_mac not yet supported
        # block ciphers are not applicable for TLS1.3

        # MAC
        mac_input = ProtocolData()
        mac_input.append_uint16(self._seq_nbr)
        mac_input.append_uint8(content_type)
        mac_input.append_uint16(version.value)
        mac_input.append_uint16(len(fragment))
        mac_input.extend(fragment)
        mac = hmac.HMAC(state._mac_key, state._hash_algo())
        mac.update(mac_input)
        enc_input = ProtocolData()
        enc_input.extend(fragment)
        enc_input.extend(mac.finalize())

        # padding
        length = len(enc_input) + 1
        missing_bytes = state.write_enc_block_len - (length % state._write_enc_block_len)
        enc_input.extend(struct.pack("!B", missing_bytes) * (missing_bytes + 1))

        # encryption
        iv = os.urandom(state._iv_len)
        cipher = Cipher(state.cipher_algo(state._enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(enc_input) + encryptor.finalize()

        msg = ProtocolData(iv)
        msg.append_uint16()


        self._add_to_sendbuffer(content_type, version, cipher_text)

        self._seq_nbr += 1

    def _protect(self, content_type, version, fragment):
        wstate = self._write_state
        if wstate is None:
            # no record layer protection
            self._add_to_sendbuffer(content_type, version, fragment)
        else:
            if wstate.cipher_type == tls.CipherType.BLOCK:
                self._protect_block_cipher(wstate, content_type, version, fragment)
            elif wstate.cipher_type == tls.CipherType.STREAM:
                pass
            elif wstate.cipher_type == tls.CipherType.AEAD:
                pass
            else:
                raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)


    def _compress(self, content_type, version, fragment):
        # not supported yet
        self._protect(content_type, version, fragment)

    def _fragment(self, message_block):
        message = message_block.fragment
        while (len(message) > self._fragment_max_size):
            frag = message[:self._fragment_max_size]
            message = message[self._fragment_max_size:]
            self._compress(message_block.content_type, message_block.version, frag)
        if len(message):
            self._compress(message_block.content_type, message_block.version, message)

    def _unprotect_block_cipher(self, state, content_type, version, fragment):
        # Only TLS1.2 currently supported, encrypt_then_mac not yet supported
        # decryption
        iv = fragment[:state.iv_len]
        cipher_text = fragment[state.iv_len]
        cipher = Cipher(state.cipher_algo(state.enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(ct) + decryptor.finalize()

        # padding
        pad = plain_text[-1]
        if pad + 1 > len(plain_text):
            raise FatalAlert("Wrong padding length", tls.AlertDescription.ILLEGAL_PARAMETER)
        padding = fragment[-(pad + 1):]
        plain_text = fragment[:-(pad + 1)]
        for pad_byte in padding:
            if pad_byte != pad:
                raise FatalAlert("Wrong padding bytes", tls.AlertDescription.ILLEGAL_PARAMETER)

        # MAC
        if len(plain_text) < state._mac_len:
            raise FatalAlert("Decoded fragment too short", tls.AlertDescription.BAD_RECORD_MAC)
        plain_text_len = len(plain_text) - state._mac_len
        mac_received = plain_text[plain_text_len:]
        plain_text = plain_text[:plain_text_len]
        mac_input = ProtocolData()
        mac_input.append_uint16(state._seq_nbr)
        mac_input.append_uint8(content_type.value)
        mac_input.append_uint16(version)
        mac_input.append_uint16(plain_text_len)
        mac_input.extend(plain_text)
        mac = hmac.HMAC(state.mac_key, state.hash_algo())
        mac.update(mac_input)
        mac_calculated = mac.finalize()
        if mac_calculated != mac_received:
            raise FatalAlert("MAC verification failed", tls.AlertDescription.BAD_RECORD_MAC)
        return plain_text

    def _unprotect(self, content_type, version, fragment):
        rstate = self._read_state
        if rstate is None:
            return fragment
        else:
            if rstate.cipher_type == tls.CipherType.BLOCK:
                return self._unprotect_block_cipher(rstate, content_type, version, fragment)
            elif rstate.cipher_type == tls.CipherType.STREAM:
                pass
            elif rstate.cipher_type == tls.CipherType.AEAD:
                pass
            else:
                raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)
        return None

    def _uncompress(self, fragment):
        return fragment

    def send_message(self, message_block):
        self._fragment(message_block)

    def set_negotiated_version(self, version):
        self._negotiated_version = version


    def open_socket(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._server, self._port))

    def close_socket(self):
        if self._socket:
            self._socket.close()

    def flush(self):
        if not self._socket:
            self.open_socket()
        self._socket.sendall(self._send_buffer)
        self._send_buffer = ProtocolData()

    def _read_from_socket(self):
        rfds, wfds, efds = select.select([self._socket], [], [], 5)
        data = None
        if rfds:
            for fd in rfds:
                if fd is self._socket:
                    data = fd.recv(self._fragment_max_size)
        return data

    def wait_fragment(self):
        # wait for record layer header
        while (len(self._receive_buffer) < 5):
            data = self._read_from_socket()
            if data is None:
                # TODO: timeout
                pass
            self._receive_buffer.extend(data)

        content_type, offset = self._receive_buffer.unpack_uint8(0)
        content_type = tls.ContentType.val2enum(content_type, alert_on_failure=True)
        version, offset = self._receive_buffer.unpack_uint16(offset)
        version = tls.Version.val2enum(version, alert_on_failure=True)
        length, offset = self._receive_buffer.unpack_uint16(offset)

        while len(self._receive_buffer) < (length + 5):
            data = self._read_from_socket()
            if data is None:
                # TODO: timeout
                pass
            self._receive_buffer.extend(data)

        # here we have received at least a complete record layer fragment
        fragment = ProtocolData(self._receive_buffer[5:(length + 5)])
        self._receive_buffer = ProtocolData(self._receive_buffer[(length + 5):])

        fragment = self._unprotect(content_type, version, fragment)
        fragment = self._uncompress(fragment)
        return tls.MessageBlock(content_type=content_type, version=version, fragment=fragment)

    def update_write_state(self, new_state):
        self.write_state = RecordLayerState(new_state)

    def update_read_state(self, new_state):
        self.read_state = RecordLayerState(new_state)

