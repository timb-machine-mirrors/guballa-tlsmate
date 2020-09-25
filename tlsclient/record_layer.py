# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import struct
import tlsclient.constants as tls

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes, aead


class RecordLayerState(object):
    def __init__(self, param):
        self._seq_nbr = 0
        # self._cipher = tls.cipher2algorithm[param.cipher]
        self._cipher_primitive = param.cipher_primitive
        self._cipher_algo = param.cipher_algo
        self._cipher_type = param.cipher_type
        self._block_size = param.block_size
        self._enc_key = param.enc_key
        self._mac_key = param.mac_key
        self._mac_len = param.mac_len
        self._iv_value = param.iv_value
        self._iv_len = param.iv_len
        self._hash_algo = param.hash_algo
        self._compression_method = param.compression_method
        self._encrypt_then_mac = param.encrypt_then_mac
        self._socket = None


class RecordLayer(object):
    def __init__(self, socket, recorder):
        self._send_buffer = ProtocolData()
        self._receive_buffer = ProtocolData()
        self._fragment_max_size = 4 * 4096
        self._negotiated_version = tls.Version.TLS10
        self._write_state = None
        self._read_state = None
        self._socket = socket
        self._flush_each_fragment = False
        self._recorder = recorder

    def set_recorder(self, recorder):
        self._recorder = recorder
        self._socket.set_recorder(recorder)

    def _add_to_sendbuffer(self, content_type, version, fragment):
        self._send_buffer.append_uint8(content_type.value)
        self._send_buffer.append_uint16(version.value)
        self._send_buffer.append_uint16(len(fragment))
        self._send_buffer.extend(fragment)
        if self._flush_each_fragment:
            self.flush()

    def _append_mac(self, state, content_type, version, fragment):
        mac_input = ProtocolData()
        mac_input.append_uint64(state._seq_nbr)
        mac_input.append_uint8(content_type.value)
        mac_input.append_uint16(version.value)
        mac_input.append_uint16(len(fragment))
        mac_input.extend(fragment)
        mac = hmac.HMAC(state._mac_key, state._hash_algo())
        mac.update(mac_input)
        hmac_bytes = mac.finalize()
        fragment.extend(hmac_bytes)

    def _encrypt_cbc(self, state, iv, fragment):
        # padding
        length = len(fragment) + 1
        missing_bytes = state._block_size - (length % state._block_size)
        fragment.extend(struct.pack("!B", missing_bytes) * (missing_bytes + 1))

        cipher = Cipher(state._cipher_algo(state._enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(fragment) + encryptor.finalize()

    def _protect_block_cipher(self, state, content_type, version, fragment):
        # restrictions: only TLS1.2 supported right now (handling of iv has changed),
        # block ciphers are not applicable for TLS1.3

        # iv should be random but we want to have it reproducable
        iv = ProtocolData(state._iv_value[:-4])
        iv.append_uint32(state._seq_nbr)

        if state._encrypt_then_mac:
            fragment = self._encrypt_cbc(state, iv, fragment)
            fragment = ProtocolData(iv + fragment)
            self._append_mac(state, content_type, version, fragment)
        else:
            self._append_mac(state, content_type, version, fragment)
            fragment = self._encrypt_cbc(state, iv, fragment)
            fragment = ProtocolData(iv + fragment)

        self._add_to_sendbuffer(content_type, version, fragment)

        state._seq_nbr += 1
        return

    def _protect_aead_cipher(self, state, content_type, version, fragment):
        aesgcm = aead.AESGCM(state._enc_key)
        nonce_explicit = ProtocolData()
        nonce_explicit.append_uint64(state._seq_nbr)
        nonce = state._iv_value + nonce_explicit
        aad = ProtocolData()
        aad.append_uint64(state._seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment))
        cipher_text = aesgcm.encrypt(nonce, bytes(fragment), bytes(aad))
        aead_ciphered = ProtocolData()
        aead_ciphered.extend(nonce_explicit)
        aead_ciphered.extend(cipher_text)

        self._add_to_sendbuffer(content_type, version, aead_ciphered)

        state._seq_nbr += 1

    def _protect_chacha_cipher(self, state, content_type, version, fragment):
        nonce_val = (
            int.from_bytes(state._iv_value, "big", signed=False) ^ state._seq_nbr
        )
        nonce = nonce_val.to_bytes(state._iv_len, "big", signed=False)
        aad = ProtocolData()
        aad.append_uint64(state._seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment))
        chachapoly = aead.ChaCha20Poly1305(state._enc_key)
        cipher_text = chachapoly.encrypt(nonce, bytes(fragment), bytes(aad))

        self._add_to_sendbuffer(content_type, version, cipher_text)

        state._seq_nbr += 1

    def _protect(self, content_type, version, fragment):
        wstate = self._write_state
        if wstate is None:
            # no record layer protection
            self._add_to_sendbuffer(content_type, version, fragment)
        else:
            if wstate._cipher_type == tls.CipherType.BLOCK:
                self._protect_block_cipher(wstate, content_type, version, fragment)
            elif wstate._cipher_type == tls.CipherType.STREAM:
                pass
            elif wstate._cipher_type == tls.CipherType.AEAD:
                if wstate._cipher_primitive == tls.CipherPrimitive.CHACHA:
                    self._protect_chacha_cipher(wstate, content_type, version, fragment)
                else:
                    self._protect_aead_cipher(wstate, content_type, version, fragment)
            else:
                raise FatalAlert(
                    "Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR
                )

    def _compress(self, content_type, version, fragment):
        # not supported yet
        self._protect(content_type, version, fragment)

    def _fragment(self, message_block):
        message = message_block.fragment
        while len(message) > self._fragment_max_size:
            frag = message[: self._fragment_max_size]
            message = message[self._fragment_max_size :]
            self._compress(message_block.content_type, message_block.version, frag)
        if len(message):
            self._compress(message_block.content_type, message_block.version, message)

    def _verify_mac(self, state, content_type, version, fragment):
        if len(fragment) < state._mac_len:
            raise FatalAlert(
                "Decoded fragment too short", tls.AlertDescription.BAD_RECORD_MAC
            )
        msg_len = len(fragment) - state._mac_len
        mac_received = fragment[msg_len:]
        msg = fragment[:msg_len]
        mac_input = ProtocolData()
        mac_input.append_uint64(state._seq_nbr)
        mac_input.append_uint8(content_type.value)
        mac_input.append_uint16(version)
        mac_input.append_uint16(msg_len)
        mac_input.extend(msg)
        mac = hmac.HMAC(state._mac_key, state._hash_algo())
        mac.update(mac_input)
        mac_calculated = mac.finalize()
        if mac_calculated != mac_received:
            raise FatalAlert(
                "MAC verification failed", tls.AlertDescription.BAD_RECORD_MAC
            )
        return msg

    def _decode_cbc(self, state, fragment):
        iv = fragment[: state._iv_len]
        cipher_text = fragment[state._iv_len :]
        cipher = Cipher(state._cipher_algo(state._enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        # padding
        pad = plain_text[-1]
        pad_start = len(plain_text) - pad - 1
        if pad_start < 0:
            raise FatalAlert(
                "Wrong padding length", tls.AlertDescription.BAD_RECORD_MAC
            )
        padding = plain_text[pad_start:]
        plain_text = plain_text[:pad_start]
        if (struct.pack("!B", pad) * (pad + 1)) != padding:
            raise FatalAlert("Wrong padding bytes", tls.AlertDescription.BAD_RECORD_MAC)
        return plain_text

    def _unprotect_block_cipher(self, state, content_type, version, fragment):
        # Only TLS1.2 currently supported

        if state._encrypt_then_mac:
            fragment = self._verify_mac(state, content_type, version, fragment)
            plain_text = ProtocolData(self._decode_cbc(state, fragment))
        else:
            fragment = self._decode_cbc(state, fragment)
            plain_text = self._verify_mac(state, content_type, version, fragment)

        state._seq_nbr += 1
        return ProtocolData(plain_text)

    def _unprotect_aead_cipher(self, state, content_type, version, fragment):
        nonce_explicit = fragment[:8]
        cipher_text = bytes(fragment[8:])
        aad = ProtocolData()
        aad.append_uint64(state._seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(cipher_text) - 16)  # substract what aes_gcm adds
        nonce = bytes(state._iv_value + nonce_explicit)
        aesgcm = aead.AESGCM(state._enc_key)
        state._seq_nbr += 1
        return ProtocolData(aesgcm.decrypt(nonce, cipher_text, bytes(aad)))

    def _unprotect_chacha_cipher(self, state, content_type, version, fragment):
        nonce_val = (
            int.from_bytes(state._iv_value, "big", signed=False) ^ state._seq_nbr
        )
        nonce = nonce_val.to_bytes(state._iv_len, "big", signed=False)
        aad = ProtocolData()
        aad.append_uint64(state._seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment) - 16)  # substract what chacha-poly adds
        chachapoly = aead.ChaCha20Poly1305(state._enc_key)
        state._seq_nbr += 1
        return ProtocolData(chachapoly.decrypt(nonce, bytes(fragment), bytes(aad)))

    def _unprotect(self, content_type, version, fragment):
        rstate = self._read_state
        if rstate is None:
            return fragment
        else:
            if rstate._cipher_type == tls.CipherType.BLOCK:
                return self._unprotect_block_cipher(
                    rstate, content_type, version, fragment
                )
            elif rstate._cipher_type == tls.CipherType.STREAM:
                pass
            elif rstate._cipher_type == tls.CipherType.AEAD:
                if rstate._cipher_primitive == tls.CipherPrimitive.CHACHA:
                    return self._unprotect_chacha_cipher(
                        rstate, content_type, version, fragment
                    )
                else:
                    return self._unprotect_aead_cipher(
                        rstate, content_type, version, fragment
                    )
            else:
                raise FatalAlert(
                    "Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR
                )
        return None

    def _uncompress(self, fragment):
        return fragment

    def send_message(self, message_block):
        self._fragment(message_block)

    def set_negotiated_version(self, version):
        self._negotiated_version = version

    def close_socket(self):
        self._socket.close_socket()

    def flush(self):
        self._socket.sendall(self._send_buffer)
        self._send_buffer = ProtocolData()

    def wait_fragment(self):
        # wait for record layer header
        while len(self._receive_buffer) < 5:
            data = self._socket.recv_data()
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
            data = self._socket.recv_data()
            if data is None:
                # TODO: timeout
                pass
            self._receive_buffer.extend(data)

        # here we have received at least a complete record layer fragment
        fragment = ProtocolData(self._receive_buffer[5 : (length + 5)])
        self._receive_buffer = ProtocolData(self._receive_buffer[(length + 5) :])

        fragment = self._unprotect(content_type, version, fragment)
        fragment = self._uncompress(fragment)
        return tls.MessageBlock(
            content_type=content_type, version=version, fragment=fragment
        )

    def update_write_state(self, new_state):
        self._write_state = RecordLayerState(new_state)

    def update_read_state(self, new_state):
        self._read_state = RecordLayerState(new_state)
