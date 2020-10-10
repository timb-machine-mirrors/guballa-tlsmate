# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import struct
import tlsclient.constants as tls
import tlsclient.structures as structs

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes, aead


class RecordLayerState(object):
    def __init__(self, param):

        self.keys = param.keys
        self.mac = param.mac
        self.cipher = param.cipher
        self.compr = param.compr
        self.enc_then_mac = param.enc_then_mac
        self.version = param.version
        self.seq_nbr = 0
        self.cipher_object = None
        self.iv = param.keys.iv
        self.is_write_state = param.is_write_state
        if self.cipher.c_type == tls.CipherType.STREAM:
            cipher = Cipher(self.cipher.algo(self.keys.enc), mode=None)
            if self.is_write_state:
                self.cipher_object = cipher.encryptor()
            else:
                self.cipher_object = cipher.decryptor()
        if self.version is tls.Version.TLS13:
            if self.cipher.primitive is tls.CipherPrimitive.AES:
                self.cipher_object = aead.AESGCM
            else:
                self.cipher_object = aead.ChaCha20Poly1305


class RecordLayer(object):
    def __init__(self, socket, recorder):
        self._send_buffer = ProtocolData()
        self._receive_buffer = ProtocolData()
        self._fragment_max_size = 4 * 4096
        self._write_state = None
        self._read_state = None
        self._socket = socket
        self._flush_each_fragment = False
        self._recorder = recorder

    def _add_to_sendbuffer(self, content_type, version, fragment):
        self._send_buffer.append_uint8(content_type.value)
        self._send_buffer.append_uint16(version.value)
        self._send_buffer.append_uint16(len(fragment))
        self._send_buffer.extend(fragment)
        if self._flush_each_fragment:
            self.flush()

    def _append_mac(self, state, content_type, version, fragment):
        mac_input = ProtocolData()
        mac_input.append_uint64(state.seq_nbr)
        mac_input.append_uint8(content_type.value)
        mac_input.append_uint16(version.value)
        mac_input.append_uint16(len(fragment))
        mac_input.extend(fragment)
        mac = hmac.HMAC(state.keys.mac, state.mac.hash_algo())
        mac.update(mac_input)
        hmac_bytes = mac.finalize()
        fragment.extend(hmac_bytes)

    def _encrypt_cbc(self, state, fragment):
        # padding
        length = len(fragment) + 1
        missing_bytes = state.cipher.block_size - (length % state.cipher.block_size)
        fragment.extend(struct.pack("!B", missing_bytes) * (missing_bytes + 1))

        if state.version <= tls.Version.TLS10:
            iv = state.iv
        else:
            # iv should be random but we want to have it reproducable
            iv = ProtocolData(state.iv[:-4])
            iv.append_uint32(state.seq_nbr)

        cipher = Cipher(state.cipher.algo(state.keys.enc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_block = encryptor.update(fragment) + encryptor.finalize()
        if state.version <= tls.Version.TLS10:
            state.iv = cipher_block[-state.cipher.iv_len :]
            return cipher_block
        else:
            return iv + cipher_block

    def _protect_block_cipher(self, state, content_type, version, fragment):
        # restrictions: only TLS1.1/1.2 supported right now (handling of iv has
        # changed), block ciphers are not applicable for TLS1.3

        if state.enc_then_mac:
            fragment = self._encrypt_cbc(state, fragment)
            fragment = ProtocolData(fragment)
            self._append_mac(state, content_type, version, fragment)
        else:
            self._append_mac(state, content_type, version, fragment)
            fragment = self._encrypt_cbc(state, fragment)
            fragment = ProtocolData(fragment)

        self._add_to_sendbuffer(content_type, version, fragment)

        state.seq_nbr += 1

    def _protect_stream_cipher(self, state, content_type, version, fragment):
        self._append_mac(state, content_type, version, fragment)
        stream_ciphered = state.cipher_object.update(fragment)
        self._add_to_sendbuffer(content_type, version, stream_ciphered)
        state.seq_nbr += 1

    def _protect_aead_cipher(self, state, content_type, version, fragment):
        aesgcm = aead.AESGCM(state.keys.enc)
        nonce_explicit = ProtocolData()
        nonce_explicit.append_uint64(state.seq_nbr)
        nonce = state.keys.iv + nonce_explicit
        aad = ProtocolData()
        aad.append_uint64(state.seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment))
        cipher_text = aesgcm.encrypt(nonce, bytes(fragment), bytes(aad))
        aead_ciphered = ProtocolData()
        aead_ciphered.extend(nonce_explicit)
        aead_ciphered.extend(cipher_text)

        self._add_to_sendbuffer(content_type, version, aead_ciphered)

        state.seq_nbr += 1

    def _protect_chacha_cipher(self, state, content_type, version, fragment):
        nonce_val = int.from_bytes(state.keys.iv, "big", signed=False) ^ state.seq_nbr
        nonce = nonce_val.to_bytes(state.cipher.iv_len, "big", signed=False)
        aad = ProtocolData()
        aad.append_uint64(state.seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment))
        chachapoly = aead.ChaCha20Poly1305(state.keys.enc)
        cipher_text = chachapoly.encrypt(nonce, bytes(fragment), bytes(aad))

        self._add_to_sendbuffer(content_type, version, cipher_text)

        state.seq_nbr += 1

    def _protect(self, content_type, version, fragment):
        wstate = self._write_state
        if wstate is None:
            # no record layer protection
            self._add_to_sendbuffer(content_type, version, fragment)
        else:
            if wstate.cipher.c_type == tls.CipherType.BLOCK:
                self._protect_block_cipher(wstate, content_type, version, fragment)
            elif wstate.cipher.c_type == tls.CipherType.STREAM:
                self._protect_stream_cipher(wstate, content_type, version, fragment)
            elif wstate.cipher.c_type == tls.CipherType.AEAD:
                if wstate.cipher.primitive == tls.CipherPrimitive.CHACHA:
                    self._protect_chacha_cipher(wstate, content_type, version, fragment)
                else:
                    self._protect_aead_cipher(wstate, content_type, version, fragment)
            else:
                raise FatalAlert(
                    "Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR
                )

    def _tls13_protect(self, state, content_type, version, fragment):
        fragment.append_uint8(content_type.value)
        aad = ProtocolData()
        aad.append_uint8(tls.ContentType.APPLICATION_DATA.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment) + 16)
        nonce_val = int.from_bytes(state.keys.iv, "big", signed=False) ^ state.seq_nbr
        nonce = nonce_val.to_bytes(state.cipher.iv_len, "big", signed=False)
        cipher = state.cipher_object(state.keys.enc)
        encoded = cipher.encrypt(nonce, bytes(fragment), bytes(aad))

        self._add_to_sendbuffer(tls.ContentType.APPLICATION_DATA, version, encoded)

        state.seq_nbr += 1

    def _compress(self, content_type, version, fragment):
        # not supported yet
        state = self._write_state
        if state is not None and state.version is tls.Version.TLS13:
            self._tls13_protect(state, content_type, version, fragment)
        else:
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
        if len(fragment) < state.mac.mac_len:
            raise FatalAlert(
                "Decoded fragment too short", tls.AlertDescription.BAD_RECORD_MAC
            )
        msg_len = len(fragment) - state.mac.mac_len
        mac_received = fragment[msg_len:]
        msg = fragment[:msg_len]
        mac_input = ProtocolData()
        mac_input.append_uint64(state.seq_nbr)
        mac_input.append_uint8(content_type.value)
        mac_input.append_uint16(version)
        mac_input.append_uint16(msg_len)
        mac_input.extend(msg)
        mac = hmac.HMAC(state.keys.mac, state.mac.hash_algo())
        mac.update(mac_input)
        mac_calculated = mac.finalize()
        if mac_calculated != mac_received:
            raise FatalAlert(
                "MAC verification failed", tls.AlertDescription.BAD_RECORD_MAC
            )
        return msg

    def _decode_cbc(self, state, fragment):
        if state.version <= tls.Version.TLS10:
            iv = state.iv
            cipher_text = fragment
            state.iv = fragment[-state.cipher.iv_len :]
        else:
            iv = fragment[: state.cipher.iv_len]
            cipher_text = fragment[state.cipher.iv_len :]
        cipher = Cipher(state.cipher.algo(state.keys.enc), modes.CBC(iv))
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

        if state.enc_then_mac:
            fragment = self._verify_mac(state, content_type, version, fragment)
            plain_text = ProtocolData(self._decode_cbc(state, fragment))
        else:
            fragment = self._decode_cbc(state, fragment)
            plain_text = self._verify_mac(state, content_type, version, fragment)

        state.seq_nbr += 1
        return ProtocolData(plain_text)

    def _unprotect_stream_cipher(self, state, content_type, version, fragment):
        fragment = state.cipher_object.update(fragment)
        clear_text = self._verify_mac(state, content_type, version, fragment)
        state.seq_nbr += 1
        return ProtocolData(clear_text)

    def _unprotect_aead_cipher(self, state, content_type, version, fragment):
        nonce_explicit = fragment[:8]
        cipher_text = bytes(fragment[8:])
        aad = ProtocolData()
        aad.append_uint64(state.seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(cipher_text) - 16)  # substract what aes_gcm adds
        nonce = bytes(state.keys.iv_value + nonce_explicit)
        aesgcm = aead.AESGCM(state.keys.enc)
        state.seq_nbr += 1
        return ProtocolData(aesgcm.decrypt(nonce, cipher_text, bytes(aad)))

    def _unprotect_chacha_cipher(self, state, content_type, version, fragment):
        nonce_val = int.from_bytes(state.keys.iv, "big", signed=False) ^ state.seq_nbr
        nonce = nonce_val.to_bytes(state.cipher.iv_len, "big", signed=False)
        aad = ProtocolData()
        aad.append_uint64(state.seq_nbr)
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment) - 16)  # substract what chacha-poly adds
        chachapoly = aead.ChaCha20Poly1305(state.keys.enc)
        state.seq_nbr += 1
        return ProtocolData(chachapoly.decrypt(nonce, bytes(fragment), bytes(aad)))

    def _tls13_unprotect(self, state, content_type, version, fragment):
        aad = ProtocolData()
        aad.append_uint8(content_type.value)
        aad.append_uint16(version.value)
        aad.append_uint16(len(fragment))
        nonce_val = int.from_bytes(state.keys.iv, "big", signed=False) ^ state.seq_nbr
        nonce = nonce_val.to_bytes(state.cipher.iv_len, "big", signed=False)
        cipher = state.cipher_object(state.keys.enc)
        decoded = cipher.decrypt(nonce, bytes(fragment), bytes(aad))
        # find idx of last non-zero octet
        idx = len(decoded) - 1
        while idx >= 0:
            if decoded[idx] != 0:
                break
            idx -= 1
        if idx < 0:
            raise FatalAlert(
                "decoded record: padding not Ok",
                tls.AlertDescription.UNEXPECTED_MESSAGE,
            )
        state.seq_nbr += 1
        return structs.MessageBlock(
            content_type=tls.ContentType.val2enum(decoded[idx], alert_on_failure=True),
            version=version,
            fragment=ProtocolData(decoded[:idx]),
        )

    def _uncompress(self, fragment):
        return fragment

    def _unprotect(self, state, content_type, version, fragment):
        if state.cipher.c_type == tls.CipherType.BLOCK:
            fragment = self._unprotect_block_cipher(
                state, content_type, version, fragment
            )
        elif state.cipher.c_type == tls.CipherType.STREAM:
            fragment = self._unprotect_stream_cipher(
                state, content_type, version, fragment
            )
        elif state.cipher.c_type == tls.CipherType.AEAD:
            if state.cipher.primitive == tls.CipherPrimitive.CHACHA:
                fragment = self._unprotect_chacha_cipher(
                    state, content_type, version, fragment
                )
            else:
                fragment = self._unprotect_aead_cipher(
                    state, content_type, version, fragment
                )
        else:
            raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)
        fragment = self._uncompress(fragment)
        return structs.MessageBlock(
            content_type=content_type, version=version, fragment=fragment
        )

    def send_message(self, message_block):
        self._fragment(message_block)

    def close_socket(self):
        self._socket.close_socket()

    def flush(self):
        self._socket.sendall(self._send_buffer)
        self._send_buffer = ProtocolData()

    def wait_fragment(self, timeout=5000):
        # wait for record layer header
        while len(self._receive_buffer) < 5:
            data = self._socket.recv_data(timeout=timeout)
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
            data = self._socket.recv_data(timeout=timeout)
            if data is None:
                # TODO: timeout
                pass
            self._receive_buffer.extend(data)

        # here we have received at least a complete record layer fragment
        fragment = ProtocolData(self._receive_buffer[5 : (length + 5)])
        self._receive_buffer = ProtocolData(self._receive_buffer[(length + 5) :])

        if (
            self._read_state is not None
            and content_type is tls.ContentType.APPLICATION_DATA
        ):
            state = self._read_state
            if state.version is tls.Version.TLS13:
                return self._tls13_unprotect(state, content_type, version, fragment)
            else:
                return self._unprotect(state, content_type, version, fragment)
        else:
            return structs.MessageBlock(
                content_type=content_type, version=version, fragment=fragment
            )

    def update_state(self, new_state):
        state = RecordLayerState(new_state)
        if state.is_write_state:
            self._write_state = state
        else:
            self._read_state = state


#    def update_write_state(self, new_state):
#        state = RecordLayerState(new_state)
#        if state.cipher.c_type == tls.CipherType.STREAM:
#            cipher = Cipher(state.cipher.algo(state.keys.enc), mode=None)
#            state.cipher_object = cipher.encryptor()
#        self._write_state_app = state
#        self._write_state_hs = state
#
#    def update_read_state(self, new_state):
#        state = RecordLayerState(new_state)
#        if state.cipher.c_type == tls.CipherType.STREAM:
#            cipher = Cipher(state.cipher.algo(state.keys.enc), mode=None)
#            state.cipher_object = cipher.decryptor()
#        self._read_state_app = state
#
#    def tls13_update_read_state_app(self, new_state):
#        self._read_state_app = RecordLayerState(new_state)
#
#    def tls13_update_read_state_hs(self, new_state):
#        self._read_state_hs = RecordLayerState(new_state)
#
#    def tls13_update_write_state_app(self, new_state):
#        self._write_state_app = RecordLayerState(new_state)
#
#    def tls13_update_write_state_hs(self, new_state):
#        self._write_state_hs = RecordLayerState(new_state)
