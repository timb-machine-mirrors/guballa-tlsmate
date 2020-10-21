# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""
import struct
from tlsclient import pdu
import tlsclient.constants as tls
import tlsclient.structures as structs
from tlsclient.exception import FatalAlert
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes, aead


class RecordLayerState(object):
    """Class to represent an dynamic record layer state
    """

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

    def _encrypt_cbc(self, fragment):
        # padding
        length = len(fragment) + 1
        missing_bytes = self.cipher.block_size - (length % self.cipher.block_size)
        fragment += struct.pack("!B", missing_bytes) * (missing_bytes + 1)

        if self.version <= tls.Version.TLS10:
            iv = self.iv
        else:
            # iv should be random but we want to have it reproducable
            iv = self.iv[:-4] + pdu.pack_uint32(self.seq_nbr)

        cipher = Cipher(self.cipher.algo(self.keys.enc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_block = encryptor.update(fragment) + encryptor.finalize()
        if self.version <= tls.Version.TLS10:
            self.iv = cipher_block[-self.cipher.iv_len :]
            return cipher_block
        else:
            return iv + cipher_block

    def _append_mac(self, content_type, version, fragment):
        mac_input = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(content_type.value)
            + pdu.pack_uint16(version.value)
            + pdu.pack_uint16(len(fragment))
            + fragment
        )
        mac = hmac.HMAC(self.keys.mac, self.mac.hash_algo())
        mac.update(mac_input)
        return fragment + mac.finalize()

    def _protect_block_cipher(self, rl_msg):
        if self.enc_then_mac:
            fragment = self._encrypt_cbc(rl_msg.fragment)
            fragment = self._append_mac(rl_msg.content_type, rl_msg.version, fragment)
        else:
            fragment = self._append_mac(
                rl_msg.content_type, rl_msg.version, rl_msg.fragment
            )
            fragment = self._encrypt_cbc(fragment)

        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type, version=rl_msg.version, fragment=fragment
        )

    def _protect_stream_cipher(self, rl_msg):
        fragment = self._append_mac(
            rl_msg.content_type, rl_msg.version, rl_msg.fragment
        )
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=self.cipher_object.update(fragment),
        )

    def _protect_chacha_cipher(self, rl_msg):
        nonce_val = int.from_bytes(self.keys.iv, "big", signed=False) ^ self.seq_nbr
        nonce = nonce_val.to_bytes(self.cipher.iv_len, "big", signed=False)
        aad = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        chachapoly = aead.ChaCha20Poly1305(self.keys.enc)
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=chachapoly.encrypt(nonce, rl_msg.fragment, aad),
        )

    def _protect_aead_cipher(self, rl_msg):
        kwargs = {}
        if self.cipher.aead_expansion != 16:
            kwargs["tag_length"] = self.cipher.aead_expansion
        aes_aead = self.cipher.algo(self.keys.enc, **kwargs)
        nonce_explicit = pdu.pack_uint64(self.seq_nbr)
        nonce = self.keys.iv + nonce_explicit
        aad = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=nonce_explicit + aes_aead.encrypt(nonce, rl_msg.fragment, aad),
        )

    def _protect(self, rl_msg):
        if self.cipher.c_type == tls.CipherType.BLOCK:
            return self._protect_block_cipher(rl_msg)
        elif self.cipher.c_type == tls.CipherType.STREAM:
            return self._protect_stream_cipher(rl_msg)
        elif self.cipher.c_type == tls.CipherType.AEAD:
            if self.cipher.primitive == tls.CipherPrimitive.CHACHA:
                return self._protect_chacha_cipher(rl_msg)
            else:
                return self._protect_aead_cipher(rl_msg)
        else:
            raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)

    def _tls13_protect(self, rl_msg):
        fragment = bytes(rl_msg.fragment) + pdu.pack_uint8(rl_msg.content_type.value)
        aad = (
            pdu.pack_uint8(tls.ContentType.APPLICATION_DATA.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(fragment) + 16)
        )
        nonce_val = int.from_bytes(self.keys.iv, "big", signed=False) ^ self.seq_nbr
        nonce = nonce_val.to_bytes(self.cipher.iv_len, "big", signed=False)
        cipher = self.cipher_object(self.keys.enc)
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=tls.ContentType.APPLICATION_DATA,
            version=rl_msg.version,
            fragment=cipher.encrypt(nonce, fragment, aad),
        )

    def protect_msg(self, rl_msg):
        if self.version is tls.Version.TLS13:
            return self._tls13_protect(rl_msg)
        else:
            # Skip compression, we don't want to support it.
            return self._protect(rl_msg)

    def _verify_mac(self, content_type, version, fragment):
        if len(fragment) < self.mac.mac_len:
            raise FatalAlert(
                "Decoded fragment too short", tls.AlertDescription.BAD_RECORD_MAC
            )
        msg_len = len(fragment) - self.mac.mac_len
        mac_received = fragment[msg_len:]
        msg = fragment[:msg_len]
        mac_input = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(content_type.value)
            + pdu.pack_uint16(version)
            + pdu.pack_uint16(msg_len)
            + msg
        )
        mac = hmac.HMAC(self.keys.mac, self.mac.hash_algo())
        mac.update(mac_input)
        mac_calculated = mac.finalize()
        if mac_calculated != mac_received:
            raise FatalAlert(
                "MAC verification failed", tls.AlertDescription.BAD_RECORD_MAC
            )
        return msg

    def _decode_cbc(self, fragment):
        if self.version <= tls.Version.TLS10:
            iv = self.iv
            cipher_text = fragment
            self.iv = fragment[-self.cipher.iv_len :]
        else:
            iv = fragment[: self.cipher.iv_len]
            cipher_text = fragment[self.cipher.iv_len :]
        cipher = Cipher(self.cipher.algo(self.keys.enc), modes.CBC(iv))
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

    def _unprotect_block_cipher(self, rl_msg):
        if self.enc_then_mac:
            fragment = self._verify_mac(
                rl_msg.content_type, rl_msg.version, rl_msg.fragment
            )
            plain_text = self._decode_cbc(fragment)
        else:
            fragment = self._decode_cbc(rl_msg.fragment)
            plain_text = self._verify_mac(rl_msg.content_type, rl_msg.version, fragment)

        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=plain_text,
        )

    def _unprotect_stream_cipher(self, rl_msg):
        fragment = self.cipher_object.update(rl_msg.fragment)
        clear_text = self._verify_mac(rl_msg.content_type, rl_msg.version, fragment)
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=clear_text,
        )

    def _unprotect_chacha_cipher(self, rl_msg):
        nonce_val = int.from_bytes(self.keys.iv, "big", signed=False) ^ self.seq_nbr
        nonce = nonce_val.to_bytes(self.cipher.iv_len, "big", signed=False)
        aad = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment) - self.cipher.aead_expansion)
        )
        chachapoly = aead.ChaCha20Poly1305(self.keys.enc)
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=chachapoly.decrypt(nonce, rl_msg.fragment, aad),
        )

    def _unprotect_aead_cipher(self, rl_msg):
        nonce_explicit = rl_msg.fragment[:8]
        cipher_text = rl_msg.fragment[8:]
        aad = (
            pdu.pack_uint64(self.seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(cipher_text) - self.cipher.aead_expansion)
        )
        nonce = bytes(self.keys.iv + nonce_explicit)
        kwargs = {}
        if self.cipher.aead_expansion != 16:
            kwargs["tag_length"] = self.cipher.aead_expansion
        aes_aead = self.cipher.algo(self.keys.enc, **kwargs)
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=aes_aead.decrypt(nonce, cipher_text, aad),
        )

    def _unprotect(self, rl_msg):
        if self.cipher.c_type == tls.CipherType.BLOCK:
            return self._unprotect_block_cipher(rl_msg)
        elif self.cipher.c_type == tls.CipherType.STREAM:
            return self._unprotect_stream_cipher(rl_msg)
        elif self.cipher.c_type == tls.CipherType.AEAD:
            if self.cipher.primitive == tls.CipherPrimitive.CHACHA:
                return self._unprotect_chacha_cipher(rl_msg)
            else:
                return self._unprotect_aead_cipher(rl_msg)
        else:
            raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)

    def _tls13_unprotect(self, rl_msg):
        aad = (
            pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        nonce_val = int.from_bytes(self.keys.iv, "big", signed=False) ^ self.seq_nbr
        nonce = nonce_val.to_bytes(self.cipher.iv_len, "big", signed=False)
        cipher = self.cipher_object(self.keys.enc)
        decoded = cipher.decrypt(nonce, rl_msg.fragment, aad)
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
        self.seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=tls.ContentType.val2enum(decoded[idx], alert_on_failure=True),
            version=rl_msg.version,
            fragment=decoded[:idx],
        )

    def unprotect_msg(self, rl_msg):
        if self.version is tls.Version.TLS13:
            return self._tls13_unprotect(rl_msg)
        else:
            # We do not support compression.
            return self._unprotect(rl_msg)
