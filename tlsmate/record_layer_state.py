# -*- coding: utf-8 -*-
"""Module containing the class implementing the record layer
"""
# import basic stuff
import struct

# import own stuff
from tlsmate import pdu
from tlsmate import tls
from tlsmate import structs
from tlsmate.exception import FatalAlert

# import other stuff
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes, aead


class RecordLayerState(object):
    """Class to represent a dynamic record layer state

    Attributes:
        param (:obj:`tlsmate.structs.StateUpdateParams`): the structure to initialite
            the record layer state.
    """

    def __init__(self, param):

        self._keys = param.keys
        self._mac = param.mac
        self._cipher = param.cipher
        self._compr = param.compr
        self._enc_then_mac = param.enc_then_mac
        self._version = param.version
        self._seq_nbr = 0
        self._cipher_object = None
        self._iv = param.keys.iv
        if self._cipher.c_type == tls.CipherType.STREAM:
            cipher = Cipher(self._cipher.algo(self._keys.enc), mode=None)
            if param.is_write_state:
                self._cipher_object = cipher.encryptor()

            else:
                self._cipher_object = cipher.decryptor()

        if self._version is tls.Version.TLS13:
            self._cipher_object = param.cipher.algo

    def _encrypt_cbc(self, fragment):
        """Encrypt a fragment using a block cipher in CBC mode.

        Arguments:
            fragment (bytes): The fragment to encrypt.

        Returns:
            bytes: The encrypted fragment.
        """

        # padding
        length = len(fragment) + 1
        missing_bytes = self._cipher.block_size - (length % self._cipher.block_size)
        fragment += struct.pack("!B", missing_bytes) * (missing_bytes + 1)

        if self._version <= tls.Version.TLS10:
            iv = self._iv

        else:
            # iv should be random but we want to have it reproducable
            iv = self._iv[:-4] + pdu.pack_uint32(self._seq_nbr)

        cipher = Cipher(self._cipher.algo(self._keys.enc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_block = encryptor.update(fragment) + encryptor.finalize()
        if self._version <= tls.Version.TLS10:
            self._iv = cipher_block[-self._cipher.iv_len :]
            return cipher_block

        else:
            return iv + cipher_block

    def _append_mac(self, content_type, version, fragment):
        """Calculates the MAC and appends it to the fragment.

        Arguments:
            content_type (:obj:`tlsmate.constants.ContentType`): The content type.
            version (:obj:`tlsmate.constants.Version`): The version of the
                record layer.
            fragment: The message for which the MAC is calculated.

        Returns:
            bytes: The fragment appended with the MAC.
        """

        mac_input = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(content_type.value)
            + pdu.pack_uint16(version.value)
            + pdu.pack_uint16(len(fragment))
            + fragment
        )
        mac = hmac.HMAC(self._keys.mac, self._mac.hash_algo())
        mac.update(mac_input)
        return fragment + mac.finalize()

    def _protect_block_cipher(self, rl_msg):
        """Protects a fragment using a block cipher.

        The fragment is encrypted and authenticated with a MAC. Both modes,
        encrypt_then_mac and mac_then_encrypt are supported.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        if self._enc_then_mac:
            fragment = self._encrypt_cbc(rl_msg.fragment)
            fragment = self._append_mac(rl_msg.content_type, rl_msg.version, fragment)

        else:
            fragment = self._append_mac(
                rl_msg.content_type, rl_msg.version, rl_msg.fragment
            )
            fragment = self._encrypt_cbc(fragment)

        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type, version=rl_msg.version, fragment=fragment
        )

    def _protect_stream_cipher(self, rl_msg):
        """Protects a fragment using a stream cipher.

        The fragment is authenticated with a MAC and then encrypted.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        fragment = self._append_mac(
            rl_msg.content_type, rl_msg.version, rl_msg.fragment
        )
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=self._cipher_object.update(fragment),
        )

    def _protect_chacha_cipher(self, rl_msg):
        """Protects a fragment using the CHACHA20_POLY1305 cipher.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        nonce_val = int.from_bytes(self._keys.iv, "big", signed=False) ^ self._seq_nbr
        nonce = nonce_val.to_bytes(self._cipher.iv_len, "big", signed=False)
        aad = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        chachapoly = aead.ChaCha20Poly1305(self._keys.enc)
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=chachapoly.encrypt(nonce, rl_msg.fragment, aad),
        )

    def _protect_aead_cipher(self, rl_msg):
        """Protects a fragment using an AEAD cipher.

        This supports AES_GCM (128&256) as well as AES_CCM and AES_CCM_8.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        kwargs = {}
        if self._cipher.tag_length != 16:
            kwargs["tag_length"] = self._cipher.tag_length

        aes_aead = self._cipher.algo(self._keys.enc, **kwargs)
        nonce_explicit = pdu.pack_uint64(self._seq_nbr)
        nonce = self._keys.iv + nonce_explicit
        aad = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=nonce_explicit + aes_aead.encrypt(nonce, rl_msg.fragment, aad),
        )

    def _protect(self, rl_msg):
        """Protects a fragment.

        Supports stream ciphers, block cipher, AEAD ciphers and POLY20_CHACHA1305.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.

        Raises:
            FatalAlert: if the cipher type is unknown.
        """

        if self._cipher.c_type == tls.CipherType.BLOCK:
            return self._protect_block_cipher(rl_msg)

        elif self._cipher.c_type == tls.CipherType.STREAM:
            return self._protect_stream_cipher(rl_msg)

        elif self._cipher.c_type == tls.CipherType.AEAD:
            if self._cipher.primitive == tls.CipherPrimitive.CHACHA:
                return self._protect_chacha_cipher(rl_msg)

            else:
                return self._protect_aead_cipher(rl_msg)

        else:
            raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)

    def _tls13_protect(self, rl_msg):
        """Protects a fragment using the TLS1.3 specification.

        All TLS1.3 ciphers are supported.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        fragment = bytes(rl_msg.fragment) + pdu.pack_uint8(rl_msg.content_type.value)
        aad = (
            pdu.pack_uint8(tls.ContentType.APPLICATION_DATA.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(fragment) + self._cipher.tag_length)
        )
        nonce_val = int.from_bytes(self._keys.iv, "big", signed=False) ^ self._seq_nbr
        nonce = nonce_val.to_bytes(self._cipher.iv_len, "big", signed=False)
        kwargs = {}
        if self._cipher.tag_length == 8:
            kwargs["tag_length"] = 8

        cipher = self._cipher_object(self._keys.enc, **kwargs)
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=tls.ContentType.APPLICATION_DATA,
            version=rl_msg.version,
            fragment=cipher.encrypt(nonce, fragment, aad),
        )

    def protect_msg(self, rl_msg):
        """Protects a fragment.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to protect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The protected record layer message.
        """

        if self._version is tls.Version.TLS13:
            return self._tls13_protect(rl_msg)

        else:
            # Skip compression, we don't want to support it.
            return self._protect(rl_msg)

    def _verify_mac(self, content_type, version, fragment):
        """Verifies the MAC of a fragment.

        Arguments:
            content_type (:obj:`tlsmate.constants.ContentType`): The content type.
            version (:obj:`tlsmate.constants.Version`): The version of the
                record layer.
            fragment: The message for which the MAC is verified.

        Returns:
            bytes: The fragment appended with the MAC.

        Raises:
            FatalAlert: If the MAC is incorrect.
        """

        if len(fragment) < self._mac.mac_len:
            raise FatalAlert(
                "Decoded fragment too short", tls.AlertDescription.BAD_RECORD_MAC
            )

        msg_len = len(fragment) - self._mac.mac_len
        mac_received = fragment[msg_len:]
        msg = fragment[:msg_len]
        mac_input = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(content_type.value)
            + pdu.pack_uint16(version.value)
            + pdu.pack_uint16(msg_len)
            + msg
        )
        mac = hmac.HMAC(self._keys.mac, self._mac.hash_algo())
        mac.update(mac_input)
        mac_calculated = mac.finalize()
        if mac_calculated != mac_received:
            raise FatalAlert(
                "MAC verification failed", tls.AlertDescription.BAD_RECORD_MAC
            )

        return msg

    def _decode_cbc(self, fragment):
        """Decodes a fragment using a block cipher in CBC mode.

        Arguments:
            fragment (bytes): The fragment to decode.

        Returns:
            bytes: the decoded fragment.

        Raises:
            FatalAlert: If padding errors are detected.
        """

        if self._version <= tls.Version.TLS10:
            iv = self._iv
            cipher_text = fragment
            self._iv = fragment[-self._cipher.iv_len :]

        else:
            iv = fragment[: self._cipher.iv_len]
            cipher_text = fragment[self._cipher.iv_len :]

        cipher = Cipher(self._cipher.algo(self._keys.enc), modes.CBC(iv))
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
        """Unprotects a record layer message (block cipher).

        The message is decrypted and the authentication is verified. Both modes,
        encrypt_then_mac and mac_then_encrypt are supported.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        if self._enc_then_mac:
            fragment = self._verify_mac(
                rl_msg.content_type, rl_msg.version, rl_msg.fragment
            )
            plain_text = self._decode_cbc(fragment)

        else:
            fragment = self._decode_cbc(rl_msg.fragment)
            plain_text = self._verify_mac(rl_msg.content_type, rl_msg.version, fragment)

        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=plain_text,
        )

    def _unprotect_stream_cipher(self, rl_msg):
        """Unprotects a record layer message (stream cipher).

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        fragment = self._cipher_object.update(rl_msg.fragment)
        clear_text = self._verify_mac(rl_msg.content_type, rl_msg.version, fragment)
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=clear_text,
        )

    def _unprotect_chacha_cipher(self, rl_msg):
        """Unprotects a record layer message (CHACHA20_POLY1305 cipher).

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        nonce_val = int.from_bytes(self._keys.iv, "big", signed=False) ^ self._seq_nbr
        nonce = nonce_val.to_bytes(self._cipher.iv_len, "big", signed=False)
        aad = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment) - self._cipher.tag_length)
        )
        chachapoly = aead.ChaCha20Poly1305(self._keys.enc)
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=chachapoly.decrypt(nonce, rl_msg.fragment, aad),
        )

    def _unprotect_aead_cipher(self, rl_msg):
        """Unprotects a record layer message (AEAD cipher).

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        nonce_explicit = rl_msg.fragment[:8]
        cipher_text = rl_msg.fragment[8:]
        aad = (
            pdu.pack_uint64(self._seq_nbr)
            + pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(cipher_text) - self._cipher.tag_length)
        )
        nonce = bytes(self._keys.iv + nonce_explicit)
        kwargs = {}
        if self._cipher.tag_length != 16:
            kwargs["tag_length"] = self._cipher.tag_length

        aes_aead = self._cipher.algo(self._keys.enc, **kwargs)
        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=rl_msg.content_type,
            version=rl_msg.version,
            fragment=aes_aead.decrypt(nonce, cipher_text, aad),
        )

    def _unprotect(self, rl_msg):
        """Unprotects a record layer message (all ciphers, but not for TLS1.3).

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        if self._cipher.c_type == tls.CipherType.BLOCK:
            return self._unprotect_block_cipher(rl_msg)

        elif self._cipher.c_type == tls.CipherType.STREAM:
            return self._unprotect_stream_cipher(rl_msg)

        elif self._cipher.c_type == tls.CipherType.AEAD:
            if self._cipher.primitive == tls.CipherPrimitive.CHACHA:
                return self._unprotect_chacha_cipher(rl_msg)

            else:
                return self._unprotect_aead_cipher(rl_msg)

        else:
            raise FatalAlert("Unknown cipher type", tls.AlertDescription.INTERNAL_ERROR)

    def _tls13_unprotect(self, rl_msg):
        """Unprotects a record layer message (TLS1.3).

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        aad = (
            pdu.pack_uint8(rl_msg.content_type.value)
            + pdu.pack_uint16(rl_msg.version.value)
            + pdu.pack_uint16(len(rl_msg.fragment))
        )
        nonce_val = int.from_bytes(self._keys.iv, "big", signed=False) ^ self._seq_nbr
        nonce = nonce_val.to_bytes(self._cipher.iv_len, "big", signed=False)
        kwargs = {}
        if self._cipher.tag_length == 8:
            kwargs["tag_length"] = 8

        cipher = self._cipher_object(self._keys.enc, **kwargs)
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

        self._seq_nbr += 1
        return structs.RecordLayerMsg(
            content_type=tls.ContentType.val2enum(decoded[idx], alert_on_failure=True),
            version=rl_msg.version,
            fragment=decoded[:idx],
        )

    def unprotect_msg(self, rl_msg):
        """Unprotects a record layer message.

        The message is decrypted and the authentication is verified.

        Arguments:
            rl_msg (:obj:`tlsmate.structs.RecordLayerMsg`): The record layer
                message to unprotect.

        Returns:
            :obj:`tlsmate.structs.RecordLayerMsg`:
            The unprotected record layer message (plain text).
        """

        if self._version is tls.Version.TLS13:
            if rl_msg.content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                return rl_msg

            return self._tls13_unprotect(rl_msg)

        else:
            # We do not support compression.
            return self._unprotect(rl_msg)
