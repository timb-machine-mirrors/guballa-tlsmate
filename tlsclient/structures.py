# -*- coding: utf-8 -*-
"""Module defining various structures
"""
from typing import NamedTuple
import tlsclient.constants as tls

import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.hashes


class SessionStateId(NamedTuple):
    """Set of items to store a session id in the client.
    """

    session_id: bytes
    cipher_suite: tls.CipherSuite
    version: tls.Version
    master_secret: bytes


class SessionStateTicket(NamedTuple):
    """Set of items to store a session ticket in the client.
    """

    ticket: bytes
    lifetime: int
    cipher_suite: tls.CipherSuite
    version: tls.Version
    master_secret: bytes


class Cipher(NamedTuple):
    """Set of properties describing a cipher.
    """

    primitive: tls.CipherPrimitive = None
    algo: cryptography.hazmat.primitives.ciphers.algorithms.AES = None
    c_type: tls.CipherType = None
    key_len: int = None
    block_size: int = None
    iv_len: int = None
    aead_expansion: int = None
    cipher_supported: bool = False


class Mac(NamedTuple):
    """Set of properties describing a MAC.
    """

    hash_algo: cryptography.hazmat.primitives.hashes.SHA1  # just an example
    mac_len: int
    key_len: int
    hmac_algo: cryptography.hazmat.primitives.hashes.SHA1  # just an example


class SymmetricKeys(NamedTuple):
    """Set of keys
    """

    mac: bytes
    enc: bytes
    iv: bytes


class StateUpdateParams(NamedTuple):
    """Set of properties used to update the record layer state.
    """

    cipher: Cipher
    mac: Mac
    keys: SymmetricKeys
    compr: tls.CompressionMethod
    enc_then_mac: bool
    version: tls.Version
    is_write_state: bool


class CipherSuite(NamedTuple):
    """Set of properties for a cipher suite.
    """

    key_ex: tls.KeyExchangeAlgorithm
    cipher: tls.SymmetricCipher
    mac: tls.HashPrimitive


class RecordLayerMsg(NamedTuple):
    """Set of properties describing a record layer message.
    """

    content_type: tls.ContentType
    version: tls.Version
    fragment: bytes


class UpperLayerMsg(NamedTuple):
    """Set of properties describing an upper layer message.

    "Upper Layer" comprises handshake, ccs and alert protocols.
    """

    content_type: tls.ContentType
    msg_type: tls.HandshakeType  # can be CCSType as well
    msg: bytes


class KeyExchange(NamedTuple):
    """Set of properties describing a key exchange method.
    """

    key_ex_type: tls.KeyExchangeType = None
    key_auth: tls.KeyAuthentication = None
    key_ex_supported: bool = False
    default_sig_scheme: tls.SignatureScheme = None


class KeyShareEntry(NamedTuple):
    """Set of properties describing a key share entry.
    """

    group: tls.SupportedGroups
    key_exchange: bytes


class CipherSuiteDetails(NamedTuple):
    """Structure which provides details for a cipher suite.
    """

    cipher_suite: tls.CipherSuite
    full_hs: bool = False
    key_exchange_supported: bool = False
    key_algo: tls.KeyExchangeAlgorithm = None
    key_algo_struct: KeyExchange = None
    cipher: tls.SymmetricCipher = None
    cipher_struct: Cipher = None
    mac: tls.HashPrimitive = None
    mac_struct: Mac = None
