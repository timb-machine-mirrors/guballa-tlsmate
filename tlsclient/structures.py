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
    primitive: tls.CipherPrimitive
    algo: cryptography.hazmat.primitives.ciphers.algorithms.AES  # just an example
    c_type: tls.CipherType
    key_len: int
    block_size: int
    iv_len: int
    aead_expansion: int


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


class KeyExchangeAlgo(NamedTuple):
    """Set of properties describing a key exchange algorithm.
    """
    cls: type


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
    cipher: tls.SupportedCipher
    mac: tls.SupportedHash


class RecordLayerMsg(NamedTuple):
    """Set of properties describing a record layer message.
    """
    content_type: tls.ContentType
    version: tls.Version
    fragment: bytes


class SPCipherSuite(NamedTuple):
    """Properties describing a cipher suite in the server profile.
    """
    cipher_suite: tls.CipherSuite
    cert_chain_id: int


class KeyExchange(NamedTuple):
    """Set of properties describing a key exchange method.
    """
    key_ex_type: tls.KeyExchangeType
    key_auth: tls.KeyAuthentication


class KeyShareEntry(NamedTuple):
    """Set of properties describing a key share entry.
    """
    group: tls.SupportedGroups
    key_exchange: bytes


class DHNumbers(NamedTuple):
    """Set of properties describing a DH group.
    """
    g_val: int
    p_val: bytes
