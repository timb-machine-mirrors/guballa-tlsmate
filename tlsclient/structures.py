# -*- coding: utf-8 -*-
"""Module defining various structures
"""
import collections

SessionStateId = collections.namedtuple(
    "SessionStateId", ["session_id", "cipher_suite", "version", "master_secret"]
)

SessionStateTicket = collections.namedtuple(
    "SessionStateTicket", ["session_ticket", "cipher_suite", "version", "master_secret"]
)


Cipher = collections.namedtuple(
    "Cipher", "cipher_primitive cipher_algo cipher_type enc_key_len block_size iv_len"
)

Mac = collections.namedtuple("Mac", "hash_algo mac_len mac_key_len hmac_algo")

KeyExchangeAlgo = collections.namedtuple("KeyExchangeAlgo", "cls")


StateUpdateParams = collections.namedtuple(
    "StateUpdateParams",
    [
        "cipher_primitive",  # tls.CipherPrimitive
        "cipher_algo",
        "cipher_type",  # tls.CipherType
        "block_size",
        "enc_key",
        "mac_key",
        "iv_value",
        "iv_len",
        "mac_len",
        "hash_algo",
        "compression_method",  # tls.CompressionMethod
        "encrypt_then_mac",
        "implicit_iv",
    ],
)

CipherSuite = collections.namedtuple("CipherSuite", "key_ex cipher mac")


MessageBlock = collections.namedtuple("MessageBlock", "content_type version fragment")


Groups = collections.namedtuple("Groups", "curve_algo")
SPCipherSuite = collections.namedtuple("SPCipherSuite", "cipher_suite cert_chain_id")
