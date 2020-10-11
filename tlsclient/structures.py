# -*- coding: utf-8 -*-
"""Module defining various structures
"""
import collections

SessionStateId = collections.namedtuple(
    "SessionStateId", ["session_id", "cipher_suite", "version", "master_secret"]
)

SessionStateTicket = collections.namedtuple(
    "SessionStateTicket",
    ["ticket", "lifetime", "cipher_suite", "version", "master_secret"],
)


Cipher = collections.namedtuple(
    "Cipher", "primitive algo c_type key_len block_size iv_len, aead_expansion"
)

Mac = collections.namedtuple("Mac", "hash_algo mac_len key_len hmac_algo")

SymmetricKeys = collections.namedtuple("SymmetricKeys", "mac enc iv")

KeyExchangeAlgo = collections.namedtuple("KeyExchangeAlgo", "cls")

StateUpdateParams = collections.namedtuple(
    "StateUpdateParams",
    ["cipher", "mac", "keys", "compr", "enc_then_mac", "version", "is_write_state"],
)


CipherSuite = collections.namedtuple("CipherSuite", "key_ex cipher mac")

MessageBlock = collections.namedtuple("MessageBlock", "content_type version fragment")


Groups = collections.namedtuple("Groups", "curve_algo")
SPCipherSuite = collections.namedtuple("SPCipherSuite", "cipher_suite cert_chain_id")

KeyExchange = collections.namedtuple("KeyExchange", "key_ex_type key_auth")

KeyShareEntry = collections.namedtuple("KeyShareEntry", "group key_exchange")

DHNumbers = collections.namedtuple("DHNumbers", "g_val p_val")
