# -*- coding: utf-8 -*-
"""Module containing the class implementing for security parameters
"""
import time
import os
from tlsclient.protocol import ProtocolData

def get_random_value():
    random = ProtocolData()
    random.append_uint16(int(time.time()))
    random.extend(os.urandom(28))
    return random


class SecurityParameters(object):

    def __init__(self, entity):
        # general
        self.entity = entity
        self.version = None
        self.cipher_suite = None
        self.key_exchange_method = None
        self.compression_method = None

        # key exchange
        self.client_random = None
        self.server_random = None
        self.curve_name = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.pre_master_secret = None
        self.master_secret = None

        # for key deriviation
        self.mac_key_len = None
        self.enc_key_len = None
        self.iv_len = None

        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None

        # cipher
        self.cipher_type = None
        self.block_size = None
        self.cipher_mode = None

        # hash
        self.hash_primitive = None
        self.hash_algo = None


