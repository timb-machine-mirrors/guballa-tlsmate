# -*- coding: utf-8 -*-
import pytest

import tlsclient.constants as tls
from tlsclient.security_parameters import SecurityParameters
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import x25519


def test_security_parameters(sec_param_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, mocker):
    sec_ref = sec_param_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

    sec_param = SecurityParameters(tls.Entity.CLIENT)
    sec_param.client_random = sec_ref.client_random
    sec_param.server_random = sec_ref.server_random
    sec_param.update_cipher_suite(sec_ref.cipher_suite)
    assert sec_param.cipher == sec_ref.cipher
    assert sec_param.key_exchange_method == sec_ref.key_exchange_method
    assert sec_param.hash_primitive == sec_ref.hash_primitive
    assert sec_param.cipher_primitive == sec_ref.cipher_primitive
    assert sec_param.cipher_algo == sec_ref.cipher_algo
    assert sec_param.cipher_type == sec_ref.cipher_type
    assert sec_param.enc_key_len == sec_ref.enc_key_len
    assert sec_param.block_size == sec_ref.block_size
    assert sec_param.iv_len == sec_ref.iv_len
    assert sec_param.hash_algo == sec_ref.hash_algo
    assert sec_param.mac_len == sec_ref.mac_len
    assert sec_param.mac_key_len == sec_ref.mac_key_len

    private_bytes = sec_ref.private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    mocker.patch(
        "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate",
        return_value=x25519.X25519PrivateKey.from_private_bytes(private_bytes),
    )
    # import pudb; pudb.set_trace()
    sec_param.named_curve = sec_ref.named_curve
    sec_param.remote_public_key = sec_ref.remote_public_key
    sec_param.generate_master_secret()

    assert sec_param.pre_master_secret == sec_ref.pre_master_secret
    assert sec_param.master_secret == sec_ref.master_secret

    sec_param.key_deriviation()
    assert sec_param.client_write_mac_key == sec_ref.client_write_mac_key
    assert sec_param.server_write_mac_key == sec_ref.server_write_mac_key
    assert sec_param.client_write_key == sec_ref.client_write_key
    assert sec_param.server_write_key == sec_ref.server_write_key
    assert sec_param.client_write_iv == sec_ref.client_write_iv
