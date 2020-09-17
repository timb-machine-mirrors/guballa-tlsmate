# -*- coding: utf-8 -*-
"""Define common fixtures
"""
import pytest
import tlsclient.security_parameters as sec
import tlsclient.constants as tls
from tlsclient.dependencies import Container

from tlsclient.protocol import ProtocolData
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import x25519


@pytest.fixture
def sec_param_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256():
    sec_param = sec.SecurityParameters(tls.Entity.CLIENT)
    sec_param.block_size = 16
    sec_param.cipher = tls.SupportedCipher.AES_128_CBC
    sec_param.cipher_algo = algorithms.AES
    sec_param.cipher_primitive = tls.CipherPrimitive.AES
    sec_param.cipher_suite = tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    sec_param.cipher_type = tls.CipherType.BLOCK
    sec_param.client_random = ProtocolData().fromhex(
        "5f 63 8e 08 a6 e4 0a ce c6 c1 29 8a 99 7c 72 9d "
        "fe c7 ae 50 73 f9 04 36 c1 1a b9 96 93 50 1d 4f "
    )
    sec_param.client_write_iv = ProtocolData().fromhex(
        "65 e0 d8 cd e7 f6 69 9e 33 19 af 28 9b c6 6d fa"
    )
    sec_param.client_write_key = ProtocolData().fromhex(
        "c3 fb bc d7 4e 47 76 65 12 a1 e6 6c 2f 1f 3b 58"
    )
    sec_param.client_write_mac_key = ProtocolData().fromhex(
        "ff ec 32 f7 6f e7 b9 9f b9 65 32 32 6f 6f c2 11 "
        "b1 c1 03 c4 bc 75 75 71 a4 4e cf 13 dc 65 77 5b "
    )
    sec_param.compression_method = None
    sec_param.enc_key_len = 16
    sec_param.hash_algo = hashes.SHA256
    sec_param.hash_primitive = tls.SupportedHash.SHA256
    sec_param.iv_len = 16
    sec_param.key_exchange_method = tls.KeyExchangeAlgorithm.ECDHE_RSA
    sec_param.mac_key_len = 32
    sec_param.mac_len = 32
    sec_param.master_secret = ProtocolData().fromhex(
        "56 8e e8 8a 31 a0 94 fc ba 1a e3 8f 94 33 7f 94 "
        "36 55 ba 69 c6 25 ba 02 07 6e 12 49 7d 7f f0 eb "
        "4b 00 7b 83 1a a4 d5 c5 ed 00 22 3e 06 84 54 78 "
    )
    sec_param.named_curve = tls.SupportedGroups.X25519
    sec_param.pre_master_secret = ProtocolData().fromhex(
        "6c b3 8d ab 49 e9 b6 aa 66 55 ad 98 11 6b c6 0f"
        "d8 4d f6 fd bb 83 2a 07 d0 2b bd 17 63 3f 5f 69"
    )
    sec_param.private_key = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(
            "50 8f 05 45 43 8f ad 9c f6 4f 0c 0e d0 4f f2 10 "
            "aa d0 d8 79 bc 81 94 d3 66 6f 88 f6 96 27 08 46"
        )
    )

    sec_param.public_key = ProtocolData().fromhex(
        "90 27 12 b2 0f 36 e2 9d c9 c4 37 9d 85 be 20 79 "
        "be 79 5c 1c b0 c7 da e2 b5 c8 74 04 ac 23 c5 68"
    )
    sec_param.remote_public_key = ProtocolData().fromhex(
        "83 e1 55 b5 18 03 0c 43 2d bb 96 ec 8e 09 09 f7 "
        "70 a1 83 2b 82 bb a1 d1 f6 e4 69 73 6c f3 b1 6c"
    )
    sec_param.server_random = ProtocolData().fromhex(
        "21 90 fd f9 28 a7 49 86 b0 d0 29 0e 0e bc 3f d2 "
        "d0 f5 8b e0 8b e8 a9 53 09 fe e7 69 f5 7a 85 12"
    )
    sec_param.server_write_iv = ProtocolData().fromhex(
        "9c c1 ae 1b 3d 20 dc 56 33 0e df 20 18 d8 fd 5d"
    )
    sec_param.server_write_key = ProtocolData().fromhex(
        "70 13 26 1a 69 b6 6a ab 43 04 a2 eb ad bc 73 8b"
    )
    sec_param.server_write_mac_key = ProtocolData().fromhex(
        "a3 26 14 53 61 c1 ce c9 8b 4d 0e 4a 7c fa e6 1b "
        "cc 37 bd 13 02 7f ef 21 f7 57 82 cc 61 bc da 99"
    )
    sec_param.version = tls.Version.TLS12
    return sec_param


@pytest.fixture
def msg_array():
    msgs = [
        bytes().fromhex(
            "01 00 00 7b 03 03 5f 63 8e 08 a6 e4 0a ce c6 c1 "
            "29 8a 99 7c 72 9d fe c7 ae 50 73 f9 04 36 c1 1a "
            "b9 96 93 50 1d 4f 00 00 12 c0 0a c0 23 c0 09 c0 "
            "13 c0 14 00 2f 00 35 00 0a c0 27 01 00 00 40 00 "
            "00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73 "
            "74 00 0a 00 0e 00 0c 00 1d 00 17 00 18 00 19 01 "
            "00 01 02 00 0d 00 18 00 16 04 03 05 03 06 03 08 "
            "04 08 05 08 06 04 01 05 01 06 01 02 03 02 01 "
        ),
        bytes().fromhex(
            "02 00 00 46 03 03 21 90 fd f9 28 a7 49 86 b0 d0 "
            "29 0e 0e bc 3f d2 d0 f5 8b e0 8b e8 a9 53 09 fe "
            "e7 69 f5 7a 85 12 20 34 15 34 a1 4c 54 17 80 1f "
            "44 58 c5 09 4a 0d 5a 9c 2f 7a b4 ca 45 c3 c2 cb "
            "ce 42 c2 58 97 ee 81 c0 27 00 "
        ),
        bytes().fromhex(
            "0b 00 03 fd 00 03 fa 00 03 f7 30 82 03 f3 30 82 "
            "02 db a0 03 02 01 02 02 14 66 43 9d 04 3e 55 0f "
            "7f de ac 5f ef 8b 6a 84 1c 58 3a ca 12 30 0d 06 "
            "09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 81 88 31 "
            "0b 30 09 06 03 55 04 06 13 02 44 45 31 10 30 0e "
            "06 03 55 04 08 0c 07 47 65 72 6d 61 6e 79 31 0d "
            "30 0b 06 03 55 04 07 0c 04 54 61 6d 6d 31 13 30 "
            "11 06 03 55 04 0a 0c 0a 67 75 62 61 6c 6c 61 2e "
            "64 65 31 0f 30 0d 06 03 55 04 0b 0c 06 50 72 69 "
            "76 61 74 31 12 30 10 06 03 55 04 03 0c 09 6c 6f "
            "63 61 6c 68 6f 73 74 31 1e 30 1c 06 09 2a 86 48 "
            "86 f7 0d 01 09 01 16 0f 6a 65 6e 73 40 67 75 62 "
            "61 6c 6c 61 2e 64 65 30 1e 17 0d 32 30 30 39 30 "
            "35 31 33 33 33 35 39 5a 17 0d 32 31 30 39 30 35 "
            "31 33 33 33 35 39 5a 30 81 88 31 0b 30 09 06 03 "
            "55 04 06 13 02 44 45 31 10 30 0e 06 03 55 04 08 "
            "0c 07 47 65 72 6d 61 6e 79 31 0d 30 0b 06 03 55 "
            "04 07 0c 04 54 61 6d 6d 31 13 30 11 06 03 55 04 "
            "0a 0c 0a 67 75 62 61 6c 6c 61 2e 64 65 31 0f 30 "
            "0d 06 03 55 04 0b 0c 06 50 72 69 76 61 74 31 12 "
            "30 10 06 03 55 04 03 0c 09 6c 6f 63 61 6c 68 6f "
            "73 74 31 1e 30 1c 06 09 2a 86 48 86 f7 0d 01 09 "
            "01 16 0f 6a 65 6e 73 40 67 75 62 61 6c 6c 61 2e "
            "64 65 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d "
            "01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 "
            "01 01 00 b2 c8 6f 5a e5 1b be 4d c4 82 2c 66 bf "
            "55 fa 3c 52 7e 93 c7 c6 cb a6 cf 7b 26 5f b4 b0 "
            "53 80 b3 78 ea 36 72 7d 80 8b ad c5 be 98 1a d6 "
            "d6 dc a0 30 91 0c e2 68 80 44 94 5c 01 3c aa eb "
            "6d 67 5c 63 5a 1b 3a 48 ea ec 39 c3 59 9c ca 60 "
            "19 36 69 bb be 1f ae c3 b9 78 c9 82 a1 ba 17 08 "
            "17 b6 e1 16 ae ab 71 e9 ba 6a 84 cd c4 c7 41 b3 "
            "2e 09 d7 e1 a8 1b e3 7f 4f 03 ac dd 4b 79 81 2a "
            "ce a8 72 35 c5 4c f5 06 78 18 47 46 23 48 35 ff "
            "0b f2 5c 60 e3 1a de 0a 09 02 cf 5c 0b e3 25 14 "
            "21 6f d2 92 2a 11 8e 4f aa 59 b4 62 75 8e 60 75 "
            "c8 a1 25 2a 93 83 f7 43 cf c6 b8 b3 33 a5 3c f7 "
            "9a 51 2d b9 df dc 14 17 15 47 3f 8d 43 13 fc 81 "
            "33 32 92 2a 08 3d ae 22 06 fe 01 ea 09 bb 93 2c "
            "04 22 a3 e3 c4 0a 75 e9 17 b1 98 6a 9e 02 f0 36 "
            "af 07 5e 00 26 10 c6 3e 95 be fb 2d 2f 7c dd d2 "
            "b4 7e 47 02 03 01 00 01 a3 53 30 51 30 1d 06 03 "
            "55 1d 0e 04 16 04 14 20 fe 2c e5 55 39 f7 86 28 "
            "27 80 25 65 67 16 3d 7c a5 60 8a 30 1f 06 03 55 "
            "1d 23 04 18 30 16 80 14 20 fe 2c e5 55 39 f7 86 "
            "28 27 80 25 65 67 16 3d 7c a5 60 8a 30 0f 06 03 "
            "55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0d 06 "
            "09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 "
            "00 96 7d b2 fd 59 b4 74 1b 23 00 20 0e 4a f7 2a "
            "e0 71 7c e1 d2 04 41 6a 2d f0 47 91 b0 f3 47 b0 "
            "ed 42 c9 be eb 20 63 ed 99 5b 10 1e ad af 77 03 "
            "40 53 93 d7 ed a1 91 2a a6 a6 0e d6 02 c4 f6 47 "
            "f8 7b 0d be 54 91 91 f9 40 eb a9 48 1f b7 6c 24 "
            "4b 05 5c d5 16 68 de 6d 92 0a 5e 7a 6b 66 a1 ed "
            "cc 9a 36 44 cf 39 d1 bf c5 43 c1 68 5c e4 e1 1f "
            "f0 34 4e 6d c2 67 0e 90 9b b4 11 a7 53 72 dc be "
            "20 af 92 05 f9 c6 e7 7b ad 80 e3 a2 b0 a1 76 52 "
            "c3 91 b2 7c 3c d3 12 5a a3 a8 60 23 4b 86 3f b3 "
            "60 a2 2d 93 fd 52 13 00 ed b1 42 0c e7 1d 65 10 "
            "33 4b 3d 30 54 a4 98 56 e4 d2 0f 3e 6f 3a ca 4e "
            "cd fc 11 62 55 a1 46 25 17 a2 29 20 d2 8c 71 80 "
            "c1 a4 9c 9e f0 9f 7a 1b a2 d8 35 b3 f3 a2 f1 d5 "
            "e7 7b 00 15 90 41 17 aa 09 50 91 75 0e 42 5c 75 "
            "ee cb 86 3b 37 73 30 b0 1e 98 fa 22 9c fe c9 4f "
            "65 "
        ),
        bytes().fromhex(
            "0c 00 01 28 03 00 1d 20 83 e1 55 b5 18 03 0c 43 "
            "2d bb 96 ec 8e 09 09 f7 70 a1 83 2b 82 bb a1 d1 "
            "f6 e4 69 73 6c f3 b1 6c 08 04 01 00 5d ee 53 e4 "
            "27 25 f0 d3 6c f4 0b ee 40 32 cc 1b b7 f1 f5 28 "
            "f4 b2 53 1d 18 f1 b8 37 15 e1 dd aa 84 e9 12 43 "
            "93 fb 73 39 98 ac 51 d6 69 4c 49 d6 b5 ff 95 e0 "
            "5f 74 6e 91 04 02 95 5f d3 4e 90 93 74 9d 46 15 "
            "e4 5f cf 11 75 34 1c 97 8a e4 88 b8 b0 02 64 5b "
            "9c 6a ea 66 cb 3d 58 e1 51 d4 57 47 32 00 a5 d3 "
            "53 74 58 9d 5f f4 d4 9b d5 b4 de a5 13 d0 13 61 "
            "c3 a5 9d b7 d2 df 07 fd d8 9b 28 d7 06 6e 98 f1 "
            "7b 97 95 5f 71 44 05 7f ec 8c cf 09 85 d4 30 db "
            "0a 86 ea 9b 96 3f 0e 2c 9b 9a f9 5c be 07 4b 40 "
            "5d 49 79 09 5f 29 9a b9 67 2d b1 83 85 16 4b dd "
            "84 af f1 dc 01 5c 5c 16 d8 21 7d 38 21 50 1d 76 "
            "f2 0c d5 48 54 e0 2f af 34 39 00 7d 15 1e 4d 89 "
            "d4 29 62 c9 3e 4c 94 d8 79 ce 9b 96 ea f5 a5 b2 "
            "e3 cf 81 4d c6 19 7d 1e c3 14 ff 03 e6 a7 c9 47 "
            "3b 14 01 0b 67 85 f2 31 1e 6a 3b 57 "
        ),
        bytes().fromhex("0e 00 00 00 "),
        bytes().fromhex(
            "10 00 00 21 20 90 27 12 b2 0f 36 e2 9d c9 c4 37 "
            "9d 85 be 20 79 be 79 5c 1c b0 c7 da e2 b5 c8 74 "
            "04 ac 23 c5 68 "
        ),
        bytes().fromhex("14 00 00 0c 8a da a3 4c a5 4b 42 69 38 0d cb 5e "),
    ]
    return msgs


#    client_verify_data = ProtocolData().fromhex("8ADAA34CA54B4269380DCB5E")
#
#    server_verify_data = ProtocolData().fromhex("9E166D65FA31E07DB53820E2")


@pytest.fixture
def tls_connection_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(
    sec_param_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
):
    tls_connection = Container.tls_connection()
    tls_connection.sec_param = sec_param_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    return tls_connection
