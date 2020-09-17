# -*- coding: utf-8 -*-
import pytest

import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData

def test_tls_connection_msg_digest(tls_connection_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, msg_array):
    conn = tls_connection_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    conn.init_msg_hash()
    for msg in msg_array[:-1]:
        conn.update_msg_hash(msg)
    digest1 = conn.finalize_msg_hash(intermediate=True)
    conn.update_msg_hash(msg_array[-1])
    digest2 = conn.finalize_msg_hash()

    verify_data1 = conn.sec_param.prf(conn.sec_param.master_secret, b"client finished", digest1, 12)
    verify_data2 = conn.sec_param.prf(conn.sec_param.master_secret, b"server finished", digest2, 12)

    assert verify_data1 == bytes.fromhex("8ADAA34CA54B4269380DCB5E")
    assert verify_data2 == bytes.fromhex("9E166D65FA31E07DB53820E2")

