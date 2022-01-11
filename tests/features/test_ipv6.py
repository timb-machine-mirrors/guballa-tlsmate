# -*- coding: utf-8 -*-
"""Test connection to external server.
"""
import os
import pytest
import subprocess
import sys
import time
import tlsmate.tls as tls


@pytest.fixture
def openssl_ipv6_port(server_rsa_key_file, server_rsa_cert_file, server_rsa_chain_file):
    port = os.environ.get("TLSMATE_TEST_PORT", 44550)
    cmd = (
        f"openssl s_server -key {server_rsa_key_file} -cert {server_rsa_cert_file} "
        f"-cert_chain {server_rsa_chain_file} -accept {port} -6"
    )
    proc = subprocess.Popen(
        cmd.split(),
        stdin=subprocess.PIPE,
        stdout=sys.stdout,
    )
    time.sleep(5)
    yield port
    proc.kill()


def test_main(tlsmate, openssl_ipv6_port):
    tlsmate.client.set_profile(tls.Profile.INTEROPERABILITY)
    with tlsmate.client.create_connection(
        host="::1", port=openssl_ipv6_port, sni="localhost"
    ) as conn:
        conn.handshake()

    assert conn.handshake_completed
