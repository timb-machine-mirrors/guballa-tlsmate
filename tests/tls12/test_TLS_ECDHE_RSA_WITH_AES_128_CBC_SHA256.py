# -*- coding: utf-8 -*-
import pytest
import pickle
import pathlib

from dependency_injector import providers
import tlsclient.constants as tls
import tlsclient.tls_message as msg
from tlsclient.dependencies import Container


PICKLE_DIR = pathlib.Path(__file__).resolve().parent / "recordings"
FILE_NAME = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.pickle"
PICKLE_FILE = PICKLE_DIR / FILE_NAME

OPENSSL_SERVER_CMD = "export OPENSSL_TRACE=TLS && openssl s_server -key key.pem -cert cert.pem -accept 44330 -www -no_tls1_3 -cipher ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"

def scenario(container):

    client_profile = container.client_profile()

    client_profile.tls_versions = [tls.Version.TLS12]
    client_profile.cipher_suites = [
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    ]
    client_profile.supported_groups = [
        tls.SupportedGroups.X25519,
        tls.SupportedGroups.SECP256R1,
        tls.SupportedGroups.SECP384R1,
        tls.SupportedGroups.SECP521R1,
        tls.SupportedGroups.FFDHE2048,
        tls.SupportedGroups.FFDHE4096,
    ]
    client_profile.signature_algorithms = [
        tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
        tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
        tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
        tls.SignatureScheme.RSA_PKCS1_SHA256,
        tls.SignatureScheme.RSA_PKCS1_SHA384,
        tls.SignatureScheme.RSA_PKCS1_SHA512,
        tls.SignatureScheme.ECDSA_SHA1,
        tls.SignatureScheme.RSA_PKCS1_SHA1,
    ]

    with client_profile.create_connection() as conn:
        conn.send(msg.ClientHello)
        conn.wait(msg.ServerHello)
        conn.wait(msg.Certificate, optional=True)
        conn.wait(msg.ServerKeyExchange, optional=True)
        conn.wait(msg.ServerHelloDone)
        conn.send(msg.ClientKeyExchange, msg.ChangeCipherSpec, msg.Finished)
        conn.wait(msg.ChangeCipherSpec)
        conn.wait(msg.Finished)
        conn.send(msg.AppData(b"Hier kommen Daten!"))

    return conn

def test_all():

    with open(PICKLE_FILE, "rb") as fd:
        recorder = pickle.load(fd)
    recorder.replay()
    config = {"server": "localhost", "port": 44330}
    container = Container(config=config, recorder=providers.Object(recorder))
    conn = scenario(container)


def gen_test():

    config = {"server": "localhost", "port": 44330}
    container = Container(config=config)
    recorder = container.recorder()
    recorder.openssl_s_server = OPENSSL_SERVER_CMD
    recorder.record()
    conn = scenario(container)

    with open(PICKLE_FILE, "wb") as fd:
        pickle.dump(conn.recorder, fd)


if __name__ == "__main__":
    gen_test()
