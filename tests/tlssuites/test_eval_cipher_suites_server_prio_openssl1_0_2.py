# -*- coding: utf-8 -*-
"""Implements a class to be used for unit testing.
"""
import pathlib
from tlsmate.tlssuites.eval_cipher_suites import ScanCipherSuites
from tlsmate.tlssuite import TlsSuiteTester
from tlsmate.tlssuite import OpensslVersion


tls10_cs = [
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
    "TLS_DH_ANON_WITH_AES_256_CBC_SHA",
    "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA",
    "TLS_DH_ANON_WITH_AES_128_CBC_SHA",
    "TLS_DH_ANON_WITH_SEED_CBC_SHA",
    "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_SEED_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_RSA_WITH_IDEA_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDH_ANON_WITH_RC4_128_SHA",
    "TLS_DH_ANON_WITH_RC4_128_MD5",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
]


tls12_cs = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
    "TLS_DH_ANON_WITH_AES_256_GCM_SHA384",
    "TLS_DH_ANON_WITH_AES_256_CBC_SHA256",
    "TLS_DH_ANON_WITH_AES_256_CBC_SHA",
    "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA",
    "TLS_DH_ANON_WITH_AES_128_GCM_SHA256",
    "TLS_DH_ANON_WITH_AES_128_CBC_SHA256",
    "TLS_DH_ANON_WITH_AES_128_CBC_SHA",
    "TLS_DH_ANON_WITH_SEED_CBC_SHA",
    "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_SEED_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_RSA_WITH_IDEA_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDH_ANON_WITH_RC4_128_SHA",
    "TLS_DH_ANON_WITH_RC4_128_MD5",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
]


class TestCase(TlsSuiteTester):
    """Class used for tests with pytest.

    For more information refer to the documentation of the TcRecorder class.
    """

    sp_out_yaml = "profile_basic_server_prio_openssl1_0_2"
    recorder_yaml = "recorder_eval_cipher_suites_server_prio_openssl1_0_2"
    path = pathlib.Path(__file__)
    server_cmd = (
        "utils/start_openssl --prefix {prefix} --port {port} --cert rsa --cert2 ecdsa "
        "--mode www -- -cipher ALL -serverpref"
    )
    openssl_version = OpensslVersion.v1_0_2

    server = "localhost"

    def check_cert_chain(self, cert_chain):
        assert len(cert_chain) == 2
        assert cert_chain[0]["id"] == 1
        assert cert_chain[1]["id"] == 2
        assert len(cert_chain[0]["cert_chain"]) == 3
        assert len(cert_chain[1]["cert_chain"]) == 3

    def check_versions(self, versions):
        assert len(versions) == 4
        assert versions[0]["version"]["name"] == "SSL30"
        assert versions[0]["server_preference"] == "C_TRUE"
        assert versions[1]["version"]["name"] == "TLS10"
        assert versions[1]["server_preference"] == "C_TRUE"
        assert versions[2]["version"]["name"] == "TLS11"
        assert versions[2]["server_preference"] == "C_TRUE"
        assert versions[3]["version"]["name"] == "TLS12"
        assert versions[3]["server_preference"] == "C_TRUE"
        for a, b in zip(tls10_cs, versions[0]["cipher_suites"]):
            assert a == b["name"]
        for a, b in zip(tls10_cs, versions[1]["cipher_suites"]):
            assert a == b["name"]
        for a, b in zip(tls10_cs, versions[2]["cipher_suites"]):
            assert a == b["name"]
        for a, b in zip(tls12_cs, versions[3]["cipher_suites"]):
            assert a == b["name"]

    def check_profile(self, profile):
        self.check_cert_chain(profile["cert_chains"])
        self.check_versions(profile["versions"])

    def run(self, tlsmate, is_replaying):
        server_profile = tlsmate.server_profile
        test_suite = ScanCipherSuites()
        test_suite._inject_dependencies(server_profile, tlsmate.client)
        test_suite.run()

        self.check_profile(server_profile.make_serializable())


if __name__ == "__main__":
    TestCase().entry(is_replaying=False)
