# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import logging
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.testmanager import TestManager, TestSuite
import tlsclient.mappings as mappings


class MyTestSuite(TestSuite):
    name = "testme"
    descr = "Scratch test suite"
    prio = 100

    def run(self):
        version_profile = self.server_profile.get_version(tls.Version.TLS12)
        client = self.client
        client.versions = [tls.Version.TLS12]
        tls12_ciphers = version_profile.get_cipher_suites()
        used_ciphers = []
        for cipher in tls12_ciphers:
            obj = mappings.supported_cipher_suites.get(cipher)
            if obj is not None:
                if obj.key_ex in [
                    tls.KeyExchangeAlgorithm.ECDHE_RSA,
                    tls.KeyExchangeAlgorithm.ECDH_RSA,
                    tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
                    tls.KeyExchangeAlgorithm.ECDH_ECDSA,
                ]:
                    used_ciphers.append(cipher)
        client.support_supported_groups = True
        client.supported_groups = [
            tls.SupportedGroups.X448,
            tls.SupportedGroups.SECT163K1,
            tls.SupportedGroups.SECT163R2,
            tls.SupportedGroups.SECT233K1,
            tls.SupportedGroups.SECT233R1,
            tls.SupportedGroups.SECT283K1,
            tls.SupportedGroups.SECT283R1,
            tls.SupportedGroups.SECT409K1,
            tls.SupportedGroups.SECT409R1,
            tls.SupportedGroups.SECT571K1,
            tls.SupportedGroups.SECT571R1,
            tls.SupportedGroups.SECP224R1,
            tls.SupportedGroups.SECP256K1,
            tls.SupportedGroups.BRAINPOOLP256R1,
            tls.SupportedGroups.BRAINPOOLP384R1,
            tls.SupportedGroups.BRAINPOOLP512R1,
            tls.SupportedGroups.SECP256R1,
            tls.SupportedGroups.SECP384R1,
            tls.SupportedGroups.SECP521R1,
            tls.SupportedGroups.FFDHE2048,
            tls.SupportedGroups.FFDHE4096,
            tls.SupportedGroups.X25519,
        ]
        client.signature_algorithms = [
            tls.SignatureScheme.RSA_PKCS1_SHA1,
            tls.SignatureScheme.ECDSA_SHA1,
            tls.SignatureScheme.RSA_PKCS1_SHA256,
            tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls.SignatureScheme.RSA_PKCS1_SHA256_LEGACY,
            tls.SignatureScheme.RSA_PKCS1_SHA384,
            tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls.SignatureScheme.RSA_PKCS1_SHA384_LEGACY,
            tls.SignatureScheme.RSA_PKCS1_SHA512,
            tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            tls.SignatureScheme.RSA_PKCS1_SHA512_LEGACY,
            tls.SignatureScheme.ECCSI_SHA256,
            tls.SignatureScheme.ISO_IBS1,
            tls.SignatureScheme.ISO_IBS2,
            tls.SignatureScheme.ISO_CHINESE_IBS,
            tls.SignatureScheme.SM2SIG_SM3,
            # tls.SignatureScheme.GOSTR34102012_256A,
            # tls.SignatureScheme.GOSTR34102012_256B,
            # tls.SignatureScheme.GOSTR34102012_256C,
            # tls.SignatureScheme.GOSTR34102012_256D,
            # tls.SignatureScheme.GOSTR34102012_512A,
            # tls.SignatureScheme.GOSTR34102012_512B,
            # tls.SignatureScheme.GOSTR34102012_512C,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
            tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            tls.SignatureScheme.ED25519,
            tls.SignatureScheme.ED448,
            tls.SignatureScheme.RSA_PSS_PSS_SHA256,
            tls.SignatureScheme.RSA_PSS_PSS_SHA384,
            tls.SignatureScheme.RSA_PSS_PSS_SHA512,
            tls.SignatureScheme.ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            tls.SignatureScheme.ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            tls.SignatureScheme.ECDSA_BRAINPOOLP512R1TLS13_SHA512,
        ]
        # client.support_encrypt_then_mac = True
        # client.support_extended_master_secret = True

        # client.support_session_ticket = True
        # client.support_supported_groups = False
        # self.client.key_shares = [
        #     tls.SupportedGroups.SECP256R1,
        #     tls.SupportedGroups.SECP384R1,
        #     tls.SupportedGroups.SECP521R1,
        #     tls.SupportedGroups.X25519,
        #     tls.SupportedGroups.X448,

        #     tls.SupportedGroups.FFDHE2048,
        #     tls.SupportedGroups.FFDHE3072,
        #     tls.SupportedGroups.FFDHE4096,
        #     tls.SupportedGroups.FFDHE6144,
        #     tls.SupportedGroups.FFDHE8192,
        # ]

        for cipher in used_ciphers:
            client.cipher_suites = [cipher]
            with client.create_connection() as conn:
                conn.send(msg.ClientHello)
                conn.wait(msg.ServerHello)

                # conn.wait(msg.ChangeCipherSpec, optional=True)
                # conn.wait(msg.EncryptedExtensions)
                # conn.wait(msg.Certificate)
                # conn.wait(msg.CertificateVerify)
                # conn.wait(msg.Finished)
                # conn.send(msg.Finished)
                # conn.wait(msg.NewSessionTicket)
                # conn.wait(msg.NewSessionTicket)

                conn.wait(msg.Certificate, optional=True)
                ske = conn.wait(msg.ServerKeyExchange)
                print(f"cipher {cipher.name}: {ske.ec.named_curve.name}")


TestManager.register_cli(
    "--ccc", cli_help="performs a regular scan", classes=[MyTestSuite]
)
