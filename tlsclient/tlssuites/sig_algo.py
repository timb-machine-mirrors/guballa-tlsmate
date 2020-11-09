# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
import abc
import tlsclient.messages as msg
import tlsclient.constants as tls
from tlsclient.tlssuite import TlsSuite
from tlsclient import utils
from tlsclient.server_profile import SPSignatureAlgorithms, ProfileEnum, ProfileBasic


class _Backend(metaclass=abc.ABCMeta):
    @staticmethod
    def get_sig_alg_from_server(client, cipher_suites, sig_algs):
        raise NotImplementedError


class _BackendTls12(_Backend):
    @staticmethod
    def get_sig_alg_from_server(client, cipher_suites, sig_algs):
        sig_alg = None
        cert_chain = None
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            cert_chain = conn.wait(msg.Certificate).certificates
            msg_ske = conn.wait(msg.ServerKeyExchange)
            if msg_ske.ec is not None:
                sig_alg = msg_ske.ec.sig_scheme
            elif msg_ske.dh is not None:
                sig_alg = msg_ske.dh.sig_scheme
        return sig_alg, cert_chain


class _BackendTls13(_Backend):
    @staticmethod
    def get_sig_alg_from_server(client, cipher_suites, sig_algs):
        sig_alg = None
        cert_chain = None
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec, optional=True)
            conn.wait(msg.EncryptedExtensions)
            cert_chain = conn.wait(msg.Certificate).certificates
            sig_alg = conn.wait(msg.CertificateVerify).signature_scheme
        return sig_alg, cert_chain


class ScanSigAlgs(TlsSuite):
    name = "sigalgo"
    descr = "check signature algorithms"
    prio = 20

    def scan_auth_method(self, cipher_suites, sig_algs, prof_sig_algo, backend):
        sig_alg_supported = []
        if not cipher_suites:
            return sig_alg_supported
        self.client.cipher_suites = cipher_suites
        self.client.support_signature_algorithms = True
        self.client.signature_algorithms = sig_algs
        while sig_algs:
            sig_alg, cert_chain = backend.get_sig_alg_from_server(
                self.client, cipher_suites, sig_algs
            )
            if sig_alg is None:
                break
            self.server_profile.get("cert_chain").append_unique(cert_chain)
            if sig_alg not in sig_algs:
                prof_sig_algo.add(
                    "info",
                    ProfileBasic(
                        f"server selects sig_alg {sig_alg} even when not offered"
                    ),
                    keep_existing=True,
                )
                break
            sig_alg_supported.append(sig_alg)
            sig_algs.remove(sig_alg)
        if (
            len(sig_alg_supported) > 1
            and prof_sig_algo.get("server_preference").get() is tls.SPBool.C_NA
        ):
            ref_sig_algo = sig_alg_supported[0]
            sig_alg_supported.append(sig_alg_supported.pop(0))
            sig_alg = backend.get_sig_alg_from_server(
                self.client, cipher_suites, sig_alg_supported
            )
            sig_alg_supported.insert(0, sig_alg_supported.pop())
            if sig_alg is ref_sig_algo:
                prof_sig_algo.get("server_preference").set(tls.SPBool.C_TRUE)
            else:
                prof_sig_algo.get("server_preference").set(tls.SPBool.C_FALSE)
        for sig_algo in sig_alg_supported:
            prof_sig_algo.get("algorithms").append(ProfileEnum(sig_algo))

    def scan_tls12(self):
        version = self.server_profile.get("versions").key(tls.Version.TLS12)
        if version is None:
            return
        prof_sig_algo = SPSignatureAlgorithms()
        version.add("signature_algorithms", prof_sig_algo)
        cs_list = version.get("cipher_suites").all()
        sigalg_list = tls.SignatureScheme.all()
        self.client.support_supported_groups = True
        self.client.supported_groups = (
            version.get("supported_groups").get("groups").all()
        )
        self.client.versions = [tls.Version.TLS12]

        rsa_ciphers = utils.filter_cipher_suites(
            cs_list, key_auth=[tls.KeyAuthentication.RSA]
        )
        rsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.RSA.value,
                sigalg_list,
            )
        ]
        self.scan_auth_method(rsa_ciphers, rsa_sigalgs, prof_sig_algo, _BackendTls12)

        dsa_ciphers = utils.filter_cipher_suites(
            cs_list, key_auth=[tls.KeyAuthentication.DSS]
        )
        dsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.DSA.value,
                sigalg_list,
            )
        ]
        self.scan_auth_method(dsa_ciphers, dsa_sigalgs, prof_sig_algo, _BackendTls12)

        ecdsa_ciphers = utils.filter_cipher_suites(
            cs_list, key_algo=[tls.KeyExchangeAlgorithm.ECDHE_ECDSA]
        )
        ecdsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.ECDSA.value,
                sigalg_list,
            )
        ]
        ecdsa_sigalgs.extend([tls.SignatureScheme.ED25519, tls.SignatureScheme.ED448])
        self.scan_auth_method(
            ecdsa_ciphers, ecdsa_sigalgs, prof_sig_algo, _BackendTls12
        )

    def scan_tls13(self):
        prof_version = self.server_profile.get("versions").key(tls.Version.TLS13)
        if prof_version is None:
            return
        prof_sig_algo = SPSignatureAlgorithms()
        prof_version.add("signature_algorithms", prof_sig_algo)
        cs_list = prof_version.get("cipher_suites").all()
        sigalg_list = tls.SignatureScheme.all()
        self.client.support_supported_groups = True
        self.client.supported_groups = (
            prof_version.get("supported_groups").get("groups").all()
        )
        self.client.versions = [tls.Version.TLS13]

        self.scan_auth_method(cs_list, sigalg_list, prof_sig_algo, _BackendTls13)

    def run(self):
        self.scan_tls12()
        self.scan_tls13()
