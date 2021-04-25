# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff
import abc

# import own stuff
from tlsmate import msg
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin
from tlsmate import utils
from tlsmate.server_profile import SPSignatureAlgorithms

# import other stuff


class _Backend(metaclass=abc.ABCMeta):
    @staticmethod
    def get_sig_alg_from_server(client, sig_algs):
        raise NotImplementedError


class _BackendTls12(_Backend):
    @staticmethod
    def get_sig_alg_from_server(client, sig_algs):
        sig_alg = None
        cert_chain = None
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            cert_chain = conn.wait(msg.Certificate).chain
            msg_ske = conn.wait(msg.ServerKeyExchange)
            if msg_ske.ec is not None:
                sig_alg = msg_ske.ec.sig_scheme

            elif msg_ske.dh is not None:
                sig_alg = msg_ske.dh.sig_scheme

        return sig_alg, cert_chain


class _BackendTls13(_Backend):
    @staticmethod
    def get_sig_alg_from_server(client, sig_algs):
        sig_alg = None
        cert_chain = None
        with client.create_connection() as conn:
            conn.send(msg.ClientHello)
            conn.wait(msg.ServerHello)
            conn.wait(msg.ChangeCipherSpec, optional=True)
            conn.wait(msg.EncryptedExtensions)
            cert_chain = conn.wait(msg.Certificate).chain
            sig_alg = conn.wait(msg.CertificateVerify).signature_scheme

        return sig_alg, cert_chain


class ScanSigAlgs(WorkerPlugin):
    name = "sigalgo"
    descr = "check signature algorithms"
    prio = 20

    def _scan_auth_method(self, cipher_suites, sig_algs, prof_sig_algo, backend):
        sig_alg_supported = []
        if not cipher_suites:
            return sig_alg_supported
        self.client.cipher_suites = cipher_suites
        self.client.support_signature_algorithms = True
        self.client.signature_algorithms = sig_algs

        while sig_algs:
            sig_alg, cert_chain = backend.get_sig_alg_from_server(self.client, sig_algs)
            if sig_alg is None:
                break

            self.server_profile.append_unique_cert_chain(cert_chain)
            if sig_alg not in sig_algs:
                if not hasattr(prof_sig_algo, "info"):
                    prof_sig_algo.info = []

                info = f"server selects sig_alg {sig_alg} even when not offered"
                if info not in prof_sig_algo.info:
                    prof_sig_algo.info.append(info)

                break

            sig_alg_supported.append(sig_alg)
            sig_algs.remove(sig_alg)

        if len(sig_alg_supported) > 1:
            ref_sig_algo = sig_alg_supported[0]
            sig_alg_supported.append(sig_alg_supported.pop(0))
            sig_alg = backend.get_sig_alg_from_server(self.client, sig_alg_supported)
            sig_alg_supported.insert(0, sig_alg_supported.pop())

            if sig_alg is ref_sig_algo:
                prof_sig_algo.server_preference = tls.SPBool.C_TRUE

            else:
                prof_sig_algo.server_preference = tls.SPBool.C_FALSE
        else:
            prof_sig_algo.server_preference = tls.SPBool.C_NA

        for sig_algo in sig_alg_supported:
            prof_sig_algo.algorithms.append(sig_algo)

    def _scan_tls12(self):
        prof_version = self.server_profile.get_version_profile(tls.Version.TLS12)
        if prof_version is None:
            return

        if not hasattr(prof_version, "signature_algorithms"):
            prof_version.signature_algorithms = SPSignatureAlgorithms()

        values = self.server_profile.get_profile_values([tls.Version.TLS12])
        self.client.init_profile(profile_values=values)

        prof_sig_algo = prof_version.signature_algorithms
        sigalg_list = tls.SignatureScheme.all()

        rsa_ciphers = utils.filter_cipher_suites(
            values.cipher_suites, key_auth=[tls.KeyAuthentication.RSA]
        )
        rsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.RSA.value,
                sigalg_list,
            )
        ]
        self._scan_auth_method(rsa_ciphers, rsa_sigalgs, prof_sig_algo, _BackendTls12)

        dsa_ciphers = utils.filter_cipher_suites(
            values.cipher_suites, key_auth=[tls.KeyAuthentication.DSS]
        )
        dsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.DSA.value,
                sigalg_list,
            )
        ]
        self._scan_auth_method(dsa_ciphers, dsa_sigalgs, prof_sig_algo, _BackendTls12)

        ecdsa_ciphers = utils.filter_cipher_suites(
            values.cipher_suites, key_algo=[tls.KeyExchangeAlgorithm.ECDHE_ECDSA]
        )
        ecdsa_sigalgs = [
            x
            for x in filter(
                lambda alg: (alg.value & 0xFF) == tls.SignatureAlgorithm.ECDSA.value,
                sigalg_list,
            )
        ]
        ecdsa_sigalgs.extend([tls.SignatureScheme.ED25519, tls.SignatureScheme.ED448])
        self._scan_auth_method(
            ecdsa_ciphers, ecdsa_sigalgs, prof_sig_algo, _BackendTls12
        )

    def _scan_tls13(self):
        prof_version = self.server_profile.get_version_profile(tls.Version.TLS13)
        if prof_version is None:
            return

        if not hasattr(prof_version, "signature_algorithms"):
            prof_version.signature_algorithms = SPSignatureAlgorithms()

        values = self.server_profile.get_profile_values([tls.Version.TLS12])
        self.client.init_profile(profile_values=values)
        prof_sig_algo = prof_version.signature_algorithms
        self.client.support_supported_groups = True
        self.client.supported_groups = prof_version.supported_groups.groups
        self.client.key_shares = tls.SupportedGroups.all_tls13()
        self.client.versions = [tls.Version.TLS13]

        self._scan_auth_method(
            prof_version.cipher_suites,
            tls.SignatureScheme.all(),
            prof_sig_algo,
            _BackendTls13,
        )

    def run(self):
        self._scan_tls12()
        self._scan_tls13()
