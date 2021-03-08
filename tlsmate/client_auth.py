# -*- coding: utf-8 -*-
"""Module for handling client auth (keys & cert chains)
"""
# import basic stuff
import pem

# import own stuff
from tlsmate import tls
from tlsmate.cert import CertChain

# import other stuff
from cryptography.hazmat.primitives import serialization


class ClientAuth(object):
    # TODO: docu
    """Manages client authentication (multiple keys and cert chains)
    """

    def __init__(self, tlsmate):
        self._used_idx = set()
        self._auth = []
        self._recorder = tlsmate.recorder

    def add_auth(self, key, chain):
        self._auth.append((key, chain))

    def add_auth_files(self, key_file, chain_file):
        with open(key_file, "rb") as fd:
            key = serialization.load_pem_private_key(fd.read(), password=None)

        chain = CertChain()
        pem_list = pem.parse_file(chain_file)
        for pem_item in pem_list:
            chain.append_pem_cert(pem_item.as_bytes())

        self.add_auth(key, chain)

    def supported(self):
        return bool(self._auth)

    def find_algo(self, algo, version):
        for idx, key_chain in enumerate(self._auth):
            cert = key_chain[1].certificates[0]
            if version is tls.Version.TLS13:
                cert_algos = cert.tls13_signature_algorithms

            else:
                cert_algos = cert.tls12_signature_algorithms

            if algo in cert_algos:
                if self._recorder.is_recording():
                    if idx not in self._used_idx:
                        self._used_idx.add(idx)
                        self._recorder.trace_client_auth(self.serialize_key_chain(idx))
                return idx

        return None

    def serialize_key_chain(self, idx):
        key, chain = self._auth[idx]
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return [key_bytes.hex(), chain.serialize()]

    def deserialize_key_chain(self, key_chain):
        key, chain = key_chain
        priv_key = serialization.load_der_private_key(bytes.fromhex(key), None)
        chn = CertChain()
        chn.deserialize(chain)
        self.add_auth(priv_key, chn)

    def get_chain(self, idx):
        return self._auth[idx][1]

    def get_key(self, idx):
        return self._auth[idx][0]
