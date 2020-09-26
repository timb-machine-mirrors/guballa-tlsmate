# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import inspect
import logging
import re

from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls
from tlsclient.messages import (
    Alert,
    HandshakeMessage,
    ChangeCipherSpecMessage,
    AppDataMessage,
)
from tlsclient import mappings


from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


class TlsConnectionMsgs(object):

    map_msg2attr = {
        tls.HandshakeType.HELLO_REQUEST: None,
        tls.HandshakeType.CLIENT_HELLO: None,
        tls.HandshakeType.SERVER_HELLO: "server_hello",
        tls.HandshakeType.NEW_SESSION_TICKET: None,
        tls.HandshakeType.END_OF_EARLY_DATA: None,
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: None,
        tls.HandshakeType.CERTIFICATE: "server_certificate",
        tls.HandshakeType.SERVER_KEY_EXCHANGE: "server_key_exchange",
        tls.HandshakeType.CERTIFICATE_REQUEST: None,
        tls.HandshakeType.SERVER_HELLO_DONE: "server_hello_done",
        tls.HandshakeType.CERTIFICATE_VERIFY: None,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: None,
        tls.HandshakeType.FINISHED: "server_finished",
        tls.HandshakeType.KEY_UPDATE: None,
        tls.HandshakeType.COMPRESSED_CERTIFICATE: None,
        tls.HandshakeType.EKT_KEY: None,
        tls.HandshakeType.MESSAGE_HASH: None,
    }

    def __init__(self):
        self.client_hello = None
        self.server_hello = None
        self.server_certificate = None
        self.server_key_exchange = None
        self.server_hello_done = None
        self.client_certificate = None
        self.client_key_exchange = None
        self.client_change_cipher_spec = None
        self.client_finished = None
        self.server_change_cipher_spec = None
        self.server_finished = None
        self.client_alert = None
        self.server_alert = None

    def store_received_msg(self, msg):
        if msg.content_type == tls.ContentType.HANDSHAKE:
            attr = self.map_msg2attr.get(msg.msg_type, None)
            if attr is not None:
                setattr(self, attr, msg)
        elif msg.content_type == tls.ContentType.CHANGE_CIPHER_SPEC:
            self.server_change_cipher_spec = msg
        elif msg.content_type == tls.ContentType.ALERT:
            self.server_alert = msg


class TlsConnection(object):
    def __init__(self, connection_msgs, entity, record_layer, recorder):
        self.msg = connection_msgs
        self.received_data = ProtocolData()
        self.queued_msg = None
        self.record_layer = record_layer
        self.record_layer_version = tls.Version.TLS10
        self._update_write_state = False
        self._msg_hash = None
        self._msg_hash_queue = None
        self._msg_hash_active = False
        self.recorder = recorder

        # general
        self.entity = entity
        self.version = None
        self.client_version_sent = None
        self.cipher_suite = None
        self.key_exchange_method = None
        self.compression_method = None
        self.encrypt_then_mac = False

        # key exchange
        self.client_random = None
        self.server_random = None
        self.named_curve = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.premaster_secret = None
        self.master_secret = None

        # for key deriviation
        self.mac_key_len = None
        self.enc_key_len = None
        self.iv_len = None

        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None

        # cipher
        self.cipher_primitive = None
        self.cipher_algo = None
        self.cipher_type = None
        self.block_size = None

        # hash & mac
        self.hash_primitive = None
        self.hash_algo = None
        self.mac_len = None
        self.hmac_algo = None

    def __enter__(self):
        logging.debug("New TLS connection created")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            self.send(
                Alert(level=tls.AlertLevel.FATAL, description=exc_value.description)
            )
            self.record_layer.close_socket()
            return True
        self.record_layer.close_socket()
        logging.debug("TLS connection closed")
        return False

    def set_profile(self, client_profile):
        self.client_profile = client_profile
        return self

    def rsa_key_transport(self):
        binary_cert = self.msg.server_certificate.certificates[0]
        cert = x509.load_der_x509_certificate(binary_cert)
        pub_key = cert.public_key()
        ciphered_key = pub_key.encrypt(bytes(self.premaster_secret), padding.PKCS1v15())
        # injecting the encrypted key to the recorder is required, as the
        # padding scheme PKCS1v15 produces non-deterministic cipher text.
        return self.recorder.inject(rsa_enciphered=ciphered_key)

    def get_extension(self, extensions, ext_id):
        for ext in extensions:
            if ext.extension_id == ext_id:
                return ext
        return None

    def server_hello_received(self, msg):
        if (
            self.get_extension(msg.extensions, tls.Extension.ENCRYPT_THEN_MAC)
            is not None
        ):
            self.encrypt_then_mac = True

    def send(self, *messages):
        for msg in messages:
            if inspect.isclass(msg):
                msg = msg()
                msg.auto_generate_msg(self)
            msg_data = msg.serialize(self)

            self.record_layer.send_message(
                tls.MessageBlock(
                    content_type=msg.content_type,
                    version=self.record_layer_version,
                    fragment=msg_data,
                )
            )
            self._check_update_write_state()

        self.record_layer.flush()

    def wait(self, msg_class, optional=False):
        if self.queued_msg:
            msg = self.queued_msg
            self.queued_msg = None
        else:
            content_type, version, fragment = self.record_layer.wait_fragment()
            if content_type is tls.ContentType.HANDSHAKE:
                msg = HandshakeMessage.deserialize(fragment, self)
            elif content_type is tls.ContentType.ALERT:
                raise NotImplementedError("Receiving an Alert is not yet implemented")
            elif content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                msg = ChangeCipherSpecMessage.deserialize(fragment, self)
            elif content_type is tls.ContentType.APPLICATION_DATA:
                msg = AppDataMessage.deserialize(fragment, self)
            else:
                raise ValueError("Content type unknow")

        self.msg.store_received_msg(msg)

        if isinstance(msg, msg_class):
            return msg
        else:
            if optional:
                self.queued_msg = msg
                return None
            else:
                raise FatalAlert(
                    "Unexpected message received: {}, expected: {}".format(
                        type(msg), msg_class
                    ),
                    tls.AlertDescription.UNEXPECTED_MESSAGE,
                )

    def update_keys(self):
        self.premaster_secret = self.key_exchange.agree_on_premaster_secret()
        self.generate_master_secret(self.msg.server_key_exchange)
        self.key_deriviation()

    def update(self, **kwargs):
        for argname, val in kwargs.items():
            if argname == "version":
                self.version = val
                self.version = val
                # stupid TLS1.3 RFC: let the message look like TLS1.2
                # to support not compliant middleboxes. :-(
                self.record_layer_version = min(val, tls.Version.TLS12)
            elif argname == "cipher_suite":
                self.update_cipher_suite(val)
                key_ex = mappings.key_exchange_algo[self.key_exchange_method]
                self.key_exchange = key_ex.cls(self, self.recorder)
            elif argname == "server_random":
                self.server_random = val
            elif argname == "client_random":
                self.client_random = val
            elif argname == "named_curve":
                self.named_curve = val
            elif argname == "remote_public_key":
                self.remote_public_key = val
            elif argname == "client_version_sent":
                self.client_version_sent = val
            elif argname == "server_hello":
                self.server_hello_received(val)
            else:
                raise ValueError(
                    'Update connection: unknown argument "{}" given'.format(argname)
                )

    def _check_update_write_state(self):
        if self._update_write_state:
            state = self.get_pending_write_state(self.entity)
            self.record_layer.update_write_state(state)
            self._update_write_state = False

    def update_write_state(self):
        self._update_write_state = True

    def update_read_state(self):
        if self.entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER
        else:
            entity = tls.Entity.CLIENT
        state = self.get_pending_write_state(entity)
        self.record_layer.update_read_state(state)

    def init_msg_hash(self):
        self._msg_hash_queue = ProtocolData()
        self._msg_hash = None
        self._msg_hash_active = True

        self._debug = []

    def update_msg_hash(self, msg):
        self._debug.append(msg)
        if not self._msg_hash_active:
            return
        if self.hash_algo is None:
            # cipher suite not yet negotiated, no hash algo available yet
            self._msg_hash_queue.extend(msg)
        else:
            if self._msg_hash is None:
                self._msg_hash = hashes.Hash(self.hmac_algo())
                self._msg_hash.update(self._msg_hash_queue)
                self._msg_hash_queue = None
            self._msg_hash.update(msg)

    def finalize_msg_hash(self, intermediate=False):
        if intermediate:
            hash_tmp = self._msg_hash.copy()
            return hash_tmp.finalize()
        val = self._msg_hash.finalize()
        self._msg_hash_active = False
        self._msg_hash = None
        self._msg_hash_queue = None
        return val

    def update_cipher_suite(self, cipher_suite):
        if self.version == tls.Version.TLS13:
            pass
        else:
            # Dirty: We extract key exhange method, cipher and hash from
            # the enum name.
            res = re.match(r"TLS_(.*)_WITH_(.+)_([^_]+)", cipher_suite.name)
            if not res:
                raise FatalAlert(
                    "Negotiated cipher suite {} not supported".format(
                        cipher_suite.name
                    ),
                    tls.AlertDescription.HandshakeFailure,
                )
            key_exchange_method = tls.KeyExchangeAlgorithm.str2enum(res.group(1))
            cipher = tls.SupportedCipher.str2enum(res.group(2))
            hash_primitive = tls.SupportedHash.str2enum(res.group(3))
            if key_exchange_method is None or cipher is None or hash_primitive is None:
                raise FatalAlert(
                    "Negotiated cipher suite {} not supported".format(
                        cipher_suite.name
                    ),
                    tls.AlertDescription.HandshakeFailure,
                )
            self.key_exchange_method = key_exchange_method
            self.cipher = cipher
            self.hash_primitive = hash_primitive
            (
                self.cipher_primitive,
                self.cipher_algo,
                self.cipher_type,
                self.enc_key_len,
                self.block_size,
                self.iv_len,
            ) = mappings.supported_ciphers[cipher]
            (
                self.hash_algo,
                self.mac_len,
                self.mac_key_len,
                self.hmac_algo,
            ) = mappings.supported_macs[hash_primitive]
            if self.cipher_type == tls.CipherType.AEAD:
                self.mac_key_len = 0
        logging.debug("hash_primitive: {}".format(self.hash_primitive.name))
        logging.debug("cipher_primitive: {}".format(self.cipher_primitive.name))

    def _hmac_func(self, secret, msg):
        hmac_object = hmac.HMAC(secret, self.hmac_algo())
        hmac_object.update(msg)
        return hmac_object.finalize()

    def _expand(self, secret, seed, size):
        out = b""
        ax = bytes(seed)
        while len(out) < size:
            ax = self._hmac_func(secret, ax)
            out = out + self._hmac_func(secret, ax + seed)
        return out[:size]

    def prf(self, secret, label, seed, size):
        return self._expand(secret, label + seed, size)

    def generate_master_secret(self, server_key_exchange):
        self.recorder.trace(pre_master_secret=self.premaster_secret)
        self.master_secret = ProtocolData(
            self.prf(
                self.premaster_secret,
                b"master secret",
                self.client_random + self.server_random,
                48,
            )
        )
        logging.info("premaster_secret: {}".format(self.premaster_secret.dump()))
        logging.info("master_secret: {}".format(self.master_secret.dump()))
        self.recorder.trace(master_secret=self.master_secret)

        return

    def key_deriviation(self):

        key_material = self.prf(
            self.master_secret,
            b"key expansion",
            self.server_random + self.client_random,
            2 * (self.mac_key_len + self.enc_key_len + self.iv_len),
        )
        key_material = ProtocolData(key_material)
        self.client_write_mac_key, offset = key_material.unpack_bytes(
            0, self.mac_key_len
        )
        self.server_write_mac_key, offset = key_material.unpack_bytes(
            offset, self.mac_key_len
        )
        self.client_write_key, offset = key_material.unpack_bytes(
            offset, self.enc_key_len
        )
        self.server_write_key, offset = key_material.unpack_bytes(
            offset, self.enc_key_len
        )
        self.client_write_iv, offset = key_material.unpack_bytes(offset, self.iv_len)
        self.server_write_iv, offset = key_material.unpack_bytes(offset, self.iv_len)

        self.recorder.trace(client_write_mac_key=self.client_write_mac_key)
        self.recorder.trace(server_write_mac_key=self.server_write_mac_key)
        self.recorder.trace(client_write_key=self.client_write_key)
        self.recorder.trace(server_write_key=self.server_write_key)
        self.recorder.trace(client_write_iv=self.client_write_iv)
        self.recorder.trace(server_write_iv=self.server_write_iv)
        logging.info(
            "client_write_mac_key: {}".format(self.client_write_mac_key.dump())
        )
        logging.info(
            "server_write_mac_key: {}".format(self.server_write_mac_key.dump())
        )
        logging.info("client_write_key: {}".format(self.client_write_key.dump()))
        logging.info("server_write_key: {}".format(self.server_write_key.dump()))
        logging.info("client_write_iv: {}".format(self.client_write_iv.dump()))
        logging.info("server_write_iv: {}".format(self.server_write_iv.dump()))

    def get_pending_write_state(self, entity):
        if entity == tls.Entity.CLIENT:
            enc_key = self.client_write_key
            mac_key = self.client_write_mac_key
            iv_value = self.client_write_iv
        else:
            enc_key = self.server_write_key
            mac_key = self.server_write_mac_key
            iv_value = self.server_write_iv

        return tls.StateUpdateParams(
            cipher_primitive=self.cipher_primitive,
            cipher_algo=self.cipher_algo,
            cipher_type=self.cipher_type,
            block_size=self.block_size,
            enc_key=enc_key,
            mac_key=mac_key,
            iv_value=iv_value,
            iv_len=self.iv_len,
            mac_len=self.mac_len,
            hash_algo=self.hash_algo,
            compression_method=self.compression_method,
            encrypt_then_mac=self.encrypt_then_mac,
        )
