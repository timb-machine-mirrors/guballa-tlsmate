# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import inspect
import logging
import os
import time
from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls
from tlsclient.messages import (
    HandshakeMessage,
    ChangeCipherSpecMessage,
    AppDataMessage,
    Alert,
    Any,
)
from tlsclient import mappings
import tlsclient.structures as structs
import tlsclient.key_exchange as kex


def get_random_value():
    random = ProtocolData()
    random.append_uint32(int(time.time()))
    random.extend(os.urandom(28))
    return random


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
    def __init__(self, connection_msgs, entity, record_layer, recorder, hmac_prf):
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
        self.hmac_prf = hmac_prf
        self._new_session_id = None
        self._finished_treated = False
        self.ticket_sent = False
        self.abbreviated_hs = False
        self.session_id_sent = None

        # general
        self.entity = entity
        self.version = None
        self.client_version_sent = None
        self.cipher_suite = None
        self.compression_method = None
        self.encrypt_then_mac = False
        self.key_shares = {}

        # key exchange
        self.client_random = None
        self.server_random = None
        self.named_curve = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.premaster_secret = None
        self.master_secret = None
        self.key_exchange = None
        self.key_ex_type = None
        self.key_auth = None

        self.client_write_keys = None
        self.server_write_keys = None
        self.cipher = None
        self.mac = None

        self.cipher_suite_supported = False

    def __enter__(self):
        logging.debug("New TLS connection created")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            logging.debug("exception: " + exc_value.message)
            self.send(
                Alert(level=tls.AlertLevel.FATAL, description=exc_value.description)
            )
            self.record_layer.close_socket()
            return True
        self.record_layer.close_socket()
        logging.debug("TLS connection closed")
        return False

    def set_client(self, client):
        self.client = client
        return self

    def get_key_share(self, group):
        key_share = kex.instantiate_named_group(group, self, self.recorder)
        self.key_shares[group] = key_share
        return key_share.get_key_share()

    # TODO: Move this to the extension module, as it is a static method anyway
    def get_extension(self, extensions, ext_id):
        for ext in extensions:
            if ext.extension_id == ext_id:
                return ext
        return None

    def generate_client_hello(self, msg_cls):
        msg = self.client.client_hello()
        self.on_sending_client_hello(msg)
        return msg

    def generate_client_key_exchange(self, cls):
        if self.key_exchange is None and self.key_ex_type is tls.KeyExchangeType.RSA:
            self.key_exchange = kex.RsaKeyExchange(self, self.recorder)
        self.premaster_secret = self.key_exchange.get_shared_secret()
        self.recorder.trace(pre_master_secret=self.premaster_secret)
        logging.info(f"premaster_secret: {self.premaster_secret.dump()}")
        msg = cls()
        transferable_key = self.key_exchange.get_transferable_key()
        if self.key_ex_type is tls.KeyExchangeType.RSA:
            msg.rsa_encrypted_pms = transferable_key
        elif self.key_ex_type is tls.KeyExchangeType.ECDH:
            msg.ecdh_public = transferable_key
        elif self.key_ex_type is tls.KeyExchangeType.DH:
            msg.dh_public = transferable_key
        self._post_sending_hook = self.update_keys
        return msg

    def generate_finished(self, cls):
        intermediate = not self._finished_treated
        hash_val = self.hmac_prf.finalize_msg_digest(intermediate=intermediate)
        if self.entity == tls.Entity.CLIENT:
            label = b"client finished"
        else:
            label = b"server finished"
        val = ProtocolData(self.hmac_prf.prf(self.master_secret, label, hash_val, 12))
        self.recorder.trace(msg_digest_finished_sent=hash_val)
        self.recorder.trace(verify_data_finished_sent=val)
        logging.debug(f"Finished.verify_data(out): {val.dump()}")
        self.update_write_state()
        msg = cls()
        msg.verify_data = val
        if not self._finished_treated:
            logging.info("Handshake finished, secure connection established")
        self._finished_treated = True
        return msg

    _generate_out_msg = {
        tls.HandshakeType.CLIENT_HELLO: generate_client_hello,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: generate_client_key_exchange,
        tls.HandshakeType.FINISHED: generate_finished,
    }

    def generate_outgoing_msg(self, msg_cls):
        """Setup a message for which only the class has been provided

        Here, we also do all the funny stuff required prior sending a
        mesage, e.g. for a ClientKeyExchange the key exchange and key deriviation
        is performed here.
        """
        method = self._generate_out_msg.get(msg_cls.msg_type)
        if method is not None:
            return method(self, msg_cls)
        return msg_cls()

    def on_sending_client_hello(self, msg):
        if isinstance(msg.client_version, tls.Version):
            self.client_version_sent = msg.client_version.value
        else:
            self.client_version_sent = msg.client_version
        self.client_version_sent = msg.client_version
        if self.recorder.is_injecting():
            msg.random = self.recorder.inject(client_random=None)
        else:
            if msg.random is None:
                msg.random = get_random_value()
            self.recorder.trace(client_random=msg.random)
        self.client_random = msg.random
        if len(msg.session_id):
            self.session_id_sent = msg.session_id
            logging.info(f"session_id: {msg.session_id.dump()}")
        logging.info(f"client_random: {msg.random.dump()}")
        logging.info(f"client_version: {msg.client_version.name}")
        for cipher_suite in msg.cipher_suites:
            logging.info(
                f"cipher suite: 0x{cipher_suite.value:04x} {cipher_suite.name}"
            )
        if msg.extensions is not None:
            for extension in msg.extensions:
                ext = extension.extension_id
                logging.info(f"extension {ext.value} {ext.name}")
                if ext is tls.Extension.SESSION_TICKET:
                    self.ticket_sent = extension.ticket is not None
        self.hmac_prf.start_msg_digest()

    _on_sending_message = {tls.HandshakeType.CLIENT_HELLO: on_sending_client_hello}

    def on_sending_message(self, msg):
        """Extract relevant data from a provided message instance

        This method is called if a completely setup message (i.e. an instance)
        has been provided by the test case. Here we will extract relevant
        data that are needed for the handshake.

        A user provided ClientHello() is the most relevant use case for this
        method.
        """
        method = self._on_sending_message.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def send(self, *messages):
        for msg in messages:
            self._post_sending_hook = None
            if inspect.isclass(msg):
                msg = self.generate_outgoing_msg(msg)
            else:
                self.on_sending_message(msg)
            msg_data = msg.serialize(self)
            if msg.content_type == tls.ContentType.HANDSHAKE:
                self.hmac_prf.update_msg_digest(msg_data)
            logging.info(f"Sending {msg.msg_type.name}")

            self.record_layer.send_message(
                structs.MessageBlock(
                    content_type=msg.content_type,
                    version=self.record_layer_version,
                    fragment=msg_data,
                )
            )
            # Some actions must be delayed after the message is actually sent
            if self._post_sending_hook is not None:
                self._post_sending_hook()

        self.record_layer.flush()

    def on_server_hello_tls13(self, msg):
        key_share_ext = self.get_extension(msg.extensions, tls.Extension.KEY_SHARE)
        if key_share_ext is None:
            raise FatalAlert(
                "ServerHello-TLS13: extension KEY_SHARE not present",
                tls.AlertDescription.HANDSHAKE_FAILURE,
            )
        share_entry = key_share_ext.key_shares[0]
        self.key_exchange = self.key_shares[share_entry.group]
        self.key_exchange.set_remote_key(share_entry.key_exchange)
        self.premaster_secret = self.key_exchange.get_shared_secret()
        logging.info(f"premaster_secret: {self.premaster_secret.dump()}")
        self.tls13_key_schedule()

    def on_server_hello_tls12(self, msg):
        if len(msg.session_id):
            if msg.session_id == self.session_id_sent:
                self.abbreviated_hs = True
                # TODO: check version and ciphersuite
                if self.ticket_sent:
                    self.master_secret = self.client.session_state_ticket.master_secret
                else:
                    self.master_secret = self.client.session_state_id.master_secret
                logging.info(f"master_secret: {self.master_secret.dump()}")
                self.key_derivation()
            else:
                self._new_session_id = msg.session_id
        self.encrypt_then_mac = (
            self.get_extension(msg.extensions, tls.Extension.ENCRYPT_THEN_MAC)
            is not None
        )
        self.extended_ms = (
            self.get_extension(msg.extensions, tls.Extension.EXTENDED_MASTER_SECRET)
            is not None
        )

    def on_server_hello_received(self, msg):
        logging.info(f"server random: {msg.random.dump()}")
        logging.info(f"version: {msg.version.name}")
        logging.info(
            f"cipher suite: 0x{msg.cipher_suite.value:04x} {msg.cipher_suite.name}"
        )
        for extension in msg.extensions:
            ext = extension.extension_id
            logging.info(f"extension {ext.value} {ext.name}")
        supported_versions = self.get_extension(
            msg.extensions, tls.Extension.SUPPORTED_VERSIONS
        )
        if supported_versions is not None:
            self.version = supported_versions.versions[0]
        else:
            self.version = msg.version
        self.update_cipher_suite(msg.cipher_suite)
        self.record_layer_version = min(self.version, tls.Version.TLS12)
        self.server_random = msg.random
        if self.version is tls.Version.TLS13:
            self.on_server_hello_tls13(msg)
        else:
            self.on_server_hello_tls12(msg)

    def on_server_key_exchange_received(self, msg):
        if msg.ec is not None:
            if msg.ec.named_curve is not None:
                logging.info(f"named curve: {msg.ec.named_curve.name}")
                self.key_exchange = kex.instantiate_named_group(
                    msg.ec.named_curve, self, self.recorder
                )
                self.key_exchange.set_remote_key(msg.ec.public)
        elif msg.dh is not None:
            dh = msg.dh
            self.key_exchange = kex.DhKeyExchange(self, self.recorder)
            self.key_exchange.set_remote_key(
                dh.public_key, g_val=dh.g_val, p_val=dh.p_val
            )

    def on_change_cipher_spec_received(self, msg):
        self.update_read_state()

    def on_finished_received(self, msg):
        verify_data = ProtocolData(msg.verify_data)
        logging.debug(f"Finished.verify_data(in): {verify_data.dump()}")
        intermediate = not self._finished_treated
        hash_val = self.hmac_prf.finalize_msg_digest(intermediate=intermediate)
        if self.entity == tls.Entity.CLIENT:
            label = b"server finished"
        else:
            label = b"client finished"
        val = self.hmac_prf.prf(self.master_secret, label, hash_val, 12)
        self.recorder.trace(msg_digest_finished_rec=hash_val)
        self.recorder.trace(verify_data_finished_rec=verify_data)
        self.recorder.trace(verify_data_finished_calc=val)
        if verify_data != val:
            raise FatalAlert(
                "Received Finidhed: verify_data does not match",
                tls.AlertDescription.BAD_RECORD_MAC,
            )
        logging.info("Received Finished sucessfully verified")
        if not self._finished_treated:
            logging.info("Handshake finished, secure connection established")
        self._finished_treated = True
        return self

    def on_new_session_ticket_received(self, msg):
        self.client.save_session_state_ticket(
            structs.SessionStateTicket(
                ticket=msg.ticket,
                lifetime_hint=msg.lifetime_hint,
                cipher_suite=self.cipher_suite,
                version=self.version,
                master_secret=self.master_secret,
            )
        )

    _on_msg_received = {
        tls.HandshakeType.SERVER_HELLO: on_server_hello_received,
        tls.HandshakeType.SERVER_KEY_EXCHANGE: on_server_key_exchange_received,
        tls.CCSType.CHANGE_CIPHER_SPEC: on_change_cipher_spec_received,
        tls.HandshakeType.FINISHED: on_finished_received,
        tls.HandshakeType.NEW_SESSION_TICKET: on_new_session_ticket_received,
    }

    def on_msg_received(self, msg):
        """Called whenever a message is received before it is passed to the testcase"""
        method = self._on_msg_received.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def wait(self, msg_class, optional=False, timeout=5000):
        if self.queued_msg:
            msg = self.queued_msg
            self.queued_msg = None
        else:
            content_type, version, fragment = self.record_layer.wait_fragment(timeout)
            if content_type is tls.ContentType.HANDSHAKE:
                msg = HandshakeMessage.deserialize(fragment, self)
                self.hmac_prf.update_msg_digest(fragment)
            elif content_type is tls.ContentType.ALERT:
                msg = Alert.deserialize(fragment, self)
            elif content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                msg = ChangeCipherSpecMessage.deserialize(fragment, self)
            elif content_type is tls.ContentType.APPLICATION_DATA:
                msg = AppDataMessage.deserialize(fragment, self)
            else:
                raise ValueError("Content type unknow")

        if (msg_class == Any) or isinstance(msg, msg_class):
            self.on_msg_received(msg)
            logging.info(f"Receiving {msg.msg_type.name}")
            self.msg.store_received_msg(msg)
            return msg
        else:
            if optional:
                self.queued_msg = msg
                return None
            else:
                logging.debug("unexpected message received")
                raise FatalAlert(
                    (
                        f"Unexpected message received: {msg.msg_type.name}, "
                        f"expected: {msg_class.msg_type.name}"
                    ),
                    tls.AlertDescription.UNEXPECTED_MESSAGE,
                )

    def update_keys(self):
        self.generate_master_secret()
        self.key_derivation()

    def update_write_state(self):
        state = self.get_pending_write_state(self.entity)
        self.record_layer.update_write_state(state)
        self._update_write_state = False

    def update_read_state(self):
        if self.entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER
        else:
            entity = tls.Entity.CLIENT
        state = self.get_pending_write_state(entity)
        self.record_layer.update_read_state(state)

    def update_cipher_suite(self, cipher_suite):
        self.cipher_suite = cipher_suite
        cs_info = mappings.supported_cipher_suites.get(cipher_suite)
        if cs_info is None:
            logging.debug(
                f"full handshake for cipher suite {cipher_suite.name} not supported"
            )
            return

        if cs_info.key_ex is not None:
            key_ex = mappings.key_exchange[cs_info.key_ex]
            self.key_ex_type = key_ex.key_ex_type
            self.key_auth = key_ex.key_auth

        self.cipher = mappings.supported_ciphers[cs_info.cipher]
        self.mac = mappings.supported_macs[cs_info.mac]

        if self.version < tls.Version.TLS12:
            self.hmac_prf.set_msg_digest_algo(None)
        else:
            self.hmac_prf.set_msg_digest_algo(self.mac.hmac_algo)
        self.cipher_suite_supported = True
        logging.debug(f"hash_primitive: {cs_info.mac.name}")
        logging.debug(f"cipher_primitive: {self.cipher.primitive.name}")

    def generate_master_secret(self):
        if self.extended_ms:
            msg_digest = self.hmac_prf.finalize_msg_digest(intermediate=True)
            self.master_secret = ProtocolData(
                self.hmac_prf.prf(
                    self.premaster_secret, b"extended master secret", msg_digest, 48
                )
            )
        else:
            self.master_secret = ProtocolData(
                self.hmac_prf.prf(
                    self.premaster_secret,
                    b"master secret",
                    self.client_random + self.server_random,
                    48,
                )
            )
        logging.info(f"master_secret: {self.master_secret.dump()}")
        self.recorder.trace(master_secret=self.master_secret)
        if self._new_session_id is not None:
            self.client.save_session_state_id(
                structs.SessionStateId(
                    session_id=self._new_session_id,
                    cipher_suite=self.cipher_suite,
                    version=self.version,
                    master_secret=self.master_secret,
                )
            )
        return

    def tls13_key_schedule(self):
        early_secret = self.hmac_prf.hkdf_extract(None, b"")
        empty_msg_digest = self.hmac_prf.empty_msg_digest()
        derived = self.hmac_prf.hkdf_expand_label(
            early_secret, "derived", empty_msg_digest
        )
        handshake_secret = self.hmac_prf.hkdf_extract(self.premaster_secret, derived)
        hello_digest = self.hmac_prf.finalize_msg_digest(intermediate=True)
        client_hs_tr_sec = self.hmac_prf.hkdf_expand_label(
            handshake_secret, "c hs traffic", hello_digest
        )
        server_hs_tr_sec = self.hmac_prf.hkdf_expand_label(
            handshake_secret, "s hs traffic", hello_digest
        )
        derived = self.hmac_prf.hkdf_expand_label(
            handshake_secret, "derived", empty_msg_digest
        )
        master_secret = self.hmac_prf.hkdf_extract(None, derived)

    def key_derivation(self):
        if self.cipher.c_type is tls.CipherType.AEAD:
            iv_len = 0
        else:
            iv_len = self.cipher.iv_len
        key_material = self.hmac_prf.prf(
            self.master_secret,
            b"key expansion",
            self.server_random + self.client_random,
            2 * (self.mac.key_len + self.cipher.key_len + iv_len),
        )
        key_material = ProtocolData(key_material)
        c_mac, offset = key_material.unpack_bytes(0, self.mac.key_len)
        s_mac, offset = key_material.unpack_bytes(offset, self.mac.key_len)
        c_enc, offset = key_material.unpack_bytes(offset, self.cipher.key_len)
        s_enc, offset = key_material.unpack_bytes(offset, self.cipher.key_len)
        c_iv, offset = key_material.unpack_bytes(offset, self.cipher.iv_len)
        s_iv, offset = key_material.unpack_bytes(offset, self.cipher.iv_len)

        self.recorder.trace(client_write_mac_key=c_mac)
        self.recorder.trace(server_write_mac_key=s_mac)
        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(server_write_key=s_enc)
        self.recorder.trace(client_write_iv=c_iv)
        self.recorder.trace(server_write_iv=s_iv)
        logging.info(f"client_write_mac_key: {c_mac.dump()}")
        logging.info(f"server_write_mac_key: {s_mac.dump()}")
        logging.info(f"client_write_key: {c_enc.dump()}")
        logging.info(f"server_write_key: {s_enc.dump()}")
        logging.info(f"client_write_iv: {c_iv.dump()}")
        logging.info(f"server_write_iv: {s_iv.dump()}")
        self.client_write_keys = structs.SymmetricKeys(mac=c_mac, enc=c_enc, iv=c_iv)
        self.server_write_keys = structs.SymmetricKeys(mac=s_mac, enc=s_enc, iv=s_iv)

    def get_pending_write_state(self, entity):
        if entity is tls.Entity.CLIENT:
            keys = self.client_write_keys
        else:
            keys = self.server_write_keys

        return structs.StateUpdateParams(
            cipher=self.cipher,
            mac=self.mac,
            keys=keys,
            compr=self.compression_method,
            enc_then_mac=self.encrypt_then_mac,
            implicit_iv=(self.version <= tls.Version.TLS10),
        )
