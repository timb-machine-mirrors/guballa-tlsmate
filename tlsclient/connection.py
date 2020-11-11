# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import inspect
import logging
import os
import io
import traceback as tb
import time
from tlsclient.exception import FatalAlert, TlsConnectionClosedError, TlsMsgTimeoutError
from tlsclient import messages as msg
import tlsclient.constants as tls
from tlsclient import pdu
from tlsclient.messages import (
    HandshakeMessage,
    ChangeCipherSpecMessage,
    AppDataMessage,
    Alert,
    Any,
    SSL2Message,
)
from tlsclient import utils
import tlsclient.structures as structs
import tlsclient.key_exchange as kex


def get_random_value():
    random = bytearray()
    random.extend(pdu.pack_uint32(int(time.time())))
    random.extend(os.urandom(28))
    return random


class TlsDefragmenter(object):
    def __init__(self, record_layer):
        self._record_bytes = bytearray()
        self._msg = bytearray()
        self._content_type = None
        self._version = None
        self._ultimo = None
        self._record_layer = record_layer

    def _get_bytes(self, nbr):
        while len(self._record_bytes) < nbr:
            timeout = self._ultimo - time.time()
            if timeout <= 0:
                raise TlsMsgTimeoutError
            rl_msg = self._record_layer.wait_rl_msg(timeout)
            self._content_type = rl_msg.content_type
            self._version = rl_msg.version
            self._record_bytes.extend(rl_msg.fragment)
        ret = self._record_bytes[:nbr]
        self._record_bytes = self._record_bytes[nbr:]
        return ret

    def _get_all_bytes(self):
        ret = self._record_bytes
        self._record_bytes = bytearray()
        return ret

    def get_message(self, timeout):
        self._ultimo = time.time() + (timeout / 1000)
        message = self._get_bytes(1)
        if self._content_type is tls.ContentType.ALERT:
            message.extend(self._get_bytes(1))
            return structs.UpperLayerMsg(
                content_type=self._content_type, msg_type=None, msg=message
            )
        elif self._content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
            msg_type, offset = pdu.unpack_uint8(message, 0)
            msg_type = tls.CCSType.val2enum(msg_type, alert_on_failure=True)
            return structs.UpperLayerMsg(
                content_type=self._content_type, msg_type=msg_type, msg=bytes(message)
            )
        elif self._content_type is tls.ContentType.HANDSHAKE:
            message.extend(self._get_bytes(3))
            msg_type, offset = pdu.unpack_uint8(message, 0)
            msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
            length, offset = pdu.unpack_uint24(message, offset)
            message.extend(self._get_bytes(length))
            return structs.UpperLayerMsg(
                content_type=self._content_type, msg_type=msg_type, msg=bytes(message)
            )
        elif self._content_type is tls.ContentType.APPLICATION_DATA:
            return structs.UpperLayerMsg(
                content_type=self._content_type,
                msg_type=None,
                msg=bytes(message + self._get_all_bytes()),
            )
        elif self._content_type is tls.ContentType.SSL2:
            return structs.UpperLayerMsg(
                content_type=self._content_type,
                msg_type=None,
                msg=bytes(message + self._get_all_bytes()),
            )
        else:
            raise ValueError(f"content type {self._content_type} unknown")


class TlsConnectionMsgs(object):

    map_msg2attr = {
        tls.HandshakeType.HELLO_REQUEST: None,
        tls.HandshakeType.CLIENT_HELLO: "client_hello",
        tls.HandshakeType.SERVER_HELLO: "server_hello",
        tls.HandshakeType.NEW_SESSION_TICKET: None,
        tls.HandshakeType.END_OF_EARLY_DATA: None,
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: "encrypted_extensions",
        tls.HandshakeType.CERTIFICATE: "_certificate",
        tls.HandshakeType.SERVER_KEY_EXCHANGE: "server_key_exchange",
        tls.HandshakeType.CERTIFICATE_REQUEST: None,
        tls.HandshakeType.SERVER_HELLO_DONE: "server_hello_done",
        tls.HandshakeType.CERTIFICATE_VERIFY: None,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: None,
        tls.HandshakeType.FINISHED: "_finished",
        tls.HandshakeType.KEY_UPDATE: None,
        tls.HandshakeType.COMPRESSED_CERTIFICATE: None,
        tls.HandshakeType.EKT_KEY: None,
        tls.HandshakeType.MESSAGE_HASH: None,
        tls.CCSType.CHANGE_CIPHER_SPEC: "_change_cipher_spec",
        tls.ContentType.ALERT: "_alert",
    }

    def __init__(self):
        self.client_hello = None
        self.server_hello = None
        self.encrypted_extensions = None
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

    def store_msg(self, msg, received=True):
        attr = self.map_msg2attr.get(msg.msg_type, None)
        if attr is not None:
            if attr.startswith("_"):
                prefix = "server" if received else "client"
                attr = prefix + attr
            setattr(self, attr, msg)


class TlsConnection(object):
    def __init__(self, connection_msgs, entity, record_layer, recorder, kdf):
        self.msg = connection_msgs
        self.defragmenter = TlsDefragmenter(record_layer)
        self.received_data = bytearray()
        self.awaited_msg = None
        self.queued_msg = None
        self.record_layer = record_layer
        self.record_layer_version = tls.Version.TLS10
        self._msg_hash = None
        self._msg_hash_queue = None
        self._msg_hash_active = False
        self.recorder = recorder
        self.kdf = kdf
        self._new_session_id = None
        self._finished_treated = False
        self.ticket_sent = False
        self.abbreviated_hs = False
        self.session_id_sent = None
        self.handshake_completed = False
        self.alert_received = False

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

    def __enter__(self):
        logging.debug("New TLS connection created")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            logging.debug("FatalAlter exception received")
            str_io = io.StringIO()
            tb.print_exception(exc_type, exc_value, traceback, file=str_io)
            logging.debug(str_io.getvalue())
            if not self.alert_received:
                self.send(
                    Alert(level=tls.AlertLevel.FATAL, description=exc_value.description)
                )
        elif exc_type is TlsConnectionClosedError:
            logging.debug("connected closed, probably by peer")
        elif exc_type is TlsMsgTimeoutError:
            logging.debug(f"timeout occured while waiting for {self.awaited_msg}")
        self.record_layer.close_socket()
        logging.debug("TLS connection closed")
        return exc_type in [FatalAlert, TlsConnectionClosedError, TlsMsgTimeoutError]

    def set_client(self, client):
        self.client = client
        return self

    def get_key_share(self, group):
        key_share = kex.instantiate_named_group(group, self, self.recorder)
        self.key_shares[group] = key_share
        return key_share.get_key_share()

    def generate_client_hello(self, msg_cls):
        msg = self.client.client_hello()
        self.on_sending_client_hello(msg)
        return msg

    def generate_client_key_exchange(self, cls):
        key_ex_type = self.cs_details.key_algo_struct.key_ex_type
        if self.key_exchange is None and key_ex_type is tls.KeyExchangeType.RSA:
            self.key_exchange = kex.RsaKeyExchange(self, self.recorder)
        self.premaster_secret = self.key_exchange.get_shared_secret()
        self.recorder.trace(pre_master_secret=self.premaster_secret)
        logging.info(f"premaster_secret: {pdu.dump(self.premaster_secret)}")
        msg = cls()
        transferable_key = self.key_exchange.get_transferable_key()
        if key_ex_type is tls.KeyExchangeType.RSA:
            msg.rsa_encrypted_pms = transferable_key
        elif key_ex_type is tls.KeyExchangeType.ECDH:
            msg.ecdh_public = transferable_key
        elif key_ex_type is tls.KeyExchangeType.DH:
            msg.dh_public = transferable_key
        self._post_sending_hook = self.update_keys
        return msg

    def post_generate_finished(self):
        ciph = self.cs_details.cipher_struct
        c_app_tr_secret = self.kdf.hkdf_expand_label(
            self.master_secret,
            "c ap traffic",
            self.server_finished_digest,
            self.cs_details.mac_struct.key_len,
        )
        logging.debug(f"c_app_tr_secret: {pdu.dump(c_app_tr_secret)}")
        c_enc = self.kdf.hkdf_expand_label(c_app_tr_secret, "key", b"", ciph.key_len)
        c_iv = self.kdf.hkdf_expand_label(c_app_tr_secret, "iv", b"", ciph.iv_len)

        self.record_layer.update_state(
            structs.StateUpdateParams(
                cipher=ciph,
                mac=None,
                keys=structs.SymmetricKeys(enc=c_enc, mac=None, iv=c_iv),
                compr=None,
                enc_then_mac=False,
                version=self.version,
                is_write_state=True,
            )
        )

    def generate_finished(self, cls):
        intermediate = not self._finished_treated
        hash_val = self.kdf.finalize_msg_digest(intermediate=intermediate)
        if self.version is tls.Version.TLS13:
            # TODO: server side implementation
            finished_key = self.kdf.hkdf_expand_label(
                self.c_hs_tr_secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            val = self.kdf.hkdf_extract(hash_val, finished_key)
            self._post_sending_hook = self.post_generate_finished

        else:
            if self.entity == tls.Entity.CLIENT:
                label = b"client finished"
            else:
                label = b"server finished"
            val = self.kdf.prf(self.master_secret, label, hash_val, 12)
            self.update_write_state()
        self.recorder.trace(msg_digest_finished_sent=hash_val)
        self.recorder.trace(verify_data_finished_sent=val)
        logging.debug(f"Finished.verify_data(out): {pdu.dump(val)}")
        msg = cls()
        msg.verify_data = val
        if self._finished_treated:
            self.handshake_completed = True
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
            logging.info(f"session_id: {pdu.dump(msg.session_id)}")
        logging.info(f"client_random: {pdu.dump(msg.random)}")
        logging.info(f"client_version: {msg.client_version}")
        for cipher_suite in msg.cipher_suites:
            logging.info(f"cipher suite: 0x{cipher_suite.value:04x} {cipher_suite}")
        if msg.extensions is not None:
            for extension in msg.extensions:
                ext = extension.extension_id
                logging.info(f"extension {ext.value} {ext}")
                if ext is tls.Extension.SESSION_TICKET:
                    self.ticket_sent = extension.ticket is not None
        self.kdf.start_msg_digest()

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
        for message in messages:
            logging.info(f"Sending {message.msg_type}")
            self._post_sending_hook = None
            if inspect.isclass(message):
                message = self.generate_outgoing_msg(message)
            else:
                self.on_sending_message(message)
            msg_data = message.serialize(self)
            self.msg.store_msg(message, received=False)
            if message.content_type == tls.ContentType.HANDSHAKE:
                self.kdf.update_msg_digest(msg_data)

            self.record_layer.send_message(
                structs.RecordLayerMsg(
                    content_type=message.content_type,
                    version=self.record_layer_version,
                    fragment=msg_data,
                )
            )
            # Some actions must be delayed after the message is actually sent
            if self._post_sending_hook is not None:
                self._post_sending_hook()

        self.record_layer.flush()

    def on_server_hello_tls13(self, msg):
        key_share_ext = msg.get_extension(tls.Extension.KEY_SHARE)
        if key_share_ext is None:
            raise FatalAlert(
                "ServerHello-TLS13: extension KEY_SHARE not present",
                tls.AlertDescription.HANDSHAKE_FAILURE,
            )
        share_entry = key_share_ext.key_shares[0]
        self.key_exchange = self.key_shares[share_entry.group]
        self.key_exchange.set_remote_key(
            share_entry.key_exchange, group=share_entry.group
        )
        self.premaster_secret = self.key_exchange.get_shared_secret()
        logging.info(f"premaster_secret: {pdu.dump(self.premaster_secret)}")
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
                logging.info(f"master_secret: {pdu.dump(self.master_secret)}")
                self.key_derivation()
            else:
                self._new_session_id = msg.session_id
        self.encrypt_then_mac = (
            msg.get_extension(tls.Extension.ENCRYPT_THEN_MAC) is not None
        )
        self.extended_ms = (
            msg.get_extension(tls.Extension.EXTENDED_MASTER_SECRET) is not None
        )

    def on_server_hello_received(self, msg):
        logging.info(f"server random: {pdu.dump(msg.random)}")
        logging.info(f"version: {msg.version}")
        logging.info(f"cipher suite: 0x{msg.cipher_suite.value:04x} {msg.cipher_suite}")
        for extension in msg.extensions:
            extension = extension.extension_id
            logging.info(f"extension {extension.value} {extension}")
        self.version = msg.get_version()
        self.update_cipher_suite(msg.cipher_suite)
        self.record_layer_version = min(self.version, tls.Version.TLS12)
        self.server_random = msg.random
        if self.version is tls.Version.TLS13:
            self.on_server_hello_tls13(msg)
        else:
            self.on_server_hello_tls12(msg)

    def on_server_key_exchange_received(self, msg):
        if msg.ec is not None:
            if msg.ec.signed_params is not None and self.version is tls.Version.TLS12:
                kex.verify_signed_params(
                    msg.ec, self.msg, self.cs_details.key_algo_struct.default_sig_scheme
                )

            if msg.ec.named_curve is not None:
                logging.info(f"named curve: {msg.ec.named_curve}")
                self.key_exchange = kex.instantiate_named_group(
                    msg.ec.named_curve, self, self.recorder
                )
                self.key_exchange.set_remote_key(msg.ec.public)
        elif msg.dh is not None:
            dh = msg.dh
            if dh.signed_params is not None and self.version is tls.Version.TLS12:
                kex.verify_signed_params(
                    msg.dh, self.msg, self.cs_details.key_algo_struct.default_sig_scheme
                )
            self.key_exchange = kex.DhKeyExchange(self, self.recorder)
            self.key_exchange.set_remote_key(
                dh.public_key, g_val=dh.g_val, p_val=dh.p_val
            )

    def on_change_cipher_spec_received(self, msg):
        if self.version is not tls.Version.TLS13:
            self.update_read_state()
            intermediate = not self._finished_treated
            self._pre_finished_digest = self.kdf.finalize_msg_digest(
                intermediate=intermediate
            )

    def on_finished_received(self, msg):
        ciph = self.cs_details.cipher_struct
        logging.debug(f"Finished.verify_data(in): {pdu.dump(msg.verify_data)}")

        if self.version is tls.Version.TLS13:
            finished_key = self.kdf.hkdf_expand_label(
                self.s_hs_tr_secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            calc_verify_data = self.kdf.hkdf_extract(
                self.pre_server_finished_digest, finished_key
            )
            logging.debug(f"calc. verify_data: {pdu.dump(calc_verify_data)}")
            if calc_verify_data != msg.verify_data:
                raise FatalAlert(
                    "Received Finished: verify_data does not match",
                    tls.AlertDescription.DECRYPT_ERROR,
                )
            self.server_finished_digest = self.kdf.finalize_msg_digest(
                intermediate=True
            )
            s_app_tr_secret = self.kdf.hkdf_expand_label(
                self.master_secret,
                "s ap traffic",
                self.server_finished_digest,
                self.cs_details.mac_struct.key_len,
            )
            logging.debug(f"s_app_tr_secret: {pdu.dump(s_app_tr_secret)}")
            c_enc = self.kdf.hkdf_expand_label(
                s_app_tr_secret, "key", b"", ciph.key_len
            )
            c_iv = self.kdf.hkdf_expand_label(s_app_tr_secret, "iv", b"", ciph.iv_len)

            self.record_layer.update_state(
                structs.StateUpdateParams(
                    cipher=ciph,
                    mac=None,
                    keys=structs.SymmetricKeys(enc=c_enc, mac=None, iv=c_iv),
                    compr=None,
                    enc_then_mac=False,
                    version=self.version,
                    is_write_state=False,
                )
            )

        else:
            if self.entity == tls.Entity.CLIENT:
                label = b"server finished"
            else:
                label = b"client finished"
            val = self.kdf.prf(self.master_secret, label, self._pre_finished_digest, 12)
            self.recorder.trace(msg_digest_finished_rec=self._pre_finished_digest)
            self.recorder.trace(verify_data_finished_rec=msg.verify_data)
            self.recorder.trace(verify_data_finished_calc=val)
            if msg.verify_data != val:
                raise FatalAlert(
                    "Received Finidhed: verify_data does not match",
                    tls.AlertDescription.BAD_RECORD_MAC,
                )
        logging.info("Received Finished sucessfully verified")
        if self._finished_treated:
            self.handshake_completed = True
            logging.info("Handshake finished, secure connection established")
        self._finished_treated = True
        return self

    def on_new_session_ticket_received(self, msg):
        self.client.save_session_state_ticket(
            structs.SessionStateTicket(
                ticket=msg.ticket,
                lifetime=msg.lifetime,
                cipher_suite=self.cipher_suite,
                version=self.version,
                master_secret=self.master_secret,
            )
        )

    def on_encrypted_extensions_received(self, msg):
        for extension in msg.extensions:
            logging.debug(f"extension {extension.extension_id}")
            if extension.extension_id is tls.Extension.SUPPORTED_GROUPS:
                for group in extension.supported_groups:
                    logging.debug(f"supported group: {group}")

    def on_certificate_received(self, msg):
        if self.version is tls.Version.TLS13:
            self.certificate_digest = self.kdf.finalize_msg_digest(intermediate=True)

    def on_certificate_verify_received(self, msg):
        self.pre_server_finished_digest = self.kdf.finalize_msg_digest(
            intermediate=True
        )
        if self.version is tls.Version.TLS13:
            kex.verify_certificate_verify(msg, self.msg, self.certificate_digest)

    _on_msg_received = {
        tls.HandshakeType.SERVER_HELLO: on_server_hello_received,
        tls.HandshakeType.SERVER_KEY_EXCHANGE: on_server_key_exchange_received,
        tls.CCSType.CHANGE_CIPHER_SPEC: on_change_cipher_spec_received,
        tls.HandshakeType.FINISHED: on_finished_received,
        tls.HandshakeType.NEW_SESSION_TICKET: on_new_session_ticket_received,
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: on_encrypted_extensions_received,
        tls.HandshakeType.CERTIFICATE_VERIFY: on_certificate_verify_received,
        tls.HandshakeType.CERTIFICATE: on_certificate_received,
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
            self.awaited_msg = msg_class
            mb = self.defragmenter.get_message(timeout)
            if mb is None:
                return None
            if mb.content_type is tls.ContentType.HANDSHAKE:
                msg = HandshakeMessage.deserialize(mb.msg, self)
                self.kdf.update_msg_digest(mb.msg)
            elif mb.content_type is tls.ContentType.ALERT:
                self.alert_received = True
                msg = Alert.deserialize(mb.msg, self)
            elif mb.content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
                msg = ChangeCipherSpecMessage.deserialize(mb.msg, self)
            elif mb.content_type is tls.ContentType.APPLICATION_DATA:
                msg = AppDataMessage.deserialize(mb.msg, self)
            elif mb.content_type is tls.ContentType.SSL2:
                msg = SSL2Message.deserialize(mb.msg, self)
            else:
                raise ValueError("Content type unknow")

            logging.info(f"Receiving {msg.msg_type}")
            self.msg.store_msg(msg, received=True)
        if (msg_class == Any) or isinstance(msg, msg_class):
            self.on_msg_received(msg)
            return msg
        else:
            if optional:
                self.queued_msg = msg
                return None
            else:
                logging.debug("unexpected message received")
                raise FatalAlert(
                    (
                        f"Unexpected message received: {msg.msg_type}, "
                        f"expected: {msg_class.msg_type}"
                    ),
                    tls.AlertDescription.UNEXPECTED_MESSAGE,
                )

    def update_keys(self):
        if not self.cs_details.full_hs:
            raise FatalAlert(
                f"full handshake not supported for {self.cipher_suite}",
                tls.AlertDescription.HANDSHAKE_FAILURE,
            )
        self.generate_master_secret()
        self.key_derivation()

    def update_write_state(self):
        state = self.get_pending_write_state(self.entity)
        self.record_layer.update_state(state)

    def update_read_state(self):
        if self.entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER
        else:
            entity = tls.Entity.CLIENT
        state = self.get_pending_write_state(entity)
        self.record_layer.update_state(state)

    def update_cipher_suite(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.cs_details = utils.get_cipher_suite_details(cipher_suite)

        if not self.cs_details.full_hs:
            logging.debug(
                f"full handshake for cipher suite {cipher_suite} not supported"
            )
            return

        if self.version < tls.Version.TLS12:
            self.kdf.set_msg_digest_algo(None)
        else:
            self.kdf.set_msg_digest_algo(self.cs_details.mac_struct.hmac_algo)
        logging.debug(f"hash_primitive: {self.cs_details.mac}")
        logging.debug(f"cipher_primitive: {self.cs_details.cipher_struct.primitive}")

    def generate_master_secret(self):
        if self.extended_ms:
            msg_digest = self.kdf.finalize_msg_digest(intermediate=True)
            self.master_secret = self.kdf.prf(
                self.premaster_secret, b"extended master secret", msg_digest, 48
            )
        else:
            self.master_secret = self.kdf.prf(
                self.premaster_secret,
                b"master secret",
                self.client_random + self.server_random,
                48,
            )

        logging.info(f"master_secret: {pdu.dump(self.master_secret)}")
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
        ciph = self.cs_details.cipher_struct
        mac = self.cs_details.mac_struct
        early_secret = self.kdf.hkdf_extract(None, b"")
        logging.debug(f"early_secret: {pdu.dump(early_secret)}")
        empty_msg_digest = self.kdf.empty_msg_digest()
        logging.debug(f"empty msg digest: {pdu.dump(empty_msg_digest)}")
        derived = self.kdf.hkdf_expand_label(
            early_secret, "derived", empty_msg_digest, mac.key_len
        )

        handshake_secret = self.kdf.hkdf_extract(self.premaster_secret, derived)
        logging.debug(f"handshake secret: {pdu.dump(handshake_secret)}")
        hello_digest = self.kdf.finalize_msg_digest(intermediate=True)
        logging.debug(f"hello_digest: {pdu.dump(hello_digest)}")
        c_hs_tr_secret = self.kdf.hkdf_expand_label(
            handshake_secret, "c hs traffic", hello_digest, mac.key_len
        )
        c_enc = self.kdf.hkdf_expand_label(c_hs_tr_secret, "key", b"", ciph.key_len)
        c_iv = self.kdf.hkdf_expand_label(c_hs_tr_secret, "iv", b"", ciph.iv_len)
        s_hs_tr_secret = self.kdf.hkdf_expand_label(
            handshake_secret, "s hs traffic", hello_digest, mac.key_len
        )
        s_enc = self.kdf.hkdf_expand_label(s_hs_tr_secret, "key", b"", ciph.key_len)
        s_iv = self.kdf.hkdf_expand_label(s_hs_tr_secret, "iv", b"", ciph.iv_len)
        logging.info(f"client hs traffic secret: {pdu.dump(c_hs_tr_secret)}")
        logging.info(f"server hs traffic secret: {pdu.dump(s_hs_tr_secret)}")
        self.s_hs_tr_secret = s_hs_tr_secret
        self.c_hs_tr_secret = c_hs_tr_secret

        self.record_layer.update_state(
            structs.StateUpdateParams(
                cipher=ciph,
                mac=None,
                keys=structs.SymmetricKeys(enc=c_enc, mac=None, iv=c_iv),
                compr=None,
                enc_then_mac=False,
                version=self.version,
                is_write_state=True,
            )
        )
        self.record_layer.update_state(
            structs.StateUpdateParams(
                cipher=ciph,
                mac=None,
                keys=structs.SymmetricKeys(enc=s_enc, mac=None, iv=s_iv),
                compr=None,
                enc_then_mac=False,
                version=self.version,
                is_write_state=False,
            )
        )

        derived = self.kdf.hkdf_expand_label(
            handshake_secret, "derived", empty_msg_digest, mac.key_len
        )

        self.master_secret = self.kdf.hkdf_extract(None, derived)

    def key_derivation(self):
        ciph = self.cs_details.cipher_struct
        if ciph.c_type is tls.CipherType.AEAD:
            mac_len = 0
        else:
            mac_len = self.cs_details.mac_struct.key_len
        key_material = self.kdf.prf(
            self.master_secret,
            b"key expansion",
            self.server_random + self.client_random,
            2 * (mac_len + ciph.key_len + ciph.iv_len),
        )
        c_mac, offset = pdu.unpack_bytes(key_material, 0, mac_len)
        s_mac, offset = pdu.unpack_bytes(key_material, offset, mac_len)
        c_enc, offset = pdu.unpack_bytes(key_material, offset, ciph.key_len)
        s_enc, offset = pdu.unpack_bytes(key_material, offset, ciph.key_len)
        c_iv, offset = pdu.unpack_bytes(key_material, offset, ciph.iv_len)
        s_iv, offset = pdu.unpack_bytes(key_material, offset, ciph.iv_len)

        self.recorder.trace(client_write_mac_key=c_mac)
        self.recorder.trace(server_write_mac_key=s_mac)
        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(server_write_key=s_enc)
        self.recorder.trace(client_write_iv=c_iv)
        self.recorder.trace(server_write_iv=s_iv)
        logging.info(f"client_write_mac_key: {pdu.dump(c_mac)}")
        logging.info(f"server_write_mac_key: {pdu.dump(s_mac)}")
        logging.info(f"client_write_key: {pdu.dump(c_enc)}")
        logging.info(f"server_write_key: {pdu.dump(s_enc)}")
        logging.info(f"client_write_iv: {pdu.dump(c_iv)}")
        logging.info(f"server_write_iv: {pdu.dump(s_iv)}")
        self.client_write_keys = structs.SymmetricKeys(mac=c_mac, enc=c_enc, iv=c_iv)
        self.server_write_keys = structs.SymmetricKeys(mac=s_mac, enc=s_enc, iv=s_iv)

    def get_pending_write_state(self, entity):
        if entity is tls.Entity.CLIENT:
            keys = self.client_write_keys
        else:
            keys = self.server_write_keys

        return structs.StateUpdateParams(
            cipher=self.cs_details.cipher_struct,
            mac=self.cs_details.mac_struct,
            keys=keys,
            compr=self.compression_method,
            enc_then_mac=self.encrypt_then_mac,
            version=self.version,
            is_write_state=(entity is tls.Entity.CLIENT),
        )

    def handshake(self):
        self.send(msg.ClientHello)
        self.wait(msg.ServerHello)
        if self.version is tls.Version.TLS13:
            self.wait(msg.ChangeCipherSpec, optional=True)
            self.wait(msg.EncryptedExtensions)
            if not self.abbreviated_hs:
                self.wait(msg.Certificate)
                self.wait(msg.CertificateVerify)
            self.wait(msg.Finished)
            self.send(msg.Finished)
        else:
            if self.abbreviated_hs:
                self.wait(msg.ChangeCipherSpec)
                self.wait(msg.Finished)
                self.send(msg.ChangeCipherSpec, msg.Finished)
            else:
                cert = True
                if (
                    self.cs_details.key_algo_struct.key_auth
                    is tls.KeyAuthentication.NONE
                ):
                    if (
                        self.cs_details.key_algo_struct.key_ex_type
                        is not tls.KeyExchangeType.RSA
                    ):
                        cert = False
                if cert:
                    self.wait(msg.Certificate)
                if self.cs_details.key_algo in [
                    tls.KeyExchangeAlgorithm.DHE_DSS,
                    tls.KeyExchangeAlgorithm.DHE_RSA,
                    tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
                    tls.KeyExchangeAlgorithm.ECDHE_RSA,
                    tls.KeyExchangeAlgorithm.DH_ANON,
                ]:
                    self.wait(msg.ServerKeyExchange)
                self.wait(msg.ServerHelloDone)
                self.send(msg.ClientKeyExchange)
                self.send(msg.ChangeCipherSpec)
                self.send(msg.Finished)
                self.wait(msg.ChangeCipherSpec)
                self.wait(msg.Finished)
                # TODO: check for NewSessionTicket
