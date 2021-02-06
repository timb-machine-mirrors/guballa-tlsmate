# -*- coding: utf-8 -*-
"""Module containing the class implementing a TLS connection
"""

import inspect
import logging
import os
import io
import traceback as tb
import time
import datetime
from tlsmate.exception import FatalAlert, TlsConnectionClosedError, TlsMsgTimeoutError
from tlsmate import messages as msg
import tlsmate.constants as tls
from tlsmate import pdu
from tlsmate.messages import (
    HandshakeMessage,
    ChangeCipherSpecMessage,
    AppDataMessage,
    Alert,
    Any,
    SSL2Message,
)
from tlsmate import utils
import tlsmate.structures as structs
import tlsmate.key_exchange as kex
from tlsmate.kdf import Kdf
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes


def get_random_value():
    """Get a value suitable for a ClientHello or ServerHello

    Returns:
        bytes: 32 bytes of almost random data
    """
    random = bytearray()
    random.extend(pdu.pack_uint32(int(time.time())))
    random.extend(os.urandom(28))
    return random


def log_extensions(extensions):
    """Log extensions

    Arguments:
        extensions: the list of extensions to iterate over
    """
    for extension in extensions:
        extension = extension.extension_id
        logging.debug(f"extension {extension.value} {extension}")


class TlsDefragmenter(object):
    """Class to collect as many bytes from the record layer as necessary for a message.
    """

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
        """Gets a message, constructed from the bytes received from the record layer.

        Arguments:
            timeout (float): the timeout in seconds

        Returns:
            :obj:`tlsmate.structures.UpperLayerMsg`: a defragmented message
        """
        self._ultimo = time.time() + (timeout)
        message = self._get_bytes(1)
        if self._content_type is tls.ContentType.ALERT:
            message.extend(self._get_bytes(1))
            msg_type = tls.ContentType.ALERT
            return structs.UpperLayerMsg(
                content_type=self._content_type, msg_type=msg_type, msg=message
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
    """Object to store all received/sent messages.

    Attributes:
        client_hello (:obj:`tlsmate.messages.ClientHello`): the ClientHello message
        server_hello (:obj:`tlsmate.messages.ServerHello`): the ServerHello message
        encrypted_extensions (:obj:`tlsmate.messages.ServerHello`): the
            EncryptedExtension message
        server_certificate (:obj:`tlsmate.messages.ServerHello`): the Certificate
            message sent by the server
        server_key_exchange (:obj:`tlsmate.messages.ServerHello`): the ServerKexExchange
            message
        server_hello_done (:obj:`tlsmate.messages.ServerHello`): the ServerHelloDone
            message
        client_certificate (:obj:`tlsmate.messages.ServerHello`): the Certificate
            message sent by the client
        client_key_exchange (:obj:`tlsmate.messages.ServerHello`): the ClientKeyExchange
            message
        client_change_cipher_spec (:obj:`tlsmate.messages.ServerHello`): the
            ChangeCipherSpec message sent by the client
        client_finished (:obj:`tlsmate.messages.ServerHello`): the Finished message
            sent by the client
        server_change_cipher_spec (:obj:`tlsmate.messages.ServerHello`): the
            ChangeCipherSpec message sent by the server
        server_finished (:obj:`tlsmate.messages.ServerHello`): the Finished messages
            sent by the server
        client_alert (:obj:`tlsmate.messages.ServerHello`): the Alert message sent by
            the client
        server_alert (:obj:`tlsmate.messages.ServerHello`): the Alert messages sent by
            the server
    """

    _map_msg2attr = {
        tls.HandshakeType.HELLO_REQUEST: "hello_request",
        tls.HandshakeType.CLIENT_HELLO: "client_hello",
        tls.HandshakeType.SERVER_HELLO: "server_hello",
        tls.HandshakeType.NEW_SESSION_TICKET: "new_session_ticket",
        tls.HandshakeType.END_OF_EARLY_DATA: "end_of_early_data",
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: "encrypted_extensions",
        tls.HandshakeType.CERTIFICATE: "_certificate",
        tls.HandshakeType.SERVER_KEY_EXCHANGE: "server_key_exchange",
        tls.HandshakeType.CERTIFICATE_REQUEST: "certificate_request",
        tls.HandshakeType.SERVER_HELLO_DONE: "server_hello_done",
        tls.HandshakeType.CERTIFICATE_VERIFY: "certificate_verify",
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: "client_key_exchange",
        tls.HandshakeType.FINISHED: "_finished",
        tls.HandshakeType.KEY_UPDATE: None,
        tls.HandshakeType.COMPRESSED_CERTIFICATE: None,
        tls.HandshakeType.EKT_KEY: None,
        tls.HandshakeType.MESSAGE_HASH: None,
        tls.CCSType.CHANGE_CIPHER_SPEC: "_change_cipher_spec",
        tls.ContentType.ALERT: "_alert",
    }

    def __init__(self):
        self.hello_request = None
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
        """Stores a received/sent message

        Arguments:
            msg (:obj:`tlsmate.messages.TlsMessage`): the message to store
            received (bool): an indication if the message was received or sent.
                Defaults to True
        """
        attr = self._map_msg2attr.get(msg.msg_type, None)
        if attr is not None:
            if attr.startswith("_"):
                prefix = "server" if received else "client"
                attr = prefix + attr
            setattr(self, attr, msg)


class TlsConnection(object):
    """Class representing a TLS connection object.

    Provides a context manager for the connection, i.e. opens and closes the associated
    socket accordingly.
    """

    _cert_chain_digests = []

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
        self.alert_sent = False
        self.auto_handler = [tls.HandshakeType.NEW_SESSION_TICKET]
        self.send_early_data = False
        self.early_data_accepted = False
        self.ext_psk = None

        # general
        self.entity = entity
        self.version = None
        self.client_version_sent = None
        self.cipher_suite = None
        self.compression_method = None
        self.encrypt_then_mac = False
        self.key_shares = {}
        self.res_ms = None

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

        self._clientauth_key_idx = None
        self._clientauth_sig_algo = None

        self.client_write_keys = None
        self.server_write_keys = None
        self.cipher = None

    def __enter__(self):
        self.record_layer.open_socket()
        return self

    def _send_alert(self, level, desc):
        if not self.alert_received and not self.alert_sent:
            self.send(Alert(level=level, description=desc))

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is FatalAlert:
            logging.warning(f"FatalAlert exception: {exc_value.args[0]}")
            str_io = io.StringIO()
            tb.print_exception(exc_type, exc_value, traceback, file=str_io)
            logging.debug(str_io.getvalue())
            self._send_alert(tls.AlertLevel.FATAL, exc_value.description)
        elif exc_type is TlsConnectionClosedError:
            logging.warning("connected closed, probably by peer")
        elif exc_type is TlsMsgTimeoutError:
            logging.warning(f"timeout occured while waiting for {self.awaited_msg}")
            self._send_alert(tls.AlertLevel.WARNING, tls.AlertDescription.CLOSE_NOTIFY)
        else:
            self._send_alert(tls.AlertLevel.WARNING, tls.AlertDescription.CLOSE_NOTIFY)
        self.record_layer.close_socket()
        return exc_type in [FatalAlert, TlsConnectionClosedError, TlsMsgTimeoutError]

    def set_client(self, client):
        """Provide the connection object with the associated client

        Arguments:
            client (:obj:`tlsmate.client.Client`): the client object
        """
        self.client = client
        return self

    def get_key_share(self, group):
        """Provide the key share for a given group.

        Arguments:
            group (:obj:`tlsmate.constants.SupportedGroup`): the group to create a key
                share for

        Returns:
            :obj:`tlsmate.key_exchange.KeyExchange`: the created key exchange object
        """
        key_share = kex.instantiate_named_group(group, self, self.recorder)
        self.key_shares[group] = key_share
        return key_share.get_key_share()

    def _init_handshake(self):
        self._finished_treated = False
        self.ticket_sent = False
        self.abbreviated_hs = False
        self.session_id_sent = None
        self.handshake_completed = False
        self.alert_received = False
        self.alert_sent = False
        self.send_early_data = False
        self.early_data_accepted = False
        self.ext_psk = None
        self._clientauth_key_idx = None
        self._clientauth_sig_algo = None

    def _sign_rsa_pss(self, key, data, hash_algo):
        return key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_algo()), salt_length=hash_algo.digest_size
            ),
            hash_algo(),
        )

    def _sign_rsa_pkcsv15(self, key, data, hash_algo):
        return key.sign(data, padding.PKCS1v15(), hash_algo())

    def _sign_dsa(self, key, data, hash_algo):
        return key.sign(data, hash_algo())

    def _sign_ecdsa(self, key, data, hash_algo):
        return key.sign(data, ec.ECDSA(hash_algo()))

    def _sign_with_client_key(self, priv_key, algo, data):
        func, hash_algo = self._map_client_signature_algorithm[algo]
        return func(self, priv_key, data, hash_algo)

    _map_client_signature_algorithm = {
        tls.SignatureScheme.RSA_PKCS1_MD5: (_sign_rsa_pkcsv15, hashes.MD5),
        tls.SignatureScheme.RSA_PKCS1_SHA1: (_sign_rsa_pkcsv15, hashes.SHA1),
        tls.SignatureScheme.RSA_PKCS1_SHA224: (_sign_rsa_pkcsv15, hashes.SHA224),
        tls.SignatureScheme.RSA_PKCS1_SHA256: (_sign_rsa_pkcsv15, hashes.SHA256),
        tls.SignatureScheme.RSA_PKCS1_SHA384: (_sign_rsa_pkcsv15, hashes.SHA384),
        tls.SignatureScheme.RSA_PKCS1_SHA512: (_sign_rsa_pkcsv15, hashes.SHA512),
        tls.SignatureScheme.RSA_PSS_PSS_SHA256: (_sign_rsa_pss, hashes.SHA256),
        tls.SignatureScheme.RSA_PSS_PSS_SHA384: (_sign_rsa_pss, hashes.SHA384),
        tls.SignatureScheme.RSA_PSS_PSS_SHA512: (_sign_rsa_pss, hashes.SHA512),
        tls.SignatureScheme.RSA_PSS_RSAE_SHA256: (_sign_rsa_pss, hashes.SHA256),
        tls.SignatureScheme.RSA_PSS_RSAE_SHA384: (_sign_rsa_pss, hashes.SHA384),
        tls.SignatureScheme.RSA_PSS_RSAE_SHA512: (_sign_rsa_pss, hashes.SHA512),
        tls.SignatureScheme.DSA_MD5: (_sign_dsa, hashes.MD5),
        tls.SignatureScheme.DSA_SHA1: (_sign_dsa, hashes.SHA1),
        tls.SignatureScheme.DSA_SHA224: (_sign_dsa, hashes.SHA224),
        tls.SignatureScheme.DSA_SHA256: (_sign_dsa, hashes.SHA256),
        tls.SignatureScheme.DSA_SHA384: (_sign_dsa, hashes.SHA384),
        tls.SignatureScheme.DSA_SHA512: (_sign_dsa, hashes.SHA512),
        tls.SignatureScheme.ECDSA_SHA1: (_sign_ecdsa, hashes.SHA1),
        tls.SignatureScheme.ECDSA_SECP256R1_SHA256: (_sign_ecdsa, hashes.SHA256),
        tls.SignatureScheme.ECDSA_SECP384R1_SHA384: (_sign_ecdsa, hashes.SHA256),
        tls.SignatureScheme.ECDSA_SECP521R1_SHA512: (_sign_ecdsa, hashes.SHA256),
        tls.SignatureScheme.ECDSA_SECP224R1_SHA224: (_sign_ecdsa, hashes.SHA256),
    }

    # ###########################
    # sending ClientHello methods
    # ###########################

    def _generate_ch(self, cls):
        return self.client.client_hello()

    def _pre_serialization_ch(self, msg):
        self._init_handshake()
        logging.info(f"version: {msg.get_version()}")
        self.client_version_sent = msg.version
        if self.recorder.is_injecting():
            msg.random = self.recorder.inject(client_random=None)
        else:
            if msg.random is None:
                msg.random = get_random_value()
            self.recorder.trace(client_random=msg.random)
        self.client_random = msg.random
        logging.debug(f"client_random: {pdu.dump(msg.random)}")
        if len(msg.session_id):
            self.session_id_sent = msg.session_id
            logging.debug(f"session_id: {pdu.dump(msg.session_id)}")
        for cs in msg.cipher_suites:
            logging.debug(f"cipher suite: 0x{cs.value:04x} {cs}")
        for comp in msg.compression_methods:
            logging.debug(f"compression method: 0x{comp.value:01x} {comp}")
        if msg.extensions is not None:
            for extension in msg.extensions:
                ext = extension.extension_id
                logging.debug(f"extension {ext.value} {ext}")
                if ext is tls.Extension.SESSION_TICKET:
                    self.ticket_sent = extension.ticket is not None
                elif ext is tls.Extension.EARLY_DATA:
                    self.send_early_data = True
                elif ext is tls.Extension.PRE_SHARED_KEY:
                    self.ext_psk = extension
        self.kdf.start_msg_digest()

    def _post_serialization_ch(self, msg, msg_data):
        if self.ext_psk is not None:
            # Update the binders for the pre_shared_key extension
            binders_offset = (
                len(msg_data) - msg._bytes_after_psk_ext - self.ext_psk._bytes_after_ids
            )
            msg_without_binders = msg_data[:binders_offset]
            offset = binders_offset + 3  # skip length of list + length of 1st binder
            self.recorder.trace(msg_without_binders=msg_without_binders)

            for idx, psk in enumerate(self.ext_psk.psks):
                kdf = Kdf()
                kdf.start_msg_digest()
                kdf.set_msg_digest_algo(psk.hmac.hmac_algo)
                kdf.update_msg_digest(msg_without_binders)
                hash_val = kdf.current_msg_digest(suspend=(idx != 0))
                early_secret = kdf.hkdf_extract(psk.psk, b"")
                if idx == 0:
                    self.early_data = structs.EarlyData(
                        kdf=kdf, early_secret=early_secret, mac_len=psk.hmac.mac_len
                    )
                binder_key = kdf.hkdf_expand_label(
                    early_secret, "res binder", kdf.empty_msg_digest(), psk.hmac.mac_len
                )
                finished_key = kdf.hkdf_expand_label(
                    binder_key, "finished", b"", psk.hmac.mac_len
                )
                binder = kdf.hkdf_extract(hash_val, finished_key)
                logging.debug(f"early secret: {pdu.dump(early_secret)}")
                logging.debug(f"binder key: {pdu.dump(binder_key)}")
                logging.debug(f"finished_key: {pdu.dump(finished_key)}")
                logging.debug(f"binder: {pdu.dump(binder)}")
                for idx, val in enumerate(binder):
                    msg_data[offset + idx] = val

                self.recorder.trace(hmac_algo=psk.hmac.hmac_algo.name)
                self.recorder.trace(msg_digest_tls13=hash_val)
                self.recorder.trace(early_secret=early_secret)
                self.recorder.trace(binder_key=binder_key)
                self.recorder.trace(finished_key=finished_key)
                self.recorder.trace(binder=binder)

            self.binders_bytes = msg_data[binders_offset:]

    def _post_sending_ch(self):
        if self.send_early_data:
            self.record_layer_version = tls.Version.TLS12
            self.early_data.kdf.update_msg_digest(self.binders_bytes)
            hash_val = self.early_data.kdf.current_msg_digest(suspend=True)
            early_tr_secret = self.early_data.kdf.hkdf_expand_label(
                self.early_data.early_secret,
                "c e traffic",
                hash_val,
                self.early_data.mac_len,
            )
            logging.debug(f"early traffic secret: {pdu.dump(early_tr_secret)}")
            cs_details = utils.get_cipher_suite_details(
                self.ext_psk.psks[0].cipher_suite
            )

            enc = self.early_data.kdf.hkdf_expand_label(
                early_tr_secret, "key", b"", cs_details.cipher_struct.key_len
            )
            iv = self.early_data.kdf.hkdf_expand_label(
                early_tr_secret, "iv", b"", cs_details.cipher_struct.iv_len
            )

            self.recorder.trace(early_secret=self.early_data.early_secret)
            self.recorder.trace(msg_digest_tls13=hash_val)
            self.recorder.trace(early_tr_secret=early_tr_secret)
            self.recorder.trace(client_write_key=enc)
            self.recorder.trace(client_write_iv=iv)

            self.record_layer.update_state(
                structs.StateUpdateParams(
                    cipher=cs_details.cipher_struct,
                    mac=None,
                    keys=structs.SymmetricKeys(enc=enc, mac=None, iv=iv),
                    compr=None,
                    enc_then_mac=False,
                    version=tls.Version.TLS13,
                    is_write_state=True,
                )
            )

    # #################################
    # sending ClientKeyExchange methods
    # #################################

    def _generate_cke(self, cls):
        key_ex_type = self.cs_details.key_algo_struct.key_ex_type
        if self.key_exchange is None:
            if key_ex_type is tls.KeyExchangeType.RSA:
                self.key_exchange = kex.RsaKeyExchange(self, self.recorder)
            elif key_ex_type is tls.KeyExchangeType.ECDH:
                self.key_exchange = kex.EcdhKeyExchangeCertificate(self, self.recorder)
        self.premaster_secret = self.key_exchange.get_shared_secret()
        self.recorder.trace(pre_master_secret=self.premaster_secret)
        logging.debug(f"premaster_secret: {pdu.dump(self.premaster_secret)}")
        msg = cls()
        transferable_key = self.key_exchange.get_transferable_key()
        if key_ex_type is tls.KeyExchangeType.RSA:
            msg.rsa_encrypted_pms = transferable_key
        elif key_ex_type is tls.KeyExchangeType.ECDH:
            msg.ecdh_public = transferable_key
        elif key_ex_type is tls.KeyExchangeType.DH:
            msg.dh_public = transferable_key
        return msg

    def _post_sending_cke(self):
        if not self.cs_details.full_hs:
            raise FatalAlert(
                f"full handshake not supported for {self.cipher_suite}",
                tls.AlertDescription.HANDSHAKE_FAILURE,
            )
        self._generate_master_secret()
        self._key_derivation()

    # ###########################
    # sending Certificate methods
    # ###########################

    def _generate_cert(self, cls):
        msg = cls()
        if self.version is tls.Version.TLS13:
            msg.request_context = (
                self.msg.certificate_request.certificate_request_context
            )

        else:
            msg.request_context = None

        msg.chain = None
        if self._clientauth_key_idx is not None:
            msg.chain = self.client.client_chains[self._clientauth_key_idx]

        return msg

    # #################################
    # sending CertificateVerify methods
    # #################################

    def _generate_cert_verify(self, cls):
        if self._clientauth_key_idx is None:
            return None

        msg = cls()
        logging.debug(f"using {self._clientauth_sig_algo} for client authentication")
        msg.signature_scheme = self._clientauth_sig_algo
        if self.version is tls.Version.TLS13:
            data = (
                " " * 64 + "TLS 1.3, client CertificateVerify" + "\0"
            ).encode() + self.kdf.current_msg_digest()
        else:
            data = self.kdf.get_handshake_messages()

        signature = self._sign_with_client_key(
            self.client.client_keys[self._clientauth_key_idx],
            self._clientauth_sig_algo,
            data,
        )
        msg.signature = signature

        return msg

    # ##############################
    # sending EndOfEarlyData methods
    # ##############################

    def _post_sending_eoed(self):
        self.record_layer.update_state(self.hs_write_state)

    # ########################
    # sending Finished methods
    # ########################

    def _generate_finished(self, cls):
        suspend = self._finished_treated
        if self.version is tls.Version.TLS13:
            suspend = False
        hash_val = self.kdf.current_msg_digest(suspend=suspend)
        if self.version is tls.Version.TLS13:
            # TODO: server side implementation
            if self.handshake_completed:
                secret = self.c_app_tr_secret
            else:
                secret = self.c_hs_tr_secret

            finished_key = self.kdf.hkdf_expand_label(
                secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            val = self.kdf.hkdf_extract(hash_val, finished_key)

        else:
            if self.entity == tls.Entity.CLIENT:
                label = b"client finished"
            else:
                label = b"server finished"
            val = self.kdf.prf(self.master_secret, label, hash_val, 12)
            self._update_write_state()
        self.recorder.trace(msg_digest_finished_sent=hash_val)
        self.recorder.trace(verify_data_finished_sent=val)
        logging.debug(f"Finished.verify_data(out): {pdu.dump(val)}")
        msg = cls()
        msg.verify_data = val
        if self._finished_treated:
            self.handshake_completed = True
            logging.debug("Handshake finished, secure connection established")
        self._finished_treated = True
        return msg

    def _post_sending_finished(self):
        if self.version is not tls.Version.TLS13:
            return
        ciph = self.cs_details.cipher_struct
        self.c_app_tr_secret = self.kdf.hkdf_expand_label(
            self.master_secret,
            "c ap traffic",
            self.server_finished_digest,
            self.cs_details.mac_struct.key_len,
        )
        logging.debug(f"c_app_tr_secret: {pdu.dump(self.c_app_tr_secret)}")
        c_enc = self.kdf.hkdf_expand_label(
            self.c_app_tr_secret, "key", b"", ciph.key_len
        )
        c_iv = self.kdf.hkdf_expand_label(self.c_app_tr_secret, "iv", b"", ciph.iv_len)

        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(client_write_iv=c_iv)

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
        hash_val = self.kdf.current_msg_digest()
        self.res_ms = self.kdf.hkdf_expand_label(
            self.master_secret,
            "res master",
            hash_val,
            self.cs_details.mac_struct.key_len,
        )

    _generate_out_msg = {
        tls.HandshakeType.CLIENT_HELLO: _generate_ch,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: _generate_cke,
        tls.HandshakeType.FINISHED: _generate_finished,
        tls.HandshakeType.CERTIFICATE: _generate_cert,
        tls.HandshakeType.CERTIFICATE_VERIFY: _generate_cert_verify,
    }

    _pre_serialization_method = {tls.HandshakeType.CLIENT_HELLO: _pre_serialization_ch}

    _post_serialization_method = {
        tls.HandshakeType.CLIENT_HELLO: _post_serialization_ch
    }

    _post_sending_method = {
        tls.HandshakeType.CLIENT_HELLO: _post_sending_ch,
        tls.HandshakeType.CLIENT_KEY_EXCHANGE: _post_sending_cke,
        tls.HandshakeType.END_OF_EARLY_DATA: _post_sending_eoed,
        tls.HandshakeType.FINISHED: _post_sending_finished,
    }

    def _generate_outgoing_msg(self, msg_cls):
        """Setup a message for which only the class has been provided

        Here, we also do all the funny stuff required prior sending a
        mesage, e.g. for a ClientKeyExchange the key exchange and key deriviation
        is performed here.
        """
        method = self._generate_out_msg.get(msg_cls.msg_type)
        if method is not None:
            return method(self, msg_cls)
        return msg_cls()

    def _pre_serialization_hook(self, msg):
        method = self._pre_serialization_method.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def _post_serialization_hook(self, msg, msg_data):
        method = self._post_serialization_method.get(msg.msg_type)
        if method is not None:
            method(self, msg, msg_data)
        return bytes(msg_data)

    def _post_sending_hook(self, msg):
        method = self._post_sending_method.get(msg.msg_type)
        if method is not None:
            method(self)

    def send(self, *messages):
        """Interface to send messages.

        Each message given here will be sent in a separate record layer record, but
        all record layer records will be sent in the same TCP segment.

        Arguments:
            *messages: either a class or an object of
                :class:`tlsmate.messages.TlsMessage`. If a class is passed, appropriate
                methods will be called to instantiate an object.
        """
        for message in messages:
            if inspect.isclass(message):
                message = self._generate_outgoing_msg(message)
                if message is None:
                    continue
            logging.info(f"{utils.Log.time()}: ==> {message.msg_type}")
            self._pre_serialization_hook(message)
            self._msg_logging(message)
            msg_data = message.serialize(self)
            msg_data = self._post_serialization_hook(message, msg_data)
            self.msg.store_msg(message, received=False)
            if message.content_type == tls.ContentType.HANDSHAKE:
                self.kdf.update_msg_digest(msg_data)
            elif message.content_type == tls.ContentType.ALERT:
                self.alert_sent = True
            self.record_layer.send_message(
                structs.RecordLayerMsg(
                    content_type=message.content_type,
                    version=self.record_layer_version,
                    fragment=msg_data,
                )
            )
            self._post_sending_hook(message)
        self.record_layer.flush()

    def _on_server_hello_tls13(self, msg):
        psk = None
        psk_ext = msg.get_extension(tls.Extension.PRE_SHARED_KEY)
        if psk_ext is not None:
            psk_idx = psk_ext.selected_id
            ch_psks = self.msg.client_hello.get_extension(tls.Extension.PRE_SHARED_KEY)
            if ch_psks is not None:
                if psk_idx >= len(ch_psks.psks):
                    raise FatalAlert(
                        "selected PSK out of range",
                        tls.AlertDescription.ILLEGAL_PARAMETER,
                    )
                psk = ch_psks.psks[psk_idx].psk
                self.abbreviated_hs = True
        key_share_ext = msg.get_extension(tls.Extension.KEY_SHARE)
        if key_share_ext is None:
            if not self.abbreviated_hs:
                raise FatalAlert(
                    "ServerHello-TLS13: extension KEY_SHARE not present",
                    tls.AlertDescription.HANDSHAKE_FAILURE,
                )
            shared_secret = None
        else:
            share_entry = key_share_ext.key_shares[0]
            self.key_exchange = self.key_shares[share_entry.group]
            self.key_exchange.set_remote_key(
                share_entry.key_exchange, group=share_entry.group
            )
            shared_secret = self.key_exchange.get_shared_secret()
            logging.debug(f"shared_secret: {pdu.dump(shared_secret)}")
        self._tls13_key_schedule(psk, shared_secret)

    def _on_server_hello_tls12(self, msg):
        if len(msg.session_id):
            if msg.session_id == self.session_id_sent:
                self.abbreviated_hs = True
                # TODO: check version and ciphersuite
                if self.ticket_sent:
                    self.master_secret = self.client.session_state_ticket.master_secret
                else:
                    self.master_secret = self.client.session_state_id.master_secret
                logging.debug(f"master_secret: {pdu.dump(self.master_secret)}")
                self._key_derivation()
            else:
                self._new_session_id = msg.session_id
        self.encrypt_then_mac = (
            msg.get_extension(tls.Extension.ENCRYPT_THEN_MAC) is not None
        )
        self.extended_ms = (
            msg.get_extension(tls.Extension.EXTENDED_MASTER_SECRET) is not None
        )

    def _on_server_hello_received(self, msg):
        self.server_random = msg.random
        logging.debug(f"server random: {pdu.dump(msg.random)}")
        self.version = msg.get_version()
        logging.info(f"version: {self.version}")
        logging.info(f"cipher suite: 0x{msg.cipher_suite.value:04x} {msg.cipher_suite}")
        self._update_cipher_suite(msg.cipher_suite)
        self.record_layer_version = min(self.version, tls.Version.TLS12)
        if self.version is tls.Version.TLS13:
            self._on_server_hello_tls13(msg)
        else:
            self._on_server_hello_tls12(msg)

    def _on_server_key_exchange_received(self, msg):
        if msg.ec is not None:
            if msg.ec.signed_params is not None:
                kex.verify_signed_params(
                    msg.ec,
                    self.msg,
                    self.cs_details.key_algo_struct.default_sig_scheme,
                    self.version,
                )
                logging.debug("signed ec parameters successfully verified")

            if msg.ec.named_curve is not None:
                logging.debug(f"named curve: {msg.ec.named_curve}")
                self.key_exchange = kex.instantiate_named_group(
                    msg.ec.named_curve, self, self.recorder
                )
                self.key_exchange.set_remote_key(msg.ec.public)
        elif msg.dh is not None:
            dh = msg.dh
            if dh.signed_params is not None:
                kex.verify_signed_params(
                    msg.dh,
                    self.msg,
                    self.cs_details.key_algo_struct.default_sig_scheme,
                    self.version,
                )
                logging.debug("signed dh parameters successfully verified")
            self.key_exchange = kex.DhKeyExchange(self, self.recorder)
            self.key_exchange.set_remote_key(
                dh.public_key, g_val=dh.g_val, p_val=dh.p_val
            )

    def _on_change_cipher_spec_received(self, msg):
        if self.version is not tls.Version.TLS13:
            self._update_read_state()

    def _on_finished_received(self, msg):
        ciph = self.cs_details.cipher_struct
        logging.debug(f"Finished.verify_data(in): {pdu.dump(msg.verify_data)}")

        if self.version is tls.Version.TLS13:

            if not self.early_data_accepted:
                self.record_layer.update_state(self.hs_write_state)

            finished_key = self.kdf.hkdf_expand_label(
                self.s_hs_tr_secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            calc_verify_data = self.kdf.hkdf_extract(
                self._pre_finished_digest, finished_key
            )
            logging.debug(f"calc. verify_data: {pdu.dump(calc_verify_data)}")
            if calc_verify_data != msg.verify_data:
                raise FatalAlert(
                    "Received Finished: verify_data does not match",
                    tls.AlertDescription.DECRYPT_ERROR,
                )
            self.server_finished_digest = self.kdf.current_msg_digest()
            s_app_tr_secret = self.kdf.hkdf_expand_label(
                self.master_secret,
                "s ap traffic",
                self.server_finished_digest,
                self.cs_details.mac_struct.key_len,
            )
            logging.debug(f"s_app_tr_secret: {pdu.dump(s_app_tr_secret)}")
            s_enc = self.kdf.hkdf_expand_label(
                s_app_tr_secret, "key", b"", ciph.key_len
            )
            s_iv = self.kdf.hkdf_expand_label(s_app_tr_secret, "iv", b"", ciph.iv_len)

            self.recorder.trace(server_write_key=s_enc)
            self.recorder.trace(server_write_iv=s_iv)
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
        logging.debug("Received Finished sucessfully verified")
        if self._finished_treated:
            self.handshake_completed = True
            logging.debug("Handshake finished, secure connection established")
        self._finished_treated = True
        return self

    def _on_new_session_ticket_received(self, msg):
        if self.version is tls.Version.TLS13:
            psk = self.kdf.hkdf_expand_label(
                self.res_ms, "resumption", msg.nonce, self.cs_details.mac_struct.mac_len
            )
            logging.debug(f"PSK: {pdu.dump(psk)}")
            log_extensions(msg.extensions)
            self.client.save_psk(
                structs.Psk(
                    psk=psk,
                    lifetime=msg.lifetime,
                    age_add=msg.age_add,
                    ticket=msg.ticket,
                    timestamp=self.recorder.inject(timestamp=time.time()),
                    cipher_suite=self.cipher_suite,
                    version=self.version,
                    hmac=self.cs_details.mac_struct,
                )
            )
        else:
            self.client.save_session_state_ticket(
                structs.SessionStateTicket(
                    ticket=msg.ticket,
                    lifetime=msg.lifetime,
                    cipher_suite=self.cipher_suite,
                    version=self.version,
                    master_secret=self.master_secret,
                )
            )

    def _on_encrypted_extensions_received(self, msg):
        for extension in msg.extensions:
            logging.debug(f"extension {extension.extension_id}")
            if extension.extension_id is tls.Extension.SUPPORTED_GROUPS:
                for group in extension.supported_groups:
                    logging.debug(f"supported group: {group}")
            elif extension.extension_id is tls.Extension.EARLY_DATA:
                self.early_data_accepted = True
        if not self.early_data_accepted:
            self.record_layer.update_state(self.hs_write_state)

    def _on_certificate_received(self, msg):

        if self.version is tls.Version.TLS13:
            self.certificate_digest = self.kdf.current_msg_digest()

        if msg.chain.digest not in self._cert_chain_digests:
            self._cert_chain_digests.append(msg.chain.digest)
            if self.recorder.is_injecting():
                timestamp = self.recorder.inject(datetime=None)
            else:
                timestamp = datetime.datetime.now()
                self.recorder.trace(datetime=timestamp)
            msg.chain.validate(
                timestamp,
                self.client.config["server"],
                self.client.trust_store,
                self.client.alert_on_invalid_cert,
            )

    def _on_certificate_request_received(self, msg):
        if self.version is tls.Version.TLS13:
            sig_algo_ext = msg.get_extension(tls.Extension.SIGNATURE_ALGORITHMS)
            if sig_algo_ext is None:
                raise FatalAlert(
                    "certificate request without extension SignatureAlgorithms received"
                )
            algos = sig_algo_ext.signature_algorithms

        else:
            algos = msg.supported_signature_algorithms

        end_loops = False
        for algo in algos:
            for idx, chain in enumerate(self.client.client_chains):
                if self.version is tls.Version.TLS13:
                    cert_algos = chain.certificates[0].tls13_signature_algorithms
                else:
                    cert_algos = chain.certificates[0].tls12_signature_algorithms

                if algo in cert_algos:
                    self._clientauth_key_idx = idx
                    self._clientauth_sig_algo = algo
                    end_loops = True
                    break
            if end_loops:
                break

        if self._clientauth_key_idx is None:
            logging.info("No suitable certificate found for client authentication")

    def _on_certificate_verify_received(self, msg):
        if self.version is tls.Version.TLS13:
            kex.verify_certificate_verify(msg, self.msg, self.certificate_digest)

    _on_msg_received_map = {
        tls.HandshakeType.SERVER_HELLO: _on_server_hello_received,
        tls.HandshakeType.ENCRYPTED_EXTENSIONS: _on_encrypted_extensions_received,
        tls.HandshakeType.SERVER_KEY_EXCHANGE: _on_server_key_exchange_received,
        tls.HandshakeType.CERTIFICATE: _on_certificate_received,
        tls.HandshakeType.CERTIFICATE_REQUEST: _on_certificate_request_received,
        tls.HandshakeType.CERTIFICATE_VERIFY: _on_certificate_verify_received,
        tls.CCSType.CHANGE_CIPHER_SPEC: _on_change_cipher_spec_received,
        tls.HandshakeType.FINISHED: _on_finished_received,
        tls.HandshakeType.NEW_SESSION_TICKET: _on_new_session_ticket_received,
    }

    def _on_msg_received(self, msg):
        """Called whenever a message is received before it is passed to the testcase"""
        method = self._on_msg_received_map.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    _auto_responder_map = {}

    def _auto_responder(self, msg):
        """Automatically process messages which are not passed back to the test case.

        Currently not used, but can be used e.g. for automatically respond to a
        HeartBeatRequest.
        """
        method = self._auto_responder_map.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def _msg_logging_alert(self, msg):
        logging.info(f"alert level: {msg.level}")
        logging.info(f"alert description: {msg.description}")

    _msg_logging_map = {tls.ContentType.ALERT: _msg_logging_alert}

    def _msg_logging(self, msg):
        method = self._msg_logging_map.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def _wait_message(self, timeout=5000):
        mb = self.defragmenter.get_message(timeout)
        if mb is None:
            return None
        if mb.content_type is tls.ContentType.HANDSHAKE:
            msg = HandshakeMessage.deserialize(mb.msg, self)
            if msg.msg_type is tls.HandshakeType.FINISHED:
                self._pre_finished_digest = self.kdf.current_msg_digest(
                    suspend=self._finished_treated
                )

            if msg.msg_type is tls.HandshakeType.CERTIFICATE_REQUEST:
                self.kdf.resume_msg_digest()

            if self.kdf.msg_digest_active():
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
            raise ValueError("Content type unknown")

        logging.info(f"{utils.Log.time()}: <== {msg.msg_type}")
        self._msg_logging(msg)
        self.msg.store_msg(msg, received=True)
        return msg

    def wait(self, msg_class, optional=False, max_nbr=1, timeout=5000):
        """Interface to wait for a message from the peer.

        Arguments:
            msg_class (:class:`tlsmate.messages.TlsMessage`): the class of the awaited
                message
            optional (bool): an indication if the message is optional. Defaults to False
            max_nbr (int): the number of identical message types to wait for. Well
                suitable for NewSessionTicket messages. Defaults to 1.
            timeout (int): the message timeout in milli seconds

        Returns:
            :obj:`tlsmate.messages.TlsMessage`: the message received or None in case
                of a timeout.

        Raise:
            FatalAlert: In case an unexpected message is received
        """
        ultimo = time.time() + (timeout / 1000)
        min_nbr = 0 if optional else 1
        cnt = 0
        self.awaited_msg = msg_class
        expected_msg = None
        while True:
            if self.queued_msg:
                msg = self.queued_msg
                self.queued_msg = None
            else:
                try:
                    msg = self._wait_message(ultimo - time.time())
                except TlsMsgTimeoutError as exc:
                    if cnt >= min_nbr:
                        return expected_msg
                    else:
                        raise exc
            if (msg_class == Any) or isinstance(msg, msg_class):
                self._on_msg_received(msg)
                cnt += 1
                if cnt == max_nbr:
                    return msg
                else:
                    expected_msg = msg
            elif msg.msg_type in self.auto_handler:
                self._on_msg_received(msg)
                self._auto_responder(msg)
            else:
                if cnt >= min_nbr:
                    self.queued_msg = msg
                    return expected_msg
                else:
                    logging.warning("unexpected message received")
                    raise FatalAlert(
                        (
                            f"Unexpected message received: {msg.msg_type}, "
                            f"expected: {msg_class.msg_type}"
                        ),
                        tls.AlertDescription.UNEXPECTED_MESSAGE,
                    )

    def _update_write_state(self):
        state = self._get_pending_write_state(self.entity)
        self.record_layer.update_state(state)

    def _update_read_state(self):
        if self.entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER
        else:
            entity = tls.Entity.CLIENT
        state = self._get_pending_write_state(entity)
        self.record_layer.update_state(state)

    def _update_cipher_suite(self, cipher_suite):
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

    def _generate_master_secret(self):
        if self.extended_ms:
            msg_digest = self.kdf.current_msg_digest()
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

        logging.debug(f"master_secret: {pdu.dump(self.master_secret)}")
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

    def _tls13_key_schedule(self, psk, shared_secret):
        ciph = self.cs_details.cipher_struct
        mac = self.cs_details.mac_struct
        early_secret = self.kdf.hkdf_extract(psk, b"")
        logging.debug(f"early_secret: {pdu.dump(early_secret)}")
        empty_msg_digest = self.kdf.empty_msg_digest()
        logging.debug(f"empty msg digest: {pdu.dump(empty_msg_digest)}")
        derived = self.kdf.hkdf_expand_label(
            early_secret, "derived", empty_msg_digest, mac.key_len
        )

        handshake_secret = self.kdf.hkdf_extract(shared_secret, derived)
        logging.debug(f"handshake secret: {pdu.dump(handshake_secret)}")
        hello_digest = self.kdf.current_msg_digest()
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
        logging.debug(f"client hs traffic secret: {pdu.dump(c_hs_tr_secret)}")
        logging.debug(f"server hs traffic secret: {pdu.dump(s_hs_tr_secret)}")
        self.s_hs_tr_secret = s_hs_tr_secret
        self.c_hs_tr_secret = c_hs_tr_secret

        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(server_write_key=s_enc)
        self.recorder.trace(client_write_iv=c_iv)
        self.recorder.trace(server_write_iv=s_iv)

        self.hs_write_state = structs.StateUpdateParams(
            cipher=ciph,
            mac=None,
            keys=structs.SymmetricKeys(enc=c_enc, mac=None, iv=c_iv),
            compr=None,
            enc_then_mac=False,
            version=self.version,
            is_write_state=True,
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

    def _key_derivation(self):
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
        self.client_write_keys = structs.SymmetricKeys(mac=c_mac, enc=c_enc, iv=c_iv)
        self.server_write_keys = structs.SymmetricKeys(mac=s_mac, enc=s_enc, iv=s_iv)

    def _get_pending_write_state(self, entity):
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
        """Convenient method to execute a complete handshake.

        With this method there is no need to define the exact scenario. Covers the
        following cases:
        TLS1.0-TLS1.2:

        * full handshake
        * abbreviated handshake (with and without server authentication)
        * client authentication

        TLS1.3:

        * full handshake
        * abbreviated handshake
        * 0-RTT

        Note:
            The handshake finishes with the exchange of the Finished messages, i.e.,
            receiving messages hereafter needs to be covered separately, e.g. receiving
            NewSessionTicket messages in TLS1.3.
        """
        self.send(msg.ClientHello)
        if self.client.early_data is not None:
            self.send(msg.AppData(self.client.early_data))

        self.wait(msg.ServerHello)
        if self.version is tls.Version.TLS13:
            self.wait(msg.ChangeCipherSpec, optional=True)
            self.wait(msg.EncryptedExtensions)
            if not self.abbreviated_hs:
                self.wait(msg.Certificate)
                self.wait(msg.CertificateVerify)

            self.wait(msg.Finished)
            if self.early_data_accepted:
                self.send(msg.EndOfEarlyData)

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

                cert_req = self.wait(msg.CertificateRequest, optional=True)
                self.wait(msg.ServerHelloDone)
                if cert_req is not None:
                    self.send(msg.Certificate)

                self.send(msg.ClientKeyExchange)
                if cert_req is not None:
                    self.send(msg.CertificateVerify)

                self.send(msg.ChangeCipherSpec)
                self.send(msg.Finished)
                self.wait(msg.ChangeCipherSpec)
                self.wait(msg.Finished)
