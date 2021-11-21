# -*- coding: utf-8 -*-
"""Module containing the implementation for a TLS connection
"""

# import basic stuff
import inspect
import logging
import io
import traceback as tb
import time

# import own stuff
from tlsmate.exception import (
    ScanError,
    ServerMalfunction,
    TlsConnectionClosedError,
    TlsMsgTimeoutError,
)
from tlsmate.msg import get_extension
from tlsmate import msg
from tlsmate import tls
from tlsmate import pdu
from tlsmate import utils
from tlsmate import structs
from tlsmate import key_exchange as kex
from tlsmate import ext
from tlsmate import resolver
from tlsmate import mappings
from tlsmate.kdf import Kdf
from tlsmate.record_layer import RecordLayer
from tlsmate.key_logging import KeyLogger

# import other stuff
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions as crypto_exc


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

    def _get_bytes(self, nbr, **kwargs):
        while len(self._record_bytes) < nbr:
            timeout = self._ultimo - time.time()
            if timeout <= 0:
                raise TlsMsgTimeoutError

            rl_msg = self._record_layer.wait_rl_msg(timeout, **kwargs)
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

    def get_message(self, timeout, **kwargs):
        """Gets a message, constructed from the bytes received from the record layer.

        Arguments:
            timeout (float): the timeout in seconds

        Returns:
            :obj:`tlsmate.structs.UpperLayerMsg`: a defragmented message
        """

        self._ultimo = time.time() + (timeout)
        message = self._get_bytes(1, **kwargs)
        if self._content_type is tls.ContentType.ALERT:
            message.extend(self._get_bytes(1, **kwargs))
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
            message.extend(self._get_bytes(3, **kwargs))
            msg_type, offset = pdu.unpack_uint8(message, 0)
            msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
            length, offset = pdu.unpack_uint24(message, offset)
            message.extend(self._get_bytes(length, **kwargs))
            return structs.UpperLayerMsg(
                content_type=self._content_type, msg_type=msg_type, msg=bytes(message)
            )

        elif self._content_type is tls.ContentType.APPLICATION_DATA:
            return structs.UpperLayerMsg(
                content_type=self._content_type,
                msg_type=None,
                msg=bytes(message + self._get_all_bytes()),
            )

        elif self._content_type is tls.ContentType.HEARTBEAT:
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
    """Object to store all received/sent messages for a handshake.

    Attributes:
        hello_request (:obj:`tlsmate.msg.HelloRequest`): the HelloRequest message
        client_hello (:obj:`tlsmate.msg.ClientHello`): the ClientHello message
        server_hello (:obj:`tlsmate.msg.ServerHello`): the ServerHello message
        encrypted_extensions (:obj:`tlsmate.msg.EncryptedExtensions`): the
            EncryptedExtension message
        server_certificate (:obj:`tlsmate.msg.Certificate`): the Certificate
            message sent by the server
        server_key_exchange (:obj:`tlsmate.msg.ServerKeyExchange`): the
            ServerKeyExchange message
        server_hello_done (:obj:`tlsmate.msg.ServerHelloDone`): the ServerHelloDone
            message
        client_certificate (:obj:`tlsmate.msg.Certificate`): the Certificate
            message sent by the client
        client_key_exchange (:obj:`tlsmate.msg.ClientKeyExchange`): the
            ClientKeyExchange message
        client_change_cipher_spec (:obj:`tlsmate.msg.ChangeCipherSpec`): the
            ChangeCipherSpec message sent by the client
        client_finished (:obj:`tlsmate.msg.Finished`): the Finished message
            sent by the client
        server_change_cipher_spec (:obj:`tlsmate.msg.ChangeCipherSpec`): the
            ChangeCipherSpec message sent by the server
        server_finished (:obj:`tlsmate.msg.Finished`): the Finished messages
            sent by the server
        certificate_status (:obj:`tlsmate.msg.CertificateStatus`): the
            CertificateStatus message sent by the server
        client_alert (:obj:`tlsmate.msg.Alert`): the Alert message sent by
            the client
        server_alert (:obj:`tlsmate.msg.Alert`): the Alert messages sent by
            the server
        client_heartbeat_request (:obj:`tlsmate.msg.HeartbeatRequest`): the
            heartbeat request message sent by the client
        server_heartbeat_request (:obj:`tlsmate.msg.HeartbeatRequest`): the
            heartbeat request message sent by the server
        client_heartbeat_response (:obj:`tlsmate.msg.HeartbeatResponse`): the
            heartbeat response message sent by the client
        server_heartbeat_response (:obj:`tlsmate.msg.HeartbeatResponse`): the
            heartbeat response message sent by the server
        hello_retry_request (:obj:`tlsmate.msg.HelloRequest`): the
            HelloRequest message
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
        tls.HandshakeType.CERTIFICATE_STATUS: "certificate_status",
        tls.HandshakeType.KEY_UPDATE: None,
        tls.HandshakeType.COMPRESSED_CERTIFICATE: None,
        tls.HandshakeType.EKT_KEY: None,
        tls.HandshakeType.MESSAGE_HASH: None,
        tls.CCSType.CHANGE_CIPHER_SPEC: "_change_cipher_spec",
        tls.ContentType.ALERT: "_alert",
        tls.HeartbeatType.HEARTBEAT_REQUEST: "_heartbeat_request",
        tls.HeartbeatType.HEARTBEAT_RESPONSE: "_heartbeat_response",
        tls.HandshakeType.HELLO_RETRY_REQUEST: "hello_retry_request",
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
        self.certificate_status = None
        self.client_alert = None
        self.server_alert = None
        self.client_heartbeat_request = None
        self.server_heartbeat_request = None
        self.client_heartbeat_response = None
        self.server_heartbeat_response = None

    def store_msg(self, msg, received=True):
        """Stores a received/sent message

        Arguments:
            msg (:obj:`tlsmate.msg.TlsMessage`): the message to store
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

    The typical way to instantiate a ``TlsConnection`` object is through the client's
    :meth:`tlsmate.client.Client.create_connection` method and by using the context
    manager this class provides.

    Example:

        >>> with client.create_connection() as conn:
        >>>     conn.handshake()

        The variable ``conn`` references the ``TlsConnection`` instance. When entering
        the context manager, the host's URL is resolved, and a TCP socket is
        opened. When leaving the context manager, the TLS-connection is always
        properly closed, e.g., by sending a closure alert and by closing the
        underlying TCP socket.

        .. note::
            The ``TlsConnection`` instance is accessible outside the context manager as
            well, "outside the context manager" only means that the TLS connection is
            closed.

        .. note::
            Multiple handshakes can be executed within the same TLS connection (e.g.,
            through renegotiation). Most of the attributes defined for this class
            will be overwritten with each subsequent handshake, i.e., they will
            represent the state of the latest handshake only.

    Attributes:
        client (:obj:`tlsmate.client.Client`): a reference to the client object which
            initiated this connection
        recorder (:obj:`tlsmate.recorder.Recorder`): a reference to the recorder
            object. Only used for unit tests.
        record_layer_version (:obj:`tlsmate.tls.Version`): the record layer version
            to use in records sent. The handling for this parameter is greatly
            underspecified in all TLS RFCs. The default behavior for ``tlsmate`` is as
            follows: ClientHellos are all sent with a version set to TLS1.0. If
            TLS1.3 is negotiated, the version is updated to TLS1.2. Anyway,
            this parameter can be set anytime in a test case to whatever value is
            desired.
        auto_handler (list of :obj:`tlsmate.tls.HandshakeType`): a list of messages
            which are registered for auto handling. `Auto handling` means that these
            messages if received, are treated by tlsmate autonomously, e.g., a received
            Heartbeat message will be answered accordingly. There is no need to
            consider those messages within the test case. If a message is registered
            for auto handling, and it is awaited in a test case, then such a received
            message will not be auto handled by tlsmate. In this case it is up
            to the test case to completely process the message, e.g., by
            sending an appropriate response. This mechanism is intended for messages,
            which can be received at any time and/or where the number of messages sent
            by the server is unknown (Heartbeat, NewSessionTicket).

            Currently, this attribute defaults to
            [tls.HandshakeType.NEW_SESSION_TICKET, tls.HeartbeatType.HEARTBEAT_REQUEST]
        msg (:obj:`TlsConnectionMsgs`): an object which contains all messages received
            and send during a handshake. Can also be used outside the context manager,
            e.g., when the handshake method was used. If the same message is sent or
            received more than once during the connection, then only the latest message
            will be available.
        abbreviated_hs (bool): an indication whether the performed handshake was an
            abbreviated one (session resumption (TLS1.2 or below) or PSK (TLS1.3)).
        handshake_completed (bool): an indication whether the handshake was completed
            or not. A handshake is regarded as complete when the Finished message
            was received and sent.
        alert_received (bool): an indication whether an alert was received from the
            peer during the handshake. The alert message will be available via
            the msg attribute.
        alert_sent (bool): an indication whether the client has sent an alert during
            the handshake. The alert message will be available via the msg attribute.
        early_data_accepted (bool): an indication whether the early data sent by the
            client was accepted by the server. Only meaningful for TLS1.3 when using
            PSKs.
        version (:obj:`tlsmate.tls.Version`): the TLS version negotiated with the
            server.
        client_version_sent (:obj:`tlsmate.tls.Version`): the highest TLS version
            offered by the client.
        cipher_suite (:obj:`tlsmate.tls.CipherSuite`): the cipher suite negotiated
            with the server.
        client_random (bytes): the random value used in the ClientHello message.
        server_random (bytes): the random value received in the ServerHello message
            from the server.
        premaster_secret (bytes): the pre master secret used in the latest handshake.
            Only used for negotiated versions < TLS1.3.
        master_secret (bytes):the master secret used in the latest handshake. Only
            used for negotiated versions < TLS1.3.
        heartbeat_allowed_to_send (bool): an indication if the peer allowed to send
            Heartbeat messages.
    """

    def __init__(self, tlsmate, host=None, port=None):
        self._tlsmate = tlsmate
        if host is None:
            host = tlsmate.config.get("host")

        if port is None:
            port = tlsmate.config.get("port")

        self._server_l4 = resolver.determine_l4_addr(host, port)
        self.msg = TlsConnectionMsgs()
        self._record_layer = RecordLayer(tlsmate, self._server_l4)
        self._defragmenter = TlsDefragmenter(self._record_layer)
        self._awaited_msg = None
        self._queued_msg = None
        self._queued_bytes = None
        self._record_layer_version = tls.Version.TLS10
        self._msg_hash = None
        self._msg_hash_queue = None
        self._msg_hash_active = False
        self.recorder = tlsmate.recorder
        self._kdf = Kdf()
        self._new_session_id = None
        self._finished_treated = False
        self._ticket_sent = False
        self.abbreviated_hs = False
        self._session_id_sent = None
        self.handshake_completed = False
        self.alert_received = False
        self.alert_sent = False
        self.auto_handler = [
            tls.HandshakeType.NEW_SESSION_TICKET,
            tls.HeartbeatType.HEARTBEAT_REQUEST,
        ]
        self._send_early_data = False
        self.early_data_accepted = False
        self._ext_psk = None
        self.heartbeat_allowed_to_send = False

        # general
        self._entity = tls.Entity.CLIENT
        self.version = None
        self.client_version_sent = None
        self.cipher_suite = None
        self._compression_method = None
        self._encrypt_then_mac = False
        self._key_shares = {}
        self.res_ms = None

        # key exchange
        self.client_random = None
        self.server_random = None
        self.premaster_secret = None
        self.master_secret = None
        self._key_exchange = None

        self._clientauth_key_idx = None
        self._clientauth_sig_algo = None

        self._client_write_keys = None
        self._server_write_keys = None
        self._initial_handshake = None

        self.client = tlsmate.client
        self._secure_reneg_cl_data = None
        self._secure_reneg_sv_data = None
        self._secure_reneg_request = False
        self._secure_reneg_flag = False
        self._secure_reneg_ext = False
        self._secure_reneg_scsv = False
        self.stapling_status = None

        if self.client.profile.support_secure_renegotiation:
            self._secure_reneg_request = True
            self._secure_reneg_ext = True

        if self.client.profile.support_scsv_renegotiation:
            self._secure_reneg_request = True
            self._secure_reneg_scsv = True

    def __enter__(self):
        """Context manager: open the socket (after potentially resolving the URL).
        """

        self._record_layer.open_socket(self._server_l4)
        return self

    def _send_alert(self, level, desc):
        if not self.alert_received and not self.alert_sent:
            self.send(msg.Alert(level=level, description=desc))

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager: cleanup the TLS- and TCP-connection.
        """

        logging.debug("exiting context manager...")
        if exc_type is ServerMalfunction:
            self.client.report_server_issue(
                exc_value.issue, exc_value.message, exc_value.extension
            )
            logging.warning(f"ServerMalfunction exception: {exc_value.args[0]}")
            str_io = io.StringIO()
            tb.print_exception(exc_type, exc_value, traceback, file=str_io)
            logging.debug(str_io.getvalue())
            descr = mappings.issue_to_alert_description.get(
                exc_value.issue, tls.AlertDescription.INTERNAL_ERROR
            )
            self._send_alert(tls.AlertLevel.FATAL, descr)

        elif exc_type in (TlsConnectionClosedError, BrokenPipeError):
            logging.warning("connected closed, probably by peer")

        elif exc_type is TlsMsgTimeoutError:
            logging.warning(f"timeout occurred while waiting for {self._awaited_msg}")
            self._send_alert(tls.AlertLevel.WARNING, tls.AlertDescription.CLOSE_NOTIFY)

        else:
            if exc_type is not None:
                logging.warning(f"exception {exc_type.__name__}: {str(exc_value)}")
                str_io = io.StringIO()
                tb.print_exception(exc_type, exc_value, traceback, file=str_io)
                logging.debug(str_io.getvalue())

            self._send_alert(tls.AlertLevel.WARNING, tls.AlertDescription.CLOSE_NOTIFY)

        self._record_layer.close_socket()
        if exc_type:
            return issubclass(exc_type, Exception)

        else:
            return True

    def get_key_share(self, group):
        """Provide the key share for a given group.

        Arguments:
            group (:obj:`tlsmate.tls.SupportedGroups`): the group to create a key
                share for

        Returns:
            :obj:`tlsmate.key_exchange.KeyExchange`: the created key exchange object
        """

        key_share = kex.instantiate_named_group(group, self, self.recorder)
        self._key_shares[group] = key_share
        return key_share.get_key_share()

    def _init_handshake(self):
        """Reset properties before starting a new handshake.
        """
        self._finished_treated = False
        self._ticket_sent = False
        self.abbreviated_hs = False
        self._session_id_sent = None
        self.handshake_completed = False
        self.alert_received = False
        self.alert_sent = False
        self._send_early_data = False
        self.early_data_accepted = False
        self._ext_psk = None
        self._clientauth_key_idx = None
        self._clientauth_sig_algo = None
        self._initial_handshake = True if self._initial_handshake is None else False

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
        msg = self.client.client_hello()
        if self._secure_reneg_request:
            if self._initial_handshake is None:
                if self._secure_reneg_scsv:
                    msg.cipher_suites.append(
                        tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                    )

                if self._secure_reneg_ext:
                    # Put it in the beginning, just to be sure preshared_keys stays the
                    # last extension (if present at all)
                    msg.extensions.insert(
                        0, ext.ExtRenegotiationInfo(renegotiated_connection=b"")
                    )

            elif self._secure_reneg_flag:
                if self._secure_reneg_cl_data is not None:
                    msg.extensions.insert(
                        0,
                        ext.ExtRenegotiationInfo(
                            renegotiated_connection=self._secure_reneg_cl_data
                        ),
                    )

        return msg

    def _pre_serialization_ch(self, msg):
        self._init_handshake()
        logging.info(f"version: {msg.get_version()}")
        self.client_version_sent = msg.version
        if self.recorder.is_injecting():
            msg.random = self.recorder.inject(client_random=None)

        else:
            if msg.random is None:
                msg.random = utils.get_random_value()

            self.recorder.trace(client_random=msg.random)

        self.client_random = msg.random
        logging.debug(f"client_random: {pdu.dump(msg.random)}")
        if len(msg.session_id):
            self._session_id_sent = msg.session_id
            logging.debug(f"session_id: {pdu.dump(msg.session_id)}")

        for cs in msg.cipher_suites:
            logging.debug(f"cipher suite: 0x{getattr(cs, 'value', cs):04x} {cs}")

        for comp in msg.compression_methods:
            logging.debug(f"compression method: 0x{comp.value:01x} {comp}")

        if msg.extensions is not None:
            for extension in msg.extensions:
                ext = extension.extension_id
                logging.debug(f"extension {ext.value} {ext}")
                if ext is tls.Extension.SESSION_TICKET:
                    self._ticket_sent = extension.ticket is not None

                elif ext is tls.Extension.EARLY_DATA:
                    self._send_early_data = True

                elif ext is tls.Extension.PRE_SHARED_KEY:
                    self._ext_psk = extension

                elif ext is tls.Extension.RENEGOTIATION_INFO:
                    logging.debug(
                        f"renegotiated_connection: "
                        f"{pdu.dump(extension.renegotiated_connection)}"
                    )

        self._kdf.start_msg_digest()

    def _post_serialization_ch(self, msg, msg_data):
        if self._ext_psk is not None:
            # Update the binders for the pre_shared_key extension
            binders_offset = (
                len(msg_data)
                - msg._bytes_after_psk_ext
                - self._ext_psk._bytes_after_ids
            )
            msg_without_binders = msg_data[:binders_offset]
            offset = binders_offset + 3  # skip length of list + length of 1st binder
            self.recorder.trace(msg_without_binders=msg_without_binders)

            for idx, psk in enumerate(self._ext_psk.psks):
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
        if self._send_early_data:
            self._record_layer_version = tls.Version.TLS12
            self.early_data.kdf.update_msg_digest(self.binders_bytes)
            hash_val = self.early_data.kdf.current_msg_digest(suspend=True)
            early_tr_secret = self.early_data.kdf.hkdf_expand_label(
                self.early_data.early_secret,
                "c e traffic",
                hash_val,
                self.early_data.mac_len,
            )
            KeyLogger.client_early_tr_secret(self.client_random, early_tr_secret)
            logging.debug(f"early traffic secret: {pdu.dump(early_tr_secret)}")
            cs_details = utils.get_cipher_suite_details(
                self._ext_psk.psks[0].cipher_suite
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

            self._record_layer.update_state(
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
        if self._key_exchange is None:
            if key_ex_type is tls.KeyExchangeType.RSA:
                self._key_exchange = kex.RsaKeyExchange(self, self.recorder)

            elif key_ex_type is tls.KeyExchangeType.ECDH:
                self._key_exchange = kex.EcdhKeyExchangeCertificate(self, self.recorder)

        self.premaster_secret = self._key_exchange.get_shared_secret()
        self.recorder.trace(pre_master_secret=self.premaster_secret)
        logging.debug(f"premaster_secret: {pdu.dump(self.premaster_secret)}")
        msg = cls()
        transferable_key = self._key_exchange.get_transferable_key()
        if key_ex_type is tls.KeyExchangeType.RSA:
            msg.rsa_encrypted_pms = transferable_key

        elif key_ex_type is tls.KeyExchangeType.ECDH:
            msg.ecdh_public = transferable_key

        elif key_ex_type is tls.KeyExchangeType.DH:
            msg.dh_public = transferable_key

        return msg

    def _post_sending_cke(self):
        if not self.cs_details.full_hs:
            raise ValueError(f"full handshake not supported for {self.cipher_suite}")

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
            msg.chain = self._tlsmate.client_auth.get_chain(self._clientauth_key_idx)

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
            ).encode() + self._kdf.current_msg_digest()
        else:
            data = self._kdf.get_handshake_messages()

        if self.recorder.is_injecting():
            signature = self.recorder.inject(signature=None)
        else:
            signature = self._sign_with_client_key(
                self._tlsmate.client_auth.get_key(self._clientauth_key_idx),
                self._clientauth_sig_algo,
                data,
            )
            self.recorder.trace(signature=signature)

        msg.signature = signature

        return msg

    # ##############################
    # sending EndOfEarlyData methods
    # ##############################

    def _post_sending_eoed(self):
        self._record_layer.update_state(self.hs_write_state)

    # ########################
    # sending Finished methods
    # ########################

    def _generate_finished(self, cls):
        suspend = self._finished_treated
        if self.version is tls.Version.TLS13:
            suspend = False

        hash_val = self._kdf.current_msg_digest(suspend=suspend)

        if self.version is tls.Version.TLS13:
            # TODO: server side implementation
            if self.handshake_completed:
                secret = self.c_app_tr_secret

            else:
                secret = self.c_hs_tr_secret

            finished_key = self._kdf.hkdf_expand_label(
                secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            val = self._kdf.hkdf_extract(hash_val, finished_key)

        elif self.version is tls.Version.SSL30:
            val = self._kdf._backend.ssl30_digest(self.master_secret, b"CLNT")
            self._update_write_state()

        else:
            if self._entity == tls.Entity.CLIENT:
                label = b"client finished"

            else:
                label = b"server finished"

            val = self._kdf.prf(self.master_secret, label, hash_val, 12)
            self._secure_reneg_cl_data = val
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
        self.c_app_tr_secret = self._kdf.hkdf_expand_label(
            self.master_secret,
            "c ap traffic",
            self.server_finished_digest,
            self.cs_details.mac_struct.key_len,
        )
        KeyLogger.client_tr_secret_0(self.client_random, self.c_app_tr_secret)
        logging.debug(f"c_app_tr_secret: {pdu.dump(self.c_app_tr_secret)}")
        c_enc = self._kdf.hkdf_expand_label(
            self.c_app_tr_secret, "key", b"", ciph.key_len
        )
        c_iv = self._kdf.hkdf_expand_label(self.c_app_tr_secret, "iv", b"", ciph.iv_len)

        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(client_write_iv=c_iv)

        self._record_layer.update_state(
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
        hash_val = self._kdf.current_msg_digest(suspend=True)
        self.res_ms = self._kdf.hkdf_expand_label(
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
        message, e.g. for a ClientKeyExchange the key exchange and key derivation
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

    def _validate_cert_chain(self, cert_chain):
        timestamp = self.recorder.get_timestamp()
        sni_ext = self.msg.client_hello.get_extension(tls.Extension.SERVER_NAME)
        if sni_ext is not None:
            sni = sni_ext.host_name

        else:
            sni = self.client.get_sni()
            if sni is None:
                raise ValueError("No SNI defined")

        cert_chain.validate(timestamp, sni, self.client.alert_on_invalid_cert)

    def send(self, *messages, pre_serialization=None, **kwargs):
        """Interface to send messages.

        Each message given here will be sent in a separate record layer record,
        all record layer records will be passed altogether to the TCP layer.

        Arguments:
            *messages: either a class or an object of
                :class:`tlsmate.msg.TlsMessage`. If a class is passed, appropriate
                methods will be called to instantiate an object automagically.
            pre_serialization (func): an optional callback function, which can be used
                to process an automagically generated message before it is serialized.
                Can be suitable, e.g. to modify message parameters without the need
                to setup the message completely by its own (which can be rather
                difficult, e.g. for a Finished message).
                The function receives the message object
                (:obj:`tlsmate.msg.TlsMessage`) as an argument. No return value is
                expected.
        """

        for message in messages:
            if inspect.isclass(message):
                message = self._generate_outgoing_msg(message)
                if message is None:
                    continue

            if pre_serialization is not None:
                pre_serialization(message)

            logging.info(f"{utils.Log.time()}: ==> {message.msg_type}")
            self._pre_serialization_hook(message)
            self._msg_logging(message)
            msg_data = message.serialize(self)
            msg_data = self._post_serialization_hook(message, msg_data)
            self.msg.store_msg(message, received=False)
            if message.content_type == tls.ContentType.HANDSHAKE:
                self._kdf.update_msg_digest(msg_data)

            elif message.content_type == tls.ContentType.ALERT:
                self.alert_sent = True

            self._record_layer.send_message(
                structs.RecordLayerMsg(
                    content_type=message.content_type,
                    version=self._record_layer_version,
                    fragment=msg_data,
                ),
                **kwargs,
            )
            self._post_sending_hook(message)
        self._record_layer.flush()

    def _on_server_hello_tls13(self, msg):
        psk = None
        psk_ext = msg.get_extension(tls.Extension.PRE_SHARED_KEY)
        if psk_ext is not None:
            psk_idx = psk_ext.selected_id
            ch_psks = self.msg.client_hello.get_extension(tls.Extension.PRE_SHARED_KEY)
            if ch_psks is not None:
                if psk_idx >= len(ch_psks.psks):
                    raise ServerMalfunction(tls.ServerIssue.PSK_OUT_OF_RANGE)

                psk = ch_psks.psks[psk_idx].psk
                self.abbreviated_hs = True

        key_share_ext = msg.get_extension(tls.Extension.KEY_SHARE)
        if key_share_ext is None:
            if not self.abbreviated_hs:
                raise ServerMalfunction(tls.ServerIssue.KEY_SHARE_NOT_PRESENT)

            shared_secret = None

        else:
            share_entry = key_share_ext.key_shares[0]
            self._key_exchange = self._key_shares[share_entry.group]
            self._key_exchange.set_remote_key(
                share_entry.key_exchange, group=share_entry.group
            )
            shared_secret = self._key_exchange.get_shared_secret()
            logging.debug(f"shared_secret: {pdu.dump(shared_secret)}")

        self._tls13_key_schedule(psk, shared_secret)

    def _on_server_hello_tls12(self, msg):
        if len(msg.session_id):
            if msg.session_id == self._session_id_sent:
                self.abbreviated_hs = True
                # TODO: check version and ciphersuite
                if self._ticket_sent:
                    self.master_secret = self.client.session_state_ticket.master_secret

                else:
                    self.master_secret = self.client.session_state_id.master_secret

                logging.debug(f"master_secret: {pdu.dump(self.master_secret)}")
                KeyLogger.master_secret(self.client_random, self.master_secret)
                self._key_derivation()

            else:
                self._new_session_id = msg.session_id

        self._encrypt_then_mac = (
            msg.get_extension(tls.Extension.ENCRYPT_THEN_MAC) is not None
        )
        self.extended_ms = (
            msg.get_extension(tls.Extension.EXTENDED_MASTER_SECRET) is not None
        )
        if self._secure_reneg_request:
            data = None
            reneg = msg.get_extension(tls.Extension.RENEGOTIATION_INFO)
            if reneg is not None:
                data = reneg.renegotiated_connection

            if self._initial_handshake:
                self._secure_reneg_flag = False
                if data == b"":
                    self._secure_reneg_flag = True
                    logging.debug("renegotiation extension successfully verified")

                elif data is not None:
                    raise ServerMalfunction(tls.ServerIssue.SECURE_RENEG_FAILED)

            elif self._secure_reneg_flag:
                self._secure_reneg_flag = False
                if self._secure_reneg_cl_data and self._secure_reneg_sv_data:
                    if data != self._secure_reneg_cl_data + self._secure_reneg_sv_data:
                        raise ServerMalfunction(tls.ServerIssue.SECURE_RENEG_FAILED)

                    self._secure_reneg_flag = True
                    logging.debug("renegotiation extension successfully verified")

                else:
                    raise ServerMalfunction(tls.ServerIssue.SECURE_RENEG_FAILED)

            self._secure_reneg_cl_data = None
            self._secure_reneg_sv_data = None

    def _on_server_hello_received(self, msg):
        self.server_random = msg.random
        logging.debug(f"server random: {pdu.dump(msg.random)}")
        self.version = msg.get_version()
        logging.info(f"version: {self.version}")
        logging.info(f"cipher suite: 0x{msg.cipher_suite.value:04x} {msg.cipher_suite}")
        self._update_cipher_suite(msg.cipher_suite)
        self._record_layer_version = min(self.version, tls.Version.TLS12)
        heartbeat_ext = msg.get_extension(tls.Extension.HEARTBEAT)
        if heartbeat_ext:
            self.heartbeat_allowed_to_send = (
                heartbeat_ext.heartbeat_mode is tls.HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
        if self.version is tls.Version.TLS13:
            self._on_server_hello_tls13(msg)

        else:
            self._on_server_hello_tls12(msg)

    def _handle_signed_params(self, params, string):
        if params:
            randoms = self.msg.client_hello.random + self.msg.server_hello.random
            cert = self.msg.server_certificate.chain.certificates[0]
            try:
                kex.verify_signed_params(
                    randoms,
                    params,
                    cert,
                    self.cs_details.key_algo_struct.default_sig_scheme,
                    self.version,
                )
                logging.debug(f"signed {string} parameters successfully verified")

            except crypto_exc.InvalidSignature:
                error = (
                    f"signature of server's {string} key exchange "
                    f"parameters is invalid"
                )
                cert.issues.append(error)
                logging.debug(error)
                issue = tls.ServerIssue.KEX_INVALID_SIGNATURE
                if self.client.alert_on_invalid_cert:
                    raise ServerMalfunction(
                        issue, message=tls.HandshakeType.SERVER_KEY_EXCHANGE
                    )

                else:
                    self.client.report_server_issue(issue)

    def _on_server_key_exchange_received(self, msg):
        if not (msg.ec or msg.dh):
            return

        if msg.ec is not None:
            if msg.ec.signed_params is not None:
                self._handle_signed_params(msg.ec, "EC")

            if msg.ec.named_curve is not None:
                logging.debug(f"named curve: {msg.ec.named_curve}")
                self._key_exchange = kex.instantiate_named_group(
                    msg.ec.named_curve, self, self.recorder
                )
                self._key_exchange.set_remote_key(msg.ec.public)

        elif msg.dh is not None:
            dh = msg.dh
            if dh.signed_params is not None:
                self._handle_signed_params(dh, "DH")

            logging.debug(f"DH group size: {len(dh.p_val) * 8}")
            self._key_exchange = kex.DhKeyExchange(self, self.recorder)
            self._key_exchange.set_remote_key(
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
                self._record_layer.update_state(self.hs_write_state)

            finished_key = self._kdf.hkdf_expand_label(
                self.s_hs_tr_secret, "finished", b"", self.cs_details.mac_struct.key_len
            )
            logging.debug(f"finished_key: {pdu.dump(finished_key)}")
            calc_verify_data = self._kdf.hkdf_extract(
                self._pre_finished_digest, finished_key
            )
            logging.debug(f"calc. verify_data: {pdu.dump(calc_verify_data)}")
            if calc_verify_data != msg.verify_data:
                raise ServerMalfunction(tls.ServerIssue.VERIFY_DATA_INVALID)

            self.server_finished_digest = self._kdf.current_msg_digest()
            s_app_tr_secret = self._kdf.hkdf_expand_label(
                self.master_secret,
                "s ap traffic",
                self.server_finished_digest,
                self.cs_details.mac_struct.key_len,
            )
            KeyLogger.server_tr_secret_0(self.client_random, s_app_tr_secret)
            logging.debug(f"s_app_tr_secret: {pdu.dump(s_app_tr_secret)}")
            s_enc = self._kdf.hkdf_expand_label(
                s_app_tr_secret, "key", b"", ciph.key_len
            )
            s_iv = self._kdf.hkdf_expand_label(s_app_tr_secret, "iv", b"", ciph.iv_len)

            self.recorder.trace(server_write_key=s_enc)
            self.recorder.trace(server_write_iv=s_iv)
            self._record_layer.update_state(
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
            if self.version is tls.Version.SSL30:
                val = self._kdf._backend.ssl30_digest(self.master_secret, b"SRVR")

            else:
                if self._entity == tls.Entity.CLIENT:
                    label = b"server finished"

                else:
                    label = b"client finished"

                val = self._kdf.prf(
                    self.master_secret, label, self._pre_finished_digest, 12
                )

            self._secure_reneg_sv_data = val
            self.recorder.trace(msg_digest_finished_rec=self._pre_finished_digest)
            self.recorder.trace(verify_data_finished_rec=msg.verify_data)
            self.recorder.trace(verify_data_finished_calc=val)
            if msg.verify_data != val:
                raise ServerMalfunction(tls.ServerIssue.VERIFY_DATA_INVALID)

        logging.debug("Received Finished successfully verified")
        if self._finished_treated:
            self.handshake_completed = True
            logging.debug("Handshake finished, secure connection established")

        self._finished_treated = True
        return self

    def _on_certificate_status_received(self, msg):
        cert_chain = self.msg.server_certificate.chain
        self._validate_cert_chain(cert_chain)
        self.stapling_status = cert_chain.verify_ocsp_stapling(
            msg.responses, self.client.alert_on_invalid_cert
        )

    def _on_new_session_ticket_received(self, msg):
        if self.version is tls.Version.TLS13:
            psk = self._kdf.hkdf_expand_label(
                self.res_ms, "resumption", msg.nonce, self.cs_details.mac_struct.mac_len
            )
            logging.debug(f"PSK: {pdu.dump(psk)}")
            utils.log_extensions(msg.extensions)
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
            self._record_layer.update_state(self.hs_write_state)

    def _on_certificate_received(self, msg):
        self._validate_cert_chain(msg.chain)
        if self.version is tls.Version.TLS13:
            self.certificate_digest = self._kdf.current_msg_digest()
            ext_status_req = get_extension(
                msg.chain.certificates[0].tls_extensions, tls.Extension.STATUS_REQUEST
            )
            if ext_status_req:
                self.stapling_status = msg.chain.verify_ocsp_stapling(
                    [ext_status_req.ocsp_response], self.client.alert_on_invalid_cert
                )

    def _on_certificate_request_received(self, msg):
        if self.version is tls.Version.TLS13:
            sig_algo_ext = msg.get_extension(tls.Extension.SIGNATURE_ALGORITHMS)
            if sig_algo_ext is None:
                raise ServerMalfunction(tls.ServerIssue.CERT_REQ_NO_SIG_ALGO)

            algos = sig_algo_ext.signature_algorithms

        else:
            algos = msg.supported_signature_algorithms

        idx = None
        for algo in algos:
            idx = self._tlsmate.client_auth.find_algo(algo, self.version)
            if idx is not None:
                self._clientauth_key_idx = idx
                self._clientauth_sig_algo = algo
                break

        if idx is None:
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
        tls.HandshakeType.CERTIFICATE_STATUS: _on_certificate_status_received,
        tls.HandshakeType.NEW_SESSION_TICKET: _on_new_session_ticket_received,
    }

    def _on_msg_received(self, msg):
        """Called whenever a message is received before it is passed to the test case
        """
        method = self._on_msg_received_map.get(msg.msg_type)
        if method is not None:
            method(self, msg)

    def _auto_heartbeat_request(self, message):
        if self.client.profile.heartbeat_mode is tls.HeartbeatMode.PEER_ALLOWED_TO_SEND:
            response = msg.HeartbeatResponse()
            response.payload_length = message.payload_length
            response.payload = message.payload
            response.padding = b"\xff" * 16
            self.send(response)

    _auto_responder_map = {
        tls.HeartbeatType.HEARTBEAT_REQUEST: _auto_heartbeat_request,
    }
    """Maps the message to the auto handler function.

    Auto handler functions are only required, if specific actions must be taken, e.g.,
    sending a response.
    """

    def _auto_responder(self, msg):
        """Automatically process messages which are not passed back to the test case.
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

    def _wait_message(self, timeout=5000, **kwargs):
        mb = self._defragmenter.get_message(timeout, **kwargs)
        if mb is None:
            return None, None

        if mb.content_type is tls.ContentType.HANDSHAKE:
            message = msg.HandshakeMessage.deserialize(mb.msg, self)
            if message.msg_type is tls.HandshakeType.FINISHED:
                self._pre_finished_digest = self._kdf.current_msg_digest(
                    suspend=self._finished_treated
                )

            if message.msg_type is tls.HandshakeType.CERTIFICATE_REQUEST:
                self._kdf.resume_msg_digest()

            if self._kdf.msg_digest_active():
                self._kdf.update_msg_digest(mb.msg)

        elif mb.content_type is tls.ContentType.ALERT:
            self.alert_received = True
            message = msg.Alert.deserialize(mb.msg, self)

        elif mb.content_type is tls.ContentType.CHANGE_CIPHER_SPEC:
            message = msg.ChangeCipherSpecMessage.deserialize(mb.msg, self)

        elif mb.content_type is tls.ContentType.APPLICATION_DATA:
            message = msg.AppDataMessage.deserialize(mb.msg, self)

        elif mb.content_type is tls.ContentType.HEARTBEAT:
            message = msg.HeartbeatMessage.deserialize(mb.msg, self)

        elif mb.content_type is tls.ContentType.SSL2:
            message = msg.SSL2Message.deserialize(mb.msg, self)

        else:
            raise ValueError("Content type unknown")

        logging.info(f"{utils.Log.time()}: <== {message.msg_type}")
        self._msg_logging(message)
        self.msg.store_msg(message, received=True)
        return message, mb.msg

    def wait_msg_bytes(
        self,
        msg_class,
        optional=False,
        max_nbr=1,
        timeout=5000,
        fail_on_timeout=True,
        **kwargs,
    ):
        """Interface to wait for a message from the peer.

        Arguments:
            msg_class (:class:`tlsmate.msg.TlsMessage`): the class of the awaited
                message
            optional (bool): an indication if the message is optional. Defaults to False
            max_nbr (int): the number of identical message types to wait for. Well
                suitable for NewSessionTicket messages. Defaults to 1.
            timeout (int): the message timeout in milliseconds
            fail_on_timeout (bool): if True, in case of a timeout raise an exception,
                otherwise return (None, None)

        Returns:
            tuple(:obj:`tlsmate.msg.TlsMessage`, bytearray):
            the message received and the message as bytes. In case of a timeout
            (None, None) is returned if fail_on_timeout is False

        Raises:
            ScanError: In case an unexpected message is received
            TlsMsgTimeoutError: In case fail_on_timeout is True and a timeout occurred.
        """
        ultimo = time.time() + (timeout / 1000)
        min_nbr = 0 if optional else 1
        cnt = 0
        self._awaited_msg = msg_class
        expected_msg = None
        expected_bytes = None
        while True:
            if self._queued_msg:
                message = self._queued_msg
                msg_bytes = self._queued_bytes
                self._queued_msg = None

            else:
                try:
                    message, msg_bytes = self._wait_message(
                        ultimo - time.time(), **kwargs
                    )

                except TlsMsgTimeoutError as exc:
                    if msg_class is msg.Timeout:
                        return msg.Timeout(), None

                    elif cnt >= min_nbr:
                        return expected_msg, expected_bytes

                    elif fail_on_timeout:
                        raise exc

                    else:
                        return None, None

            if (msg_class == msg.Any) or isinstance(message, msg_class):
                self._on_msg_received(message)
                cnt += 1
                if cnt == max_nbr:
                    return message, msg_bytes

                else:
                    expected_msg = message
                    expected_bytes = msg_bytes

            elif message.msg_type in self.auto_handler:
                self._on_msg_received(message)
                self._auto_responder(message)

            else:
                if cnt >= min_nbr:
                    self._queued_msg = message
                    self._queued_bytes = msg_bytes
                    return expected_msg, expected_bytes

                else:
                    logging.warning("unexpected message received")
                    raise ScanError(
                        (
                            f"Unexpected message received: {message.msg_type}, "
                            f"expected: {msg_class.msg_type}"
                        )
                    )

    def wait(self, msg_class, **kwargs):
        """Interface to wait for a message from the peer.

        Arguments:
            msg_class (:class:`tlsmate.msg.TlsMessage`): the class of the awaited
                message
            optional (bool): an indication if the message is optional. Defaults to False
            max_nbr (int): the number of identical message types to wait for. Well
                suitable for NewSessionTicket messages. Defaults to 1.
            timeout (int): the message timeout in milliseconds
            fail_on_timeout (bool): if True, in case of a timeout raise an exception,
                otherwise return (None, None)

        Returns:
            :obj:`tlsmate.msg.TlsMessage`: the message received or None in case
            of a timeout and fail_on_timeout is False.

        Raises:
            ScanError: In case an unexpected message is received
            TlsMsgTimeoutError: In case fail_on_timeout is True and a timeout occured.
        """

        return self.wait_msg_bytes(msg_class, **kwargs)[0]

    def _update_write_state(self):
        state = self._get_pending_write_state(self._entity)
        self._record_layer.update_state(state)

    def _update_read_state(self):
        if self._entity == tls.Entity.CLIENT:
            entity = tls.Entity.SERVER

        else:
            entity = tls.Entity.CLIENT

        state = self._get_pending_write_state(entity)
        self._record_layer.update_state(state)

    def _update_cipher_suite(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.cs_details = utils.get_cipher_suite_details(cipher_suite)

        if not self.cs_details.full_hs:
            logging.debug(
                f"full handshake for cipher suite {cipher_suite} not supported"
            )
            return

        if self.version < tls.Version.TLS12:
            self._kdf.set_msg_digest_algo(None)

        else:
            self._kdf.set_msg_digest_algo(self.cs_details.mac_struct.hmac_algo)

        logging.debug(f"hash_primitive: {self.cs_details.mac}")
        logging.debug(f"cipher_primitive: {self.cs_details.cipher_struct.primitive}")

    def _generate_master_secret(self):
        if self.version is tls.Version.SSL30:
            self.master_secret = self._kdf._backend.ssl3_master_secret(
                self.premaster_secret, self.client_random + self.server_random
            )

        elif self.extended_ms:
            msg_digest = self._kdf.current_msg_digest()
            self.master_secret = self._kdf.prf(
                self.premaster_secret, b"extended master secret", msg_digest, 48
            )

        else:
            self.master_secret = self._kdf.prf(
                self.premaster_secret,
                b"master secret",
                self.client_random + self.server_random,
                48,
            )

        KeyLogger.master_secret(self.client_random, self.master_secret)
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
        early_secret = self._kdf.hkdf_extract(psk, b"")
        logging.debug(f"early_secret: {pdu.dump(early_secret)}")
        empty_msg_digest = self._kdf.empty_msg_digest()
        logging.debug(f"empty msg digest: {pdu.dump(empty_msg_digest)}")
        derived = self._kdf.hkdf_expand_label(
            early_secret, "derived", empty_msg_digest, mac.key_len
        )

        handshake_secret = self._kdf.hkdf_extract(shared_secret, derived)
        logging.debug(f"handshake secret: {pdu.dump(handshake_secret)}")
        hello_digest = self._kdf.current_msg_digest()
        logging.debug(f"hello_digest: {pdu.dump(hello_digest)}")
        c_hs_tr_secret = self._kdf.hkdf_expand_label(
            handshake_secret, "c hs traffic", hello_digest, mac.key_len
        )
        KeyLogger.client_hs_tr_secret(self.client_random, c_hs_tr_secret)
        c_enc = self._kdf.hkdf_expand_label(c_hs_tr_secret, "key", b"", ciph.key_len)
        c_iv = self._kdf.hkdf_expand_label(c_hs_tr_secret, "iv", b"", ciph.iv_len)
        s_hs_tr_secret = self._kdf.hkdf_expand_label(
            handshake_secret, "s hs traffic", hello_digest, mac.key_len
        )
        KeyLogger.server_hs_tr_secret(self.client_random, s_hs_tr_secret)
        s_enc = self._kdf.hkdf_expand_label(s_hs_tr_secret, "key", b"", ciph.key_len)
        s_iv = self._kdf.hkdf_expand_label(s_hs_tr_secret, "iv", b"", ciph.iv_len)
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

        self._record_layer.update_state(
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

        derived = self._kdf.hkdf_expand_label(
            handshake_secret, "derived", empty_msg_digest, mac.key_len
        )

        self.master_secret = self._kdf.hkdf_extract(None, derived)

    def _key_derivation(self):
        ciph = self.cs_details.cipher_struct
        if self.version is tls.Version.SSL30:
            mac_len = self.cs_details.mac_struct.key_len
            key_material = self._kdf._backend.ssl3_key_material(
                self.master_secret,
                self.server_random + self.client_random,
                2 * (mac_len + ciph.key_len + ciph.iv_len),
            )
            logging.debug(f"keying material: {pdu.dump(key_material)}")

        else:

            if ciph.c_type is tls.CipherType.AEAD:
                mac_len = 0

            else:
                mac_len = self.cs_details.mac_struct.key_len

            key_material = self._kdf.prf(
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

        # TODO: SSL30, export ciphers

        self.recorder.trace(client_write_mac_key=c_mac)
        self.recorder.trace(server_write_mac_key=s_mac)
        self.recorder.trace(client_write_key=c_enc)
        self.recorder.trace(server_write_key=s_enc)
        self.recorder.trace(client_write_iv=c_iv)
        self.recorder.trace(server_write_iv=s_iv)
        self._client_write_keys = structs.SymmetricKeys(mac=c_mac, enc=c_enc, iv=c_iv)
        self._server_write_keys = structs.SymmetricKeys(mac=s_mac, enc=s_enc, iv=s_iv)

    def _get_pending_write_state(self, entity):
        if entity is tls.Entity.CLIENT:
            keys = self._client_write_keys

        else:
            keys = self._server_write_keys

        return structs.StateUpdateParams(
            cipher=self.cs_details.cipher_struct,
            mac=self.cs_details.mac_struct,
            keys=keys,
            compr=self._compression_method,
            enc_then_mac=self._encrypt_then_mac,
            version=self.version,
            is_write_state=(entity is tls.Entity.CLIENT),
        )

    def timeout(self, timeout):
        """Implement a timeout function

        This function will wait until the timeout expires. Messages received during
        the timeout will cause the function to fail.

        Arguments:
            timeout (int): the timeout in milliseconds

        Raises:
            ScanError: In case an unexpected message is received
        """
        self.wait(msg.Timeout, timeout=timeout)

    def handshake(self, ch_pre_serialization=None):
        """Convenient method to execute a complete handshake.

        With this method there is no need to define the exact scenario. The parameters
        for the ClientHello message are taken from the client profile.

        Covers the following cases:

        TLS1.0-TLS1.2:

        * full handshake
        * abbreviated handshake (with and without server authentication)
        * client authentication

        TLS1.3:

        * full handshake
        * abbreviated handshake
        * 0-RTT
        * client authentication

        Note:
            The handshake finishes with the exchange of the Finished messages, i.e.,
            receiving messages hereafter needs to be covered separately, e.g. receiving
            NewSessionTicket messages in TLS1.3 (if not treated by the auto_handler).

        Arguments:
            ch_pre_serialization (func): a call back function executed after
                the parameters for the ClientHello are setup, but before its
                serialization. Useful to manipulate the ClientHello.
                The function receives the client_hello object
                (:obj:`tlsmate.msg.TlsMessage`) as an argument. No return value is
                expected.
        """
        self.send(msg.ClientHello, pre_serialization=ch_pre_serialization)
        if self.client.profile.early_data is not None:
            self.send(msg.AppData(self.client.profile.early_data))

        self.wait(msg.ServerHello)
        if self.version is tls.Version.TLS13:
            self.wait(msg.ChangeCipherSpec, optional=True)
            self.wait(msg.EncryptedExtensions)
            cert_req = None
            if not self.abbreviated_hs:
                cert_req = self.wait(msg.CertificateRequest, optional=True)
                self.wait(msg.Certificate)
                self.wait(msg.CertificateVerify)

            self.wait(msg.Finished)
            if self.early_data_accepted:
                self.send(msg.EndOfEarlyData)

            elif cert_req is not None:
                self.send(msg.Certificate)
                self.send(msg.CertificateVerify)

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
                    self.wait(msg.CertificateStatus, optional=True)

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
