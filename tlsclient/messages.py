# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import logging
import tlsclient.constants as tls
from tlsclient.protocol import ProtocolData
import tlsclient.extensions as ext
from tlsclient.alert import FatalAlert
from tlsclient.security_parameters import get_random_value


class TlsMessage(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def deserialize(cls, fragment, conn):
        pass

    def auto_generate_msg(self, conn):
        pass

    @abc.abstractmethod
    def serialize(self, conn):
        pass


class HandshakeMessage(TlsMessage):

    content_type = tls.ContentType.HANDSHAKE
    msg_type = None

    @classmethod
    def deserialize(cls, fragment, conn):
        msg_type, offset = fragment.unpack_uint8(0)
        msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
        logging.info("Receiving {}".format(msg_type.name))
        length, offset = fragment.unpack_uint24(offset)
        if length + offset != len(fragment):
            raise FatalAlert(
                "Length of {} incorrect".format(msg_type),
                tls.AlertDescription.DECODE_ERROR,
            )
        cls_name = _hs_deserialization_map[msg_type]
        msg = cls_name()._deserialize_msg_body(fragment, offset, conn)
        conn.update_msg_hash(fragment)
        return msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, msg_body, length, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass

    def auto_generate_msg(self, conn):
        return self

    def serialize(self, conn):
        msg_body = self._serialize_msg_body(conn)

        handshake_msg = ProtocolData()
        handshake_msg.append_uint8(self.msg_type.value)
        handshake_msg.append_uint24(len(msg_body))
        handshake_msg.extend(msg_body)
        conn.update_msg_hash(handshake_msg)
        logging.info("Sending {}".format(self.msg_type.name))
        return handshake_msg


class ClientHello(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_HELLO

    def __init__(self):
        self.client_version = tls.Version.TLS12
        self.random = get_random_value()
        self.session_id = ProtocolData()
        self.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []

    def auto_generate_msg(self, conn):
        self.init_from_profile(conn.client_profile)

    def init_from_profile(self, profile):
        self.client_version = max(profile.versions)
        if profile.support_session_id and profile.session_id:
            self.session_id = profile.session_id
        self.session_id = profile.session_id
        self.cipher_suites = profile.cipher_suites
        self.compression_methods = profile.compression_methods
        self.extensions = []
        if profile.support_sni:
            self.extensions.append(
                ext.ExtServerNameIndication(host_name=profile.server_name)
            )
        if profile.support_extended_master_secret:
            self.extensions.append(ext.ExtExtendedMasterSecret())
        if profile.support_ec_point_formats:
            self.extensions.append(
                ext.ExtEcPointFormats(ec_point_formats=profile.ec_point_formats)
            )
        if profile.support_supported_groups:
            self.extensions.append(
                ext.ExtSupportedGroups(supported_groups=profile.supported_groups)
            )
        if profile.support_signature_algorithms:
            self.extensions.append(
                ext.ExtSignatureAlgorithms(
                    signature_algorithms=profile.signature_algorithms
                )
            )
        if profile.support_encrypt_then_mac:
            self.extensions.append(ext.ExtEncryptThenMac())
        return self

    def _serialize_msg_body(self, conn):
        msg = ProtocolData()

        # version
        version = self.client_version
        if type(version) == tls.Version:
            version = version.value
        conn.update(client_version_sent=version)
        msg.append_uint16(version)

        # random
        if self.random is None:
            self.random = get_random_value()
        self.random = conn.recorder.inject(client_random=self.random)
        logging.info("client_random: {}".format(self.random.dump()))
        conn.update(client_random=self.random)
        msg.extend(self.random)

        # session_id
        msg.append_uint8(len(self.session_id))
        msg.extend(self.session_id)

        # cipher suites
        msg.append_uint16(2 * len(self.cipher_suites))
        for cipher_suite in self.cipher_suites:
            if type(cipher_suite) == int:
                msg.append_uint16(cipher_suite)
            else:
                msg.append_uint16(cipher_suite.value)

        # compression methods
        msg.append_uint8(len(self.compression_methods))
        for comp_meth in self.compression_methods:
            if type(comp_meth) == tls.CompressionMethod:
                comp_meth = comp_meth.value
            msg.append_uint8(comp_meth)

        # extensions
        ext_bytes = ProtocolData()
        for extension in self.extensions:
            ext_bytes.extend(extension.serialize())
        msg.append_uint16(len(ext_bytes))
        msg.extend(ext_bytes)

        conn.init_msg_hash()
        return msg

    def _deserialize_msg_body(self, msg_body, length, conn):
        return self


class ServerHello(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):

        version, offset = fragment.unpack_uint16(offset)
        self.version = tls.Version.val2enum(version, alert_on_failure=True)
        self.random, offset = fragment.unpack_bytes(offset, 32)
        session_id_len, offset = fragment.unpack_uint8(offset)
        self.session_id, offset = fragment.unpack_bytes(offset, session_id_len)
        cipher_suite, offset = fragment.unpack_uint16(offset)
        self.cipher_suite = tls.CipherSuite.val2enum(
            cipher_suite, alert_on_failure=True
        )
        compression_method, offset = fragment.unpack_uint8(offset)
        self.compression_method = tls.CompressionMethod.val2enum(
            compression_method, alert_on_failure=True
        )
        self.extensions = []
        if offset < len(fragment):
            # extensions present
            ext_len, offset = fragment.unpack_uint16(offset)
            while offset < len(fragment):
                extension, offset = ext.Extension.deserialize(fragment, offset)
                self.extensions.append(extension)

        conn.update(
            version=self.version,
            cipher_suite=self.cipher_suite,
            server_random=self.random,
            server_hello=self,
        )
        logging.info("TLS version: {}".format(self.version.name))
        logging.info("Cipher suite: {}".format(self.cipher_suite.name))
        logging.info("server_random: {}".format(self.random.dump()))
        return self


class Certificate(HandshakeMessage):

    msg_type = tls.HandshakeType.CERTIFICATE

    def _serialize_msg_body(self, conn):
        # TODO
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.certificates = []
        list_len, offset = fragment.unpack_uint24(offset)
        while offset < len(fragment):
            cert_len, offset = fragment.unpack_uint24(offset)
            cert, offset = fragment.unpack_bytes(offset, cert_len)
            self.certificates.append(cert)
        return self


class KeyExchangeEC(object):
    def deserialize_ECParameters(self, fragment, offset, conn):
        curve_type, offset = fragment.unpack_uint8(offset)
        self.curve_type = tls.EcCurveType.val2enum(curve_type)
        if self.curve_type is tls.EcCurveType.NAMED_CURVE:
            named_curve, offset = fragment.unpack_uint16(offset)
            self.named_curve = tls.SupportedGroups.val2enum(named_curve)
            logging.debug("named curve: " + self.named_curve.name)
            conn.update(named_curve=self.named_curve)
        # TODO: add other curve types
        return offset

    def deserialize_ServerECDHParams(self, fragment, offset, conn):
        # ECParameters    curve_params;
        offset = self.deserialize_ECParameters(fragment, offset, conn)
        # ECPoint         public;
        point_len, offset = fragment.unpack_uint8(offset)
        self.public, offset = fragment.unpack_bytes(offset, point_len)
        conn.update(remote_public_key=self.public)

        return offset

    def _deserialize_msg_body(self, fragment, offset, conn):
        # ServerECDHParams    params;
        offset = self.deserialize_ServerECDHParams(fragment, offset, conn)
        # Signature           signed_params;
        signature_scheme, offset = fragment.unpack_uint16(offset)
        self.signature_scheme = tls.SignatureScheme.val2enum(signature_scheme)
        signature_len, offset = fragment.unpack_uint16(offset)
        self.signature, offset = fragment.unpack_bytes(offset, signature_len)
        return self


class KeyExchangeDH(object):
    def _deserialize_msg_body(self, fragment, offset, conn):
        p_length, offset = fragment.unpack_uint16(offset)
        self.p_val, offset = fragment.unpack_bytes(offset, p_length)
        g_len, offset = fragment.unpack_uint16(offset)
        g_bytes, offset = fragment.unpack_bytes(offset, g_len)
        self.g_val = int.from_bytes(g_bytes, "big")
        pub_key_len, offset = fragment.unpack_uint16(offset)
        self.public_key, offset = fragment.unpack_bytes(offset, pub_key_len)
        sig_scheme, offset = fragment.unpack_uint16(offset)
        self.sig_scheme = tls.SignatureScheme.val2enum(sig_scheme)
        sig_length, offset = fragment.unpack_uint16(offset)
        self.signature, offset = fragment.unpack_bytes(offset, sig_length)
        return self


class ServerKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_KEY_EXCHANGE

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.ec = None
        self.dh = None
        key_exchange_method = conn.key_exchange_method
        if key_exchange_method in [
            tls.KeyExchangeAlgorithm.ECDH_ECDSA,
            tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
            tls.KeyExchangeAlgorithm.ECDH_RSA,
            tls.KeyExchangeAlgorithm.ECDHE_RSA,
        ]:
            # RFC 4492
            self.ec = KeyExchangeEC()._deserialize_msg_body(fragment, offset, conn)
        elif key_exchange_method in [
            tls.KeyExchangeAlgorithm.DHE_DSS,
            tls.KeyExchangeAlgorithm.DHE_RSA,
            tls.KeyExchangeAlgorithm.DH_ANON,
        ]:
            # RFC5246
            self.dh = KeyExchangeDH()._deserialize_msg_body(fragment, offset, conn)
        else:
            raise FatalAlert(
                "Key exchange algorithm incompatible with ServerKeyExchange message",
                tls.AlertDescription.UNEXPECTED_MESSAGE,
            )
        conn.key_exchange.inspect_server_key_exchange(self)
        return self


class ServerHelloDone(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO_DONE

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return self


class ClientKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_KEY_EXCHANGE

    def _serialize_msg_body(self, conn):
        msg = ProtocolData()
        if conn.key_exchange_method == tls.KeyExchangeAlgorithm.RSA:
            data = conn.rsa_key_transport()
            msg.append_uint16(len(data))
            msg.extend(data)
        elif conn.key_exchange_method == tls.KeyExchangeAlgorithm.DHE_RSA:
            msg.append_uint16(len(self.client_dh_public))
            msg.extend(self.client_dh_public)
        else:
            msg.append_uint8(len(self.client_ec_public))
            msg.extend(self.client_ec_public)
        return msg

    def auto_generate_msg(self, conn):
        conn.update_keys()
        conn.key_exchange.setup_client_key_exchange(self)

    def _deserialize_msg_body(self, fragment, offset, conn):
        pass


class Finished(HandshakeMessage):

    msg_type = tls.HandshakeType.FINISHED

    def _serialize_msg_body(self, conn):
        if conn.entity == tls.Entity.CLIENT:
            hash_val = conn.finalize_msg_hash(intermediate=True)
            label = b"client finished"
        else:
            hash_val = conn.finalize_msg_hash()
            label = b"server finished"

        val = conn.prf(conn.master_secret, label, hash_val, 12)
        conn.recorder.trace(msg_digest_finished_sent=hash_val)
        conn.recorder.trace(verify_data_finished_sent=val)
        msg = ProtocolData(val)
        logging.debug("Finished.verify_data(out): {}".format(msg.dump()))
        return msg

    def _deserialize_msg_body(self, fragment, offset, conn):
        verify_data = fragment[offset:]
        logging.debug(
            "Finished.verify_data(in): {}".format(ProtocolData(verify_data).dump())
        )
        if conn.entity == tls.Entity.CLIENT:
            hash_val = conn.finalize_msg_hash()
            label = b"server finished"
        else:
            hash_val = conn.finalize_msg_hash(intermediate=True)
            label = b"client finished"
        val = conn.prf(conn.master_secret, label, hash_val, 12)
        conn.recorder.trace(msg_digest_finished_rec=hash_val)
        conn.recorder.trace(verify_data_finished_rec=verify_data)
        conn.recorder.trace(verify_data_finished_calc=val)
        if verify_data != val:
            FatalAlert(
                "Received Finidhed: verify_data does not match",
                tls.AlertDescription.BAD_RECORD_MAC,
            )
        logging.info("Received Finished sucessfully verified")
        return self


class ChangeCipherSpecMessage(TlsMessage):

    content_type = tls.ContentType.CHANGE_CIPHER_SPEC
    msg_type = None

    @classmethod
    def deserialize(cls, fragment, conn):
        if len(fragment) != 1:
            FatalAlert(
                "Received ChangedCipherSpec has unexpected length",
                tls.AlertDescription.DECODE_ERROR,
            )
        msg_type, offset = fragment.unpack_uint8(0)
        msg_type = tls.CCSType.val2enum(msg_type, alert_on_failure=True)
        logging.info("Receiving {}".format(msg_type.name))
        cls_name = _ccs_deserialization_map[msg_type]
        msg = cls_name()
        msg._deserialize_msg_body(conn)
        return msg

    def serialize(self, conn):
        self._serialize_msg_body(conn)
        ccs_msg = ProtocolData()
        ccs_msg.append_uint8(self.msg_type.value)
        logging.info("Sending {}".format(self.msg_type.name))
        return ccs_msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass


class ChangeCipherSpec(ChangeCipherSpecMessage):

    msg_type = tls.CCSType.CHANGE_CIPHER_SPEC

    def _deserialize_msg_body(self, conn):
        conn.update_read_state()

    def _serialize_msg_body(self, conn):
        conn.update_write_state()


class Alert(TlsMessage):

    content_type = tls.ContentType.ALERT

    def __init__(self, **kwargs):
        self.level = kwargs.get("level", tls.AlertLevel.FATAL)
        self.description = kwargs.get(
            "description", tls.AlertDescription.HANDSHAKE_FAILURE
        )

    def serialize(self, conn):
        alert = ProtocolData()
        if self.level == int:
            alert.append_uint8(self.level)
        else:
            alert.append_uint8(self.level.value)
        if self.description == int:
            alert.append_uint8(self.description)
        else:
            alert.append_uint8(self.description.value)

        logging.info("Sending ALERT ({})".format(self.description.name))
        return alert


class AppDataMessage(TlsMessage):

    content_type = tls.ContentType.APPLICATION_DATA

    @classmethod
    def deserialize(cls, fragment, conn):
        logging.info("Receiving {}".format(cls.content_type.name))
        msg = AppData()
        msg._deserialize_msg_body(fragment, conn)
        return msg

    def serialize(self, conn):
        logging.info("Sending {}".format(self.content_type.name))
        return self._serialize_msg_body(conn)

    @abc.abstractmethod
    def _deserialize_msg_body(self, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass

    def init_from_profile(self, profile):
        return self


class AppData(AppDataMessage):
    def __init__(self, *content):
        self.data = ProtocolData()
        for data in content:
            self.data.extend(data)

    def _deserialize_msg_body(self, fragment, conn):
        self.data = fragment

    def _serialize_msg_body(self, conn):
        return self.data


_hs_deserialization_map = {
    # tls.HandshakeType.HELLO_REQUEST = 0
    tls.HandshakeType.CLIENT_HELLO: ClientHello,
    tls.HandshakeType.SERVER_HELLO: ServerHello,
    # tls.HandshakeType.NEW_SESSION_TICKET = 4
    # tls.HandshakeType.END_OF_EARLY_DATA = 5
    # tls.HandshakeType.ENCRYPTED_EXTENSIONS = 8
    tls.HandshakeType.CERTIFICATE: Certificate,
    tls.HandshakeType.SERVER_KEY_EXCHANGE: ServerKeyExchange,
    # tls.HandshakeType.CERTIFICATE_REQUEST = 13
    tls.HandshakeType.SERVER_HELLO_DONE: ServerHelloDone,
    # tls.HandshakeType.CERTIFICATE_VERIFY = 15
    # tls.HandshakeType.CLIENT_KEY_EXCHANGE = 16
    tls.HandshakeType.FINISHED: Finished,
    # tls.HandshakeType.KEY_UPDATE = 24
    # tls.HandshakeType.COMPRESSED_CERTIFICATE = 25
    # tls.HandshakeType.EKT_KEY = 26
    # tls.HandshakeType.MESSAGE_HASH = 254
}

_ccs_deserialization_map = {tls.CCSType.CHANGE_CIPHER_SPEC: ChangeCipherSpec}
