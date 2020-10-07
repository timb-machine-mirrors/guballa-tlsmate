# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import tlsclient.constants as tls
from tlsclient.protocol import ProtocolData
import tlsclient.extensions as ext
from tlsclient.alert import FatalAlert


class TlsMessage(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def deserialize(cls, fragment, conn):
        pass

    @abc.abstractmethod
    def serialize(self, conn):
        pass


class Any(object):
    pass


class HandshakeMessage(TlsMessage):

    content_type = tls.ContentType.HANDSHAKE
    msg_type = None

    @classmethod
    def deserialize(cls, fragment, conn):
        msg_type, offset = fragment.unpack_uint8(0)
        msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
        length, offset = fragment.unpack_uint24(offset)
        if length + offset != len(fragment):
            raise FatalAlert(
                "Length of {} incorrect".format(msg_type),
                tls.AlertDescription.DECODE_ERROR,
            )
        cls_name = _hs_deserialization_map[msg_type]
        msg = cls_name()._deserialize_msg_body(fragment, offset, conn)
        return msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, msg_body, length, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass

    def serialize(self, conn):
        msg_body = self._serialize_msg_body(conn)

        handshake_msg = ProtocolData()
        handshake_msg.append_uint8(self.msg_type.value)
        handshake_msg.append_uint24(len(msg_body))
        handshake_msg.extend(msg_body)
        return handshake_msg


class ClientHello(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_HELLO

    def __init__(self):
        self.client_version = tls.Version.TLS12
        self.random = None
        self.session_id = ProtocolData()
        self.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []

    def _serialize_msg_body(self, conn):
        msg = ProtocolData()

        # version
        version = self.client_version
        if type(version) == tls.Version:
            version = version.value
        msg.append_uint16(version)

        # random
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
        if self.extensions is not None:
            ext_bytes = ProtocolData()
            for extension in self.extensions:
                ext_bytes.extend(extension.serialize())
            msg.append_uint16(len(ext_bytes))
            msg.extend(ext_bytes)

        return msg

    def _deserialize_msg_body(self, msg_body, length, conn):
        return self


class ServerHello(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO

    def __init__(self):
        self.version = None
        self.random = None
        self.session_id = None
        self.cipher_suite = None
        self.compression_method = None
        self.extensions = []

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
        return self


class Certificate(HandshakeMessage):

    msg_type = tls.HandshakeType.CERTIFICATE

    def __init__(self):
        self.certificates = []

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
        # TODO: add other curve types
        return offset

    def deserialize_ServerECDHParams(self, fragment, offset, conn):
        # ECParameters    curve_params;
        offset = self.deserialize_ECParameters(fragment, offset, conn)
        # ECPoint         public;
        point_len, offset = fragment.unpack_uint8(offset)
        self.public, offset = fragment.unpack_bytes(offset, point_len)

        return offset

    def _deserialize_msg_body(self, fragment, offset, conn):
        # ServerECDHParams    params;
        offset = self.deserialize_ServerECDHParams(fragment, offset, conn)
        # Signature           signed_params;
        signature_scheme, offset = fragment.unpack_uint16(offset)
        self.signature_scheme = tls.SignatureScheme.val2enum(signature_scheme)
        signature_len, offset = fragment.unpack_uint8(offset)
        self.signature, offset = fragment.unpack_bytes(offset, signature_len)
        return self


class KeyExchangeDH(object):
    def _deserialize_msg_body(self, fragment, offset, conn, signature_present=True):
        p_length, offset = fragment.unpack_uint16(offset)
        self.p_val, offset = fragment.unpack_bytes(offset, p_length)
        g_len, offset = fragment.unpack_uint16(offset)
        g_bytes, offset = fragment.unpack_bytes(offset, g_len)
        self.g_val = int.from_bytes(g_bytes, "big")
        pub_key_len, offset = fragment.unpack_uint16(offset)
        self.public_key, offset = fragment.unpack_bytes(offset, pub_key_len)
        if signature_present:
            sig_scheme, offset = fragment.unpack_uint16(offset)
            self.sig_scheme = tls.SignatureScheme.val2enum(sig_scheme)
            sig_length, offset = fragment.unpack_uint16(offset)
            self.signature, offset = fragment.unpack_bytes(offset, sig_length)
        return self


class ServerKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_KEY_EXCHANGE

    def __init__(self):
        self.ec = None
        self.dh = None

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.ec = None
        self.dh = None
        if conn.key_ex_type is tls.KeyExchangeType.ECDH:
            # RFC 4492
            self.ec = KeyExchangeEC()._deserialize_msg_body(fragment, offset, conn)
        elif conn.key_ex_type is tls.KeyExchangeType.DH:
            # RFC5246
            self.dh = KeyExchangeDH()._deserialize_msg_body(
                fragment,
                offset,
                conn,
                signature_present=(conn.key_auth is not tls.KeyAuthentication.NONE),
            )
        else:
            raise FatalAlert(
                (
                    f"Key exchange algorithm {conn.key_ex_type} is incompatible "
                    f"with ServerKeyExchange message"
                ),
                tls.AlertDescription.UNEXPECTED_MESSAGE,
            )
        return self


class ServerHelloDone(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO_DONE

    def __init__(self):
        pass

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise FatalAlert(
                f"Message length error for {self.msg_type.name}",
                tls.AlertDescription.DECODE_ERROR,
            )
        return self


class ClientKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_KEY_EXCHANGE

    def __init__(self):
        self.rsa_encrypted_pms = None
        self.dh_public = None
        self.ecdh_public = None

    def _serialize_msg_body(self, conn):
        msg = ProtocolData()
        if self.rsa_encrypted_pms is not None:
            msg.append_uint16(len(self.rsa_encrypted_pms))
            msg.extend(self.rsa_encrypted_pms)
        elif self.dh_public is not None:
            msg.append_uint16(len(self.dh_public))
            msg.extend(self.dh_public)
        elif self.ecdh_public is not None:
            msg.append_uint8(len(self.ecdh_public))
            msg.extend(self.ecdh_public)

        return msg

    def _deserialize_msg_body(self, fragment, offset, conn):
        pass


class Finished(HandshakeMessage):

    msg_type = tls.HandshakeType.FINISHED

    def __init__(self):
        self.verify_data = None

    def _serialize_msg_body(self, conn):
        return ProtocolData(self.verify_data)

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.verify_data = fragment[offset:]
        return self


class NewSessionTicket(HandshakeMessage):

    msg_type = tls.HandshakeType.NEW_SESSION_TICKET

    def __init__(self):
        # TODO for server side implementation
        pass

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return ProtocolData()

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.lifetime_hint, offset = fragment.unpack_uint32(offset)
        length, offset = fragment.unpack_uint16(offset)
        self.ticket, offset = fragment.unpack_bytes(offset, length)
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
        cls_name = _ccs_deserialization_map[msg_type]
        msg = cls_name()
        msg._deserialize_msg_body(conn)
        return msg

    def serialize(self, conn):
        self._serialize_msg_body(conn)
        ccs_msg = ProtocolData()
        ccs_msg.append_uint8(self.msg_type.value)
        return ccs_msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass


class ChangeCipherSpec(ChangeCipherSpecMessage):

    msg_type = tls.CCSType.CHANGE_CIPHER_SPEC

    def __init__(self):
        pass

    def _deserialize_msg_body(self, conn):
        pass

    def _serialize_msg_body(self, conn):
        pass


class Alert(TlsMessage):

    content_type = tls.ContentType.ALERT
    msg_type = tls.ContentType.ALERT

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

        return alert

    @classmethod
    def deserialize(cls, fragment, conn):
        msg = cls()
        alert_level, offset = fragment.unpack_uint8(0)
        msg.level = tls.AlertLevel.val2enum(alert_level)
        descr, offset = fragment.unpack_uint8(offset)
        msg.description = tls.AlertDescription(descr)
        return msg


class AppDataMessage(TlsMessage):

    content_type = tls.ContentType.APPLICATION_DATA

    msg_type = tls.ContentType.APPLICATION_DATA

    @classmethod
    def deserialize(cls, fragment, conn):
        msg = AppData()
        msg._deserialize_msg_body(fragment, conn)
        return msg

    def serialize(self, conn):
        return self._serialize_msg_body(conn)

    @abc.abstractmethod
    def _deserialize_msg_body(self, conn):
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        pass


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
    tls.HandshakeType.NEW_SESSION_TICKET: NewSessionTicket,
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
