# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import os
import tlsclient.constants as tls
import tlsclient.extensions as ext
from tlsclient.exception import FatalAlert
from tlsclient import pdu

def _get_extension(extensions, ext_id):
    """Helper function to search for an extension

    Arguments:
        extensions (list of :obj:`tlsclient.constants.Extensions`): the list
            to search for the extension
        ext_id (:obj:`tlsclient.constants.Extensions): the extension to to look for

    Returns:
        :obj:`tlsclient.constants.Extensions`: The extension if present, or None
            otherwise.
    """
    for extension in extensions:
        if extension.extension_id == ext_id:
            return extension
    return None


class TlsMessage(metaclass=abc.ABCMeta):
    """Abstract base class for TLS messages
    """
    @abc.abstractmethod
    def deserialize(cls, fragment, conn):
        """Method to deserialize the message received from the network

        Arguments:
            fragment (bytearray): The byte array representation of the message in
                network order (big endian).
            conn (:obj:`tlsclient.connection.TlsConnectio`): The connection object,
                needed for some odd cases, e.g. when deserializing a ServerKeyExchange
                message, as the layout purely depends on the key exchange method.

        Returns:
            :obj:`TlsMessage`:
                The deserialized message represented in a python object.
        """
        pass

    @abc.abstractmethod
    def serialize(self, conn):
        """A method to serialize this object.

        Arguments:
            conn (:obj:`tlsclient.connection.TlsConnectio`): The connection object,
                needed for some odd cases, e.g. when serializing a ServerKeyExchange
                message, as the layout purely depends on the key exchange method.

        Returns:
            bytearray: The bytes of the message in network order (big endian).
        """
        pass


class Any(object):
    """Class to represent any message to wait for in a test case.
    """
    pass


class HandshakeMessage(TlsMessage):
    """A base class for all handshake messages.
    """

    content_type = tls.ContentType.HANDSHAKE
    """ :obj:`tlsclient.constants.ContentType.HANDSHAKE`
    """

    msg_type = None
    """ :obj:`tlsclient.constants.HandshakeType`: The type of the handshake message.
    """

    @classmethod
    def deserialize(cls, fragment, conn):
        msg_type, offset = pdu.unpack_uint8(fragment, 0)
        msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
        length, offset = pdu.unpack_uint24(fragment, offset)
        if length + offset != len(fragment):
            raise FatalAlert(
                "Length of {} incorrect".format(msg_type),
                tls.AlertDescription.DECODE_ERROR,
            )
        cls_name = _hs_deserialization_map[msg_type]
        msg = cls_name()._deserialize_msg_body(fragment, offset, conn)
        return msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, msg_body, offset, conn):
        """Method to deserialize a handshake message.

        Arguments:
            msg_body (bytearray): The bytes which contain the serialized handhshake
                message.
            offset (int): The offset within the bytes where the handshake message
                starts.
            conn (:obj:`tlsclient.connection.TlsConnection`): the connection object,
                used to retrieve additional information required to deserialize
                the handshake message.

        Returns:
            :obj:`HandshakeMessage`: the deserialized message object, i.e. self.
        """
        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        """Serializes the message body.

        I.e., the message body only is serialized, without the common handshake header.
        """
        pass

    def serialize(self, conn):
        msg_body = self._serialize_msg_body(conn)

        handshake_msg = bytearray()
        handshake_msg.extend(pdu.pack_uint8(self.msg_type.value))
        handshake_msg.extend(pdu.pack_uint24(len(msg_body)))
        handshake_msg.extend(msg_body)
        return handshake_msg


class ClientHello(HandshakeMessage):
    """This class respresents a ClientHello message.

    Attributes:
        client_version (:obj:`tlsclient.constants.Version`):
            The version the client offers to the server.
        random (bytes): The random value.
        session_id (bytes): The session id.
        cipher_suites (list of :obj:`tlsclient.constants.CipherSuite`): The list
            of cipher suites offered to the server
        compression_methods (list of :obj:`tlsclient.constants.CompressionMethod`):
            The list of compression methods offered to the server.
        extensions (list of :obj:`tlsclient.constants.Extensions`): The list of
            extensions offered to the server. It can be a class (in this case the
            content of the extension is filled according to the client profile), or
            an instance, which leaves the user the full control of the contents.
    """

    msg_type = tls.HandshakeType.CLIENT_HELLO
    """:obj:`tlsclient.constants.HandshakeType.CLIENT_HELLO`
    """

    def __init__(self):
        self.client_version = tls.Version.TLS12
        self.random = None
        self.session_id = bytes()
        self.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []

    def _serialize_msg_body(self, conn):
        msg = bytearray()

        # version
        version = self.client_version
        if type(version) == tls.Version:
            version = version.value
        msg.extend(pdu.pack_uint16(version))

        # random
        msg.extend(self.random)

        # session_id
        msg.extend(pdu.pack_uint8(len(self.session_id)))
        msg.extend(self.session_id)

        # cipher suites
        msg.extend(pdu.pack_uint16(2 * len(self.cipher_suites)))
        for cipher_suite in self.cipher_suites:
            if type(cipher_suite) == int:
                msg.extend(pdu.pack_uint16(cipher_suite))
            else:
                msg.extend(pdu.pack_uint16(cipher_suite.value))

        # compression methods
        msg.extend(pdu.pack_uint8(len(self.compression_methods)))
        for comp_meth in self.compression_methods:
            if type(comp_meth) == tls.CompressionMethod:
                comp_meth = comp_meth.value
            msg.extend(pdu.pack_uint8(comp_meth))

        # extensions
        if self.extensions is not None:
            ext_bytes = bytearray()
            for extension in self.extensions:
                ext_bytes.extend(extension.serialize(conn))
            msg.extend(pdu.pack_uint16(len(ext_bytes)))
            msg.extend(ext_bytes)

        return msg

    def _deserialize_msg_body(self, msg_body, length, conn):
        return self

    def get_extension(self, ext_id):
        """Method to extract a specific extension.

        Arguments:
            ext_id (:obj:`tlsclient.constants.Extensions`): The extension id to
                look for.

        Returns:
            :obj:`tlsclient.extensions.Extension`:
                The extension object or None if not present.
        """
        return _get_extension(self.extensions, ext_id)

class ServerHello(HandshakeMessage):
    """This class respresents a ServerHello message.

    Attributes:
        version (:obj:`tlsclient.constants.Version`): The version selected by
            the server.
        random (bytes): The random value from the server.
        session_id (bytes): The session id from the server.
        compression_method (:obj:`tlsclient.constants.CompressionMethod`): The
            selected compression method by the server.
        extensions (list of :obj:`tlsclient.constants.Extensions`): The list of
            extensions as returned from the server.
    """

    msg_type = tls.HandshakeType.SERVER_HELLO
    """:obj:`tlsclient.constants.HandshakeType.SERVER_HELLO`
    """

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

        version, offset = pdu.unpack_uint16(fragment, offset)
        self.version = tls.Version.val2enum(version, alert_on_failure=True)
        self.random, offset = pdu.unpack_bytes(fragment, offset, 32)
        session_id_len, offset = pdu.unpack_uint8(fragment, offset)
        self.session_id, offset = pdu.unpack_bytes(fragment, offset, session_id_len)
        cipher_suite, offset = pdu.unpack_uint16(fragment, offset)
        self.cipher_suite = tls.CipherSuite.val2enum(
            cipher_suite, alert_on_failure=True
        )
        compression_method, offset = pdu.unpack_uint8(fragment, offset)
        self.compression_method = tls.CompressionMethod.val2enum(
            compression_method, alert_on_failure=True
        )
        self.extensions = []
        if offset < len(fragment):
            # extensions present
            ext_len, offset = pdu.unpack_uint16(fragment, offset)
            while offset < len(fragment):
                extension, offset = ext.Extension.deserialize(fragment, offset)
                self.extensions.append(extension)
        return self


    def get_extension(self, ext_id):
        ClientHello.get_extension.__doc__
        return _get_extension(self.extensions, ext_id)

ServerHello.get_extension.__doc__ = ClientHello.get_extension.__doc__

class Certificate(HandshakeMessage):
    """This class respresents a Certificate message.
    """

    msg_type = tls.HandshakeType.CERTIFICATE

    def __init__(self):
        self.request_context = None
        self.certificates = []

    def _serialize_msg_body(self, conn):
        # TODO
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.certificates = []
        if conn.version is tls.Version.TLS13:
            length, offset = pdu.unpack_uint8(fragment, offset)
            if length:
                self.request_context, offset = pdu.unpack_bytes(
                    fragment, offset, length
                )
        list_len, offset = pdu.unpack_uint24(fragment, offset)
        while offset < len(fragment):
            cert_len, offset = pdu.unpack_uint24(fragment, offset)
            cert, offset = pdu.unpack_bytes(fragment, offset, cert_len)
            self.certificates.append(cert)
            # TODO: save the extensions
            if conn.version is tls.Version.TLS13:
                ext_len, offset = pdu.unpack_uint16(fragment, offset)
                if ext_len:
                    extensions, offset = pdu.unpack_bytes(fragment, ext_len)
        return self


class CertificateVerify(HandshakeMessage):
    """This class respresents a CertificateVerify message.
    """

    msg_type = tls.HandshakeType.CERTIFICATE_VERIFY

    def __init__(self):
        self.signature_scheme = None
        self.signature = None

    def _serialize_msg_body(self, conn):
        # TODO
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        scheme, offset = pdu.unpack_uint16(fragment, offset)
        self.signature_scheme = tls.SignatureScheme(scheme)
        length, offset = pdu.unpack_uint16(fragment, offset)
        self.signature, offset = pdu.unpack_bytes(fragment, offset, length)
        return self


class KeyExchangeEC(object):
    def deserialize_ECParameters(self, fragment, offset, conn):
        curve_type, offset = pdu.unpack_uint8(fragment, offset)
        self.curve_type = tls.EcCurveType.val2enum(curve_type)
        if self.curve_type is tls.EcCurveType.NAMED_CURVE:
            named_curve, offset = pdu.unpack_uint16(fragment, offset)
            self.named_curve = tls.SupportedGroups.val2enum(named_curve)
        # TODO: add other curve types
        return offset

    def deserialize_ServerECDHParams(self, fragment, offset, conn):
        # ECParameters    curve_params;
        offset = self.deserialize_ECParameters(fragment, offset, conn)
        # ECPoint         public;
        point_len, offset = pdu.unpack_uint8(fragment, offset)
        self.public, offset = pdu.unpack_bytes(fragment, offset, point_len)

        return offset

    def _deserialize_msg_body(self, fragment, offset, conn):
        # ServerECDHParams    params;
        offset = self.deserialize_ServerECDHParams(fragment, offset, conn)
        # Signature           signed_params;
        signature_scheme, offset = pdu.unpack_uint16(fragment, offset)
        self.signature_scheme = tls.SignatureScheme.val2enum(signature_scheme)
        signature_len, offset = pdu.unpack_uint8(fragment, offset)
        self.signature, offset = pdu.unpack_bytes(fragment, offset, signature_len)
        return self


class KeyExchangeDH(object):
    def _deserialize_msg_body(self, fragment, offset, conn, signature_present=True):
        p_length, offset = pdu.unpack_uint16(fragment, offset)
        self.p_val, offset = pdu.unpack_bytes(fragment, offset, p_length)
        g_len, offset = pdu.unpack_uint16(fragment, offset)
        g_bytes, offset = pdu.unpack_bytes(fragment, offset, g_len)
        self.g_val = int.from_bytes(g_bytes, "big")
        pub_key_len, offset = pdu.unpack_uint16(fragment, offset)
        self.public_key, offset = pdu.unpack_bytes(fragment, offset, pub_key_len)
        if signature_present:
            if conn.version is not tls.Version.SSL30:
                sig_scheme, offset = pdu.unpack_uint16(fragment, offset)
                self.sig_scheme = tls.SignatureScheme.val2enum(sig_scheme)
            sig_length, offset = pdu.unpack_uint16(fragment, offset)
            self.signature, offset = pdu.unpack_bytes(fragment, offset, sig_length)
        return self


class ServerKeyExchange(HandshakeMessage):
    """This class respresents a ServerKeyExchange message.
    """

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
        msg = bytearray()
        if self.rsa_encrypted_pms is not None:
            msg.extend(pdu.pack_uint16(len(self.rsa_encrypted_pms)))
            msg.extend(self.rsa_encrypted_pms)
        elif self.dh_public is not None:
            msg.extend(pdu.pack_uint16(len(self.dh_public)))
            msg.extend(self.dh_public)
        elif self.ecdh_public is not None:
            msg.extend(pdu.pack_uint8(len(self.ecdh_public)))
            msg.extend(self.ecdh_public)

        return msg

    def _deserialize_msg_body(self, fragment, offset, conn):
        pass


class Finished(HandshakeMessage):

    msg_type = tls.HandshakeType.FINISHED

    def __init__(self):
        self.verify_data = None

    def _serialize_msg_body(self, conn):
        return bytes(self.verify_data)

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.verify_data = fragment[offset:]
        return self


class NewSessionTicket(HandshakeMessage):

    msg_type = tls.HandshakeType.NEW_SESSION_TICKET

    def __init__(self):
        self.lifetime = None
        self.age_add = None
        self.nonce = None
        self.ticket = None
        self.extensions = []

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return bytearray()

    def _deserialize_msg_body(self, fragment, offset, conn):
        if conn.version is tls.Version.TLS13:
            self.lifetime, offset = pdu.unpack_uint32(fragment, offset)
            self.age_add, offset = pdu.unpack_uint32(fragment, offset)
            length, offset = pdu.unpack_uint8(fragment, offset)
            self.nonce, offset = pdu.unpack_bytes(fragment, offset, length)
            length, offset = pdu.unpack_uint16(fragment, offset)
            self.ticket, offset = pdu.unpack_bytes(fragment, offset, length)

            # TODO: move deserialization to dedicated method
            if offset < len(fragment):
                # extensions present
                ext_len, offset = pdu.unpack_uint16(fragment, offset)
                while offset < len(fragment):
                    extension, offset = ext.Extension.deserialize(fragment, offset)
                    self.extensions.append(extension)
            return self
        else:
            self.lifetime, offset = pdu.unpack_uint32(fragment, offset)
            length, offset = pdu.unpack_uint16(fragment, offset)
            self.ticket, offset = pdu.unpack_bytes(fragment, offset, length)
        return self

    def get_extension(self, ext_id):
        return _get_extension(self.extensions, ext_id)


class EncryptedExtensions(HandshakeMessage):

    msg_type = tls.HandshakeType.ENCRYPTED_EXTENSIONS

    def __init__(self):
        self.extensions = []

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return bytearray()

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset < len(fragment):
            # extensions present
            ext_len, offset = pdu.unpack_uint16(fragment, offset)
            while offset < len(fragment):
                extension, offset = ext.Extension.deserialize(fragment, offset)
                self.extensions.append(extension)
        return self

    def get_extension(self, ext_id):
        return _get_extension(self.extensions, ext_id)

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
        msg_type, offset = pdu.unpack_uint8(fragment, 0)
        msg_type = tls.CCSType.val2enum(msg_type, alert_on_failure=True)
        cls_name = _ccs_deserialization_map[msg_type]
        msg = cls_name()
        msg._deserialize_msg_body(conn)
        return msg

    def serialize(self, conn):
        self._serialize_msg_body(conn)
        ccs_msg = bytearray()
        ccs_msg.extend(pdu.pack_uint8(self.msg_type.value))
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
        alert = bytearray()
        if self.level == int:
            alert.extend(pdu.pack_uint8(self.level))
        else:
            alert.extend(pdu.pack_uint8(self.level.value))
        if self.description == int:
            alert.extend(pdu.pack_uint8(self.description))
        else:
            alert.extend(pdu.pack_uint8(self.description.value))

        return alert

    @classmethod
    def deserialize(cls, fragment, conn):
        msg = cls()
        alert_level, offset = pdu.unpack_uint8(fragment, 0)
        msg.level = tls.AlertLevel.val2enum(alert_level)
        descr, offset = pdu.unpack_uint8(fragment, offset)
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
        self.data = bytearray()
        for data in content:
            self.data.extend(data)

    def _deserialize_msg_body(self, fragment, conn):
        self.data = fragment

    def _serialize_msg_body(self, conn):
        return self.data


class SSL2Message(TlsMessage):

    content_type = tls.ContentType.SSL2
    msg_type = None

    @classmethod
    def deserialize(cls, fragment, conn, length=0):
        msg_type, offset = pdu.unpack_uint8(fragment, 0)
        msg_type = tls.SSLMessagType.val2enum(msg_type, alert_on_failure=True)

        cls_name = _ssl2_deserialization_map[msg_type]
        msg = cls_name()._deserialize_msg_body(fragment, offset, conn)
        return msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, msg_body, length, conn):
        pass

    @abc.abstractmethod
    def serialize(self, conn):
        pass


class SSL2ClientHello(SSL2Message):

    msg_type = tls.SSLMessagType.SSL2_CLIENT_HELLO

    def __init__(self):
        self.client_version = tls.SSLVersion.SSL2
        self.cipher_specs = [
            tls.SSLCipherKind.SSL_CK_RC4_128_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_RC4_128_EXPORT40_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_RC2_128_CBC_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_IDEA_128_CBC_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_DES_64_CBC_WITH_MD5,
            tls.SSLCipherKind.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
        ]
        self.session_id = bytes()
        self.challenge = os.urandom(16)

    def serialize(self, conn):
        msg = bytearray()
        msg.extend(pdu.pack_uint8(self.msg_type.value))
        msg.extend(pdu.pack_uint16(self.client_version.value))
        msg.extend(pdu.pack_uint16(3 * len(self.cipher_specs)))
        msg.extend(pdu.pack_uint16(len(self.session_id)))
        msg.extend(pdu.pack_uint16(len(self.challenge)))
        for ck in self.cipher_specs:
            msg.extend(pdu.pack_uint24(ck.value))
        msg.extend(self.session_id)
        msg.extend(self.challenge)
        return msg

    def _deserialize_msg_body(self, fragment, length, conn):
        return self


class SSL2ServerHello(SSL2Message):

    msg_type = tls.SSLMessagType.SSL2_CLIENT_HELLO

    def __init__(self):
        self.session_id_hit = None
        self.cert_type = None
        self.version = None
        self.cipher_specs = []
        self.connection_id = None
        self.certificate = None

    def serialize(self, conn):
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.session_id_hit, offset = pdu.unpack_uint8(fragment, offset)
        self.cert_type, offset = pdu.unpack_uint8(fragment, offset)
        version, offset = pdu.unpack_uint16(fragment, offset)
        self.version = tls.SSLVersion.val2enum(version)
        cert_len, offset = pdu.unpack_uint16(fragment, offset)
        cipher_len, offset = pdu.unpack_uint16(fragment, offset)
        conn_id_len, offset = pdu.unpack_uint16(fragment, offset)
        self.certificate, offset = pdu.unpack_bytes(fragment, offset, cert_len)
        for _ in range(int(cipher_len / 3)):
            cipher, offset = pdu.unpack_uint24(fragment, offset)
            self.cipher_specs.append(tls.SSLCipherKind.val2enum(cipher))
        self.connection_id, offset = pdu.unpack_bytes(fragment, offset, conn_id_len)
        return self


_hs_deserialization_map = {
    # tls.HandshakeType.HELLO_REQUEST = 0
    tls.HandshakeType.CLIENT_HELLO: ClientHello,
    tls.HandshakeType.SERVER_HELLO: ServerHello,
    tls.HandshakeType.NEW_SESSION_TICKET: NewSessionTicket,
    # tls.HandshakeType.END_OF_EARLY_DATA = 5
    tls.HandshakeType.ENCRYPTED_EXTENSIONS: EncryptedExtensions,
    tls.HandshakeType.CERTIFICATE: Certificate,
    tls.HandshakeType.SERVER_KEY_EXCHANGE: ServerKeyExchange,
    # tls.HandshakeType.CERTIFICATE_REQUEST = 13
    tls.HandshakeType.SERVER_HELLO_DONE: ServerHelloDone,
    tls.HandshakeType.CERTIFICATE_VERIFY: CertificateVerify,
    # tls.HandshakeType.CLIENT_KEY_EXCHANGE = 16
    tls.HandshakeType.FINISHED: Finished,
    # tls.HandshakeType.KEY_UPDATE = 24
    # tls.HandshakeType.COMPRESSED_CERTIFICATE = 25
    # tls.HandshakeType.EKT_KEY = 26
    # tls.HandshakeType.MESSAGE_HASH = 254
}

_ccs_deserialization_map = {tls.CCSType.CHANGE_CIPHER_SPEC: ChangeCipherSpec}

_ssl2_deserialization_map = {tls.SSLMessagType.SSL2_SERVER_HELLO: SSL2ServerHello}
