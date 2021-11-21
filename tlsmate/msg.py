# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
# import basic stuff
import abc
import os

# import own stuff
from tlsmate import tls
from tlsmate import ext
from tlsmate.exception import ServerMalfunction
from tlsmate.cert_chain import CertChain
from tlsmate import pdu

# import other stuff


def get_extension(extensions, ext_id):
    """Helper function to search for an extension

    Arguments:
        extensions (list of :obj:`tlsmate.tls.Extensions`): the list
            to search for the extension
        ext_id (:obj:`tlsmate.tls.Extensions`): the extension to to look for

    Returns:
        :obj:`tlsmate.tls.Extensions`: The extension if present, or None
            otherwise.
    """

    if extensions is not None:
        for extension in extensions:
            if extension.extension_id == ext_id:
                return extension

    return None


def _deserialize_extensions(extensions, fragment, offset):
    """Helper function to deserialize extensions

    Arguments:
        extensions (list): the list where to store the deserialized extensions
        fragment (bytes): the pdu buffer
        offset (int): the offset within the pdu buffer to the start of the extensions

    Returns:
        int: the offset on the byte following the extensions
    """

    if offset < len(fragment):
        # extensions present
        ext_len, offset = pdu.unpack_uint16(fragment, offset)
        ext_end = offset + ext_len
        while offset < ext_end:
            extension, offset = ext.Extension.deserialize(fragment, offset)
            extensions.append(extension)

    return offset


def _get_version(msg):
    """Get the highest version from a hello message.

    Arguments:
        msg (:obj:`HandshakeMessage`): the message

    Returns:
        :class:`tls.Version`: The highest version
    """

    supported_versions = msg.get_extension(tls.Extension.SUPPORTED_VERSIONS)
    if supported_versions is not None:
        return supported_versions.versions[0]

    return msg.version


class TlsMessage(metaclass=abc.ABCMeta):
    """Abstract base class for TLS messages
    """

    @abc.abstractmethod
    def deserialize(cls, fragment, conn):
        """Method to deserialize the message received from the network

        Arguments:
            fragment (bytearray): The byte array representation of the message in
                network order (big endian).
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object,
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
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object,
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


class Timeout(object):
    """Class to allow waiting for a timeout.
    """

    msg_type = "Timeout"


class HandshakeMessage(TlsMessage):
    """A base class for all handshake messages.
    """

    content_type = tls.ContentType.HANDSHAKE
    """ :obj:`tlsmate.tls.ContentType.HANDSHAKE`
    """

    msg_type = None
    """ :obj:`tlsmate.tls.HandshakeType`: The type of the handshake message.
    """

    @classmethod
    def deserialize(cls, fragment, conn):
        msg_type, offset = pdu.unpack_uint8(fragment, 0)
        msg_type = tls.HandshakeType.val2enum(msg_type, alert_on_failure=True)
        length, offset = pdu.unpack_uint24(fragment, offset)
        if length + offset != len(fragment):
            raise ServerMalfunction(
                tls.ServerIssue.MESSAGE_LENGTH_ERROR, message=cls.msg_type
            )

        cls_name = _hs_deserialization_map[msg_type]
        msg = cls_name()._deserialize_msg_body(fragment, offset, conn)
        return msg

    @abc.abstractmethod
    def _deserialize_msg_body(self, msg_body, offset, conn):
        """Method to deserialize a handshake message.

        Arguments:
            msg_body (bytearray): The bytes which contain the serialized handshake
                message.
            offset (int): The offset within the bytes where the handshake message
                starts.
            conn (:obj:`tlsmate.connection.TlsConnection`): the connection object,
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

        return bytearray(
            pdu.pack_uint8(self.msg_type.value)
            + pdu.pack_uint24(len(msg_body))
            + msg_body
        )


class HelloRequest(HandshakeMessage):
    """This class represents a HelloRequest message.
    """

    msg_type = tls.HandshakeType.HELLO_REQUEST
    """:obj:`tlsmate.tls.HandshakeType.HELLO_REQUEST`
    """

    def __init__(self):
        pass

    def _serialize_msg_body(self, conn):
        return b""

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise ServerMalfunction(
                tls.ServerIssue.MESSAGE_LENGTH_ERROR, message=self.msg_type
            )

        return self


class ClientHello(HandshakeMessage):
    """This class represents a ClientHello message.

    Attributes:
        version (:obj:`tlsmate.tls.Version`):
            The version the client offers to the server.
        random (bytes): The random value.
        session_id (bytes): The session id.
        cipher_suites (list of :obj:`tlsmate.tls.CipherSuite`): The list
            of cipher suites offered to the server
        compression_methods (list of :obj:`tlsmate.tls.CompressionMethod`):
            The list of compression methods offered to the server.
        extensions (list of :obj:`tlsmate.ext.Extension`): The list of
            extensions offered to the server. It can be a class (in this case the
            content of the extension is filled according to the client profile), or
            an instance, which leaves the user the full control of the contents.
    """

    msg_type = tls.HandshakeType.CLIENT_HELLO
    """:obj:`tlsmate.tls.HandshakeType.CLIENT_HELLO`
    """

    def __init__(self):
        self.version = tls.Version.TLS12
        self.random = None
        self.session_id = bytes()
        self.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []
        self._bytes_after_psk_ext = 0

    def _serialize_msg_body(self, conn):
        msg = bytearray()

        # version
        msg.extend(pdu.pack_uint16(getattr(self.version, "value", self.version)))

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
            psk_end_offset = 0
            ext_bytes = bytearray()
            for extension in self.extensions:
                ext_bytes.extend(extension.serialize(conn))
                if extension.extension_id is tls.Extension.PRE_SHARED_KEY:
                    psk_end_offset = len(ext_bytes)

            msg.extend(pdu.pack_uint16(len(ext_bytes)))
            msg.extend(ext_bytes)
            self._bytes_after_psk_ext = len(ext_bytes) - psk_end_offset

        return msg

    def _deserialize_msg_body(self, msg_body, length, conn):
        return self

    def get_extension(self, ext_id):
        """Method to extract a specific extension.

        Arguments:
            ext_id (:obj:`tlsmate.tls.Extension`): The extension id to
                look for.

        Returns:
            :obj:`tlsmate.ext.Extension`:
                The extension object or None if not present.
        """

        return get_extension(self.extensions, ext_id)

    def get_version(self):
        """Get the highest TLS version from the message.

        Takes the version parameter into account as well as the extension
        SUPPORTED_VERSIONS (if present).

        Returns:
            :class:`tlsmate.tls.Version`: The highest TLS version offered.
        """

        return _get_version(self)


class ServerHello(HandshakeMessage):
    """This class represents a ServerHello message.

    Attributes:
        version (:obj:`tlsmate.tls.Version`): The version selected by
            the server.
        random (bytes): The random value from the server.
        session_id (bytes): The session id from the server.
        compression_method (:obj:`tlsmate.tls.CompressionMethod`): The
            selected compression method by the server.
        extensions (list of :obj:`tlsmate.ext.Extension`): The list of
            extensions as returned from the server.
    """

    msg_type = tls.HandshakeType.SERVER_HELLO
    """:obj:`tlsmate.tls.HandshakeType.SERVER_HELLO`
    """

    HELLO_RETRY_REQ_RAND = bytes.fromhex(
        "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 "
        "C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C "
    )

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
        if self.random == self.HELLO_RETRY_REQ_RAND:
            self.msg_type = tls.HandshakeType.HELLO_RETRY_REQUEST

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
        _deserialize_extensions(self.extensions, fragment, offset)
        return self

    def get_extension(self, ext_id):
        """Get an extension from the message

        Arguments:
            ext_id: (:class:`tlsmate.tls`): The extensions to look for

        Returns:
            :obj:`tlsmate.ext.Extension`: The extension or None if not present.
        """

        return get_extension(self.extensions, ext_id)

    def get_version(self):
        """Get the negotiated TLS version from the message.

        Takes the version parameter into account as well as the extension
        SUPPORTED_VERSIONS (if present).

        Returns:
            :class:`tlsmate.tls.Version`: The negotiated TLS version.
        """

        return _get_version(self)


ServerHello.get_extension.__doc__ = ClientHello.get_extension.__doc__


class Certificate(HandshakeMessage):
    """This class represents a Certificate message.

    The TLS1.3 format is not yet 100% implemented, but the basic certificate
    chain (as for TLS1.2 and below) is supported.

    Attributes:
        request_context (bytes): Set to None for TLS1.2 and below. For TLS1.3
            it is only applicable for Certificate messages send by the client. TLS1.3
            servers SHALL set this to a zero-length field (RFC8446, 4.4.2)
        certificates (list of bytes): The certificate chain, as received from the
            peer, i.e. the list will start with the host certificate.
    """

    msg_type = tls.HandshakeType.CERTIFICATE
    """:obj:`tlsmate.tls.HandshakeType.CERTIFICATE`
    """

    def __init__(self):
        self.request_context = None
        self.chain = CertChain()
        self.extensions = []

    def _serialize_msg_body(self, conn):
        msg = bytearray()
        if self.request_context is not None:
            msg.extend(pdu.pack_uint8(len(self.request_context)))
            msg.extend(self.request_context)

        cert_list = bytearray()
        if self.chain is not None:
            for certificate in self.chain.certificates:
                cert_list.extend(pdu.pack_uint24(len(certificate.bytes)))
                cert_list.extend(certificate.bytes)
                if conn.version is tls.Version.TLS13:
                    # no extensions supported right now, set length to 0.
                    cert_list.extend(pdu.pack_uint16(0))

        msg.extend(pdu.pack_uint24(len(cert_list)))
        msg.extend(cert_list)
        return msg

    def _deserialize_msg_body(self, fragment, offset, conn):

        if conn.version is tls.Version.TLS13:
            length, offset = pdu.unpack_uint8(fragment, offset)
            if length:
                self.request_context, offset = pdu.unpack_bytes(
                    fragment, offset, length
                )

        list_len, offset = pdu.unpack_uint24(fragment, offset)
        while offset < len(fragment):
            cert_len, offset = pdu.unpack_uint24(fragment, offset)
            certificate, offset = pdu.unpack_bytes(fragment, offset, cert_len)
            self.chain.append_bin_cert(certificate)
            if conn.version is tls.Version.TLS13:
                offset = _deserialize_extensions(
                    self.chain.certificates[-1].tls_extensions, fragment, offset
                )

        return self


class CertificateVerify(HandshakeMessage):
    """This class represents a CertificateVerify message.

    Attributes:
        signature_scheme (:obj:`tlsmate.tls.SignatureScheme`): The scheme
            used for the signature
        signature (bytes): The signature.
    """

    msg_type = tls.HandshakeType.CERTIFICATE_VERIFY
    """:obj:`tlsmate.tls.HandshakeType.CERTIFICATE_VERIFY`
    """

    def __init__(self):
        self.signature_scheme = None
        self.signature = None

    def _serialize_msg_body(self, conn):
        msg = bytearray()
        msg.extend(pdu.pack_uint16(self.signature_scheme.value))
        msg.extend(pdu.pack_uint16(len(self.signature)))
        msg.extend(self.signature)
        return msg

    def _deserialize_msg_body(self, fragment, offset, conn):
        scheme, offset = pdu.unpack_uint16(fragment, offset)
        self.signature_scheme = tls.SignatureScheme(scheme)
        length, offset = pdu.unpack_uint16(fragment, offset)
        self.signature, offset = pdu.unpack_bytes(fragment, offset, length)
        return self


class KeyExchangeEC(object):
    """Class representing parameters for a DH-based key exchange.

    Currently only named curves are supported.

    Attributes:
        curve_type (:obj:`tlsmate.tls.EcCurveType`): The type of the curve.
        named_curve (:obj:`tlsmate.tls.SupportedGroups`): The curve name, as
            defined by the supported groups.
        public (bytes): The public key from the peer.
        sig_scheme (:obj:`tlsmate.tls.SignatureScheme`): The scheme of the
            signature, if present.
        signature (bytes): The signature.
        signed_params (bytes): The part of the message which has been signed.
    """

    def __init__(self):
        self.curve_type = None
        self.named_curve = None
        self.public = None
        self.sig_scheme = None
        self.signature = None
        self.signed_params = None

    def _deserialize_ECParameters(self, fragment, offset, conn):
        """Deserializes the EC-parameters.

        Arguments:
            fragment (bytes): A PDU buffer as received from the network.
            offset (int): The offset within the fragment where the DH-params start.
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object.
        Returns:
            int: The new offset after unpacking the EC-parameters.
        """

        curve_type, offset = pdu.unpack_uint8(fragment, offset)
        self.curve_type = tls.EcCurveType.val2enum(curve_type)
        if self.curve_type is tls.EcCurveType.NAMED_CURVE:
            named_curve, offset = pdu.unpack_uint16(fragment, offset)
            self.named_curve = tls.SupportedGroups.val2enum(named_curve)

        # TODO: add other curve types
        return offset

    def _deserialize_ServerECDHParams(self, fragment, offset, conn):
        """Deserializes the ECDH-parameters.

        Arguments:
            fragment (bytes): A PDU buffer as received from the network.
            offset (int): The offset within the fragment where the DH-params start.
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object.
        Returns:
            int: The new offset after unpacking the EC-parameters.
        """

        # ECParameters    curve_params;
        offset = self._deserialize_ECParameters(fragment, offset, conn)
        # ECPoint         public;
        point_len, offset = pdu.unpack_uint8(fragment, offset)
        self.public, offset = pdu.unpack_bytes(fragment, offset, point_len)

        return offset

    def _deserialize_msg_body(self, fragment, offset, conn):
        """Deserializes the EC-parameters.

        Arguments:
            fragment (bytes): A PDU buffer as received from the network.
            offset (int): The offset within the fragment where the DH-params start.
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object.
        Returns:
            :obj:`KeyExchangeEC`: The object representing the EC parameters, i.e. self.
        """

        signed_params_start = offset
        # ServerECDHParams    params;
        offset = self._deserialize_ServerECDHParams(fragment, offset, conn)
        self.signed_params = fragment[signed_params_start:offset]
        # Signature           signed_params;
        if conn.cs_details.key_algo is not tls.KeyExchangeAlgorithm.ECDH_ANON:
            if conn.version is tls.Version.TLS12:
                sig_scheme, offset = pdu.unpack_uint16(fragment, offset)
                self.sig_scheme = tls.SignatureScheme.val2enum(sig_scheme)

            signature_len, offset = pdu.unpack_uint16(fragment, offset)
            self.signature, offset = pdu.unpack_bytes(fragment, offset, signature_len)

        return self


class KeyExchangeDH(object):
    """Class representing parameters for a DH-based key exchange.

    Attributes:
        p_val (bytes): The modulo p used for the DH-key exchange.
        g_val (int): The generator g used for the DH.key exchange.
        public_key (bytes): The public key of the peer.
        sig_scheme (:obj:`tlsmate.tls.SignatureScheme`): the signature
            scheme use in the signature. Only used for authenticated DH, set to None
            for anonymous key exchange.
        signature (bytes): The signature. Only used for authenticated DH, set to None
            for anonymous key exchange.
    """

    def __init__(self):
        self.p_val = None
        self.g_val = None
        self.public_key = None
        self.sig_scheme = None
        self.signature = None
        self.signed_params = None

    def _deserialize_msg_body(self, fragment, offset, conn, signature_present=True):
        signed_params_start = offset
        p_length, offset = pdu.unpack_uint16(fragment, offset)
        self.p_val, offset = pdu.unpack_bytes(fragment, offset, p_length)
        g_len, offset = pdu.unpack_uint16(fragment, offset)
        g_bytes, offset = pdu.unpack_bytes(fragment, offset, g_len)
        self.g_val = int.from_bytes(g_bytes, "big")
        pub_key_len, offset = pdu.unpack_uint16(fragment, offset)
        self.public_key, offset = pdu.unpack_bytes(fragment, offset, pub_key_len)
        if signature_present:
            self.signed_params = fragment[signed_params_start:offset]
            if conn.version is tls.Version.TLS12:
                sig_scheme, offset = pdu.unpack_uint16(fragment, offset)
                self.sig_scheme = tls.SignatureScheme.val2enum(sig_scheme)

            sig_length, offset = pdu.unpack_uint16(fragment, offset)
            self.signature, offset = pdu.unpack_bytes(fragment, offset, sig_length)

        return self


class ServerKeyExchange(HandshakeMessage):
    """This class represents a ServerKeyExchange message.

    The available attributes depend on the key exchange type. If they are not
    applicable, they are set to None.

    Attributes:
        ec (:obj:`KeyExchangeEC`): Object representing the parameters for an EC-based
            key exchange.
        dh (:obj:`KeyExchangeDH`): Object representing the parameters for an DH-based
            key exchange.
    """

    msg_type = tls.HandshakeType.SERVER_KEY_EXCHANGE
    """:obj:`tlsmate.tls.HandshakeType.SERVER_KEY_EXCHANGE`
    """

    def __init__(self):
        self.ec = None
        self.dh = None

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.ec = None
        self.dh = None
        if conn.cs_details.key_algo_struct.key_ex_type is tls.KeyExchangeType.ECDH:
            # RFC 4492
            self.ec = KeyExchangeEC()._deserialize_msg_body(fragment, offset, conn)

        elif conn.cs_details.key_algo_struct.key_ex_type is tls.KeyExchangeType.DH:
            # RFC5246
            self.dh = KeyExchangeDH()._deserialize_msg_body(
                fragment,
                offset,
                conn,
                signature_present=(
                    conn.cs_details.key_algo_struct.key_auth
                    is not tls.KeyAuthentication.NONE
                ),
            )

        else:
            raise ServerMalfunction(tls.ServerIssue.INCOMPATIBLE_KEY_EXCHANGE)

        return self


class ServerHelloDone(HandshakeMessage):
    """This class represents a ServerHelloDone message.
    """

    msg_type = tls.HandshakeType.SERVER_HELLO_DONE
    """:obj:`tlsmate.tls.HandshakeType.SERVER_HELLO_DONE`
    """

    def __init__(self):
        pass

    def _serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise ServerMalfunction(
                tls.ServerIssue.MESSAGE_LENGTH_ERROR, message=self.msg_type
            )

        return self


class ClientKeyExchange(HandshakeMessage):
    """This class represents a ClientKeyExchange message.

    The attributes depend on the key exchange type.

    Attributes:
        rsa_encrypted_pms (bytes): The premaster secret encrypted with RSA. Only
            applicable for RSA-based key transport.
        dh_public (bytes): The public DH key of the client. Only applicable for
            DH key exchanges.
        ecdh_public (bytes): The public ECDH key of the client. Only applicable for
            for ECDH key exchanges.
    """

    msg_type = tls.HandshakeType.CLIENT_KEY_EXCHANGE
    """:obj:`tlsmate.tls.HandshakeType.CLIENT_KEY_EXCHANGE`
    """

    def __init__(self):
        self.rsa_encrypted_pms = None
        self.dh_public = None
        self.ecdh_public = None

    def _serialize_msg_body(self, conn):
        msg = bytearray()
        if self.rsa_encrypted_pms is not None:
            if conn.version is not tls.Version.SSL30:
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
    """This class represents a Finished message.

    Attributes:
        verify_data (bytes): The verify data item.
    """

    msg_type = tls.HandshakeType.FINISHED
    """:obj:`tlsmate.tls.HandshakeType.FINISHED`
    """

    def __init__(self):
        self.verify_data = None

    def _serialize_msg_body(self, conn):
        return bytes(self.verify_data)

    def _deserialize_msg_body(self, fragment, offset, conn):
        self.verify_data = fragment[offset:]
        return self


class EndOfEarlyData(HandshakeMessage):
    """This class represents an EndOfEarlyData message.
    """

    msg_type = tls.HandshakeType.END_OF_EARLY_DATA
    """:obj:`tlsmate.tls.HandshakeType.END_OF_EARLY_DATA`
    """

    def __init__(self):
        pass

    def _serialize_msg_body(self, conn):
        return b""

    def _deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise ServerMalfunction(
                tls.ServerIssue.MESSAGE_LENGTH_ERROR, message=self.msg_type
            )

        return self


class NewSessionTicket(HandshakeMessage):
    """This class represents a NewSessionTicket message.

    Attributes:
        lifetime (int): The lifetime hint for the ticket in seconds.
        age_add (int): The age_add parameter (only TLS1.3)
        nonce (bytes): The nonce (only TLS1.3)
        ticket (bytes): The ticket.
        extensions (list of :obj:`tlsmate.tls.Extension`): The list of
            TLS extensions (only TLS1.3).
    """

    msg_type = tls.HandshakeType.NEW_SESSION_TICKET
    """:obj:`tlsmate.tls.HandshakeType.NEW_SESSION_TICKET`
    """

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
            _deserialize_extensions(self.extensions, fragment, offset)
            return self

        else:
            self.lifetime, offset = pdu.unpack_uint32(fragment, offset)
            length, offset = pdu.unpack_uint16(fragment, offset)
            self.ticket, offset = pdu.unpack_bytes(fragment, offset, length)
            return self

    def get_extension(self, ext_id):
        return get_extension(self.extensions, ext_id)


NewSessionTicket.get_extension.__doc__ = ClientHello.get_extension.__doc__


class CertificateRequest(HandshakeMessage):
    """This class represents a CertificateRequest message.

    Attributes:
        certificate_types (list of :obj:`tlsmate.tls.CertType`): the list of certificate
            types the client may offer. Only used for TLS1.2 and below.
        supported_signature_algorithms (list of :obj:`tlsmate.tls.SignatureScheme`):
            the list of signature algorithms supported by the server. Only used
            for TLS1.2 and below.
        certificate_authorities (list of bytes): the list of acceptable authorities.
            Currently, only byte strings are provided. Only used for TLS1.2 and below.
        certificate_request_context (bytes): an opaque string (only TLS1.3).
        extensions (list of :obj:`tlsmate.tls.Extension`): The list of
            TLS extensions (only TLS1.3).
    """

    msg_type = tls.HandshakeType.CERTIFICATE_REQUEST
    """:obj:`tlsmate.tls.HandshakeType.CERTIFICATE_REQUEST`
    """

    def __init__(self):
        pass

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return bytearray()

    def _deserialize_msg_body(self, fragment, offset, conn):
        if conn.version is tls.Version.TLS13:
            self.certificate_request_context = None
            self.extensions = []
            length, offset = pdu.unpack_uint8(fragment, offset)
            context, offset = pdu.unpack_bytes(fragment, offset, length)
            self.certificate_request_context = context
            _deserialize_extensions(self.extensions, fragment, offset)

        else:
            self.certificate_types = []
            self.supported_signature_algorithms = []
            self.certificate_authorities = []

            length, offset = pdu.unpack_uint8(fragment, offset)
            end = offset + length
            while offset < end:
                cert_type, offset = pdu.unpack_uint8(fragment, offset)
                self.certificate_types.append(tls.CertType.val2enum(cert_type))

            length, offset = pdu.unpack_uint16(fragment, offset)
            end = offset + length
            while offset < end:
                algo, offset = pdu.unpack_uint16(fragment, offset)
                self.supported_signature_algorithms.append(
                    tls.SignatureScheme.val2enum(algo)
                )

            if offset < len(fragment):
                length, offset = pdu.unpack_uint16(fragment, offset)
                end = offset + length
                while offset < end:
                    # TODO: here we only unpack the whole ASN.1 structure as a
                    # byte string.
                    # Unpacking the ASN.1 structure is required.
                    length, offset = pdu.unpack_uint16(fragment, offset)
                    name, offset = pdu.unpack_bytes(fragment, offset, length)
                    self.certificate_authorities.append(name)

        return self

    def get_extension(self, ext_id):
        if not hasattr(self, "extensions"):
            return None

        return get_extension(self.extensions, ext_id)


CertificateRequest.get_extension.__doc__ = ClientHello.get_extension.__doc__


class EncryptedExtensions(HandshakeMessage):
    """This class represents an EncryptedExtensions message.

    Attributes:
        extensions (list of :obj:`tlsmate.ext.Extension`): The list of
            extensions.
    """

    msg_type = tls.HandshakeType.ENCRYPTED_EXTENSIONS

    def __init__(self):
        self.extensions = []

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return bytearray()

    def _deserialize_msg_body(self, fragment, offset, conn):
        _deserialize_extensions(self.extensions, fragment, offset)
        return self

    def get_extension(self, ext_id):
        return get_extension(self.extensions, ext_id)


EncryptedExtensions.get_extension.__doc__ = ClientHello.get_extension.__doc__


class CertificateStatus(HandshakeMessage):
    """This class represents a Certificate Status message.
    """

    msg_type = tls.HandshakeType.CERTIFICATE_STATUS

    def __init__(self,):
        self.status_type = tls.StatusType.OCSP
        self.responses = []

    def _serialize_msg_body(self, conn):
        # TODO for server side implementation
        return bytearray()

    def _unpack_ocsp_response(self, fragment, offset):
        length, offset = pdu.unpack_uint24(fragment, offset)
        response, offset = pdu.unpack_bytes(fragment, offset, length)
        self.responses.append(response)
        return offset

    def _deserialize_msg_body(self, fragment, offset, conn):
        status_type, offset = pdu.unpack_uint8(fragment, offset)
        self.status_type = tls.StatusType.val2enum(status_type)
        if self.status_type is tls.StatusType.OCSP:
            offset = self._unpack_ocsp_response(fragment, offset)

        else:
            length, offset = pdu.unpack_uint24(fragment, offset)
            end = offset + length
            while offset < end:
                offset = self._unpack_ocsp_response(fragment, offset)

        return self


class ChangeCipherSpecMessage(TlsMessage):
    """A base class for all ChangeCipherSpec messages.

    Well, there is only one message for this protocol: ChangeCipherSpec. :-)
    """

    content_type = tls.ContentType.CHANGE_CIPHER_SPEC
    """ :obj:`tlsmate.tls.ContentType.CHANGE_CIPHER_SPEC`
    """

    msg_type = None
    """ :obj:`tlsmate.tls.CCSType`: The type of the CCS message.
    """

    @classmethod
    def deserialize(cls, fragment, conn):
        if len(fragment) != 1:
            raise ServerMalfunction(
                tls.ServerIssue.MESSAGE_LENGTH_ERROR, message=cls.msg_type
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
        """Method to deserialize a CCS message.

        Arguments:
            msg_body (bytearray): The bytes which contain the serialized handshake
                message.
            offset (int): The offset within the bytes where the handshake message
                starts.
            conn (:obj:`tlsmate.connection.TlsConnection`): the connection object,
                used to retrieve additional information required to deserialize
                the handshake message.

        Returns:
            :obj:`ChangeCipherSpecMessage`: the deserialized message object.
        """

        pass

    @abc.abstractmethod
    def _serialize_msg_body(self, conn):
        """Serializes the message body.

        I.e., the message body only is serialized, without the common handshake header.
        """

        pass


class ChangeCipherSpec(ChangeCipherSpecMessage):
    """This class represents a ChangeCipherSpecMessage message.
    """

    msg_type = tls.CCSType.CHANGE_CIPHER_SPEC
    """:obj:`tlsmate.tls.CCSType.CHANGE_CIPHER_SPEC`
    """

    def __init__(self):
        pass

    def _deserialize_msg_body(self, conn):
        pass

    def _serialize_msg_body(self, conn):
        pass


class Alert(TlsMessage):
    """This class represents an Alert message.

    Attributes:
        level (:obj:`tlsmate.tls.AlertLevel`): The level of the alert.
        description(:obj:`tlsmate.tls.AlertDescription`): The description of the alert.
    """

    content_type = tls.ContentType.ALERT
    msg_type = tls.ContentType.ALERT

    def __init__(self, **kwargs):
        self.level = kwargs.get("level", tls.AlertLevel.FATAL)
        self.description = kwargs.get(
            "description", tls.AlertDescription.HANDSHAKE_FAILURE
        )

    def serialize(self, conn):
        alert = bytearray()
        if type(self.level) is int:
            alert.extend(pdu.pack_uint8(self.level))

        else:
            alert.extend(pdu.pack_uint8(self.level.value))

        if type(self.description) is int:
            alert.extend(pdu.pack_uint8(self.description))

        else:
            alert.extend(pdu.pack_uint8(self.description.value))

        return bytes(alert)

    @classmethod
    def deserialize(cls, fragment, conn):
        msg = cls()
        alert_level, offset = pdu.unpack_uint8(fragment, 0)
        msg.level = tls.AlertLevel.val2enum(alert_level)
        descr, offset = pdu.unpack_uint8(fragment, offset)
        msg.description = tls.AlertDescription(descr)
        return msg


class AppDataMessage(TlsMessage):
    """Base class for all AppDataMessage.
    """

    content_type = tls.ContentType.APPLICATION_DATA
    """ :obj:`tlsmate.tls.ContentType.APPLICATION_DATA`
    """

    msg_type = tls.ContentType.APPLICATION_DATA
    """ :obj:`tlsmate.tls.ContentType.APPLICATION_DATA`
    """

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
    """This class represents an AppData message.

    Attributes:
        data (bytes): The application data received/to be sent.
    """

    def __init__(self, *content):
        self.data = bytearray()
        for data in content:
            self.data.extend(data)

    def _deserialize_msg_body(self, fragment, conn):
        self.data = fragment

    def _serialize_msg_body(self, conn):
        return bytes(self.data)


class HeartbeatMessage(TlsMessage):
    """A base class for all Heartbeat messages.
    """

    content_type = tls.ContentType.HEARTBEAT
    """ :obj:`tlsmate.tls.ContentType.HEARTBEAT`
    """

    msg_type = None
    """ :obj:`tlsmate.tls.HeartbeatType`: The type of the Heartbeat message.
    """

    def __init__(self, payload_length=None, payload=None, padding=None):
        self.payload_length = payload_length
        self.payload = payload
        self.padding = padding

    @classmethod
    def deserialize(cls, fragment, conn):
        msg_type, offset = pdu.unpack_uint8(fragment, 0)
        msg_type = tls.HeartbeatType.val2enum(msg_type, alert_on_failure=True)
        payload_length, offset = pdu.unpack_uint16(fragment, offset)
        payload, offset = pdu.unpack_bytes(fragment, offset, payload_length)
        padding = fragment[offset:]
        cls_name = _heartbeat_deserialization_map[msg_type]
        return cls_name(payload_length, payload, padding)

    def serialize(self, conn):
        message = bytearray()
        message.extend(pdu.pack_uint8(self.msg_type.value))
        message.extend(pdu.pack_uint16(self.payload_length))
        message.extend(self.payload)
        message.extend(self.padding)
        return message


class HeartbeatRequest(HeartbeatMessage):
    """This class represents a heartbeat request message.
    """

    msg_type = tls.HeartbeatType.HEARTBEAT_REQUEST
    """ :obj:`tlsmate.tls.HeartbeatType.HEARTBEAT_REQUEST`
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class HeartbeatResponse(HeartbeatMessage):
    """This class represents a heartbeat response message.
    """

    msg_type = tls.HeartbeatType.HEARTBEAT_RESPONSE
    """ :obj:`tlsmate.tls.HeartbeatType.HEARTBEAT_RESPONSE`
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class SSL2Message(TlsMessage):
    """A base class for all SSL2 messages.
    """

    content_type = tls.ContentType.SSL2
    """:obj:`tlsmate.tls.ContentType.SSL2`
    """

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
    """This class represents an SSL2 CLientHello message.

    Attributes:
        version (:obj:`tlsmate.tls.SSLVersion`): The version "SSL2".
        cipher_specs (list of :obj:`tlsmate.tls.SSLCipherKind`): The list
            of cipher kinds offered by the client.
        session_id (bytes): The session id.
        challenge (bytes): The random bytes by the client.
    """

    msg_type = tls.SSLMessagType.SSL2_CLIENT_HELLO
    """:obj:`tlsmate.tls.SSLMessagType.SSL2_CLIENT_HELLO`
    """

    def __init__(self):
        self.version = tls.SSLVersion.SSL2
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
        msg.extend(pdu.pack_uint16(self.version.value))
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
    """This class represents an SSL2 ServerHello message.

    Attributes:
        session_id_hit (int): An indication if the session id offered by the client
            will be used.
        cert_type (int): The type of the certificate.
        version (:obj:`tlsmate.tls.SSLVersion`): The version "SSL2".
        cipher_specs (list of :obj:`tlsmate.tls.SSLCipherKind`): The list
            of cipher kinds offered by the server.
        connection_id (bytes): The connection id.
        certificate (bytes): The certificate provided by the server.
    """

    msg_type = tls.SSLMessagType.SSL2_SERVER_HELLO
    """:obj:`tlsmate.tls.SSLMessagType.SSL2_SERVER_HELLO`
    """

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


class SSL2Error(SSL2Message):
    """This class represents an SSL2 Error message.

    Attributes:
        session_id_hit (int): An indication if the session id offered by the client
            will be used.
        cert_type (int): The type of the certificate.
        version (:obj:`tlsmate.tls.SSLVersion`): The version "SSL2".
        cipher_specs (list of :obj:`tlsmate.tls.SSLCipherKind`): The list
            of cipher kinds offered by the server.
        connection_id (bytes): The connection id.
        certificate (bytes): The certificate provided by the server.
    """

    msg_type = tls.SSLMessagType.SSL2_ERROR
    """:obj:`tlsmate.tls.SSLMessagType.SSL2_ERROR`
    """

    def __init__(self):
        self.error = None

    def serialize(self, conn):
        pass

    def _deserialize_msg_body(self, fragment, offset, conn):
        error, offset = pdu.unpack_uint16(fragment, offset)
        self.error = tls.SSLError.val2enum(error)
        return self


"""Map the handshake message type to the corresponding class.
"""
_hs_deserialization_map = {
    tls.HandshakeType.HELLO_REQUEST: HelloRequest,
    tls.HandshakeType.CLIENT_HELLO: ClientHello,
    tls.HandshakeType.SERVER_HELLO: ServerHello,
    tls.HandshakeType.NEW_SESSION_TICKET: NewSessionTicket,
    tls.HandshakeType.END_OF_EARLY_DATA: EndOfEarlyData,
    tls.HandshakeType.ENCRYPTED_EXTENSIONS: EncryptedExtensions,
    tls.HandshakeType.CERTIFICATE: Certificate,
    tls.HandshakeType.SERVER_KEY_EXCHANGE: ServerKeyExchange,
    tls.HandshakeType.CERTIFICATE_REQUEST: CertificateRequest,
    tls.HandshakeType.SERVER_HELLO_DONE: ServerHelloDone,
    tls.HandshakeType.CERTIFICATE_VERIFY: CertificateVerify,
    # tls.HandshakeType.CLIENT_KEY_EXCHANGE = 16
    tls.HandshakeType.FINISHED: Finished,
    tls.HandshakeType.CERTIFICATE_STATUS: CertificateStatus,
    # tls.HandshakeType.KEY_UPDATE = 24
    # tls.HandshakeType.COMPRESSED_CERTIFICATE = 25
    # tls.HandshakeType.EKT_KEY = 26
    # tls.HandshakeType.MESSAGE_HASH = 254
}

_ccs_deserialization_map = {tls.CCSType.CHANGE_CIPHER_SPEC: ChangeCipherSpec}
"""Map the CCS message type to the corresponding class.
"""

_heartbeat_deserialization_map = {
    tls.HeartbeatType.HEARTBEAT_REQUEST: HeartbeatRequest,
    tls.HeartbeatType.HEARTBEAT_RESPONSE: HeartbeatResponse,
}

_ssl2_deserialization_map = {
    tls.SSLMessagType.SSL2_SERVER_HELLO: SSL2ServerHello,
    tls.SSLMessagType.SSL2_ERROR: SSL2Error,
}
"""Map the SSL2 message type to the corresponding class.
"""
