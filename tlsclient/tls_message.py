# -*- coding: utf-8 -*-
"""Module providing classes for each TLS message.
"""
import abc
import os
import time
import tlsclient.constants as tls
import tlsclient.protocol as protocol
import tlsclient.extensions as ext
from tlsclient.security_parameters import get_random_value

class TlsMessage(metaclass=abc.ABCMeta):
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
        cls_name = hs_deserialization_map[msg_type]
        msg = cls_name().deserialize_msg_body(fragment, offset, conn)
        conn.update_msg_hash(fragment)
        return msg

    @abc.abstractmethod
    def deserialize_msg_body(self, msg_body, length, conn):
        pass

    @abc.abstractmethod
    def serialize_msg_body(self, conn):
        pass

    def init_from_profile(self, profile):
        return self

    def serialize(self, conn):
        msg_body = self.serialize_msg_body(conn)

        handshake_msg = protocol.ProtocolData()
        handshake_msg.append_uint8(self.msg_type.value)
        handshake_msg.append_uint24(len(msg_body))
        handshake_msg.extend(msg_body)
        conn.update_msg_hash(handshake_msg)
        return handshake_msg


class ClientHello(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_HELLO

    def __init__(self):
        self.client_version = tls.Version.TLS12
        self.random = get_random_value()
        self.session_id = protocol.ProtocolData()
        self.cipher_suites = [tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.compression_methods = [tls.CompressionMethod.NULL]
        self.extensions = []

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
        return self

    def serialize_msg_body(self, conn):
        msg = protocol.ProtocolData()

        # version
        version = self.client_version
        if type(version) == tls.Version:
            version = version.value
        msg.append_uint16(version)

        # random
        if self.random is None:
            self.random = get_random_value()
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
        ext_bytes = protocol.ProtocolData()
        for extension in self.extensions:
            ext_bytes.extend(extension.serialize())
        msg.append_uint16(len(ext_bytes))
        msg.extend(ext_bytes)

        conn.init_msg_hash()
        return msg

    def deserialize_msg_body(self, msg_body, length, conn):
        return self


class ServerHello(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO

    def serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def deserialize_msg_body(self, fragment, offset, conn):

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
                ext_id, offset = fragment.unpack_uint16(offset)
                ext_id = tls.Extension.val2enum(ext_id, alert_on_failure=True)
                ext_len, offset = fragment.unpack_uint16(offset)
                ext_body, offset = fragment.unpack_bytes(offset, ext_len)
                self.extensions.append(ext.Extension.deserialize(ext_id, ext_body))

        conn.update(
            version=self.version,
            cipher_suite=self.cipher_suite,
            server_random=self.random,
        )
        return self


class Certificate(HandshakeMessage):

    msg_type = tls.HandshakeType.CERTIFICATE

    def serialize_msg_body(self, conn):
        # TODO
        pass

    def deserialize_msg_body(self, fragment, offset, conn):
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

    def deserialize_msg_body(self, fragment, offset, conn):
        # ServerECDHParams    params;
        offset = self.deserialize_ServerECDHParams(fragment, offset, conn)
        # Signature           signed_params;
        signature_scheme, offset = fragment.unpack_uint16(offset)
        self.signature_scheme = tls.SignatureScheme.val2enum(signature_scheme)
        signature_len, offset = fragment.unpack_uint16(offset)
        self.signature, offset = fragment.unpack_bytes(offset, signature_len)
        return self


class KeyExchangeDH(object):
    def deserialize_msg_body(self, fragment, offset, conn):
        pass


class ServerKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_KEY_EXCHANGE

    def serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def deserialize_msg_body(self, fragment, offset, conn):
        self.ec = None
        self.dh = None
        key_exchange_method = conn.sec_param.key_exchange_method
        if key_exchange_method in [
            tls.KeyExchangeAlgorithm.ECDH_ECDSA,
            tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
            tls.KeyExchangeAlgorithm.ECDH_RSA,
            tls.KeyExchangeAlgorithm.ECDHE_RSA,
        ]:
            # RFC 4492
            self.ec = KeyExchangeEC().deserialize_msg_body(
                fragment, offset, conn
            )
        elif key_exchange_method in [
            tls.KeyExchangeAlgorithm.DHE_DSS,
            tls.KeyExchangeAlgorithm.DHE_RSA,
            tls.KeyExchangeAlgorithm.DH_ANON,
        ]:
            # RFC5246
            self.dh = KeyExchangeDH().deserialize_msg_body(
                fragment, offset, conn
            )
        else:
            raise FatalAlert(
                "Key exchange algorithm incompatible with ServerKeyExchange message",
                tls.AlertDescription.UNEXPECTED_MESSAGE,
            )
        return self


class ServerHelloDone(HandshakeMessage):

    msg_type = tls.HandshakeType.SERVER_HELLO_DONE

    def serialize_msg_body(self, conn):
        # TODO if we want to implement the server side as well
        pass

    def deserialize_msg_body(self, fragment, offset, conn):
        if offset != len(fragment):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return self


class ClientKeyExchange(HandshakeMessage):

    msg_type = tls.HandshakeType.CLIENT_KEY_EXCHANGE

    def serialize_msg_body(self, conn):
        conn.update_keys()
        msg = protocol.ProtocolData()
        msg.append_uint8(len(conn.sec_param.public_key))
        msg.extend(conn.sec_param.public_key)
        return msg

    def deserialize_msg_body(self, fragment, offset, conn):
        pass


class Finished(HandshakeMessage):

    msg_type = tls.HandshakeType.FINISHED

    def serialize_msg_body(self, conn):
        if conn.sec_param.entity == tls.Entity.CLIENT:
            hash_val = conn.finalize_msg_hash(intermediate=True)
            label = b"client finished"
        else:
            hash_val = conn.finalize_msg_hash()
            label = b"server finished"

#        # patch to fix values
#        hash_val = bytes.fromhex("6492b05d5a5b165784ad89d3b1fca68928361601029a9489ced65591da4997d6")
#        conn.sec_param.master_secret = bytes.fromhex(
#"81 d3 22 cb 5d ff 62 f4 9b f0 f0 04 c1 46 46 c3 "
#"a3 12 20 f0 90 52 10 de 29 cb df b5 86 94 e2 ba "
#"87 f8 f0 85 23 10 3d 0b 9c 9e a4 ca 3e fc 8f 30 "
#        )
#
#        conn.record_layer._write_state._enc_key = bytes.fromhex(
#"1c a8 96 7e f4 82 2b 65 4c 77 17 0b ec 14 cf 9b "
#        )
#        conn.record_layer._write_state._mac_key = bytes.fromhex(
#"55 d9 b5 1a cc d3 8a a7 71 8b 40 18 ef e5 7f d4 "
#"b3 e5 a5 c1 ff a9 e2 7f 94 c1 9d 18 23 33 2a a9 "
#        )


        val = conn.sec_param.prf(conn.sec_param.master_secret, label, hash_val, 12)
        print("Debug02:", hash_val)
        print("Debug03:", val)
        print("Debug04:", conn.sec_param.hash_algo)
        msg = protocol.ProtocolData(val)
        return msg

    def deserialize_msg_body(self, fragment, offset, conn):
        verify_data = fragment[offset:]
        if conn.sec_param.entity == tls.Entity.CLIENT:
            hash_val = conn.finalize_msg_hash()
            label = b"server finished"
        else:
            hash_val = conn.finalize_msg_hash(intermediate=True)
            label = b"client finished"
        val = conn.sec_param.prf(conn.sec_param.master_secret, label, hash_val, 12)
        print("Debug02:", hash_val)
        print("Debug03:", val)
        print("Debug04:", conn.sec_param.hash_algo)
        print("Debug05:", fragment.dump())
        if verify_data != val:
            FatalAlert("Received Finidhed: verify_data does not match", tls.AlertDescription.BAD_RECORD_MAC)
        return self



class ChangeCipherSpecMessage(TlsMessage):

    content_type = tls.ContentType.CHANGE_CIPHER_SPEC
    msg_type = None

    @classmethod
    def deserialize(cls, fragment, conn):
        if len(fragment) != 1:
            FatalAlert("Received ChangedCipherSpec has unexpected length", tls.AlertDescription.DECODE_ERROR)
        msg_type, offset = fragment.unpack_uint8(0)
        msg_type = tls.CCSType.val2enum(msg_type, alert_on_failure=True)
        cls_name = ccs_deserialization_map[msg_type]
        msg = cls_name()
        msg.deserialize_msg_body(conn)
        return msg

    def serialize(self, conn):
        self.serialize_msg_body(conn)
        ccs_msg = protocol.ProtocolData()
        ccs_msg.append_uint8(self.msg_type.value)
        return ccs_msg

    @abc.abstractmethod
    def deserialize_msg_body(self, conn):
        pass

    @abc.abstractmethod
    def serialize_msg_body(self, conn):
        pass

    def init_from_profile(self, profile):
        return self

class ChangeCipherSpec(ChangeCipherSpecMessage):

    msg_type = tls.CCSType.CHANGE_CIPHER_SPEC

    def deserialize_msg_body(self, conn):
        conn.update_read_state()

    def serialize_msg_body(self, conn):
        conn.update_write_state()


class Alert(TlsMessage):

    content_type = tls.ContentType.ALERT

    def __init__(self, **kwargs):
        self.level = kwargs.get("level", tls.AlertLevel.FATAL)
        self.description = kwargs.get(
            "description", tls.AlertDescription.HANDSHAKE_FAILURE
        )

    def serialize(self, conn):
        alert = protocol.ProtocolData()
        if self.level == int:
            alert.append_uint8(self.level)
        else:
            alert.append_uint8(self.level.value)
        if self.description == int:
            alert.append_uint8(self.description)
        else:
            alert.append_uint8(self.description.value)
        return alert


hs_deserialization_map = {
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

ccs_deserialization_map = {
        tls.CCSType.CHANGE_CIPHER_SPEC: ChangeCipherSpec
        }
