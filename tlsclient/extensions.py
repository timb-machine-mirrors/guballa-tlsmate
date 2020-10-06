# -*- coding: utf-8 -*-
"""Module containing the TLS Extension classes
"""

import abc
from tlsclient.protocol import ProtocolData
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls


class Extension(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def serialize_ext_body(self):
        pass

    def serialize(self):
        ext = ProtocolData()
        ext_body = self.serialize_ext_body()
        ext.append_uint16(self.extension_id.value)
        ext.append_uint16(len(ext_body))
        ext.extend(ext_body)
        return ext

    @staticmethod
    def deserialize(fragment, offset):
        ext_id, offset = fragment.unpack_uint16(offset)
        ext_id = tls.Extension.val2enum(ext_id, alert_on_failure=True)
        ext_len, offset = fragment.unpack_uint16(offset)
        ext_body, offset = fragment.unpack_bytes(offset, ext_len)
        cls_name = deserialization_map[ext_id]
        extension = cls_name()
        extension.deserialize_ext_body(ext_body)
        return extension, offset


class ExtServerNameIndication(Extension):

    extension_id = tls.Extension.SERVER_NAME

    def __init__(self, **kwargs):
        self.host_name = kwargs.get("host_name")

    def serialize_ext_body(self):
        # we only support exacly one list element: host_name
        ext = ProtocolData()
        ext.append_uint8(0)  # host_name
        ext.append_uint16(len(self.host_name))
        ext.append_str(self.host_name)
        name_list = ProtocolData()
        name_list.append_uint16(len(ext))
        name_list.extend(ext)
        return name_list

    def deserialize_ext_body(self, fragment):
        if not len(fragment):
            return
        list_length, offset = fragment.unpack_uint16(0)
        if offset + list_length != len(fragment):
            raise FatalAlert(
                f"Extension {self.extension_id.name}: list length incorrect",
                tls.AlertDescription.DECODE_ERROR,
            )
        while offset < len(fragment):
            name_type, offset = fragment.unpack_uint8(offset)
            name_length, offset = fragment.unpack_uint16(offset)
            name, offset = fragment.unpack_bytes(offset, name_length)
            if name_type == 0:
                self.host_name = name.decode()
        if self.host_name is None:
            raise FatalAlert(
                f"{self.extension_id}: host_name not present",
                tls.AlertDescription.DECODE_ERROR,
            )


class ExtExtendedMasterSecret(Extension):

    extension_id = tls.Extension.EXTENDED_MASTER_SECRET

    def serialize_ext_body(self):
        return ProtocolData()

    def deserialize_ext_body(self, ext_body):
        if ext_body:
            raise FatalAlert(
                f"Message length error for {self.extension_id.name}",
                tls.AlertDescription.DECODE_ERROR,
            )
        return self


class ExtEncryptThenMac(Extension):

    extension_id = tls.Extension.ENCRYPT_THEN_MAC

    def serialize_ext_body(self):
        return ProtocolData()

    def deserialize_ext_body(self, ext_body):
        if ext_body:
            raise FatalAlert(
                f"Message length error for {self.extension_id.name}",
                tls.AlertDescription.DECODE_ERROR,
            )
        return self


class ExtRenegotiationInfo(Extension):

    extension_id = tls.Extension.RENEGOTIATION_INFO

    def __init__(self, **kwargs):
        self.opaque = kwargs.get("opaque", b"\0")

    def serialize_ext_body(self):
        return self.opaque

    def deserialize_ext_body(self, ext_body):
        self.opaque, _ = ext_body.unpack_bytes(0, len(ext_body))
        return self


class ExtEcPointFormats(Extension):

    extension_id = tls.Extension.EC_POINT_FORMATS

    def __init__(self, **kwargs):
        self.point_formats = kwargs.get(
            "point_formats", [tls.EcPointFormat.UNCOMPRESSED]
        )

    def serialize_ext_body(self):
        format_list = ProtocolData()
        for point_format in self.point_formats:
            if type(point_format) == int:
                format_list.append_uint8(point_format)
            else:
                format_list.append_uint8(point_format.value)
        ext_body = ProtocolData()
        ext_body.append_uint8(len(format_list))
        ext_body.extend(format_list)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        self.point_formats = []
        length, offset = ext_body.unpack_uint8(0)
        if offset + length != len(ext_body):
            raise FatalAlert(
                f"Message length error for {self.extension_id.name}",
                tls.AlertDescription.DECODE_ERROR,
            )
        for i in range(length):
            point_format, offset = ext_body.unpack_uint8(offset)
            self.point_formats.append(tls.EcPointFormat.val2enum(point_format))
        return self


class ExtSupportedGroups(Extension):

    extension_id = tls.Extension.SUPPORTED_GROUPS

    def __init__(self, **kwargs):
        self.supported_groups = kwargs.get("supported_groups", [])

    def serialize_ext_body(self):
        group_list = ProtocolData()
        for group in self.supported_groups:
            if type(group) == int:
                group_list.append_uint16(group)
            else:
                group_list.append_uint16(group.value)
        ext_body = ProtocolData()
        ext_body.append_uint16(len(group_list))
        ext_body.extend(group_list)
        return ext_body


class ExtSignatureAlgorithms(Extension):

    extension_id = tls.Extension.SIGNATURE_ALGORITHMS

    def __init__(self, **kwargs):
        self.signature_algorithms = kwargs.get("signature_algorithms", [])

    def serialize_ext_body(self):
        algo_list = ProtocolData()
        for algo in self.signature_algorithms:
            if type(algo) == int:
                algo_list.append_uint16(algo)
            elif type(algo) == tls.SignatureScheme:
                algo_list.append_uint16(algo.value)
            elif type(algo) == tuple:
                pass  # TODO
        ext_body = ProtocolData()
        ext_body.append_uint16(len(algo_list))
        ext_body.extend(algo_list)
        return ext_body


class ExtSessionTicket(Extension):

    extension_id = tls.Extension.SESSION_TICKET

    def __init__(self, **kwargs):
        self.ticket = kwargs.get("ticket")

    def serialize_ext_body(self):
        ext_body = ProtocolData()
        if self.ticket is not None:
            ext_body.extend(self.ticket)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        return self


deserialization_map = {
    tls.Extension.SERVER_NAME: ExtServerNameIndication,
    # tls.Extension.MAX_FRAGMENT_LENGTH = 1
    # tls.Extension.CLIENT_CERTIFICATE_URL = 2
    # tls.Extension.TRUSTED_CA_KEYS = 3
    # tls.Extension.TRUNCATED_HMAC = 4
    # tls.Extension.STATUS_REQUEST = 5
    # tls.Extension.USER_MAPPING = 6
    # tls.Extension.CLIENT_AUTHZ = 7
    # tls.Extension.SERVER_AUTHZ = 8
    # tls.Extension.CERT_TYPE = 9
    # tls.Extension.SUPPORTED_GROUPS = 10
    tls.Extension.EC_POINT_FORMATS: ExtEcPointFormats,
    # tls.Extension.SRP = 12
    # tls.Extension.SIGNATURE_ALGORITHMS = 13
    # tls.Extension.USE_SRTP = 14
    # tls.Extension.HEARTBEAT = 15
    # tls.Extension.APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    # tls.Extension.STATUS_REQUEST_V2 = 17
    # tls.Extension.SIGNED_CERTIFICATE_TIMESTAMP = 18
    # tls.Extension.CLIENT_CERTIFICATE_TYPE = 19
    # tls.Extension.SERVER_CERTIFICATE_TYPE = 20
    # tls.Extension.PADDING = 21
    tls.Extension.ENCRYPT_THEN_MAC: ExtEncryptThenMac,
    tls.Extension.EXTENDED_MASTER_SECRET: ExtExtendedMasterSecret,
    # tls.Extension.TOKEN_BINDING = 24
    # tls.Extension.CACHED_INFO = 25
    # tls.Extension.TLS_LTS = 26
    # tls.Extension.COMPRESS_CERTIFICATE = 27
    # tls.Extension.RECORD_SIZE_LIMIT = 28
    # tls.Extension.PWD_PROTECT = 29
    # tls.Extension.PWD_CLEAR = 30
    # tls.Extension.PASSWORD_SALT = 31
    # tls.Extension.TICKET_PINNING = 32
    # tls.Extension.TLS_CERT_WITH_EXTERN_PSK = 33
    # tls.Extension.DELEGATED_CREDENTIALS = 34
    tls.Extension.SESSION_TICKET: ExtSessionTicket,
    # tls.Extension.SUPPORTED_EKT_CIPHERS = 39
    # tls.Extension.PRE_SHARED_KEY = 41
    # tls.Extension.EARLY_DATA = 42
    # tls.Extension.SUPPORTED_VERSIONS = 43
    # tls.Extension.COOKIE = 44
    # tls.Extension.PSK_KEY_EXCHANGE_MODES = 45
    # tls.Extension.CERTIFICATE_AUTHORITIES = 47
    # tls.Extension.OID_FILTERS = 48
    # tls.Extension.POST_HANDSHAKE_AUTH = 49
    # tls.Extension.SIGNATURE_ALGORITHMS_CERT = 50
    # tls.Extension.KEY_SHARE = 51
    # tls.Extension.TRANSPARENCY_INFO = 52
    # tls.Extension.CONNECTION_ID = 53
    # tls.Extension.EXTERNAL_ID_HASH = 55
    # tls.Extension.EXTERNAL_SESSION_ID = 56
    tls.Extension.RENEGOTIATION_INFO: ExtRenegotiationInfo,
}
