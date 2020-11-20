# -*- coding: utf-8 -*-
"""Module containing the TLS Extension classes
"""

import abc
import time
from tlsmate.exception import FatalAlert
import tlsmate.constants as tls
import tlsmate.structures as structs
from tlsmate import pdu


class Extension(metaclass=abc.ABCMeta):
    """Abstract class for all extensions.
    """

    @abc.abstractmethod
    def serialize_ext_body(self):
        """Serializes the content of an extension, i.e. excluding the header.

        Returns:
            bytes: The serialized extensions body.
        """
        pass

    def serialize(self, conn):
        """Serializes an extensions, including the extensions header.

        Arguments:
            conn (:obj:`tlsmate.connection.TlsConnection`): The connection object,
                needed for some odd cases, e.g. when serializing a key share
                extensions.

        Returns:
            bytes: The serialized extension.
        """
        ext_body = self.serialize_ext_body(conn)
        ext = bytearray(pdu.pack_uint16(self.extension_id.value))
        ext.extend(pdu.pack_uint16(len(ext_body)))
        ext.extend(ext_body)
        return ext

    @staticmethod
    def deserialize(fragment, offset):
        """Deserializes an extension.

        Arguments:
            fragment (bytes): A PDU buffer as received from the network.
            offset (int): The offset within the fragment where the extension starts.

        Returns:
            :obj:`Extension`, new offset: The deserialized extension as an
                python object and the new offset into the fragment.
        """
        ext_id, offset = pdu.unpack_uint16(fragment, offset)
        ext_id = tls.Extension.val2enum(ext_id, alert_on_failure=True)
        ext_len, offset = pdu.unpack_uint16(fragment, offset)
        ext_body, offset = pdu.unpack_bytes(fragment, offset, ext_len)
        cls_name = deserialization_map[ext_id]
        extension = cls_name()
        extension.deserialize_ext_body(ext_body)
        return extension, offset


class ExtServerNameIndication(Extension):
    """Represents the ServerNameIndication extension.

    Attributes:
        host_name (str): The name which identifies the host.
    """

    extension_id = tls.Extension.SERVER_NAME
    """:obj:`tlsmate.constants.Extension.SERVER_NAME`
    """

    def __init__(self, **kwargs):
        self.host_name = kwargs.get("host_name")

    def serialize_ext_body(self, conn):
        # we only support exacly one list element: host_name
        ext = bytearray(pdu.pack_uint8(0))  # host_name
        ext.extend(pdu.pack_uint16(len(self.host_name)))
        ext.extend(pdu.pack_str(self.host_name))
        ext_body = bytearray(pdu.pack_uint16(len(ext)))
        ext_body.extend(ext)
        return ext_body

    def deserialize_ext_body(self, fragment):
        if not len(fragment):
            return
        list_length, offset = pdu.unpack_uint16(fragment, 0)
        if offset + list_length != len(fragment):
            raise FatalAlert(
                f"Extension {self.extension_id}: list length incorrect",
                tls.AlertDescription.DECODE_ERROR,
            )
        while offset < len(fragment):
            name_type, offset = pdu.unpack_uint8(fragment, offset)
            name_length, offset = pdu.unpack_uint16(fragment, offset)
            name, offset = pdu.unpack_bytes(fragment, offset, name_length)
            if name_type == 0:
                self.host_name = name.decode()
        if self.host_name is None:
            raise FatalAlert(
                f"{self.extension_id}: host_name not present",
                tls.AlertDescription.DECODE_ERROR,
            )


class ExtExtendedMasterSecret(Extension):
    """Represents the ExtendedMasterSecret extension.
    """

    extension_id = tls.Extension.EXTENDED_MASTER_SECRET
    """:obj:`tlsmate.constants.Extension.EXTENDED_MASTER_SECRET`
    """

    def serialize_ext_body(self, conn):
        return b""

    def deserialize_ext_body(self, ext_body):
        if ext_body:
            raise FatalAlert(
                f"Message length error for {self.extension_id}",
                tls.AlertDescription.DECODE_ERROR,
            )
        return self


class ExtEncryptThenMac(Extension):
    """Represents the EncryptThenMac extension.
    """

    extension_id = tls.Extension.ENCRYPT_THEN_MAC
    """:obj:`tlsmate.constants.Extension.ENCRYPT_THEN_MAC`
    """

    def serialize_ext_body(self, conn):
        return b""

    def deserialize_ext_body(self, ext_body):
        if ext_body:
            raise FatalAlert(
                f"Message length error for {self.extension_id}",
                tls.AlertDescription.DECODE_ERROR,
            )
        return self


class ExtRenegotiationInfo(Extension):
    """Represents the RenegotiationInfo extension.

    Attributes:
        opaque (bytes): The opaque bytes.
    """

    extension_id = tls.Extension.RENEGOTIATION_INFO
    """:obj:`tlsmate.constants.Extension.RENEGOTIATION_INFO`
    """

    def __init__(self, **kwargs):
        self.opaque = kwargs.get("opaque", b"\0")

    def serialize_ext_body(self, conn):
        return self.opaque

    def deserialize_ext_body(self, ext_body):
        self.opaque, _ = pdu.unpack_bytes(ext_body, 0, len(ext_body))
        return self


class ExtEcPointFormats(Extension):
    """Represents the EcPointFormat extension.

    Attributes:
        point_formats (list of :obj:`tlsmate.constants.EcPointFormat`): The list
        of supported point formats.
    """

    extension_id = tls.Extension.EC_POINT_FORMATS
    """:obj:`tlsmate.constants.Extension.EC_POINT_FORMATS`
    """

    def __init__(self, **kwargs):
        self.point_formats = kwargs.get(
            "point_formats", [tls.EcPointFormat.UNCOMPRESSED]
        )

    def serialize_ext_body(self, conn):
        format_list = bytearray()
        for point_format in self.point_formats:
            if type(point_format) == int:
                format_list.extend(pdu.pack_uint8(point_format))
            else:
                format_list.extend(pdu.pack_uint8(point_format.value))
        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint8(len(format_list)))
        ext_body.extend(format_list)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        self.point_formats = []
        length, offset = pdu.unpack_uint8(ext_body, 0)
        if offset + length != len(ext_body):
            raise FatalAlert(
                f"Message length error for {self.extension_id}",
                tls.AlertDescription.DECODE_ERROR,
            )
        for i in range(length):
            point_format, offset = pdu.unpack_uint8(ext_body, offset)
            self.point_formats.append(tls.EcPointFormat.val2enum(point_format))
        return self


class ExtSupportedGroups(Extension):
    """Represents the SupportedGroup extension.

    Attributes:
        supported_groups (list of :obj:`tlsmate.constants.SupportedGroup`): The list
        of supported groups.
    """

    extension_id = tls.Extension.SUPPORTED_GROUPS
    """:obj:`tlsmate.constants.Extension.SUPPORTED_GROUPS`
    """

    def __init__(self, **kwargs):
        self.supported_groups = kwargs.get("supported_groups", [])

    def serialize_ext_body(self, conn):
        group_list = bytearray()
        for group in self.supported_groups:
            if type(group) == int:
                group_list.extend(pdu.pack_uint16(group))
            else:
                group_list.extend(pdu.pack_uint16(group.value))
        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint16(len(group_list)))
        ext_body.extend(group_list)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        length, offset = pdu.unpack_uint16(ext_body, 0)
        end_of_list = offset + length
        while offset < end_of_list:
            group, offset = pdu.unpack_uint16(ext_body, offset)
            try:
                group = tls.SupportedGroups(group)
            except ValueError:
                pass
            self.supported_groups.append(group)
        return self


class ExtSignatureAlgorithms(Extension):
    """Represents the SignatureAlgorithms extension.

    Attributes:
        signature_algorithms (list of :obj:`tlsmate.constants.SignatureScheme`): The
        of supported signature algorithms.
    """

    extension_id = tls.Extension.SIGNATURE_ALGORITHMS
    """:obj:`tlsmate.constants.Extension.SIGNATURE_ALGORITHMS`
    """

    def __init__(self, **kwargs):
        self.signature_algorithms = kwargs.get("signature_algorithms", [])

    def serialize_ext_body(self, conn):
        algo_list = bytearray()
        for algo in self.signature_algorithms:
            if type(algo) == int:
                algo_list.extend(pdu.pack_uint16(algo))
            elif type(algo) == tls.SignatureScheme:
                algo_list.extend(pdu.pack_uint16(algo.value))
            elif type(algo) == tuple:
                pass  # TODO
        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint16(len(algo_list)))
        ext_body.extend(algo_list)
        return ext_body


class ExtSessionTicket(Extension):
    """Represents the SessionTicket extension.

    Attributes:
        ticket (bytes): The ticket.
    """

    extension_id = tls.Extension.SESSION_TICKET
    """:obj:`tlsmate.constants.Extension.SIGNATURE_ALGORITHMS`
    """

    def __init__(self, **kwargs):
        self.ticket = kwargs.get("ticket")

    def serialize_ext_body(self, conn):
        ext_body = bytearray()
        if self.ticket is not None:
            ext_body.extend(self.ticket)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        return self


class ExtSupportedVersions(Extension):
    """Represents the SupportedVersion extension.

    Attributes:
        versions (list of :obj:`tlsmate.constants.Version`): The list of TLS versions
            supported.
    """

    extension_id = tls.Extension.SUPPORTED_VERSIONS
    """:obj:`tlsmate.constants.Extension.SUPPORTED_VERSIONS`
    """

    def __init__(self, **kwargs):
        self.versions = kwargs.get("versions")

    def serialize_ext_body(self, conn):
        versions = bytearray()
        for version in self.versions:
            versions.extend(pdu.pack_uint16(version.value))
        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint8(len(versions)))
        ext_body.extend(versions)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        self.versions = []
        offset = 0
        while offset < len(ext_body):
            version, offset = pdu.unpack_uint16(ext_body, offset)
            version = tls.Version.val2enum(version)
            self.versions.append(version)
        return self


class ExtKeyShare(Extension):
    """Represents the KeyShare extension.

    Given the list of supported groups, during serialization the shares are actually
    generated and the resulting public keys are included into the extension. The user
    must ensure that the key share uses the same sequence for the groups than
    provided in the SupportedGroup extension.

    Attributes:
        key_shares (list of :obj:`tlsmate.constants.SupportedGroup`): The list of
            supported groups for which key shares shall be generated.
    """

    extension_id = tls.Extension.KEY_SHARE
    """:obj:`tlsmate.constants.Extension.SIGNATURE_ALGORITHMS`
    """

    def __init__(self, **kwargs):
        self.key_shares = kwargs.get("key_shares")

    def serialize_ext_body(self, conn):
        key_shares = bytearray()
        for group in self.key_shares:
            key_shares.extend(pdu.pack_uint16(group.value))
            share = conn.get_key_share(group)
            key_shares.extend(pdu.pack_uint16(len(share)))
            key_shares.extend(share)
        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint16(len(key_shares)))
        ext_body.extend(key_shares)
        return ext_body

    def deserialize_ext_body(self, ext_body):
        self.key_shares = []
        offset = 0
        while offset < len(ext_body):
            group, offset = pdu.unpack_uint16(ext_body, offset)
            group = tls.SupportedGroups.val2enum(group, alert_on_failure=True)
            length, offset = pdu.unpack_uint16(ext_body, offset)
            share, offset = pdu.unpack_bytes(ext_body, offset, length)
            self.key_shares.append(
                structs.KeyShareEntry(group=group, key_exchange=share)
            )
        return self


class ExtPreSharedKey(Extension):
    """Represents the PreSharedKey extension for TLS1.3

    Builds this extension based on the list of the given pre shared keys.

    Attributes:
        psks (list of :obj:`tlsmate.structs.Psk`): The list of
            pre shared keys to offer to the server.
    """

    extension_id = tls.Extension.PRE_SHARED_KEY
    """:obj:`tlsmate.constants.Extension.PRE_SHARED_KEY`
    """

    def __init__(self, **kwargs):
        self.psks = kwargs.get("psks")
        self._bytes_after_ids = 0

    def serialize_ext_body(self, conn):
        identities = bytearray()
        binders = bytearray()
        for psk in self.psks:
            identities.extend(pdu.pack_uint16(len(psk.ticket)))
            identities.extend(psk.ticket)
            ticket_age = int((time.time() - psk.timestamp) * 1000 + psk.age_add) % (
                2 ** 32
            )
            identities.extend(pdu.pack_uint32(ticket_age))
            binders.extend(pdu.pack_uint8(psk.hmac.mac_len))
            binders.extend(b"\0" * psk.hmac.mac_len)

        ext_body = bytearray()
        ext_body.extend(pdu.pack_uint16(len(identities)))
        ext_body.extend(identities)
        binders_len = len(binders)
        self._bytes_after_ids = binders_len + 2  # 2 bytes for length indicator
        ext_body.extend(pdu.pack_uint16(binders_len))
        ext_body.extend(binders)

        return ext_body

    def deserialize_ext_body(self, ext_body):
        self.selected_id, offset = pdu.unpack_uint16(ext_body, 0)
        return self


class ExtPskKeyExchangeMode(Extension):
    """Represents the psk_key_exchange_mode extension.

    Attributes:
        modes (list of :obj:`tlsmate.constants.PskKeyExchangeMode`): The list of
            the PSK key exchange modes to offer to the server.
    """

    extension_id = tls.Extension.PSK_KEY_EXCHANGE_MODES
    """:obj:`tlsmate.constants.Extension.PSK_KEY_EXCHANGE_MODES`
    """

    def __init__(self, **kwargs):
        self.modes = kwargs.get("modes")

    def serialize_ext_body(self, conn):
        ext_body = bytearray(pdu.pack_uint8(len(self.modes)))
        for mode in self.modes:
            ext_body.extend(pdu.pack_uint8(mode.value))
        return ext_body

    def deserialize_ext_body(self, ext_body):
        raise NotImplementedError


class ExtEarlyData(Extension):
    """Represents the EarlyData extension.
    """

    extension_id = tls.Extension.EARLY_DATA
    """:obj:`tlsmate.constants.Extension.EARLY_DATA`
    """

    def __init__(self, **kwargs):
        self.max_early_data_size = kwargs.get("max_early_data_size")

    def serialize_ext_body(self, conn):
        if self.max_early_data_size is None:
            return b""
        else:
            return bytes(pdu.pack_uint32(self.max_early_data_size))

    def deserialize_ext_body(self, ext_body):
        if ext_body:
            self.max_early_data_size, _ = pdu.unpack_uint32(ext_body, 0)
        return self


"""Map the extensions id to the corresponding class.
"""
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
    tls.Extension.SUPPORTED_GROUPS: ExtSupportedGroups,
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
    tls.Extension.PRE_SHARED_KEY: ExtPreSharedKey,
    tls.Extension.EARLY_DATA: ExtEarlyData,
    tls.Extension.SUPPORTED_VERSIONS: ExtSupportedVersions,
    # tls.Extension.COOKIE = 44
    # tls.Extension.PSK_KEY_EXCHANGE_MODES = 45
    # tls.Extension.CERTIFICATE_AUTHORITIES = 47
    # tls.Extension.OID_FILTERS = 48
    # tls.Extension.POST_HANDSHAKE_AUTH = 49
    # tls.Extension.SIGNATURE_ALGORITHMS_CERT = 50
    tls.Extension.KEY_SHARE: ExtKeyShare,
    # tls.Extension.TRANSPARENCY_INFO = 52
    # tls.Extension.CONNECTION_ID = 53
    # tls.Extension.EXTERNAL_ID_HASH = 55
    # tls.Extension.EXTERNAL_SESSION_ID = 56
    tls.Extension.RENEGOTIATION_INFO: ExtRenegotiationInfo,
}
