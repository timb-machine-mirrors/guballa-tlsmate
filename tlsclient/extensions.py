# -*- coding: utf-8 -*-
"""Module containing the TLS Extension classes
"""

import abc
from tlsclient.protocol import ProtocolData
import tlsclient.constants as tls

class Extension(metaclass=abc.ABCMeta):

    def serialize_body(self):
        raise NotImplementedError("class {} does not implement method serialize_ext_body".format(type(self).__name__))

    def serialize(self):
        ext = ProtocolData()
        ext_body = self.serialize_ext_body()
        ext.append_uint16(self.extension_id.value)
        ext.append_uint16(len(ext_body))
        ext.extend(ext_body)
        return ext

class ExtServerNameIndication(Extension):

    extension_id = tls.Extension.SERVER_NAME

    def __init__(self, **kwargs):
        self.host_name = kwargs.get("host_name", "")

    def serialize_ext_body(self):
        # we only support exacly one list element: host_name
        ext = ProtocolData()
        ext.append_uint8(0) # host_name
        ext.append_uint16(len(self.host_name))
        ext.append_str(self.host_name)
        name_list = ProtocolData()
        name_list.append_uint16(len(ext))
        name_list.extend(ext)
        return name_list

class ExtExtendedMasterSecret(Extension):

    extension_id = tls.Extension.EXTENDED_MASTER_SECRET

    def serialize_ext_body(self):
        return ProtocolData()


class ExtRenegotiationInfo(Extension):

    extension_id = tls.Extension.RENEGOTIATION_INFO

    def __init__(self, **kwargs):
        self.opaque = kwargs.get("opaque", b"\0")

    def serialize_ext_body(self):
        return self.opaque


class ExtEcPointFormats(Extension):

    extension_id = tls.Extension.EC_POINT_FORMATS

    def __init__(self, **kwargs):
        self.point_formats = kwargs.get("point_formats", [tls.EcPointFormat.UNCOMPRESSED])

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
                pass # TODO
        ext_body = ProtocolData()
        ext_body.append_uint16(len(algo_list))
        ext_body.extend(algo_list)
        return ext_body

