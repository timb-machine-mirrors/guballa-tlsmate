# -*- coding: utf-8 -*-
"""Module containing a class for a binary protocol
"""
import struct
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls

class ProtocolData(bytearray):


    def unpack_uint8(self, offset):
        if offset >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return self[offset], offset + 1

    def unpack_uint16(self, offset):
        if offset + 1 >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return struct.unpack("!H", self[offset:offset+2])[0], offset + 2

    def unpack_uint24(self, offset):
        if offset + 2 >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        high_byte, val = struct.unpack("!BH", self[offset:offset+3])
        return 0x10000 * high_byte + val, offset + 3

    def unpack_bytes(self, offset, length):
        if offset + length > len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return ProtocolData(self[offset:offset+length]), offset + length


    def unshift_uint8(self):
        return struct.unpack("!B", self[:1])[0], ProtocolData(self[1:])

    def unshift_uint16(self):
        return struct.unpack("!H", self[:2])[0], ProtocolData(self[2:])

    def unshift_uint24(self):
        high_byte, val = struct.unpack("!BH", self[:3])
        return 0x10000 * high_byte + val, ProtocolData(self[3:])
        #return struct.unpack("!I", self[:3])[0], ProtocolData(self[3:])

    def append_uint8(self, *vals):
        for val in vals:
            if val > 0xff:
                raise ValueError("Cannot pack {} into 1 bytes".format(val))
            self.extend(struct.pack("!B", val))

    def append_uint16(self, *vals):
        for val in vals:
            if val > 0xffff:
                raise ValueError("Cannot pack {} into 2 bytes".format(val))
            self.extend(struct.pack("!H", val))

    def append_uint24(self, *vals):
        for val in vals:
            if val > 0xffffff:
                raise ValueError("Cannot pack {} into 3 bytes".format(val))
            self.extend(struct.pack("!I", val)[1:])

    def append_uint32(self, *vals):
        for val in vals:
            if val > 0xffffffff:
                raise ValueError("Cannot pack {} into 4 bytes".format(val))
            self.extend(struct.pack("!I", val))

    def append_str(self, *strings):
        for string in strings:
            self.extend(map(ord, string))

    def dump(self, bytes_per_row=16):
        rows = []
        for x in range(0, len(self), bytes_per_row):
            chunk = self[x:x+bytes_per_row]
            rows.append(" ".join("{:02x}".format(y) for y in chunk))
        return "\n".join(rows)
