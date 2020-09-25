# -*- coding: utf-8 -*-
"""Module containing a class for a binary protocol
"""
import struct
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls


class ProtocolData(bytearray):
    def __str__(self):
        return self.dump()

    def unpack_uint8(self, offset):
        if offset >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return self[offset], offset + 1

    def unpack_uint16(self, offset):
        if offset + 1 >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return struct.unpack("!H", self[offset : offset + 2])[0], offset + 2

    def unpack_uint24(self, offset):
        if offset + 2 >= len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        high_byte, val = struct.unpack("!BH", self[offset : offset + 3])
        return 0x10000 * high_byte + val, offset + 3

    def unpack_bytes(self, offset, length):
        if offset + length > len(self):
            raise FatalAlert("Message length error", tls.AlertDescription.DECODE_ERROR)
        return ProtocolData(self[offset : offset + length]), offset + length

    def append_uint8(self, *vals):
        for val in vals:
            if val > 0xFF:
                raise ValueError("Cannot pack {} into 1 bytes".format(val))
            self.extend(struct.pack("!B", val))

    def append_uint16(self, *vals):
        for val in vals:
            if val > 0xFFFF:
                raise ValueError("Cannot pack {} into 2 bytes".format(val))
            self.extend(struct.pack("!H", val))

    def append_uint24(self, *vals):
        for val in vals:
            if val > 0xFFFFFF:
                raise ValueError("Cannot pack {} into 3 bytes".format(val))
            self.extend(struct.pack("!I", val)[1:])

    def append_uint32(self, *vals):
        for val in vals:
            if val > 0xFFFFFFFF:
                raise ValueError("Cannot pack {} into 4 bytes".format(val))
            self.extend(struct.pack("!I", val))

    def append_uint64(self, *vals):
        for val in vals:
            if val > 0xFFFFFFFFFFFFFFFF:
                raise ValueError("Cannot pack {} into 8 bytes".format(val))
            self.extend(struct.pack("!Q", val))

    def append_str(self, *strings):
        for string in strings:
            self.extend(map(ord, string))

    def dump(self, bytes_per_row=0):
        if not len(self):
            return ""
        if bytes_per_row == 0:
            bytes_per_row = len(self)
        rows = []
        for x in range(0, len(self), bytes_per_row):
            chunk = self[x : x + bytes_per_row]
            rows.append(" ".join("{:02x}".format(y) for y in chunk))
        return "\n".join(rows) + " ({})".format(len(self))
