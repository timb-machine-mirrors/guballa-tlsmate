# -*- coding: utf-8 -*-
"""Module containing a class for a binary protocol
"""
import struct

class ProtocolData(bytearray):

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
