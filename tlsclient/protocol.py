# -*- coding: utf-8 -*-
"""Module containing a class for a binary protocol
"""
import struct

class ProtocolData(bytearray):

    def append_uint2(self, *vals):
        for val in vals:
            self.extend(struct.pack("!H", val))
