# -*- coding: utf-8 -*-
"""Module impleminting helper functions for handling protocol data units
"""
import struct
from tlsclient.alert import FatalAlert
import tlsclient.constants as tls


def pack_uint8(val):
    if val > 0xFF:
        raise ValueError(f"Cannot pack {val} into 1 byte")
    return struct.pack("!B", val)

def pack_uint16(val):
    if val > 0xFFFF:
        raise ValueError(f"Cannot pack {val} into 2 bytes")
    return struct.pack("!H", val)

def pack_uint24(val):
    if val > 0xFFFFFF:
        raise ValueError(f"Cannot pack {val} into 3 bytes")
    return struct.pack("!I", val)[1:]

def pack_uint32(val):
    if val > 0xFFFFFFFF:
        raise ValueError(f"Cannot pack {val} into 4 bytes")
    return struct.pack("!I", val)

def pack_uint64(val):
    if val > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Cannot pack {val} into 8 bytes")
    return struct.pack("!Q", val)

def pack_str(string):
    return bytes(map(ord, string))

def unpack_uint8(data, offset):
    if offset >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint8",
            tls.AlertDescription.DECODE_ERROR,
        )
    return data[offset], offset + 1

def unpack_uint16(data, offset):
    if offset + 1 >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint16",
            tls.AlertDescription.DECODE_ERROR,
        )
    return struct.unpack("!H", data[offset : offset + 2])[0], offset + 2

def unpack_uint24(data, offset):
    if offset + 2 >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint24",
            tls.AlertDescription.DECODE_ERROR,
        )
    high_byte, val = struct.unpack("!BH", data[offset : offset + 3])
    return 0x10000 * high_byte + val, offset + 3

def unpack_uint32(data, offset):
    if offset + 3 >= len(self):
        raise FatalAlert(
            "Message length error when unpacking uint32",
            tls.AlertDescription.DECODE_ERROR,
        )
    return struct.unpack("!I", data[offset : offset + 4])[0], offset + 4

def unpack_bytes(data, offset, length):
    if offset + length > len(data):
        raise FatalAlert(
            "Message length error when unpacking bytes",
            tls.AlertDescription.DECODE_ERROR,
        )
    return data[offset : offset + length], offset + length

def dump(data):
    return (" ".join(f"{y:02x}" for y in data) + f" ({len(data)})")
