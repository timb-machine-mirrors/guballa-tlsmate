# -*- coding: utf-8 -*-
"""Module impleminting helper functions for handling protocol data units
"""
import struct
from tlsmate.exception import FatalAlert
import tlsmate.constants as tls


def pack_uint8(val):
    """Packs a uint8 value into a byte object.

    Arguments:
        val (int): The value to pack.

    Returns:
        bytes: The bytes object representing the value in network order (big endian).

    Raises:
        ValueError: If the value cannot be respresented in one byte.
    """
    if val > 0xFF:
        raise ValueError(f"Cannot pack {val} into 1 byte")
    return struct.pack("!B", val)


def pack_uint16(val):
    """Packs a uint16 value into a byte object.

    Arguments:
        val (int): The value to pack.

    Returns:
        bytes: The bytes object representing the value in network order (big endian).

    Raises:
        ValueError: If the value cannot be respresented in two bytes.
    """
    if val > 0xFFFF:
        raise ValueError(f"Cannot pack {val} into 2 bytes")
    return struct.pack("!H", val)


def pack_uint24(val):
    """Packs a uint24 value into a byte object.

    Arguments:
        val (int): The value to pack.

    Returns:
        bytes: The bytes object representing the value in network order (big endian).

    Raises:
        ValueError: If the value cannot be respresented in three bytes.
    """
    if val > 0xFFFFFF:
        raise ValueError(f"Cannot pack {val} into 3 bytes")
    return struct.pack("!I", val)[1:]


def pack_uint32(val):
    """Packs a uint32 value into a byte object.

    Arguments:
        val (int): The value to pack.

    Returns:
        bytes: The bytes object representing the value in network order (big endian).

    Raises:
        ValueError: If the value cannot be respresented in four bytes.
    """
    if val > 0xFFFFFFFF:
        raise ValueError(f"Cannot pack {val} into 4 bytes")
    return struct.pack("!I", val)


def pack_uint64(val):
    """Packs a uint64 value into a byte object.

    Arguments:
        val (int): The value to pack.

    Returns:
        bytes: The bytes object representing the value in network order (big endian).

    Raises:
        ValueError: If the value cannot be respresented in eight bytes.
    """
    if val > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Cannot pack {val} into 8 bytes")
    return struct.pack("!Q", val)


def pack_str(string):
    """Packs a string into a byte object.

    Arguments:
        string (str): The string to pack.

    Returns:
        bytes: The bytes object representing the string in network order (big endian).
    """
    return bytes(map(ord, string))


def unpack_uint8(data, offset):
    """Unpacks a value from a given an buffer.

    Arguments:
        data (bytes): The buffer to unpack from.
        offset (int): The offset within the buffer.

    Returns:
        value, offset: The tuple with the result. The first entry is the value that
        has been unpacked, the second one is the new offset in the buffer, i.e. it
        points to the next byte after the unpacked value.

    Raises:
        :obj:`tlsmate.exception.FatalAlert`: If the buffer boundary is exceeded.
    """
    if offset >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint8",
            tls.AlertDescription.DECODE_ERROR,
        )
    return data[offset], offset + 1


def unpack_uint16(data, offset):
    """Unpacks a value from a given an buffer.

    Arguments:
        data (bytes): The buffer to unpack from.
        offset (int): The offset within the buffer.

    Returns:
        value, offset: The tuple with the result. The first entry is the value that
        has been unpacked, the second one is the new offset in the buffer, i.e. it
        points to the next byte after the unpacked value.

    Raises:
        :obj:`tlsmate.exception.FatalAlert`: If the buffer boundary is exceeded.
    """
    if offset + 1 >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint16",
            tls.AlertDescription.DECODE_ERROR,
        )
    return struct.unpack("!H", data[offset : offset + 2])[0], offset + 2


def unpack_uint24(data, offset):
    """Unpacks a value from a given an buffer.

    Arguments:
        data (bytes): The buffer to unpack from.
        offset (int): The offset within the buffer.

    Returns:
        value, offset: The tuple with the result. The first entry is the value that
        has been unpacked, the second one is the new offset in the buffer, i.e. it
        points to the next byte after the unpacked value.

    Raises:
        :obj:`tlsmate.exception.FatalAlert`: If the buffer boundary is exceeded.
    """
    if offset + 2 >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint24",
            tls.AlertDescription.DECODE_ERROR,
        )
    high_byte, val = struct.unpack("!BH", data[offset : offset + 3])
    return 0x10000 * high_byte + val, offset + 3


def unpack_uint32(data, offset):
    """Unpacks a value from a given an buffer.

    Arguments:
        data (bytes): The buffer to unpack from.
        offset (int): The offset within the buffer.

    Returns:
        value, offset: The tuple with the result. The first entry is the value that
        has been unpacked, the second one is the new offset in the buffer, i.e. it
        points to the next byte after the unpacked value.

    Raises:
        :obj:`tlsmate.exception.FatalAlert`: If the buffer boundary is exceeded.
    """
    if offset + 3 >= len(data):
        raise FatalAlert(
            "Message length error when unpacking uint32",
            tls.AlertDescription.DECODE_ERROR,
        )
    return struct.unpack("!I", data[offset : offset + 4])[0], offset + 4


def unpack_bytes(data, offset, length):
    """Unpacks a given number of bytes from a given an buffer.

    Arguments:
        data (bytes): The buffer to unpack from.
        offset (int): The offset within the buffer.
        length (int): The number of bytes to unpack.

    Returns:
        value, offset: The tuple with the result. The first entry is the value that
        has been unpacked, the second one is the new offset in the buffer, i.e. it
        points to the next byte after the unpacked value.

    Raises:
        :obj:`tlsmate.exception.FatalAlert`: If the buffer boundary is exceeded.
    """
    if offset + length > len(data):
        raise FatalAlert(
            "Message length error when unpacking bytes",
            tls.AlertDescription.DECODE_ERROR,
        )
    return data[offset : offset + length], offset + length


def dump(data, separator=" ", with_length=True):
    """Provide a human readable representation of a bytes object.

    Arguments:
        data (bytes): The data to represent
        separator (str): the separator character(s) between the bytes. Defaults to " ".
        with_length (bool): indication, if the length shall be appended in brackets.

    Returns:
        str: A human readable string, with a blank between each byte, and the
        length of the string appended in brackets.
    """
    ret = separator.join(f"{y:02x}" for y in data)
    if with_length:
        ret = ret + f" ({len(data)})"
    return ret


def string(data):
    return dump(data, separator=":", with_length=False)
