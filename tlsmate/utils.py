# -*- coding: utf-8 -*-
"""Module defining some utilities
"""
# import basic stuff
import time
import logging
import json
import os
import sys
import argparse

# import own stuff
from tlsmate import tls
from tlsmate import mappings
from tlsmate import structs
from tlsmate import pdu

# import other stuff
import yaml
import pathlib


class BooleanOptionalAction(argparse.Action):
    """Class to support --flag and --no-flag arguments.

    Will be natively supported by Python3.9
    """

    def __init__(
        self,
        option_strings,
        dest,
        default=None,
        type=None,
        choices=None,
        required=False,
        help=None,
        metavar=None,
    ):

        _option_strings = []
        for option_string in option_strings:
            _option_strings.append(option_string)

            if option_string.startswith("--"):
                option_string = "--no-" + option_string[2:]
                _option_strings.append(option_string)

        if help is not None and default is not None:
            help += f" (default: {default})"

        super().__init__(
            option_strings=_option_strings,
            dest=dest,
            nargs=0,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            setattr(namespace, self.dest, not option_string.startswith("--no-"))

    def format_usage(self):
        return " | ".join(self.option_strings)


def serialize_data(data, file_name=None, replace=True, use_json=False, indent=4):
    """Serialize the data object to JSON or yaml.

    Arguments:
        data: the serializable data structure
        file_name (str or :obj:`pathlib.Path`): the file to write the serialized
            data to. If not given, the serialized object is printed on STDOUT.
        replace (bool): If True, allow overwriting an existing file. Defaults to True.
            This argument is only evaluated if a file_name is given.
        json (bool): If True, use JSON, else use Yaml.
        indent (int): The indentation to apply.
    """

    if file_name is not None:
        if not replace and pathlib.Path(file_name).exists():
            form = "JSON" if use_json else "Yaml"
            print(f"File {file_name} existing. {form}-file not generated")
            return

        with open(file_name, "w") as fd:
            if use_json:
                json.dump(data, fd, indent=indent, sort_keys=True)

            else:
                yaml.dump(data, fd, indent=indent)
    else:
        if use_json:
            print(json.dumps(data, indent=indent, sort_keys=True))

        else:
            print(yaml.dump(data, indent=indent))


def deserialize_data(file_name):
    """Deserialize from a JSON- or Yaml-file.

    Arguments:
        file_name (str or :obj:`pathlib.Path`): the full file name

    Returns:
        object: the deserialized object
    """

    with open(file_name) as fd:
        return yaml.safe_load(fd)


def fold_string(text, max_length, sep=" "):
    """Splits a string into lines of the given length.

    Arguments:
        text (str): the string to split
        length (int): the maximum length of the line
        sep (str): the separator where splitting the text is allowed

    Returns:
        list: the list of strings
    """

    ret_lines = []
    tokens = []
    length = 0
    sep_len = len(sep)

    for token in text.split(sep):
        token_len = len(token)
        if length + token_len + sep_len > max_length:
            if tokens:
                ret_lines.append(sep.join(tokens) + sep)
                tokens = [token]
                length = token_len

            else:
                ret_lines.append(token + sep)
                tokens = []
                length = 0

        else:
            tokens.append(token)
            length += token_len + sep_len

    if tokens:
        ret_lines.append(sep.join(tokens))

    return ret_lines


def get_cipher_suite_details(cipher_suite):
    """Get details for a given cipher suite

    Arguments:
        cipher_suite (:class:`tlsmate.tls.CipherSuite`): The given cipher suite.

    Returns:
        :obj:`tlsmate.structs.CipherSuiteDetails`:
        The structure with the detailed info regarding the given cipher suite.
    """

    cs = mappings.supported_cipher_suites.get(cipher_suite)
    if cs is None:
        return None

    ciph = mappings.supported_ciphers[cs.cipher]
    key = mappings.key_exchange.get(cs.key_ex)
    if key is not None:
        key_ex_supp = key.key_ex_supported

    else:
        key_ex_supp = False

    mac_struct = mappings.supported_macs.get(cs.mac)

    return structs.CipherSuiteDetails(
        cipher_suite=cipher_suite,
        full_hs=(key_ex_supp and ciph.cipher_supported),
        key_exchange_supported=key_ex_supp,
        key_algo=cs.key_ex,
        key_algo_struct=key,
        cipher=cs.cipher,
        cipher_struct=ciph,
        mac=cs.mac,
        mac_struct=mac_struct,
    )


def filter_cipher_suites(
    cs_list,
    key_exch=None,
    key_auth=None,
    key_algo=None,
    cipher_type=None,
    cipher_prim=None,
    cipher=None,
    cipher_mode=None,
    mac=None,
    version=None,
    full_hs=None,
    key_exchange_supported=None,
    remove=False,
):
    """Filters a list of cipher suites.

    Various match conditions can be specified. A cipher suite is filtered, if all
    given conditions match (AND-logic). All filtered cipher suites are returned in
    a list.

    Arguments:
        cs_list (list of :class:`tlsmate.tls.CipherSuite`): A list of cipher
            suites to be filtered.
        key_algo (list of :class:`tlsmate.tls.KeyExchangeAlgorithm`): Optional
            match condition. If the key_algo (a combination of key_exch and key_auth,
            e.g. "DHE_RSA") of a cipher suite is in the given list, it is a match.
        key_exch (list of :class:`tlsmate.tls.KeyExchangeType`): Optional
            match condition. If the key_exch (e.g. "ECDH") of a cipher suite is in
            the given list, it is a match.
        key_auth (list of :class:`tlsmate.tls.KeyAuthentication`): Optional
            match condition. If the key_auth (e.g. "ECDSA") of a cipher suite is in
            the given list, it is a match.
        cipher_type (list of :class:`tlsmate.tls.CipherType`): Optional
            match condition. If the cipher_type (e.g. "STREAM") of a cipher suite
            is in the list, it is a match.
        cipher_prim (list of :class:`tlsmate.tls.CipherPrimitive`): Optional
            match condition. If the cipher_prim (e.g. "AES") of a cipher suite is in
            the given list, it is a match.
        cipher (list of :class:`tlsmate.tls.SymmetricCipher`): Optional
            match condition. If the cipher (e.g. "AES_256_CCM_8") of a cipher suite
            is in the given list, it is a match.
        mac (list of :class:`tlsmate.tls.HashPrimitive`): Optional match
            condition. If the mac (e.g. "SHA384") of a cipher suite is in the give
            list, it is a match.
        version (:class:`tlsmate.tls.Version`): Optional match condition.
            Cipher suites supported by the given TLS version are a match. This is
            rather rudimentary implemented: AEAD ciphers only for TLS1.2, specific
            ciphers only for TLS1.3.
        full_hs (bool): Optional match condition. If the implementation supports a
            full handshake with a cipher suite, i.e. an encrypted connection can
            successfully established, it is a match. It means the key exchange,
            the symmetric cipher and the hash primitive are all supported.
        key_exchange_supported (bool): Optional match condition. If the key exchange
            for a cipher suite is supported, it is a match. Note, that this does not
            mean that the symmetric cipher is supported as well.
        remove (bool): An indication if the filtered cipher suites shall be removed
            from the original list of cipher suites. Defaults to False.

    Returns:
        list of :class:`tlsmate.tls.CipherSuite`:
        The list of cipher suites that match all the given conditions.
    """

    filter_funcs = []
    if key_algo is not None:
        filter_funcs.append(lambda cs: cs.key_algo in key_algo)

    if key_exch is not None:
        filter_funcs.append(
            lambda cs: getattr(cs.key_algo_struct, "key_ex_type", None) in key_exch
        )

    if key_auth is not None:
        filter_funcs.append(
            lambda cs: getattr(cs.key_algo_struct, "key_auth", None) in key_auth
        )

    if cipher_type is not None:
        filter_funcs.append(
            lambda cs: getattr(cs.cipher_struct, "c_type", None) in cipher_type
        )

    if cipher_prim is not None:
        filter_funcs.append(
            lambda cs: getattr(cs.cipher_struct, "primitive", None) in cipher_prim
        )

    if cipher is not None:
        filter_funcs.append(lambda cs: cs.cipher in cipher)

    if mac is not None:
        filter_funcs.append(lambda cs: cs.mac in mac)

    if version in [tls.Version.SSL30, tls.Version.TLS10, tls.Version.TLS11]:
        filter_funcs.append(
            lambda cs: cs.key_algo is not tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE
            and (
                cs.cipher_struct is None
                or cs.cipher_struct.c_type is not tls.CipherType.AEAD
            )
        )

    if version is tls.Version.TLS12:
        filter_funcs.append(
            lambda cs: cs.key_algo is not tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE
        )

    if version is tls.Version.TLS13:
        filter_funcs.append(
            lambda cs: cs.key_algo is tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE
        )

    if full_hs is not None:
        filter_funcs.append(lambda cs: cs.full_hs is full_hs)

    if key_exchange_supported is not None:
        filter_funcs.append(
            lambda cs: cs.key_exchange_supported is key_exchange_supported
        )

    if tls.CipherSuite.TLS_FALLBACK_SCSV in cs_list:
        cs_list.remove(tls.CipherSuite.TLS_FALLBACK_SCSV)

    if tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in cs_list:
        cs_list.remove(tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)

    filtered = []
    for cs in cs_list:
        cs_details = get_cipher_suite_details(cs)
        if cs_details is None:
            continue

        match = True
        for filt_func in filter_funcs:
            if not filt_func(cs_details):
                match = False
                break

        if match:
            filtered.append(cs)

    if remove:
        for cs in filtered:
            cs_list.remove(cs)

    return filtered


def int_to_bytes(number):
    """Convert an integer to a byte string

    Arguments:
        number (int): the integer to convert

    Returns:
        bytes: just as many bytes as needed to represent the integer as an octet string
    """

    if number:
        return number.to_bytes((number.bit_length() + 7) // 8, "big")

    else:
        return b"\0"


def set_logging_format():
    """Initializes the format of log messages
    """

    logging.basicConfig(format="%(levelname)s: %(message)s")


def set_logging_level(level):
    """Sets the logging level

    Arguments:
        level (str): The logging level to use.
    """

    logging.getLogger().setLevel(level.upper())


class Log(object):
    """A class which implements relative time stamps.
    """

    start_time = None

    @classmethod
    def time(cls):
        """returns a time stamp relative to the time of the first call to this method.

        Returns:
            str: the time in seconds with 3 positions after the decimal point.
        """

        timestamp = time.time()
        if cls.start_time is None:
            cls.start_time = timestamp

        diff = timestamp - cls.start_time
        return f"Timestamp {diff:.3f}"


class Table(object):
    """Helper class for printing text in a table

    Attributes:
        indent (int): the indentation level, i.e. how many blanks shall be added
            on the left side of the table
        sep (str): the separator to print between adjacent columns within a row
    """

    def __init__(self, indent=0, sep=": "):
        self._indent = indent
        self._sep = sep
        self._nbr_columns = 0
        self._rows = []

    def row(self, *args):
        """Register a row

        Arguments:
            args (str): a complete row, one string for each column
        """
        self._nbr_columns = max(self._nbr_columns, len(args))
        cols = [col if type(col) is tuple else (col, len(col)) for col in args]
        self._rows.append(cols)

    def dump(self):
        """Print the table
        """

        if not self._nbr_columns:
            return

        cols = [1] * self._nbr_columns
        for row in self._rows:
            for idx, col in enumerate(row):
                cols[idx] = max(cols[idx], col[1])

        cols[-1] = 1
        for row in self._rows:
            print(" " * self._indent, end="")
            print(
                self._sep.join(
                    [
                        f"{col[0]:{cols[idx] + len(col[0]) - col[1]}}"
                        for idx, col in enumerate(row)
                    ]
                )
            )


def get_random_value():
    """Get a value suitable for a ClientHello or ServerHello

    Returns:
        bytes: 32 bytes of almost random data
    """

    random = bytearray()
    random.extend(pdu.pack_uint32(int(time.time())))
    random.extend(os.urandom(28))
    return random


def log_extensions(extensions):
    """Log extensions

    Arguments:
        extensions: the list of extensions to iterate over
    """

    for extension in extensions:
        extension = extension.extension_id
        logging.debug(f"extension {extension.value} {extension}")


def exit_with_error(error):
    """Abort tlsmate with an error message

    Arguments:
        error (str): the error message to print on stderr
    """

    sys.stderr.write(f"Error: {error}\n")
    sys.stderr.flush()
    sys.exit(1)
