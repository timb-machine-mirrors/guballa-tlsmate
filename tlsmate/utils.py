# -*- coding: utf-8 -*-
"""Module defining some utilities
"""
# import basic stuff
import time
import logging

# import own stuff
from tlsmate import tls
from tlsmate import mappings
from tlsmate import structs

# import other stuff


def get_cipher_suite_details(cipher_suite):
    """Get details for a given cipher suite

    Arguments:
        cipher_suite (:class:`tls.constants.CipherSuite`): The given cipher suite.

    Returns:
        :obj:`_CipherSuiteDetails`:
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
        cs_list (list of :class:`tlsmate.constants.CipherSuite`): A list of cipher
            suites to be filtered.
        key_algo (list of :class:`tlsmate.constants.KeyExchangeAlgorithm`): Optional
            match condition. If the key_algo (a combination of key_exch and key_auth,
            e.g. "DHE_RSA") of a cipher suite is in the given list, it is a match.
        key_exch (list of :class:`tlsmate.constants.KeyExchangeType`): Optional
            match condition. If the key_exch (e.g. "ECDH") of a cipher suite is in
            the given list, it is a match.
        key_auth (list of :class:`tlsmate.constants.KeyAuthentication`): Optional
            match condition. If the key_auth (e.g. "ECDSA") of a cipher suite is in
            the given list, it is a match.
        cipher_type (list of :class:`tlsmate.constants.CipherType`): Optional
            match condition. If the cipher_type (e.g. "STREAM") of a cipher suite
            is in the list, it is a match.
        cipher_prim (list of :class:`tlsmate.constants.CipherPrimitive`): Optional
            match condition. If the cipher_prim (e.g. "AES") of a cipher suite is in
            the given list, it is a match.
        cipher (list of :class:`tlsmate.constants.SymmetricCipher`): Optional
            match condition. If the cipher (e.g. "AES_256_CCM_8") of a cipher suite
            is in the given list, it is a match.
        mac (list of :class:`tlsmate.constants.HashPrimitive`): Optional match
            condition. If the mac (e.g. "SHA384") of a cipher suite is in the give
            list, it is a match.
        version (:class:`tlsmate.constants.Version`): Optional match condition.
            Cipher suites supported by the given TLS version are a match. This is
            rather rudimentarily implemented: AEAD ciphers only for TLS1.2, specific
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
        list of :class:`tlsmate.constants.CipherSuite`:
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
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


def set_logging(level):
    """Sets the logging level

    Arguments:
        level (str): The logging level to use.
    """
    if level is not None:
        logging.basicConfig(level=level.upper(), format="%(levelname)s: %(message)s")


class Log(object):
    """A class which implements relative timestamps.
    """

    start_time = None

    @classmethod
    def time(cls):
        """returns a timestamp relative to the time of the first call to this method.

        Returns:
            str: the time in seconds with 3 positions after the decimal point.
        """
        timestamp = time.time()
        if cls.start_time is None:
            cls.start_time = timestamp
        diff = timestamp - cls.start_time
        return f"Timestamp {diff:.3f}"
