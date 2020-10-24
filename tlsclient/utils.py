# -*- coding: utf-8 -*-
"""Module defining some utilities
"""
from typing import NamedTuple
import tlsclient.constants as tls
from tlsclient import mappings


class _CipherSuiteDetails(NamedTuple):
    """Structure which provides details for a cipher suite.
    """

    cipher_suite: tls.CipherSuite
    full_hs: bool = False
    key_exchange_supported: bool = False
    key_algo: tls.KeyExchangeAlgorithm = None
    key_exch: tls.KeyExchangeType = None
    key_auth: tls.KeyAuthentication = None
    cipher_type: tls.CipherType = None
    cipher_prim: tls.CipherPrimitive = None
    cipher: tls.SymmetricCipher = None
    cipher_mode: tls.SymmetricCipherMode = None
    mac: tls.HashPrimitive = None


def _get_cipher_suite_details(cipher_suite):
    """Get details for a given cipher suite

    Arguments:
        cipher_suite (:class:`tls.constants.CipherSuite`): The given cipher suite.

    Returns:
        :obj:`_CipherSuiteDetails`:
        The structure with the detailed info regarding the given cipher suite.
    """
    cs = mappings.supported_cipher_suites.get(cipher_suite)
    if cs is None:
        return _CipherSuiteDetails(cipher_suite=cipher_suite)
    ciph = mappings.supported_ciphers[cs.cipher]
    key = mappings.key_exchange.get(cs.key_ex)
    if key is not None:
        key_ex_type = key.key_ex_type
        key_auth = key.key_auth
        key_ex_supp = key.key_ex_supported
    else:
        key_ex_type = None
        key_auth = None
        key_ex_supp = None

    return _CipherSuiteDetails(
        cipher_suite=cipher_suite,
        full_hs=(key_ex_supp and ciph.cipher_supported),
        key_exchange_supported=key_ex_supp,
        key_algo=cs.key_ex,
        key_exch=key_ex_type,
        key_auth=key_auth,
        cipher_type=ciph.c_type,
        cipher_prim=ciph.primitive,
        cipher=cs.cipher,
        mac=cs.mac,
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
        cs_list (list of :class:`tlsclient.constants.CipherSuite`): A list of cipher
            suites to be filtered.
        key_exch (list of :class:`tlsclient.constants.KeyExchangeType`): Optional
            match condition. If the key_exch (e.g. "ECDH") of a cipher suite is in
            the given list, it is a match.
        key_auth (list of :class:`tlsclient.constants.KeyAuthentication`): Optional
            match condition. If the key_auth (e.g. "ECDSA") of a cipher suite is in
            the given list, it is a match.
        key_algo (list of :class:`tlsclient.constants.KeyExchangeAlgorithm`): Optional
            match condition. If the key_algo (a combination of key_exch and key_auth,
            e.g. "DHE_RSA") of a cipher suite is in the given list, it is a match.
        cipher_type (list of :class:`tlsclient.constants.CipherType`): Optional
            match condition. If the cipher_type (e.g. "STREAM") of a cipher suite
            is in the list, it is a match.
        cipher_prim (list of :class:`tlsclient.constants.CipherPrimitive`): Optional
            match condition. If the cipher_prim (e.g. "AES") of a cipher suite is in
            the given list, it is a match.
        cipher (list of :class:`tlsclient.constants.SymmetricCipher`): Optional
            match condition. If the cipher (e.g. "AES_256_CCM_8") of a cipher suite
            is in the given list, it is a match.
        cipher_mode (list of :class:`tlsclient.constants.SymmetricCipherMode`): Optional
            match condition. If the cipher_mode (e.g. "GCM") of a cipher suite is in
            the given list, it is a match.
        mac (list of :class:`tlsclient.constants.HashPrimitive`): Optional match
            condition. If the mac (e.g. "SHA384") of a cipher suite is in the give
            list, it is a match.
        version (:class:`tlsclient.constants.Version`): Optional match condition.
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
        list of :class:`tlsclient.constants.CipherSuite`:
        The list of cipher suites that match all the given conditions.
    """

    filter_funcs = []
    if key_algo is not None:
        filter_funcs.append(lambda cs: cs.key_algo in key_algo)
    if key_exch is not None:
        filter_funcs.append(lambda cs: cs.key_exch in key_exch)
    if key_auth is not None:
        filter_funcs.append(lambda cs: cs.key_auth in key_auth)
    if cipher_type is not None:
        filter_funcs.append(lambda cs: cs.cipher_type in cipher_type)
    if cipher_prim is not None:
        filter_funcs.append(lambda cs: cs.cipher_prim in cipher_prim)
    if cipher is not None:
        filter_funcs.append(lambda cs: cs.cipher in cipher)
    if cipher_mode is not None:
        filter_funcs.append(lambda cs: cs.cipher_mode in cipher_mode)
    if mac is not None:
        filter_funcs.append(lambda cs: cs.mac in mac)
    if version in [tls.Version.SSL30, tls.Version.TLS10, tls.Version.TLS11]:
        filter_funcs.append(
            lambda cs: cs.key_algo is not tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE
            and cs.cipher_type is not tls.CipherType.AEAD
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

    filtered = []
    for cs in cs_list:
        cs_details = _get_cipher_suite_details(cs)
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
