# -*- coding: utf-8 -*-
"""Module scanning for CBC padding vulnerabilities

We will scan for the following vaulnerabilities:

* POODLE
    Just check if SSLV3 is supported for CBC cipher suites

* TLS POODLE
    padding bytes not checked in TLS.
    vector: invert all padding bits
    fingerprint: server accepts record

* Lucky-Minus-20 (aka. OpenSSL Padding Oracle vuln.): CVE-2016-2107
    padding length spans the complete record, so that there is no "room" for the
    MAC and the data
    vector: no data, no mac, valid padding
    fingerprint: server responds with RECORD_OVERFLOW-Alert
    - https://web-in-security.blogspot.com/2016/05/curious-padding-oracle-in-openssl-cve.html  # noqa
    - https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/  # noqua

* other padding orcales, including
    * 0-length-Openssl vulnerability (CVE-2019-1559)
        vector: no data, invalid mac, valid padding
        fingerprint: Hm, according to
        https://www.usenix.org/system/files/sec19-merget.pdf, the typical behaviour
        is a timeout on the server (after sending two Alerts), but SSLLABS seems to
        consider any other distinguishable behavior as well.
    * Zombie-POODLE
        invalid padding bits
        vector: data (optional), valid mac, invalid padding bits
        fingerprint: server responds with ALERT and behaves differently than to a
        wrong MAC
    * GOLDENDOODLE
        invalid MAC bits
        vector: data(optional), invalid mac, valid padding
        fingerprint: server accepts the record
    * Sleeping POODLE
        In case the POODLE behaviour differs between the differen TLS record protocols
        (handshake, app data, alert)

    As it is not exactly defined which fingerprints are related to which vulnerability,
    we will following for any of those oracles:

        Report it as a POODLE-like oracle.
        Add a note, if it is a 0-length oracle
        Add a note, if the oracle is weak or strong
        Add a note, if the oracle is observable (exploitable) or not


    - https://web-in-security.blogspot.com/2016/05/curious-padding-oracle-in-openssl-cve.html  # noqa
    - https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/  # noqua

"""
# import basic stuff
from typing import NamedTuple, Callable
import enum
import logging

# import own stuff
from tlsmate import msg
from tlsmate import pdu
from tlsmate import tls
from tlsmate import utils
from tlsmate.exception import TlsConnectionClosedError
from tlsmate.plugin import WorkerPlugin
from tlsmate.server_profile import SPCbcPaddingOracle, SPCipherGroup

# import other stuff


class ResponseEvent(tls.ExtendedEnum):
    ALERT = enum.auto()
    MSG = enum.auto()
    TIMEOUT = enum.auto()
    TCP_CLOSE = enum.auto()
    TCP_RESET = enum.auto()


class ResponseFingerprint(object):
    def __init__(self, version, cipher_suite):
        self.events = []
        self.version = version
        self.cipher_suite = cipher_suite

    def add_event(self, event, data=None):
        self.events.append((event, data))

    def __eq__(self, other):
        return self.events == other.events

    def __ne__(self, other):
        return not self.__eq__(other)

    def visible_difference(self, other):
        if len(self.events) != len(other.events):
            return True
        return any(i[0] != j[0] for i, j in zip(self.events, other.events))

    def no_rejection(self, protocol):
        if protocol is tls.ContentType.HANDSHAKE:
            return self.events[0][0] is ResponseEvent.MSG

        elif protocol is tls.ContentType.ALERT:
            return self.events[0][0] is ResponseEvent.TIMEOUT

        else:
            return self.events[0][0] in (ResponseEvent.MSG, ResponseEvent.TIMEOUT)

    def __str__(self):
        parts = []
        for event, info in self.events:
            if event is ResponseEvent.ALERT:
                parts.append(f"A({info.value})")
            elif event is ResponseEvent.MSG:
                parts.append(f"M({info})")
            elif event is ResponseEvent.TIMEOUT:
                parts.append("T")
            elif event is ResponseEvent.TCP_CLOSE:
                parts.append("C")
            elif event is ResponseEvent.TCP_RESET:
                parts.append("R")
        return "".join(parts)


class CipherSuiteFingerprint(object):
    def __init__(self):
        self.strong = tls.SPBool.C_UNDETERMINED
        self.exploitable = tls.SPBool.C_UNDETERMINED
        self.oracle_types = []

    def __eq__(self, other):
        return self.get_fingerprint_id() == other.get_fingerprint_id()

    def __ne__(self, other):
        return not self.__eq__(other)

    def get_fingerprint_id(self):
        return hash((self.strong, self.exploitable, tuple(self.oracle_types)))


class RecordLayerCallbacks(NamedTuple):
    data: Callable
    hmac: Callable
    padding: Callable


# basic modifications


def raw_bytes(bytestring):
    def cb(data):
        return bytestring

    return cb


def xor_byte(pos, val):
    def cb(data):
        data[pos] = data[pos] ^ val
        return data

    return cb


def flip_all_bits():
    def cb(data):
        return bytes([x ^ 0xFF for x in data])

    return cb


# padding modifications


def padding_valid(length):
    def cb(padding):
        return pdu.pack_uint8(length - 1) * length

    return cb


def padding_flip_all_bits(block_size):
    def cb(padding):
        length = padding[-1]
        if length < block_size:
            length += block_size

        return pdu.pack_uint8(length ^ 0xFF) * length + pdu.pack_uint8(length)

    return cb


def padding_flip_msb(block_size):
    def cb(padding):
        length = padding[-1]
        if length == 0:
            length += block_size
            padding = bytearray(pdu.pack_uint8(length)) * (length + 1)

        padding[0] = padding[0] ^ 0x80
        return padding

    return cb


# definition of test vectors


def vector_valid_record(block_size, hmac_len):
    """Vector used to determine the response to a valid record as a reference."""

    return RecordLayerCallbacks(data=None, hmac=None, padding=None)


def vector_invalid_hmac(block_size, hmac_len):
    """Vector used to determine the invalid HMAC behaviour as a reference."""

    return RecordLayerCallbacks(data=None, hmac=flip_all_bits(), padding=None)


def vector_tls_poodle(block_size, hmac_len):
    """Vector to check for TLS POODLE.

    Data present, valid HMAC, all padding bits invalid
    """

    return RecordLayerCallbacks(
        data=None, hmac=None, padding=padding_flip_all_bits(block_size)
    )


def vector_6_padding_fills_record(block_size, hmac_len):
    """Padding length equal to record length

    Reference: https://www.usenix.org/system/files/sec19-merget.pdf,
    malformed record #6
    """

    return RecordLayerCallbacks(
        data=raw_bytes(b""), hmac=raw_bytes(b""), padding=raw_bytes(b"\x4f" * 80)
    )


def vector_7_padding_overflow(block_size, hmac_len):
    """Padding length exceeds record length

    Reference: https://www.usenix.org/system/files/sec19-merget.pdf,
    malformed record #7
    """

    return RecordLayerCallbacks(
        data=raw_bytes(b""), hmac=raw_bytes(b""), padding=raw_bytes(b"\xff" * 80)
    )


def vector_8_invalid_padding_bit(block_size, hmac_len):
    """No data, valid HMAC, first padding bit flipped

    Reference: https://www.usenix.org/system/files/sec19-merget.pdf,
    malformed record #8
    """

    pad_len = 80 - hmac_len
    pad_val = pad_len - 1
    padding = pdu.pack_uint8(pad_val ^ 0x80) + pdu.pack_uint8(pad_val) * pad_val

    return RecordLayerCallbacks(
        data=raw_bytes(b""), hmac=None, padding=raw_bytes(padding)
    )


def vector_11_no_data_invalid_hmac_msb(block_size, hmac_len):
    """No data, first bit of hmac flipped, valid padding

    Reference: https://www.usenix.org/system/files/sec19-merget.pdf,
    malformed record #11
    """

    return RecordLayerCallbacks(
        data=raw_bytes(b""),
        hmac=xor_byte(0, 0x80),
        padding=padding_valid(80 - hmac_len),
    )


def vector_17_invalid_short_padding_msb(block_size, hmac_len):
    """Data present, hmac valid, 6 bytes padding, first bit flipped

    Reference: https://www.usenix.org/system/files/sec19-merget.pdf,
    malformed record #17
    """

    return RecordLayerCallbacks(
        data=None, hmac=None, padding=padding_flip_msb(block_size)
    )


class ScanPaddingOracle(WorkerPlugin):
    name = "scan_padding_oracles"
    descr = "scan for CBC padding oracles"
    prio = 40

    def response_fingerprint(self, conn):

        fp = ResponseFingerprint(conn.version, conn.cipher_suite)
        done = False
        while not done:
            try:
                rec_msg = conn.wait(msg.Any, timeout=1000, fail_on_timeout=False)
                if rec_msg is None:
                    fp.add_event(ResponseEvent.TIMEOUT)
                    done = True

                else:
                    if isinstance(rec_msg, msg.Alert):
                        fp.add_event(ResponseEvent.ALERT, rec_msg.description)

                    else:
                        fp.add_event(ResponseEvent.MSG, rec_msg.msg_type)

            except TlsConnectionClosedError as exc:
                if exc.exc is None:
                    fp.add_event(ResponseEvent.TCP_CLOSE)

                else:
                    fp.add_event(ResponseEvent.TCP_RESET)

                done = True

        return fp

    def handshake_scenario(self, conn, vector):
        conn.send(msg.ClientHello)
        conn.wait(msg.ServerHello)
        conn.wait(msg.Certificate, optional=True)
        conn.wait(msg.ServerKeyExchange, optional=True)
        cert_req = conn.wait(msg.CertificateRequest, optional=True)
        conn.wait(msg.ServerHelloDone)
        if cert_req:
            conn.send(msg.Certificate)

        conn.send(msg.ClientKeyExchange)
        if cert_req:
            conn.send(msg.CertificateVerify)

        conn.send(msg.ChangeCipherSpec)

        callback = vector(
            conn.cs_details.cipher_struct.block_size, conn.cs_details.mac_struct.mac_len
        )
        conn.send(
            msg.Finished,
            data_cb=callback.data,
            hmac_cb=callback.hmac,
            padding_cb=callback.padding,
        )

    def app_data_scenario(self, conn, vector):
        conn.handshake()

        callback = vector(
            conn.cs_details.cipher_struct.block_size, conn.cs_details.mac_struct.mac_len
        )
        conn.send(
            msg.AppData(b" "),
            data_cb=callback.data,
            hmac_cb=callback.hmac,
            padding_cb=callback.padding,
        )

    def alert_scenario(self, conn, vector):
        conn.handshake()
        callback = vector(
            conn.cs_details.cipher_struct.block_size, conn.cs_details.mac_struct.mac_len
        )
        conn.send(
            msg.Alert(
                level=tls.AlertLevel.WARNING,
                description=tls.AlertDescription.CLOSE_NOTIFY,
            ),
            data_cb=callback.data,
            hmac_cb=callback.hmac,
            padding_cb=callback.padding,
        )

    def vector_fingerprint(self, protocol, vector):
        with self.client.create_connection() as conn:
            if protocol is tls.ContentType.HANDSHAKE:
                self.handshake_scenario(conn, vector)

            elif protocol is tls.ContentType.APPLICATION_DATA:
                self.app_data_scenario(conn, vector)

            elif protocol is tls.ContentType.ALERT:
                self.alert_scenario(conn, vector)

            return self.response_fingerprint(conn)
        return None

    def store_cs_fingerprint(self, fp, version, cipher_suite, protocol):
        fp_id = fp.get_fingerprint_id()
        if fp_id not in self.fingerprints:
            self.fingerprints[fp_id] = {"fp": fp, "entries": []}
        self.fingerprints[fp_id]["entries"].append((version, cipher_suite, protocol))

    def scan_record_protocol(self, protocol):

        cs_fp = CipherSuiteFingerprint()

        fps = [
            self.vector_fingerprint(protocol, vector)
            for vector in [
                vector_6_padding_fills_record,
                vector_7_padding_overflow,
                vector_8_invalid_padding_bit,
                vector_11_no_data_invalid_hmac_msb,
            ]
        ]
        (
            fp_6_padding_fills_record,
            fp_7_padding_overflow,
            fp_8_padding_invalid_padding_bit,
            fp_11_padding_no_data_invalid_hmac_msb,
        ) = fps
        logging.debug(f"fp_6_padding_fills_record {fp_6_padding_fills_record}")
        logging.debug(f"fp_7_padding_overflow {fp_7_padding_overflow}")
        logging.debug(
            f"fp_8_padding_invalid_padding_bit {fp_8_padding_invalid_padding_bit}"
        )
        logging.debug(
            f"fp_11_padding_no_data_invalid_hmac_msb "
            f"{fp_11_padding_no_data_invalid_hmac_msb}"
        )
        if not all(fps):
            return

        if not all(x == fps[0] for x in fps):
            fp_invalid_hmac = self.vector_fingerprint(protocol, vector_invalid_hmac)
            logging.debug(f"fp_invalid_hmac: {fp_invalid_hmac}")
            if not fp_invalid_hmac:
                return

            if (
                fp_6_padding_fills_record != fp_invalid_hmac
                and fp_6_padding_fills_record.events[0][1]
                is tls.AlertDescription.RECORD_OVERFLOW
            ):
                cs_fp.oracle_types.append(tls.SPCbcPaddingOracle.LUCKY_MINUS_20)

            else:
                if fp_6_padding_fills_record != fp_invalid_hmac:
                    cs_fp.oracle_types.append(
                        tls.SPCbcPaddingOracle.PADDING_EQUAL_RECORD
                    )

                if fp_7_padding_overflow != fp_invalid_hmac:
                    cs_fp.oracle_types.append(
                        tls.SPCbcPaddingOracle.PADDING_EXCEEDS_RECORD
                    )

            if fp_8_padding_invalid_padding_bit != fp_invalid_hmac:
                cs_fp.oracle_types.append(tls.SPCbcPaddingOracle.INVALID_PADDING)

            if fp_11_padding_no_data_invalid_hmac_msb != fp_invalid_hmac:
                cs_fp.oracle_types.append(tls.SPCbcPaddingOracle.INVALID_HMAC)

            cs_fp.exploitable = tls.SPBool(
                any(fp_invalid_hmac.visible_difference(fp) for fp in fps)
            )
            fp_17_invalid_short_padding_msb = self.vector_fingerprint(
                protocol, vector_17_invalid_short_padding_msb
            )
            logging.debug(
                f"fp_17_invalid_short_padding_msb {fp_17_invalid_short_padding_msb}"
            )
            if not fp_17_invalid_short_padding_msb:
                cs_fp.strong = tls.SPBool.C_UNDETERMINED
            else:
                cs_fp.strong = tls.SPBool(
                    fp_17_invalid_short_padding_msb != fp_invalid_hmac
                )

            self.store_cs_fingerprint(
                cs_fp, fp_invalid_hmac.version, fp_invalid_hmac.cipher_suite, protocol
            )

    def scan_cipher_suite(self):
        if self.all_protocols:
            self.scan_record_protocol(tls.ContentType.HANDSHAKE)
            self.scan_record_protocol(tls.ContentType.APPLICATION_DATA)
            self.scan_record_protocol(tls.ContentType.ALERT)

        else:
            self.scan_record_protocol(tls.ContentType.APPLICATION_DATA)

    def scan_version(self, values):
        if values.versions:
            cbc_ciphers = utils.filter_cipher_suites(
                values.cipher_suites, cipher_type=[tls.CipherType.BLOCK], full_hs=True,
            )
            if not cbc_ciphers:
                return

            self.client.init_profile(profile_values=values)
            if self.all_cs:
                for cipher in cbc_ciphers:
                    self.client.profile.cipher_suites = [cipher]
                    self.scan_cipher_suite()

            else:
                self.client.profile.cipher_suites = cbc_ciphers
                self.scan_cipher_suite()

    def determine_accuracy(self):
        accuracy = self.config.get("oracle_accuracy")
        if accuracy not in ["lowest", "low", "medium", "high"]:
            accuracy = "medium"
        if accuracy == "lowest":
            self.all_versions = True
            self.all_cs = False
            self.all_protocols = False
        elif accuracy == "low":
            self.all_versions = False
            self.all_cs = True
            self.all_protocols = False
        elif accuracy == "medium":
            self.all_versions = True
            self.all_cs = True
            self.all_protocols = False
        elif accuracy == "high":
            self.all_versions = True
            self.all_cs = True
            self.all_protocols = True

    def run(self):
        self.determine_accuracy()
        self.fingerprints = {}
        versions = [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12]
        if self.all_versions:
            for version in versions:
                values = self.server_profile.get_profile_values([version])
                self.scan_version(values)

        else:
            values = self.server_profile.get_profile_values(versions)
            self.scan_version(values)

        if self.fingerprints:
            oracles = []
            for entry in self.fingerprints.values():
                item = entry["fp"]
                sp_oracle = SPCbcPaddingOracle(
                    exploitable=item.exploitable, strong=item.strong
                )
                sp_oracle.types = item.oracle_types
                sp_oracle.cipher_group = [
                    SPCipherGroup(
                        version=version,
                        cipher_suite=cipher_suite,
                        record_protocol=protocol,
                    )
                    for version, cipher_suite, protocol in entry["entries"]
                ]
                oracles.append(sp_oracle)
            self.server_profile.vulnerabilities.cbc_padding_oracle = oracles
