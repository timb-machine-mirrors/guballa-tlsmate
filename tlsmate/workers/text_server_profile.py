# -*- coding: utf-8 -*-
"""Module for a worker handling the server profile (de)serialization
"""
# import basic stuff

# import own stuff

from tlsmate.plugin import WorkerPlugin
from tlsmate import tls
from tlsmate import utils
from tlsmate import pdu
from tlsmate.version import __version__

# import other stuff
from colorama import init, Fore, Style


class Mood(object):
    GOOD = Fore.GREEN
    NEUTRAL = ""
    SOSO = Fore.YELLOW + Style.BRIGHT
    BAD = Fore.RED
    HEADLINE = Fore.MAGENTA + Style.BRIGHT
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL


def apply_mood(txt, mood):
    if mood == "":
        return str(txt)

    return mood + str(txt) + Mood.RESET


def merge_moods(moods):
    for mood in [Mood.BAD, Mood.SOSO, Mood.NEUTRAL, Mood.GOOD]:
        if mood in moods:
            return mood

    raise ValueError("cannot merge moods")


def get_cert_ext(cert, name):
    if not hasattr(cert, "extensions"):
        return None

    for ext in cert.extensions:
        if ext.name == name:
            return ext

    return None


_versions = {
    tls.Version.SSL20: (Mood.GOOD, Mood.BAD),
    tls.Version.SSL30: (Mood.GOOD, Mood.BAD),
    tls.Version.TLS10: (Mood.NEUTRAL, Mood.SOSO),
    tls.Version.TLS11: (Mood.NEUTRAL, Mood.SOSO),
    tls.Version.TLS12: (Mood.NEUTRAL, Mood.GOOD),
    tls.Version.TLS13: (Mood.NEUTRAL, Mood.GOOD),
}

_cipher_order = {
    tls.Version.SSL20: (Mood.BAD, Mood.GOOD),
    tls.Version.SSL30: (Mood.BAD, Mood.GOOD),
    tls.Version.TLS10: (Mood.BAD, Mood.GOOD),
    tls.Version.TLS11: (Mood.BAD, Mood.GOOD),
    tls.Version.TLS12: (Mood.BAD, Mood.GOOD),
    tls.Version.TLS13: (Mood.NEUTRAL, Mood.NEUTRAL),
}

_supported_key_exchange = {
    tls.KeyExchangeAlgorithm.DHE_DSS: Mood.SOSO,
    tls.KeyExchangeAlgorithm.DHE_RSA: Mood.SOSO,
    tls.KeyExchangeAlgorithm.DH_ANON: Mood.BAD,
    tls.KeyExchangeAlgorithm.RSA: Mood.SOSO,
    tls.KeyExchangeAlgorithm.DH_DSS: Mood.BAD,
    tls.KeyExchangeAlgorithm.DH_RSA: Mood.BAD,
    tls.KeyExchangeAlgorithm.ECDH_ECDSA: Mood.BAD,
    tls.KeyExchangeAlgorithm.ECDHE_ECDSA: Mood.GOOD,
    tls.KeyExchangeAlgorithm.ECDH_RSA: Mood.BAD,
    tls.KeyExchangeAlgorithm.ECDHE_RSA: Mood.GOOD,
    tls.KeyExchangeAlgorithm.TLS13_KEY_SHARE: Mood.GOOD,
    tls.KeyExchangeAlgorithm.DHE_DSS_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.DHE_PSK: Mood.SOSO,
    tls.KeyExchangeAlgorithm.DHE_RSA_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.DH_ANON_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.DH_DSS_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.DH_RSA_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.ECCPWD: Mood.NEUTRAL,
    tls.KeyExchangeAlgorithm.ECDHE_PSK: Mood.NEUTRAL,
    tls.KeyExchangeAlgorithm.ECDH_ANON: Mood.BAD,
    tls.KeyExchangeAlgorithm.KRB5: Mood.NEUTRAL,
    tls.KeyExchangeAlgorithm.KRB5_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.NULL: Mood.BAD,
    tls.KeyExchangeAlgorithm.PSK: Mood.BAD,
    tls.KeyExchangeAlgorithm.PSK_DHE: Mood.SOSO,
    tls.KeyExchangeAlgorithm.RSA_EXPORT: Mood.BAD,
    tls.KeyExchangeAlgorithm.RSA_PSK: Mood.NEUTRAL,
    tls.KeyExchangeAlgorithm.SRP_SHA: Mood.BAD,
    tls.KeyExchangeAlgorithm.SRP_SHA_DSS: Mood.BAD,
    tls.KeyExchangeAlgorithm.SRP_SHA_RSA: Mood.BAD,
}

_supported_ciphers = {
    tls.SymmetricCipher.AES_128_CBC: Mood.SOSO,
    tls.SymmetricCipher.AES_256_CBC: Mood.SOSO,
    tls.SymmetricCipher.AES_128_GCM: Mood.GOOD,
    tls.SymmetricCipher.AES_256_GCM: Mood.GOOD,
    tls.SymmetricCipher.AES_128_CCM: Mood.GOOD,
    tls.SymmetricCipher.AES_128_CCM_8: Mood.GOOD,
    tls.SymmetricCipher.AES_256_CCM: Mood.GOOD,
    tls.SymmetricCipher.AES_256_CCM_8: Mood.GOOD,
    tls.SymmetricCipher.CHACHA20_POLY1305: Mood.GOOD,
    tls.SymmetricCipher.TRIPPLE_DES_EDE_CBC: Mood.BAD,
    tls.SymmetricCipher.CAMELLIA_128_CBC: Mood.SOSO,
    tls.SymmetricCipher.CAMELLIA_256_CBC: Mood.SOSO,
    tls.SymmetricCipher.IDEA_CBC: Mood.BAD,
    tls.SymmetricCipher.RC4_128: Mood.BAD,
    tls.SymmetricCipher.SEED_CBC: Mood.SOSO,
    tls.SymmetricCipher.TLS13_AES_128_GCM: Mood.GOOD,
    tls.SymmetricCipher.TLS13_AES_256_GCM: Mood.GOOD,
    tls.SymmetricCipher.TLS13_AES_128_CCM: Mood.GOOD,
    tls.SymmetricCipher.TLS13_AES_128_CCM_8: Mood.GOOD,
    tls.SymmetricCipher.ARIA_128_CBC: Mood.SOSO,
    tls.SymmetricCipher.ARIA_128_GCM: Mood.GOOD,
    tls.SymmetricCipher.ARIA_256_CBC: Mood.SOSO,
    tls.SymmetricCipher.ARIA_256_GCM: Mood.GOOD,
    tls.SymmetricCipher.CAMELLIA_128_GCM: Mood.GOOD,
    tls.SymmetricCipher.CAMELLIA_256_GCM: Mood.GOOD,
    tls.SymmetricCipher.DES40_CBC: Mood.BAD,
    tls.SymmetricCipher.DES_CBC: Mood.BAD,
    tls.SymmetricCipher.DES_CBC_40: Mood.BAD,
    tls.SymmetricCipher.NULL: Mood.BAD,
    tls.SymmetricCipher.RC2_CBC_40: Mood.BAD,
    tls.SymmetricCipher.RC4_40: Mood.BAD,
}

_supported_macs = {
    tls.HashPrimitive.SHA1: Mood.SOSO,
    tls.HashPrimitive.SHA256: Mood.GOOD,
    tls.HashPrimitive.SHA384: Mood.GOOD,
    tls.HashPrimitive.SHA512: Mood.GOOD,
    tls.HashPrimitive.MD5: Mood.BAD,
}

_cipher_order = {
    "text": {
        tls.SPBool.C_FALSE: "server does not enforce cipher suite order",
        tls.SPBool.C_TRUE: "server enforces cipher suite order",
        tls.SPBool.C_NA: "",
        tls.SPBool.C_UNDETERMINED: (
            "no indication if server enforces cipher suite order"
        ),
    },
    "mood": {
        tls.Version.SSL20: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.SSL30: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS10: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
    },
}

_supported_groups = {
    "support_txt": {
        tls.SPBool.C_FALSE: 'extension "supported_groups" not supported',
        tls.SPBool.C_TRUE: 'extension "supported_groups" supported',
        tls.SPBool.C_NA: None,
        tls.SPBool.C_UNDETERMINED: 'support for extensions "supported_group" unknown',
    },
    "support_mood": {
        tls.Version.SSL20: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.SSL30: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.TLS10: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    },
    "preference_txt": {
        tls.SPBool.C_FALSE: "server does not enforce order of supported groups",
        tls.SPBool.C_TRUE: "server enforces order of supported groups",
        tls.SPBool.C_NA: None,
        tls.SPBool.C_UNDETERMINED: "server preference for supported groups unknown",
    },
    "preference_mood": {
        tls.Version.SSL20: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.SSL30: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.TLS10: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    },
    "advertised_txt": {
        tls.SPBool.C_FALSE: "server does not advertise supported groups",
        tls.SPBool.C_TRUE: "server advertises supported groups",
        tls.SPBool.C_NA: None,
        tls.SPBool.C_UNDETERMINED: "advertisement of supported groups unknown",
    },
    "advertised_mood": {
        tls.Version.SSL20: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.SSL30: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.TLS10: (Mood.SOSO, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.SOSO, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.SOSO, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.SOSO, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    },
    "groups": {
        tls.SupportedGroups.SECT163K1: Mood.BAD,
        tls.SupportedGroups.SECT163R1: Mood.BAD,
        tls.SupportedGroups.SECT163R2: Mood.BAD,
        tls.SupportedGroups.SECT193R1: Mood.BAD,
        tls.SupportedGroups.SECT193R2: Mood.BAD,
        tls.SupportedGroups.SECT233K1: Mood.BAD,
        tls.SupportedGroups.SECT233R1: Mood.BAD,
        tls.SupportedGroups.SECT239K1: Mood.BAD,
        tls.SupportedGroups.SECT283K1: Mood.BAD,
        tls.SupportedGroups.SECT283R1: Mood.BAD,
        tls.SupportedGroups.SECT409K1: Mood.SOSO,
        tls.SupportedGroups.SECT409R1: Mood.SOSO,
        tls.SupportedGroups.SECT571K1: Mood.SOSO,
        tls.SupportedGroups.SECT571R1: Mood.SOSO,
        tls.SupportedGroups.SECP160K1: Mood.BAD,
        tls.SupportedGroups.SECP160R1: Mood.BAD,
        tls.SupportedGroups.SECP160R2: Mood.BAD,
        tls.SupportedGroups.SECP192K1: Mood.BAD,
        tls.SupportedGroups.SECP192R1: Mood.BAD,
        tls.SupportedGroups.SECP224K1: Mood.BAD,
        tls.SupportedGroups.SECP224R1: Mood.BAD,
        tls.SupportedGroups.SECP256K1: Mood.SOSO,
        tls.SupportedGroups.SECP256R1: Mood.GOOD,
        tls.SupportedGroups.SECP384R1: Mood.GOOD,
        tls.SupportedGroups.SECP521R1: Mood.GOOD,
        tls.SupportedGroups.BRAINPOOLP256R1: Mood.SOSO,
        tls.SupportedGroups.BRAINPOOLP384R1: Mood.SOSO,
        tls.SupportedGroups.BRAINPOOLP512R1: Mood.SOSO,
        tls.SupportedGroups.X25519: Mood.GOOD,
        tls.SupportedGroups.X448: Mood.GOOD,
        tls.SupportedGroups.BRAINPOOLP256R1TLS13: Mood.SOSO,
        tls.SupportedGroups.BRAINPOOLP384R1TLS13: Mood.SOSO,
        tls.SupportedGroups.BRAINPOOLP512R1TLS13: Mood.SOSO,
        tls.SupportedGroups.GC256A: Mood.BAD,
        tls.SupportedGroups.GC256B: Mood.BAD,
        tls.SupportedGroups.GC256C: Mood.BAD,
        tls.SupportedGroups.GC256D: Mood.BAD,
        tls.SupportedGroups.GC512A: Mood.BAD,
        tls.SupportedGroups.GC512B: Mood.BAD,
        tls.SupportedGroups.GC512C: Mood.BAD,
        tls.SupportedGroups.CURVESM2: Mood.BAD,
        tls.SupportedGroups.FFDHE2048: Mood.SOSO,
        tls.SupportedGroups.FFDHE3072: Mood.GOOD,
        tls.SupportedGroups.FFDHE4096: Mood.GOOD,
        tls.SupportedGroups.FFDHE6144: Mood.GOOD,
        tls.SupportedGroups.FFDHE8192: Mood.GOOD,
        tls.SupportedGroups.ARBITRARY_EXPLICIT_PRIME_CURVES: Mood.BAD,
        tls.SupportedGroups.ARBITRARY_EXPLICIT_CHAR2_CURVES: Mood.BAD,
    },
}

_sig_algo = {
    "algos": {
        tls.SignatureScheme.RSA_PKCS1_SHA1: Mood.SOSO,
        tls.SignatureScheme.ECDSA_SHA1: Mood.SOSO,
        tls.SignatureScheme.RSA_PKCS1_SHA256: Mood.GOOD,
        tls.SignatureScheme.ECDSA_SECP256R1_SHA256: Mood.GOOD,
        tls.SignatureScheme.RSA_PKCS1_SHA384: Mood.GOOD,
        tls.SignatureScheme.ECDSA_SECP384R1_SHA384: Mood.GOOD,
        tls.SignatureScheme.RSA_PKCS1_SHA512: Mood.GOOD,
        tls.SignatureScheme.ECDSA_SECP521R1_SHA512: Mood.GOOD,
        tls.SignatureScheme.ECCSI_SHA256: Mood.BAD,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA256: Mood.GOOD,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA384: Mood.GOOD,
        tls.SignatureScheme.RSA_PSS_RSAE_SHA512: Mood.GOOD,
        tls.SignatureScheme.ED25519: Mood.GOOD,
        tls.SignatureScheme.ED448: Mood.GOOD,
        tls.SignatureScheme.RSA_PSS_PSS_SHA256: Mood.GOOD,
        tls.SignatureScheme.RSA_PSS_PSS_SHA384: Mood.GOOD,
        tls.SignatureScheme.RSA_PSS_PSS_SHA512: Mood.GOOD,
        tls.SignatureScheme.ECDSA_BRAINPOOLP256R1TLS13_SHA256: Mood.SOSO,
        tls.SignatureScheme.ECDSA_BRAINPOOLP384R1TLS13_SHA384: Mood.SOSO,
        tls.SignatureScheme.ECDSA_BRAINPOOLP512R1TLS13_SHA512: Mood.SOSO,
        tls.SignatureScheme.RSA_PKCS1_MD5: Mood.BAD,
        tls.SignatureScheme.RSA_PKCS1_SHA224: Mood.SOSO,
        tls.SignatureScheme.DSA_MD5: Mood.BAD,
        tls.SignatureScheme.DSA_SHA1: Mood.SOSO,
        tls.SignatureScheme.DSA_SHA224: Mood.SOSO,
        tls.SignatureScheme.DSA_SHA256: Mood.SOSO,
        tls.SignatureScheme.DSA_SHA384: Mood.SOSO,
        tls.SignatureScheme.DSA_SHA512: Mood.SOSO,
        tls.SignatureScheme.ECDSA_SECP224R1_SHA224: Mood.SOSO,
    },
}

_assym_key_sizes = {3072: Mood.GOOD, 2048: Mood.SOSO, 0: Mood.BAD}
_assym_ec_key_sizes = {256: Mood.GOOD, 0: Mood.BAD}

_features = {
    "text": ("not supported", "supported", "not applicable", "undetermined"),
    "scsv_renegotiation": (Mood.SOSO, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "encrypt_then_mac": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "extended_master_secret": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "insecure_renegotiation": (Mood.GOOD, Mood.BAD, Mood.NEUTRAL, Mood.SOSO),
    "secure_renegotiation": (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.SOSO),
    "session_id": (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
    "session_ticket": (Mood.GOOD, Mood.SOSO, Mood.NEUTRAL, Mood.SOSO),
    "resumption_psk": (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
    "early_data": (Mood.GOOD, Mood.BAD, Mood.NEUTRAL, Mood.SOSO),
}

_heartbeat = {
    tls.SPHeartbeat.C_FALSE: ("not supported", Mood.GOOD),
    tls.SPHeartbeat.C_TRUE: ("supported", Mood.BAD),
    tls.SPHeartbeat.C_NA: ("not applicable", Mood.NEUTRAL),
    tls.SPHeartbeat.C_UNDETERMINED: ("undetermined", Mood.SOSO),
    tls.SPHeartbeat.C_NOT_REPONDING: ("supported, but no response", Mood.BAD),
    tls.SPHeartbeat.C_WRONG_RESPONSE: (
        "supported, but invalid response received",
        Mood.BAD,
    ),
}

_grease = {
    "parameters": (
        ("version_tolerance", "protocol versions"),
        ("cipher_suite_tolerance", "cipher suites"),
        ("extension_tolerance", "extensions"),
        ("group_tolerance", "named groups"),
        ("sig_algo_tolerance", "signature algorithms"),
        ("psk_mode_tolerance", "PSK exchange modes (TLS1.3)"),
    ),
    "result": {
        tls.SPBool.C_FALSE: ("not tolerant", Mood.BAD),
        tls.SPBool.C_TRUE: ("tolerant", Mood.GOOD),
        tls.SPBool.C_NA: ("not applicable", Mood.NEUTRAL),
        tls.SPBool.C_UNDETERMINED: ("undetermined", Mood.SOSO),
    },
}


_cert = {
    "chain_valid": {
        tls.SPBool.C_FALSE: ("validation failed", Mood.BAD),
        tls.SPBool.C_TRUE: ("successfully validated", Mood.GOOD),
        tls.SPBool.C_NA: ("", Mood.NEUTRAL),
        tls.SPBool.C_UNDETERMINED: ("validation status undetermined", Mood.SOSO),
    },
    "root_transmitted": {
        tls.SPBool.C_FALSE: (
            "root certificate was not provided by the server",
            Mood.GOOD,
        ),
        tls.SPBool.C_TRUE: ("root certificate was provided by the server", Mood.SOSO),
    },
    "subject_matches": {
        tls.SPBool.C_FALSE: ("no, URI not matched against subject/SAN", Mood.BAD),
        tls.SPBool.C_TRUE: ("yes, URI matches subject/SAN", Mood.GOOD),
        tls.SPBool.C_NA: ("", Mood.NEUTRAL),
        tls.SPBool.C_UNDETERMINED: ("validation status undetermined", Mood.SOSO),
    },
    "crl_status": {
        tls.CertCrlStatus.UNDETERMINED: ("unknown", Mood.SOSO),
        tls.CertCrlStatus.NOT_REVOKED: ("certificate not revoked", Mood.GOOD),
        tls.CertCrlStatus.REVOKED: ("certificate revoked", Mood.BAD),
        tls.CertCrlStatus.CRL_DOWNLOAD_FAILED: ("CRL download failed", Mood.BAD),
        tls.CertCrlStatus.WRONG_CRL_ISSUER: ("wrong CRL issuer", Mood.BAD),
        tls.CertCrlStatus.CRL_SIGNATURE_INVALID: ("CRL signature invalid", Mood.BAD),
    },
    "ocsp_status": {
        tls.OcspStatus.UNDETERMINED: ("not checked", Mood.NEUTRAL),
        tls.OcspStatus.NOT_REVOKED: ("certificate not revoked", Mood.GOOD),
        tls.OcspStatus.REVOKED: ("certificate revoked", Mood.BAD),
        tls.OcspStatus.UNKNOWN: ("certificate unknwon", Mood.BAD),
        tls.OcspStatus.TIMEOUT: ("OCSP server timeout", Mood.BAD),
        tls.OcspStatus.INVALID_RESPONSE: (
            "invalid response from OCSP server",
            Mood.BAD,
        ),
        tls.OcspStatus.SIGNATURE_INVALID: (
            "OCSP response has invalid signature",
            Mood.BAD,
        ),
        tls.OcspStatus.INVALID_TIMESTAMP: (
            "OCSP response has invalid timestamp",
            Mood.BAD,
        ),
    },
}

_cert_sig_algo = {}

_vulnerabilities = {
    tls.SPBool.C_FALSE: ("not vulnerable", Mood.GOOD),
    tls.SPBool.C_TRUE: ("vulnerable", Mood.BAD),
    tls.SPBool.C_NA: ("not applicable", Mood.NEUTRAL),
    tls.SPBool.C_UNDETERMINED: ("undetermined", Mood.SOSO),
}

_heartbleed = {
    tls.HeartbleedStatus.NOT_APPLICABLE: ("not applicable", Mood.NEUTRAL),
    tls.HeartbleedStatus.UNDETERMINED: ("undetermined", Mood.SOSO),
    tls.HeartbleedStatus.VULNERABLE: ("vulnerable", Mood.BAD),
    tls.HeartbleedStatus.NOT_VULNERABLE: ("not vulnerable", Mood.GOOD),
    tls.HeartbleedStatus.TIMEOUT: ("timeout, probably not vulnerable", Mood.GOOD),
    tls.HeartbleedStatus.CONNECTION_CLOSED: (
        "not vulnerable (connection closed)",
        Mood.GOOD,
    ),
}

_robot = {
    tls.RobotVulnerability.NOT_APPLICABLE: ("not applicable", Mood.NEUTRAL),
    tls.RobotVulnerability.UNDETERMINED: ("undetermined", Mood.NEUTRAL),
    tls.RobotVulnerability.INCONSITENT_RESULTS: ("inconsistent results", Mood.BAD),
    tls.RobotVulnerability.WEAK_ORACLE: ("vulnerable, weak oracle", Mood.BAD),
    tls.RobotVulnerability.STRONG_ORACLE: ("vulnerable, strong oracle", Mood.BAD),
    tls.RobotVulnerability.NOT_VULNERABLE: ("not vulnerable", Mood.GOOD),
}


def _check_version(version, reference):
    support = version in reference
    mood = _versions[version][support]
    txt = "supported" if support else "not supported"

    return apply_mood(txt, mood)


class TextProfileWorker(WorkerPlugin):
    """WorkerPlugin class which serializes a server profile.
    """

    name = "text_profile_dumper"
    prio = 1002

    def _print_tlsmate(self):
        print(apply_mood("A TLS configuration scanner (and more)", Mood.HEADLINE))
        print()
        print(f"  tlsmate, version {__version__}")
        print()
        print("  Repository: https://gitlab.com/guballa/tlsmate")
        print(
            "  Please file bug reports at https://gitlab.com/guballa/tlsmate/-/issues"
        )
        print()

    def _print_scan_info(self):
        scan_info = self.server_profile.scan_info
        self._start_date = scan_info.start_date
        print(apply_mood("Basic scan information", Mood.HEADLINE))
        print()
        print(f"  Command: {scan_info.command}")
        print(f"  tlsmate version used for the scan: {scan_info.version}")
        print(
            f"  The scan took place on {scan_info.start_date}, "
            f"scan duration: {scan_info.run_time} seconds"
        )
        print()

    def _print_host(self):
        host_info = self.server_profile.server
        print(apply_mood("Scanned host", Mood.HEADLINE))
        print()
        table = utils.Table(indent=2, sep="  ")
        name_resolution = hasattr(host_info, "name_resolution")
        if name_resolution:
            host = host_info.name_resolution.domain_name

        else:
            host = host_info.ip

        table.row("Host", f"{host}, port: {host_info.port}")
        table.row("SNI", host_info.sni)
        if name_resolution:
            if hasattr(host_info.name_resolution, "ipv4_addresses"):
                addresses = ", ".join(host_info.name_resolution.ipv4_addresses)
                table.row("IPv4 addresses", addresses)

            if hasattr(host_info.name_resolution, "ipv6_addresses"):
                addresses = ", ".join(host_info.name_resolution.ipv6_addresses)
                table.row("IPv6 addresses", addresses)

        table.dump()
        print()

    def _print_versions(self):
        print(apply_mood("TLS protocol versions:", Mood.HEADLINE))
        print()
        for version in tls.Version.all():
            txt = apply_mood(version, Mood.BOLD)
            print(f"  {txt}: {_check_version(version, self._prof_values.versions)}")

        print()

    def _print_cipher_suites(self):
        cipher_hash = {}
        print(apply_mood("Cipher suites", Mood.HEADLINE))
        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            if version is tls.Version.SSL20:
                cipher_list = version_prof.cipher_kinds
                txt = ""
                mood_txt = ""
            else:
                cipher_list = version_prof.ciphers.cipher_suites
                order = version_prof.ciphers.server_preference
                txt = _cipher_order["text"][order]
                mood = _cipher_order["mood"][version][order.value]
                mood_txt = apply_mood(txt, mood)

            hashed = hash((mood_txt, tuple(cipher_list)))
            if hashed in cipher_hash:
                cipher_hash[hashed]["versions"].append(str(version))

            else:
                cipher_hash[hashed] = {
                    "versions": [str(version)],
                    "lines": [],
                    "preference": mood_txt,
                }
                all_good = True
                for cs in cipher_list:
                    if version is tls.Version.SSL20:
                        cipher_hash[hashed]["lines"].append(
                            f"    0x{cs.value:06x} {apply_mood(cs, Mood.BAD)}"
                        )
                    else:
                        det = utils.get_cipher_suite_details(cs)
                        key_mood = _supported_key_exchange[det.key_algo]
                        cipher_mood = _supported_ciphers[det.cipher]
                        mac_mood = _supported_macs[det.mac]
                        mood = merge_moods([key_mood, cipher_mood, mac_mood])
                        if mood is not Mood.GOOD:
                            all_good = False
                        cipher_hash[hashed]["lines"].append(
                            f"    0x{cs.value:04x} {apply_mood(cs, mood)}"
                        )

                if all_good:
                    cipher_hash[hashed]["preference"] = apply_mood(txt, Mood.NEUTRAL)

        for values in cipher_hash.values():
            versions = apply_mood(", ".join(values["versions"]), Mood.BOLD)
            print(f'\n  {versions}: {values["preference"]}')
            for line in values["lines"]:
                print(line)

        print()

    def _print_supported_groups(self):
        group_hash = {}
        print(apply_mood("Supported groups", Mood.HEADLINE))
        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            group_prof = getattr(version_prof, "supported_groups", None)
            if group_prof is None:
                continue

            if not hasattr(group_prof, "groups"):
                continue

            supported = getattr(group_prof, "extension_supported", None)
            if supported is None:
                supp_txt = None

            else:
                supp_txt = _supported_groups["support_txt"][supported]
                if supp_txt is not None:
                    supp_mood = _supported_groups["support_mood"][version][
                        supported.value
                    ]
                    supp_txt = apply_mood(supp_txt, supp_mood)

            preference = getattr(group_prof, "server_preference", None)
            if preference is None:
                pref_txt = None

            else:
                pref_txt = _supported_groups["preference_txt"][preference]
                if pref_txt is not None:
                    if all(
                        [
                            _supported_groups["groups"][grp] is Mood.GOOD
                            for grp in group_prof.groups
                        ]
                    ):
                        pref_mood = Mood.NEUTRAL

                    else:
                        pref_mood = _supported_groups["preference_mood"][version][
                            preference.value
                        ]

                    pref_txt = apply_mood(pref_txt, pref_mood)

            advertised = getattr(group_prof, "groups_advertised", None)
            if advertised is None:
                ad_txt = None

            else:
                ad_txt = _supported_groups["advertised_txt"][advertised]
                if ad_txt is not None:
                    ad_mood = _supported_groups["advertised_mood"][version][
                        advertised.value
                    ]
                    ad_txt = apply_mood(ad_txt, ad_mood)

            combined = (supp_txt, pref_txt, ad_txt, tuple(group_prof.groups))
            hashed = hash(combined)
            if hashed in group_hash:
                group_hash[hashed]["versions"].append(str(version))

            else:
                group_hash[hashed] = {"versions": [str(version)], "combined": combined}

        for group in group_hash.values():
            versions = ", ".join(group["versions"])
            print(f"\n  {apply_mood(versions, Mood.BOLD)}:")
            supp_txt, pref_txt, ad_txt, groups = group["combined"]

            if supp_txt is not None:
                print(f"    {supp_txt}")

            if pref_txt is not None:
                print(f"    {pref_txt}")

            if ad_txt is not None:
                print(f"    {ad_txt}")

            print("    supported groups:")
            for grp in groups:
                grp_txt = apply_mood(grp, _supported_groups["groups"][grp])
                print(f"      0x{grp.value:02x} {grp_txt}")

        print()

    def _print_sig_algos(self):
        algo_hash = {}
        print(apply_mood("Signature algorithms", Mood.HEADLINE))
        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            if not hasattr(version_prof, "signature_algorithms"):
                continue

            algo_prof = version_prof.signature_algorithms
            hashed = hash(tuple(algo_prof.algorithms))
            if hashed in algo_hash:
                algo_hash[hashed]["versions"].append(str(version))

            else:
                algo_hash[hashed] = {
                    "versions": [str(version)],
                    "algos": algo_prof.algorithms,
                }

        for algo in algo_hash.values():
            versions = ", ".join(algo["versions"])
            print(f"\n  {apply_mood(versions, Mood.BOLD)}:")

            print("    signature algorithms:")
            for alg in algo["algos"]:
                alg_txt = apply_mood(alg, _sig_algo["algos"][alg])
                print(f"      0x{alg.value:04x} {alg_txt}")
        print()

    def _print_dh_groups(self):
        dh_groups = {}
        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            dh_prof = getattr(version_prof, "dh_group", None)
            if dh_prof is None:
                continue

            name = getattr(dh_prof, "name", None)
            combined = (name, dh_prof.size)
            hashed = hash(combined)
            if hashed in dh_groups:
                dh_groups[hashed]["versions"].append(str(version))

            else:
                dh_groups[hashed] = {
                    "versions": [str(version)],
                    "combined": combined,
                }

        if dh_groups:
            print(apply_mood("DH groups (finite field)", Mood.HEADLINE))
            for values in dh_groups.values():
                versions = ", ".join(values["versions"])
                print(f"\n  {apply_mood(versions, Mood.BOLD)}:")
                name, size = values["combined"]
                if name is None:
                    name = "unknown group"
                txt = f"{name} ({size} bits)"
                for val, mood in _assym_key_sizes.items():
                    if size >= val:
                        break
                print(f"    {apply_mood(txt, mood)}")

            print()

    def _print_common_features(self, feat_prof):
        print(f'  {apply_mood("Common features", Mood.BOLD)}')
        table = utils.Table(indent=4, sep="  ")
        hb_state = getattr(feat_prof, "heartbeat", None)
        if hb_state is not None:
            txt, mood = _heartbeat[hb_state]
            table.row("Heartbeat", apply_mood(txt, mood))

        table.dump()
        print()

    def _print_features_tls12(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.2 and below", Mood.BOLD)}')
        table = utils.Table(indent=4, sep="  ")
        if hasattr(feat_prof, "compression"):
            if (len(feat_prof.compression) == 1) and feat_prof.compression[
                0
            ] is tls.CompressionMethod.NULL:
                txt = apply_mood("not supported", Mood.GOOD)

            else:
                txt = apply_mood("supported", Mood.BAD)

            table.row("compression", txt)

        scsv = getattr(feat_prof, "scsv_renegotiation", None)
        if scsv is not None:
            txt = _features["text"][scsv.value]
            mood = _features["scsv_renegotiation"][scsv.value]
            table.row("SCSV-renegotiation", apply_mood(txt, mood))

        etm = getattr(feat_prof, "encrypt_then_mac", None)
        if etm is not None:
            txt = _features["text"][etm.value]
            mood = _features["encrypt_then_mac"][etm.value]
            table.row("encrypt-then-mac", apply_mood(txt, mood))

        ems = getattr(feat_prof, "extended_master_secret", None)
        if ems is not None:
            txt = _features["text"][ems.value]
            mood = _features["extended_master_secret"][ems.value]
            table.row("extended master secret", apply_mood(txt, mood))

        insec_reneg = getattr(feat_prof, "insecure_renegotiation", None)
        if insec_reneg is not None:
            txt = _features["text"][insec_reneg.value]
            mood = _features["insecure_renegotiation"][insec_reneg.value]
            table.row("insecure renegotiation", apply_mood(txt, mood))

        sec_reneg = getattr(feat_prof, "secure_renegotation", None)
        if sec_reneg is not None:
            txt = _features["text"][sec_reneg.value]
            mood = _features["secure_renegotiation"][sec_reneg.value]
            table.row("secure renegotiation", apply_mood(txt, mood))

        session_id = getattr(feat_prof, "session_id", None)
        if session_id is not None:
            txt = _features["text"][session_id.value]
            mood = _features["session_id"][session_id.value]
            table.row("resumption with session_id", apply_mood(txt, mood))

        session_ticket = getattr(feat_prof, "session_ticket", None)
        if session_ticket is not None:
            txt = _features["text"][session_ticket.value]
            mood = _features["session_ticket"][session_ticket.value]
            life_time = getattr(feat_prof, "session_ticket_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.session_ticket_lifetime} seconds"
            table.row(
                "resumption with session ticket", f"{apply_mood(txt, mood)}{add_txt}"
            )
        table.dump()
        print()

    def _print_features_tls13(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.3", Mood.BOLD)}')

        table = utils.Table(indent=4, sep="  ")
        resumption_psk = getattr(feat_prof, "resumption_psk", None)
        if resumption_psk is not None:
            txt = _features["text"][resumption_psk.value]
            mood = _features["resumption_psk"][resumption_psk.value]
            life_time = getattr(feat_prof, "psk_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.psk_lifetime} seconds"
            table.row("resumption with PSK", f"{apply_mood(txt, mood)}{add_txt}")

        early_data = getattr(feat_prof, "early_data", None)
        if early_data is not None:
            txt = _features["text"][early_data.value]
            mood = _features["early_data"][early_data.value]
            table.row("early data (0-RTT)", apply_mood(txt, mood))

        table.dump()
        print()

    def _print_grease(self, grease_prof):
        caption = apply_mood(
            "Server tolerance to unknown values (GREASE, RFC8701)", Mood.BOLD
        )
        print(f"  {caption}")
        table = utils.Table(indent=4, sep="  ")

        for attribute, text in _grease["parameters"]:
            val = getattr(grease_prof, attribute, tls.SPBool.C_UNDETERMINED)
            result, mood = _grease["result"][val]
            table.row(text, apply_mood(result, mood))

        table.dump()
        print()

    def _print_features(self):
        feat_prof = getattr(self.server_profile, "features", None)
        if feat_prof is None:
            return

        print(apply_mood("Features", Mood.HEADLINE))
        print()

        self._print_common_features(feat_prof)

        versions = self.server_profile.get_versions()
        wanted = {
            tls.Version.SSL30,
            tls.Version.TLS10,
            tls.Version.TLS11,
            tls.Version.TLS12,
        }
        if wanted.intersection(set(versions)):
            self._print_features_tls12(feat_prof)

        if tls.Version.TLS13 in versions:
            self._print_features_tls13(feat_prof)

        if hasattr(feat_prof, "grease"):
            self._print_grease(feat_prof.grease)

    def _print_cert(self, cert, idx):
        items = [str(getattr(cert, "version", ""))]
        self_signed = getattr(cert, "self_signed", None)
        if self_signed is tls.SPBool.C_TRUE:
            items.append("self-signed")

        print(f'  Certificate #{idx}: {", ".join(items)}')
        table = utils.Table(indent=4, sep="  ")

        issues = getattr(cert, "issues", None)
        if issues:
            issue_txt = []
            for issue in issues:
                folded_lines = utils.fold_string(issue, max_length=100)
                issue_txt.append("- " + folded_lines.pop(0))
                issue_txt.extend(["  " + item for item in folded_lines])
            table.row("Issues", apply_mood(issue_txt[0], Mood.BAD))
            for line in issue_txt[1:]:
                table.row("", apply_mood(line, Mood.BAD))

        table.row("Serial number", f"{cert.serial_number_int} (integer)")
        table.row("", f"{pdu.string(cert.serial_number_bytes)} (hex)")
        lines = utils.fold_string(cert.subject, max_length=100, sep=",")
        table.row("Subject", lines.pop(0))
        for line in lines:
            table.row("", line)

        san_ext = get_cert_ext(cert, "SubjectAlternativeName")
        if san_ext is not None:
            sans = " ".join([str(name) for name in san_ext.subj_alt_names])
            lines = utils.fold_string(sans, max_length=80)
            table.row("SubjectAltName (SAN)", lines.pop(0))
            for line in lines:
                table.row("", line)

        if hasattr(cert, "subject_matches"):
            txt, mood = _cert["subject_matches"][cert.subject_matches]
            table.row("URI matches", apply_mood(txt, mood))

        lines = utils.fold_string(cert.issuer, max_length=100, sep=",")
        table.row("Issuer", lines.pop(0))
        for line in lines:
            table.row("", line)

        sig_algo = getattr(cert, "signature_algorithm", None)
        if sig_algo is not None:
            mood = _sig_algo["algos"][sig_algo]
            table.row("Signature algorithm", apply_mood(str(sig_algo), mood))

        pub_key = getattr(cert, "public_key", None)
        if pub_key is not None:
            key_size = pub_key.key_size
            if pub_key.key_type in [
                tls.SignatureAlgorithm.RSA,
                tls.SignatureAlgorithm.DSA,
            ]:
                mood_reference = _assym_key_sizes

            else:
                mood_reference = _assym_ec_key_sizes

            for val, mood in mood_reference.items():
                if key_size >= val:
                    break

            table.row(
                "Public key",
                f'{pub_key.key_type}, {apply_mood(f"{key_size} bits", mood)}',
            )

        key_usage_ext = get_cert_ext(cert, "KeyUsage")
        if key_usage_ext is not None:
            usage_txt = ", ".join([str(usage) for usage in key_usage_ext.key_usage])
            table.row("Key usage", usage_txt)

        ext_key_usage_ext = get_cert_ext(cert, "ExtendedKeyUsage")
        if ext_key_usage_ext is not None:
            usage_txt = ", ".join(
                [str(usage) for usage in ext_key_usage_ext.extended_key_usage]
            )
            table.row("Extended key usage", usage_txt)

        if hasattr(cert, "not_valid_before"):
            valid = True
            mood = Mood.GOOD
            if cert.not_valid_before > self._start_date:
                valid = False
                mood = Mood.BAD

            from_txt = apply_mood(cert.not_valid_before, mood)
            mood = Mood.GOOD
            if cert.not_valid_after < self._start_date:
                valid = False
                mood = Mood.BAD
            to_txt = apply_mood(cert.not_valid_after, mood)

            if valid:
                valid_txt = apply_mood("valid period", Mood.GOOD)

            else:
                valid_txt = apply_mood("invalid period", Mood.BAD)

            table.row(
                "Validity period",
                (
                    f"{from_txt} - {to_txt} ({cert.validity_period_days} days), "
                    f"{valid_txt}"
                ),
            )

        crl_distr = get_cert_ext(cert, "CRLDistributionPoints")
        if crl_distr is not None:
            crls = []
            for distr_schema in crl_distr.distribution_points:
                for gen_name in distr_schema.full_name:
                    if hasattr(gen_name, "uri"):
                        crls.append(gen_name.uri)

            table.row("CRLs", crls.pop(0))
            for crl in crls:
                table.row("", crl)

        crl_status = getattr(cert, "crl_revocation_status", None)
        if crl_status is not None:
            txt, mood = _cert["crl_status"][crl_status]
            table.row("CRL revocation status", apply_mood(txt, mood))

        ocsp_status = getattr(cert, "ocsp_revocation_status", None)
        if ocsp_status is not None:
            txt, mood = _cert["ocsp_status"][ocsp_status]
            table.row("OCSP revocation status", apply_mood(txt, mood))

        if hasattr(cert, "fingerprint_sha1"):
            table.row("Fingerprint SHA1", pdu.string(cert.fingerprint_sha1))

        if hasattr(cert, "fingerprint_sha256"):
            table.row("Fingerprint SHA256", pdu.string(cert.fingerprint_sha256))

        table.dump()
        print()

    def _print_certificates(self):
        cert_chains = getattr(self.server_profile, "cert_chains", None)
        if cert_chains is None:
            return

        print(apply_mood("Certificate chains", Mood.HEADLINE))
        for cert_chain in cert_chains:
            print()
            if hasattr(cert_chain, "successful_validation"):
                txt, mood = _cert["chain_valid"][cert_chain.successful_validation]
                valid_txt = apply_mood(txt, mood)

            else:
                valid_txt = ""

            head_line = apply_mood(f"Certificate chain #{cert_chain.id}:", Mood.BOLD)
            print(f"  {head_line} {valid_txt}")
            if hasattr(cert_chain, "issues"):
                print("    Issues:")
                for issue in cert_chain.issues:
                    lines = utils.fold_string(issue, max_length=100)
                    txt = "    - " + "\n      ".join(lines)
                    print(apply_mood(txt, Mood.BAD))

            if hasattr(cert_chain, "root_cert_transmitted"):
                root_transmitted = cert_chain.root_cert_transmitted
                txt, mood = _cert["root_transmitted"][root_transmitted]
                print(f"    {apply_mood(txt, mood)}")

            for idx, cert in enumerate(cert_chain.cert_chain, start=1):
                self._print_cert(cert, idx)

            root_cert = getattr(cert_chain, "root_certificate", None)
            if root_cert:
                self._print_cert(root_cert, len(cert_chain.cert_chain) + 1)

    def _print_vulnerabilities(self):
        vuln_prof = getattr(self.server_profile, "vulnerabilities", None)
        if vuln_prof is None:
            return

        table = utils.Table(indent=2, sep="  ")
        print(apply_mood("Vulnerabilities", Mood.HEADLINE))
        print()
        ccs = getattr(vuln_prof, "ccs_injection", None)
        if ccs is not None:
            txt, mood = _vulnerabilities[ccs]
            table.row("CCS injection (CVE-2014-0224)", apply_mood(txt, mood))

        hb = getattr(vuln_prof, "heartbleed", None)
        if hb is not None:
            txt, mood = _heartbleed[hb]
            table.row("Heartbleed (CVE-2014-0160)", apply_mood(txt, mood))

        robot = getattr(vuln_prof, "robot", None)
        if robot is not None:
            txt, mood = _robot[robot]
            table.row(
                "ROBOT vulnerability (CVE-2017-13099, ...)", apply_mood(txt, mood)
            )

        table.dump()
        print()

    def run(self):
        init(strip=not self.config.get("color"))
        self._prof_values = self.server_profile.get_profile_values(tls.Version.all())
        self._print_tlsmate()
        self._print_scan_info()
        self._print_host()
        self._print_versions()
        self._print_cipher_suites()
        self._print_supported_groups()
        self._print_sig_algos()
        self._print_dh_groups()
        self._print_features()
        self._print_certificates()
        self._print_vulnerabilities()
