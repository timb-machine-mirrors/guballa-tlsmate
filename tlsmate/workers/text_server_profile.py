# -*- coding: utf-8 -*-
"""Module for a worker handling the server profile (de)serialization
"""
# import basic stuff

# import own stuff

from tlsmate.plugin import Worker
from tlsmate import tls
from tlsmate import utils
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
    tls.KeyExchangeAlgorithm.DHE_RSA: Mood.GOOD,
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
    tls.KeyExchangeAlgorithm.DHE_PSK: Mood.NEUTRAL,
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
    tls.KeyExchangeAlgorithm.PSK_DHE: Mood.NEUTRAL,
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
        tls.Version.TLS10: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
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
    "preference_txt": {
        tls.SPBool.C_FALSE: "server does not enforce order of signature algorithms",
        tls.SPBool.C_TRUE: "server enforces order of signature algorithms",
        tls.SPBool.C_NA: None,
        tls.SPBool.C_UNDETERMINED: "server preference for signature algorithms unknown",
    },
    "preference_mood": {
        tls.Version.SSL20: (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.SSL30: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.NEUTRAL),
        tls.Version.TLS10: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS11: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS12: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
        tls.Version.TLS13: (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    },
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

_dh_group_sizes = {3072: Mood.GOOD, 2048: Mood.SOSO, 0: Mood.BAD}

_features = {
    "text": ("not supported", "supported", "not applicable", "undetermined"),
    "scsv_renegotiation": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "encrypt_then_mac": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "extended_master_secret": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "insecure_renegotiation": (Mood.GOOD, Mood.BAD, Mood.NEUTRAL, Mood.SOSO),
    "secure_renegotiation": (Mood.BAD, Mood.GOOD, Mood.NEUTRAL, Mood.SOSO),
    "session_id": (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
    "session_ticket": (Mood.GOOD, Mood.SOSO, Mood.NEUTRAL, Mood.SOSO),
    "resumption_psk": (Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL, Mood.NEUTRAL),
    "early_data": (Mood.GOOD, Mood.BAD, Mood.NEUTRAL, Mood.SOSO),
}

_vulnerabilities = {
    tls.SPBool.C_FALSE: ("not vulnerable", Mood.GOOD),
    tls.SPBool.C_TRUE: ("vulnerable", Mood.BAD),
    tls.SPBool.C_NA: ("not applicable", Mood.NEUTRAL),
    tls.SPBool.C_UNDETERMINED: ("undetermined", Mood.SOSO),
}


def _check_version(version, reference):
    support = version in reference
    mood = _versions[version][support]
    txt = "supported" if support else "not supported"

    return apply_mood(txt, mood)


class TextProfileWorker(Worker):
    """Worker class which serializes a server profile.
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
        name_resolution = hasattr(host_info, "name_resolution")
        if name_resolution:
            host = host_info.name_resolution.domain_name

        else:
            host = host_info.ip

        print(f"  Host: {host}, port: {host_info.port}")
        print(f"  SNI: {host_info.sni}")
        if name_resolution:
            if hasattr(host_info.name_resolution, "ipv4_addresses"):
                addresses = ", ".join(host_info.name_resolution.ipv4_addresses)
                print(f"  IPv4 addresses: {addresses}")

            if hasattr(host_info.name_resolution, "ipv6_addresses"):
                addresses = ", ".join(host_info.name_resolution.ipv6_addresses)
                print(f"  IPv6 addresses: {addresses}")

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
            order = version_prof.server_preference
            txt = _cipher_order["text"][order]
            mood = _cipher_order["mood"][version][order.value]
            mood_txt = apply_mood(txt, mood)
            hashed = hash((mood_txt, tuple(version_prof.cipher_suites)))
            if hashed in cipher_hash:
                cipher_hash[hashed]["versions"].append(str(version))

            else:
                cipher_hash[hashed] = {
                    "versions": [str(version)],
                    "lines": [],
                    "preference": mood_txt,
                }
                for cs in version_prof.cipher_suites:
                    det = utils.get_cipher_suite_details(cs)
                    key_mood = _supported_key_exchange[det.key_algo]
                    cipher_mood = _supported_ciphers[det.cipher]
                    mac_mood = _supported_macs[det.mac]
                    mood = merge_moods([key_mood, cipher_mood, mac_mood])
                    cipher_hash[hashed]["lines"].append(
                        f"    0x{cs.value:04x} {apply_mood(cs, mood)}"
                    )

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
            if not hasattr(version_prof, "supported_groups"):
                continue

            group_prof = version_prof.supported_groups
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
            preference = getattr(algo_prof, "server_preference", None)
            if preference is None:
                pref_txt = None

            else:
                pref_txt = _sig_algo["preference_txt"][preference]
                if pref_txt is not None:
                    pref_mood = _sig_algo["preference_mood"][version][preference.value]
                    pref_txt = apply_mood(pref_txt, pref_mood)

            combined = (pref_txt, tuple(algo_prof.algorithms))
            hashed = hash(combined)
            if hashed in algo_hash:
                algo_hash[hashed]["versions"].append(str(version))

            else:
                algo_hash[hashed] = {"versions": [str(version)], "combined": combined}

        for algo in algo_hash.values():
            versions = ", ".join(algo["versions"])
            print(f"\n  {apply_mood(versions, Mood.BOLD)}:")
            pref_txt, algos = algo["combined"]
            if pref_txt is not None:
                print(f"    {pref_txt}")

            print("    signature algorithms:")
            for alg in algos:
                alg_txt = apply_mood(alg, _sig_algo["algos"][alg])
                print(f"      0x{alg.value:04x} {alg_txt}")
        print()

    def _print_dh_groups(self):
        dh_groups = {}
        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            dh_prof = getattr(version_prof, "dh_groups", None)
            if dh_prof is None:
                continue

            for group in dh_prof:
                name = getattr(group, "name", None)
                combined = (name, group.size)
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
                for val, mood in _dh_group_sizes.items():
                    if size >= val:
                        break
                print(f"    {apply_mood(txt, mood)}")

            print()

    def _print_features_tls12(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.2 and below", Mood.BOLD)}')
        if hasattr(feat_prof, "compression"):
            if (len(feat_prof.compression) == 1) and feat_prof.compression[
                0
            ] is tls.CompressionMethod.NULL:
                txt = apply_mood("not supported", Mood.GOOD)

            else:
                txt = apply_mood("supported", Mood.BAD)

            print(f"    compression: {txt}")

        scsv = getattr(feat_prof, "scsv_renegotiation", None)
        if scsv is not None:
            txt = _features["text"][scsv.value]
            mood = _features["scsv_renegotiation"][scsv.value]
            print(f"    SCSV-renegotiation: {apply_mood(txt, mood)}")

        etm = getattr(feat_prof, "encrypt_then_mac", None)
        if etm is not None:
            txt = _features["text"][etm.value]
            mood = _features["encrypt_then_mac"][etm.value]
            print(f"    encrypt-then-mac: {apply_mood(txt, mood)}")

        ems = getattr(feat_prof, "extended_master_secret", None)
        if ems is not None:
            txt = _features["text"][ems.value]
            mood = _features["extended_master_secret"][ems.value]
            print(f"    extended master secret: {apply_mood(txt, mood)}")

        insec_reneg = getattr(feat_prof, "insecure_renegotiation", None)
        if insec_reneg is not None:
            txt = _features["text"][insec_reneg.value]
            mood = _features["insecure_renegotiation"][insec_reneg.value]
            print(f"    insecure renegotiation: {apply_mood(txt, mood)}")

        sec_reneg = getattr(feat_prof, "secure_renegotation", None)
        if sec_reneg is not None:
            txt = _features["text"][sec_reneg.value]
            mood = _features["secure_renegotiation"][sec_reneg.value]
            print(f"    secure renegotiation: {apply_mood(txt, mood)}")

        session_id = getattr(feat_prof, "session_id", None)
        if session_id is not None:
            txt = _features["text"][session_id.value]
            mood = _features["session_id"][session_id.value]
            print(f"    resumption with session_id: {apply_mood(txt, mood)}")

        session_ticket = getattr(feat_prof, "session_ticket", None)
        if session_ticket is not None:
            txt = _features["text"][session_ticket.value]
            mood = _features["session_ticket"][session_ticket.value]
            life_time = getattr(feat_prof, "session_ticket_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.session_ticket_lifetime} seconds"
            print(
                f"    resumption with session ticket (RFC5077): "
                f"{apply_mood(txt, mood)}{add_txt}"
            )

        print()

    def _print_features_tls13(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.3", Mood.BOLD)}')

        resumption_psk = getattr(feat_prof, "resumption_psk", None)
        if resumption_psk is not None:
            txt = _features["text"][resumption_psk.value]
            mood = _features["resumption_psk"][resumption_psk.value]
            life_time = getattr(feat_prof, "psk_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.psk_lifetime} seconds"
            print(f"    resumption with PSK: {apply_mood(txt, mood)}{add_txt}")

        early_data = getattr(feat_prof, "early_data", None)
        if early_data is not None:
            txt = _features["text"][early_data.value]
            mood = _features["early_data"][early_data.value]
            print(f"    early data (0-RTT): {apply_mood(txt, mood)}")

        print()

    def _print_features(self):
        feat_prof = getattr(self.server_profile, "features", None)
        if feat_prof is None:
            return

        print(apply_mood("Features", Mood.HEADLINE))
        print()

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

    def _print_vulnerabilities(self):
        vuln_prof = getattr(self.server_profile, "vulnerabilities", None)
        if vuln_prof is None:
            return

        print(apply_mood("Vulnerabilities", Mood.HEADLINE))
        print()
        ccs = getattr(vuln_prof, "ccs_injection", None)
        if ccs is not None:
            txt, mood = _vulnerabilities[ccs]
            print(f"  CCS injection (CVE-2014-0224): {apply_mood(txt, mood)}")

        print()

    def run(self):
        init(strip=self.config.get("no_color"))
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
        self._print_vulnerabilities()
