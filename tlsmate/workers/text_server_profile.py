# -*- coding: utf-8 -*-
"""Module for a worker handling the server profile (de)serialization
"""
# import basic stuff
import sys

# import own stuff

from tlsmate.plugin import WorkerPlugin
from tlsmate import tls
from tlsmate import utils
from tlsmate import pdu
from tlsmate.version import __version__

# import other stuff
from colorama import init, Fore, Style


class Mood(object):
    """Defining the styles for a colorful text output
    """

    GOOD = Fore.GREEN
    NEUTRAL = ""
    SOSO = Fore.YELLOW + Style.BRIGHT
    BAD = Fore.RED
    HEADLINE = Fore.MAGENTA + Style.BRIGHT
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL
    ERROR = Fore.RED + Style.BRIGHT


def apply_mood(txt, mood):
    """Decorate the text with the given mood

    Arguments:
        txt (str): the text to decorate
        mood(str): the ANSI escape code string to style a terminal output

    Returns:
        str: the decorated text. The output will be reset to a normal terminal output
        at the end.
    """
    if mood == "":
        return str(txt)

    return mood + str(txt) + Mood.RESET


def merge_moods(moods):
    """Returns the "worst" mood from a given list

    Arguments:
        moods (list of moods): the list of mood strings
    """
    for mood in [Mood.ERROR, Mood.BAD, Mood.SOSO, Mood.NEUTRAL, Mood.GOOD]:
        if mood in moods:
            return mood

    raise ValueError("cannot merge moods")


def get_dict_value(profile, *keys, default=None):
    """Save function to get an item from a nested dict

    Arguments:
        profile (dict): the dict to start with
        *keys (str): a list the keys to descent to the wanted item of the profile
        default(any): the value to return if a key does not exist. Defaults to None.

    Returns:
        object: the item
    """

    if not profile:
        return default

    for key in keys:
        if key in profile:
            profile = profile[key]

        else:
            return default

    return profile


def get_mood(profile, *keys):
    """Get the mood string from a nested dict, descending according to the keys

    The leaf must be in ["good", "neutral", "soso", "bad", "headline", "bold", "reset",
    "error"] (case insensitive). These mood names are translated to the corresponding
    ANSI escape code.

    Arguments:
        profile (dict): the nested dict
        *keys (str): the keys applied in sequence to descent to the mood

    Returns:
        str: ANSI escape code string. If anything fails, Mood.ERROR is returned.
    """
    return getattr(
        Mood, get_dict_value(profile, *keys, default="error").upper(), Mood.ERROR
    )


def get_mood_applied(txt, profile, *keys):
    """Descent into a nested dict and apply the found mood to the given text.

    Arguments:
        txt (str): the text to decorate
        profile (dict): the nested dict
        *keys (str): the keys to descent into the nested dict

    Returns:
        str: the given text, decorated with the found ANSI escape code.
    """

    return apply_mood(txt, get_mood(profile, *keys))


def get_styled_text(data, *path):
    """Comfortable way to use common structure to apply a mood to a text.

    The item determined by data and path must be a dict with the following structure:
    {
        "txt": str,
        "style": str
    }
    The text given by the "txt" item will be decorated with the ANSI escape code
    which related to the "style" item.

    Arguments:
        data (dict): the nested dict to use
        *keys (str): the keys to descent into the nested dict

    Returns:
        str: the "txt" string decoraded with the "style" mood.
    """
    prof = get_dict_value(data, *path)
    if not prof:
        return apply_mood("???", Mood.ERROR)

    return get_mood_applied(get_dict_value(prof, "txt"), prof, "style")


def get_cert_ext(cert, name):
    """Extract the given extension from a certificate.

    Arguments:
        cert (:obj:`tlsmate.server_profile.SPCertificate`): the certificate object
        name (str): the name of the extension

    Returns:
        :obj:`tlsmate.server_profile.SPCertExtension`: the extension or None if not
        found
    """
    if not hasattr(cert, "extensions"):
        return None

    for ext in cert.extensions:
        if ext.name == name:
            return ext

    return None


class TextProfileWorker(WorkerPlugin):
    """WorkerPlugin class which serializes a server profile.
    """

    name = "text_profile_dumper"
    descr = "dump the scan results"
    prio = 1002

    def _parse_style(self):
        if not self._style:
            return

        if "style" in self._style:
            for mood in ["good", "neutral", "soso", "bad", "headline", "bold"]:
                if mood in self._style["style"]:
                    mood_def = self._style["style"][mood]
                    if mood_def:
                        string = ""
                        if "fg" in mood_def:
                            string += getattr(Fore, mood_def["fg"].upper())

                        if "style" in mood_def:
                            string += getattr(Style, mood_def["style"].upper())

                        setattr(Mood, mood.upper(), string)

    def _read_style(self):
        self._style = utils.deserialize_data(self.style_file)
        self._parse_style()

    def _print_tlsmate(self):
        print(apply_mood("A TLS configuration scanner (and more)", Mood.HEADLINE))
        print()
        table = utils.Table(indent=2, sep="  ")
        table.row("tlsmate version", __version__)
        table.row("repository", "https://gitlab.com/guballa/tlsmate")
        table.dump()
        print(
            "  Please file bug reports at https://gitlab.com/guballa/tlsmate/-/issues"
        )
        print()

    def _print_scan_info(self):
        scan_info = self.server_profile.scan_info
        self._start_date = scan_info.start_date
        print(apply_mood("Basic scan information", Mood.HEADLINE))
        print()
        print(f"  command: {scan_info.command}")
        table = utils.Table(indent=2, sep="  ")
        table.row("tlsmate version", f"{scan_info.version} (producing the scan)")
        table.row("scan start timestamp", str(scan_info.start_date))
        table.row("scan duration", f"{scan_info.run_time} seconds")
        table.row("applied style", self.style_file)
        table.row(
            "style description",
            get_dict_value(self._style, "description", "short", default="-"),
        )
        table.dump()
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

        table.row("host", host)
        table.row("port", str(host_info.port))
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
        if not hasattr(self.server_profile, "versions"):
            return

        print(apply_mood("TLS protocol versions:", Mood.HEADLINE))
        print()
        table = utils.Table(indent=2, sep="  ")
        for version in tls.Version.all():
            if any([vers.version is version for vers in self.server_profile.versions]):
                key = "supported"
                txt = "supported"

            else:
                key = "not_supported"
                txt = "not supported"

            table.row(
                apply_mood(version, Mood.BOLD),
                get_mood_applied(txt, self._style, "version", version.name, key),
            )

        table.dump()
        print()

    def _print_cipher_suites(self):
        if not hasattr(self.server_profile, "versions"):
            return

        cipher_hash = {}
        print(apply_mood("Cipher suites", Mood.HEADLINE))

        for version in self._prof_values.versions:
            version_prof = self.server_profile.get_version_profile(version)
            if version is tls.Version.SSL20:
                cipher_list = version_prof.cipher_kinds
                mood_txt = ""
                chacha_txt = ""
                pref_txt = ""
            else:
                cipher_list = version_prof.ciphers.cipher_suites
                order = version_prof.ciphers.server_preference

                struct = get_dict_value(
                    self._style, "version", version.name, "cipher_order", order.name
                )
                pref_txt = get_dict_value(struct, "txt", default="???")
                mood_txt = get_mood_applied(pref_txt, struct, "style")

                chacha_pref = getattr(
                    version_prof.ciphers, "chacha_poly_preference", None
                )
                if chacha_pref:
                    struct = get_dict_value(
                        self._style,
                        "version",
                        version.name,
                        "chacha_preference",
                        chacha_pref.name,
                    )
                    chacha_txt = get_mood_applied(
                        get_dict_value(struct, "txt", default="???"), struct, "style"
                    )

                else:
                    chacha_txt = ""

            hashed = hash((mood_txt, chacha_txt, tuple(cipher_list)))
            if hashed in cipher_hash:
                cipher_hash[hashed]["versions"].append(str(version))

            else:
                cipher_hash[hashed] = {
                    "versions": [str(version)],
                    "table": utils.Table(indent=4, sep="  "),
                    "preference": mood_txt,
                    "chacha_preference": chacha_txt,
                }
                all_good = True
                for cs in cipher_list:
                    if version is tls.Version.SSL20:
                        cipher_hash[hashed]["table"].row(
                            f"0x{cs.value:06x}", apply_mood(cs, Mood.BAD)
                        )

                    else:
                        det = utils.get_cipher_suite_details(cs)
                        key_mood = get_mood(
                            self._style, "key_exchange", det.key_algo.name
                        )
                        cipher_mood = get_mood(
                            self._style, "symmetric_ciphers", det.cipher.name
                        )
                        mac_mood = get_mood(self._style, "macs", det.mac.name)
                        mood = merge_moods([key_mood, cipher_mood, mac_mood])
                        if mood is not Mood.GOOD:
                            all_good = False

                        cipher_hash[hashed]["table"].row(
                            f"0x{cs.value:04x}", apply_mood(cs, mood)
                        )

                if all_good:
                    cipher_hash[hashed]["preference"] = apply_mood(
                        pref_txt, Mood.NEUTRAL
                    )

        for values in cipher_hash.values():
            versions = apply_mood(", ".join(values["versions"]), Mood.BOLD)
            print(f"\n  {versions}:")
            print(f'    {values["preference"]}')
            if values["chacha_preference"] != "":
                print(f'    {values["chacha_preference"]}')

            values["table"].dump()

        print()

    def _print_supported_groups(self):
        if not hasattr(self.server_profile, "versions"):
            return

        prof_grps = get_dict_value(self._style, "supported_groups", "groups")
        group_hash = {}
        print(apply_mood("Supported groups", Mood.HEADLINE))
        for version in self._prof_values.versions:
            prof_version = get_dict_value(self._style, "supported_groups", version.name)
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
                prof = get_dict_value(prof_version, "support", supported.name)
                supp_txt = get_dict_value(prof, "txt", default="???")
                if supp_txt:
                    supp_txt = get_mood_applied(supp_txt, prof, "style")

            preference = getattr(group_prof, "server_preference", None)
            if preference is None:
                pref_txt = None

            else:
                prof = get_dict_value(prof_version, "preference", preference.name)
                pref_txt = get_dict_value(prof, "txt", default="???")
                if pref_txt:
                    if prof_grps and all(
                        [prof_grps[grp.name] == "good" for grp in group_prof.groups]
                    ):
                        pref_mood = Mood.NEUTRAL

                    else:
                        pref_mood = get_mood(prof, "style")

                    pref_txt = apply_mood(pref_txt, pref_mood)

            advertised = getattr(group_prof, "groups_advertised", None)
            if advertised is None:
                ad_txt = None

            else:
                prof = get_dict_value(prof_version, "advertised", advertised.name)
                ad_txt = get_dict_value(prof, "txt", default="???")
                if ad_txt:
                    ad_txt = get_mood_applied(ad_txt, prof, "style")

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

            if supp_txt:
                print(f"    {supp_txt}")

            if pref_txt:
                print(f"    {pref_txt}")

            if ad_txt:
                print(f"    {ad_txt}")

            print("    supported groups:")
            table = utils.Table(indent=6, sep="  ")
            for grp in groups:
                table.row(
                    f"0x{grp.value:02x}",
                    get_mood_applied(grp.name, prof_grps, grp.name),
                )

            table.dump()

        print()

    def _print_sig_algos(self):
        if not hasattr(self.server_profile, "versions"):
            return

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
            table = utils.Table(indent=6, sep="  ")
            for alg in algo["algos"]:
                table.row(
                    f"0x{alg.value:04x}",
                    get_mood_applied(
                        alg.name, self._style, "signature_schemes", alg.name
                    ),
                )

            table.dump()

        print()

    def _print_dh_groups(self):
        if not hasattr(self.server_profile, "versions"):
            return

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
                key_sizes = get_dict_value(self._style, "assymetric_key_sizes")
                if key_sizes:
                    for prof in key_sizes:
                        if size >= prof["size"]:
                            break

                else:
                    prof = None

                print(f'    {get_mood_applied(txt, prof, "style")}')

            print()

    def _print_common_features(self, feat_prof):
        print(f'  {apply_mood("Common features", Mood.BOLD)}')
        table = utils.Table(indent=4, sep="  ")

        ocsp_state = getattr(feat_prof, "ocsp_stapling", None)
        if ocsp_state is not None:
            table.row(
                "OCSP stapling (status_request)",
                get_styled_text(self._style, "ocsp_stapling", ocsp_state.name),
            )

        ocsp_state = getattr(feat_prof, "ocsp_multi_stapling", None)
        if ocsp_state is not None:
            table.row(
                "OCSP multi stapling (status_request_v2)",
                get_styled_text(self._style, "ocsp_multi_stapling", ocsp_state.name),
            )

        hb_state = getattr(feat_prof, "heartbeat", None)
        if hb_state is not None:
            table.row(
                "Heartbeat", get_styled_text(self._style, "heartbeat", hb_state.name)
            )

        fallback = getattr(feat_prof, "downgrade_attack_prevention", None)
        if fallback is not None:
            table.row(
                "Downgrade attack prevention",
                get_styled_text(self._style, "fallback", fallback.name),
            )

        table.dump()
        print()

    def _print_features_tls12(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.2 and below", Mood.BOLD)}')
        table = utils.Table(indent=4, sep="  ")
        if hasattr(feat_prof, "compression"):
            if (len(feat_prof.compression) == 1) and feat_prof.compression[
                0
            ] is tls.CompressionMethod.NULL:
                compr = tls.SPBool.C_FALSE

            else:
                compr = tls.SPBool.C_TRUE

            table.row(
                "compression", get_styled_text(self._style, "compression", compr.name)
            )

        scsv = getattr(feat_prof, "scsv_renegotiation", None)
        if scsv is not None:
            table.row(
                "SCSV-renegotiation",
                get_styled_text(self._style, "scsv_renegotiation", scsv.name),
            )

        etm = getattr(feat_prof, "encrypt_then_mac", None)
        if etm is not None:
            table.row(
                "encrypt-then-mac",
                get_styled_text(self._style, "encrypt_then_mac", etm.name),
            )

        ems = getattr(feat_prof, "extended_master_secret", None)
        if ems is not None:
            table.row(
                "extended master secret",
                get_styled_text(self._style, "extended_master_secret", ems.name),
            )

        insec_reneg = getattr(feat_prof, "insecure_renegotiation", None)
        if insec_reneg is not None:
            table.row(
                "insecure renegotiation",
                get_styled_text(
                    self._style, "insecure_renegotiation", insec_reneg.name
                ),
            )

        sec_reneg = getattr(feat_prof, "secure_renegotation", None)
        if sec_reneg is not None:
            table.row(
                "secure renegotiation",
                get_styled_text(self._style, "secure_renegotiation", sec_reneg.name),
            )

        session_id = getattr(feat_prof, "session_id", None)
        if session_id is not None:
            table.row(
                "resumption with session_id",
                get_styled_text(self._style, "session_id", session_id.name),
            )

        session_ticket = getattr(feat_prof, "session_ticket", None)
        if session_ticket is not None:
            txt = get_styled_text(self._style, "session_ticket", session_ticket.name)
            life_time = getattr(feat_prof, "session_ticket_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.session_ticket_lifetime} seconds"
            table.row("resumption with session ticket", f"{txt}{add_txt}")
        table.dump()
        print()

    def _print_features_tls13(self, feat_prof):
        print(f'  {apply_mood("Features for TLS1.3", Mood.BOLD)}')

        table = utils.Table(indent=4, sep="  ")
        resumption_psk = getattr(feat_prof, "resumption_psk", None)
        if resumption_psk is not None:
            txt = get_styled_text(self._style, "resumption_psk", resumption_psk.name)
            life_time = getattr(feat_prof, "psk_lifetime", None)
            if life_time is None:
                add_txt = ""
            else:
                add_txt = f", life time: {feat_prof.psk_lifetime} seconds"
            table.row("resumption with PSK", f"{txt}{add_txt}")

        early_data = getattr(feat_prof, "early_data", None)
        if early_data is not None:
            table.row(
                "early data (0-RTT)",
                get_styled_text(self._style, "early_data", early_data.name),
            )

        table.dump()
        print()

    def _print_grease(self, grease_prof):
        grease = (
            ("version_tolerance", "version"),
            ("cipher_suite_tolerance", "cipher_suite"),
            ("extension_tolerance", "extension"),
            ("group_tolerance", "group"),
            ("sig_algo_tolerance", "sig_algo"),
            ("psk_mode_tolerance", "psk_mode"),
        )

        caption = apply_mood(
            "Server tolerance to unknown values (GREASE, RFC8701)", Mood.BOLD
        )
        print(f"  {caption}")
        table = utils.Table(indent=4, sep="  ")

        for prof_prop, style_prop in grease:
            val = getattr(grease_prof, prof_prop, tls.SPBool.C_UNDETERMINED)
            table.row(
                get_dict_value(
                    self._style, "grease", style_prop, "descr", default="???"
                ),
                get_styled_text(self._style, "grease", style_prop, val.name),
            )

        table.dump()
        print()

    def _print_ephemeral_key_reuse(self):
        if not hasattr(self.server_profile.features, "ephemeral_key_reuse"):
            return

        ekr = self.server_profile.features.ephemeral_key_reuse
        print(apply_mood("  Ephemeral key reuse", Mood.BOLD))
        table = utils.Table(indent=4, sep="  ")
        table.row(
            "DHE key reuse (TLS1.2 or below)",
            get_styled_text(
                self._style, "ephemeral_key_reuse", ekr.tls12_dhe_reuse.name
            ),
        )
        table.row(
            "ECDHE key reuse (TLS1.2 or below)",
            get_styled_text(
                self._style, "ephemeral_key_reuse", ekr.tls12_ecdhe_reuse.name
            ),
        )
        table.row(
            "DHE key reuse (TLS1.3)",
            get_styled_text(
                self._style, "ephemeral_key_reuse", ekr.tls13_dhe_reuse.name
            ),
        )
        table.row(
            "ECDHE key reuse (TLS1.3)",
            get_styled_text(
                self._style, "ephemeral_key_reuse", ekr.tls13_ecdhe_reuse.name
            ),
        )
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

        self._print_ephemeral_key_reuse()

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
            mood = get_mood(self._style, "certificate", "issues")
            for issue in issues:
                folded_lines = utils.fold_string(issue, max_length=100)
                issue_txt.append("- " + folded_lines.pop(0))
                issue_txt.extend(["  " + item for item in folded_lines])
            table.row("Issues", apply_mood(issue_txt[0], mood))
            for line in issue_txt[1:]:
                table.row("", apply_mood(line, mood))

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
            table.row(
                "URI matches",
                get_styled_text(
                    self._style,
                    "certificate",
                    "subject_matches",
                    cert.subject_matches.name,
                ),
            )

        ev = getattr(cert, "extended_validation", tls.SPBool.C_NA)
        if ev is not tls.SPBool.C_NA:
            table.row(
                "Extended validation",
                get_styled_text(
                    self._style, "certificate", "extended_validation", ev.name
                ),
            )

        lines = utils.fold_string(cert.issuer, max_length=100, sep=",")
        table.row("Issuer", lines.pop(0))
        for line in lines:
            table.row("", line)

        sig_algo = getattr(cert, "signature_algorithm", None)
        if sig_algo is not None:
            table.row(
                "Signature algorithm",
                get_mood_applied(
                    sig_algo.name, self._style, "signature_schemes", sig_algo.name
                ),
            )

        pub_key = getattr(cert, "public_key", None)
        if pub_key is not None:
            key_size = pub_key.key_size
            if pub_key.key_type in [
                tls.SignatureAlgorithm.RSA,
                tls.SignatureAlgorithm.DSA,
            ]:
                mood_reference = get_dict_value(self._style, "assymetric_key_sizes")

            else:
                mood_reference = get_dict_value(self._style, "assymetric_ec_key_sizes")

            if mood_reference is None:
                mood = Mood.ERROR

            else:
                for item in mood_reference:
                    if key_size >= item.get("size", 0):
                        mood = get_mood(item, "style")
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
            valid = tls.SPBool.C_TRUE
            valid_from = tls.SPBool.C_TRUE
            if cert.not_valid_before > self._start_date:
                valid_from = tls.SPBool.C_FALSE
                valid = tls.SPBool.C_FALSE

            valid_to = tls.SPBool.C_TRUE
            if cert.not_valid_after < self._start_date:
                valid_to = tls.SPBool.C_FALSE
                valid = tls.SPBool.C_FALSE

            from_txt = get_mood_applied(
                cert.not_valid_before,
                self._style,
                "certificate",
                "validity",
                valid_from.name,
                "style",
            )
            to_txt = get_mood_applied(
                cert.not_valid_after,
                self._style,
                "certificate",
                "validity",
                valid_to.name,
                "style",
            )
            valid_txt = get_styled_text(
                self._style, "certificate", "validity", valid.name
            )
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
            table.row(
                "CRL revocation status",
                get_styled_text(
                    self._style, "certificate", "crl_status", crl_status.name
                ),
            )

        ocsp_status = getattr(cert, "ocsp_revocation_status", None)
        if ocsp_status is not None:
            table.row(
                "OCSP revocation status",
                get_styled_text(
                    self._style, "certificate", "ocsp_status", ocsp_status.name
                ),
            )

            text = []
            must_staple = tls.SPBool.C_FALSE
            if cert.ocsp_must_staple is tls.SPBool.C_TRUE:
                text.append("must staple")
                must_staple = tls.SPBool.C_TRUE

            if cert.ocsp_must_staple_multi is tls.SPBool.C_TRUE:
                text.append("must multi-staple")
                must_staple = tls.SPBool.C_TRUE

            txt = get_dict_value(
                self._style,
                "certificate",
                "must_staple",
                must_staple.name,
                "txt",
                default="???",
            )
            if text:
                txt += f" ({', '.join(text)})"

            table.row(
                "OCSP must staple",
                get_mood_applied(
                    txt,
                    self._style,
                    "certificate",
                    "must_staple",
                    must_staple.name,
                    "style",
                ),
            )

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
                valid_txt = get_styled_text(
                    self._style,
                    "cert_chain",
                    "validation",
                    cert_chain.successful_validation.name,
                )

            else:
                valid_txt = ""

            head_line = apply_mood(f"Certificate chain #{cert_chain.id}:", Mood.BOLD)
            print(f"  {head_line} {valid_txt}")
            if hasattr(cert_chain, "issues"):
                mood = get_mood(self._style, "cert_chain", "issues")
                print("    Issues:")
                for issue in cert_chain.issues:
                    lines = utils.fold_string(issue, max_length=100)
                    txt = "    - " + "\n      ".join(lines)
                    print(apply_mood(txt, mood))

            if hasattr(cert_chain, "root_cert_transmitted"):
                txt = get_styled_text(
                    self._style,
                    "cert_chain",
                    "root_cert_transmitted",
                    cert_chain.root_cert_transmitted.name,
                )
                print("    ", txt)

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
            table.row(
                "CCS injection (CVE-2014-0224)",
                get_styled_text(
                    self._style, "vulnerabilities", "ccs_injection", ccs.name
                ),
            )

        hb = getattr(vuln_prof, "heartbleed", None)
        if hb is not None:
            table.row(
                "Heartbleed (CVE-2014-0160)",
                get_styled_text(self._style, "vulnerabilities", "heartbleed", hb.name),
            )

        robot = getattr(vuln_prof, "robot", None)
        if robot is not None:
            table.row(
                "ROBOT vulnerability (CVE-2017-13099, ...)",
                get_styled_text(self._style, "vulnerabilities", "robot", robot.name),
            )

        table.dump()
        print()

    def run(self):
        self.style_file = self.config.get("style")
        self._read_style()
        if self.config.get("progress"):
            sys.stderr.write("\n")

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
