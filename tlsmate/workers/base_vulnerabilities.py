# -*- coding: utf-8 -*-
"""Module scanning for base vulnerabilities

Actually, this is not a scan but rather an evaluation of the server profile.
The following vulnerabilities are treated:
    - BEAST (TLS1.0 enabled)
    - CRIME (compression enabled)
    - Sweet-32 (64-bit block ciphers [IDEA, 3DES])
    - FREAK: RSA export cipher suites
    - LogJam: DHE with 1024 or less bits

"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate import utils
from tlsmate.plugin import Worker

# import other stuff


class ScanBaseVulnerabilities(Worker):
    name = "scan_base_vulnerabilities"
    descr = "scan for base vulnerabilities"
    prio = 40

    def _scan_beast(self):
        beast = False
        cipher_suites = self.server_profile.get_cipher_suites(tls.Version.TLS10)
        if cipher_suites:
            cs = utils.filter_cipher_suites(
                cipher_suites, cipher_type=[tls.CipherType.BLOCK]
            )
            beast = bool(cs)

        self.server_profile.vulnerabilities.beast = tls.SPBool(beast)

    def _scan_crime(self):
        crime = tls.SPBool.C_FALSE
        if hasattr(self.server_profile, "features"):
            if hasattr(self.server_profile.features, "compression"):
                compr = self.server_profile.features.compression
                null_compr = int(any([x.name == "NULL" for x in compr]))
                crime = tls.SPBool(len(compr) - null_compr)

            else:
                crime = tls.SPBool.C_UNDETERMINED

        else:
            crime = tls.SPBool.C_UNDETERMINED

        self.server_profile.vulnerabilities.crime = crime

    def _scan_sweet_32(self):
        prof_values = self.server_profile.get_profile_values(tls.Version.all())
        sweet_32 = tls.SPBool(
            bool(
                utils.filter_cipher_suites(
                    prof_values.cipher_suites,
                    cipher_prim=[
                        tls.CipherPrimitive.IDEA,
                        tls.CipherPrimitive.TRIPPLE_DES,
                    ],
                )
            )
        )
        self.server_profile.vulnerabilities.sweet_32 = sweet_32

    def _scan_freak(self):
        prof_values = self.server_profile.get_profile_values(tls.Version.all())
        freak = tls.SPBool(
            bool(
                utils.filter_cipher_suites(
                    prof_values.cipher_suites,
                    key_algo=[tls.KeyExchangeAlgorithm.RSA_EXPORT],
                )
            )
        )
        self.server_profile.vulnerabilities.freak = freak

    def _scan_logjam(self):
        logjam = tls.SPBool.C_NA
        for vers in self.server_profile.get_versions():
            vers_prof = self.server_profile.get_version_profile(vers)
            if hasattr(vers_prof, "dh_group"):
                logjam = tls.SPBool.C_FALSE
                if vers_prof.dh_group.size <= 1024:
                    logjam = tls.SPBool.C_TRUE
                    break

        self.server_profile.vulnerabilities.logjam = logjam

    def run(self):
        self.server_profile.allocate_vulnerabilities()
        self._scan_beast()
        self._scan_crime()
        self._scan_sweet_32()
        self._scan_freak()
        self._scan_logjam()
