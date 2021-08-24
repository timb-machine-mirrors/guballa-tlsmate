# -*- coding: utf-8 -*-
"""Module scanning for the lucky-minus-20 vulnerability

Refer to CVE-2016-2107

Bug in openssl: no check was done if padding + hmac > record length.

Difficult to test, as only AESNI code was affected.

References:
    - https://web-in-security.blogspot.com/2016/05/curious-padding-oracle-in-openssl-cve.html  # noqa
    - https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/  # noqua

"""
# import basic stuff

# import own stuff
from tlsmate import msg
from tlsmate import tls
from tlsmate import utils
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanLuckyMinus20(WorkerPlugin):
    name = "lucky_minus_20"
    descr = "scan for Lucky-Minus-20 vulnerability (CVE-2016-2107)"
    prio = 40

    def run(self):
        status = tls.SPBool.C_NA
        values = self.server_profile.get_profile_values(
            [
                tls.Version.SSL30,
                tls.Version.TLS10,
                tls.Version.TLS11,
                tls.Version.TLS12,
            ],
            full_hs=True,
        )
        if values.versions:
            cbc_ciphers = utils.filter_cipher_suites(
                values.cipher_suites,
                cipher=[
                    tls.SymmetricCipher.AES_128_CBC,
                    tls.SymmetricCipher.AES_256_CBC,
                ],
                full_hs=True,
            )
            if cbc_ciphers:
                status = tls.SPBool.C_UNDETERMINED
                self.client.init_profile(profile_values=values)
                self.client.profile.cipher_suites = cbc_ciphers
                with self.client.create_connection() as conn:
                    conn.handshake()

                    block_size = conn.cs_details.cipher_struct.block_size
                    conn.send(
                        msg.AppData(b""),
                        use_hmac=b"",
                        use_padding=b"A" * 2 * block_size,
                    )
                    alert = conn.wait(msg.Alert)
                    if alert.description is tls.AlertDescription.RECORD_OVERFLOW:
                        status = tls.SPBool.C_TRUE

                    else:
                        status = tls.SPBool.C_FALSE

        self.server_profile.vulnerabilities.lucky_minus_20 = status
