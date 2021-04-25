# -*- coding: utf-8 -*-
"""Module scanning for the CCS-injection vulnerability

Refer to CVE-2014-0224

OpenSSL 1.0.1g and before was vulnerable.

ChangeCipherSpec is injected directly after receiving the ServerHelloDone. The server
then updated its connection state which means subsequent sent messages by the client
were regarded as protected records.
"""
# import basic stuff

# import own stuff
from tlsmate import msg
from tlsmate import tls
from tlsmate.exception import TlsConnectionClosedError
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanCcsInjection(WorkerPlugin):
    name = "ccsinjection"
    descr = "check if server is vulnerable to CCS injection (CVE-2014-0224)"
    prio = 40

    def run(self):
        status = tls.SPBool.C_NA
        values = self.server_profile.get_profile_values(
            [tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12], full_hs=True
        )
        if values.versions:
            status = tls.SPBool.C_UNDETERMINED
            self.client.init_profile(profile_values=values)
            with self.client.create_connection() as conn:
                conn.send(msg.ClientHello)
                conn.wait(msg.ServerHello)
                conn.wait(msg.Certificate, optional=True)
                conn.wait(msg.ServerKeyExchange, optional=True)
                conn.wait(msg.CertificateRequest, optional=True)
                conn.wait(msg.ServerHelloDone)

                # Normal handshake up to here. Now prematurely inject the CCS.
                conn.send(msg.ChangeCipherSpec)

                # And now send any other message. We use CCS again
                conn.send(msg.ChangeCipherSpec)

                try:
                    alert = conn.wait(msg.Alert, timeout=2000)
                    if isinstance(alert, msg.Alert) and (
                        alert.description is tls.AlertDescription.BAD_RECORD_MAC
                        or alert.description is tls.AlertDescription.DECRYPTION_FAILED
                    ):
                        # vulnerable
                        status = tls.SPBool.C_TRUE

                    else:
                        status = tls.SPBool.C_FALSE

                except TlsConnectionClosedError:
                    status = tls.SPBool.C_FALSE

        self.server_profile.vulnerabilities.ccs_injection = status
