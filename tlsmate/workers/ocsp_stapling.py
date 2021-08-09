# -*- coding: utf-8 -*-
"""Module for OCSP stapling worker
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanOcspStapling(WorkerPlugin):
    name = "ocsp_stapling"
    descr = "check if OCSP stapling is supported"
    prio = 30

    def run(self):

        versions = tls.Version.tls_only()
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.versions:
            status = tls.OcspStatus.NOT_APPLICABLE

        else:
            self.client.init_profile(profile_values=prof_values)
            self.client.alert_on_invalid_cert = False
            self.client.profile.support_status_request = True
            with self.client.create_connection() as conn:
                conn.handshake()

            if not conn.handshake_completed:
                status = tls.OcspStatus.UNDETERMINED

            elif conn.ocsp_status is None:
                status = tls.OcspStatus.NOT_SUPPORTED

            else:
                status = conn.ocsp_status

        self.server_profile.features.ocsp_stapling = status
