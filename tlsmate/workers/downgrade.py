# -*- coding: utf-8 -*-
"""Module for downgrade attack prevention worker
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate import msg
from tlsmate.plugin import Worker

# import other stuff


class ScanDowngrade(Worker):
    name = "downgrade"
    descr = "scan for downgrade attack prevention"
    prio = 30

    def run(self):

        versions = self.server_profile.get_versions()
        if len(versions) < 2:
            status = tls.SPBool.NA

        else:
            prof_values = self.server_profile.get_profile_values([versions[-2]])
            self.client.init_profile(profile_values=prof_values)
            self.client.profile.cipher_suites.append(tls.CipherSuite.TLS_FALLBACK_SCSV)

            status = tls.SPBool.UNDETERMINED
            with self.client.create_connection() as conn:
                conn.send(msg.ClientHello)
                response = conn.wait(msg.Any)
                if isinstance(response, msg.ServerHello):
                    status = tls.SPBool.FALSE

                elif isinstance(response, msg.Alert):
                    status = tls.SPBool.TRUE

        self.server_profile.allocate_features()
        self.server_profile.features.downgrade_attack_prevention = status
