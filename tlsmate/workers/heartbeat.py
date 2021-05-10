# -*- coding: utf-8 -*-
"""Module containing the test suite
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate import msg
from tlsmate.plugin import WorkerPlugin

# import other stuff


class ScanHeartbeat(WorkerPlugin):
    name = "heartbeat"
    descr = "check if heartbeats are supported"
    prio = 30

    def run(self):
        state = tls.SPHeartbeat.C_UNDETERMINED
        versions = [
            tls.Version.TLS10,
            tls.Version.TLS11,
            tls.Version.TLS12,
            tls.Version.TLS13,
        ]
        prof_values = self.server_profile.get_profile_values(versions, full_hs=True)
        if not prof_values.versions:
            state = tls.SPHeartbeat.C_NA

        else:
            self.client.init_profile(profile_values=prof_values)
            self.client.profile.heartbeat_mode = tls.HeartbeatMode.PEER_ALLOWED_TO_SEND
            with self.client.create_connection() as conn:
                conn.handshake()
                if conn.handshake_completed:
                    hb = conn.msg.server_hello.get_extension(tls.Extension.HEARTBEAT)
                    if hb:
                        if hb.heartbeat_mode is tls.HeartbeatMode.PEER_ALLOWED_TO_SEND:
                            req = msg.HeartbeatRequest()
                            req.payload = b"abracadabra"
                            req.payload_length = len(req.payload)
                            req.padding = b"\xff" * 16
                            conn.send(req)
                            res = conn.wait(msg.HeartbeatResponse, timeout=2000)
                            if res is None:
                                state = tls.SPHeartbeat.C_NOT_REPONDING

                            else:
                                if (
                                    req.payload_length == res.payload_length
                                    and req.payload == res.payload
                                ):
                                    state = tls.SPHeartbeat.C_TRUE

                                else:
                                    state = tls.SPHeartbeat.C_WRONG_RESPONSE

                        else:
                            state = tls.SPHeartbeat.C_FALSE

                    else:
                        state = tls.SPHeartbeat.C_FALSE

        self.server_profile.features.heartbeat = state
