# -*- coding: utf-8 -*-
"""Module with a class for recording a tls connection
"""

import enum

class RecorderState(enum.Enum):

    INACTIVE = 0
    RECORDING = 1
    REPLAYING = 2

class Recorder(object):

    _INCOMING = 0
    _OUTGOING = 1

    _attr = [
        "client_random",
        "server_random",
        "pre_master_secret",
        "master_secret",
        "private_key",
        "client_write_mac_key",
        "server_write_mac_key",
        "client_write_key",
        "server_write_key",
        "client_write_iv",
        "server_write_iv",
        "verify_data_finished_rec",
        "verify_data_finished_calc",
        "msg_digest_finished_rec",
        "msg_digest_finished_sent",
        "verify_data_finished_sent"
    ]

    def __init__(self):
        self.state = RecorderState.INACTIVE
        self._msg_flow = []
        for attr in self._attr:
            setattr(self, attr, None)

    def deactivate(self):
        self.state = RecorderState.INACTIVE

    def record(self):
        self.state = RecorderState.RECORDING

    def replay(self):
        self.state = RecorderState.REPLAYING

    def trace_incoming_msg(self, msg):
        if self.state == RecorderState.RECORDING:
            self._msg_flow.append({"direction": self._INCOMING, "msg": msg})

    def injected_msg(self):
        if self.state == RecorderState.REPLAYING:
            cur = self._msg_flow.pop(0)
            if cur["direction"] != self._INCOMING:
                raise ValueError("Wrong state: Recorder cannot inject incoming message")
            return cur["msg"]
        return None


    def outgoing_msg(self, msg):
        if self.state == RecorderState.RECORDING:
            self._msg_flow.append({"direction": self._OUTGOING, "msg": msg})
            return True
        elif self.state == RecorderState.REPLAYING:
            cur = self._msg_flow.pop(0)
            if cur["direction"] != self._OUTGOING:
                raise ValueError("Wrong state: Recorder cannot check outgoing message")
            assert msg == cur["msg"]
            return False
        return True

    def trace(self, **kwargs):
        if self.state == RecorderState.INACTIVE:
            return
        name, val = kwargs.popitem()
        if name in self._attr:
            if self.state == RecorderState.REPLAYING:
                assert getattr(self, name) == val
            else:
                setattr(self, name, val)

    def inject(self, **kwargs):
        name, val = kwargs.popitem()
        if self.state == RecorderState.INACTIVE:
            return val
        if name in self._attr:
            if self.state == RecorderState.REPLAYING:
                val = getattr(self, name)
            else:
                setattr(self, name, val)
        return val


