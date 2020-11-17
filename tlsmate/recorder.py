# -*- coding: utf-8 -*-
"""Module with a class for recording a tls connection
"""

import enum


class RecorderState(enum.Enum):

    INACTIVE = 0
    RECORDING = 1
    REPLAYING = 2


class Recorder(object):

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
        "verify_data_finished_sent",
        "ec_seed",
        "pms_rsa",
        "rsa_enciphered",
        "x_val",
        "y_val",
        "openssl_command",
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        self._state = RecorderState.INACTIVE
        self._msg_sendall = []
        self._msg_recv = []
        for attr in self._attr:
            setattr(self, attr, [])

    def deactivate(self):
        self._state = RecorderState.INACTIVE

    def record(self):
        self._state = RecorderState.RECORDING

    def replay(self):
        self._state = RecorderState.REPLAYING

    def is_injecting(self):
        return self._state == RecorderState.REPLAYING

    def is_recording(self):
        return self._state == RecorderState.RECORDING

    def trace_socket_recv(self, msg):
        if self._state == RecorderState.RECORDING:
            self._msg_recv.append(msg)

    def inject_socket_recv(self):
        if self._state == RecorderState.REPLAYING:
            return self._msg_recv.pop(0)
        return None

    def trace_socket_sendall(self, msg):
        if self._state == RecorderState.RECORDING:
            self._msg_sendall.append(msg)
        return self._state != RecorderState.REPLAYING

    def trace(self, **kwargs):
        if self._state == RecorderState.INACTIVE:
            return
        name, val = kwargs.popitem()
        if name in self._attr:
            if self._state == RecorderState.REPLAYING:
                item = getattr(self, name)
                if isinstance(item, list):
                    rec_val = item.pop(0)
                else:
                    rec_val = item
                assert rec_val == val
            else:
                getattr(self, name).append(val)

    def inject(self, **kwargs):
        name, val = kwargs.popitem()
        if self._state == RecorderState.INACTIVE:
            return val
        if name in self._attr:
            if self._state == RecorderState.REPLAYING:
                val = getattr(self, name)
                if isinstance(val, list):
                    val = val.pop(0)
            else:
                getattr(self, name).append(val)
        return val
