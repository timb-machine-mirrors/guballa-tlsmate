# -*- coding: utf-8 -*-
"""Module with a class for recording a tls connection
"""

import enum


class RecorderState(enum.Enum):
    """States for the recorder
    """

    INACTIVE = 0
    RECORDING = 1
    REPLAYING = 2


class Recorder(object):
    """Class implementing a recorder mechanism.

    The purpose of the class is to have a build-in mechanism for unit testing. It works
    by providing hooks to all external interfaces. "External interface" means messages
    sent and received via the socket as well as numbers generated randomly.

    If inactive, the recorder has no functional impact on the rest of tlsmate.
    When recording, the recorder stores all data which are passing the interfaces,
    and they are "recorded", i.e., they are stored in the recorder object. This mode
    is used to record a unit test case (which can be as complex as a complete scan of
    a server). After the recoding is finished, the complete recorder object is
    pickled (i.e. serialized) and stored in a file.
    When replaying (normally triggered by pytest), the recorder object is unpickled
    from the file, and all recorded data is injected when the external interfaces
    are used. This way an EXACTLY clone of the connection(s) is/are executed. The
    replayed test case uses the same keying material as well, it is a "byte-to-byte""
    copy. Of course, all data sent over external interfaces are checked, and any
    diviation with the previously recorded data will let the test case fail.
    Note, that even after some cryptographic operations the recorder is hooked in, this
    allows easier debugging in case a replayed test deviates from the recorded twin.
    """

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
        "early_secret",
        "early_tr_secret",
        "msg_digest_tls13",
        "binder",
        "binder_key",
        "finished_key",
        "msg_without_binders",
        "hmac_algo",
        "timestamp",
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset the recorder to an initial state.
        """
        self._state = RecorderState.INACTIVE
        self._msg_sendall = []
        self._msg_recv = []
        for attr in self._attr:
            setattr(self, attr, [])

    def deactivate(self):
        """Deactivate the recorder.
        """
        self._state = RecorderState.INACTIVE

    def record(self):
        """Activate the recorder to record a test case.
        """
        self._state = RecorderState.RECORDING

    def replay(self):
        """Activate the recorder to replay a test case.
        """
        self._state = RecorderState.REPLAYING

    def is_injecting(self):
        """Check if the recorder is currently replaying (i.e. injecting data)

        Returns:
            bool: True if the recorder is replaying
        """
        return self._state == RecorderState.REPLAYING

    def is_recording(self):
        """Check if the recorder is currently recording.

        Returns:
            bool: True, if the recorder is recording
        """
        return self._state == RecorderState.RECORDING

    def trace_socket_recv(self, msg):
        """Trace a message received from a socket (if state is recording).

        Arguments:
            msg (bytes): the message in raw format
        """
        if self._state == RecorderState.RECORDING:
            self._msg_recv.append(msg)

    def inject_socket_recv(self):
        """If the recorder is replaying, inject the previously recorded message.

        Returns:
            bytes: the message previously recorded
        """
        if self._state == RecorderState.REPLAYING:
            return self._msg_recv.pop(0)
        return None

    def trace_socket_sendall(self, msg):
        """Interface for the sendall socket function.

        Arguments:
            msg (bytes): the message to send over the socket

        Returns:
            bool: True, if the message is sent externally.
        """
        if self._state == RecorderState.RECORDING:
            self._msg_sendall.append(msg)
        return self._state != RecorderState.REPLAYING

    def trace(self, **kwargs):
        """Interface to trace any data

        Arguments:
            **kwargs: the name and value to trace
        """
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
        """Interface to potentially inject recorded data

        If recording, the data provided is stored in the recorder object.
        If replaying, the data previously recorded is returned.

        Arguments:
            **kwargs: the name and value of the data

        Returns:
            value: If recording: the data provided via kwargs, if replaying: the
                data previously recorded.
        """
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
