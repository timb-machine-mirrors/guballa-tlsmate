# -*- coding: utf-8 -*-
"""Module containing a classes to abstract the socket
"""

import socket
import select

class Socket(object):

    def __init__(self, server, port, recorder):

        self._socket = None
        self._server = server
        self._port = port
        self._recorder = recorder
        self._fragment_max_size = 16384

    def _open_socket(self):
        if self._recorder.is_injecting():
            return
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._server, self._port))

    def close_socket(self):
        if self._socket is not None:
            self._socket.close()

    def set_recorder(self, recorder):
        self._recorder = recorder

    def sendall(self, data):
        cont = self._recorder.trace_socket_sendall(data)
        if cont:
            if self._socket is None:
                self._open_socket()
            self._socket.sendall(data)

    def recv_data(self):
        data = self._recorder.inject_socket_recv()
        if data is not None:
            return data
        if self._socket is None:
            self._open_socket()
        rfds, wfds, efds = select.select([self._socket], [], [], 5)
        if rfds:
            for fd in rfds:
                if fd is self._socket:
                    data = fd.recv(self._fragment_max_size)
        self._recorder.trace_socket_recv(data)
        return data

    def set_fragment_size(self, fragment_size):
        self._fragment_max_size = fragment_size

