# -*- coding: utf-8 -*-
"""Module containing a classes to abstract the socket
"""

import socket
import select
import logging
import sys
from tlsclient.exception import TLSConnectionClosedError


class Socket(object):
    """Class implementing the socket interface.

    Arguments:
        server (str): The name of server to connect to.
        port (int): The port number to connect to.
        recorder (:obj:`tlsclient.recorder.Recorder`): The recorder object
    """

    def __init__(self, config, recorder):
        self._socket = None
        self._config = config
        self._recorder = recorder
        self._fragment_max_size = 16384

    def _open_socket(self):
        """Opens a socket.
        """
        if self._recorder.is_injecting():
            return
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._config["server"], self._config["port"]))
        laddr, lport = self._socket.getsockname()
        raddr, rport = self._socket.getpeername()
        if self._config["progress"]:
            sys.stderr.write(".")
            sys.stderr.flush()
        logging.debug("Socket opened")
        logging.debug("local address: {}:{}".format(laddr, lport))
        logging.debug("remote address: {}:{}".format(raddr, rport))

    def close_socket(self):
        """Closes a socket.
        """
        if self._socket is not None:
            logging.debug("Closing socket")
            self._socket.close()
            self._socket = None

    def sendall(self, data):
        """Sends data to the network.

        Arguments:
            data (bytes): The data to send.
        """
        cont = self._recorder.trace_socket_sendall(data)
        if cont:
            if self._socket is None:
                self._open_socket()
            self._socket.sendall(data)

    def recv_data(self, timeout=5000):
        """Wait for data from the network.

        Arguments:
            timeout (int): The maximum time to wait.

        Returns:
            bytes: The bytes received or None if the timeout expired.
        """
        data = self._recorder.inject_socket_recv()
        if data is not None:
            return data
        if self._socket is None:
            self._open_socket()
        rfds, wfds, efds = select.select([self._socket], [], [], timeout / 1000)
        if rfds:
            try:
                data = self._socket.recv(self._fragment_max_size)
            except ConnectionResetError:
                raise TLSConnectionClosedError
        self._recorder.trace_socket_recv(data)
        if data == b"":
            raise TLSConnectionClosedError
        return data
