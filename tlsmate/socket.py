# -*- coding: utf-8 -*-
"""Module containing a classes to abstract the socket
"""
# import basic stuff
import socket
import select
import logging
import time
import sys

# import own stuff
from tlsmate import utils
from tlsmate.exception import TlsConnectionClosedError, TlsMsgTimeoutError
from tlsmate import recorder

# import other stuff


class Socket(object):
    """Class implementing the socket interface.

    Arguments:
        server (str): The name of server to connect to.
        port (int): The port number to connect to.
        recorder (:obj:`tlsmate.recorder.Recorder`): The recorder object
    """

    def __init__(self, config, recorder, server_endpoint):
        self._socket = None
        self._config = config
        self._recorder = recorder
        self._server_endpoint = server_endpoint
        self._fragment_max_size = 16384

    def open_socket(self):
        """Opens a socket.
        """
        self._server_endpoint.resolve_ip()
        if self._recorder.is_injecting():
            return

        self._socket = socket.socket(self._server_endpoint.family, socket.SOCK_STREAM)
        self._socket.connect((self._server_endpoint.ip, self._server_endpoint.port))
        laddr, lport = self._socket.getsockname()
        raddr, rport = self._socket.getpeername()
        if self._config["progress"]:
            sys.stderr.write(".")
            sys.stderr.flush()
        logging.info(f"{utils.Log.time()}: Socket opened")
        logging.info(f"local address: {laddr}:{lport}")
        logging.info(f"remote address: {raddr}:{rport}")

    def close_socket(self):
        """Closes a socket.
        """
        if self._socket is not None:
            logging.info(f"{utils.Log.time()}: closing socket")
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
                self.open_socket()
            self._socket.sendall(data)

    def recv_data(self, timeout=5):
        """Wait for data from the network.

        Arguments:
            timeout (int): The maximum time to wait in seconds.

        Returns:
            bytes: The bytes received or None if the timeout expired.

        Raises:
            TlsMsgTimeoutError: If no data is received within the given timeout
            TlsConnectionClosedError: If the connection was closed.
        """
        data = self._recorder.inject_socket_recv()
        if data is None:
            if self._socket is None:
                self.open_socket()
            start = time.time()
            rfds, wfds, efds = select.select([self._socket], [], [], timeout)
            timeout = time.time() - start
            if not rfds:
                self._recorder.trace_socket_recv(timeout, recorder.SocketEvent.TIMEOUT)
                raise TlsMsgTimeoutError
            try:
                data = self._socket.recv(self._fragment_max_size)
            except ConnectionResetError:
                self._recorder.trace_socket_recv(timeout, recorder.SocketEvent.CLOSURE)
                self.close_socket()
                raise TlsConnectionClosedError
            self._recorder.trace_socket_recv(
                timeout, recorder.SocketEvent.DATA, data=data
            )
        if data == b"":
            self.close_socket()
            raise TlsConnectionClosedError
        return data
