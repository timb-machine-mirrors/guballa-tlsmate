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
from tlsmate import tls
from tlsmate.exception import TlsConnectionClosedError, TlsMsgTimeoutError
from tlsmate import recorder
from tlsmate import resolver

# import other stuff


class Socket(object):
    """Class implementing the socket interface.

    Arguments:
        server (str): The name of server to connect to.
        port (int): The port number to connect to.
        recorder (:obj:`tlsmate.recorder.Recorder`): The recorder object
    """

    def __init__(self, tlsmate):
        self._socket = None
        self._config = tlsmate.config
        self._recorder = tlsmate.recorder
        self._fragment_max_size = 16384

    def open_socket(self, l4_addr):
        """Opens a socket.

        Arguments:
            l4_addr (:obj:`tlsmate.structs.TransportEndpoint`): The L4-endpoint,
                consisting of the IP-address and the port.
        """

        if l4_addr.host_type is tls.HostType.HOST:
            l4_addr = resolver.get_ip_endpoint(l4_addr)

        if l4_addr.host_type is tls.HostType.IPV4:
            family = socket.AF_INET
            addr_info = (l4_addr.host, l4_addr.port)

        else:
            family = socket.AF_INET6
            addr_info = (l4_addr.host, l4_addr.port, 0, 0)

        if self._recorder.is_injecting():
            return

        try:
            self._socket = socket.socket(family, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect(addr_info)
            self._socket.settimeout(None)
            addr = self._socket.getsockname()
            laddr = addr[0]
            lport = addr[1]
            addr = self._socket.getpeername()
            raddr = addr[0]
            rport = addr[1]

        except OSError:
            utils.exit_with_error(f"Cannot open TCP connection to {l4_addr}")

        if self._config.get("progress"):
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
                return

            self._socket.sendall(data)

    def recv_data(self, timeout=5):
        """Wait for data from the network.

        Arguments:
            timeout (float): The maximum time to wait in seconds.

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

            except ConnectionResetError as exc:
                self._recorder.trace_socket_recv(timeout, recorder.SocketEvent.CLOSURE)
                self.close_socket()
                raise TlsConnectionClosedError(exc)

            self._recorder.trace_socket_recv(
                timeout, recorder.SocketEvent.DATA, data=data
            )
        if data == b"":
            self.close_socket()
            raise TlsConnectionClosedError()

        return data
