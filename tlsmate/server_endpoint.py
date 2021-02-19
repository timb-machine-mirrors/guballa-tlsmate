# -*- coding: utf-8 -*-
"""Module containing a classes to abstract the socket
"""
# import basic stuff
import socket
import re
import logging

# import own stuff
from tlsmate.exception import ScanError

# import other stuff


class ServerEndpoint(object):
    """Class handling the addresses of the server endpoint.
    """

    def __init__(self):
        self.ip = None
        self.port = 443
        self.ipv4_addresses = None
        self.ipv6_addresses = None
        self.host_name = None
        self._host = None
        self.family = None
        self._is_host_name = False

    def configure(self, endpoint):
        """Configure the server endpoint based on tlsmates' config.

        Arguments:
            config (dict): the dictionary with the configuration.
        """

        if endpoint.startswith("["):
            # IPv6 address with port, e.g.
            # [2a00:d0c0:200:0:b9:1a:9c:5f]:443
            pattern = re.compile(r"\[(.*)\]:(\d+)")
            match = pattern.match(endpoint)
            if not match:
                raise ValueError("invalid IPv6 address")

            self._host = match.groups()[0]
            self.port = int(match.groups()[1])

        else:
            host_arg = endpoint.split(":")
            self._host = host_arg.pop(0)
            if host_arg:
                self.port = int(host_arg.pop(0))

        self._is_host_name = False
        try:
            socket.inet_pton(socket.AF_INET, self._host)
            self.family = socket.AF_INET

        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, self._host)
                self.family = socket.AF_INET6

            except OSError:
                self._is_host_name = True

    def resolve_ip(self):
        """Do a DNS lookup, if neccessary.
        """

        if self._is_host_name:
            if self._host != self.host_name:
                try:
                    logging.debug(f"Performing DNS lookup for {self._host}")
                    ips = socket.getaddrinfo(self._host, None, type=socket.SOCK_STREAM)

                except socket.gaierror:
                    raise ScanError(f"Cannot resolve {self._host}")

                self.ipv4_addresses = [
                    item[4][0] for item in ips if item[0] is socket.AF_INET
                ]
                self.ipv6_addresses = [
                    item[4][0] for item in ips if item[0] is socket.AF_INET6
                ]

                if self.ipv4_addresses:
                    self.ip = self.ipv4_addresses[0]
                    self.family = socket.AF_INET

                elif self.ipv6_addresses:
                    self.ip = self.ipv6_addresses[0]
                    self.family = socket.AF_INET6

                else:
                    raise ScanError(f"No IP address available for {self._host}")

                logging.debug(f"Using IP address {self.ip}")
                self.host_name = self._host
        else:
            self.ip = self._host
            self.host_name = None
            self.ipv4_addresses = None
            self.ipv6_addresses = None
