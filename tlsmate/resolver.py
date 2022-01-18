# -*- coding: utf-8 -*-
"""Module for host name handling
"""
# import basic stuff
import socket
import logging
import os
from typing import List, Dict

# import own stuff
import tlsmate.structs as structs
import tlsmate.tls as tls
import tlsmate.utils as utils

# import other stuff
import dns.resolver
import dns.exception

_DOH_SERVER = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.digitale-gesellschaft.ch/dns-query",
]


def determine_l4_addr(host: str, port: int) -> structs.TransportEndpoint:
    """Determine type of the host

    Arguments:
        host: the given host. This might be an IP address or a hostname.
        port: the given port.

    Returns:
        The structure representing a transport protocol endpoint.
    """

    try:
        socket.inet_pton(socket.AF_INET, host)
        host_type = tls.HostType.IPV4

    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            host_type = tls.HostType.IPV6

        except OSError:
            host_type = tls.HostType.HOST

    return structs.TransportEndpoint(host=host, port=port, host_type=host_type)


class Resolver(object):
    """Resolved domain names and provides service for IP address handling.
    """

    def __init__(self) -> None:
        if "http_proxy" in os.environ:
            self._resolver = dns.resolver.Resolver(configure=False)
            self._resolver.nameservers = _DOH_SERVER

        else:
            self._resolver = dns.resolver.Resolver()

        self._resolved: Dict[str, structs.ResolvedHost] = {}

    def _resolve_to_ip(self, host_name: str, rd_type: str) -> List[str]:
        try:
            answer = self._resolver.resolve(host_name, rd_type)
            return [rr.address for rr in answer]

        except (dns.resolver.NoAnswer, dns.exception.Timeout):
            return []

        except dns.resolver.NXDOMAIN:
            utils.exit_with_error(f"Cannot resolve domain name {host_name}")

    def resolve_hostname(self, host_name: str) -> structs.ResolvedHost:
        """Resolve a hostname into sets of IPv4 and IPv6 addresses

        Arguments:
            host_name: the host name to resolve. May not be an IP address.

        Returns:
            the structure for a resolved host name.
        """

        if host_name not in self._resolved:
            logging.debug(f"Performing DNS lookup for {host_name}")

            ipv4_addresses = self._resolve_to_ip(host_name, "A")
            ipv6_addresses = self._resolve_to_ip(host_name, "AAAA")

            for ipv4 in ipv4_addresses:
                logging.debug(f"IPv4 address: {ipv4}")

            for ipv6 in ipv6_addresses:
                logging.debug(f"IPv6 address: {ipv6}")

            self._resolved[host_name] = structs.ResolvedHost(
                ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses
            )

        return self._resolved[host_name]

    def get_ip_endpoint(
        self, l4_addr: structs.TransportEndpoint, ipv6_preference: bool = False,
    ) -> structs.TransportEndpoint:
        """Resolve the hostname, if applicable.

        Arguments:
            l4_addr: the l4_addr to resolve

        Returns:
            the l4_addr, either with an IPv4 or IPv6 address.
        """

        if l4_addr.host_type is not tls.HostType.HOST:
            return l4_addr

        ips = self.resolve_hostname(l4_addr.host)

        ipv4_present = bool(ips.ipv4_addresses)
        ipv6_present = bool(ips.ipv6_addresses)
        if not ipv4_present and not ipv6_present:
            raise tls.ScanError(f"No IP address available for {l4_addr.host}")

        if ipv4_present and ipv6_present:
            host_type = tls.HostType.IPV6 if ipv6_preference else tls.HostType.IPV4

        else:
            host_type = tls.HostType.IPV4 if ipv4_present else tls.HostType.IPV6

        host = (
            ips.ipv4_addresses[0]
            if host_type is tls.HostType.IPV4
            else ips.ipv6_addresses[0]
        )

        return structs.TransportEndpoint(
            host=host, port=l4_addr.port, host_type=host_type
        )
