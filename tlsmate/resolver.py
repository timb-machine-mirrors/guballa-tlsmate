# -*- coding: utf-8 -*-
"""Module for host name handling
"""
# import basic stuff
import socket
import re
import logging

# import own stuff
from tlsmate.exception import ScanError
from tlsmate import tls
from tlsmate import structs

# import other stuff


def determine_transport_endpoint(endpoint):
    """Evaluate an endpoint (host name or an IP-address), optionally followed by a port.

    Arguments:
        endpoint (str): the given transport protocol endpoint. This might be an IP
            address or a hostname, optionally followed by a port (separated by a colon).

    Returns:
        :obj:`tlsmate.structs.TransportEndpoint`: The structure representing a transport
        protocol endpoint.
    """

    if endpoint.startswith("["):
        # IPv6 address with port, e.g.
        # [2a00:d0c0:200:0:b9:1a:9c:5f]:443
        pattern = re.compile(r"\[(.*)\]:(\d+)")
        match = pattern.match(endpoint)
        if not match:
            raise ValueError("invalid IPv6 address")

        groups = match.groups()
        host = groups[0]
        port = groups[1]
        host_type = tls.HostType.IPV6

    else:
        host_arg = endpoint.split(":")
        host = host_arg.pop(0)
        port = int(host_arg.pop(0)) if host_arg else 443

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


_resolved = {}


def resolve_hostname(host_name):
    """Resolve a hostname into sets of IPv4 and IPv6 addresses

    Arguments:
        host_name (str): the host name to resolve. May not be an IP address.

    Returns:
        :obj:`tlsmate.structs.ResolvedHost`: the structure for a resolved host name.
    """

    if host_name not in _resolved:

        try:
            logging.debug(f"Performing DNS lookup for {host_name}")
            ips = socket.getaddrinfo(host_name, None, type=socket.SOCK_STREAM)

        except socket.gaierror:
            raise ScanError(f"Cannot resolve {host_name}")

        ipv4_addresses = [item[4][0] for item in ips if item[0] is socket.AF_INET]
        ipv6_addresses = [item[4][0] for item in ips if item[0] is socket.AF_INET6]
        _resolved[host_name] = structs.ResolvedHost(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses
        )
        for ipv4 in ipv4_addresses:
            logging.debug(f"IPv4 address: {ipv4}")

        for ipv6 in ipv6_addresses:
            logging.debug(f"IPv6 address: {ipv6}")

    return _resolved[host_name]


def get_ip_endpoint(endpoint):
    """Resolve the hostname, if applicable.

    Arguments:
        endpoint (:obj:`tlsmate.structs.TransportEndpoint`): the endpoint to resolve

    Returns:
        :obj:`tlsmate.structs.TransportEndpoint`: the endpoint, either with an IPv4
        or IPv6 address.
    """

    if endpoint.host_type is not tls.HostType.HOST:
        return endpoint

    ips = resolve_hostname(endpoint.host)
    if ips.ipv4_addresses:
        host = ips.ipv4_addresses[0]
        host_type = tls.HostType.IPV4

    else:
        if ips.ipv6_addresses:
            host = ips.ipv4_addresses[0]
            host_type = tls.HostType.IPV4

        else:
            raise ScanError(f"No IP address available for {endpoint.host}")

    return structs.TransportEndpoint(host=host, port=endpoint.port, host_type=host_type)
