# -*- coding: utf-8 -*-
"""Module for host name handling
"""
# import basic stuff
import socket
import logging

# import own stuff
from tlsmate.exception import ScanError
from tlsmate import tls
from tlsmate import structs
from tlsmate import utils

# import other stuff


def determine_l4_addr(host, port):
    """Determine type of the host

    Arguments:
        host (str): the given host. This might be an IP address or a hostname.
        port (int): the given port.

    Returns:
        :obj:`tlsmate.structs.TransportEndpoint`: The structure representing a transport
        protocol endpoint.
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
            utils.exit_with_error(f"Cannot resolve domain name {host_name}")

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


def get_ip_endpoint(l4_addr):
    """Resolve the hostname, if applicable.

    Arguments:
        l4_addr (:obj:`tlsmate.structs.TransportEndpoint`): the l4_addr to resolve

    Returns:
        :obj:`tlsmate.structs.TransportEndpoint`: the l4_addr, either with an IPv4
        or IPv6 address.
    """

    if l4_addr.host_type is not tls.HostType.HOST:
        return l4_addr

    ips = resolve_hostname(l4_addr.host)
    if ips.ipv4_addresses:
        host = ips.ipv4_addresses[0]
        host_type = tls.HostType.IPV4

    else:
        if ips.ipv6_addresses:
            host = ips.ipv4_addresses[0]
            host_type = tls.HostType.IPV4

        else:
            raise ScanError(f"No IP address available for {l4_addr.host}")

    return structs.TransportEndpoint(host=host, port=l4_addr.port, host_type=host_type)
