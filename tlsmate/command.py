# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
# import basic stuff
import argparse
import importlib
import pkgutil

# import own stuff
from tlsmate.config import Configuration
from tlsmate.tlsmate import TlsMate
from tlsmate.plugin import CliManager
from tlsmate import utils
from tlsmate.version import __version__

# import other stuff


def _args_authentication(parser):
    """Defines the arguments for authentication via certificates
    """
    group = parser.add_argument_group(title="X509 certificates options")
    group.add_argument(
        "--ca-certs",
        nargs="*",
        type=str,
        help=(
            "list of root-ca certificate files. Each file may contain multiple root-CA "
            "certificates in PEM format. Certificate chains received from the server "
            "will be validated against this set of root certificates."
        ),
    )

    group.add_argument(
        "--client-key",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the client private keys in PEM format. Used "
            "for client authentication."
        ),
    )
    group.add_argument(
        "--client-chain",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the certificate chain used for client "
            "authentication in PEM format. The number of given files must be the same "
            "than the number of given client key files. This first given chain file "
            "corresponds to the first given client key file, and so on."
        ),
    )

    group.add_argument(
        "--no-crl",
        help=(
            "do not download the CRL to check for the certificate revokation status."
        ),
        action="store_const",
        const=True,
    )


def build_parser():
    """Creates the parser object

    Returns:
        :obj:`argparse.ArgumentParser`: the parser object as created with argparse
    """
    parser = argparse.ArgumentParser(
        description=(
            "tlsmate is an application for testing and analyzing TLS servers. "
            "Test scenarios can be defined in a simple way with great flexibility. "
            "A TLS server configuration and vulnarability scan is built in."
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="print the version of the tool",
    )

    parser.add_argument(
        "--config",
        dest="config_file",
        default=None,
        help="ini-file to read the configuration from.",
    )

    parser.add_argument(
        "--interval",
        default=0,
        help="the interval in milliseconds between two handshakes.",
        type=int,
    )

    parser.add_argument(
        "--key-log-file",
        default=None,
        help=(
            "write to a key log file which can be used by wireshark to decode "
            "encrypted traffic."
        ),
    )

    parser.add_argument(
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the logging level. Default is error.",
        default="error",
    )

    parser.add_argument(
        "--progress",
        help="provides a kind of progress indicator",
        action="store_const",
        const=True,
    )

    parser.add_argument(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of for the server to "
            "contact. If not given, the value will be taken from the host parameter "
            "(after stripping of the port number, if present). This parameter is "
            "useful, if the host is given as an IP address."
        ),
    )

    parser.add_argument(
        "host",
        help=(
            "the host to scan. May optionally have the port number appended, "
            "separated by a colon."
        ),
        type=str,
    )

    _args_authentication(parser)

    CliManager.add_args(parser)

    return parser


def _args_consistency(args, parser):
    """Check the consistency of the given args which cannot be checked by argparse.

    Arguments:
        args (object): the arguments parsed as an object
        parser (:obj:`argparse.ArgumentParser`): the parser object
    """
    if (args.client_key is not None) or (args.client_chain is not None):
        if (args.client_chain is None) or (args.client_chain is None):
            parser.error(
                "if --client-key is given, --client-chain must be given as well, "
                "and vice versa"
            )
        if len(args.client_key) != len(args.client_chain):
            parser.error(
                "number of arguments for --client-key and --client-chain must "
                "be identical"
            )


def main():
    """The entry point for the command line interface
    """

    parser = build_parser()

    args = parser.parse_args()
    _args_consistency(args, parser)

    # logging must be setup before the first log is generated.
    utils.set_logging(args.logging)

    config = Configuration()

    CliManager.register_config(config)

    config.init_from_external(args.config_file)

    config.set("progress", args.progress)
    config.set("ca_certs", args.ca_certs)
    config.set("logging", args.logging)
    config.set("interval", args.interval)

    config.set("client_key", args.client_key)
    config.set("client_chain", args.client_chain)
    config.set("no_crl", args.no_crl)
    config.set("endpoint", args.host)
    config.set("sni", args.sni)
    config.set("key_log_file", args.key_log_file)

    CliManager.args_parsed(args, parser, config)

    tlsmate = TlsMate(config=config)
    tlsmate.work_manager.run(tlsmate)


CliManager.reset()

# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import server_profile, scan  # NOQA

# And now look for additional user provided plugins
for finder, name, ispkg in pkgutil.iter_modules():
    if name.startswith("tlsmate_"):
        importlib.import_module(name)
