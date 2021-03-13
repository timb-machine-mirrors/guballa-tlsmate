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
from tlsmate.plugin import PluginManager
from tlsmate import utils
from tlsmate.version import __version__

# import other stuff


def print_version():
    """Prints the version.
    """
    print(__version__)


def args_version(subparsers):
    """Defines the arguments for the subcommand "version"

    Arguments:
        subparsers: subparsers object to extend with the subcommand
    """
    parser_version = subparsers.add_parser(
        "version", help="print the version of the tool"
    )
    parser_version.set_defaults(subparser=parser_version)


def build_parser():
    """Creates the parser object

    Returns:
        :obj:`argparse.ArgumentParser`: the parser object as created with argparse
    """
    parser = argparse.ArgumentParser(description="tlsmate")

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
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the loggin level. Default is error.",
        default="error",
    )
    parser.add_argument(
        "--progress",
        help="provides a kind of progress indicator",
        action="store_const",
        const=True,
    )

    parser.add_argument(
        "--ca-certs",
        nargs="*",
        type=str,
        help=(
            "list of root-ca cert files. Each file may contain multiple root-CA "
            "certificates in PEM format."
        ),
    )

    parser.add_argument(
        "--client-key",
        type=str,
        nargs="*",
        help="a file containing the client private key in PEM format",
    )

    parser.add_argument(
        "--client-chain",
        type=str,
        nargs="*",
        help=(
            "a file containing the certificate chain used for client authentication "
            "in PEM format"
        ),
    )

    parser.add_argument(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of for the server to "
            "to contact. If not given, the value will be taken from the host parameter "
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

    PluginManager.add_args(parser)

    return parser


def args_consistency(args, parser):
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
    args_consistency(args, parser)

    # logging must be setup before the first log is generated.
    utils.set_logging(args.logging)

    config = Configuration()

    PluginManager.extend_config(config)

    config.init_from_external(args.config_file)

    config.set("progress", args.progress)
    config.set("ca_certs", args.ca_certs)
    config.set("logging", args.logging)

    config.set("client_key", args.client_key)
    config.set("client_chain", args.client_chain)
    config.set("endpoint", args.host)
    config.set("sni", args.sni)

    PluginManager.args_parsed(args, config)

    tlsmate = TlsMate(config=config)
    tlsmate.work_manager.run(tlsmate)


# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import server_profile, scan  # NOQA

# And now look for additional user provided plugins
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsmate_")
}
