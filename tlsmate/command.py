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
from tlsmate.plugins.scan import ScanPlugin

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
        "--read-profile",
        type=str,
        help="JSON/Yaml file to read the server profile from",
    )

    parser.add_argument(
        "--write-profile",
        type=str,
        help=(
            "file to write the server profile to. By default the format of the file "
            "is Yaml. If this option is not given the profile is printed to STDOUT."
        ),
    )

    parser.add_argument(
        "--json",
        help="use the JSON-format for outputting the server profile",
        action="store_const",
        const=True,
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

    #    plugin_cli_options = sorted(SuiteManager.test_suites.keys())
    #    selected_plugins = []
    #    for arg in plugin_cli_options:
    #        if getattr(args, arg[2:]):
    #            selected_plugins.append(arg)
    #
    #    if not selected_plugins:
    #        options = " ".join(plugin_cli_options)
    #        parser.error("specify at least one of the following options: " + options)

    config = Configuration(ini_file=args.config_file)

    config.set("progress", args.progress)
    config.set("ca_certs", args.ca_certs)
    config.set("logging", args.logging)

    config.set("client_key", args.client_key)
    config.set("client_chain", args.client_chain)
    config.set("endpoint", args.host)
    config.set("sni", args.sni)
    config.set("json", args.json)
    config.set("read_profile", args.read_profile)
    config.set("write_profile", args.write_profile)

    utils.set_logging(config.get("logging"))

    PluginManager.args_parsed(args, config)

    tlsmate = TlsMate(config=config)
    tlsmate.work_manager.run(tlsmate)


PluginManager.register(ScanPlugin)

# and now look for additional user provided plugins
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsmate_")
}
