# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
import argparse
import importlib
import pkgutil

import tlsmate.dependency_injection as dependency
from tlsmate.suitemanager import SuiteManager
from tlsmate.tlssuites.eval_cipher_suites import ScanCipherSuites
from tlsmate.tlssuites.scanner_info import ScanStart, ScanEnd
from tlsmate.tlssuites.supported_groups import ScanSupportedGroups
from tlsmate.tlssuites.testsuite import ScanScratch
from tlsmate.tlssuites.sig_algo import ScanSigAlgs
from tlsmate.tlssuites.compression import ScanCompression
from tlsmate.tlssuites.encrypt_then_mac import ScanEncryptThenMac
from tlsmate.tlssuites.master_secret import ScanExtendedMasterSecret
from tlsmate.tlssuites.resumption import ScanResumption
from tlsmate import utils

from tlsmate.version import __version__


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


def add_plugins_to_parser(parser):
    """Generate the CLI options for the plugins

    Arguments:
        parsers: parsers object
    """

    plugin_cli_options = SuiteManager.test_suites.keys()
    for arg in plugin_cli_options:
        parser.add_argument(
            arg, help=SuiteManager.cli_help[arg], action="store_true", default=False
        )


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
        help="sets the loggin level. Default id error.",
    )
    parser.add_argument(
        "--progress",
        help="provides a kind of progress indicator",
        action="store_const",
        const=True,
    )

    parser.add_argument(
        "--ca-certs",
        nargs="+",
        type=str,
        help=(
            "list of root-ca cert files. Each file may contain multiple root-CA "
            "certificates in PEM format."
        ),
    )

    parser.add_argument(
        "--client-key",
        type=str,
        help="a file containing the client private key in PEM format.",
    )

    parser.add_argument(
        "--client-cert",
        type=str,
        help=("a file containing the certificate chain used for client authentication "
            "in PEM format."
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

    add_plugins_to_parser(parser)

    return parser


def main():
    """The entry point for the command line interface
    """

    container = dependency.Container()

    test_manager = container.test_manager()
    parser = build_parser()

    args = parser.parse_args()
    host_arg = args.host.split(":")
    host = host_arg.pop(0)
    if host_arg:
        port = int(host_arg.pop(0))
    else:
        port = 443

    config = container.config(ini_file=args.config_file)

    config.merge_config("server", host)
    config.merge_config("port", port)
    config.merge_config("progress", args.progress)
    config.merge_config("ca_certs", args.ca_certs)
    config.merge_config("logging", args.logging)
    config.merge_config("client_key", args.client_key)
    config.merge_config("client_cert", args.client_cert)

    utils.set_logging(config["logging"])

    plugin_cli_options = sorted(SuiteManager.test_suites.keys())
    selected_plugins = []
    for arg in plugin_cli_options:
        if getattr(args, arg[2:]):
            selected_plugins.append(arg)

    if not selected_plugins:
        options = " ".join(plugin_cli_options)
        parser.error("specify at least one of the following options: " + options)

    test_manager.run(container, selected_plugins)


# always register the basic plugins provided with tlsmate
SuiteManager.register_cli(
    "--scan",
    cli_help="performs a basic scan",
    classes=[
        ScanStart,
        ScanCipherSuites,
        ScanSupportedGroups,
        ScanSigAlgs,
        ScanCompression,
        ScanEncryptThenMac,
        ScanExtendedMasterSecret,
        ScanResumption,
        ScanEnd,
    ],
)
SuiteManager.register_cli(
    "--scratch", cli_help="this is just a scratch scenario", classes=[ScanScratch]
)

# and now look for additional user provided plugins
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsmate_")
}
