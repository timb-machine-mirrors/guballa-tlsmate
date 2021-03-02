# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
# import basic stuff
import argparse
import importlib
import pkgutil

# import own stuff
from tlsmate.tlsmate import TlsMate
from tlsmate.suitemanager import SuiteManager
from tlsmate.tlssuites.eval_cipher_suites import ScanCipherSuites
from tlsmate.tlssuites.scanner_info import ScanStart, ScanEnd
from tlsmate.tlssuites.supported_groups import ScanSupportedGroups
from tlsmate.tlssuites.sig_algo import ScanSigAlgs
from tlsmate.tlssuites.compression import ScanCompression
from tlsmate.tlssuites.encrypt_then_mac import ScanEncryptThenMac
from tlsmate.tlssuites.master_secret import ScanExtendedMasterSecret
from tlsmate.tlssuites.resumption import ScanResumption
from tlsmate.tlssuites.renegotiation import ScanRenegotiation
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


def add_tls_versions(parser):
    """Define command line options to filter on specific protocol versions.

    Arguments:
        parser (:obj:`argparse.ArgumentParser`): the parser object
    """

    group = parser.add_argument_group(
        "TLS protocol versions",
        (
            "Perform the scan for the given TLS protocol versions. "
            "If no version is given, then the default applies which means to scan "
            "for all versions."
        ),
    )

    group.add_argument(
        "--sslv2",
        help="scan for protocol version SSLv2",
        action="store_const",
        const=True,
    )
    group.add_argument(
        "--sslv3",
        help="scan for protocol version SSLv3",
        action="store_const",
        const=True,
    )
    group.add_argument(
        "--tls10",
        help="scan for protocol version TLS1.0",
        action="store_const",
        const=True,
    )
    group.add_argument(
        "--tls11",
        help="scan for protocol version TLS1.1",
        action="store_const",
        const=True,
    )
    group.add_argument(
        "--tls12",
        help="scan for protocol version TLS1.2",
        action="store_const",
        const=True,
    )
    group.add_argument(
        "--tls13",
        help="scan for protocol version TLS1.3",
        action="store_const",
        const=True,
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

    add_tls_versions(parser)

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

    add_plugins_to_parser(parser)

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

    tlsmate = TlsMate()

    test_manager = tlsmate.test_manager()
    parser = build_parser()

    args = parser.parse_args()
    _args_consistency(args, parser)

    config = tlsmate.config(ini_file=args.config_file)

    config.set_config("progress", args.progress)
    config.set_config("ca_certs", args.ca_certs)
    config.set_config("logging", args.logging)
    config.set_config("sslv2", args.sslv2)
    config.set_config("sslv3", args.sslv3)
    config.set_config("tls10", args.tls10)
    config.set_config("tls11", args.tls11)
    config.set_config("tls12", args.tls12)
    config.set_config("tls13", args.tls13)

    config.set_config("client_key", args.client_key)
    config.set_config("client_chain", args.client_chain)
    config.set_config("endpoint", args.host)
    config.set_config("sni", args.sni)

    utils.set_logging(config["logging"])

    plugin_cli_options = sorted(SuiteManager.test_suites.keys())
    selected_plugins = []
    for arg in plugin_cli_options:
        if getattr(args, arg[2:]):
            selected_plugins.append(arg)

    if not selected_plugins:
        options = " ".join(plugin_cli_options)
        parser.error("specify at least one of the following options: " + options)

    test_manager.run(tlsmate, selected_plugins)


# always register the basic cli plugins provided with tlsmate
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
        ScanRenegotiation,
        ScanEnd,
    ],
)

# and now look for additional user provided plugins
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsmate_")
}
