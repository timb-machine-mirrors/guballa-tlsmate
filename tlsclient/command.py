# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
import sys
import argparse
import logging
import importlib
import pkgutil

import tlsclient.dependency_injection as dependency
from tlsclient.testmanager import TestManager
from tlsclient.testsuites.eval_cipher_suites import ScanCipherSuites
from tlsclient.testsuites.scanner_info import ScanStart, ScanEnd
from tlsclient.testsuites.supported_groups import ScanSupportedGroups
from tlsclient.testsuites.testsuite import ScanScratch

from tlsclient.version import __version__


def print_version():
    """Prints the version.
    """
    print(__version__)


def args_version(subparsers):
    """Defines the arguments for the subcommand "version"

    :param subparsers: subparsers object to extend with the subcommand
    :type subparsers: object returned by add_subparsers
    """
    parser_version = subparsers.add_parser(
        "version", help="print the version of the tool"
    )
    parser_version.set_defaults(subparser=parser_version)


def add_plugins_to_parser(parser):
    """Generate the CLI options for the plugins

    :param parsers: parsers object
    :type parser: object
    """

    plugin_cli_options = TestManager.test_suites.keys()
    for arg in plugin_cli_options:
        parser.add_argument(
            arg, help=TestManager.cli_help[arg], action="store_true", default=False
        )


def build_parser():
    """Creates the parser object

    :return: the parser object as created with argparse
    :rtype: :class:`argparse.ArgumentParser`
    """
    parser = argparse.ArgumentParser(description="tlsclient")

    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="print the version of the tool",
    )
    parser.add_argument(
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the loggin level. Default id error.",
        default="error",
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


def set_logging(level):
    """Sets the logging level

    :param args: args object as created by arg_parser
    :type args: :class:`Namespace`
    """
    logging.basicConfig(level=level.upper())


def main():
    """The entry point for the command line interface
    """

    config = {"server": "localhost", "port": 44330}

    container = dependency.Container(config=config)

    test_manager = container.test_manager()
    parser = build_parser()

    args = parser.parse_args()
    host_arg = args.host.split(":")
    host = host_arg.pop(0)
    if host_arg:
        port = int(host_arg.pop(0))
    else:
        port = 443

    container.config.set("server", host)
    container.config.set("port", port)

    set_logging(args.logging)

    plugin_cli_options = sorted(TestManager.test_suites.keys())
    selected_plugins = []
    for arg in plugin_cli_options:
        if getattr(args, arg[2:]):
            selected_plugins.append(arg)

    if not selected_plugins:
        options = " ".join(selected_plugins)
        parser.error("specify at least one of the following options: " + options)

    test_manager.run(container, selected_plugins)


# always register the basic plugins provided with tlsclient
TestManager.register_cli(
    "--scan",
    cli_help="performs a basic scan",
    classes=[ScanCipherSuites, ScanStart, ScanEnd, ScanSupportedGroups],
)
TestManager.register_cli(
    "--scratch", cli_help="this is just a scratch scenario", classes=[ScanScratch]
)

# and now look for additional user provided plugins
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsclient_")
}
