# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
import sys
import argparse
import logging
import yaml

import tlsclient.dependency_injection as dependency

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


def build_parser():
    """Creates the parser object

    :return: the parser object as created with argparse
    :rtype: :class:`argparse.ArgumentParser`
    """
    parser = argparse.ArgumentParser(description="tlsclient")

    parser.add_argument(
        "--version",
        action="store_true",
        default=False,
        help="print the version of the tool",
    )
    parser.add_argument(
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the loggin level. Default id error.",
        default="error",
    )

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
    all_names = []
    for test_suite in test_manager.test_suites():
        all_names.append(test_suite.name)
        parser.add_argument(
            "--" + test_suite.name,
            help=test_suite.descr,
            action="store_true",
            default=False,
        )

    args = parser.parse_args()
    if args.version:
        print_version()
        sys.exit(0)
    set_logging(args.logging)

    test_suite_names = []
    for name in all_names:
        if getattr(args, name):
            test_suite_names.append(name)

    if not test_suite_names:
        options = " ".join(["--" + name for name in all_names])
        parser.error("specify at least of the following options: " + options)

    test_manager.run(container, test_suite_names)
    print(yaml.dump(container.server_profile().serialize_obj(), indent=4))
