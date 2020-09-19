# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
import sys
import argparse
import logging

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
    parser_version.set_defaults(subparser=parser_version, func=command_version)


def build_parser():
    """Creates the parser object

    :return: the parser object as created with argparse
    :rtype: :class:`argparse.ArgumentParser`
    """
    parser = argparse.ArgumentParser(description="tlsclient")

    parser.add_argument("--version", action="store_true", default=False,
            help="print the version of the tool")
    parser.add_argument("--logging", choices=["critical", "error", "warning", "info", "debug"],
            help="sets the loggin level. Default id error.", default="error")

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

    parser = build_parser()
    args = parser.parse_args()
    if args.version:
        print_version()
        sys.exit(0)
    set_logging(args.logging)


    config = {"server": "localhost", "port": 44330}

    container = dependency.Container(config=config)

    container.test_suite().run()

    # parser = build_parser()
    # args = parser.parse_args()

    # if args.command is None:
    #     parser.print_help()
    # else:
    #     args.func(args)
