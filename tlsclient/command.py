# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
import argparse

import tlsclient.dependencies as dependencies


from tlsclient.version import __version__


def command_version(args):
    """Prints the version.

    :param object args: object containing the converted arguments
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
    parser = argparse.ArgumentParser(description="Bla bla bla")
    subparsers = parser.add_subparsers(help="subcommands to execute", dest="command")

    args_version(subparsers)
    return parser


def main():
    """The entry point for the command line interface
    """
    config = {"server": "localhost", "port": 44330}

    container = dependencies.Container(config=config)

    container.test_suite().run()

    # parser = build_parser()
    # args = parser.parse_args()

    # if args.command is None:
    #     parser.print_help()
    # else:
    #     args.func(args)
