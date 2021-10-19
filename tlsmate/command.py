# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
# import basic stuff
import argparse
import importlib
import pkgutil
import sys

# import own stuff
from tlsmate.config import Configuration
from tlsmate.tlsmate import TlsMate
from tlsmate.plugin import BaseCommand
from tlsmate import utils
from tlsmate.plugin import WorkManager

# import other stuff


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
    subparsers = parser.add_subparsers(title="commands", dest="subcommand")
    BaseCommand.extend_parser(parser, subparsers)
    return parser


def main():
    """The entry point for the command line interface
    """

    parser = build_parser()
    args = parser.parse_args()
    if args.subcommand is None:
        parser.error("Subcommand is mandatory")

    # logging must be setup before the first log is generated.
    utils.set_logging(args.logging)

    config = Configuration()
    BaseCommand.register_config(config)
    config.init_from_external(args.config_file)
    config.set("logging", args.logging)
    work_manager = WorkManager()
    BaseCommand.args_parsed(args, parser, args.subcommand, config)
    tlsmate = TlsMate(config=config)
    work_manager.run(tlsmate)


# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import scan, version  # NOQA

# And now look for additional user provided plugins
if len(sys.argv) < 2 or sys.argv[1] != "--no-plugin":
    for finder, name, ispkg in pkgutil.iter_modules():
        if name.startswith("tlsmate_"):
            importlib.import_module(name)
