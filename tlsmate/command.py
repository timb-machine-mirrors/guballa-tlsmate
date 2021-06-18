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

    parser.add_argument(
        "--config",
        dest="config_file",
        default=None,
        help="ini-file to read the configuration from.",
    )

    parser.add_argument(
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the logging level. Default is error.",
        default="error",
    )

    CliManager.extend_parser(parser)

    return parser


def main():
    """The entry point for the command line interface
    """

    parser = build_parser()
    args = parser.parse_args()

    # logging must be setup before the first log is generated.
    utils.set_logging(args.logging)

    config = Configuration()
    CliManager.register_config(config)
    config.init_from_external(args.config_file)
    config.set("logging", args.logging)
    CliManager.args_parsed(args, parser, config)
    tlsmate = TlsMate(config=config)
    tlsmate.work_manager.run(tlsmate)


# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import scan, version  # NOQA

# And now look for additional user provided plugins
for finder, name, ispkg in pkgutil.iter_modules():
    if name.startswith("tlsmate_"):
        importlib.import_module(name)
