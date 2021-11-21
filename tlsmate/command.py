# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
# import basic stuff
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

    return BaseCommand.create_parser()


def main():
    """The entry point for the command line interface
    """

    utils.set_logging_format()

    parser = build_parser()
    args = parser.parse_args()

    # logging should be setup as early as possible
    utils.set_logging_level(args.logging)

    config = Configuration()
    BaseCommand.register_config(config)
    config.init_from_external(args.config_file)
    config.set("logging", args.logging)
    work_manager = WorkManager()
    BaseCommand.args_parsed(args, parser, None, config)
    tlsmate = TlsMate(config=config)
    work_manager.run(tlsmate)


# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import scan, version  # NOQA

# And now look for additional user provided plugins
if len(sys.argv) < 2 or sys.argv[1] != "--no-plugin":
    for finder, name, ispkg in pkgutil.iter_modules():
        if name.startswith("tlsmate_"):
            importlib.import_module(name)
