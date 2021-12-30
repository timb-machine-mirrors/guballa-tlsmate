# -*- coding: utf-8 -*-
"""Module containing the CLI implementation
"""
# import basic stuff
import importlib
import pkgutil
import sys
import argparse

# import own stuff
import tlsmate.config as conf
import tlsmate.plugin as plg
import tlsmate.tlsmate as tm
import tlsmate.utils as utils

# import other stuff


def build_parser() -> argparse.ArgumentParser:
    """Creates the parser object

    Returns:
        the parser object as created with argparse
    """

    return plg.BaseCommand.create_parser()


def main() -> None:
    """The entry point for the command line interface
    """

    utils.set_logging_format()

    parser = build_parser()
    args = parser.parse_args()

    # logging should be setup as early as possible
    utils.set_logging_level(args.logging)

    config = conf.Configuration()
    plg.BaseCommand.register_config(config)
    config.init_from_external(args.config_file)
    config.set("logging", args.logging)
    work_manager = plg.WorkManager()
    plg.BaseCommand.args_parsed(args, parser, None, config)
    tlsmate = tm.TlsMate(config=config)
    work_manager.run(tlsmate)


# And now load the plugins which are shipped by default with tlsmate...
from tlsmate.plugins import scan, version  # NOQA

# And now look for additional user provided plugins
if len(sys.argv) < 2 or sys.argv[1] != "--no-plugin":
    for finder, name, ispkg in pkgutil.iter_modules():
        if name.startswith("tlsmate_"):
            importlib.import_module(name)
