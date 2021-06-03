# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import CliPlugin, CliManager
from tlsmate.version import __version__

# import other stuff


@CliManager.register
class VersionPlugin(CliPlugin):
    """CLI plugin to print the version of ``tlsmate``.
    """

    prio = 30
    name = "version"

    def add_subcommand(self, subparsers):
        """Adds a subcommand to the CLI parser object.

        Arguments:
            subparser (:obj:`argparse.Action`): the CLI subparsers object
        """

        subparsers.add_parser(self.name, help="prints the version of tlsmate")

    def args_parsed(self, args, parser, subcommand, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser: the parser object, can be used to issue consistency errors
            subcommand (str): the subcommand selected by the user
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if subcommand == self.name:
            print(__version__)
