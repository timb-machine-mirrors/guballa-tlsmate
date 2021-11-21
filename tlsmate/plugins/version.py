# -*- coding: utf-8 -*-
"""Module for the version plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import BaseCommand, Plugin, Args, Worker
from tlsmate.version import __version__

# import other stuff


class VersionWorker(Worker):
    """Worker to print the version of tlsmate.
    """

    name = "version"

    def run(self):
        print(__version__)


@BaseCommand.extend
class SubcommandVersion(Plugin):
    """CLI plugin to print the version of ``tlsmate``.
    """

    subcommand = Args("version", help="prints the version of tlsmate")
    workers = [VersionWorker]
