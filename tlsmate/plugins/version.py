# -*- coding: utf-8 -*-
"""Module for the version plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import PluginBase, Plugin, Args, WorkerPlugin
from tlsmate.version import __version__

# import other stuff


class VersionWorker(WorkerPlugin):
    """Worker to print the version of tlsmate.
    """

    name = "version"

    def run(self):
        print(__version__)


@PluginBase.extend
class PluginVersion(Plugin):
    """CLI plugin to print the version of ``tlsmate``.
    """

    subcommand = Args("version", help="prints the version of tlsmate")
    workers = [VersionWorker]
