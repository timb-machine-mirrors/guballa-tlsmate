# -*- coding: utf-8 -*-
"""Module deserialization and serialization of server profile
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import Plugin, WorkManager, PluginManager
from tlsmate.workers.server_profile import ReadProfileWorker, DumpProfileWorker

# import other stuff


@PluginManager.register
class ServerProfilePlugin(Plugin):
    """Plugin for deserializing and serializing the server profile.
    """

    name = "server_profile"

    config = {
        "write_profile": None,
        "read_profile": None,
        "json": False,
    }

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        parser.add_argument(
            "--json",
            help=(
                "use the JSON-format for outputting the server profile. If not given, "
                "the Yaml-format is used."
            ),
            action="store_const",
            const=True,
        )

        parser.add_argument(
            "--profile",
            type=str,
            help=(
                "writes the server profile to the given file. If no file is given, "
                "the profile will be dumped to STDOUT."
            ),
            nargs="?",
            default=None,
            const=True,
        )

        parser.add_argument(
            "--read-profile",
            type=str,
            help="JSON/Yaml file to read the server profile from",
        )

    def args_parsed(self, args, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """
        config.set("json", args.json)
        config.set("write_profile", args.profile)

        if args.read_profile is not None:
            WorkManager.register(ReadProfileWorker)

        if args.profile is not None:
            WorkManager.register(DumpProfileWorker)
            if type(args.profile) is str:
                config.set("read_profile", args.profile)
