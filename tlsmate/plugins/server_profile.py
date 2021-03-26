# -*- coding: utf-8 -*-
"""Module deserialization and serialization of server profile
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import Plugin, WorkManager, PluginManager
from tlsmate.workers.server_profile import ReadProfileWorker, DumpProfileWorker
from tlsmate.structs import ConfigItem

# import other stuff


@PluginManager.register
class ServerProfilePlugin(Plugin):
    """Plugin for deserializing and serializing the server profile.
    """

    prio = 10
    name = "server_profile"

    def register_config(self, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        config.register(ConfigItem("write_profile", type=str, default=None))
        config.register(ConfigItem("read_profile", type=str, default=None))
        config.register(ConfigItem("format", type=str, default="yaml"))

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        group = parser.add_argument_group(
            title="server profile options", description=None
        )
        group.add_argument(
            "--read-profile",
            type=str,
            help=(
                "JSON/Yaml file to read the server profile from. The format will be "
                "determined automatically."
            ),
        )
        group.add_argument(
            "--write-profile",
            type=str,
            help=(
                "writes the server profile to the given file. If no file is given, "
                'the profile will be dumped to STDOUT (unless "--format=none" is '
                "given)."
            ),
        )
        group.add_argument(
            "--format",
            choices=["json", "yaml", "none"],
            help=(
                'the output format of the server profile. Defaults to "yaml". "none" '
                "can be used to disable the output to STDOUT."
            ),
            default="yaml",
        )

    def args_parsed(self, args, parser, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser: the parser object, can be used to issue consistency errors
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """
        config.set("format", args.format)
        config.set("write_profile", args.write_profile)
        config.set("read_profile", args.read_profile)

        if args.read_profile is not None:
            WorkManager.register(ReadProfileWorker)

        if args.format != "none":
            WorkManager.register(DumpProfileWorker)
