# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import CliPlugin, WorkManager, CliManager
from tlsmate.workers.eval_cipher_suites import ScanCipherSuites
from tlsmate.workers.scanner_info import ScanStart, ScanEnd
from tlsmate.workers.supported_groups import ScanSupportedGroups
from tlsmate.workers.sig_algo import ScanSigAlgs
from tlsmate.plugins.basic_arguments import (
    BasicOptions,
    ServerProfileOptions,
    X509Options,
    TlsVersions,
    Features,
    Vulnerabilities,
)

# import other stuff


@CliManager.register
class ScanPlugin(CliPlugin):
    """CLI plugin to perform a scan against a TLS server.
    """

    prio = 20
    name = "scan"

    _cli_options = [
        BasicOptions,
        X509Options,
        TlsVersions,
        Features,
        Vulnerabilities,
        ServerProfileOptions,
    ]

    @classmethod
    def register_config(cls, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        for argument in cls._cli_options:
            argument.register_config(config)

    @classmethod
    def add_subcommand(cls, subparsers):
        """Adds a subcommand to the CLI parser object.

        Arguments:
            subparser (:obj:`argparse.Action`): the CLI subparsers object
        """

        subparsers.add_parser(cls.name, help="performs a TLS server scan")

    @classmethod
    def add_args(cls, parser, subcommand):
        """A callback method used to add arguments to the CLI parser object.

        This method is called to allow the CLI plugin to add additional command line
        argument to the parser.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
            subcommand (str): the subcommand for which arguments can be added. If None,
                the global arguments (valid for all subcommands) can be added.
        """

        if subcommand == cls.name:
            for argument in cls._cli_options:
                argument.add_args(parser, subcommand)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser: the parser object, can be used to issue consistency errors
            subcommand (str): the subcommand selected by the user
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if subcommand == cls.name:
            for argument in cls._cli_options:
                argument.args_parsed(args, parser, subcommand, config)

            WorkManager.register(ScanStart)
            WorkManager.register(ScanCipherSuites)
            WorkManager.register(ScanSupportedGroups)
            WorkManager.register(ScanSigAlgs)
            WorkManager.register(ScanEnd)
