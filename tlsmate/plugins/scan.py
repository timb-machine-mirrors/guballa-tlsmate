# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import Plugin, WorkManager, PluginManager
from tlsmate.workers.eval_cipher_suites import ScanCipherSuites
from tlsmate.workers.scanner_info import ScanStart, ScanEnd, ProfileDumper
from tlsmate.workers.supported_groups import ScanSupportedGroups
from tlsmate.workers.sig_algo import ScanSigAlgs
from tlsmate.workers.compression import ScanCompression
from tlsmate.workers.encrypt_then_mac import ScanEncryptThenMac
from tlsmate.workers.master_secret import ScanExtendedMasterSecret
from tlsmate.workers.resumption import ScanResumption
from tlsmate.workers.renegotiation import ScanRenegotiation

# import other stuff


@PluginManager.register
class ScanPlugin(Plugin):
    """Plugin to perform a scan against a TLS server.
    """
    name = "scan"
    cli_name = "--scan"
    cli_help = "performs a basic scan"

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        group = parser.add_argument_group(
            'additional options in case "--scan" is given',
            (
                "If none of the options is given then by default all protocol versions "
                "will be scanned."
            ),
        )
        group.add_argument(
            "--sslv2",
            help="scan for protocol version SSLv2",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--sslv3",
            help="scan for protocol version SSLv3",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--tls10",
            help="scan for protocol version TLS1.0",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--tls11",
            help="scan for protocol version TLS1.1",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--tls12",
            help="scan for protocol version TLS1.2",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--tls13",
            help="scan for protocol version TLS1.3",
            action="store_const",
            const=True,
        )

    def args_parsed(self, args, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """
        if args.scan:
            WorkManager.register(ScanStart)
            WorkManager.register(ScanCipherSuites)
            WorkManager.register(ScanSupportedGroups)
            WorkManager.register(ScanSigAlgs)
            WorkManager.register(ScanCompression)
            WorkManager.register(ScanEncryptThenMac)
            WorkManager.register(ScanExtendedMasterSecret)
            WorkManager.register(ScanResumption)
            WorkManager.register(ScanRenegotiation)
            WorkManager.register(ScanEnd)
            WorkManager.register(ProfileDumper)

            config.set("sslv2", args.sslv2)
            config.set("sslv3", args.sslv3)
            config.set("tls10", args.tls10)
            config.set("tls11", args.tls11)
            config.set("tls12", args.tls12)
            config.set("tls13", args.tls13)
