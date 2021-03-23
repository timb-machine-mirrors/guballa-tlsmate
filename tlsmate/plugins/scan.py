# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.structs import ConfigItem
from tlsmate.plugin import Plugin, WorkManager, PluginManager
from tlsmate.workers.eval_cipher_suites import ScanCipherSuites
from tlsmate.workers.scanner_info import ScanStart, ScanEnd
from tlsmate.workers.supported_groups import ScanSupportedGroups
from tlsmate.workers.sig_algo import ScanSigAlgs
from tlsmate.workers.compression import ScanCompression
from tlsmate.workers.encrypt_then_mac import ScanEncryptThenMac
from tlsmate.workers.master_secret import ScanExtendedMasterSecret
from tlsmate.workers.resumption import ScanResumption
from tlsmate.workers.renegotiation import ScanRenegotiation
from tlsmate.workers.ccs_injection import ScanCcsInjection
from tlsmate.workers.dh_params import ScanDhGroups

# import other stuff


@PluginManager.register
class ScanPlugin(Plugin):
    """Plugin to perform a scan against a TLS server.
    """

    name = "scan"
    cli_name = "--scan"
    cli_help = "performs a basic scan"

    _versions = ["sslv2", "sslv3", "tls10", "tls11", "tls12", "tls13"]
    _features = [
        "dh_groups",
        "compression",
        "encrypt_then_mac",
        "ext_master_secret",
        "renegotiation",
        "resumption",
        "ccs_injection",
    ]

    def register_config(self, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """
        for version in self._versions:
            config.register(ConfigItem(version, type=bool, default=False))

        for feature in self._features:
            config.register(ConfigItem(feature, type=bool, default=False))

    def _add_args_tls_versions(self, parser):
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

    def _add_args_workers(self, parser):
        group = parser.add_argument_group(
            'additional options in case "--scan" is given',
            (
                "If none of the options is given then by default all features "
                "will be scanned."
            ),
        )
        group.add_argument(
            "--dh-groups",
            help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--compression",
            help="scan for compression support",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--encrypt-then-mac",
            help="scan for encrypt-then-mac support (only TL1.0 - TLS1.2)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--ext-master-secret",
            help="scan for extended master secret support (only TL1.0 - TLS1.2)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--renegotiation",
            help="scan for renegotiation support (SSL30 - TLS1.2)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--resumption",
            help="scan for resumption support (SSL30 - TLS1.3)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--ccs-injection",
            help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
            action="store_const",
            const=True,
        )

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """
        self._add_args_tls_versions(parser)
        self._add_args_workers(parser)

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
            WorkManager.register(ScanDhGroups)
            WorkManager.register(ScanCompression)
            WorkManager.register(ScanEncryptThenMac)
            WorkManager.register(ScanExtendedMasterSecret)
            WorkManager.register(ScanResumption)
            WorkManager.register(ScanRenegotiation)
            WorkManager.register(ScanCcsInjection)
            WorkManager.register(ScanEnd)

            config.set("sslv2", args.sslv2)
            config.set("sslv3", args.sslv3)
            config.set("tls10", args.tls10)
            config.set("tls11", args.tls11)
            config.set("tls12", args.tls12)
            config.set("tls13", args.tls13)

            # if no version is given at all: scan all versions by default
            if not any([config.get(version) for version in self._versions]):
                for version in self._versions:
                    config.set(version, True)

            config.set("dh_groups", args.dh_groups)
            config.set("compression", args.compression)
            config.set("encrypt_then_mac", args.encrypt_then_mac)
            config.set("ext_master_secret", args.ext_master_secret)
            config.set("renegotiation", args.renegotiation)
            config.set("resumption", args.resumption)
            config.set("ccs_injection", args.ccs_injection)

            # if no feature is given at all: scan all features by default
            if not any([config.get(feature) for feature in self._features]):
                for feature in self._features:
                    config.set(feature, True)
