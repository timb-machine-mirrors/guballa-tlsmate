# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.structs import ConfigItem
from tlsmate.plugin import CliPlugin, WorkManager, CliManager
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
from tlsmate.workers.robot import ScanRobot
from tlsmate.workers.dh_params import ScanDhGroups
from tlsmate.workers.text_server_profile import TextProfileWorker

# import other stuff


@CliManager.register
class ScanPlugin(CliPlugin):
    """CLI plugin to perform a scan against a TLS server.
    """

    prio = 20
    name = "scan"
    cli_name = "--scan"
    cli_help = "scan for TLS server configurations, features and vulnerabilities"

    _versions = ["sslv2", "sslv3", "tls10", "tls11", "tls12", "tls13"]
    _feature_workers = {
        "dh_groups": ScanDhGroups,
        "compression": ScanCompression,
        "encrypt_then_mac": ScanEncryptThenMac,
        "ext_master_secret": ScanExtendedMasterSecret,
        "renegotiation": ScanRenegotiation,
        "resumption": ScanResumption,
        "ccs_injection": ScanCcsInjection,
        "robot": ScanRobot,
    }

    def register_config(self, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """
        for version in self._versions:
            config.register(ConfigItem(version, type=bool, default=False))

        for feature in self._feature_workers.keys():
            config.register(ConfigItem(feature, type=bool, default=False))

    def _add_args_tls_versions(self, parser):
        group = parser.add_argument_group(
            title='TLS protocol versions for the "--scan" option',
            description=(
                "The following options specify the TLS protocol versions to scan. "
                "If none of the versions is given then by default all protocol "
                "versions will be scanned."
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

    def _add_args_features(self, parser):
        group = parser.add_argument_group(
            title='Feature to include for the "--scan" option',
            description=(
                "The following options specify which features to include in the scan. "
                "If none of the features is given then by default all features "
                "will be included. Note: TLS protocol versions, cipher suites, "
                "supported groups, signature algorithms and certificates will always "
                "be included in the scan."
            ),
        )
        group.add_argument(
            "--compression",
            help="scan for compression support",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--dh-groups",
            help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
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
            help=(
                "scan for resumption support (SSL30 - TLS1.2) and for PSK support "
                "(TLS1.3)"
            ),
            action="store_const",
            const=True,
        )

    def _add_args_vulenerabilities(self, parser):
        group = parser.add_argument_group(
            title='Vulnerabilities to include for the "--scan" option',
            description=(
                "The following options specify which vulnerabilities to scan for. "
                "If none of the vulnerabilities is given then by default all "
                "vulnerabilities will be scanned."
            ),
        )
        group.add_argument(
            "--ccs-injection",
            help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
            action="store_const",
            const=True,
        )
        group.add_argument(
            "--robot",
            help=(
                "scan for ROBOT vulnerability CVE-2017-13099, etc. (only TL1.0 "
                "- TLS1.2)"
            ),
            action="store_const",
            const=True,
        )

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        self._add_args_tls_versions(parser)
        self._add_args_features(parser)
        self._add_args_vulenerabilities(parser)

    def args_parsed(self, args, parser, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser: the parser object, can be used to issue consistency errors
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if args.scan:
            WorkManager.register(ScanStart)
            WorkManager.register(ScanCipherSuites)
            WorkManager.register(ScanSupportedGroups)
            WorkManager.register(ScanSigAlgs)
            WorkManager.register(ScanEnd)

            for version in self._versions:
                config.set(version, getattr(args, version))

            # if no version is given at all: scan all versions by default
            if not any([config.get(version) for version in self._versions]):
                for version in self._versions:
                    config.set(version, True)

            for feature in self._feature_workers.keys():
                config.set(feature, getattr(args, feature))

            # if no feature is given at all: scan all features by default
            if not any(
                [config.get(feature) for feature in self._feature_workers.keys()]
            ):
                for feature in self._feature_workers.keys():
                    config.set(feature, True)

            for feature, worker in self._feature_workers.items():
                if config.get(feature):
                    WorkManager.register(worker)

            if config.get("format") is None:
                WorkManager.register(TextProfileWorker)
