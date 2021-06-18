# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate import utils
from tlsmate.structs import ConfigItem
from tlsmate.plugin import CliConnectionPlugin, WorkManager, CliManager
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
from tlsmate.workers.heartbeat import ScanHeartbeat
from tlsmate.workers.heartbleed import ScanHeartbleed
from tlsmate.workers.grease import ScanGrease
from tlsmate.workers.server_profile import DumpProfileWorker
from tlsmate.workers.text_server_profile import TextProfileWorker

# import other stuff


def _add_args_tls_versions(parser):
    """Add basic arguments for TLS versions to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    group = parser.add_argument_group(
        title="TLS protocol versions",
        description=(
            "The following options specify the TLS protocol versions to scan. "
            "By default all versions will be scanned, but if one version is explicitly "
            "set to True, all other versions will be defaulted to False."
        ),
    )
    group.add_argument(
        "--sslv2",
        help="scan for protocol version SSLv2",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--sslv3",
        help="scan for protocol version SSLv3",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--tls10",
        help="scan for protocol version TLS1.0",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--tls11",
        help="scan for protocol version TLS1.1",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--tls12",
        help="scan for protocol version TLS1.2",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--tls13",
        help="scan for protocol version TLS1.3",
        action=utils.BooleanOptionalAction,
    )


def _add_args_features(parser):
    """Add arguments for using different workers to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    group = parser.add_argument_group(
        title="Feature to include into the scan",
        description=(
            "The following options specify which features to include in the scan. "
            "By default all features will be scanned, but if one feature is explicitly "
            "set to True, all other features will be defaulted to False."
        ),
    )
    group.add_argument(
        "--compression",
        help="scan for compression support",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--dh-groups",
        help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--encrypt-then-mac",
        help="scan for encrypt-then-mac support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--ext-master-secret",
        help="scan for extended master secret support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--renegotiation",
        help="scan for renegotiation support (SSL30 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--resumption",
        help=(
            "scan for resumption support (SSL30 - TLS1.2) and for PSK support "
            "(TLS1.3)"
        ),
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--heartbeat",
        help="scan for heartbeat support",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--grease",
        help="scan for unknown parameter tolerance",
        action=utils.BooleanOptionalAction,
    )


def _add_args_vulenerabilities(parser):
    """Add arguments for vulnerabilities to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """
    group = parser.add_argument_group(
        title="Vulnerabilities to scan for",
        description=(
            "The following options specify which vulnerabilities to scan for. "
            "By default tlsmate will scan for all vulnerabilities, but if one "
            "vulnerability is explicitly set to True, all other vulnerabilities will "
            "be defaulted to False."
        ),
    )
    group.add_argument(
        "--ccs-injection",
        help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--heartbleed",
        help="scan for the Heartbleed vulnerability CVE-2014-0160",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--robot",
        help=(
            "scan for ROBOT vulnerability CVE-2017-13099, etc. (only TL1.0 " "- TLS1.2)"
        ),
        action=utils.BooleanOptionalAction,
    )


def _add_args_server_profile(parser):
    """Add arguments for the server profile to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    group = parser.add_argument_group(title="Server profile options", description=None)
    # group.add_argument(
    #     "--read-profile",
    #     type=str,
    #     help=(
    #         "JSON/Yaml file to read the server profile from. The format will be "
    #         "determined automatically."
    #     ),
    # )
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
        choices=["text", "json", "yaml", "none"],
        help=('the output format of the server profile. Defaults to "text".'),
        default=None,
    )
    group.add_argument(
        "--color",
        help="use colored console output. Only used if --format=text is given.",
        action=utils.BooleanOptionalAction,
    )


@CliManager.register
class ScanPlugin(CliConnectionPlugin):
    """CLI plugin to perform a scan against a TLS server.
    """

    prio = 20
    name = "scan"

    _versions = ["sslv2", "sslv3", "tls10", "tls11", "tls12", "tls13"]
    _feature_workers = {
        "dh_groups": ScanDhGroups,
        "compression": ScanCompression,
        "encrypt_then_mac": ScanEncryptThenMac,
        "ext_master_secret": ScanExtendedMasterSecret,
        "renegotiation": ScanRenegotiation,
        "resumption": ScanResumption,
        "heartbeat": ScanHeartbeat,
        "ccs_injection": ScanCcsInjection,
    }
    _vulnerability_workers = {
        "robot": ScanRobot,
        "heartbleed": ScanHeartbleed,
        "grease": ScanGrease,
    }

    def register_config(self, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        for item in (
            self._versions
            + list(self._feature_workers.keys())
            + list(self._vulnerability_workers.keys())
        ):
            config.register(ConfigItem(item, type=bool, default=False))

        # config items for the server profile
        config.register(ConfigItem("write_profile", type=str, default=None))
        # config.register(ConfigItem("read_profile", type=str, default=None))
        config.register(ConfigItem("format", type=str, default="text"))
        config.register(ConfigItem("color", type=bool, default=True))

    def add_subcommand(self, subparsers):
        """Adds a subcommand to the CLI parser object.

        Arguments:
            subparser (:obj:`argparse.Action`): the CLI subparsers object
        """

        subparsers.add_parser(self.name, help="performs a TLS server scan")

    def add_args(self, parser, subcommand):
        """A callback method used to add arguments to the CLI parser object.

        This method is called to allow the CLI plugin to add additional command line
        argument to the parser.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
            subcommand (str): the subcommand for which arguments can be added. If None,
                the global arguments (valid for all subcommands) can be added.
        """

        if subcommand == self.name:
            super().add_args(parser, subcommand)
            _add_args_tls_versions(parser)
            _add_args_features(parser)
            _add_args_vulenerabilities(parser)
            _add_args_server_profile(parser)

    def _args_consistency(self, args, parser):
        """Check the consistency of the given args which cannot be checked by argparse.

        Arguments:
            args (object): the arguments parsed as an object
            parser (:obj:`argparse.ArgumentParser`): the parser object
        """
        if (args.client_key is not None) or (args.client_chain is not None):
            if (args.client_chain is None) or (args.client_chain is None):
                parser.error(
                    "if --client-key is given, --client-chain must be given as well, "
                    "and vice versa"
                )
            if len(args.client_key) != len(args.client_chain):
                parser.error(
                    "number of arguments for --client-key and --client-chain must "
                    "be identical"
                )

    def args_parsed(self, args, parser, subcommand, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser: the parser object, can be used to issue consistency errors
            subcommand (str): the subcommand selected by the user
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if subcommand == self.name:
            super().args_parsed(args, parser, subcommand, config)
            self._args_consistency(args, parser)
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

            # features
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

            # vulnerabilities
            for vulnerability in self._vulnerability_workers.keys():
                config.set(vulnerability, getattr(args, vulnerability))

            # if no vulnerability is given at all: scan all vulnerabilities by default
            if not any(
                [
                    config.get(vulnerability)
                    for vulnerability in self._vulnerability_workers.keys()
                ]
            ):
                for vulnerability in self._vulnerability_workers.keys():
                    config.set(vulnerability, True)

            for vulnerability, worker in self._vulnerability_workers.items():
                if config.get(vulnerability):
                    WorkManager.register(worker)

            # handle server profile
            config.set("format", args.format)
            config.set("write_profile", args.write_profile)
            # config.set("read_profile", args.read_profile)
            config.set("color", args.color)

            # if args.read_profile is not None:
            #     WorkManager.register(ReadProfileWorker)

            format_type = config.get("format")
            if format_type == "text":
                WorkManager.register(TextProfileWorker)

            elif format_type in ["json", "yaml"]:
                WorkManager.register(DumpProfileWorker)
