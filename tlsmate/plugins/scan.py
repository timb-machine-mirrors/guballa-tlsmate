# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff
from pathlib import Path

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
from tlsmate.workers.padding_oracle import ScanPaddingOracle
from tlsmate.workers.dh_params import ScanDhGroups
from tlsmate.workers.heartbeat import ScanHeartbeat
from tlsmate.workers.heartbleed import ScanHeartbleed
from tlsmate.workers.grease import ScanGrease
from tlsmate.workers.server_profile import DumpProfileWorker
from tlsmate.workers.text_server_profile import TextProfileWorker
from tlsmate.workers.ephemeral_key_reuse import ScanEphemeralKeyReuse
from tlsmate.workers.ocsp_stapling import ScanOcspStapling
from tlsmate.workers.downgrade import ScanDowngrade

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
            "set to true, all other versions will be defaulted to false."
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

    group = parser.add_argument_group(title="Feature to include into the scan",)
    group.add_argument(
        "--features",
        help=(
            "specifies whether to include or exclude all features in the scan. "
            "Per feature this behavior can be overruled by its specific command "
            "line option below. "
            "Defaults to true if no specific feature is enabled, otherwise it "
            "defaults to false."
        ),
        action=utils.BooleanOptionalAction,
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
        "--ephemeral-key-reuse",
        help="scan for reuse of ephemeral keys",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--ext-master-secret",
        help="scan for extended master secret support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--fallback",
        help="scan for downgrade attack prevention (TLS_FALLBACK_SCSV)",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--grease",
        help="scan for unknown parameter tolerance",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--heartbeat",
        help="scan for heartbeat support",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--ocsp-stapling",
        help="scan for OCSP stapling support",
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


def _add_args_vulenerabilities(parser):
    """Add arguments for vulnerabilities to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """
    group = parser.add_argument_group(title="Vulnerabilities to scan for")
    group.add_argument(
        "--vulnerabilities",
        help=(
            "specifies whether to include or exclude all vulnerabilities in the scan. "
            "Per vulnerability this behavior can be overruled by its specific command "
            "line option below. "
            "Defaults to true if no specific vulnerability is enabled, otherwise it "
            "defaults to false."
        ),
        action=utils.BooleanOptionalAction,
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
        "--padding-oracle",
        help="scan for CBC padding oracles",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--oracle-accuracy",
        help=(
            "the accuracy of the scan for CBC padding oracles. "
            "low: scan application data records for each TLS version with minimal set "
            "of cipher suites (fastest). "
            "medium: scan application data records for each TLS version and cipher "
            "suite combination (slower). "
            "high: scan application data, handshake and alert records for each TLS "
            "version and cipher suite combination (slowest). "
            "Default is medium."
        ),
        choices=["low", "medium", "high"],
        default="medium",
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
        choices=["text", "html", "json", "yaml", "none"],
        help=('the output format of the server profile. Defaults to "text".'),
        default=None,
    )
    group.add_argument(
        "--color",
        help="use colored console output. Only used if --format=text is given.",
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--style",
        type=str,
        help=(
            "a yaml file defining the text outout and the color scheme used if "
            "--format=text or --format=html is given. If not given, the internal "
            "default file will be used."
        ),
    )


def _group_applicability(args, config, default, options):
    """Applies defaults to a group of boolean-option parameters

    Arguments:
        args: the object holding the parsed CLI arguments
        config (:obj:`tlsmate.config.Configuration`): the configuration object
        default (boolean or None): the default to apply for unspecified options
        options (list of str): a list with the boolean-option parameter names

    Returns:
        dict: contains for each boolean-option parameter name the applicability (bool)
    """

    opts = {key: getattr(args, key) for key in options}
    opts = {key: config.get(key) if val is None else val for key, val in opts.items()}

    if default is None:
        default = not any(opts.values())

    return {key: default if val is None else val for key, val in opts.items()}


def _group_register_workers(config, workers, applicability):
    """Register workers according to their applicability

    Arguments:
        config (:obj:`tlsmate.config.Configuration`): the configuration object
        workers (dict): maps a worker name (str) to a worker class
        applicability (dict): maps a a worker name (str) to its applicability (bool)
    """

    for key, val in applicability.items():
        config.set(key, val)
        if val:
            WorkManager.register(workers[key])


@CliManager.register
class ScanPlugin(CliConnectionPlugin):
    """CLI plugin to perform a scan against a TLS server.
    """

    prio = 20
    name = "scan"

    _DEFAULT_STYLE = Path(__file__).parent / "../styles/default.yaml"

    _versions = ["sslv2", "sslv3", "tls10", "tls11", "tls12", "tls13"]
    _feature_workers = {
        "dh_groups": ScanDhGroups,
        "compression": ScanCompression,
        "encrypt_then_mac": ScanEncryptThenMac,
        "ext_master_secret": ScanExtendedMasterSecret,
        "renegotiation": ScanRenegotiation,
        "resumption": ScanResumption,
        "heartbeat": ScanHeartbeat,
        "ephemeral_key_reuse": ScanEphemeralKeyReuse,
        "ocsp_stapling": ScanOcspStapling,
        "fallback": ScanDowngrade,
        "grease": ScanGrease,
    }
    _vulnerability_workers = {
        "ccs_injection": ScanCcsInjection,
        "robot": ScanRobot,
        "heartbleed": ScanHeartbleed,
        "padding_oracle": ScanPaddingOracle,
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
            config.register(ConfigItem(item, type=bool, default=None))

        # config items for the server profile
        config.register(ConfigItem("write_profile", type=str, default=None))
        # config.register(ConfigItem("read_profile", type=str, default=None))
        config.register(ConfigItem("format", type=str, default="text"))
        config.register(ConfigItem("color", type=bool, default=True))
        config.register(
            ConfigItem("style", type=str, default=str(self._DEFAULT_STYLE.resolve()))
        )
        config.register(ConfigItem("oracle_accuracy", type=str, default="medium"))

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

            versions = _group_applicability(args, config, None, self._versions)
            _ = [config.set(key, val) for key, val in versions.items()]
            if not any([config.get(key) for key in self._versions]):
                parser.error("at least one TLS version must be given")

            features = _group_applicability(
                args, config, args.features, self._feature_workers.keys()
            )
            _group_register_workers(config, self._feature_workers, features)

            vulns = _group_applicability(
                args, config, args.vulnerabilities, self._vulnerability_workers.keys(),
            )
            _group_register_workers(config, self._vulnerability_workers, vulns)

            config.set("oracle_accuracy", args.oracle_accuracy)

            # handle server profile
            config.set("format", args.format)
            config.set("write_profile", args.write_profile)
            # config.set("read_profile", args.read_profile)
            config.set("color", args.color)
            config.set("style", args.style)

            # if args.read_profile is not None:
            #     WorkManager.register(ReadProfileWorker)

            format_type = config.get("format")
            if format_type in ["text", "html"]:
                WorkManager.register(TextProfileWorker)

            elif format_type in ["json", "yaml"]:
                WorkManager.register(DumpProfileWorker)
