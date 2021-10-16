# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff
from pathlib import Path

# import own stuff
from tlsmate import utils
from tlsmate.structs import ConfigItem
from tlsmate.plugin import WorkManager, CliPlugin
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
from tlsmate.workers.ephemeral_key_reuse import ScanEphemeralKeyReuse
from tlsmate.workers.ocsp_stapling import ScanOcspStapling
from tlsmate.workers.downgrade import ScanDowngrade
from tlsmate.workers.server_profile import DumpProfileWorker
from tlsmate.workers.text_server_profile import TextProfileWorker

# import other stuff


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

class CliArg(object):

    def __init__(self, name, **attributes):
        self._name = name
        self._attributes = attributes

    def add_argument(self, parser, exclude=None):
        if not (exclude and self._name in exclude):
            parser.add_argument(self._name, **self._attributes)

        else:
            dest = self._attributes.get("dest")
            if not dest:
                dest = self._name.lower().replace("-", "_")

            if dest.startswith("__"):
                dest = dest[2:]

            default = self._attributes.get("default", None)
            parser.set_defaults(**{dest: default})

class BasicOptions(CliPlugin):

    cli_args = [
        CliArg(
            "--port",
            default=None,
            help="the port number of the host [0-65535]. Defaults to 443.",
            type=int,
        ),
        CliArg(
            "--interval",
            default=0,
            help="the interval in milliseconds between two handshakes.",
            type=int,
        ),
        CliArg(
            "--key-log-file",
            default=None,
            help=(
                "write to a key log file which can be used by wireshark to decode "
                "encrypted traffic."
            ),
        ),
        CliArg(
            "--progress",
            help="provides a progress indicator. Defaults to False.",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--sni",
            type=str,
            help=(
                "the server name indication, i.e., the domain name of the server to "
                "contact. If not given, the value will be taken from the host "
                "parameter (after stripping of the port number, if present). This "
                "parameter is useful, if the host is given as an IP address."
            ),
        ),
        CliArg(
            "host",
            help=(
                "the host to scan. If an IPv6 address is given, it must be enclosed in "
                "square brackets. May optionally have the port number appended, "
                "separated by a colon. The port defaults to 443."
            ),
            type=str,
        ),
    ]

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        """Add basic arguments to a parser

        Arguments:
            parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
        """

        for arg in cls.cli_args:
            arg.add_argument(parser, exclude)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        if args.port is not None and (args.port < 0 or args.port > 0xFFFF):
            parser.error("port must be in the range [0-65535]")

        config.set("host", args.host)
        config.set("port", args.port)
        config.set("interval", args.interval)
        config.set("key_log_file", args.key_log_file)
        config.set("progress", args.progress)
        config.set("sni", args.sni)


class ServerProfileOptions(CliPlugin):
    """Class to implement CLI arguments for server profile options.
    """

    _DEFAULT_STYLE = Path(__file__).parent / "../styles/default.yaml"
    _config_registered = False

    cli_args = [
        CliArg(
            "--read-profile",
            type=str,
            help=(
                "JSON/Yaml file to read the server profile from. The format will be "
                "determined automatically."
            ),
        ),
        CliArg(
            "--write-profile",
            type=str,
            help=(
                "writes the server profile to the given file. If no file is given, "
                'the profile will be dumped to STDOUT (unless "--format=none" is '
                "given)."
            ),
        ),
        CliArg(
            "--format",
            choices=["text", "html", "json", "yaml", "none"],
            help=('the output format of the server profile. Defaults to "text".'),
            default=None,
        ),
        CliArg(
            "--color",
            help="use colored console output. Only used if --format=text is given.",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--style",
            type=str,
            help=(
                "a yaml file defining the text outout and the color scheme used if "
                "--format=text or --format=html is given. If not given, the internal "
                "default file will be used."
            ),
        ),
    ]

    @classmethod
    def register_config(cls, config):
        if cls._config_registered:
            return

        config.register(ConfigItem("write_profile", type=str, default=None))
        config.register(ConfigItem("read_profile", type=str, default=None))
        config.register(ConfigItem("format", type=str, default="text"))
        config.register(ConfigItem("color", type=bool, default=True))
        config.register(
            ConfigItem("style", type=str, default=str(cls._DEFAULT_STYLE.resolve()))
        )
        cls._config_registered = True

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        group = parser.add_argument_group(
            title="Server profile options", description=None
        )
        if exclude is None:
            exclude = []

        exclude.append("--read-profile")
        for arg in cls.cli_args:
            arg.add_argument(group, exclude)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        config.set("format", args.format)
        config.set("write_profile", args.write_profile)
        config.set("read_profile", args.read_profile)
        config.set("color", args.color)
        config.set("style", args.style)

        if args.read_profile is not None:
            WorkManager.register(ReadProfileWorker)

        format_type = config.get("format")
        if format_type in ["text", "html"]:
            WorkManager.register(TextProfileWorker)
        elif format_type in ["json", "yaml"]:
            WorkManager.register(DumpProfileWorker)


class X509Options(CliPlugin):
    """Class to implement CLI arguments for X509 certificate options.
    """

    cli_args = [
        CliArg(
            "--ca-certs",
            nargs="*",
            type=str,
            help=(
                "list of root-ca certificate files. Each file may contain multiple "
                "root-CA certificates in PEM format. Certificate chains received from "
                "the server will be validated against this set of root certificates."
            ),
        ),
        CliArg(
            "--client-key",
            type=str,
            nargs="*",
            help=(
                "a list of files containing the client private keys in PEM format. "
                "Used for client authentication."
            ),
            default=None,
        ),
        CliArg(
            "--client-chain",
            type=str,
            nargs="*",
            help=(
                "a list of files containing the certificate chain used for client "
                "authentication in PEM format. The number of given files must be the "
                "same than the number of given client key files. This first given "
                "chain file corresponds to the first given client key file, and so on."
            ),
        ),
        CliArg(
            "--crl",
            help=(
                "download the CRL to check for the certificate revocation status. "
                "Defaults to True."
            ),
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--ocsp",
            help=(
                "query the OCSP servers for checking the certificate "
                "revocation status. Defaults to True."
            ),
            action=utils.BooleanOptionalAction,
        ),
    ]

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        """Add basic arguments for authentication to a parser

        Arguments:
            parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
        """

        group = parser.add_argument_group(title="X509 certificates options")
        for arg in cls.cli_args:
            arg.add_argument(group, exclude)

    @classmethod
    def _args_consistency(cls, args, parser):
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

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        cls._args_consistency(args, parser)
        config.set("ca_certs", args.ca_certs)
        config.set("client_chain", args.client_chain)
        config.set("client_key", args.client_key)
        config.set("crl", args.crl)
        config.set("ocsp", args.ocsp)


class TlsVersions(CliPlugin):

    cli_args = [
        CliArg(
            "--sslv2",
            help="scan for protocol version SSLv2",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--sslv3",
            help="scan for protocol version SSLv3",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--tls10",
            help="scan for protocol version TLS1.0",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--tls11",
            help="scan for protocol version TLS1.1",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--tls12",
            help="scan for protocol version TLS1.2",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--tls13",
            help="scan for protocol version TLS1.3",
            action=utils.BooleanOptionalAction,
        ),
    ]
    _versions = [arg._name[2:] for arg in cli_args]


    @classmethod
    def register_config(cls, config):
        for vers in cls._versions:
            config.register(ConfigItem(vers, type=bool, default=None))

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        """Add basic arguments for TLS versions to a parser

        Arguments:
            parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
        """

        group = parser.add_argument_group(
            title="TLS protocol versions",
            description=(
                "The following options specify the TLS protocol versions to scan. "
                "By default all versions will be scanned, but if one version is "
                "explicitly set to true, all other versions will be defaulted to false."
            ),
        )
        for arg in cls.cli_args:
            arg.add_argument(group, exclude)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        versions = _group_applicability(args, config, None, cls._versions)
        _ = [config.set(key, val) for key, val in versions.items()]
        if not any([config.get(key) for key in cls._versions]):
            parser.error("at least one TLS version must be given")


class Features(CliPlugin):

    cli_args = [
        CliArg(
            "--features",
            help=(
                "specifies whether to include or exclude all features in the scan. "
                "Per feature this behavior can be overruled by its specific command "
                "line option below. "
                "Defaults to true if no specific feature is enabled, otherwise it "
                "defaults to false."
            ),
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--compression",
            help="scan for compression support",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--dh-groups",
            help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--encrypt-then-mac",
            help="scan for encrypt-then-mac support (only TL1.0 - TLS1.2)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--ephemeral-key-reuse",
            help="scan for reuse of ephemeral keys",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--ext-master-secret",
            help="scan for extended master secret support (only TL1.0 - TLS1.2)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--fallback",
            help="scan for downgrade attack prevention (TLS_FALLBACK_SCSV)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--grease",
            help="scan for unknown parameter tolerance",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--heartbeat",
            help="scan for heartbeat support",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--ocsp-stapling",
            help="scan for OCSP stapling support",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--renegotiation",
            help="scan for renegotiation support (SSL30 - TLS1.2)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--resumption",
            help=(
                "scan for resumption support (SSL30 - TLS1.2) and for PSK support "
                "(TLS1.3)"
            ),
            action=utils.BooleanOptionalAction,
        ),
    ]

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

    @classmethod
    def register_config(cls, config):
        for feature in cls._feature_workers.keys():
            config.register(ConfigItem(feature, type=bool, default=None))

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        """Add arguments for using different workers to a parser

        Arguments:
            parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
        """

        group = parser.add_argument_group(title="Feature to include into the scan",)
        for arg in cls.cli_args:
            arg.add_argument(group, exclude)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        features = _group_applicability(
            args, config, args.features, cls._feature_workers.keys()
        )
        _group_register_workers(config, cls._feature_workers, features)


class Vulnerabilities(CliPlugin):

    cli_args = [
        CliArg(
            "--vulnerabilities",
            help=(
                "specifies whether to include or exclude all vulnerabilities in the "
                "scan. Per vulnerability this behavior can be overruled by its "
                "specific command line option below. Defaults to true if no specific "
                "vulnerability is enabled, otherwise it defaults to false."
            ),
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--ccs-injection",
            help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--heartbleed",
            help="scan for the Heartbleed vulnerability CVE-2014-0160",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--padding-oracle",
            help="scan for CBC padding oracles",
            action=utils.BooleanOptionalAction,
        ),
        CliArg(
            "--oracle-accuracy",
            help=(
                "the accuracy of the scan for CBC padding oracles. "
                "low: scan application data records for each TLS version with minimal "
                "set of cipher suites (fastest). "
                "medium: scan application data records for each TLS version and cipher "
                "suite combination (slower). "
                "high: scan application data, handshake and alert records for each TLS "
                "version and cipher suite combination (slowest). "
                "Default is medium."
            ),
            choices=["low", "medium", "high"],
            default="medium",
        ),
        CliArg(
            "--robot",
            help=(
                "scan for ROBOT vulnerability CVE-2017-13099, etc. (only TL1.0 "
                "- TLS1.2)"
            ),
            action=utils.BooleanOptionalAction,
        )
    ]
    _vulnerability_workers = {
        "ccs_injection": ScanCcsInjection,
        "robot": ScanRobot,
        "heartbleed": ScanHeartbleed,
        "padding_oracle": ScanPaddingOracle,
    }

    @classmethod
    def register_config(cls, config):
        for vulnerability in cls._vulnerability_workers.keys():
            config.register(ConfigItem(vulnerability, type=bool, default=None))

        config.register(ConfigItem("oracle_accuracy", type=str, default="medium"))

    @classmethod
    def add_args(cls, parser, subcommand, exclude=None):
        """Add arguments for vulnerabilities to a parser

        Arguments:
            parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
        """
        group = parser.add_argument_group(title="Vulnerabilities to scan for")
        for arg in cls.cli_args:
            arg.add_argument(group, exclude)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        vulns = _group_applicability(
            args, config, args.vulnerabilities, cls._vulnerability_workers.keys(),
        )
        _group_register_workers(config, cls._vulnerability_workers, vulns)

        config.set("oracle_accuracy", args.oracle_accuracy)
