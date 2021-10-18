# -*- coding: utf-8 -*-
"""Module for basic CLI arguments
"""
# import basic stuff
from pathlib import Path

# import own stuff
from tlsmate import utils
from tlsmate.structs import ConfigItem
from tlsmate.plugin import WorkManager, Plugin, Args, PluginBase
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
from tlsmate.workers.server_profile import DumpProfileWorker, ReadProfileWorker
from tlsmate.workers.text_server_profile import TextProfileWorker
from tlsmate.workers.eval_cipher_suites import ScanCipherSuites
from tlsmate.workers.scanner_info import ScanStart, ScanEnd
from tlsmate.workers.supported_groups import ScanSupportedGroups
from tlsmate.workers.sig_algo import ScanSigAlgs

# import other stuff


class PluginNoPlugin(Plugin):
    cli_args = Args(
        "--no-plugin",
        default=None,
        help="disable loading external plugins. Must be the first argument.",
        action="store_true",
    )


class PluginConfig(Plugin):
    cli_args = Args(
        "--config",
        dest="config_file",
        default=None,
        help="ini-file to read the configuration from.",
    )


class PluginLogging(Plugin):
    cli_args = Args(
        "--logging",
        choices=["critical", "error", "warning", "info", "debug"],
        help="sets the logging level. Default is error.",
        default="error",
    )


@PluginBase.extend
class PluginCore(Plugin):
    plugins = [PluginNoPlugin, PluginConfig, PluginLogging]


class PluginPort(Plugin):
    config = ConfigItem("port", type=int, default=443)
    cli_args = Args(
        "--port",
        default=None,
        help="the port number of the host [0-65535]. Defaults to 443.",
        type=int,
    )

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        if args.port is not None and (args.port < 0 or args.port > 0xFFFF):
            parser.error("port must be in the range [0-65535]")
        super().args_parsed(args, parser, subcommand, config)


class PluginInterval(Plugin):
    config = ConfigItem("interval", type=int, default=0)
    cli_args = Args(
        "--interval",
        default=0,
        help="the interval in milliseconds between two handshakes.",
        type=int,
    )


class PluginKeyLogFile(Plugin):
    config = ConfigItem("key_log_file", type=str)
    cli_args = Args(
        "--key-log-file",
        default=None,
        help=(
            "write to a key log file which can be used by wireshark to decode "
            "encrypted traffic."
        ),
    )


class PluginProgress(Plugin):
    config = ConfigItem("progress", type=bool, default=False)
    cli_args = Args(
        "--progress",
        help="provides a progress indicator. Defaults to False.",
        action=utils.BooleanOptionalAction,
    )


class PluginSni(Plugin):
    config = ConfigItem("sni", type=str, default=None)
    cli_args = Args(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of the server to "
            "contact. If not given, the value will be taken from the host "
            "parameter (after stripping of the port number, if present). This "
            "parameter is useful, if the host is given as an IP address."
        ),
    )


class PluginHost(Plugin):
    config = ConfigItem("host", type=str, default="localhost")
    cli_args = Args(
        "host",
        help=(
            "the host to scan. If an IPv6 address is given, it must be enclosed in "
            "square brackets. May optionally have the port number appended, "
            "separated by a colon. The port defaults to 443."
        ),
        type=str,
    )


class PluginBasicScan(Plugin):
    plugins = [
        PluginPort,
        PluginInterval,
        PluginKeyLogFile,
        PluginProgress,
        PluginSni,
        PluginHost,
    ]


class PluginReadProfile(Plugin):
    config = ConfigItem("read_profile", type=str, default=None)
    cli_args = Args(
        "--read-profile",
        type=str,
        help=(
            "JSON/Yaml file to read the server profile from. The format will be "
            "determined automatically."
        ),
    )
    workers = [ReadProfileWorker]


class PluginWriteProfile(Plugin):
    config = ConfigItem("write_profile", type=str, default=None)
    cli_args = Args(
        "--write-profile",
        type=str,
        help=(
            "writes the server profile to the given file. If no file is given, "
            'the profile will be dumped to STDOUT (unless "--format=none" is '
            "given)."
        ),
    )


class PluginFormat(Plugin):
    config = ConfigItem("format", type=str, default="text")
    cli_args = Args(
        "--format",
        choices=["text", "html", "json", "yaml", "none"],
        help=('the output format of the server profile. Defaults to "text".'),
        default=None,
    )

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)
        format_type = config.get("format")
        if format_type in ["text", "html"]:
            WorkManager.register(TextProfileWorker)
        elif format_type in ["json", "yaml"]:
            WorkManager.register(DumpProfileWorker)


class PluginColor(Plugin):
    config = ConfigItem("color", type=bool, default=True)
    cli_args = Args(
        "--color",
        help="use colored console output. Only used if --format=text is given.",
        action=utils.BooleanOptionalAction,
    )


class PluginStyle(Plugin):
    _DEFAULT_STYLE = Path(__file__).parent / "../styles/default.yaml"
    config = ConfigItem("style", type=str, default=str(_DEFAULT_STYLE.resolve()))
    cli_args = Args(
        "--style",
        type=str,
        help=(
            "a yaml file defining the text outout and the color scheme used if "
            "--format=text or --format=html is given. If not given, the internal "
            "default file will be used."
        ),
    )


class PluginServerProfile(Plugin):
    group = Args(title="Server profile options")
    plugins = [
        PluginReadProfile,
        PluginWriteProfile,
        PluginFormat,
        PluginColor,
        PluginStyle,
    ]


class PluginCaCerts(Plugin):
    config = ConfigItem("ca_certs", type="file_list")
    cli_args = Args(
        "--ca-certs",
        nargs="*",
        type=str,
        help=(
            "list of root-ca certificate files. Each file may contain multiple "
            "root-CA certificates in PEM format. Certificate chains received from "
            "the server will be validated against this set of root certificates."
        ),
    )


class PluginClientKey(Plugin):
    config = ConfigItem("client_key", type="file_list")
    cli_args = Args(
        "--client-key",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the client private keys in PEM format. "
            "Used for client authentication."
        ),
        default=None,
    )


class PluginClientChain(Plugin):
    config = ConfigItem("client_chain", type="file_list")
    cli_args = Args(
        "--client-chain",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the certificate chain used for client "
            "authentication in PEM format. The number of given files must be the "
            "same than the number of given client key files. This first given "
            "chain file corresponds to the first given client key file, and so on."
        ),
    )


class PluginCrl(Plugin):
    config = ConfigItem("crl", type=bool, default=True)
    cli_args = Args(
        "--crl",
        help=(
            "download the CRL to check for the certificate revocation status. "
            "Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class PluginOcsp(Plugin):
    config = ConfigItem("ocsp", type=bool, default=True)
    cli_args = Args(
        "--ocsp",
        help=(
            "query the OCSP servers for checking the certificate "
            "revocation status. Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class PluginX509(Plugin):
    group = Args(title="X509 certificates options")
    plugins = [PluginCaCerts, PluginClientKey, PluginClientChain, PluginCrl, PluginOcsp]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
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


class PluginSslv2(Plugin):
    config = ConfigItem("sslv2", type=bool, default=None)
    cli_args = Args(
        "--sslv2",
        help="scan for protocol version SSLv2",
        action=utils.BooleanOptionalAction,
    )


class PluginSslv3(Plugin):
    config = ConfigItem("sslv3", type=bool, default=None)
    cli_args = Args(
        "--sslv3",
        help="scan for protocol version SSLv3",
        action=utils.BooleanOptionalAction,
    )


class PluginTls10(Plugin):
    config = ConfigItem("tls10", type=bool, default=None)
    cli_args = Args(
        "--tls10",
        help="scan for protocol version TLS1.0",
        action=utils.BooleanOptionalAction,
    )


class PluginTls11(Plugin):
    config = ConfigItem("tls11", type=bool, default=None)
    cli_args = Args(
        "--tls11",
        help="scan for protocol version TLS1.1",
        action=utils.BooleanOptionalAction,
    )


class PluginTls12(Plugin):
    config = ConfigItem("tls12", type=bool, default=None)
    cli_args = Args(
        "--tls12",
        help="scan for protocol version TLS1.2",
        action=utils.BooleanOptionalAction,
    )


class PluginTls13(Plugin):
    config = ConfigItem("tls13", type=bool, default=None)
    cli_args = Args(
        "--tls13",
        help="scan for protocol version TLS1.3",
        action=utils.BooleanOptionalAction,
    )


class PluginTlsVersions(Plugin):
    group = Args(
        title="TLS protocol versions",
        description=(
            "The following options specify the TLS protocol versions to scan. "
            "By default all versions will be scanned, but if one version is "
            "explicitly set to true, all other versions will be defaulted to false."
        ),
    )
    plugins = [
        PluginSslv2,
        PluginSslv3,
        PluginTls10,
        PluginTls11,
        PluginTls12,
        PluginTls13,
    ]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)
        default = all([config.get(vers.config.name) is None for vers in cls.plugins])
        enabled = False
        for vers in cls.plugins:
            val = config.get(vers.config.name)
            if val is None:
                val = default
                config.set(vers.config.name, default)
            enabled = enabled or val

        if not enabled:
            parser.error("at least one TLS version must be given")


class PluginFeatures(Plugin):
    config = ConfigItem("features", type=bool, default=True)
    cli_args = Args(
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


class PluginCompression(Plugin):
    config = ConfigItem("compression", type=bool, default=None)
    cli_args = Args(
        "--compression",
        help="scan for compression support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanCompression]


class PluginDhGroup(Plugin):
    config = ConfigItem("dh_groups", type=bool, default=None)
    cli_args = Args(
        "--dh-groups",
        help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanDhGroups]


class PluginEncThenMac(Plugin):
    config = ConfigItem("encrypt_then_mac", type=bool, default=None)
    cli_args = Args(
        "--encrypt-then-mac",
        help="scan for encrypt-then-mac support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanEncryptThenMac]


class PluginEphemKeyReuse(Plugin):
    config = ConfigItem("ephemeral_key_reuse", type=bool, default=None)
    cli_args = Args(
        "--ephemeral-key-reuse",
        help="scan for reuse of ephemeral keys",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanEphemeralKeyReuse]


class PluginExtMasterSecret(Plugin):
    config = ConfigItem("ext_master_secret", type=bool, default=None)
    cli_args = Args(
        "--ext-master-secret",
        help="scan for extended master secret support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanExtendedMasterSecret]


class PluginFallback(Plugin):
    config = ConfigItem("fallback", type=bool, default=None)
    cli_args = Args(
        "--fallback",
        help="scan for downgrade attack prevention (TLS_FALLBACK_SCSV)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanDowngrade]


class PluginGrease(Plugin):
    config = ConfigItem("grease", type=bool, default=None)
    cli_args = Args(
        "--grease",
        help="scan for unknown parameter tolerance",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanGrease]


class PluginHeartbeat(Plugin):
    config = ConfigItem("heartbeat", type=bool, default=None)
    cli_args = Args(
        "--heartbeat",
        help="scan for heartbeat support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanHeartbeat]


class PluginOcspStapling(Plugin):
    config = ConfigItem("ocsp_stapling", type=bool, default=None)
    cli_args = Args(
        "--ocsp-stapling",
        help="scan for OCSP stapling support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanOcspStapling]


class PluginRenegotiation(Plugin):
    config = ConfigItem("renegotiation", type=bool, default=None)
    cli_args = Args(
        "--renegotiation",
        help="scan for renegotiation support (SSL30 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanRenegotiation]


class PluginResumption(Plugin):
    config = ConfigItem("resumption", type=bool, default=None)
    cli_args = Args(
        "--resumption",
        help=(
            "scan for resumption support (SSL30 - TLS1.2) and for PSK support (TLS1.3)"
        ),
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanResumption]


class PluginFeatureGroup(Plugin):
    group = Args(title="Feature to include into the scan")
    plugins = [
        PluginFeatures,
        PluginCompression,
        PluginDhGroup,
        PluginEncThenMac,
        PluginEphemKeyReuse,
        PluginExtMasterSecret,
        PluginFallback,
        PluginGrease,
        PluginHeartbeat,
        PluginOcspStapling,
        PluginRenegotiation,
        PluginResumption,
    ]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)

        plugins = cls.plugins[1:]
        default = config.get(PluginFeatures.config.name)
        if default is None:
            default = not any(config.get(feat.config.name) for feat in plugins)

        for feat in plugins:
            val = config.get(feat.config.name)
            if val is None:
                config.set(feat.config.name, default)
                if default and feat.workers:
                    for worker in feat.workers:
                        WorkManager.register(worker)


class PluginVulnerabilities(Plugin):
    config = ConfigItem("vulnerabilities", type=bool, default=True)
    cli_args = Args(
        "--vulnerabilities",
        help=(
            "specifies whether to include or exclude all vulnerabilities in the "
            "scan. Per vulnerability this behavior can be overruled by its "
            "specific command line option below. Defaults to true if no specific "
            "vulnerability is enabled, otherwise it defaults to false."
        ),
        action=utils.BooleanOptionalAction,
    )


class PluginCcsInjection(Plugin):
    config = ConfigItem("ccs_injection", type=bool, default=None)
    cli_args = Args(
        "--ccs-injection",
        help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanCcsInjection]


class PluginHeartbleed(Plugin):
    config = ConfigItem("heartbleed", type=bool, default=None)
    cli_args = Args(
        "--heartbleed",
        help="scan for the Heartbleed vulnerability CVE-2014-0160",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanHeartbleed]


class PluginPaddingOracle(Plugin):
    config = ConfigItem("padding_oracle", type=bool, default=None)
    cli_args = Args(
        "--padding-oracle",
        help="scan for CBC padding oracles",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanPaddingOracle]


class PluginPaddingOracleAccuracy(Plugin):
    config = ConfigItem("oracle_accuracy", type=str, default="medium")
    cli_args = Args(
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
    )


class PluginRobot(Plugin):
    config = ConfigItem("robot", type=bool, default=None)
    cli_args = Args(
        "--robot",
        help=(
            "scan for ROBOT vulnerability CVE-2017-13099, etc. (only TL1.0 - TLS1.2)"
        ),
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanRobot]


class PluginVulnerabilityGroup(Plugin):
    group = Args(title="Vulnerabilities to scan for")
    plugins = [
        PluginVulnerabilities,
        PluginCcsInjection,
        PluginHeartbleed,
        PluginPaddingOracle,
        PluginPaddingOracleAccuracy,
        PluginRobot,
    ]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)

        plugins = cls.plugins[:]
        plugins.remove(PluginVulnerabilities)
        plugins.remove(PluginPaddingOracleAccuracy)

        default = config.get(PluginVulnerabilities.config.name)
        if default is None:
            default = not any(config.get(vuln.config.name) for vuln in plugins)

        for vuln in plugins:
            val = config.get(vuln.config.name)
            if val is None:
                config.set(vuln.config.name, default)
                if default and vuln.workers:
                    for worker in vuln.workers:
                        WorkManager.register(worker)


@PluginBase.extend
class PluginScan(Plugin):
    subcommand = Args("scan", help="performs a TLS server scan")
    plugins = [
        PluginBasicScan,
        PluginX509,
        PluginTlsVersions,
        PluginFeatureGroup,
        PluginVulnerabilityGroup,
        PluginServerProfile,
    ]
    workers = [ScanStart, ScanCipherSuites, ScanSupportedGroups, ScanSigAlgs, ScanEnd]
