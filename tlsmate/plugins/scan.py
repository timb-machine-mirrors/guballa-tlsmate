# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff
from pathlib import Path

# import own stuff
from tlsmate import utils
from tlsmate.structs import ConfigItem
from tlsmate.plugin import BaseCommand, Plugin, Args, WorkManager
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
from tlsmate.workers.base_vulnerabilities import ScanBaseVulnerabilities
from tlsmate.config import (
    config_host,
    config_port,
    config_interval,
    config_key_log_file,
    config_progress,
    config_sni,
    config_ca_certs,
    config_client_key,
    config_client_chain,
    config_crl,
    config_ocsp,
)


class ArgPort(Plugin):
    """Argument for port.
    """

    config = config_port
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


class ArgInterval(Plugin):
    """Argument for interval.
    """

    config = config_interval
    cli_args = Args(
        "--interval",
        default=0,
        help="the interval in milliseconds between two handshakes.",
        type=int,
    )


class ArgKeyLogFile(Plugin):
    """Argument for key logging file.
    """

    config = config_key_log_file
    cli_args = Args(
        "--key-log-file",
        default=None,
        help=(
            "write to a key log file which can be used by wireshark to decode "
            "encrypted traffic."
        ),
    )


class ArgProgress(Plugin):
    """Argument for progress.
    """

    config = config_progress
    cli_args = Args(
        "--progress",
        help="provides a progress indicator. Defaults to False.",
        action=utils.BooleanOptionalAction,
    )


class ArgSni(Plugin):
    """Argument for sni.
    """

    config = config_sni
    cli_args = Args(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of the server to "
            "contact. If not given, the value will be taken from the host "
            "parameter. This parameter is useful, if the host is given as an "
            "IP address."
        ),
    )


class ArgHost(Plugin):
    """Argument for host.
    """

    config = config_host
    cli_args = Args(
        "host",
        help=(
            "the target host. Can be given as a domain name or as an IPv4/IPv6 address."
        ),
        type=str,
    )


class GroupBasicScan(Plugin):
    """Group for basic arguments.
    """

    plugins = [
        ArgPort,
        ArgInterval,
        ArgKeyLogFile,
        ArgProgress,
        ArgSni,
        ArgHost,
    ]


class ArgReadProfile(Plugin):
    """Argument for read-profile.
    """

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


class ArgWriteProfile(Plugin):
    """Argument for write-profile.
    """

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


class ArgFormat(Plugin):
    """Argument for format.
    """

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


class ArgColor(Plugin):
    """Argument for color.
    """

    config = ConfigItem("color", type=bool, default=True)
    cli_args = Args(
        "--color",
        help=(
            "use colored console output. Only used if --format=text is given. "
            "Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class ArgStyle(Plugin):
    """Argument for style.
    """

    _DEFAULT_STYLE = Path(__file__).parent / "../styles/default.yaml"
    config = ConfigItem("style", type=str, default=str(_DEFAULT_STYLE.resolve()))
    cli_args = Args(
        "--style",
        type=str,
        help=(
            "a yaml file defining the text output and the color scheme used if "
            "--format=text or --format=html is given. If not given, the internal "
            "default file will be used."
        ),
    )


class GroupServerProfile(Plugin):
    """Argument group for server profile arguments.
    """

    group = Args(title="Server profile options")
    plugins = [
        ArgWriteProfile,
        ArgFormat,
        ArgColor,
        ArgStyle,
    ]


class ArgCaCerts(Plugin):
    """Argument for CA certs.
    """

    config = config_ca_certs
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


class ArgClientKey(Plugin):
    """Argument for client keys.
    """

    config = config_client_key
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


class ArgClientChain(Plugin):
    """Argument for client certificate chains.
    """

    config = config_client_chain
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


class ArgCrl(Plugin):
    """Argument for CRL.
    """

    config = config_crl
    cli_args = Args(
        "--crl",
        help=(
            "download the CRL to check for the certificate revocation status. "
            "Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class ArgOcsp(Plugin):
    """Argument for OCSP.
    """

    config = config_ocsp
    cli_args = Args(
        "--ocsp",
        help=(
            "query the OCSP servers for checking the certificate "
            "revocation status. Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class GroupX509(Plugin):
    """Argument group for X509 arguments.
    """

    group = Args(title="X509 certificates options")
    plugins = [ArgCaCerts, ArgClientKey, ArgClientChain, ArgCrl, ArgOcsp]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        if (args.client_key is not None) or (args.client_chain is not None):
            if (args.client_key is None) or (args.client_chain is None):
                parser.error(
                    "if --client-key is given, --client-chain must be given as well, "
                    "and vice versa"
                )
            if len(args.client_key) != len(args.client_chain):
                parser.error(
                    "number of arguments for --client-key and --client-chain must "
                    "be identical"
                )


class ArgSslv2(Plugin):
    """Argument for SSLv2.
    """

    config = ConfigItem("sslv2", type=bool, default=None)
    cli_args = Args(
        "--sslv2",
        help="scan for protocol version SSLv2",
        action=utils.BooleanOptionalAction,
    )


class ArgSslv3(Plugin):
    """Argument for SSLv3.
    """

    config = ConfigItem("sslv3", type=bool, default=None)
    cli_args = Args(
        "--sslv3",
        help="scan for protocol version SSLv3",
        action=utils.BooleanOptionalAction,
    )


class ArgTls10(Plugin):
    """Argument for TLS1.0.
    """

    config = ConfigItem("tls10", type=bool, default=None)
    cli_args = Args(
        "--tls10",
        help="scan for protocol version TLS1.0",
        action=utils.BooleanOptionalAction,
    )


class ArgTls11(Plugin):
    """Argument for TLS1.1.
    """

    config = ConfigItem("tls11", type=bool, default=None)
    cli_args = Args(
        "--tls11",
        help="scan for protocol version TLS1.1",
        action=utils.BooleanOptionalAction,
    )


class ArgTls12(Plugin):
    """Argument for TLS1.2.
    """

    config = ConfigItem("tls12", type=bool, default=None)
    cli_args = Args(
        "--tls12",
        help="scan for protocol version TLS1.2",
        action=utils.BooleanOptionalAction,
    )


class ArgTls13(Plugin):
    """Argument for TLS1.3.
    """

    config = ConfigItem("tls13", type=bool, default=None)
    cli_args = Args(
        "--tls13",
        help="scan for protocol version TLS1.3",
        action=utils.BooleanOptionalAction,
    )


class GroupTlsVersions(Plugin):
    """Argument group for TLS versions.
    """

    group = Args(
        title="TLS protocol versions",
        description=(
            "The following options specify the TLS protocol versions to scan. "
            "By default all versions will be scanned, but if one version is "
            "explicitly set to true, all other versions will be defaulted to false."
        ),
    )
    plugins = [ArgSslv2, ArgSslv3, ArgTls10, ArgTls11, ArgTls12, ArgTls13]

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


class ArgFeatures(Plugin):
    """Argument for Features.
    """

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


class ArgCompression(Plugin):
    """Argument for compression feature.
    """

    config = ConfigItem("compression", type=bool, default=None)
    cli_args = Args(
        "--compression",
        help="scan for compression support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanCompression]


class ArgDhGroup(Plugin):
    """Argument for DH groups.
    """

    config = ConfigItem("dh_groups", type=bool, default=None)
    cli_args = Args(
        "--dh-groups",
        help="scan for finite field DH groups (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanDhGroups]


class ArgEncThenMac(Plugin):
    """Argument for encrypt-then-mac extension.
    """

    config = ConfigItem("encrypt_then_mac", type=bool, default=None)
    cli_args = Args(
        "--encrypt-then-mac",
        help="scan for encrypt-then-mac support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanEncryptThenMac]


class ArgEphemKeyReuse(Plugin):
    """Argument for ephemeral key reuse.
    """

    config = ConfigItem("ephemeral_key_reuse", type=bool, default=None)
    cli_args = Args(
        "--ephemeral-key-reuse",
        help="scan for reuse of ephemeral keys",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanEphemeralKeyReuse]


class ArgExtMasterSecret(Plugin):
    """Argument for extended-master-secret extension.
    """

    config = ConfigItem("ext_master_secret", type=bool, default=None)
    cli_args = Args(
        "--ext-master-secret",
        help="scan for extended master secret support (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanExtendedMasterSecret]


class ArgFallback(Plugin):
    """Argument for fallback.
    """

    config = ConfigItem("fallback", type=bool, default=None)
    cli_args = Args(
        "--fallback",
        help="scan for downgrade attack prevention (TLS_FALLBACK_SCSV)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanDowngrade]


class ArgGrease(Plugin):
    """Argument for GREASE.
    """

    config = ConfigItem("grease", type=bool, default=None)
    cli_args = Args(
        "--grease",
        help="scan for unknown parameter tolerance",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanGrease]


class ArgHeartbeat(Plugin):
    """Argument for heartbeat extension.
    """

    config = ConfigItem("heartbeat", type=bool, default=None)
    cli_args = Args(
        "--heartbeat",
        help="scan for heartbeat support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanHeartbeat]


class ArgOcspStapling(Plugin):
    """Argument for OCSP stapling.
    """

    config = ConfigItem("ocsp_stapling", type=bool, default=None)
    cli_args = Args(
        "--ocsp-stapling",
        help="scan for OCSP stapling support",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanOcspStapling]


class ArgRenegotiation(Plugin):
    """Argument for renegotiation feature.
    """

    config = ConfigItem("renegotiation", type=bool, default=None)
    cli_args = Args(
        "--renegotiation",
        help="scan for renegotiation support (SSL30 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanRenegotiation]


class ArgResumption(Plugin):
    """Argument for resumption feature.
    """

    config = ConfigItem("resumption", type=bool, default=None)
    cli_args = Args(
        "--resumption",
        help=(
            "scan for resumption support (SSL30 - TLS1.2) and for PSK support (TLS1.3)"
        ),
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanResumption]


class GroupFeatures(Plugin):
    """Argument group for features.
    """

    group = Args(title="Feature to include into the scan")
    plugins = [
        ArgFeatures,
        ArgCompression,
        ArgDhGroup,
        ArgEncThenMac,
        ArgEphemKeyReuse,
        ArgExtMasterSecret,
        ArgFallback,
        ArgGrease,
        ArgHeartbeat,
        ArgOcspStapling,
        ArgRenegotiation,
        ArgResumption,
    ]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)

        plugins = cls.plugins[1:]
        default = config.get(ArgFeatures.config.name)
        if default is None:
            default = not any(config.get(feat.config.name) for feat in plugins)

        for feat in plugins:
            val = config.get(feat.config.name)
            if val is None:
                config.set(feat.config.name, default)
                if default and feat.workers:
                    for worker in feat.workers:
                        WorkManager.register(worker)


class ArgVulnerabilities(Plugin):
    """Argument for Vulnerabilities.
    """

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


class ArgCcsInjection(Plugin):
    """Argument for CCS-injection vulnerability.
    """

    config = ConfigItem("ccs_injection", type=bool, default=None)
    cli_args = Args(
        "--ccs-injection",
        help="scan for vulnerability CCS-injection (only TL1.0 - TLS1.2)",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanCcsInjection]


class ArgHeartbleed(Plugin):
    """Argument for heartbleed vulnerability.
    """

    config = ConfigItem("heartbleed", type=bool, default=None)
    cli_args = Args(
        "--heartbleed",
        help="scan for the Heartbleed vulnerability CVE-2014-0160",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanHeartbleed]


class ArgPaddingOracle(Plugin):
    """Argument for CBC padding oracles.
    """

    config = ConfigItem("padding_oracle", type=bool, default=None)
    cli_args = Args(
        "--padding-oracle",
        help="scan for CBC padding oracles",
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanPaddingOracle]


class ArgPaddingOracleAccuracy(Plugin):
    """Argument for oracle accuracy.
    """

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


class ArgRobot(Plugin):
    """Argument for ROBOT vulnerability.
    """

    config = ConfigItem("robot", type=bool, default=None)
    cli_args = Args(
        "--robot",
        help=(
            "scan for ROBOT vulnerability CVE-2017-13099, etc. (only TL1.0 - TLS1.2)"
        ),
        action=utils.BooleanOptionalAction,
    )
    workers = [ScanRobot]


class GroupVulnerabilities(Plugin):
    """Argument group vulnerabilities.
    """

    group = Args(title="Vulnerabilities to scan for")
    plugins = [
        ArgVulnerabilities,
        ArgCcsInjection,
        ArgHeartbleed,
        ArgPaddingOracle,
        ArgPaddingOracleAccuracy,
        ArgRobot,
    ]

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        super().args_parsed(args, parser, subcommand, config)

        plugins = cls.plugins[:]
        plugins.remove(ArgVulnerabilities)
        plugins.remove(ArgPaddingOracleAccuracy)

        default = config.get(ArgVulnerabilities.config.name)
        if default is None:
            default = not any(config.get(vuln.config.name) for vuln in plugins)

        base_vuln = False
        for vuln in plugins:
            val = config.get(vuln.config.name)
            if val is None:
                config.set(vuln.config.name, default)
                if default and vuln.workers:
                    for worker in vuln.workers:
                        WorkManager.register(worker)
                        base_vuln = True

        if base_vuln:
            WorkManager.register(ScanBaseVulnerabilities)


@BaseCommand.extend
class SubcommandScan(Plugin):
    """CLI plugin to perform a scan against a TLS server.
    """

    subcommand = Args("scan", help="performs a TLS server scan")
    plugins = [
        GroupBasicScan,
        GroupX509,
        GroupTlsVersions,
        GroupFeatures,
        GroupVulnerabilities,
        GroupServerProfile,
    ]
    workers = [ScanStart, ScanCipherSuites, ScanSupportedGroups, ScanSigAlgs, ScanEnd]
