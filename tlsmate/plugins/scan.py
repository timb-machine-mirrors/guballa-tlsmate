# -*- coding: utf-8 -*-
"""Module for the scan plugin
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import PluginBase, Plugin, Args
from tlsmate.plugins.basic_arguments import (
    PluginBasicScan,
    PluginX509,
    PluginTlsVersions,
    PluginFeatureGroup,
    PluginVulnerabilityGroup,
    PluginServerProfile,
)
from tlsmate.workers.eval_cipher_suites import ScanCipherSuites
from tlsmate.workers.scanner_info import ScanStart, ScanEnd
from tlsmate.workers.supported_groups import ScanSupportedGroups
from tlsmate.workers.sig_algo import ScanSigAlgs


@PluginBase.extend
class PluginScan(Plugin):
    """CLI plugin to perform a scan against a TLS server.
    """

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
