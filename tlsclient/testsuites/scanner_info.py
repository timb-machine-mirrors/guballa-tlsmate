# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
import sys
import time
import datetime
from tlsclient.server_profile import Serializable
from tlsclient.testmanager import TestSuite
from tlsclient.version import __version__


class _ScannerProfile(Serializable):

    node_name = "scan_info"

    def __init__(self, server_profile):
        super().__init__()
        self.command = " ".join(sys.argv)
        self.version = __version__
        self.start_timestamp = time.time()
        self.start_date = datetime.datetime.fromtimestamp(int(self.start_timestamp))
        self.stop_timestamp = None
        self.stop_date = None
        self.run_time = None
        server_profile.register(self)

    def end(self):
        self.stop_timestamp = time.time()
        self.stop_date = datetime.datetime.fromtimestamp(int(self.stop_timestamp))
        self.run_time = float(f"{self.stop_timestamp - self.start_timestamp:.3f}")


_scanner_profile = None


class ScanStart(TestSuite):
    name = "scanstart"
    prio = 0

    def run(self):
        global _scanner_profile
        _scanner_profile = _ScannerProfile(self.server_profile)


class ScanEnd(TestSuite):
    name = "scanend"
    prio = 1000

    def run(self):
        _scanner_profile.end()
