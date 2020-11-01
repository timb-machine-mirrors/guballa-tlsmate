# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
import sys
import time
import datetime
import yaml
from tlsclient.server_profile import Serializable
from tlsclient.testmanager import TestSuite
from tlsclient.version import __version__


class _ScannerProfile(Serializable):
    name = "scan_info"

    serialize_map = {
        "command": lambda self: self.command,
        "version": lambda self: self.version,
        "start_time": lambda self: self.start_timestamp,
        "start_date": lambda self: self.start_date,
        "stop_timestamp": lambda self: self.stop_timestamp,
        "stop_date": lambda self: self.stop_date,
        "run_time": lambda self: self.run_time,
    }

    def __init__(self, server_profile):
        super().__init__()
        self.command = " ".join(sys.argv)
        self.version = __version__
        self.start_timestamp = time.time()
        self.start_date = datetime.datetime.fromtimestamp(int(self.start_timestamp))
        self.stop_timestamp = None
        self.stop_date = None
        self.run_time = None
        server_profile.register(self, as_child="scan_info")

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
        if self.client.config["progress"]:
            sys.stderr.write("\n")
        print(yaml.dump(self.server_profile.serialize_obj(), indent=4))
