# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
import sys
import yaml
from tlsclient.testmanager import TestSuite
from tlsclient.server_profile import SPScanner


class ScanStart(TestSuite):
    name = "scanstart"
    prio = 0

    def run(self):
        self.server_profile.scan_info = SPScanner()


class ScanEnd(TestSuite):
    name = "scanend"
    prio = 1000

    def run(self):
        self.server_profile.scan_info.end()
        if self.client.config["progress"]:
            sys.stderr.write("\n")
        print(yaml.dump(self.server_profile.serialize_obj(), indent=4))
