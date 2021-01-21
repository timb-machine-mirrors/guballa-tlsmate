# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
import sys
import time
import datetime
import yaml
from tlsmate.tlssuite import TlsSuite
from tlsmate.version import __version__


class ScanStart(TlsSuite):
    name = "scanstart"
    prio = 0

    def run(self):
        scan_info = self.server_profile.scan_info
        start_time = time.time()
        scan_info.command = " ".join(sys.argv)
        scan_info.version = __version__
        scan_info.start_timestamp = start_time
        scan_info.start_date = datetime.datetime.fromtimestamp(int(start_time))


class ScanEnd(TlsSuite):
    name = "scanend"
    prio = 1000

    def run(self):
        scan_info = self.server_profile.scan_info
        start_time = scan_info.start_timestamp
        stop_time = time.time()
        scan_info.stop_timestamp = stop_time
        scan_info.stop_date = datetime.datetime.fromtimestamp(int(stop_time))
        scan_info.run_time = float(f"{stop_time - start_time:.3f}")
        if self.client.config["progress"]:
            sys.stderr.write("\n")
        data = self.server_profile.make_serializable()
        print(yaml.dump(data, indent=4))


#        print(json.dumps(data, indent=4, sort_keys=True))
