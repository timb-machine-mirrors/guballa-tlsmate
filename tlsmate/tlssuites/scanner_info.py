# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
import sys
import time
import datetime
import yaml
from tlsmate.tlssuite import TlsSuite
from tlsmate.server_profile import ProfileDict, ProfileBasic, YamlBlockStyle
from tlsmate.version import __version__


def literal_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
yaml.add_representer(YamlBlockStyle, literal_presenter)


class ProfileScanInfo(ProfileDict):
    def __init__(self):
        super().__init__()
        self.add("command", ProfileBasic(" ".join(sys.argv)))
        self.add("version", ProfileBasic(__version__))
        self._start_time = time.time()
        self.add("start_timestamp", ProfileBasic(self._start_time))
        self.add(
            "start_date",
            ProfileBasic(datetime.datetime.fromtimestamp(int(self._start_time))),
        )

    def end(self):
        stop_time = time.time()
        self.add("stop_timestamp", ProfileBasic(stop_time))
        self.add(
            "stop_date", ProfileBasic(datetime.datetime.fromtimestamp(int(stop_time)))
        )
        self.add("run_time", ProfileBasic(float(f"{stop_time - self._start_time:.3f}")))


class ScanStart(TlsSuite):
    name = "scanstart"
    prio = 0

    def run(self):
        self.server_profile.add("scan_info", ProfileScanInfo())


class ScanEnd(TlsSuite):
    name = "scanend"
    prio = 1000

    def run(self):
        self.server_profile.get("scan_info").end()
        if self.client.config["progress"]:
            sys.stderr.write("\n")
        print(yaml.dump(self.server_profile.serialize(), indent=4))
