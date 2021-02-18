# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
# import basic stuff
import sys
import time
import datetime

# import own stuff
from tlsmate.tlssuite import TlsSuite
from tlsmate.version import __version__
from tlsmate.server_profile import SPServer

# import other stuff
import yaml


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
        srv = self.client.server_endpoint
        srv.resolve_ip()
        data = {"ip": srv.ip, "port": srv.port, "sni": srv.sni}
        if srv.host_name is not None:
            data["name"] = srv.host_name

        if srv.ipv4_addresses is not None:
            data["ipv4_addresses"] = srv.ipv4_addresses

        if srv.ipv6_addresses is not None:
            data["ipv6_addresses"] = srv.ipv6_addresses

        self.server_profile.server = SPServer(data=data)


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
