# -*- coding: utf-8 -*-
"""Module providing infos about the scanner
"""
# import basic stuff
import sys
import time
import datetime

# import own stuff
from tlsmate import tls
from tlsmate.tlssuite import TlsSuite
from tlsmate.version import __version__
from tlsmate.server_profile import SPServer
from tlsmate import resolver
from tlsmate import utils

# import other stuff


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
        endp = resolver.determine_transport_endpoint(self.config["endpoint"])
        data = {"port": endp.port}
        if endp.host_type is tls.HostType.HOST:
            data["name"] = endp.host
            ips = resolver.resolve_hostname(endp.host)
            if ips.ipv4_addresses:
                data["ipv4_addresses"] = ips.ipv4_addresses

            if ips.ipv6_addresses:
                data["ipv6_addresses"] = ips.ipv6_addresses

            endp = resolver.get_ip_endpoint(endp)

        data["ip"] = endp.host
        try:
            data["sni"] = self.client.get_sni()

        except ValueError:
            pass

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
        if self.config["progress"]:
            sys.stderr.write("\n")

        utils.serialize_data(
            self.server_profile.make_serializable(),
            file_name=self.config["write_profile"],
            replace=True,
            use_json=bool(self.config["json"]),
            indent=4,
        )
