# -*- coding: utf-8 -*-
"""Module for a worker handling the server profile (de)serialization
"""
# import basic stuff

# import own stuff
from tlsmate.plugin import Worker
from tlsmate import utils

# import other stuff


class ReadProfileWorker(Worker):
    """Worker class which deserializes a server profile in Yaml format
    """

    name = "profile_reader"
    descr = "read the server profile"
    prio = 1

    def run(self):
        read_profile = self.config.get("read_profile")
        if read_profile is not None:
            self.server_profile.load(utils.deserialize_data(read_profile))


class DumpProfileWorker(Worker):
    """Worker class which serializes a server profile.
    """

    name = "profile_dumper"
    descr = "dump the server profile"
    prio = 1001

    def run(self):
        utils.serialize_data(
            self.server_profile.make_serializable(),
            file_name=self.config.get("write_profile"),
            replace=True,
            use_json=(self.config.get("format") == "json"),
            indent=4,
        )
