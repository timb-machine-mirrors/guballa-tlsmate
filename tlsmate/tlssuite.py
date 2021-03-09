# -*- coding: utf-8 -*-
"""Module defining classes for test suites
"""
# import basic stuff
import abc
import subprocess
import sys
import time
import enum

# import own stuff
from tlsmate.tlsmate import TlsMate, TLSMATE_DIR
from tlsmate import utils
from tlsmate.config import Configuration

# import other stuff


class OpensslVersion(enum.Enum):
    v1_0_2 = enum.auto()
    v1_1_1 = enum.auto()
    v3_0_0 = enum.auto()


class TlsSuite(metaclass=abc.ABCMeta):
    """Provides a base class for the implementation of test suites.

    Attributes:
        server_profile (:obj:`tlsmate.server_profile.ServerProfile`): The server
            profile instance. Can be used to get data from it (e.g. which cipher
            suites are supported for which TLS versions), or to extend it.
        client (:obj:`tlsmate.client.Client`): The client object.
    """

    prio = 100

    def __init__(self, tlsmate):
        self.server_profile = tlsmate.server_profile
        self.client = tlsmate.client
        self.config = tlsmate.config

    def _inject_dependencies(self, server_profile, client):
        """Method to inject the server profile and the client into the object
        """
        self.server_profile = server_profile
        self.client = client

    @abc.abstractmethod
    def run(self):
        """Entry point for the test suite.

        The test manager will call this method which will implement the test suite.
        """
        raise NotImplementedError


class TlsSuiteTester(metaclass=abc.ABCMeta):
    """Base class to define unit tests
    """

    recorder_yaml = None
    sp_in_yaml = None
    sp_out_yaml = None
    path = None
    server = None
    port = None

    def _start_server(self):
        openssl_prefix = {
            OpensslVersion.v1_0_2: self.config["pytest_openssl_1_0_2"],
            OpensslVersion.v1_1_1: self.config["pytest_openssl_1_1_1"],
            OpensslVersion.v3_0_0: self.config["pytest_openssl_3_0_0"],
        }[self.openssl_version]

        cmd = (
            str(TLSMATE_DIR)
            + "/"
            + self.server_cmd.format(prefix=openssl_prefix, port=self.port)
        )

        self.server_proc = subprocess.Popen(
            cmd.split(),
            stdin=subprocess.PIPE,
            stdout=sys.stdout,
            universal_newlines=True,
        )
        time.sleep(2)  # give openssl some time for a clean startup

    def server_input(self, input_str, timeout=None):
        """Feed a string to the server process' STDIN pipe

        Arguments:
            input_str (str): the string to provide on the STDIN pipe
            timeout (int): the timeout to wait before providing the input in milli
            seconds.
        """

        if self.recorder.is_injecting():
            return

        if timeout is not None:
            self.recorder.additional_delay(timeout / 1000)
            time.sleep(timeout / 1000)

        print(input_str, file=self.server_proc.stdin, flush=True)

    def get_yaml_file(self, name):
        """Determine the file where an object is serialized to.

        Arguments:
            name (str): the basic name of the file, without directory and without
                the suffix

        Returns:
            :class:`pathlib.Path`: a Path object for the yaml file
        """
        if name is None:
            return None

        return self.path.resolve().parent / "recordings" / (name + ".yaml")

    def entry(self, is_replaying=False):
        """Entry point for a test case.

        Arguments:
            is_replaying (bool): an indication if the test case is replayed or recorded.
                Defaults to False.
        """
        if is_replaying:
            ini_file = None

        else:
            ini_file = TLSMATE_DIR / "tests/tlsmate.ini"
            if not ini_file.is_file():
                ini_file = None

        self.config = Configuration(
            ini_file=ini_file, init_from_external=not is_replaying
        )
        self.port = self.config["pytest_port"]
        if self.port is None:
            self.port = 44330

        self.config.set_config("endpoint", self.server + ":" + str(self.port))
        self.config.set_config("progress", False)
        self.config.set_config("read_profile", self.get_yaml_file(self.sp_in_yaml))
        self.config.set_config(
            "pytest_recorder_file", self.get_yaml_file(self.recorder_yaml)
        )
        self.config.set_config("pytest_recorder_replaying", is_replaying)
        utils.set_logging(self.config["logging"])

        self.tlsmate = TlsMate(self.config)
        self.recorder = self.tlsmate.recorder

        if not is_replaying:
            if self.server_cmd is not None:
                self._start_server()

        self.run(self.tlsmate, is_replaying)

        if not is_replaying:
            if self.recorder_yaml is not None:
                self.tlsmate.recorder.serialize(self.get_yaml_file(self.recorder_yaml))

            if self.sp_out_yaml is not None:
                utils.serialize_data(
                    self.tlsmate.server_profile.make_serializable(),
                    file_name=self.get_yaml_file(self.sp_out_yaml),
                    replace=False,
                    indent=2,
                )

    def test_entry(self):
        """Entry point for pytest.
        """
        self.entry(is_replaying=True)
