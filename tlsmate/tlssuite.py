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
            OpensslVersion.v1_0_2: self.config.get("pytest_openssl_1_0_2"),
            OpensslVersion.v1_1_1: self.config.get("pytest_openssl_1_1_1"),
            OpensslVersion.v3_0_0: self.config.get("pytest_openssl_3_0_0"),
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
        self.port = self.config.get("pytest_port")
        if self.port is None:
            self.port = 44330

        self.config.set("endpoint", self.server + ":" + str(self.port))
        self.config.set("progress", False)
        self.config.set("read_profile", self.get_yaml_file(self.sp_in_yaml))
        self.config.set("pytest_recorder_file", self.get_yaml_file(self.recorder_yaml))
        self.config.set("pytest_recorder_replaying", is_replaying)
        utils.set_logging(self.config.get("logging"))

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
