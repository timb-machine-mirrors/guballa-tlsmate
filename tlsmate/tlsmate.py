# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
# import basic stuff
import pathlib
import logging

# import own stuff
from tlsmate.server_profile import ServerProfile
from tlsmate.client import Client
from tlsmate.client_auth import ClientAuth
from tlsmate.recorder import Recorder
from tlsmate.config import Configuration
from tlsmate.cert import TrustStore, Certificate, CrlManager
from tlsmate.plugin import WorkManager
from tlsmate.key_logging import KeyLogger
from tlsmate import utils

# import other stuff

TLSMATE_DIR = pathlib.Path(__file__).parent.parent.resolve()


class TlsMate(object):
    """Class defining the tlsmate application.

    Arguments:
        config (:obj:`tlsmate.config.Configuration`): an object representing tlsmate's
            configuration.
    """

    def __init__(self, config=None):
        if config is None:
            config = Configuration()

        for key, val in config.items():
            logging.debug(f"using config {key}={val}")

        self.config = config
        self.server_profile = ServerProfile()
        self.recorder = Recorder()
        self.trust_store = TrustStore(recorder=self.recorder)
        self.client_auth = ClientAuth(tlsmate=self)
        self.crl_manager = CrlManager()
        key_log_file = config.get("key_log_file")
        if key_log_file:
            KeyLogger.open_file(key_log_file)

        read_profile = config.get("read_profile")
        if read_profile:
            self.server_profile.load(utils.deserialize_data(read_profile))

        recorder_replaying = config.get("pytest_recorder_replaying")
        if recorder_replaying is not True:
            # "Normal" init of trust store and client auth from configuration
            if recorder_replaying is False:
                self.recorder.record()

            self.trust_store.set_ca_files(config.get("ca_certs"))
            if config.get("client_key"):
                for key_file, chain_file in zip(
                    config.get("client_key"), config.get("client_chain")
                ):
                    self.client_auth.add_auth_files(key_file, chain_file)

            key_log_file = config.get("key_log_file")
            if key_log_file:
                KeyLogger.open_file(key_log_file)

        else:
            pytest_recorder_file = config.get("pytest_recorder_file")
            if pytest_recorder_file:
                self.recorder.deserialize(pytest_recorder_file)

            self.recorder.replay()
            # Init trust store and client auth from recorded data
            for cert in self.recorder.get_trust_store():
                self.trust_store.add_cert(Certificate(der=bytes.fromhex(cert)))

            for key_chain in self.recorder.get_client_auth():
                self.client_auth.deserialize_key_chain(key_chain)

        self.client = Client(tlsmate=self)
        self.work_manager = WorkManager()
