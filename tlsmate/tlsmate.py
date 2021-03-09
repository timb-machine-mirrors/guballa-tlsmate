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
from tlsmate.suitemanager import SuiteManager
from tlsmate.cert import TrustStore, Certificate, CrlManager
from tlsmate import utils

# import other stuff

TLSMATE_DIR = pathlib.Path(__file__).parent.parent.resolve()


class TlsMate(object):
    """Class defining all the dependencies

    Arguments:
        config (:obj:`tlsmate.config.Configuration`): an object representing tlsmate's
            configuration.
    """

    def __init__(self, config=None):
        if config is None:
            config = Configuration()

        for key, val in config.config.items():
            logging.debug(f"using config {key}={val}")

        self.config = config
        self.server_profile = ServerProfile()
        self.recorder = Recorder()
        self.trust_store = TrustStore(recorder=self.recorder)
        self.client_auth = ClientAuth(tlsmate=self)
        self.crl_manager = CrlManager()

        if config["read_profile"]:
            self.server_profile.load(utils.deserialize_data(config["read_profile"]))

        recorder_replaying = config["pytest_recorder_replaying"]
        if recorder_replaying is not True:
            # "Normal" init of trust store and client auth from configuration
            if recorder_replaying is False:
                self.recorder.record()

            self.trust_store.set_ca_files(config["ca_certs"])
            if config["client_key"]:
                for key_file, chain_file in zip(
                    config["client_key"], config["client_chain"]
                ):
                    self.client_auth.add_auth_files(key_file, chain_file)
        else:
            if config["pytest_recorder_file"]:
                self.recorder.deserialize(config["pytest_recorder_file"])

            self.recorder.replay()
            # Init trust store and client auth from recorded data
            for cert in self.recorder.get_trust_store():
                self.trust_store.add_cert(Certificate(der=bytes.fromhex(cert)))

            for key_chain in self.recorder.get_client_auth():
                self.client_auth.deserialize_key_chain(key_chain)

        self.client = Client(tlsmate=self)
        self.suite_manager = SuiteManager()
