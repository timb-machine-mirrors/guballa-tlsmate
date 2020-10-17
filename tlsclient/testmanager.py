# -*- coding: utf-8 -*-
"""Module implementing a test manager class
"""

import logging
import abc


class ScanError(Exception):

    def __init__(self, message):
        self.message = message


class TestSuite(metaclass=abc.ABCMeta):

    prio = 100

    def inject_dependencies(self, server_profile, client):
        self.server_profile = server_profile
        self.client = client

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError


class TestManager(object):
    cli_help = {}
    test_suites = {}

    @classmethod
    def register_cli(cls, argument, cli_help="", classes=[]):
        if argument in cls.cli_help:
            raise ValueError(
                f"CLI option {argument} is already registered"
            )
        cls.cli_help[argument] = cli_help
        cls.test_suites[argument] = classes

    def run(self, container, selected_test_suite_args):
        prio_pool = {}
        for arg in selected_test_suite_args:
            for cls in self.test_suites[arg]:
                prio_pool.setdefault(cls.prio, [])
                if cls not in prio_pool[cls.prio]:
                    prio_pool[cls.prio].append(cls)
        for prio_list in sorted(prio_pool.keys()):
            for cls in sorted(prio_pool[prio_list], key=lambda cls: cls.name):
                logging.debug(f"starting test suite {cls.name}")
                test_suite = cls()
                test_suite.inject_dependencies(
                    container.server_profile(), container.client()
                )
                test_suite.run()
                logging.debug(f"test suite {cls.name} finished")
