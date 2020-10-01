# -*- coding: utf-8 -*-
"""Module implementing a test manager class
"""

import logging
import abc


class TestSuite(metaclass=abc.ABCMeta):

    prio = 100

    def inject_dependencies(self, server_profile, client_profile):
        self.server_profile = server_profile
        self.client_profile = client_profile

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError


class TestManager(object):
    test_suite_names = []
    prio_pool = {}

    @classmethod
    def register(cls, test_suite_cls):
        if test_suite_cls.name in cls.test_suite_names:
            raise ValueError(
                f"Test suite with the name {test_suite_cls.name} is already registered"
            )
        cls.prio_pool.setdefault(test_suite_cls.prio, {})
        cls.prio_pool[test_suite_cls.prio][test_suite_cls.name] = test_suite_cls
        return test_suite_cls

    def test_suites(self):
        for prio in self.prio_pool.values():
            for test_suite in prio.values():
                yield test_suite

    def run(self, container, test_suite_names):
        for prio in sorted(self.prio_pool.keys()):
            prio_elem = self.prio_pool[prio]
            for name in sorted(prio_elem.keys()):
                test_suite_cls = prio_elem[name]
                if test_suite_cls.name in test_suite_names:
                    logging.debug(f"starting test suite {test_suite_cls.name}")
                    test_suite = test_suite_cls()
                    test_suite.inject_dependencies(
                        container.server_profile(), container.client_profile()
                    )
                    test_suite.run()
                    logging.debug(f"test suite {test_suite_cls.name} finished")
