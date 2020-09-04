# -*- coding: utf-8 -*-
"""Module containing the test suite
"""

class TestSuite(object):

    def __init__(self, logger, server_profile):
        self.logger = logger
        self.server_profile = server_profile

    def run(self):
        print("Ok, we run")
        pass

