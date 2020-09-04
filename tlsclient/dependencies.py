# -*- coding: utf-8 -*-
"""Module containing the dependencies
"""
import logging
from tlsclient.server_profile import ServerProfile
from tlsclient.test_suite import TestSuite

from dependency_injector import containers, providers

class Container(containers.DeclarativeContainer):

    logger = providers.Singleton(logging.Logger, name='tlsclient')

    server_profile = providers.Singleton(ServerProfile, logger=logger)

    test_suite = providers.Factory(TestSuite, logger=logger, server_profile=server_profile)
