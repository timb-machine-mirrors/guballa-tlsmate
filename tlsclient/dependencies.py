# -*- coding: utf-8 -*-
"""Module containing the dependencies
"""
import logging
from tlsclient.server_profile import ServerProfile
from tlsclient.test_suite import TestSuite
from tlsclient.tls_connection import TlsConnection, TlsConnectionState

from dependency_injector import containers, providers


class Container(containers.DeclarativeContainer):

    config = providers.Configuration("config")

    logger = providers.Singleton(logging.Logger, name="tlsclient")

    server_profile = providers.Singleton(ServerProfile, logger=logger)

    tls_connection_state = providers.Factory(TlsConnectionState)

    tls_connection = providers.Factory(
        TlsConnection,
        tls_connection_state=tls_connection_state,
        logger=logger,
        server=config.server,
        port=config.port,
    )

    test_suite = providers.Factory(
        TestSuite,
        logger=logger,
        server_profile=server_profile,
        tls_connection_factory=tls_connection.provider,
    )
