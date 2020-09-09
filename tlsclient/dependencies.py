# -*- coding: utf-8 -*-
"""Module containing the dependencies
"""
import logging
from tlsclient.server_profile import ServerProfile
from tlsclient.test_suite import TestSuite
from tlsclient.tls_connection import TlsConnection, TlsConnectionState, TlsConnectionMsgs
from tlsclient.client_profile import ClientProfile

from dependency_injector import containers, providers


class Container(containers.DeclarativeContainer):

    config = providers.Configuration("config")

    logger = providers.Singleton(logging.Logger, name="tlsclient")

    server_profile = providers.Singleton(ServerProfile)

    tls_connection_state = providers.Factory(TlsConnectionState)

    tls_connection_msgs = providers.Factory(TlsConnectionMsgs)

    tls_connection = providers.Factory(
        TlsConnection,
        tls_connection_state=tls_connection_state,
        tls_connection_msgs=tls_connection_msgs,
        logger=logger,
        server=config.server,
        port=config.port,
    )

    client_profile = providers.Factory(
        ClientProfile,
        tls_connection_factory=tls_connection.provider,
        server_name=config.server
    )

    test_suite = providers.Factory(
        TestSuite,
        logger=logger,
        server_profile=server_profile,
        client_profile_factory=client_profile.provider
    )
