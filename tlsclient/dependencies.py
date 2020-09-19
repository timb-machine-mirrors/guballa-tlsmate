# -*- coding: utf-8 -*-
"""Module containing the dependencies
"""
import logging
import tlsclient.constants as tls
from tlsclient.server_profile import ServerProfile
from tlsclient.testsuite import TestSuite
from tlsclient.tls_connection import (
    TlsConnection,
    TlsConnectionState,
    TlsConnectionMsgs,
)
from tlsclient.client_profile import ClientProfile
from tlsclient.record_layer import RecordLayer
from tlsclient.security_parameters import SecurityParameters
from tlsclient.recorder import Recorder
from tlsclient.socket import Socket

from dependency_injector import containers, providers


class Container(containers.DeclarativeContainer):

    config = providers.Configuration("config")

    logger = providers.Singleton(logging.Logger, name="tlsclient")

    server_profile = providers.Singleton(ServerProfile)

    recorder = providers.Singleton(Recorder)

    socket = providers.Factory(Socket, server=config.server, port=config.port, recorder=recorder)

    record_layer = providers.Factory(
        RecordLayer,
        socket=socket,
        recorder=recorder,
        logger=logger,
    )

    security_parameters = providers.Factory(
        SecurityParameters, entity=tls.Entity.CLIENT, recorder=recorder
    )

    tls_connection_state = providers.Factory(TlsConnectionState)

    tls_connection_msgs = providers.Factory(TlsConnectionMsgs)

    tls_connection = providers.Factory(
        TlsConnection,
        tls_connection_state=tls_connection_state,
        tls_connection_msgs=tls_connection_msgs,
        security_parameters=security_parameters,
        record_layer=record_layer,
        logger=logger,
        recorder=recorder,
    )

    client_profile = providers.Factory(
        ClientProfile,
        tls_connection_factory=tls_connection.provider,
        server_name=config.server,
    )

    test_suite = providers.Factory(
        TestSuite,
        logger=logger,
        server_profile=server_profile,
        client_profile_factory=client_profile.provider,
    )
