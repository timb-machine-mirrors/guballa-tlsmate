# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
import logging
import tlsclient.constants as tls
from tlsclient.server_profile import ServerProfile
from tlsclient.testsuite import TestSuite
from tlsclient.connection import (
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
    """Class defining all the dependencies"""

    config = providers.Configuration("config")

    server_profile = providers.Singleton(ServerProfile)

    recorder = providers.Singleton(Recorder)

    socket = providers.Factory(
        Socket, server=config.server, port=config.port, recorder=recorder
    )

    record_layer = providers.Factory(
        RecordLayer, socket=socket, recorder=recorder, 
    )

    security_parameters = providers.Factory(
        SecurityParameters, entity=tls.Entity.CLIENT, recorder=recorder
    )

    connection_state = providers.Factory(TlsConnectionState)

    connection_msgs = providers.Factory(TlsConnectionMsgs)

    connection = providers.Factory(
        TlsConnection,
        connection_state=connection_state,
        connection_msgs=connection_msgs,
        security_parameters=security_parameters,
        record_layer=record_layer,
        recorder=recorder,
    )

    client_profile = providers.Factory(
        ClientProfile,
        connection_factory=connection.provider,
        server_name=config.server,
    )

    test_suite = providers.Factory(
        TestSuite,
        server_profile=server_profile,
        client_profile_factory=client_profile.provider,
    )
