# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
import tlsclient.constants as tls
from tlsclient.server_profile import ServerProfile
from tlsclient.testsuite import TestSuite
from tlsclient.connection import TlsConnection, TlsConnectionMsgs
from tlsclient.client_profile import ClientProfile
from tlsclient.record_layer import RecordLayer
from tlsclient.recorder import Recorder
from tlsclient.socket import Socket
from tlsclient.hmac_prf import HmacPrf

from dependency_injector import containers, providers


class Container(containers.DeclarativeContainer):
    """Class defining all the dependencies"""

    config = providers.Configuration("config")

    server_profile = providers.Singleton(ServerProfile)

    recorder = providers.Singleton(Recorder)

    socket = providers.Factory(
        Socket, server=config.server, port=config.port, recorder=recorder
    )

    hmac_prf = providers.Factory(HmacPrf)

    record_layer = providers.Factory(RecordLayer, socket=socket, recorder=recorder)

    connection_msgs = providers.Factory(TlsConnectionMsgs)

    connection = providers.Factory(
        TlsConnection,
        connection_msgs=connection_msgs,
        entity=tls.Entity.CLIENT,
        record_layer=record_layer,
        recorder=recorder,
        hmac_prf=hmac_prf,
    )

    client_profile = providers.Factory(
        ClientProfile, connection_factory=connection.provider, server_name=config.server
    )

    test_suite = providers.Factory(
        TestSuite,
        server_profile=server_profile,
        client_profile_factory=client_profile.provider,
    )
