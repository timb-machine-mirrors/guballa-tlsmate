# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
# import basic stuff

# import own stuff
from tlsmate import tls
from tlsmate.server_profile import ServerProfile
from tlsmate.connection import TlsConnection, TlsConnectionMsgs
from tlsmate.client import Client
from tlsmate.record_layer import RecordLayer
from tlsmate.recorder import Recorder
from tlsmate.socket import Socket
from tlsmate.kdf import Kdf
from tlsmate.server_endpoint import ServerEndpoint
from tlsmate.config import Configuration
from tlsmate.suitemanager import SuiteManager

# import other stuff
from dependency_injector import containers, providers


class TlsMate(containers.DeclarativeContainer):
    """Class defining all the dependencies
    """

    config = providers.Singleton(Configuration)

    server_endpoint = providers.Singleton(ServerEndpoint)

    server_profile = providers.Singleton(ServerProfile)

    recorder = providers.Singleton(Recorder)

    socket = providers.Factory(
        Socket, config=config, recorder=recorder, server_endpoint=server_endpoint,
    )

    kdf = providers.Factory(Kdf)

    record_layer = providers.Factory(RecordLayer, socket=socket, recorder=recorder)

    connection_msgs = providers.Factory(TlsConnectionMsgs)

    connection = providers.Factory(
        TlsConnection,
        connection_msgs=connection_msgs,
        entity=tls.Entity.CLIENT,
        record_layer=record_layer,
        recorder=recorder,
        kdf=kdf,
    )

    client = providers.Factory(
        Client,
        connection_factory=connection.provider,
        config=config,
        server_endpoint=server_endpoint,
    )

    test_manager = providers.Singleton(SuiteManager)
