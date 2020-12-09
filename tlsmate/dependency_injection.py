# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
from dependency_injector import containers, providers
import tlsmate.constants as tls
from tlsmate.server_profile import ServerProfile
from tlsmate.connection import TlsConnection, TlsConnectionMsgs
from tlsmate.client import Client
from tlsmate.record_layer import RecordLayer
from tlsmate.recorder import Recorder
from tlsmate.socket import Socket
from tlsmate.kdf import Kdf
from tlsmate.config import Configuration

from tlsmate.suitemanager import SuiteManager


class Container(containers.DeclarativeContainer):
    """Class defining all the dependencies"""

    # config = providers.Configuration("config")
    config = providers.Singleton(Configuration)

    server_profile = providers.Singleton(ServerProfile)

    recorder = providers.Singleton(Recorder)

    socket = providers.Factory(Socket, config=config, recorder=recorder)

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
        Client, connection_factory=connection.provider, config=config
    )

    test_manager = providers.Singleton(SuiteManager)
