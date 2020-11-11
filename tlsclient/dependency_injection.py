# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
from dependency_injector import containers, providers
import tlsclient.constants as tls
from tlsclient.server_profile import ServerProfile
from tlsclient.connection import TlsConnection, TlsConnectionMsgs
from tlsclient.client import Client
from tlsclient.record_layer import RecordLayer
from tlsclient.recorder import Recorder
from tlsclient.socket import Socket
from tlsclient.kdf import Kdf

from tlsclient.suitemanager import SuiteManager


class Container(containers.DeclarativeContainer):
    """Class defining all the dependencies"""

    config = providers.Configuration("config")

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
