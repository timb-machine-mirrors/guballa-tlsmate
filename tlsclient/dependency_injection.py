# -*- coding: utf-8 -*-
"""Module for dependency injection
"""
import importlib
import pkgutil
from dependency_injector import containers, providers
import tlsclient.constants as tls
from tlsclient.server_profile import ServerProfile
from tlsclient.connection import TlsConnection, TlsConnectionMsgs
from tlsclient.client import Client
from tlsclient.record_layer import RecordLayer
from tlsclient.recorder import Recorder
from tlsclient.socket import Socket
from tlsclient.hmac_prf import HmacPrf

from tlsclient.testmanager import TestManager
import tlsclient.testsuites.eval_cipher_suites as tmp1
import tlsclient.testsuites.testsuite as tmp2

tmp1, tmp2  # make linters happy

discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith("tlsclient_")
}


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

    client = providers.Factory(
        Client, connection_factory=connection.provider, server_name=config.server
    )

    test_manager = providers.Singleton(TestManager)
