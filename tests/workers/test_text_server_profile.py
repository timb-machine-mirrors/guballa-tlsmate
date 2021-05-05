# -*- coding: utf-8 -*-
"""Implements a class to test the text server profile worker.
"""
from tlsmate.workers.server_profile import ReadProfileWorker
from tlsmate.workers.text_server_profile import TextProfileWorker
from tlsmate.config import Configuration
from tlsmate.tlsmate import TlsMate
from tlsmate.structs import ConfigItem


def test_server_profile(server_profile):
    config = Configuration()
    config.register(ConfigItem("write_profile"))
    config.register(ConfigItem("read_profile"))
    config.register(ConfigItem("format", type=str, default="text"))
    config.set("read_profile", str(server_profile))
    tlsmate = TlsMate(config)
    ReadProfileWorker(tlsmate).run()
    TextProfileWorker(tlsmate).run()


def test_text_server_profile(text_server_profile):
    config = Configuration()
    config.register(ConfigItem("write_profile"))
    config.register(ConfigItem("read_profile"))
    config.register(ConfigItem("format", type=str, default="text"))
    config.set("read_profile", str(text_server_profile))
    tlsmate = TlsMate(config)
    ReadProfileWorker(tlsmate).run()
    TextProfileWorker(tlsmate).run()
