# -*- coding: utf-8 -*-
"""Implements a class to test the compression worker.
"""
from tlsmate.workers.server_profile import ReadProfileWorker, DumpProfileWorker
from tlsmate.config import Configuration
from tlsmate.tlsmate import TlsMate


def test_server_profile(server_profile, capsys):
    with open(server_profile) as fd:
        server_file = fd.read()

    conf = {
        "write_profile": None,
        "read_profile": None,
        "json": False,
    }

    config = Configuration()
    config.extend(conf)
    config.set("read_profile", str(server_profile))
    tlsmate = TlsMate(config)
    ReadProfileWorker(tlsmate).run()
    DumpProfileWorker(tlsmate).run()

    captured = capsys.readouterr()
    a1 = server_file.split("\n")
    a2 = captured.out.split("\n")
    for a, b in zip(a1, a2):
        assert a == b
