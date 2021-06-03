# -*- coding: utf-8 -*-
"""Implements test cases for the cli
"""
import sys
import pytest
import re

from tlsmate import command


def test_no_subcommand(capsys):
    cmd = "tlsmate"
    sys.argv = cmd.split()
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        command.main()
    captured = capsys.readouterr()
    assert "tlsmate: error: Subcommand is mandatory" in captured.err
    assert pytest_wrapped_e.value.code == 2


def test_version(capsys):
    cmd = "tlsmate version"
    sys.argv = cmd.split()
    # import pudb; pudb.set_trace()
    command.main()
    captured = capsys.readouterr()
    assert re.match(r"^\d+\.\d+\.\d+", captured.out)


def test_scan():
    cmd = "tlsmate scan 127.0.0.1:100000"
    sys.argv = cmd.split()
    with pytest.raises(OverflowError):
        command.main()
