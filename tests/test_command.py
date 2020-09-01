# -*- coding: utf-8 -*-
import sys
import re
import pytest

import boilerplate.command as command


def test_command_version(capsys):
    cmd = "boilerplate version"
    sys.argv = cmd.split()
    command.main()
    captured = capsys.readouterr()
    assert re.match(r"^\d+\.\d+\.\d+", captured.out)
