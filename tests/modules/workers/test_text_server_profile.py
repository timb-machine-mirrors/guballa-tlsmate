# -*- coding: utf-8 -*-
"""Implement unit tests for the module utils.
"""
import io
import re
from tlsmate.workers.text_server_profile import (
    FontStyle,
    Color,
    merge_moods,
    get_dict_value,
    get_styled_text,
    TextProfileWorker,
)
import pytest
import yaml


def test_FontStyle_html():
    FontStyle.html = True
    style = FontStyle(color=Color.GREEN, bold=True)
    txt = "hello word"
    styled_txt = style.decorate(txt)
    assert styled_txt == f"<font color=green><b>{txt}</b></font>"


def test_FontStyle_orig_length():
    FontStyle.html = True
    style = FontStyle(color=Color.GREEN, bold=True)
    txt = "hello word"
    styled_txt = style.decorate(txt, with_orig_len=True)
    assert styled_txt == (f"<font color=green><b>{txt}</b></font>", len(txt))


def test_merge_moods():
    with pytest.raises(ValueError, match="cannot merge moods"):
        merge_moods([])


def test_get_dict_value_no_profile():
    assert get_dict_value(None, default="test") == "test"


def test_get_dict_value_not_found():
    profile = {"there": 0}
    assert get_dict_value(profile, "not_there", default="test") == "test"


def test_get_styled_text():
    FontStyle.html = True
    assert get_styled_text(None) == "<font color=red><b>???</b></font>"

def test_empty_profile(tlsmate, style_file, capsys):
    tlsmate.server_profile.load({})
    tlsmate.config.set("style", str(style_file))
    TextProfileWorker(tlsmate).run()
    captured = capsys.readouterr()
    assert "Scanned host" not in captured.out
    assert "TLS protocol versions" not in captured.out
    assert "Cipher suites" not in captured.out
    assert "Supported groups" not in captured.out
    assert "Signature algorithms" not in captured.out
    assert "DH groups (finite field)" not in captured.out
    assert "Features" not in captured.out
    assert "Certificate chains" not in captured.out
    assert "Vulnerabilities" not in captured.out
    assert "Severe server implementation flaws" not in captured.out


def test_host(tlsmate, style_file, capsys):
    FontStyle.html = False
    yaml_data = """
server:
    ip: 127.0.0.1
    name_resolution:
        domain_name: localhost
        ipv4_addresses:
        - 127.0.0.1
    port: 44330
    sni: localhost
"""
    data = yaml.safe_load(io.StringIO(yaml_data))
    tlsmate.server_profile.load(data)
    tlsmate.config.set("style", str(style_file))
    tlsmate.config.set("color", False)
    TextProfileWorker(tlsmate).run()
    captured = capsys.readouterr()
    assert re.match(r".*host +localhost", captured.out, re.DOTALL)
    assert re.match(r".*port +44330", captured.out, re.DOTALL)
    assert re.match(r".*SNI +localhost", captured.out, re.DOTALL)
    assert re.match(r".*IPv4 addresses +127\.0\.0\.1", captured.out, re.DOTALL)

def test_host_no_name_resolution(tlsmate, style_file, capsys):
    FontStyle.html = False
    yaml_data = """
server:
    ip: 127.0.0.1
    port: 44330
    sni: 127.0.0.1
"""
    data = yaml.safe_load(io.StringIO(yaml_data))
    tlsmate.server_profile.load(data)
    tlsmate.config.set("style", str(style_file))
    tlsmate.config.set("color", False)
    TextProfileWorker(tlsmate).run()
    captured = capsys.readouterr()
    assert re.match(r".*host +127\.0\.0\.1", captured.out, re.DOTALL)

def test_server_malfunctions(tlsmate, style_file, capsys):
    FontStyle.html = False
    yaml_data = """
server_malfunctions:
-   issue:
        description: 'received Finished: verify data does not match'
        name: VERIFY_DATA_INVALID
-   issue:
        description: 'certificate request without extension SignatureAlgorithms received'
        name: CERT_REQ_NO_SIG_ALGOD
"""
    data = yaml.safe_load(io.StringIO(yaml_data))
    tlsmate.server_profile.load(data)
    tlsmate.config.set("style", str(style_file))
    tlsmate.config.set("color", False)
    TextProfileWorker(tlsmate).run()
    captured = capsys.readouterr()
    assert "Severe server implementation flaws" in captured.out
    assert re.match(r".*- received Finished: verify data does not match", captured.out, re.DOTALL)
    assert re.match(r".*- certificate request without extension SignatureAlgorithms received", captured.out, re.DOTALL)
