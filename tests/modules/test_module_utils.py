# -*- coding: utf-8 -*-
"""Implement unit tests for the module utils.
"""
import re
from tlsmate import utils
from tlsmate import tls

data = {
    "array": [1, 2, 3],
    "integer": 4,
    "object": {"a": 1, "b": 2},
    "string": "hello",
}

json = (
    "{\n"
    '    "array": [\n'
    "        1,\n"
    "        2,\n"
    "        3\n"
    "    ],\n"
    '    "integer": 4,\n'
    '    "object": {\n'
    '        "a": 1,\n'
    '        "b": 2\n'
    "    },\n"
    '    "string": "hello"\n'
    "}"
)

yaml = (
    "array:\n"
    "- 1\n"
    "- 2\n"
    "- 3\n"
    "integer: 4\n"
    "object:\n"
    "    a: 1\n"
    "    b: 2\n"
    "string: hello\n"
)


def test_get_random_value():
    val = utils.get_random_value()
    assert type(val) is bytearray
    assert len(val) == 32


def test_serialize_data_file(tmp_path):
    file_name = tmp_path / "output.txt"
    utils.serialize_data(data, file_name)
    content = file_name.read_text()
    assert content == yaml


def test_serialize_data_file_exists(tmp_path, capsys):
    file_name = tmp_path / "output.txt"
    file_name.touch()
    utils.serialize_data(data, file_name, replace=False)
    captured = capsys.readouterr()
    assert re.match(r"File .* existing\. .*-file not generated", captured.out)


def test_serialize_data_file_json(tmp_path):
    file_name = tmp_path / "output.txt"
    utils.serialize_data(data, file_name, use_json=True)
    content = file_name.read_text()
    assert content == json


def test_serialize_data_file_json_console(capsys):
    utils.serialize_data(data, use_json=True)
    captured = capsys.readouterr()
    assert captured.out == json + "\n"


def test_serialize_data_file_yaml_console(capsys):
    utils.serialize_data(data)
    captured = capsys.readouterr()
    assert captured.out == yaml + "\n"


def test_fold_string():
    string = "Hello world, this is a long string! Have fun!"
    assert utils.fold_string(string, 15) == [
        "Hello world, ",
        "this is a long ",
        "string! Have ",
        "fun!",
    ]


def test_filter_cipher_suites_key_exchange_supported():
    cipher_suites = [
        tls.CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
    ]
    assert utils.filter_cipher_suites(cipher_suites, key_exchange_supported=True) == [
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5
    ]


def test_int_to_bytes():
    assert utils.int_to_bytes(0) == b"\0"
    assert utils.int_to_bytes(255) == b"\xff"
    assert utils.int_to_bytes(256) == b"\01\00"
