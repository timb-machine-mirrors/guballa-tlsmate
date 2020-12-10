# -*- coding: utf-8 -*-
"""Module containing the class for the configuration
"""
import os
import configparser

from pathlib import Path


def _str_to_bool(string):
    return string.lower() not in ["0", "off", "no", "false"]


def _str_to_strlist(string):
    return [val.strip() for val in string.split(",")]


class Configuration(object):

    _format_option = {"progress": _str_to_bool, "ca_certs": _str_to_strlist}

    def __init__(self, ini_file=None):
        self.config = {
            "server": "localhost",
            "port": 443,
            "logging": "error",
            "progress": False,
            "ca_certs": None,
        }
        parser = configparser.ConfigParser(os.environ)
        if ini_file is not None:
            abs_path = Path(ini_file)
            if not abs_path.is_absolute():
                abs_path = Path.cwd() / abs_path
            if not abs_path.is_file():
                raise FileNotFoundError(abs_path)
        else:
            abs_path = Path.home() / ".tlsmate.ini"

        parser.read(str(abs_path))
        if parser.has_section("tlsmate"):
            config = parser["tlsmate"]
        else:
            config = {}
        for option in self.config.keys():
            val = os.environ.get("TLSMATE_" + option.upper())
            if val is None:
                val = config.get(option)
            if val is not None:
                func = self._format_option.get(option)
                if func is not None:
                    val = func(val)
                self.config[option] = val

    def __getitem__(self, key):
        return self.config.get(key)

    def merge_config(self, key, val):
        if val is not None:
            self.config[key] = val
