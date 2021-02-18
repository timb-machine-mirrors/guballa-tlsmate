# -*- coding: utf-8 -*-
"""Module containing the class for the configuration
"""
# import basic stuff
import os
from pathlib import Path

# import own stuff

# import other stuff
import configparser


def _str_to_bool(string):
    return string.lower() not in ["0", "off", "no", "false"]


def _str_to_strlist(string):
    return [val.strip() for val in string.split(",")]


class Configuration(object):
    """Class representing the configuration for tlsmate.

    The configuration is taken from the following sources (the list is ordered
    according to the priority, first item has the least priority):

    * The hard coded default values
    * The file .tlsmate.ini in the user's home directory
    * Environment variables
    * From the ini file as specified on the command line interface
    * From the command line interface parameters

    Example:
        Specifying the logging option:

        Via command line:
            tlsmate --logging=debug ...

        Via Enviroment variable:
            export TLSMATE_LOGGING=debug

        Via ini-file:

        [tlsmate]
        logging = debug

    The configuration options can be retrieved by using the object like a dict:

    >>> config = Configuration()
    >>> config["server"]
    'localhost'
    """

    _format_option = {
        "progress": _str_to_bool,
        "ca_certs": _str_to_strlist,
        "client_key": _str_to_strlist,
        "client_chain": _str_to_strlist,
        "sslv2": _str_to_bool,
        "sslv3": _str_to_bool,
        "tls10": _str_to_bool,
        "tls11": _str_to_bool,
        "tls12": _str_to_bool,
        "tls13": _str_to_bool,
    }

    def __init__(self, ini_file=None):
        self.config = {
            "server": "localhost",
            "port": 443,
            "logging": "error",
            "progress": False,
            "ca_certs": None,
            "client_key": None,
            "client_chain": None,
            "sslv2": False,
            "sslv3": False,
            "tls10": False,
            "tls11": False,
            "tls12": False,
            "tls13": False,
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

    def set_config(self, key, val):
        """Add a configuration option.

        If the given configuration is already defined, it will be overwritten by
        the given input.

        Arguments:
            key (str): the name of the option
            val: the value of the option
        """
        if val is not None:
            self.config[key] = val
