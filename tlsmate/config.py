# -*- coding: utf-8 -*-
"""Module containing the class for the configuration
"""
# import basic stuff
import os
import logging
from pathlib import Path

# import own stuff

# import other stuff
import configparser


class Configuration(object):
    """Class representing the configuration for tlsmate.

    The configuration is taken from the following sources (the list is ordered
    according to the priority, first item has the least priority):

    * The hard coded default values
    * From the ini-file, if present. If the ini-file is not specified via the
      CLI option, the file .tlsmate.ini in the user's home directory will be used,
      if present.
    * Environment variables. They need to be given in upper cases and must start with
      TLSMATE_ followed by the name of the setting.
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

    """

    def __init__(self):
        self._config = {
            "endpoint": "localhost",
            "logging": "error",
            "progress": False,
            "ca_certs": None,
            "client_key": None,
            "client_chain": None,
            "key_log_file": None,
            "sslv2": False,
            "sslv3": False,
            "tls10": False,
            "tls11": False,
            "tls12": False,
            "tls13": False,
            "pytest_recorder_file": None,
            "pytest_recorder_replaying": None,
            "pytest_port": None,
            "pytest_openssl_1_0_1g": None,
            "pytest_openssl_1_0_2": None,
            "pytest_openssl_1_1_1": None,
            "pytest_openssl_3_0_0": None,
        }

    def _str_to_bool(self, string):
        return string.lower() not in ["0", "off", "no", "false"]

    def _str_to_filelist(self, string):
        ret = []
        for val in string.split(","):
            val = val.strip()
            if not val.startswith("/"):
                val = str(self._config_dir / val)
            ret.append(val)
        return ret

    def _str_to_int(self, string):
        return int(string)

    _format_option = {
        "progress": _str_to_bool,
        "ca_certs": _str_to_filelist,
        "client_key": _str_to_filelist,
        "client_chain": _str_to_filelist,
        "sslv2": _str_to_bool,
        "sslv3": _str_to_bool,
        "tls10": _str_to_bool,
        "tls11": _str_to_bool,
        "tls12": _str_to_bool,
        "tls13": _str_to_bool,
        "pytest_port": _str_to_int,
    }

    def _init_from_ini_file(self, ini_file):
        if ini_file is None:
            ini_file = Path.home() / ".tlsmate.ini"

        else:
            ini_file = Path(ini_file)
            if not ini_file.is_absolute():
                ini_file = Path.cwd() / ini_file

        if not ini_file.is_file():
            raise FileNotFoundError(ini_file)

        logging.debug(f"using config file {str(ini_file)}")
        self._config_dir = ini_file.parent
        parser = configparser.ConfigParser()
        parser.read(str(ini_file))
        if parser.has_section("tlsmate"):
            config = parser["tlsmate"]
            for item in self._config:
                val = config.get(item)
                if val is not None:
                    self._config[item] = self._cast_item(item, val)

    def _init_from_environment(self):
        for item in self._config:
            val = os.environ.get("TLSMATE_" + item.upper())
            if val is not None:
                self._config[item] = self._cast_item(item, val)

    def _cast_item(self, item, val):
        if item in self._format_option:
            val = self._format_option[item](self, val)
        return val

    def init_from_external(self, ini_file):
        """Take the configuration from the ini file and from the environment variables.

        Arguments:
            ini_file (str): the path to the ini file
        """
        self._init_from_ini_file(ini_file)
        self._init_from_environment()

    def extend(self, config):
        """Extends the base configuration by additional configuration options.

        Used by plugins to register additional configuration options.

        Arguments:
            config (dict): A dict mapping the name of new configuration options
                to their default value.

        Raises:
            ValueError: If the name of the configuration option is already present.
                Used to avoid double use of the same option name by different plugins.
        """
        if config is not None:
            for key, val in config.items():
                if key in self._config:
                    raise ValueError(f'configuration "{key}" defined twice')

                self._config[key] = val

    def items(self):
        """Return the items for a configuration section.

        """
        return self._config.items()

    def get(self, key, default=None):
        """Get a configuration item.

        Arguments:
            key (str): the name of the configuration item
            default: the default value to return in case the configuration item is
                not existing. Defaults to None.
        """
        return self._config.get(key, default)

    def set(self, key, val, keep_existing=True):
        """Add a configuration option.

        Arguments:
            key (str): the name of the option
            val: the value of the option
            keep_existing (bool): if set to True and the value is None, an existing
                configuration will not be overwritten. Defaults to True
        """

        if key in self._config and val is None and keep_existing:
            return

        self._config[key] = val
