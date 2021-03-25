# -*- coding: utf-8 -*-
"""Module containing the class for the configuration
"""
# import basic stuff
import os
import logging
from pathlib import Path

# import own stuff
from tlsmate.structs import ConfigItem

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
        self._config = {}
        self._descr = {}
        self.register(ConfigItem("endpoint", type=str, default="localhost"))
        self.register(ConfigItem("logging", type=str, default="error"))
        self.register(ConfigItem("progress", type=bool, default=False))
        self.register(ConfigItem("ca_certs", type="file_list"))
        self.register(ConfigItem("client_key", type="file_list"))
        self.register(ConfigItem("client_chain", type="file_list"))
        self.register(ConfigItem("no_crl", type=bool, default=False))
        self.register(ConfigItem("key_log_file", type=str))
        self.register(ConfigItem("pytest_recorder_file", type=str))
        self.register(ConfigItem("pytest_recorder_replaying", type=str))
        self.register(ConfigItem("pytest_port", type=int))
        self.register(ConfigItem("pytest_openssl_1_0_1g", type=str))
        self.register(ConfigItem("pytest_openssl_1_0_2", type=str))
        self.register(ConfigItem("pytest_openssl_1_1_1", type=str))
        self.register(ConfigItem("pytest_openssl_3_0_0", type=str))

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
        bool: _str_to_bool,
        int: _str_to_int,
        "file_list": _str_to_filelist,
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
        item_type = self._descr[item].type
        if item_type in self._format_option:
            val = self._format_option[item_type](self, val)
        return val

    def init_from_external(self, ini_file):
        """Take the configuration from the ini file and from the environment variables.

        Arguments:
            ini_file (str): the path to the ini file
        """
        self._init_from_ini_file(ini_file)
        self._init_from_environment()

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

    def register(self, config_item):
        """Add a new item to the configuration

        Arguments:
            config_item (:obj:`tlsmate.structs.ConfigItem`): the configuration
                item to register

        Raises:
            ValueError: if a configuration item with the same name is already existing
        """
        name = config_item.name
        if name in self._descr:
            raise ValueError(f'configuration setting "{name}" already defined')
        self._descr[name] = config_item
        self._config[name] = config_item.default
