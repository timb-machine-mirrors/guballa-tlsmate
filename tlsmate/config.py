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

config_logging = ConfigItem("logging", type=str, default="error")
config_host = ConfigItem("host", type=str, default="localhost")
config_port = ConfigItem("port", type=int, default=443)
config_interval = ConfigItem("interval", type=int, default=0)
config_key_log_file = ConfigItem("key_log_file", type=str, default=None)
config_progress = ConfigItem("progress", type=bool, default=False)
config_sni = ConfigItem("sni", type=str, default=None)
config_ca_certs = ConfigItem("ca_certs", type="file_list")
config_client_key = ConfigItem("client_key", type="file_list")
config_client_chain = ConfigItem("client_chain", type="file_list")
config_crl = ConfigItem("crl", type=bool, default=True)
config_ocsp = ConfigItem("ocsp", type=bool, default=True)


class Configuration(object):
    """Class representing the configuration for tlsmate.

    The configuration is taken from the following sources (the list is ordered
    according to the priority, first item has the least priority):

    * The hard coded default values
    * From the ini-file, if present. If the ini-file is not specified via the
      CLI option, the file .tlsmate.ini in the user's home directory will be used,
      if present.
    * Environment variables. They need to be given in upper cases and must start with
      `TLSMATE_` followed by the name of the setting in upper cases.
    * From the command line interface parameters

    Example:
        Specifying the logging option:

        Via command line::

            tlsmate --logging=debug ...

        Via Enviroment variable::

            export TLSMATE_LOGGING=debug

        Via ini-file::

            [tlsmate]
            logging = debug
    """

    def __init__(self):
        self._config = {}
        self._descr = {}

        # register configurations which are essential in the core
        # part of tlsmate.
        for item in [
            config_logging,
            config_host,
            config_port,
            config_interval,
            config_key_log_file,
            config_progress,
            config_sni,
            config_ca_certs,
            config_client_key,
            config_client_chain,
            config_crl,
            config_ocsp,
        ]:
            self.register(item)

        # special configuration item exclusively used for unit tests.
        # if set to False, the recorder will not use any delays when replaying.
        self.register(ConfigItem("recorder_delay", type=bool, default=True))
        self._init_environment_var("recorder_delay")

    def _str_to_filelist(self, string):
        """Resolves a string of files paths.

        Multiple file paths are separated by a colon. If the path is a relative
        path, it is expanded to an absolute path, taking the directory of the
        config file as a base (which is available in self._config_dir).

        Arguments:
            string (str): the list of file paths as a string, multiple paths are
                separated by a colon.

        Returns:
            list of str: the list of resolved absolute paths.
        """

        ret = []
        for val in string.split(","):
            val = val.strip()
            if not val.startswith("/"):
                val = str(self._config_dir / val)
            ret.append(val)
        return ret

    _format_option = {
        bool: lambda self, x: x.lower() not in ["0", "off", "no", "false"],
        int: lambda self, x: int(x),
        "file_list": _str_to_filelist,
    }

    def _init_from_ini_file(self, ini_file):
        """Helper method to initialize the configuration from an ini-file.
        """

        if ini_file is None:
            ini_file = Path.home() / ".tlsmate.ini"
            if not ini_file.is_file():
                return

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

    def _init_environment_var(self, item):
        """Helper method to initialize a single item from the environment variable.
        """

        val = os.environ.get("TLSMATE_" + item.upper())
        if val is not None:
            self._config[item] = self._cast_item(item, val)

    def _init_from_environment(self):
        """Helper method to initialize the configuration from environment variables.
        """

        for item in self._config:
            self._init_environment_var(item)

    def _cast_item(self, item, val):
        """Cast the type of a configuration item into the internal format.
        """

        item_type = self._descr[item].type
        if item_type in self._format_option:
            val = self._format_option[item_type](self, val)
        return val

    def init_from_external(self, ini_file=None):
        """Take the configuration from the ini file and from the environment variables.

        Arguments:
            ini_file (str): the path to the ini file. If None is given, then only
                the environment variables are taken into account.
        """

        self._init_from_ini_file(ini_file)
        self._init_from_environment()

    def items(self):
        """Return the configuration items. Mimics the dict's `items` method.

        Returns:
            list (tuple): The list of configuration items. Each item is a tuple of the
            item name and the item value.

        """

        return self._config.items()

    def get(self, key, default=None):
        """Get the value of a configuration item. Mimics the dict's `get` method.

        Arguments:
            key (str): the name of the configuration item
            default: the default value to return in case the configuration item is
                not existing. Defaults to None.

        Returns:
            any: the value of the configuration item or the provided default value if
            it is not present.
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
            if config_item != self._descr[name]:
                raise ValueError(
                    f'configuration setting "{name}" already defined with '
                    f"different properties"
                )
        self._descr[name] = config_item
        self._config[name] = config_item.default
