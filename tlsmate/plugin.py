# -*- coding: utf-8 -*-
"""Module providing stuff for plugin handling
"""
# import basic stuff
import logging
import abc

# import own stuff

# import other stuff


class Plugin(metaclass=abc.ABCMeta):
    """Base abstract class for a plugin
    """

    name = None
    cli_name = None
    cli_help = None

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        return

    def args_parsed(self, args, config):
        """Called after the arguments have been parsed.

        Arguments:
            args: the object holding the parsed CLI arguments
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        return


class PluginManager(object):

    _plugins = {}
    _objects = []

    @classmethod
    def register(cls, plugin):
        if plugin.name in cls._plugins:
            raise ValueError(
                f"Another plugin is already registered under the name "
                f'"{plugin.name}"'
            )

        cls._plugins[plugin.name] = plugin

    @classmethod
    def add_args(cls, parser):
        for name, plugin in sorted(cls._plugins.items()):
            if plugin.name is not None:
                parser.add_argument(
                    plugin.cli_name,
                    help=plugin.cli_help,
                    action="store_true",
                    default=False,
                )
            cls._objects.append(plugin())

        for plugin in cls._objects:
            plugin.add_args(parser)

    @classmethod
    def args_parsed(cls, args, config):
        for plugin in cls._objects:
            plugin.args_parsed(args, config)


def register_plugin(plugin):
    PluginManager.register(plugin)
    return plugin


class Worker(metaclass=abc.ABCMeta):
    """Provides a base class for the implementation a worker.

    Attributes:
        server_profile (:obj:`tlsmate.server_profile.ServerProfile`): The server
            profile instance. Can be used to get data from it (e.g. which cipher
            suites are supported for which TLS versions), or to extend it.
        client (:obj:`tlsmate.client.Client`): The client object.
        config (:obj:`tlsmate.config.Configuration`): The configuration object.
    """

    prio = 100

    def __init__(self, tlsmate):
        self.server_profile = tlsmate.server_profile
        self.client = tlsmate.client
        self.config = tlsmate.config

    @abc.abstractmethod
    def run(self):
        """Entry point for the test suite.

        The test manager will call this method which will implement the test suite.
        """
        raise NotImplementedError


class WorkManager(object):
    """Manages the registered workers and runs them.

    The worker manager provides an interface to register workers.

    The registered workers are triggered (via their run-method) based on their
    priority.

    Attributes:
        test_suite (dict): Maps the cli-names of the registered plugins to the
            corresponding classes.
    """

    prio_pool = {}

    @classmethod
    def register(self, worker_class):
        """Register a set of non-cli test suites.

        Arguments:
            classes (list of :obj:`TestSuite`): A list of plugins that are executed
            regardless of any cli options.
        """
        self.prio_pool.setdefault(worker_class.prio, [])
        self.prio_pool[worker_class.prio].append(worker_class)

    def run(self, tlsmate):
        """Function to actually start the test manager.

        Arguments:
            tlsmate (:obj:`tlsmate.dependency_injection.Container`): The tlsmate
                object used to inject the depencies into the test suite objects.
        """

        for prio_list in sorted(self.prio_pool.keys()):
            for cls in sorted(self.prio_pool[prio_list], key=lambda cls: cls.name):
                logging.debug(f"starting worker {cls.name}")
                cls(tlsmate).run()
                logging.debug(f"worker {cls.name} finished")


def register_worker(worker_class):
    WorkManager.register(worker_class)
    return worker_class
