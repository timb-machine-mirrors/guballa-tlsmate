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
    """str: The unique name of the plugin, used to avoid multiple registrations of the
    same plugin.
    """

    prio = 50
    """int: The prio determines the sequence of the plugins. The sequence determines
    in which order the added CLI options will be displayed. when the ``--help``
    options is used.
    """

    cli_name = None
    """str: The command line argument which causes the plugin to be activated. Includes
    the two dashes, e.g., ``--scan``. If set to None, the plugin will always be 
    activated.
    """

    cli_help = None
    """str: The help text used on the CLI for the cli_name option
    """

    def register_config(self, config):
        """Register configs for this plugin

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        return

    def add_args(self, parser):
        """Adds arguments to the CLI parser object.

        This method is called to allow the plugin to add additional command line
        argument to the parser.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
        """

        return

    def args_parsed(self, args, parser, config):
        """Called after the arguments have been parsed.

        This is the point where the plugin evaluates the given command line arguments,
        adapts the configuration object accordingly and registers the workers
        accordingly.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser (:obj:`argparse.Parser`): the parser object, can be used to issue
                consistency errors
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        return


class PluginManager(object):
    """A static class which manages the plugins.

    Plugins are mainly used to extend the CLI and to register workers based on the
    given command line options. The PluginManager takes care of integrating the
    registered plugins accordingly.
    """

    _plugins = {}
    _objects = []
    _cli_names = []

    @classmethod
    def reset(cls):
        """Method to cleanly initialize this class
        """
        cls._plugins = {}
        cls._objects = []

    @classmethod
    def register(cls, plugin):
        """Register a class derived from :class:`Plugin` as a plugin.

        Typically be used as a class decorator.

        Arguments:
            plugin (:class:`Plugin`): The class to register

        Returns:
            :class:`Plugin`: the plugin class from the arguments

        Raises:
            ValueError: If there is already another plugin registered under the
                same name.
        """

        if plugin.name in cls._plugins:
            raise ValueError(
                f"Another plugin is already registered under the name "
                f'"{plugin.name}"'
            )

        cls._plugins[plugin.name] = plugin
        return plugin

    @classmethod
    def add_args(cls, parser):
        """Adds the command line options for all registered plugins.

        At this point the plugin classes are instantiated as well.

        Arguments:
            parser (:obj:`argparse.Parser`): the parser object to add the arguments to.
        """

        group = parser.add_argument_group(title="Available plugins")
        for plugin in sorted(cls._plugins.values(), key=lambda x: x.prio):
            if plugin.cli_name is not None:
                cls._cli_names.append(plugin.cli_name[2:])
                group.add_argument(
                    plugin.cli_name,
                    help=plugin.cli_help,
                    action="store_true",
                    default=False,
                )

            cls._objects.append(plugin())

        for plugin in cls._objects:
            plugin.add_args(parser)

    @classmethod
    def register_config(cls, config):
        """Extend the configuration by all registered plugins.

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): The configuration that is to
                be extended.
        """
        for plugin in cls._objects:
            plugin.register_config(config)

    @classmethod
    def args_parsed(cls, args, parser, config):
        """Call the callbacks for all registered plugins.

        This method will be called after the CLI arguments have been parsed. Now
        the plugins can perform consistency checks on their CLI options, and they can
        decide which workers are to be registered.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser (:obj:`argparse.Parser`): the CLI parser object
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if not any([getattr(args, name.replace("-", "_")) for name in cls._cli_names]):
            cli_names = ",".join(["--" + name for name in cls._cli_names])
            parser.error(f"specify at least one of the following options: {cli_names}")

        for plugin in cls._objects:
            plugin.args_parsed(args, parser, config)


def register_plugin(plugin):
    """Alternative decorator to register plugins.

    Might be removed in the future.

    Arguments:
        plugin (:class:`Plugin`): The class to register
    """
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
        self._tlsmate = tlsmate
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
    priority by calling their run method.
    """

    _prio_pool = {}

    @classmethod
    def register(self, worker_class):
        """Register a worker class.

        Can be used as a decorator.

        Arguments:
            worker_class (:class:`Worker`): A worker class to be registered.

        Returns:
            :class:`Worker`: the worker class passed as argument
        """

        self._prio_pool.setdefault(worker_class.prio, [])
        self._prio_pool[worker_class.prio].append(worker_class)
        return worker_class

    def run(self, tlsmate):
        """Function to actually start the work manager.

        The run method of all registered workers will be called according to the
        priority of the workers.

        Arguments:
            tlsmate (:obj:`tlsmate.tlsmate.TlsMate`): The tlsmate object which is passed
                to the run methods of the workers.
        """

        for prio_list in sorted(self._prio_pool.keys()):
            for cls in sorted(self._prio_pool[prio_list], key=lambda cls: cls.name):
                logging.debug(f"starting worker {cls.name}")
                cls(tlsmate).run()
                logging.debug(f"worker {cls.name} finished")


def register_worker(worker_class):
    """Alternative decorator to register workers.

    Might be removed in the future.

    Arguments:
        worker_class (:class:`Worker`): A worker class to be registered.
    """

    WorkManager.register(worker_class)
    return worker_class
