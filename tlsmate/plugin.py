# -*- coding: utf-8 -*-
"""Module providing stuff for plugin handling
"""
# import basic stuff
import logging
import abc
import sys

# import own stuff

# import other stuff


class Args(object):
    def __init__(self, *args, **kwargs):
        self.arg = args[0] if args else None
        self.kwargs = kwargs


class Plugin(metaclass=abc.ABCMeta):
    config = None
    group = None
    subcommand = None
    cli_args = None
    plugins = None
    workers = None
    _config_registered = False

    @classmethod
    def args_name(cls):
        if "dest" in cls.cli_args.kwargs:
            return cls.cli_args.kwargs["dest"]

        name = cls.cli_args.arg
        if name.startswith("--"):
            name = name[2:]

        return name.replace("-", "_")

    @classmethod
    def extend(cls, plugin):
        if cls.plugins is None:
            cls.plugins = []
        cls.plugins.append(plugin)
        return plugin

    @classmethod
    def extend_parser(cls, parser, subparsers):
        if cls.cli_args:
            parser.add_argument(cls.cli_args.arg, **cls.cli_args.kwargs)

        elif cls.subcommand:
            parser = subparsers.add_parser(cls.subcommand.arg, **cls.subcommand.kwargs)

        elif cls.group:
            parser = parser.add_argument_group(**cls.group.kwargs)

        if cls.plugins is not None:
            for plugin in cls.plugins:
                plugin.extend_parser(parser, subparsers)

    @classmethod
    def register_config(cls, config):
        if cls._config_registered:
            return

        cls._config_registered = True
        if cls.config:
            config.register(cls.config)

        if cls.plugins:
            for plugin in cls.plugins:
                plugin.register_config(config)

    @classmethod
    def args_parsed(cls, args, parser, subcommand, config):
        if cls.subcommand and cls.subcommand.arg != subcommand:
            return

        register_workers = False
        if cls.cli_args and cls.config:
            val = getattr(args, cls.args_name())
            if val is not None:
                config.set(cls.config.name, val)

        if cls.config:
            register_workers = cls.config.type not in [None, False]

        elif cls.subcommand:
            register_workers = True

        if register_workers and cls.workers is not None:
            for worker in cls.workers:
                WorkManager.register(worker)

        if cls.plugins is not None:
            for plugin in cls.plugins:
                plugin.args_parsed(args, parser, subcommand, config)


class PluginBase(Plugin):
    pass


class WorkerPlugin(metaclass=abc.ABCMeta):
    """Provides a base class for the implementation of a worker.

    Attributes:
        name (str): name of the worker, used for logging purposes only
        prio (int): all workers are executed according to their the priority.
            A lower value indicates higher priority, i.e., the worker with the lowest
            value will run first. If two workers have the same priority, their
            execution order will be determined by the alphabetical order of their
            name attribute.
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
        """Entry point for the worker.

        The work manager will call this method which actually let worker do its job.
        """

        raise NotImplementedError


class WorkManager(object):
    """Manages the registered worker plugins and runs them.

    The worker manager provides an interface to register worker plugins.

    The registered workers are triggered (via their run-method) based on their
    priority by calling their run method.
    """

    _prio_pool = {}

    @classmethod
    def register(self, worker_class):
        """Register a worker plugin class.

        Can be used as a decorator.

        Arguments:
            worker_class (:class:`WorkerPlugin`): A worker class to be registered.

        Returns:
            :class:`WorkerPlugin`: the worker class passed as argument
        """

        self._prio_pool.setdefault(worker_class.prio, [])
        self._prio_pool[worker_class.prio].append(worker_class)
        return worker_class

    def run(self, tlsmate):
        """Function to actually start the work manager.

        The run method of all registered worker plugins will be called according to the
        priority of the workers.

        Arguments:
            tlsmate (:obj:`tlsmate.tlsmate.TlsMate`): The tlsmate object which is passed
                to the run methods of the workers.
        """

        for prio_list in sorted(self._prio_pool.keys()):
            for cls in sorted(self._prio_pool[prio_list], key=lambda cls: cls.name):
                if tlsmate.config.get("progress"):
                    sys.stderr.write(f"\n{cls.descr}")
                    sys.stderr.flush()

                logging.debug(f"starting worker {cls.name}")
                cls(tlsmate).run()
                logging.debug(f"worker {cls.name} finished")
