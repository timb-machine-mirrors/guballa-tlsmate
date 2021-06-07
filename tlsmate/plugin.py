# -*- coding: utf-8 -*-
"""Module providing stuff for plugin handling
"""
# import basic stuff
import logging
import abc

# import own stuff
from tlsmate import utils

# import other stuff


def _add_basic_arguments(parser):
    """Add basic arguments to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    parser.add_argument(
        "--interval",
        default=0,
        help="the interval in milliseconds between two handshakes.",
        type=int,
    )
    parser.add_argument(
        "--key-log-file",
        default=None,
        help=(
            "write to a key log file which can be used by wireshark to decode "
            "encrypted traffic."
        ),
    )

    parser.add_argument(
        "--progress",
        help="provides a progress indicator. Defaults to False.",
        action=utils.BooleanOptionalAction,
    )

    parser.add_argument(
        "--sni",
        type=str,
        help=(
            "the server name indication, i.e., the domain name of the server to "
            "contact. If not given, the value will be taken from the host parameter "
            "(after stripping of the port number, if present). This parameter is "
            "useful, if the host is given as an IP address."
        ),
    )

    parser.add_argument(
        "host",
        help=(
            "the host to scan. May optionally have the port number appended, "
            "separated by a colon. The port defaults to 443."
        ),
        type=str,
    )


def _add_args_authentication(parser):
    """Add basic arguments for authentication to a parser

    Arguments:
        parser (:obj:argparse.Parser): The (sub)parser to add arguments to.
    """

    group = parser.add_argument_group(title="X509 certificates options")
    group.add_argument(
        "--ca-certs",
        nargs="*",
        type=str,
        help=(
            "list of root-ca certificate files. Each file may contain multiple "
            "root-CA certificates in PEM format. Certificate chains received from "
            "the server will be validated against this set of root certificates."
        ),
    )

    group.add_argument(
        "--client-key",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the client private keys in PEM format. "
            "Used for client authentication."
        ),
        default=None,
    )
    group.add_argument(
        "--client-chain",
        type=str,
        nargs="*",
        help=(
            "a list of files containing the certificate chain used for client "
            "authentication in PEM format. The number of given files must be the "
            "same than the number of given client key files. This first given "
            "chain file corresponds to the first given client key file, and so on."
        ),
    )

    group.add_argument(
        "--crl",
        help=(
            "download the CRL to check for the certificate revocation status. "
            "Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )
    group.add_argument(
        "--ocsp",
        help=(
            "query the OCSP servers for checking the certificate revocation status. "
            "Defaults to True."
        ),
        action=utils.BooleanOptionalAction,
    )


class CliPlugin(metaclass=abc.ABCMeta):
    """Base abstract class for a plugin

    Attributes:
        name (str): The unique name of the plugin, used to avoid multiple registrations
            of the same CLI plugin.
        prio (int): The prio determines the sequence of the plugins. It is only
            relevant for displaying the command help with ``--help``: The sequence
            of parameters in the help is determined according to the prio of the CLI
            plugin.
    """

    name = None
    prio = 50

    def register_config(self, config):
        """A callback method which can be used to extend ``tlsmate``'s configuration

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        return

    def add_subcommand(self, subparsers):
        """Adds a subcommand to the CLI parser object.

        Arguments:
            subparser (:obj:`argparse.Action`): the CLI subparsers object
        """

        return

    def add_args(self, parser, subcommand):
        """A callback method used to add arguments to the CLI parser object.

        This method is called to allow the CLI plugin to add additional command line
        argument to the parser.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
            subcommand (str): the subcommand for which arguments can be added. If None,
                the global arguments (valid for all subcommands) can be added.
        """

        return

    def args_parsed(self, args, parser, subcommand, config):
        """A callback method called after the arguments have been parsed.

        This is the point where the CLI plugin evaluates the given command line
        arguments, adapts the configuration object accordingly and registers
        the workers accordingly.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser (:obj:`argparse.Parser`): the parser object, can be used to issue
                consistency errors
            subcommand (str): the subcommand that was given
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        return


class CliConnectionPlugin(CliPlugin):
    """Base class for plugins which is using TLS connections.

    This class basically provides the common CLI arguments.
    """

    def add_args(self, parser, subcommand):
        """A callback method used to add arguments to the CLI parser object.

        This method is called to allow the CLI plugin to add additional command line
        argument to the parser.

        Arguments:
            parser (:obj:`argparse.Parser`): the CLI parser object
            subcommand (str): the subcommand for which arguments can be added. If None,
                the global arguments (valid for all subcommands) can be added.
        """

        if subcommand == self.name:
            _add_basic_arguments(parser)
            _add_args_authentication(parser)

    def args_parsed(self, args, parser, subcommand, config):
        """A callback method called after the arguments have been parsed.

        This is the point where the CLI plugin evaluates the given command line
        arguments, adapts the configuration object accordingly and registers
        the workers accordingly.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser (:obj:`argparse.Parser`): the parser object, can be used to issue
                consistency errors
            subcommand (str): the subcommand that was given
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if subcommand == self.name:
            config.set("ca_certs", args.ca_certs)
            config.set("client_chain", args.client_chain)
            config.set("client_key", args.client_key)
            config.set("crl", args.crl)
            config.set("endpoint", args.host)
            config.set("interval", args.interval)
            config.set("key_log_file", args.key_log_file)
            config.set("ocsp", args.ocsp)
            config.set("progress", args.progress)
            config.set("sni", args.sni)


class CliManager(object):
    """A static class which manages the CLI plugins.

    CLI plugins are mainly used to extend the CLI and to register workers based on the
    given command line options. The CliManager takes care of integrating the
    registered CLI plugins accordingly.
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
        """Register a class derived from :class:`CliPlugin` as a plugin.

        Typically be used as a class decorator.

        Arguments:
            plugin (:class:`CliPlugin`): The class to register

        Returns:
            :class:`CliPlugin`: the plugin class from the arguments

        Raises:
            ValueError: If there is already another plugin registered under the
                same name.
        """

        if plugin.name in cls._plugins:
            raise ValueError(
                f"Another CLI plugin is already registered under the name "
                f'"{plugin.name}"'
            )

        cls._plugins[plugin.name] = plugin
        return plugin

    @classmethod
    def extend_parser(cls, parser):
        """Adds the command line options for all registered CLI plugins.

        At this point the CLI plugin classes are instantiated as well.

        Arguments:
            parser (:obj:`argparse.Parser`): the parser object to add the arguments to.
        """

        # required=True supported from Python3.7 on. Don't use it,
        # and implement a consitency check
        subparsers = parser.add_subparsers(title="commands", dest="subcommand")

        cls._objects = []
        for plugin_cls in sorted(cls._plugins.values(), key=lambda x: x.prio):
            plugin = plugin_cls()
            plugin.add_subcommand(subparsers)
            cls._objects.append(plugin)

        for plugin in cls._objects:
            plugin.add_args(parser, subcommand=None)
            for subcommand, subparser in subparsers.choices.items():
                plugin.add_args(subparser, subcommand=subcommand)

    @classmethod
    def register_config(cls, config):
        """Extend the configuration by all registered CLI plugins.

        Arguments:
            config (:obj:`tlsmate.config.Configuration`): The configuration that is to
                be extended.
        """
        for plugin in cls._objects:
            plugin.register_config(config)

    @classmethod
    def args_parsed(cls, args, parser, config):
        """Call the callbacks for all registered CLI plugins.

        This method will be called after the CLI arguments have been parsed. Now
        the plugins can perform consistency checks on their CLI options, and they can
        decide which workers are to be registered.

        Arguments:
            args: the object holding the parsed CLI arguments
            parser (:obj:`argparse.Parser`): the CLI parser object
            config (:obj:`tlsmate.config.Configuration`): the configuration object
        """

        if args.subcommand is None:
            parser.error("Subcommand is mandatory")

        for plugin in cls._objects:
            plugin.args_parsed(args, parser, args.subcommand, config)


def register_cli_plugin(plugin):
    """Alternative decorator to register CLI plugins.

    Might be removed in the future.

    Arguments:
        plugin (:class:`CliPlugin`): The class to register
    """
    CliManager.register(plugin)
    return plugin


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
                logging.debug(f"starting worker {cls.name}")
                cls(tlsmate).run()
                logging.debug(f"worker {cls.name} finished")


def register_worker(worker_class):
    """Alternative decorator to register workers.

    Might be removed in the future.

    Arguments:
        worker_class (:class:`WorkerPlugin`): A worker plugin class to be registered.
    """

    WorkManager.register(worker_class)
    return worker_class
