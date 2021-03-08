# -*- coding: utf-8 -*-
"""Module implementing a suite manager class
"""
# import basic stuff
import logging

# import own stuff

# import other stuff


class SuiteManager(object):
    """Manages the plugins (suites) and runs them.

    The suite manager provides an interface to register suites.

    The registered plugins are triggered (via their run-method) based on their
    priority.

    Attributes:
        cli_help (dict): Mapps the plugins identified by their cli-name (i.e. their
            command line option name) to the corresponding CLI help text.
        test_suite (dict): Maps the cli-names of the registered plugins to the
            corresponding classes.
    """

    cli_help = {}
    test_suites = {}
    prio_pool = {}

    @classmethod
    def register_cli(cls, argument, cli_help="", classes=[]):
        """Function to register a test suite.

        Arguments:
            argument (str): The CLI option argument used to execute the plugin.
            cli_help (str): The CLI help text for the argument.
            classes (list of :obj:`TestSuite`): A list of plugins associated with
                the argument name.

        Raises:
            ValueError: If another plugin is already registered under the given
            argument name.
        """
        if argument in cls.cli_help:
            raise ValueError(f"CLI option {argument} is already registered")
        cls.cli_help[argument] = cli_help
        cls.test_suites[argument] = classes

    @classmethod
    def register(self, classes):
        """Register a set of non-cli test suites.

        Arguments:
            classes (list of :obj:`TestSuite`): A list of plugins that are executed
            regardless of any cli options.
        """
        for cls in classes:
            self.prio_pool.setdefault(cls.prio, [])
            self.prio_pool[cls.prio].append(cls)

    def run(self, tlsmate, selected_test_suite_args):
        # TODO: adapt description
        """Function to actually start the test manager.

        Arguments:
            TODO:
            tlsmate (:obj:`tlsmate.dependency_injection.Container`): The tlsmate
                object used to inject the depencies into the test suite objects.
            selected_test_suite_args (list of str): The list of CLI options which
                were given on the CLI to select a set of plugins.
        """
        for arg in selected_test_suite_args:
            for cls in self.test_suites[arg]:
                self.prio_pool.setdefault(cls.prio, [])
                if cls not in self.prio_pool[cls.prio]:
                    self.prio_pool[cls.prio].append(cls)
        for prio_list in sorted(self.prio_pool.keys()):
            for cls in sorted(self.prio_pool[prio_list], key=lambda cls: cls.name):
                logging.debug(f"starting test suite {cls.name}")
                test_suite = cls()
                test_suite._inject_dependencies(tlsmate.server_profile, tlsmate.client)
                test_suite.run()
                logging.debug(f"test suite {cls.name} finished")
