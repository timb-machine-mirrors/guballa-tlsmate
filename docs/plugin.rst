Writing a plugin for tlsmate
============================

This section focuses on how to extend ``tlsmate`` by a plugin. We do not concentrate much
here on how a TLS connection is setup, instead you will see which classes are relevant
for embeeding your TLS scenarios into the application.

The challenge
-------------

Let's give us the following task: We want to write a plugin which establishes
a TLS connection to a server and prints the cipher suite negotiated for this connection.
The output of the cipher suite shall be preceded with a string which we can provide as
a command line parameter (well, that's an odd requirement, but it will demonstrate how to define
and use additional command line arguments). The plugin we are writing shall be located
in the directory ``~/myplugin``.

So, here is the command we want to execute::

    $ tlsmate --cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net

The new argument ``--cipher-printer`` is the command line argument to run our plugin.

Here is the expected output::

    Negotiated cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Locating plugins
----------------

``tlsmate`` has a simple mechanism to load plugins: all python modules starting with
``tlsmate_`` are imported. I.e., all we have to do is to create a file like ``tlsmate_myplugin.py``,
and add the directory where it resides to the environment variable ``PYTHONPATH``.

For our example this means we need to use the following command (bash assumed)::

    $ export PYTHONPATH=~/myplugin

Now let's create the file ``~/myplugin/tlsmate_myplugin.py`` with the following content:

.. code-block:: python

    from tlsmate.plugin import Plugin, PluginManager, Worker, WorkManager
    from tlsmate.structs import ConfigItem
    from tlsmate import tls


    class MyWorker(Worker):
        name = "cipher_suiter"
        prio = 100

        def run(self):
            # Let's use a default client profile which has a high probability to successfully
            # interoperate with a typical web server.
            self.client.set_profile(tls.Profile.INTEROPERABILITY)

            # Now open a TLS connection and execute a typical TLS handshake. Print the
            # cipher suite selected by the server.
            with self.client.create_connection() as conn:
                conn.handshake()
                print(self.config.get("text"), conn.msg.server_hello.cipher_suite)


    @PluginManager.register
    class MyPlugin(Plugin):
        name = "cipher_suite_dumper"
        prio = 100
        cli_name = "--cipher-printer"
        cli_help = "prints the negotiated cipher suite"

        def register_config(self, config):
            # Register an additional configuration item. Note, that it can be provided
            # in an ini-file as well as via the environment variable ``TLSMATE_TEXT``.
            config.register(ConfigItem("text", type=str, default="cipher suite: "))

        def add_args(self, parser):
            # Register an additional command line argument.
            parser.add_argument("--text", help="print a user defined text", type=str)

        def args_parsed(self, args, parser, config):
            if args.cipher_printer:
                # if ``--cipher-printer`` was given ...
                # ...register the worker
                WorkManager.register(MyWorker)
                # ... and set the configuration item's value to the given command line argument
                config.set("text", args.text)


First let's check if the newly defined command line arguments are recognized by ``tlsmate``::

    $ tlsmate --help
    usage: tlsmate [-h] [--version] [--config CONFIG_FILE] [--interval INTERVAL]
    ...
    --text TEXT           print a user defined text
    ...
    Available plugins:
      --scan                scan for TLS server configurations, features and
                            vulnerabilities
      --cipher-printer      prints the negotiated cipher suite
    ...

Ok. Now let's give it a try::

    $ tlsmate --cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net
    ...
    ...
    tlsmate.exception.CertChainValidationError: issuer certificate "CN=DST Root CA X3,O=Digital Signature Trust Co." for certificate "CN=R3,O=Let's Encrypt,C=US" not found in trust store

Ups, the trust store is not yet defined. Let's fix that using an environment variable.
For details refer to `CLI configuration options <cli_config.html>`__.
In the example we assume an Ubuntu system, and we are using bash::

    $ export TLSMATE_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
    $ tlsmate --cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net
    Negotiated cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Perfect.

.. note::
   The name of the cipher suite may differ, depending on the server you are using.

Let's have a closer look at the classes involved.

Plugins and Workers are an essential concept of ``tlsmate``. Indeed, the scanner provided
with the tool uses this concept internally as well. So if in doubt you can have a look at the code.

Plugins are basically extending the CLI, while workers do all the hard stuff like
executing arbitrary TLS message flows or scanning for specific TLS server configurations and
vulnerabilities. But workers are also used to read and write server profile files or dumping
such profiles in a human readable format to the user. Workers simply do something.

The Plugin class
----------------

The base class :obj:`tlsmate.plugin.Plugin` is provided to derive specific plugin classes from.
Plugins are responsible for the following tasks:

* add additional configuration items to the :obj:`tlsmate.config.Configuration` object
* define additional arguments for the CLI, i.e., extend the argument parser
* evaluate the command line arguments parsed, map these arguments to the
  configuration items and register the worker classes as desired.

Plugins are registered by decorating the class with the :meth:`tlsmate.plugin.PluginManager.register`
decorator.

The attributes :attr:`tlsmate.plugin.Plugin.cli_name` and :attr:`tlsmate.plugin.Plugin.cli_help` define
the command line argument which is associated with the plugin. Additional command line arguments
can be defined in the method :meth:`tlsmate.plugin.Plugin.add_args`.

The method :meth:`tlsmate.plugin.Plugin.register_config` is used to define additional configuration
items including their default values. Note, that defining default values for command line arguments
is a pitfall: In such a case values defined in an ini-file or via environment variables will have
no effect.

The Worker class
----------------

Workers are derived from the class :class:`tlsmate.plugin.Worker`. Analog to the plugins, worker
classes must be registered to the :class:`tlsmate.plugin.WorkManager`. There are two ways to
do this.

Using :meth:`tlsmate.plugin.WorkManager.register` as a decorator. This will register the
worker "unconditionally", i.e., it will always run, independent from any command line arguments.
In such a case the usage of the Plugin class is not required. Example:

.. code-block:: python

    @WorkManager.register
    class MyWorker(Worker):
        pass

Using :meth:`tlsmate.plugin.WorkManager.register` as a function. This allows to register
the worker from within a plugin. Example:

.. code-block:: python

    class MyWorker(Worker):
        pass

    WorkManager.register(MyWorker)

Workers are executed in the sequence which is defined by the priority attribute. Lower
priority means earlier execution. If two workers have the same priority their execution
sequence is determined by the alphabetical order of their names.

The Configuration class
-----------------------

Let's have a look at the configuration handling. The class :class:`tlsmate.config.Configuration`
manages so called configuration items. These items are structures which can be registered as
desired. Such registered configuration items are recognized by ``tlsmate``, and thus can be
specified in ini-files or can be set via environment variables. These configuration items
are then available for the workers as well.

In our code example we defined the configuration item in :meth:`tlsmate.plugin.Plugin.register_config`,
and its value is populated from the given parsed arguments. Note, that in
:meth:`tlsmate.plugin.Plugin.args_parsed` the configuration item might have already a value
populated, either taken from the ini-file or from an environment variable. Using
:meth:`tlsmate.config.Configuration.set` with the value None will actually not overwrite
the current value.
