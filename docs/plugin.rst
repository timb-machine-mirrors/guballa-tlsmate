Writing a plugin for tlsmate
============================

This section focuses on how to extend ``tlsmate`` by a plugin. We do not
concentrate much here on how a TLS connection is setup, instead you will see
which classes are relevant for embedding your python code into the application.

The challenge
-------------

Let's give us the following task: We want to write a plugin which establishes a
TLS connection to a server and prints the cipher suite negotiated for this
connection. The output of the cipher suite shall be preceded with a string
which we can provide as a command line parameter (well, that's an odd
requirement, but it will demonstrate how to define and use additional command
line arguments). The plugin we are writing shall be located in the directory
``~/myplugin``.

So, here is the command we want to execute::

    $ tlsmate cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net

The new subcommand ``cipher-printer`` is the command line argument to run our plugin.

Here is the expected output::

    Negotiated cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Locating plugins
----------------

``tlsmate`` has a simple mechanism to load plugins: all python modules starting
with ``tlsmate_`` are imported. I.e., all we have to do is to create a file
like ``tlsmate_myplugin.py``, and add the directory where it resides to the
environment variable ``PYTHONPATH``.

For our example this means we need to use the following command (bash assumed)::

    $ export PYTHONPATH=$PYTHONPATH:~/myplugin

Now let's create the file ``~/myplugin/tlsmate_myplugin.py`` with the following content:

.. code-block:: python

    from tlsmate.plugin import CliConnectionPlugin, CliManager, WorkerPlugin, WorkManager
    from tlsmate.structs import ConfigItem
    from tlsmate import tls


    class MyWorker(WorkerPlugin):
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


    @CliManager.register
    class MyPlugin(CliConnectionPlugin):
        name = "cipher-printer"
        prio = 100

        def register_config(self, config):
            # Register an additional configuration item. Note, that it can be provided
            # in an ini-file as well as via the environment variable ``TLSMATE_TEXT``.
            config.register(ConfigItem("text", type=str, default="cipher suite: "))

        def add_subcommand(self, subparsers):
            # add a new subcommand and a new argument
            parser = subparsers.add_parser(
                self.name, help="prints the negotiated cipher suite"
            )
            parser.add_argument("--text", help="print a user defined text", type=str)

        def args_parsed(self, args, parser, subcommand, config):
            if subcommand == self.name:
                # if ``cipher-printer`` was given ...
                super().args_parsed(args, parser, subcommand, config)
                # ...register the worker
                WorkManager.register(MyWorker)
                # ... and set the configuration item's value to the given command line argument
                config.set("text", args.text)

First let's check if the newly defined subcommand is recognized by ``tlsmate``::

    $ tlsmate --help
    usage: tlsmate [-h] [--config CONFIG_FILE]
                   [--logging {critical,error,warning,info,debug}]
                   {scan,version,cipher-printer} ...

    ...

    commands:
      {scan,version,cipher-printer}
        scan                performs a TLS server scan
        version             prints the version of tlsmate
        cipher-printer      prints the negotiated cipher suite

Ok. Now let's give it a try::

    $ tlsmate cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net
    ...
    ...
    tlsmate.exception.CertChainValidationError: issuer certificate "CN=DST Root CA X3,O=Digital Signature Trust Co." for certificate "CN=R3,O=Let's Encrypt,C=US" not found in trust store

Ups, the trust store is not yet defined. Let's fix that using an environment variable.
For details refer to `CLI configuration options <cli_config.html>`__.
In the example we assume an Ubuntu system, and we are using bash::

    $ export TLSMATE_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
    $ tlsmate cipher-printer --text="Negotiated cipher suite:" mytlsmatedomain.net
    Negotiated cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Perfect.

.. note::
   The name of the cipher suite may differ, depending on the server you are using.

Let's have a closer look at the classes involved.

CLI plugins and worker plugins are an essential concept of ``tlsmate``. Indeed,
the scanner provided with the tool uses this concept internally as well. So if
in doubt you can have a look at the code.

CLI plugins are basically extending the CLI, while worker plugins (or simply
called "workers") do all the hard stuff like executing arbitrary TLS message
flows or scanning for specific TLS server configurations and vulnerabilities.
But workers are also used to read and write server profile files or dumping
such profiles in a human readable format to the user. Workers simply do
something.

The CliPlugin class
-------------------

The base class :obj:`tlsmate.plugin.CliPlugin` is provided to derive specific
classes from that are extending the CLI. These plugins are responsible for the
following tasks:

* add additional configuration items to the :obj:`tlsmate.config.Configuration` object
* define additional subcommands
* define additional arguments for the CLI, i.e., extend the argument parser
* evaluate the command line arguments parsed, map these arguments to the
  configuration items and register the worker classes as desired.

CLI plugins are registered by decorating the class with the
:meth:`tlsmate.plugin.PluginManager.register` decorator.

The methods which can be used to tailor the plugin are:

* :meth:`tlsmate.plugin.CliPlugin.register_config`, used to add new configuration
  items to ``tlsmate``
* :meth:`tlsmate.plugin.CliPlugin.add_subcommand`, used to add a new subcommand
* :meth:`tlsmate.plugin.CliPlugin.add_args`, used to extend any subcommand by
  additional arguments
* :meth:`tlsmate.plugin.CliPlugin.args_parsed`, called after the arguments have been
  parsed. Can be used to update the configuration and to register workers

.. note::
    For plugins which actually are opening TLS connections, the class
    :class:`tlsmate.plugin.CliConnectionPlugin` is provided, which can be
    used as a base class with the advantage that TLS connection related
    arguments are provided. This class has been used in the example above.
    To see the full benefit, use ``tlsmate cipher-printer --help``.

The WorkerPlugin class
----------------------

Workers are derived from the class :class:`tlsmate.plugin.WorkerPlugin`. Analog
to the CLI plugins, worker classes must be registered to the
:class:`tlsmate.plugin.WorkManager`. There are two ways to do this.

Using :meth:`tlsmate.plugin.WorkManager.register` as a decorator. This will
register the worker "unconditionally", i.e., it will always run, independent
from any command line argument. In such a case the usage of the CliPlugin class
is not required. Example:

.. code-block:: python

    @WorkManager.register
    class MyWorker(WorkerPlugin):
        pass

Using :meth:`tlsmate.plugin.WorkManager.register` as a function. This allows to
register the worker from within a CLI plugin. Example:

.. code-block:: python

    class MyWorker(WorkerPlugin):
        pass

    WorkManager.register(MyWorker)

Workers are executed in the sequence which is defined by the priority
attribute. Lower priority means earlier execution. If two workers have the same
priority their execution sequence is determined by the alphabetical order of
their names.

The Configuration class
-----------------------

Let's have a look at the configuration handling. The class
:class:`tlsmate.config.Configuration` manages so called configuration items.
These items are structures which can be registered as desired. Such registered
configuration items are recognized by ``tlsmate``, and thus can be specified in
ini-files or can be set via environment variables. These configuration items
are then available for the workers as well.

In our code example we defined the configuration item in
:meth:`tlsmate.plugin.CliPlugin.register_config`, and its value is populated
from the given parsed arguments. Note, that in
:meth:`tlsmate.plugin.CliPlugin.args_parsed` the configuration item might have
already a value populated, either taken from the ini-file or from an
environment variable. Using :meth:`tlsmate.config.Configuration.set` with the
value None will actually not overwrite the current value.

Extending the server profile
----------------------------

Especially when extending the scanner it is typically desired to extend the
server profile as well.

For example, let's say we write a plugin which scans for the POODLE
vulnerability and its variants. The YAML part of the server profile
shall look as follows, i.e., the vulnerability part is extended
by the ``poodle`` block::

    vulnerabilities:
        ccs_injection: C_NA
        heartbleed: NOT_APPLICABLE
        poodle:
            golden_poodle: C_FALSE
            poodle: C_FALSE
            poodle_tls: C_FLASE
            zombie_poodle: C_FALSE
        robot: NOT_APPLICABLE

Therefore, the CLI plugin should contain something similar to this code
snippet:

.. code-block:: python

    from tlsmate.server_profile import (
        ProfileSchema, SPVulnerabilitiesSchema, FieldsEnumString, SPObject
    )
    from tlsmate import tls

    class SPPoodle(SPObject):
        """Data class for Poodle vulnerabilitites"""

    class SPPoodleSchema(ProfileSchema):
        """Schema class for Poodle vulnerabilitites"""
        __profile_class__ = SPPoodle
        golden_poodle = FieldsEnumString(enum_class=tls.SPBool)
        poodle = FieldsEnumString(enum_class=tls.SPBool)
        poodle_tls = FieldsEnumString(enum_class=tls.SPBool)
        zombie_poodle = FieldsEnumString(enum_class=tls.SPBool)

    # extend the schema ``SPVulnerabilitiesSchema`` by one additional field
    @ProfileSchema.augment(SPVulnerabilitiesSchema)
    class SPVulnExtensions(ProfileSchema):
        poodle = fields.Nested(SPPoodleSchema)

Through the decorator ``ProfileSchema.augment`` the existing vulnerability
schema class ``SPVulnerabilitiesSchema`` is extended by the field ``poodle``,
which refers to the nested schema ``SPPoodleSchema``.

.. note::

    The attribute ``__profile_class__`` must not be present in the class
    ``SPVulnExtensions``, as it is defined in the ``SPVulnerabilitiesSchema`` class.

The code in the worker can look like this (note, we are using hard-coded values here
for simplification):

.. code-block:: python

    poodle = SPPoodle()
    poodle.golden_poodle = tls.SPBool.C_FALSE
    poodle.poodle = tls.SPBool.C_FALSE
    poodle.poodle_tls = tls.SPBool.C_FALSE
    poodle.zombie_poodle = tls.SPBool.C_FALSE
    self.server_profile.vulnerabilities.poodle = poodle

Using the mechanism described above ensures that serialization and deserialization
of the server profile considers the defined extension.
