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

Loading plugins
---------------

Plugins are python modules whose name start with ``tlsmate_``. These modules must
be located in directories that are searched by python when importing modules.

Thus, our plugin will reside in the file ``~/myplugin/tlsmate_myplugin.py``.
To make it visible for python, we will add the directory ``~/myplugin`` to the
environment variable ``PYTHONPATH``.

For our example this means we need to use the following command (bash assumed)::

    $ export PYTHONPATH=$PYTHONPATH:~/myplugin

Next, we need to tell ``tlsmate`` that it shall load the plugin. We will do this
by using an environment variable::

    $ export TLSMATE_PLUGIN=tlsmate_myplugin

Now let's create the file ``~/myplugin/tlsmate_myplugin.py`` with the following content:

.. literalinclude:: ../plugin_examples/tlsmate_myplugin.py

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

Ok. Now let's check the help text for the ``cipher-printer`` subcommand::

    $ tlsmate cipher-printer --help
    usage: tlsmate cipher-printer [-h] [--port PORT] [--sni SNI] [--text TEXT] host

    positional arguments:
      host         the target host. Can be given as a domain name or as an IPv4/IPv6
                   address.

    optional arguments:
      -h, --help   show this help message and exit
      --port PORT  the port number of the host [0-65535]. Defaults to 443.
      --sni SNI    the server name indication, i.e., the domain name of the server to
                   contact. If not given, the value will be taken from the host parameter.
                   This parameter is useful, if the host is given as an IP address.
      --text TEXT  the text used to print the negotiated cipher suite

Cool. And now let's give it a try::

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

.. note::
   In the example we used the environment variables ``TLSMATE_PLUGIN`` and
   ``TLSMATE_CA_CERTS`` for demo purposes. For real life use cases it might be
   more appropriate to define these settings in an ini-file. The content of the
   corresponding ini-file (``~/.tlsmate.ini``) would be as follows::

        [tlsmate]
        ca_certs = /etc/ssl/certs/ca-certificates.crt
        plugin = tlsmate_myplugin

Let's have a closer look at the classes involved.

Plugins and workers are an essential concept of ``tlsmate``. Indeed,
the scanner provided with the tool uses this concept internally as well. So if
in doubt you can have a look at the code.

The Worker class
----------------

Workers are derived from the class :class:`tlsmate.plugin.Worker`. Their task
is to do work (oh, really?), for example, they are executing test cases against
the TLS server, or they are processing the scan result.

All registered workers are executed in sequence according to their priorities.
Lower priority means earlier execution. If two workers have the same priority
their execution sequence is determined by the alphabetical order of their
names.

There are three different options to register a worker:

- Using :meth:`tlsmate.plugin.WorkManager.register` as a decorator.
    This will register the worker "unconditionally", i.e., it will always run, independent
    from any command line argument. Example:

    .. code-block:: python

        @WorkManager.register
        class MyWorker(Worker):
            pass

- Using :meth:`tlsmate.plugin.WorkManager.register` as a function.
    This allows to register the worker, e.g. based on conditions. Example:

    .. code-block:: python

        class MyWorker(WorkerPlugin):
            pass

        if some_condition:
            WorkManager.register(MyWorker)

- Add the worker to the ``worker`` attribute of the :class:`tlsmate.plugin.Plugin` class.
    This is the option chosen in the code example above. By default, the worker
    will be registered, if the subcommand or the command line option is
    specified by the user.

A worker is executed by calling the method :meth:`tlsmate.plugin.Worker.run`.


The Plugin class
----------------

A plugin is used to extend a plugin (whow!).

Ok, let' try that again: A plugin can be a CLI subcommand, a CLI argument group
or a CLI argument. And the ``tlsmate`` command line interface itself is a
plugin.

Plugins can extend other plugins by using the decorator
:meth:`tlsmate.plugin.Plugin.extend`.

In the code example above the base command :class:`tlsmate.plugin.BaseCommand`
is extended by the new subcommand ``cipher-printer``. This new subcommand has a
list of plugins, which define the CLI arguments for this subcommand. A list of
workers can be associated with this plugin as well, in this case the worker
``CipherPrinterWorker`` will be registered only if the ``cipher-printer``
subcommand has been chosen by the user.

In the example above the class ``ArgText`` defines a new command line argument
and associates it with the configuration item ``text``. I.e., the value
specified on the CLI for the ``--text`` argument will be available as
configuration item ``text``, and thus it is available for all workers as well.

For more details please refer to the description of the :class:`tlsmate.plugin.Plugin`.


The Configuration class
-----------------------

Let's have a look at the configuration handling. The class
:class:`tlsmate.config.Configuration` manages so called configuration items.
These items are structures which can be registered as desired. Such registered
configuration items are recognized by ``tlsmate``, and thus can be specified in
ini-files or can be set via environment variables. These configuration items
are then available for the workers as well.


Extending the server profile
----------------------------

Especially when extending the scanner it is typically desired to extend the
server profile as well.

For example, let's say we write a plugin which performs a simulation
for various TLS clients. The part which extends the server profile looks like this::

    from tlsmate.server_profile import (
        SPObject,
        ProfileSchema,
        SPVersionEnumSchema,
        SPCipherSuiteSchema,
        ServerProfileSchema,
    )


    class SPClient(SPObject):
        pass


    class SPClientSchema(ProfileSchema):
        __profile_class__ = SPClient

        name = fields.String()
        version = fields.Nested(SPVersionEnumSchema)
        cipher_suite = fields.Nested(SPCipherSuiteSchema)
        ...

    @ServerProfileSchema.augment
    class SPClientSimulation(ProfileSchema):
        client_simulation = fields.List(fields.Nested(SPClientSchema))

The class ``SPClientSchema`` defines the properties for a client. Now the
class :class:`tlsmate.server_profile.ServerProfileSchema` is extended by using
the decorator :meth:`tlsmate.server_profile.ProfileSchema.augment` as shown above.

.. note::

    The attribute ``__profile_class__`` must not be present in the class
    ``SPClientSimulation``, as it is defined in the ``ServerProfileSchema`` class.

The code in the worker can look like this::

    self.server_profile.client_simulation = []
    for client in client_list:
        ...
        client_prof = SPClient()
        client_prof.name = client.name
        client_prof.version = scan.version
        client_prof.cipher_suite = scan.cipher_suite
        ...
        self.server_profile.client_simulation.append(client_prof)

Using the mechanism described above ensures that serialization and deserialization
of the server profile considers the extension for the client simulation.


Extending the text server profile plugin
----------------------------------------

Displaying the server profile in text format is done by the
:class:`tlsmate.workers.text_server_profile.TextProfileWorker` class.

The ``TextProfileWorker`` provides a decorator which allows registering
functions which can implement the display of added server profile information as
described above. The function will be called with the text-profile-worker instance
as the only parameter.

Example::

    from tlsmate.workers.text_server_profile import TextProfileWorker, Style

    @TextProfileWorker.augment_output
    def print_client_simul(text_worker):
        if not hasattr(text_worker.server_profile, "client_simulation"):
            return

        print(Style.HEADLINE.decorate("Handshake simulation"))
        print()
        ...


