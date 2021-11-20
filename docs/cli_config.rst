CLI configuration options
=========================

Providing a command line option each and every time with the same value can be
very boring. For example, it is not very handy to specify the ``--ca-certs``
option over and over again. This is where environment variables and ini-files
come into play: ``tlsmate`` determines the values for command line options from different sources.
They are listed below according to the preference (most relevant source comes first):

* command line arguments
* environment variables
* ini-file
* hard-coded default values

First, the command line option is evaluated. If it is specified, its value will be used.
Otherwise, the correspondig environment variable will be evaluated. If it is not defined,
then tlsmate tries to read the value from an ini-file. If that file is not present, or if
the setting is not defined within that file, then tlsmate will use its hard-coded default
value.

For example, if the logging level shall be set to "debug", this can be done on the CLI by
providing the argument ``--logging=debug``.

Environment variables
---------------------

For using environment variables the following rules apply: The name of the variable starts
with ``TLSMATE_`` and is appended by the name of the option in upper case and the dashes
("``-``") replaced by underscores ("``_``"). For the logging example above the
correspondig definition of the environment variable is as follows (bash shell
is assumed)::

    export TLSMATE_LOGGING=debug

Ini-files
---------

The handling for the ini-files is as follows:

The file name can be specified as a command line option, e.g., ``--config=/home/tlsmate/myinifile.ini``.
If this options is not given, then ``tlsmate`` will use the file ``$HOME/.tlsmate.ini``.
Ini-files are plain text files with a simple format. Refer to the `Configuration file parser`_
documentation for more information.

The ini-file section for tlsmate is marked with ``[tlsmate]`` and the options are specified
as key/value pairs, whereby for keys the dashes as used on the CLI are replaced by underscores.
Here is an example of an ini-file for ``tlsmate``::

    [tlsmate]
    logging = debug

Each command line options has its specific type. For some types special treatment applies.

Boolean configuration options
-----------------------------

On the command line a boolean option is set to True by providing its name, e.g. ``--heartbeat``.
Setting it to False requires to use the ``--no-`` prefix, e.g. ``--no-heartbeat``.

For environment variables as well as for ini-files different rules apply: if
the value is ``0``, ``off``, ``no`` or ``false`` (case insensitive) it is
evaluated to false, and if it is set to any other value, it is evaluated to
true.

File lists
----------

On the command line file lists are specified by proving multiple values for an option,
e.g., ``--client-key file1 file2 file3``. For environment variables and for ini-files
those file lists are specified by separating the files by colons::

    export TLSMATE_CLIENT_KEY=file1,file2,file3

or in an ini-file::

    [tlsmate]
    client_key = file1, file2, file3

Relative file paths
-------------------

Relative file paths are supported on the CLI and in ini-files.

For the CLI those paths are relative to the current working directory.

For ini-files, those paths are relative to the directory the ini-file resides in.

.. _`Configuration file parser`: https://docs.python.org/3/library/configparser.html#supported-ini-file-structure
