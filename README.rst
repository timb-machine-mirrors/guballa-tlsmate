|Build Status| |Coverage| |License| |Black|

tlsmate
#######

.. inclusion-marker-start-overview

Overview
========

This project provides a python framework for simulating TLS endpoints. It
provides a comfortable way of creating arbitrary TLS handshake scenarios and
executes the scenarios against TLS servers or clients (well, at the current
state of the project only client simulations are supported).

A plugin is provided which scans a TLS server for its configurations (i.e.,
support of TLS protocol versions, cipher suites, and much more) as well as for
some commonly known TLS vulnerabilities.

A word of warning
-----------------

This package is intended for test purposes only. Never ever use it to
transmit sensitive data! Here are some reasons:

* secret keying material isn't appropriately protected, e.g., it is not deleted
  when not used anymore. Such sensitive data are even logged for debugging purpose.
* quite a lot of checks are missing which are essential for productive use cases.
* `random values` are not always random
* Side channels? Definitely. Constant time implementation? No.
* Extensive tests and proven in practice? No!
* etc.

Features
--------

``tlsmate`` comes with its own TLS protocol stack implementation. For a list of
supported TLS protocol elements refer to `TLS features`_ .

The following basic features are supported:

* TLS versions: SSLv2 (rudimentary only), SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3
* arbitrary L4-ports are supported
* customized trust store for root certificates
* client authentication
* certificate revocation check by CRL and via OCSP
* scan result is provided as JSON/Yaml format to simplify tool-based post-processing
* plugin concept for either proprietary test cases or for extending the scanner plugin
* writing keying material to a key logging file to allow wireshark to decode encrypted packets
* configuration of ``tlsmate`` through an ini-file or through environment variables
* slowing down a scan to circumvent rate limitings
* several logging levels
* HTTP-proxy support

For creating customized handshake scenarios the following features are provided:

* TLS messages can be sent/received in any arbitrary order
* all TLS message parameters can be set to any arbitrary value
* sending and receiving application data
* predefined client profiles (legacy, interoperability, modern, TLS1.3-only)
* basic settings (version, ciphersuites, etc.) can be taken from the server profile to
  minimize interoperability issues with the server
* different levels for defining a handshake: from a one liner for the complete handshake
  to defining the deepest bit in a message
* various conditions when waiting for a message (timeout, optional message)
* background handling of some messages (e.g., NewSessionTicket)
* simple python API to use ``tlsmate`` from other python applications

The following features are currently not yet supported but will likely be added
in the future:

* simulating a TLS server (thus allowing to test TLS clients)

.. _`TLS features`: https://guballa.gitlab.io/tlsmate/tlsfeatures.html

.. inclusion-marker-end-overview

.. inclusion-marker-start-installation

Installation
============

This package requires Python3.6 or higher. The recommended way installing
``tlsmate`` is using pip:

.. code-block:: console

    $ pip install tlsmate

In case this does not work, check if the problem is caused by the cryptographic
library `cryptography <https://cryptography.io/en/latest/>`_, and refer to
`Installation of cryptography <https://cryptography.io/en/latest/installation/>`_.


Minimal configuration
=====================

By default ``tlsmate`` comes with an empty trust store, and thus all
certificate chain validations will fail.

There are two different ways recommended to configure the trust store.

Using the system's set of root certificates
-------------------------------------------

In case the root CA certificates are installed on the system, their location
depend on the OS. If ``openssl`` is installed on the system, use the following
command:

.. code-block:: console

    $ openssl version -d

This will print the openssl directory, e.g. ``/usr/lib/ssl``. The certificates
are located in the subdirectory ``certs``, and there typically a file is
provided which contains all certificates concatenated. On Ubuntu, this file
is named ``ca-certificates.crt``, on CentOS the name is ``ca-bundle.crt``.

This file needs to be configured in the tlsmate-ini file, `see below`_.

Download the Mozilla root CA certificates
-----------------------------------------

As an alternative the root CA certificates used by Mozilla can be used.
Download the file and calculate its SHA256 checksum:

.. code-block:: console

    $ curl -s -o cacert.pem https://curl.se/ca/cacert.pem && sha256sum cacert.pem

Compare the SHA256 hash value with the value provided at `<https://curl.se/ca/cacert.pem.sha256>`_.

If the value matches, configure the downloaded file in the tlsmate-ini file, see below.

.. _see below:

Configuring the trust store in the .tlsmate.ini file
----------------------------------------------------

Let's assume the name of the trust store file is ``/usr/lib/ssl/certs/ca-certificates.crt``.
Now create a new ini file in your home directory:

.. code-block:: console

    $ echo -e "[tlsmate]\nca_certs = /usr/lib/ssl/certs/ca-certificates.crt" > ~/.tlsmate.ini
    $ cat ~/.tlsmate.ini
    [tlsmate]
    ca_certs = /usr/lib/ssl/certs/ca-certificates.crt

.. note::

    This command will overwrite an existing ini file. Adapt the command or
    use your favorite editor if you want to keep the existing file.

More information on the use of ini-files is provided `here <https://guballa.gitlab.io/tlsmate/cli_config.html>`_.

.. inclusion-marker-end-installation

.. inclusion-marker-start-usage

Basic usage
===========

For a full documentation of the ``tlsmate`` command refer to the `documentation
here <https://guballa.gitlab.io/tlsmate/cli.html>`_. There you will find a
detailed description how to use the package directly from other python
applications.

In the following only some basic examples for using the CLI are
given. Use the ``tlsmate --help`` command to get all supported subcommands.

.. note::

    In the example the domain name "mytlsmatedomain.net" is used, which is
    currently not registered. Replace it with the domain name you want to use.

.. code-block:: console

   $ tlsmate scan --progress mytlsmatedomain.net

This command will perform a TLS scan against the domain ``mytlsmatedomain.net``, and the
result will be displayed as colored console output. For an example refer to the
`output of the scan command`_.

Using the tlsmate library from other python applications is described in the
`Python API documentation`_.

.. _`CLI documentation`: https://guballa.gitlab.io/tlsmate/cli.html

.. _`output of the scan command`: https://guballa.gitlab.io/tlsmate/scanner_output.html

.. _`Python API documentation`: https://guballa.gitlab.io/tlsmate/modules.html

.. inclusion-marker-end-usage


.. |Build Status| image:: https://gitlab.com/guballa/tlsmate/badges/master/pipeline.svg
   :target: https://gitlab.com/guballa/tlsmate/-/commits/master

.. |Coverage| image:: https://gitlab.com/guballa/tlsmate/badges/master/coverage.svg
   :target: https://gitlab.com/guballa/tlsmate/-/commits/master

.. |License| image:: https://img.shields.io/badge/License-MIT-blue.svg
   :target: https://gitlab.com/guballa/tlsmate/-/blob/master/LICENSE

.. |Black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/python/black
