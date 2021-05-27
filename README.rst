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

State of the project
--------------------

The project is still in an alpha phase. Consequently the interfaces (CLI,
python APIs) provided might change significantly.

A word of warning
-----------------

This package is intended for test purposes only. Never ever use it to
transmit sensitive data! Here are some reasons:

* secret keying material isn't appropriately protected, e.g., it is not deleted
  when not used anymore. Such sensitive data are even logged for debugging purpose.
* quite a lot of checks are missing which are essential for productive use cases.
* `random values` are not always random
* side channels? Probably there are some.
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
* certificate revocation check by CRL
* scan result is provided as JSON/Yaml format to simplify tool-based post-processing
* plugin concept for either proprietary test cases or for extending the scanner plugin
* writing keying material to a key logging file to allow wireshark to decode encrypted packets
* configuration of ``tlsmate`` through an ini-file or through environment variables
* slowing down a scan to circumvent rate limitings
* several logging levels

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

* proxy support
* OCSP support
* support for unknown protocol-elements (versions, cipher suites, extensions, etc) [GREASE]
* assessment of the scan result (what is good, what is bad) according to customizable profiles
* simulating a TLS server (thus allowing to test TLS clients)
* scan for more vulnerabilities

.. _`TLS features`: https://guballa.gitlab.io/tlsmate/tlsfeatures.html

.. inclusion-marker-end-overview

.. inclusion-marker-start-installation

Installation
============

This package requires Python3.6 or higher. The recommended way installing
``tlsmate`` is using pip:

.. code-block:: console

    $ pip install tlsmate

.. inclusion-marker-end-installation

.. inclusion-marker-start-usage

Basic usage
===========

For a full documentation of the ``tlsmate`` command refer to the `documentation
here <https://guballa.gitlab.io/tlsmate/cli.html>`_. There you will find also a
detailed description how to use the package directly from other python
applications.

In the following only some basic examples for using the CLI are
given. Use the ``tlsmate --help`` command to get all supported command line
options. Note, that in the examples the URL ``mytlsmatedomain.net`` is used, a
domain name which is currently not registered.

.. code-block:: console

   $ tlsmate --scan --progress mytlsmatedomain.net

This command will perform a TLS scan against the domain ``mytlsmatedomain.net``, and the
result will be displayed in Yaml format.

Using the tlsmate library from other python applications is described in the
`Python API documentation`_.

.. _`CLI documentation`: https://guballa.gitlab.io/tlsmate/cli.html

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
