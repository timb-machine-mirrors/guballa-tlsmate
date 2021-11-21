How to use the tlsmate classes
==============================

In this section only the most relevant classes are described which are
typically used when writing plugins. For a full description of all classes
defined by ``tlsmate`` refer to `Python API reference documentation <modules.html>`_.

The TlsMate class
-----------------

This class provides an umbrella for the ``tlsmate`` application. It basically
provides access to other objects. When writing plugins, this class is not
required. But it can be used in case the ``tlsmate`` library is used
directly from other python applications, see
`Using tlsmate from python applications <plain_python.html>`_.

Refer to :class:`tlsmate.tlsmate.TlsMate`.

The Configuration class
-----------------------

This class manages configuration items. These configuration items are typically
provided as command line arguments, or they are defined in ini-files or via
environment variables. A configuration object can be used to initialize the
:obj:`tlsmate.tlsmate.TlsMate` instance.

Refer to :class:`tlsmate.config.Configuration`.

The Client class
----------------

This class is used to represent a TLS client. It is something analog to a
browser: It manages everything which needs to be handled outside of a TLS
connection, e.g., session tickets, trust stores, client certificates, etc. It
is also responsible for initiating TLS connections, and it has implemented a
client profile, which is described below.

Refer to :class:`tlsmate.client.Client`.

The ClientProfile class
-----------------------

This data class describes the TLS profile of the client, i.e., it defines which
TLS features, parameters, extensions, etc., are supported. This information is
basically used to generate a ClientHello and to check a received ServerHello
for consistency (e.g., whether the protocol version selected by the server
is defined as supported in the client profile as well).

When writing a TLS scenario, the client profile can be defined according to
the needs.

Refer to :class:`tlsmate.client.ClientProfile`.


The TlsConnection class
-----------------------

Objects of this class are typically instantiated by the client. They represent a
TLS connection (including the underlying TCP connection) using a python context
manager. The object and its properties are available even after the connection
has been closed.

Refer to :class:`tlsmate.connection.TlsConnection`.

The ServerProfile class
-----------------------

This class represents the TLS profile of the server, i.e., it describes the
messages, parameters, extensions, features, cryptographic primitives supported
by the server, as well as the vulnerability to certain attacks. Plugins can
read and write to the profile. For example, when a scan is started, the server
profile is initialized to an empty state. A worker is executed which scans the
server for the supported TLS protocol versions and the supported cipher suites.
The gathered information is stored in the server profile. Other succeeding
executed workers can read this information from the profile, which simplifies
their task, e.g., a worker scanning for the ROBOT vulnerability can check if
the server actually supports protocol versions and cipher suites which are
subject for this attack, and if so, the worker can use this information to
setup a ClientHello with the information taken from the profile.

Several methods are provided which give access to the most often used server
profile values.

Server profiles can be serialized in JSON or Yaml format. It is also possible
to deserialize them, which allows to postprocess them or to use them as an
information source for implementing additional TLS scenarios.

Refer to :class:`tlsmate.server_profile.ServerProfile`.
