Writing test cases
==================

This section provides an overview how to implement a TLS scenario within
a test case.

.. note::

    In all of the following code snippets we will assume that we are
    subclassing from the class :class:`tlsmate.plugin.Worker`. Thus, if
    ``self`` is used, it always refers to an object of that class.
    The code snippets shown here are typically implemented in the ``run`` method.
    Futhermore, we will assume that all required tlsmate modules have been
    imported, like:

    .. code-block:: python

        from tlsmate import tls
        from tlsmate import msg
        from tlsmate import ext

    A complete example of a plugin is given in :doc:`plugin`.

Using the client profile
------------------------

The client profile basically provides a comfortable way of specifying the
behavior of the client. Refer to :class:`tlsmate.client.ClientProfile` to
get a complete overview which attributes are supported.

When using :class:`tlsmate.plugin.Worker` as a base class, the
client profile can be accessed with ``self.client.profile``.

For example, if only the TLS versions TLS1.1 and TLS1.2 shall be supported in a
handshake, it can be done like this:

.. code-block:: python

    self.client.profile.versions = [tls.Version.TLS11, tls.Version.TLS12]

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)
        conn.wait(msg.ServerHello)

This will send a ClientHello with the version set to TLS1.2, but is will also
accept server responses where the version in the ServerHello is set to TLS1.1.

.. note::

    In the example we focus on the TLS version. Of course, the other
    parameters in the ClientHello will be set according to the current
    attributes of the client profile.

.. note::

    The client profile is used as well when the method
    :meth:`tlsmate.connection.TlsConnection.handshake` is used, see below.

``tlsmate`` comes with a set of predefined client profiles, which can be used
as a starting point when customizing the client profile, e.g.:

.. code-block:: python

    self.client.set_profile(tls.Profile.INTEROPERABILITY)

This will initialize the client profile to values, which are typically used for
interoperability use cases. Fine tuning the profile by adapting the attributes
is possible.

For the set of supported predefined client profiles refer to
:obj:`tlsmate.client.Client.set_profile`.

Using TLS messages
------------------

There are two ways of setting up TLS messages. Either, do it yourself, or let
``tlsmate`` do that work. An example for the latter case is shown above.

Here is an example where a message is setup "manually":

.. code-block:: python

    # create ClientHello object
    client_hello = msg.ClientHello()

    client_hello.version = tls.Version.TLS12
    client_hello.random = b'deadbeaf' * 8
    client_hello.session_id = b''
    client_hello.cipher_suites = [
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    ]
    client_hello.compression_methods = [tls.CompressionMethod.NULL]
    # No extensions right now, we will come to this later
    client_hello.extensions = []

    with self.client.create_connection() as conn:
        conn.send(client_hello)

.. note::

    For the documentation of the message properties refer to
    :doc:`py_msg`.

The latter case where ``tlsmate`` generates the ClientHello by itself
has been shown in the previous example. Instead of an message object
the message class is passed to the connection method ``send``.

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)

.. note::

    The application data message is special, as it must be always
    provided as an object to the ``send`` method. But at instantiation
    the data can be provied:

    .. code-block:: python

        with self.client.create_connection() as conn:
            conn.handshake()
            conn.send(msg.AppData(b'this is a dummy text'))

When a message is received, :meth:`tlsmate.connection.TlsConnection.wait`
will return a message object, and the message attributes can be accessed,
as shown in the following example:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)
        server_hello = conn.wait(msg.ServerHello)
        print(f"Negotiated cipher suite: {server_hello.cipher_suite}")

Using TLS extensions
--------------------

All attributes are passed to the extension object at instantiation, e.g.:

.. code-block:: python

    sni_ext = ext.ExtServerNameIndication(host_name="mytlsmatedomain.net")

For a list of supported extensions and their attributes refer to :doc:`py_ext`.

At TLS message level the extensions are stored in a list:

.. code-block:: python

    client_hello = msg.ClientHello()
    client_hello.extensions.append(sni_ext)

TLS message objects which support TLS extensions provide a method to
simplify their access:

.. code-block:: python

    check_sni = client_hello.get_extension(tls.Extension.SERVER_NAME)
    if check_sni:
        assert check_sni.host_name == "mytlsmatedomain.net"


Connection methods
------------------

The class :class:`tlsmate.connection.TlsConnection` provides a context manager
which keeps track of the TLS connection. When entering the context manager,
everything is setup to start a TLS handshake: The domain name is resolved and a
TCP connection to the TLS server is opened. When leaving the context manager,
the TLS connection is appropriately closed by an Alert and the TCP connection
is closed.

The simplest way to use a TLS connection is like this:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()

The ``send`` method (:meth:`tlsmate.connection.TlsConnection.send`) may send
one ore more messages. The messages may be given as a class, in which case
``tlsmate`` automatically generates the message object based on the client
profile, or as message objects. Note, that each message will be sent in a
separate record layer record, but all records will be flushed to the TCP
socket in one go at the end of the ``send`` method.

The optional argument ``pre_serialization`` provides a comfortable way of
manipulating the message just before it is sent. A typical use case is
shown below, where the ClientHello is setup according to the client
profile, and through the pre_serialization hook an unknown extension
is added:

.. code-block:: python

    def add_unkwon_ext(msg):
        msg.extensions.append(
            ext.ExtUnknownExtension(id=0xdead, bytes=b"deadbeaf")
        )

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello, pre_serialization=add_unkwon_ext)

To wait for a message two similar methods are provided: ``wait`` and
``wait_msg_bytes``. The only difference is that the latter method will not only
return the received message object, but also the serialized byte stream of that
object.

E.g.:

.. code-block:: python

    sv_hello_done, sv_hello_done_bytes = conn.wait_msg_bytes(msg.ServerHelloDone)
    assert sv_hello_done_bytes == bytes.fromhex("0e 00 00 00")

All other arguments are the same for both methods. Refer to
:meth:`tlsmate.connection.TlsConnection.wait_msg_bytes`.

Let's have a look at some options:

Optional messages
^^^^^^^^^^^^^^^^^

During a TLS handshake some messages sent by the server might be optional.
For those messages the argument ``optional=True`` can be passed to ``wait``.
As an example let's implement a message flow for a typical handshake for
TLS1.2 or below:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)
        conn.wait(msg.ServerHello)
        conn.wait(msg.Certificate, optional=True)
        conn.wait(msg.ServerKeyExchange, optional=True)
        conn.wait(msg.ServerHelloDone)
        conn.send(msg.ClientKeyExchange)
        conn.send(msg.ChangeCipherSpec)
        conn.send(msg.Finished)
        conn.wait(msg.ChangeCipherSpec)
        conn.wait(msg.Finished)

The server will not send Certificate message for an anonymous TLS handshake.
Additionally, the server may omit the ServerKeyExchange message in case
RSA-based key transport is used. The test case above will treat all those
different server behaviors appropriately.

.. note::

    In case an optional message is not received, the ``wait`` method
    will return None.


Complete handshake
^^^^^^^^^^^^^^^^^^

For convenience, the method ``handshake`` is provided, which implements a
complete TLS handshake. Refer to
:meth:`tlsmate.connection.TlsConnection.handshake`. Its usage has been
shown above already, but for completeness here it is once again:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()

Unexpected message received
^^^^^^^^^^^^^^^^^^^^^^^^^^^

In case a message is received which was not expected, ``wait`` will raise
the exception :class:`tlsmate.exception.FatalAlert`:

.. code-block:: python

    from tlsmate.exception import FatalAlert

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)
        try:
            conn.wait(msg.Finished)
        except FatalAlert as alert:
            print(f"Ops: {alert.message}")

This should print something like this::

    Ops: Unexpected message received: SERVER_HELLO, expected: FINISHED

Receiving any message
^^^^^^^^^^^^^^^^^^^^^

In some cases the server has the option to send different messages. E.g., with
TLS1.3 on reception of a ClientHello, the server may respond either with a
ServerHello or with a HelloRetryRequest. To support such a use case, the
message :class:`tlsmate.msg.Any` is provided. Used in the ``wait`` method,
it matches any message received. See the following example:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.send(msg.ClientHello)
        any_msg = conn.wait(msg.Any)
        if any_msg.msg_type is tls.HandshakeType.SERVER_HELLO:
            print("ServerHello received")
        else:
            print("Another message received")

Timeouts
^^^^^^^^

The ``wait`` method by default waits 5000 ms for the message. This timeout
can be changed by the ``timeout`` argument.

In case a timout on a message occurs, by default the exception
:class:`tlsmate.exception.TlsMsgTimeoutError` is raised.

Example:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        no_msg = conn.wait(msg.Finished)
        print(f"Message: {no_msg}")

In the example above nothing will be printed, as the timeout
exception is raised and the context manager will be left prematurely.

However, the argument ``fail_on_timeout`` can be set to False, in which
case the ``wait`` method will return None, but the scenario continues:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        no_msg = conn.wait(msg.Finished, fail_on_timout=False)
        print(f"Message: {no_msg}")

This time, the following will be printed::

    Message: None

Sometimes it is desired to check that no message is received for a given
duration, e.g. to verify that the server does not send any sessions tickets
after the handshake is finished.

This can be realized by using the method
:meth:`tlsmate.connection.TlsConnection.timeout`:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        conn.timeout(2000)

This example will wait for 2 seconds after the handshake is finished. Any
message received during this period will raise an
:class:`tlsmate.exception.FatalAlert` exception.


Background handling of messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For some TLS messages it is unpredictable when or how often those messages are
sent by the server. For example, the server may send multiple NewSessionTicket
messages afer the handshake (if at all). Or, the server may send a Heartbeat
request at any time.

Those messages typically should not affect a test case, and ``tlsmate``
therefore offers a background handling of those messages.

Refer to :attr:`tlsmate.connection.TlsConnection.auto_handler`.

Let's assume a server sends two NewSessionTicket messages immediately after a
handshake. From scenario perspective there are the following alternatives:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        # exactly two NewSessionTicket messages must be received
        conn.wait(msg.NewSessionTicket)
        conn.wait(msg.NewSessionTicket)

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        # both session tickets are received and handled in the background
        conn.timeout(5000)


.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()
        # first session ticket received here
        conn.wait(msg.NewSessionTicket)
        # second session ticket handled in the background
        conn.timeout(5000)

.. note::

    "Handled in the background" means for NewSessionTicket, that the tickets
    are restored for later use, and means for Heartbeat requested that 
    automatically a Heartbeat response is sent.

Retrieving connection properties
--------------------------------

During a handshake the TlsConnection object collects a series of information,
which is available even after the context manager has been left, e.g., whether
an alert was received during the handshake, if the handshake completed successfully,
if it was an abbreviated handshake, and so on.

Each message sent or received during a handshake is stored as well. Here is an example
to retrieve the negotiated cipher suite:

.. code-block:: python

    with self.client.create_connection() as conn:
        conn.handshake()

    if conn.msg.server_hello:
        print(f"negotiated cipher suite: {conn.msg.server_hello.cipher_suite}")

Refer to :class:`tlsmate.connection.TlsConnection` for detailed information.

.. note::

    It is possible to execute multiple handshakes within the same connection.
    In this case the information collected will always refer to the lastest
    handshake only.

Utilities
---------

This section provides some useful utilities which come with ``tlsmate``.

Filtering cipher suites
^^^^^^^^^^^^^^^^^^^^^^^

Filtering cipher suites is extremely useful when testing specific features.

Let's start with an example how to get the set of all CHACHA_POLY1305 cipher
suites defined officially by IANA:

.. code-block:: python

    >>> from tlsmate import tls, utils
    >>> all_cs = tls.CipherSuite.all()
    >>> len(all_cs)
    339
    >>> chacha_cs = utils.filter_cipher_suites(all_cs,cipher_prim=[tls.CipherPrimitive.CHACHA])
    >>> len(chacha_cs)
    8
    >>> for cs in chacha_cs: print(cs)
    ...
    TLS_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256

Another example: Filter all cipher suites using either ECDHE_ECDSA or
ECDHE_RSA, and for which ``tlsmate`` supports a full handshake:

.. code-block:: python

    >>> from tlsmate import tls, utils
    >>> res_cs = utils.filter_cipher_suites(
    ...     tls.CipherSuite.all(),
    ...     key_algo=[
    ...         tls.KeyExchangeAlgorithm.ECDHE_ECDSA,
    ...         tls.KeyExchangeAlgorithm.ECDHE_RSA],
    ...     full_hs=True)
    >>> for cs in res_cs: print(cs)
    ...
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_RC4_128_SHA
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

Filtering can be extremely helpful if for a scanner plugin the list of
supported cipher suites is retrieved from the server profile. See below.

Packing and unpacking packet data units
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The module ``tlsmate.pdu`` provides functions to pack and unpack protocol
elements. Refer to :doc:`py_pdu`.

.. code-block:: python

    >>> from tlsmate import pdu
    >>> text = b'Hello World!'
    >>> binary = pdu.pack_uint16(len(text)) + text
    >>> binary
    b'\x00\x0cHello World!'
    >>> pdu.dump(binary)
    '00 0c 48 65 6c 6c 6f 20 57 6f 72 6c 64 21 (14)'
    >>> length, offset = pdu.unpack_uint16(binary, 0)
    >>> text2, offset = pdu.unpack_bytes(binary, offset, length)
    >>> assert text2 == text


Using information from the server profile
-----------------------------------------

The server profile provides information which TLS settings and parameters are
supported by the server. Using this information simplifies the handling in test
cases. For example, if a test case checks for the Heartbleed vulnerability, the
server profile provides the information if the Heartbeat protocol is supported
at all or not.

The server profile was originally intended for scans only, but nothing prevents
an ordinary plugin to deserialize a stored server profile and use it for its
own purpose.

For classes derived from :class:`tlsmate.plugin.Worker` access to the server
profile is provided by ``self.server_profile``.

Several methods are defined to retrieve basic information from the profile. Of
course, this information is only available after the most essential information
has been collected by the scan (TLS versions, cipher suites, supported groups
and signature algorithms).

:meth:`tlsmate.server_profile.ServerProfile.get_versions` will return the list
of TLS versions supported by the server.

:meth:`tlsmate.server_profile.ServerProfile.get_version_profile` will get the
part of the profile that is related to the given TLS version.

:meth:`tlsmate.server_profile.ServerProfile.get_cipher_suites`,
:meth:`tlsmate.server_profile.ServerProfile.get_supported_groups` and
:meth:`tlsmate.server_profile.ServerProfile.get_signature_algorithms` will return
the list of supported cipher suites, supported groups or supported signature
algorithms for the given TLS protocol version.

The method :meth:`tlsmate.server_profile.ServerProfile.get_profile_values`
collects the list of supported cipher suites, supported groups and
supported signature algorithms for the given list of TLS protocol versions,
and provides this information as a named tuple
:class:`tlsmate.structs.ProfileValues`. This named tuple can be used to
initialize the client profile.

For example, the following code sets up the client profile based on the server
profile for testing for session_id support:

.. code-block:: python

    prof_values = self.server_profile.get_profile_values([
        tls.Version.TLS10,
        tls.Version.TLS11,
        tls.Version.TLS12,
    ])
    self.client.init_profile(profile_values=prof_values)
    self.client.profile.support_session_id = True
    with self.client.create_connection() as conn:
        # full handshake
        conn.handshake()

    self.client.profile.cipher_suites = [conn.msg.server_hello.cipher_suite]
    with self.client.create_connection() as conn2:
        # abbreviated handshake
        conn2.handshake()

Information retrieved from a test case may be stored in the server profile.

.. code-block:: python

    session_id_supported = tls.ScanState.TRUE
    self.server_profile.features.session_id = session_id_supported

The structure of the server profile is defined by so called "schema" classes.
These schema classes basically define the attributes and their types (which
can be basic types like integers or strings, lists or dicts) and thus define
the JSON or Yaml structure of a serialized server profile.

Refer to :class:`tlsmate.server_profile.ServerProfileSchema`.


Setting up unkown protocol elements
-----------------------------------

Setting up unknown values is supported for some protocol elements.

For example, unknown extensions can be setup as follows:

.. code-block:: python

    unknown_ext = ext.ExtUnknownExtension(id=0xdead, bytes=b"deadbeaf")

To setup an unknown TLS version the integer value can be given instead
of the enum:

.. code-block:: python

    self.client.profile.versions = [0x0305, tls.Version.TLS13]

The above code will setup the TLS versions 1.4 and 1.3.

Unknown values are supported for the following protocol elements:

* TLS protocol versions
* cipher suites
* supported groups
* signature algorithms
* psk modes (TLS1.3 only)
* extensions
