Using tlsmate from python applications
======================================

In this section an overview is provided how to use the ``tlsmate`` library in a
stand-alone python application. Later we will also have a look on how to
integrate the same scenario into ``tlsmate`` using the plugin interface.

Here only basic features of ``tlsmate`` are used without further explanation. For
a more comprehensive description of how write test cases refer to `class description`_.

As an appetizer let's create an application which performs a TLS handshake and
prints the cipher suite selected by the server.

.. note:: The example code uses the domain `mytlsmatedomain.net`, which is
   currently not registered. Replace it with your own domain.

.. code-block:: python

    from tlsmate.tlsmate import TlsMate
    from tlsmate import tls, msg

    tlsmate = TlsMate()

    # To execute a successful TLS handshake we must tell `tlsmate` where to find
    # the trust store(s) containing the root certificates. Those trust stores are
    # files which contain a set of certificates in PEM format. This example uses
    # the trust store from a typical Ubuntu system. For demonstation purposes we
    # set the trust store hard coded in the application. Later we will see how we
    # can define such a common setting via an ini-file or via an environment variable.
    tlsmate.trust_store.set_ca_files(["/etc/ssl/certs/ca-certificates.crt"])

    # Let's use a default client profile which has a high probability to successfully
    # interoperate with a typical web server. Additionally we will exclude TLS1.3
    # here explicitly to demonstrate how to implement a typical TLS1.0 - TLS1.2
    # handshake scenario.
    tlsmate.client.set_profile(tls.Profile.INTEROPERABILITY)
    tlsmate.client.profile.versions = [
        tls.Version.TLS10, tls.Version.TLS11, tls.Version.TLS12
    ]

    # Now open a TLS connection and execute a typical TLS handshake. Print the
    # cipher suite selected by the server.
    with tlsmate.client.create_connection("mytlsmatedomain.net") as conn:
        conn.send(msg.ClientHello)
        server_hello = conn.wait(msg.ServerHello)
        print(f"Cipher suite selected by the server: {server_hello.cipher_suite}")
        conn.wait(msg.Certificate, optional=True)
        conn.wait(msg.ServerKeyExchange, optional=True)
        conn.wait(msg.ServerHelloDone)
        conn.send(msg.ClientKeyExchange)
        conn.send(msg.ChangeCipherSpec)
        conn.send(msg.Finished)
        conn.wait(msg.ChangeCipherSpec)
        conn.wait(msg.Finished)
        print("Handshake finished")

In the example above the context manager will take care of properly closing the
TLS connection by sending a closure Alert, and then closing the TCP connection.

Let's look at another example. This time we are not really interested in the
handshake but we want to display the http response headers from a web server.
And this time we do not exclude TLS1.3 from the versions, and we create a test
case which runs equally well for every TLS protocol version.

We skip the initial setup and we immediately come the interesting stuff.

.. code-block:: python

    tlsmate.client.set_profile(tls.Profile.INTEROPERABILITY)
    with tlsmate.client.create_connection("mytlsmatedomain.net") as conn:
        conn.handshake()
        conn.send(msg.AppData(b"GET / HTTP/1.1\r\nHost: mytlsmatedomain.net\r\n\r\n"))
        response = conn.wait(msg.AppData)
        for line in response.data.decode().split("\n"):
            if line.isspace():
                break

            print(line)

The output should be something like:
::

    HTTP/1.1 200 OK
    Age: 513212
    Cache-Control: max-age=604800
    Content-Type: text/html; charset=UTF-8
    Date: Sun, 28 Mar 2021 16:13:13 GMT
    Etag: "3147526947+gzip+ident"
    Expires: Sun, 04 Apr 2021 16:13:13 GMT
    Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
    Server: ECS (dcb/7F5C)
    Vary: Accept-Encoding
    X-Cache: HIT
    Content-Length: 1256

.. _`class description`: class_description.html
