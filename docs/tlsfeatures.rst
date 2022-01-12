Supported TLS protocol features
===============================

The term "protocol features" refers to messages, parameters, extensions, features and
cryptographic primitives which are essential for TLS. They are not limited to the TLS
protocol only but cover e.g. X509 certificates as well.

``tlsmate`` is using the library `cryptography`_ and provides almost all protocol features
that are supported by it.

Some protocol features can be negotiated with the server (e.g., sent in the ClientHello,
received in the ServerHello), but they are actually not fully supported, i.e., it is not
possible to fully establish a protected connection and thus no application data can be
exchanged. For instance, ``tlsmate`` supports offering and
negotiating the cipher suite ``TLS_RSA_WITH_ARIA_128_CBC_SHA256``, but actually the ARIA cipher
is not supported, and as a result the handshake will fail (``tlsmate`` cannot encrypt/decrypt
the Finished message).

Nevertheless, such rudimentary support is sufficient to check if a TLS
server is supporting a protocol feature. Those cases will be described here as well.

TLS protocol versions
---------------------

* SSLv2 (incomplete handshake)
  Only sending and receiving ClientHello/ServerHello is supported.
* SSLv3
* TLS1.0
* TLS1.1
* TLS1.2
* TLS1.3

Messages
--------

For SSLv2 only ClientHello and ServerHello are supported. A full handshake using
SSLv2 is not supported.

For the other protocol versions the following messages are supported:

* HelloRequest
* HelloRetryRequest
* ClientHello
* ServerHello
* NewSessionTicket
* EndOfEarlyData
* EncryptedExtensions
* Certificate
* ServerKeyExchange
* CertificateRequest
* ServerHelloDone
* CertificateVerify
* CertificateStatus
* ClientKeyExchange
* Finished
* ChangeCipherSpec
* Alert
* ApplicationData
* Heartbeat

Cipher suites
-------------

For SSLv2 the following cipher kinds are supported (i.e, they can be sent and received
in a ClientHello/ServerHello message), but a full handshake cannot be completed:

* SSL_CK_RC4_128_WITH_MD5
* SSL_CK_RC4_128_EXPORT40_WITH_MD5
* SSL_CK_RC2_128_CBC_WITH_MD5
* SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
* SSL_CK_IDEA_128_CBC_WITH_MD5
* SSL_CK_DES_64_CBC_WITH_MD5
* SSL_CK_DES_192_EDE3_CBC_WITH_MD5

For TLS1.3 the following cipher suites are supported:

* TLS_AES_128_GCM_SHA256
* TLS_AES_256_GCM_SHA384
* TLS_CHACHA20_POLY1305_SHA256
* TLS_AES_128_CCM_SHA256
* TLS_AES_128_CCM_8_SHA256

For all other protocol versions the cipher suites `registered at IANA`_ are supported,
but not all of them can be used for a successful handshake completion.

.. note:: The signalling cipher suite values
   ``TLS_EMPTY_RENEGOTIATION_INFO_SCSV`` and ``TLS_FALLBACK_SCSV`` are supported as
   well.

A cipher suite can be used for a successful handshake completion,
if the key exchange method, the symmetric cipher and the HMAC are supported as
described below.

Key Exchange
^^^^^^^^^^^^

All key exchange mechanisms can be negotiated, but only the following ones can be
used for a successful handshake completion:

* DHE_DSS
* DHE_RSA
* DH_ANON
* RSA
* DH_DSS
* DH_RSA
* ECDH_ECDSA
* ECDHE_ECDSA
* ECDH_RSA
* ECDHE_RSA

Symmetric ciphers
^^^^^^^^^^^^^^^^^

All symmetric ciphers can be negotiated, but only the following ones can be
used for a successful handshake completion:

* AES_128_CBC
* AES_256_CBC
* AES_128_GCM
* AES_256_GCM
* AES_128_CCM
* AES_128_CCM_8
* AES_256_CCM
* AES_256_CCM_8
* CHACHA20_POLY1305
* 3DES_EDE_CBC
* CAMELLIA_128_CBC
* CAMELLIA_256_CBC
* IDEA_CBC
* RC4_128
* SEED_CBC

HMAC
^^^^

All cipher suite HMACs `registered at IANA`_ are supported:

* SHA1
* SHA256
* SHA384
* SHA512
* MD5

.. :ref: Extensions

Extensions
----------

The following TLS extensions are supported:

* :ref:`ext_server_name`
* :ref:`ext_supported_groups`
* :ref:`ext_ec_point_formats`
* :ref:`ext_signature_algorithms`
* :ref:`ext_encrypt_then_mac`
* :ref:`ext_extended_master_secret`
* :ref:`ext_session_ticket`
* :ref:`ext_pre_shared_key`
* :ref:`ext_early_data`
* :ref:`ext_supported_versions`
* :ref:`ext_certificate_authorities`
* :ref:`ext_post_handshake_auth`
* :ref:`ext_key_share`
* :ref:`ext_renegotiation_info`
* :ref:`ext_heartbeat`
* :ref:`ext_status_request`
* :ref:`ext_status_request_v2`
* :ref:`ext_cookie`

.. _ext_server_name:

server_name
^^^^^^^^^^^

Any server name can be used.

.. _ext_supported_groups:

supported_groups
^^^^^^^^^^^^^^^^

All supported groups can be negotiated, but only the following ones can be
used for a successful handshake completion:

* SECP192R1
* SECP224R1
* SECP256K1
* SECP256R1
* SECP384R1
* SECP521R1
* SECT163K1
* SECT163R2
* SECT233K1
* SECT233R1
* SECT283K1
* SECT283R1
* SECT409K1
* SECT409R1
* SECT571K1
* SECT571R1
* X25519
* X448
* BRAINPOOLP256R1
* BRAINPOOLP384R1
* BRAINPOOLP512R1
* FFDHE2048
* FFDHE3072
* FFDHE4096
* FFDHE6144
* FFDHE8192

.. _ext_ec_point_formats:

ec_point_formats
^^^^^^^^^^^^^^^^

All EC point formats can be negotiated, but only the following one can be
used for a successful handshake completion:

* UNCOMPRESSED

.. _ext_signature_algorithms:

signature_algorithms
^^^^^^^^^^^^^^^^^^^^

All signature algorithms can be negotiated, but only the following one can be
used for signing or signature validation:

* DSA_MD5
* DSA_SHA1
* DSA_SHA224
* DSA_SHA256
* DSA_SHA384
* DSA_SHA512
* ECDSA_SECP224R1_SHA224
* ECDSA_SECP256R1_SHA256
* ECDSA_SECP384R1_SHA384
* ECDSA_SECP521R1_SHA512
* ECDSA_SHA1
* ED25519
* ED448
* RSA_PKCS1_MD5
* RSA_PKCS1_SHA1
* RSA_PKCS1_SHA224
* RSA_PKCS1_SHA256
* RSA_PKCS1_SHA384
* RSA_PKCS1_SHA512
* RSA_PSS_RSAE_SHA256
* RSA_PSS_RSAE_SHA384
* RSA_PSS_RSAE_SHA512

.. _ext_encrypt_then_mac:

encrypt_then_mac
^^^^^^^^^^^^^^^^

A full handshake is supported with this extension.

.. _ext_extended_master_secret:

extended_master_secret
^^^^^^^^^^^^^^^^^^^^^^

A full handshake is supported with this extension.

.. _ext_session_ticket:

session_ticket
^^^^^^^^^^^^^^

Sessions resumption using a previously received session ticket is supported.

.. _ext_pre_shared_key:

pre_shared_key
^^^^^^^^^^^^^^

All pre shared key exchange modes are supported:

* PSK_KE
* PSK_DHE_KE

.. _ext_early_data:

early_data
^^^^^^^^^^

Sending early data is supported.

.. _ext_supported_versions:

supported_versions
^^^^^^^^^^^^^^^^^^

All supported versions are supported.

.. _ext_certificate_authorities:

certificate_authorities
^^^^^^^^^^^^^^^^^^^^^^^

This extension is currently supported rudimentary only.

.. _ext_post_handshake_auth:

post_handshake_auth
^^^^^^^^^^^^^^^^^^^

Post-handshake client authentication is supported (TLS1.3)

.. _ext_key_share:

key_share
^^^^^^^^^

All TLS1.3 named groups are supported:

* ECDSA_SECP256R1_SHA256
* ECDSA_SECP384R1_SHA384
* ECDSA_SECP521R1_SHA512
* ED25519
* ED448
* FFDHE2048
* FFDHE3072
* FFDHE4096
* FFDHE6144
* FFDHE8192

.. _ext_renegotiation_info:

renegotiation_info
^^^^^^^^^^^^^^^^^^

Renegotiation (secure and insecure and server-initiated) is supported.

.. _ext_heartbeat:

heartbeat
^^^^^^^^^

Sending and receiving Heartbeat messages (requests and responses) is supported.

.. _ext_status_request:

status_request
^^^^^^^^^^^^^^

Requesting OCSP stapling is supported. The stapled response from the server is
check for validity. This extension is supported for TLS version 1.0 - 1.3.

.. note::
   For versions below TLS1.3 the response is sent in a CertificateStatus message,
   while for TLS1.3 the response is provided in an TLS extensions associated
   with the certificate in the Certificate message.

.. _ext_status_request_v2:

status_request_v2
^^^^^^^^^^^^^^^^^

Requesting single responses (status_type = ocsp) and requesting multi stapling
(status_type = ocsp_multi) is supported (TLS versions 1.0 - 1.2)

.. _ext_cookie:

cookie
^^^^^^

If received with a HelloRetryRequest message, it will be mirrowed back in the
ClientHello.

Certificates and certificate chains
-----------------------------------

``tlsmate`` performs basic checks to validate certificate chains received from the server.
The results are cached, i.e., if the same certificate chain is received multiple times,
the validation will only be done once. The following checks are currently implemented:

* for the server certificate the domain name must match the subject common name or
  one of the SANs (Subject Alternate Names). Wildcard domain names are supported.
* the chain is checked for gratuitous certificates
* a trust path is determined, taking alternate trust paths into account (but the
  certificates must be in the chain or in the trust store)
* the root certificate of the chain must be present in the trust store. Note, that root
  certificates are not required to be sent by the server.
* for each certificate of the trust path the following checks are done:

  * the validity period is checked.
  * its signature signed by the issuer is validated
  * the associated CRLs (if defined) are downloaded to check the revocation status.
    This check can be disabled by a command line argument. Note, that CRLs are
    cached.
  * if defined, the OCSP server is queried, and the revocation status is determined
    from the response. This check can be disabled by a command line argument.

Received certificate chains from the server are stored in the server profile, but not
all certificate extensions are supported (yet).

Other features
--------------

This section describes features or procedures supported by ``tlsmate``.

* resumption via session_id (TLS1.0 - TLS1.2)
* resumption via session tickets (TLS1.0 - TLS1.2)
* resumption via PSK (TLS1.3)
* 0-RTT or early data (TLS1.3)
* secure and insecure renegotiation, client or server initiated (SSLv3 - TLS1.2)
* client authentication (during handshake or post-handshake, SSLv3 - TLS1.3)
* compression (only NULL is supported for a complete handshake, but any value can be
  negotiated)
* encrypt-then-mac (TLS1.0 - TLS1.2), refer to `Extensions`_.
* extended-master-secret (TLS1.0 - TLS1.2), refer to `Extensions`_.

.. _`cryptography`: https://cryptography.io/en/latest/

.. _`registered at IANA`: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
