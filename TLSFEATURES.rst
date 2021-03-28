Supported protocol features
###########################

The term "protocol features" refers to messages, parameters, extensions, features and
cryptographic primitives which are essential for TLS. They are not limited to the TLS
protocol only but cover e.g. X509 certificates as well.

`tlsmate` is using the library `cryptography`_ and provides almost all protocol features
that are supported by it.

Some protocol features can be negotiated with the server (e.g., sent in the ClientHello,
received in the ServerHello), but they are actually not fully supported, i.e., it is not
possible to fully establish a protected connection and thus no application data can be
exchanged. For instance, `tlsmate` supports offering and
negotiating the cipher suite `TLS_RSA_WITH_ARIA_128_CBC_SHA256`, but actually the ARIA cipher
is not supported, and as a result the handshake will fail (`tlsmate` cannot encrypt/decrypt
the Finished message).

Nevertheless, such rudimentary support is sufficient to check if a TLS
server is supporting a protocol feature. Those cases will be described here as well.

TLS protocol versions
=====================

* SSLv2 (incomplete handshake)
  Only sending and receiving ClientHello/ServerHello is supported.
* SSLv3
* TLS1.0
* TLS1.1
* TLS1.2
* TLS1.3

Messages
========

For SSLv2 only ClientHello and ServerHello are supported. A full handshake using
SSLv2 is not supported.

For the other protocol versions the following messages are supported:

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
* ClientKeyExchange
* Finished
* ChangeCipherSpec
* Alert
* ApplicationData

Cipher suites
=============

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
   `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` and `TLS_FALLBACK_SCSV` are supported as
   well.

A cipher suite can be used for a successful handshake completion,
if the key exchange method, the symmetric cipher and the HMAC are supported as
described below.

Key Exchange
------------

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
-----------------

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
----

All cipher suite HMACs `registered at IANA`_ are supported:

* SHA1
* SHA256
* SHA384
* SHA512
* MD5

.. :ref: Extensions

Extensions
==========

The following TLS extensions are supported:

* SERVER_NAME
* SUPPORTED_GROUPS

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
  * BRAINPOOLP256R1
  * BRAINPOOLP384R1
  * BRAINPOOLP512R1
  * FFDHE2048
  * FFDHE3072
  * FFDHE4096
  * FFDHE6144
  * FFDHE8192

* EC_POINT_FORMATS

  All EC point formats can be negotiated, but only the following one can be
  used for a successful handshake completion:

  * UNCOMPRESSED

* SIGNATURE_ALGORITHMS

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

* ENCRYPT_THEN_MAC
* EXTENDED_MASTER_SECRET
* SESSION_TICKET
* PRE_SHARED_KEY

  All pre shared key exchange modes are supported:

  * PSK_KE
  * PSK_DHE_KE

* EARLY_DATA
* SUPPORTED_VERSIONS

  All supported versions are supported.

* CERTIFICATE_AUTHORITIES
* POST_HANDSHAKE_AUTH
* KEY_SHARE

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

* RENEGOTIATION_INFO

Certificates and certificate chains
===================================

`tlsmate` performs basics checks to validate certificate chains received from the server.
The results are cached, i.e., if the same certificate chain is received multiple times,
the validation will only be done once. The following checks are currently implemented:

* for the server certificate the domain name must match the subject common name or
  one of the SANs (Subject Alternate Names). Wildcard domain names are supported.
* for each certificate of the chain the validity period is checked.
* for each certificate the issuer's certificate must be in the chain or in the trust store.
* for each certificate the issuer's signature is validated
* for each certificate its associated CRL (if defined) is downloaded to check the revocation
  status. CRLs are cached. This check can be disabled, as it adds additional delay to a
  TLS handshake.
* the root certificate of the chain must be present in the trust store. Note, that root
  certificates are not required to be sent by the server.

.. note:: Revocation check using OCSP is currently not implemented but will be
   added in the future.

Received certificate chains from the server are stored in the server profile, but not
all certificate extensions are supported (yet).

Other features
==============

This section describes features or procedures supported by `tlsmate`.

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
