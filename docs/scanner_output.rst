
Example for a Scan output
=========================

The following output is the result of a scan against Openssl 1.0.1e (an rather outdated
legacy version), which is affected by several vulnerabilities.

.. raw:: html

 <pre style="color:white; background:black; overflow-x: auto; font-size:0.75em">

 <font color=green>$</font> tlsmate scan --progress localhost --port=44330 --oracle-accuracy=low

 <font color=magenta><b>A TLS configuration scanner (and more)</b></font>

   tlsmate version  1.0.1.dev59+g85c3613.d20210825
   repository       https://gitlab.com/guballa/tlsmate
   Please file bug reports at https://gitlab.com/guballa/tlsmate/-/issues

 <font color=magenta><b>Basic scan information</b></font>

   command: /home/jens/.virtualenv/tlsmate/bin/tlsmate scan --progress localhost --port=44330 --oracle-accuracy=low
   tlsmate version       1.0.1.dev59+g85c3613.d20210825 (producing the scan)
   scan start timestamp  2021-10-04 21:14:09
   scan duration         10.267 seconds
   applied style         /home/jens/project/tlsmate/tlsmate/styles/default.yaml
   style description     very strict profile targeting a security level of 128 bits

 <font color=magenta><b>Scanned host</b></font>

   host            localhost
   port            44330
   SNI             localhost
   IPv4 addresses  127.0.0.1

 <font color=magenta><b>TLS protocol versions:</b></font>

   SSL20  <font color=green>not supported</font>
   SSL30  <font color=red>supported</font>
   TLS10  <font color=yellow><b>supported</b></font>
   TLS11  <font color=yellow><b>supported</b></font>
   TLS12  <font color=green>supported</font>
   TLS13  not supported

 <font color=magenta><b>Cipher suites</b></font>

   <b>SSL30, TLS10, TLS11</b>:
     <font color=red>server does not enforce cipher suite order</font>
     0x0003  <font color=red>TLS_RSA_EXPORT_WITH_RC4_40_MD5</font>
     0x0004  <font color=red>TLS_RSA_WITH_RC4_128_MD5</font>
     0x0005  <font color=red>TLS_RSA_WITH_RC4_128_SHA</font>
     0x0006  <font color=red>TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5</font>
     0x0007  <font color=red>TLS_RSA_WITH_IDEA_CBC_SHA</font>
     0x0008  <font color=red>TLS_RSA_EXPORT_WITH_DES40_CBC_SHA</font>
     0x0009  <font color=red>TLS_RSA_WITH_DES_CBC_SHA</font>
     0x000a  <font color=red>TLS_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0x0014  <font color=red>TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA</font>
     0x0015  <font color=red>TLS_DHE_RSA_WITH_DES_CBC_SHA</font>
     0x0016  <font color=red>TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0x002f  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0033  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0035  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x0039  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x0041  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0045  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0084  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0088  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0096  <font color=yellow><b>TLS_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009a  <font color=yellow><b>TLS_DHE_RSA_WITH_SEED_CBC_SHA</b></font>
     0xc011  <font color=red>TLS_ECDHE_RSA_WITH_RC4_128_SHA</font>
     0xc012  <font color=red>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc013  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0xc014  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</b></font>

   <b>TLS12</b>:
     <font color=red>server does not enforce cipher suite order</font>
     0x0003  <font color=red>TLS_RSA_EXPORT_WITH_RC4_40_MD5</font>
     0x0004  <font color=red>TLS_RSA_WITH_RC4_128_MD5</font>
     0x0005  <font color=red>TLS_RSA_WITH_RC4_128_SHA</font>
     0x0006  <font color=red>TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5</font>
     0x0007  <font color=red>TLS_RSA_WITH_IDEA_CBC_SHA</font>
     0x0008  <font color=red>TLS_RSA_EXPORT_WITH_DES40_CBC_SHA</font>
     0x0009  <font color=red>TLS_RSA_WITH_DES_CBC_SHA</font>
     0x000a  <font color=red>TLS_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0x0014  <font color=red>TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA</font>
     0x0015  <font color=red>TLS_DHE_RSA_WITH_DES_CBC_SHA</font>
     0x0016  <font color=red>TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0x002f  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0033  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0035  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x0039  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x003c  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0x003d  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA256</b></font>
     0x0041  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0045  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0067  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0x006b  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA256</b></font>
     0x0084  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0088  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0096  <font color=yellow><b>TLS_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009a  <font color=yellow><b>TLS_DHE_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009c  <font color=yellow><b>TLS_RSA_WITH_AES_128_GCM_SHA256</b></font>
     0x009d  <font color=yellow><b>TLS_RSA_WITH_AES_256_GCM_SHA384</b></font>
     0x009e  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_GCM_SHA256</b></font>
     0x009f  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_GCM_SHA384</b></font>
     0xc011  <font color=red>TLS_ECDHE_RSA_WITH_RC4_128_SHA</font>
     0xc012  <font color=red>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc013  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0xc014  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0xc027  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0xc028  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</b></font>
     0xc02f  <font color=green>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</font>
     0xc030  <font color=green>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</font>

 <font color=magenta><b>Supported groups</b></font>

   <b>SSL30</b>:
     extension "supported_groups" not supported
     supported groups:
       0x17  <font color=green>SECP256R1</font>

   <b>TLS10, TLS11, TLS12</b>:
     <font color=green>extension "supported_groups" supported</font>
     supported groups:
       0x17  <font color=green>SECP256R1</font>

 <font color=magenta><b>Signature algorithms</b></font>

   <b>TLS12</b>:
     signature algorithms:
       0x0201  <font color=yellow><b>RSA_PKCS1_SHA1</b></font>
       0x0401  <font color=green>RSA_PKCS1_SHA256</font>
       0x0501  <font color=green>RSA_PKCS1_SHA384</font>
       0x0601  <font color=green>RSA_PKCS1_SHA512</font>
       0x0101  <font color=red>RSA_PKCS1_MD5</font>
       0x0301  <font color=yellow><b>RSA_PKCS1_SHA224</b></font>

 <font color=magenta><b>DH groups (finite field</b></font>

   <b>SSL30, TLS10, TLS11, TLS12</b>:
     <font color=red>unknown group (512 bits)</font>

 <font color=magenta><b>Features</b></font>

   <b>Common features</b>
     OCSP stapling (status_request)           <font color=red>not supported</font>
     OCSP multi stapling (status_request_v2)  not supported
     Heartbeat                                <font color=red>supported</font>
     Downgrade attack prevention              <font color=red>no, TLS_FALLBACK_SCSV not supported</font>

   <b>Features for TLS1.2 and below</b>
     compression                     <font color=green>not supported</font>
     SCSV-renegotiation              <font color=green>supported</font>
     encrypt-then-mac                <font color=red>not supported</font>
     extended master secret          <font color=red>not supported</font>
     insecure renegotiation          <font color=green>not supported</font>
     secure renegotiation            supported
     resumption with session_id      supported
     resumption with session ticket  <font color=yellow><b>supported</b></font>, life time: 300 seconds

   <b>Server tolerance to unknown values (GREASE, RFC8701)</b>
     protocol versions            <font color=green>tolerant</font>
     cipher suites                <font color=green>tolerant</font>
     extensions                   <font color=green>tolerant</font>
     named groups                 <font color=green>tolerant</font>
     signature algorithms         <font color=green>tolerant</font>
     PSK exchange modes (TLS1.3)  not applicable

 <b>  Ephemeral key reuse</b>
     DHE key reuse (TLS1.2 or below)    <font color=red>keys reused</font>
     ECDHE key reuse (TLS1.2 or below)  <font color=red>keys reused</font>
     DHE key reuse (TLS1.3)             not applicable
     ECDHE key reuse (TLS1.3)           not applicable

 <font color=magenta><b>Certificate chains</b></font>

   <b>Certificate chain #1:</b> <font color=green>successfully validated</font>
      <font color=yellow><b>root certificate was provided by the server</b></font>
   Certificate #1: Version.v3
     Serial number           244928270297404471 (integer)
                             03:66:28:f6:d2:87:14:37 (hex)
     Subject                 CN=localhost,O=The TlsMate Company (Server side) RSA,C=DE
     SubjectAltName (SAN)    test.localhost &#42;.wildcard.localhost
     URI matches             <font color=green>yes, URI matches subject/SAN</font>
     Extended validation     no
     Issuer                  CN=localhost Intermediate CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>RSA_PKCS1_SHA256</font>
     Public key              RSA, <font color=yellow><b>2048 bits</b></font>
     Extended key usage      serverAuth
     Validity period         <font color=green>2021-08-22 14:17:44</font> - <font color=green>2031-08-20 14:17:44</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/ca-rsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=green>certificate not revoked</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        99:f1:71:b7:75:17:e4:53:c5:f3:5f:03:a1:48:e5:69:f8:82:52:b1
     Fingerprint SHA256      75:b8:0d:2b:66:a0:ed:23:74:14:40:7f:06:41:55:e6:78:56:7c:c1:8f:fa:a4:91:d6:36:f5:7d:ff:75:18:46

   Certificate #2: Version.v3
     Serial number           894302408641124678 (integer)
                             0c:69:33:4d:6c:d4:99:46 (hex)
     Subject                 CN=localhost Intermediate CA RSA,O=The TlsMate Company,C=DE
     Issuer                  CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>RSA_PKCS1_SHA256</font>
     Public key              RSA, <font color=yellow><b>2048 bits</b></font>
     Key usage               KEY_CERT_SIGN, CRL_SIGN
     Validity period         <font color=green>2021-08-22 14:17:44</font> - <font color=green>2031-08-20 14:17:44</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/root-rsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=green>certificate not revoked</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        d9:75:40:b5:e0:7e:ce:97:ed:83:c2:e4:e6:8d:76:a8:f7:6b:58:ac
     Fingerprint SHA256      8a:8e:de:f9:d0:2a:22:04:0e:a5:f7:1e:ec:00:d7:a5:3b:2c:d4:d4:90:52:49:de:aa:11:a2:08:39:28:5e:94

   Certificate #3: Version.v3, self-signed
     Serial number        409274406349521581469817764321618401398589280237 (integer)
                          47:b0:7f:c5:80:01:4e:88:80:bf:be:81:c8:6c:90:56:0e:68:cf:ed (hex)
     Subject              CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Issuer               CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm  <font color=green>RSA_PKCS1_SHA256</font>
     Public key           RSA, <font color=yellow><b>2048 bits</b></font>
     Key usage            KEY_CERT_SIGN, CRL_SIGN
     Validity period      <font color=green>2021-08-22 14:17:44</font> - <font color=green>2031-08-20 14:17:44</font> (3650 days), <font color=green>valid period</font>
     Fingerprint SHA1     34:b4:24:4e:07:7f:76:31:f0:a9:39:91:8c:e0:0d:8e:20:2e:08:63
     Fingerprint SHA256   75:2a:a6:ec:8e:9d:26:7e:e3:cc:18:92:4a:af:6c:0f:dc:05:99:c0:8d:78:62:fa:74:99:b7:f8:6c:ea:fa:ca

 <font color=magenta><b>Vulnerabilities</b></font>

   CCS injection (CVE-2014-0224)                 <font color=red>vulnerable</font>
   Heartbleed (CVE-2014-0160)                    <font color=red>vulnerable</font>
   ROBOT vulnerability (CVE-2017-13099, ...)     <font color=green>not vulnerable</font>
   POODLE vulnerability (SSL30 enabled)          <font color=red>vulnerable</font>
   TLS POODLE vulnerability                      <font color=green>not vulnerable</font>
   Lucky-Minus-20 vulnerability (CVE-2016-2107)  <font color=red>vulnerable, see CBC padding oracle details below</font>
   CBC padding oracle                            <font color=red>vulnerable, number of oracles: 1</font>
     scan accuracy                               lowest (scan with minimal set of cipher suites for each TLS version, application data only)

     oracle properties
       strength             <font color=red>weak, high number of oracle queries required for exploitation</font>
       observable           <font color=red>no, different oracle behavior hard to observe</font>
       oracle type(s)       OpenSSL padding oracle "Lucky-Minus-20" (CVE-2016-2107)
       cipher suite groups  TLS10 TLS_RSA_WITH_AES_128_CBC_SHA application data
                            TLS11 TLS_RSA_WITH_AES_128_CBC_SHA application data
                            TLS12 TLS_RSA_WITH_AES_128_CBC_SHA application data

 </pre>
