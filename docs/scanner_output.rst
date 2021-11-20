
Example for a Scan output
=========================

The following output is the result of a scan against Openssl 1.0.1e (a rather outdated
legacy version), which is affected by several vulnerabilities.

.. raw:: html

 <pre style="color:white; background:black; overflow-x: auto; font-size:0.75em">
 $ tlsmate scan --progress localhost --port=44330 --oracle-accuracy=low
 <font color=magenta><b>A TLS configuration scanner (and more)</b></font>

   tlsmate version  1.0.1.dev194
   repository       https://gitlab.com/guballa/tlsmate
   Please file bug reports at https://gitlab.com/guballa/tlsmate/-/issues

 <font color=magenta><b>Basic scan information</b></font>

   command: /home/jens/.virtualenv/tlsmate/bin/tlsmate scan --progress localhost --port=44330 --oracle-accuracy=low
   tlsmate version       1.0.1.dev194 (producing the scan)
   scan start timestamp  2021-11-20 13:45:16
   scan duration         10.828 seconds
   applied style         /home/jens/project/tlsmate/tlsmate/styles/default.yaml
   style description     very strict profile targeting a security level of 128 bits

 <font color=magenta><b>Scanned host</b></font>

   host            localhost
   port            44330
   SNI             localhost
   IPv4 addresses  127.0.0.1

 <font color=magenta><b>TLS protocol versions</b></font>

   SSL20  <font color=red>supported</font>
   SSL30  <font color=red>supported</font>
   TLS10  <font color=yellow><b>supported</b></font>
   TLS11  <font color=yellow><b>supported</b></font>
   TLS12  <font color=green>supported</font>
   TLS13  not supported

 <font color=magenta><b>Cipher suites</b></font>

   <b>SSL20</b>:
     
     0x010080  <font color=red>SSL_CK_RC4_128_WITH_MD5</font>
     0x020080  <font color=red>SSL_CK_RC4_128_EXPORT40_WITH_MD5</font>
     0x030080  <font color=red>SSL_CK_RC2_128_CBC_WITH_MD5</font>
     0x040080  <font color=red>SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5</font>
     0x050080  <font color=red>SSL_CK_IDEA_128_CBC_WITH_MD5</font>
     0x060040  <font color=red>SSL_CK_DES_64_CBC_WITH_MD5</font>
     0x0700c0  <font color=red>SSL_CK_DES_192_EDE3_CBC_WITH_MD5</font>

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
     0x0017  <font color=red>TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5</font>
     0x0018  <font color=red>TLS_DH_ANON_WITH_RC4_128_MD5</font>
     0x0019  <font color=red>TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA</font>
     0x001a  <font color=red>TLS_DH_ANON_WITH_DES_CBC_SHA</font>
     0x001b  <font color=red>TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA</font>
     0x002f  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0033  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0034  <font color=red>TLS_DH_ANON_WITH_AES_128_CBC_SHA</font>
     0x0035  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x0039  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x003a  <font color=red>TLS_DH_ANON_WITH_AES_256_CBC_SHA</font>
     0x0041  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0045  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0046  <font color=red>TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA</font>
     0x0084  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0088  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0089  <font color=red>TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA</font>
     0x0096  <font color=yellow><b>TLS_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009a  <font color=yellow><b>TLS_DHE_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009b  <font color=red>TLS_DH_ANON_WITH_SEED_CBC_SHA</font>
     0xc002  <font color=red>TLS_ECDH_ECDSA_WITH_RC4_128_SHA</font>
     0xc003  <font color=red>TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc004  <font color=red>TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA</font>
     0xc005  <font color=red>TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA</font>
     0xc007  <font color=red>TLS_ECDHE_ECDSA_WITH_RC4_128_SHA</font>
     0xc008  <font color=red>TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc009  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</b></font>
     0xc00a  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</b></font>
     0xc011  <font color=red>TLS_ECDHE_RSA_WITH_RC4_128_SHA</font>
     0xc012  <font color=red>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc013  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0xc014  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0xc016  <font color=red>TLS_ECDH_ANON_WITH_RC4_128_SHA</font>
     0xc017  <font color=red>TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA</font>
     0xc018  <font color=red>TLS_ECDH_ANON_WITH_AES_128_CBC_SHA</font>
     0xc019  <font color=red>TLS_ECDH_ANON_WITH_AES_256_CBC_SHA</font>

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
     0x0017  <font color=red>TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5</font>
     0x0018  <font color=red>TLS_DH_ANON_WITH_RC4_128_MD5</font>
     0x0019  <font color=red>TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA</font>
     0x001a  <font color=red>TLS_DH_ANON_WITH_DES_CBC_SHA</font>
     0x001b  <font color=red>TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA</font>
     0x002f  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0033  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0x0034  <font color=red>TLS_DH_ANON_WITH_AES_128_CBC_SHA</font>
     0x0035  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x0039  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0x003a  <font color=red>TLS_DH_ANON_WITH_AES_256_CBC_SHA</font>
     0x003c  <font color=yellow><b>TLS_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0x003d  <font color=yellow><b>TLS_RSA_WITH_AES_256_CBC_SHA256</b></font>
     0x0041  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0045  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</b></font>
     0x0046  <font color=red>TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA</font>
     0x0067  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0x006b  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_CBC_SHA256</b></font>
     0x006c  <font color=red>TLS_DH_ANON_WITH_AES_128_CBC_SHA256</font>
     0x006d  <font color=red>TLS_DH_ANON_WITH_AES_256_CBC_SHA256</font>
     0x0084  <font color=yellow><b>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0088  <font color=yellow><b>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</b></font>
     0x0089  <font color=red>TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA</font>
     0x0096  <font color=yellow><b>TLS_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009a  <font color=yellow><b>TLS_DHE_RSA_WITH_SEED_CBC_SHA</b></font>
     0x009b  <font color=red>TLS_DH_ANON_WITH_SEED_CBC_SHA</font>
     0x009c  <font color=yellow><b>TLS_RSA_WITH_AES_128_GCM_SHA256</b></font>
     0x009d  <font color=yellow><b>TLS_RSA_WITH_AES_256_GCM_SHA384</b></font>
     0x009e  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_128_GCM_SHA256</b></font>
     0x009f  <font color=yellow><b>TLS_DHE_RSA_WITH_AES_256_GCM_SHA384</b></font>
     0x00a6  <font color=red>TLS_DH_ANON_WITH_AES_128_GCM_SHA256</font>
     0x00a7  <font color=red>TLS_DH_ANON_WITH_AES_256_GCM_SHA384</font>
     0xc002  <font color=red>TLS_ECDH_ECDSA_WITH_RC4_128_SHA</font>
     0xc003  <font color=red>TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc004  <font color=red>TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA</font>
     0xc005  <font color=red>TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA</font>
     0xc007  <font color=red>TLS_ECDHE_ECDSA_WITH_RC4_128_SHA</font>
     0xc008  <font color=red>TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc009  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</b></font>
     0xc00a  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</b></font>
     0xc011  <font color=red>TLS_ECDHE_RSA_WITH_RC4_128_SHA</font>
     0xc012  <font color=red>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA</font>
     0xc013  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</b></font>
     0xc014  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</b></font>
     0xc016  <font color=red>TLS_ECDH_ANON_WITH_RC4_128_SHA</font>
     0xc017  <font color=red>TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA</font>
     0xc018  <font color=red>TLS_ECDH_ANON_WITH_AES_128_CBC_SHA</font>
     0xc019  <font color=red>TLS_ECDH_ANON_WITH_AES_256_CBC_SHA</font>
     0xc023  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256</b></font>
     0xc024  <font color=yellow><b>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384</b></font>
     0xc025  <font color=red>TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256</font>
     0xc026  <font color=red>TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384</font>
     0xc027  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</b></font>
     0xc028  <font color=yellow><b>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</b></font>
     0xc02b  <font color=green>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</font>
     0xc02c  <font color=green>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</font>
     0xc02d  <font color=red>TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256</font>
     0xc02e  <font color=red>TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384</font>
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

 <font color=magenta><b>DH groups (finite field)</b></font>

   <b>SSL30, TLS10, TLS11, TLS12</b>:
     <font color=red>unknown group (512 bits)</font>

 <font color=magenta><b>Features</b></font>

   <b>Common features</b>
     OCSP stapling (status_request)           <font color=red>not supported</font>
     OCSP multi stapling (status_request_v2)  not supported
     Heartbeat                                <font color=red>supported</font>
     Downgrade attack prevention              <font color=red>no, TLS_FALLBACK_SCSV not supported</font>

   <b>Features for TLS1.2 and below</b>
     compression                       <font color=green>not supported</font>
     encrypt-then-mac                  <font color=red>not supported</font>
     extended master secret            <font color=red>not supported</font>
     insecure renegotiation            <font color=green>not supported</font>
     secure renegotiation (extension)  <font color=green>supported</font>
     secure renegotiation (SCSV)       <font color=green>supported</font>
     resumption with session_id        supported
     resumption with session ticket    <font color=yellow><b>supported</b></font>, life time: 300 seconds

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
     Serial number           565193647331873720 (integer)
                             07:d7:f8:a0:b2:86:13:b8 (hex)
     Subject                 CN=localhost,O=The TlsMate Company (Server side) RSA,C=DE
     SubjectAltName (SAN)    test.localhost *.wildcard.localhost
     URI matches             <font color=green>yes, URI matches subject/SAN</font>
     Extended validation     no
     Issuer                  CN=localhost Intermediate CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>RSA_PKCS1_SHA256</font>
     Public key              RSA, <font color=yellow><b>2048 bits</b></font>
     Extended key usage      serverAuth
     Validity period         <font color=green>2021-10-24 15:52:08</font> - <font color=green>2031-10-22 15:52:08</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/ca-rsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=green>certificate not revoked</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        bb:17:c4:8b:38:5e:b2:7e:53:0d:a8:da:15:f2:dc:6d:4c:f4:1e:ac
     Fingerprint SHA256      a9:a7:10:02:32:54:93:6f:2e:1e:3e:53:50:09:f0:3e:48:25:75:d5:54:3e:7e:ec:14:13:55:cc:2b:c3:85:71

   Certificate #2: Version.v3
     Serial number           884320082054204453 (integer)
                             0c:45:bc:6d:e6:95:cc:25 (hex)
     Subject                 CN=localhost Intermediate CA RSA,O=The TlsMate Company,C=DE
     Issuer                  CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>RSA_PKCS1_SHA256</font>
     Public key              RSA, <font color=yellow><b>2048 bits</b></font>
     Key usage               KEY_CERT_SIGN, CRL_SIGN
     Validity period         <font color=green>2021-10-24 15:52:08</font> - <font color=green>2031-10-22 15:52:08</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/root-rsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=green>certificate not revoked</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        10:a1:52:7d:4b:a0:e4:74:93:17:f1:d3:e6:b3:f5:b9:42:8f:e0:60
     Fingerprint SHA256      cb:9e:41:53:f4:23:54:5f:e1:11:3f:db:76:14:88:11:c9:2d:f4:75:24:41:a3:00:bf:5b:68:ba:43:18:ee:25

   Certificate #3: Version.v3, self-signed
     Serial number        521184170230288745346396856830831433308019364478 (integer)
                          5b:4a:b4:db:9b:f8:c4:47:ad:99:bf:d3:a9:48:35:84:3c:24:12:7e (hex)
     Subject              CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Issuer               CN=localhost Root CA RSA,O=The TlsMate Company,C=DE
     Signature algorithm  RSA_PKCS1_SHA256
     Public key           RSA, <font color=yellow><b>2048 bits</b></font>
     Key usage            KEY_CERT_SIGN, CRL_SIGN
     Validity period      <font color=green>2021-10-24 15:52:07</font> - <font color=green>2031-10-22 15:52:07</font> (3650 days), <font color=green>valid period</font>
     Fingerprint SHA1     2b:bb:f7:fb:97:8c:61:be:ee:82:9b:59:ae:5b:b4:82:c2:87:f1:bc
     Fingerprint SHA256   82:5d:24:41:a6:60:cb:25:69:64:86:c4:89:c8:b1:11:2e:e7:ca:a2:0e:47:69:4b:d7:90:e3:c1:7c:04:8d:51


   <b>Certificate chain #2:</b> <font color=red>validation failed</font>
      <font color=yellow><b>root certificate was provided by the server</b></font>
   Certificate #1: Version.v3
     Issues                  <font color=red>- connection to OCSP server http://ocsp.localhost:44402 failed</font>
     Serial number           623199794906479353 (integer)
                             08:a6:0c:e9:5f:7f:3a:f9 (hex)
     Subject                 CN=localhost,O=The TlsMate Company (Server side) ECDSA,C=DE
     SubjectAltName (SAN)    test.localhost *.wildcard.localhost
     URI matches             <font color=green>yes, URI matches subject/SAN</font>
     Extended validation     no
     Issuer                  CN=localhost Intermediate CA ECDSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>ECDSA_SECP256R1_SHA256</font>
     Public key              ECDSA, <font color=green>384 bits</font>
     Extended key usage      serverAuth
     Validity period         <font color=green>2021-10-24 15:52:08</font> - <font color=green>2031-10-22 15:52:08</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/ca-ecdsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=red>invalid response from OCSP server</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        8b:84:35:26:e7:f9:4b:93:0c:38:61:7d:4c:fc:c7:ab:08:62:24:7d
     Fingerprint SHA256      18:d8:4d:ce:23:ac:ac:b4:65:a3:69:81:3f:75:84:94:40:bd:c2:f6:1d:16:9e:10:55:f1:57:1c:e1:5c:f1:04

   Certificate #2: Version.v3
     Serial number           378045038698480976 (integer)
                             05:3f:15:f5:b0:b8:c5:50 (hex)
     Subject                 CN=localhost Intermediate CA ECDSA,O=The TlsMate Company,C=DE
     Issuer                  CN=localhost Root CA ECDSA,O=The TlsMate Company,C=DE
     Signature algorithm     <font color=green>ECDSA_SECP256R1_SHA256</font>
     Public key              ECDSA, <font color=green>384 bits</font>
     Key usage               KEY_CERT_SIGN, CRL_SIGN
     Validity period         <font color=green>2021-10-24 15:52:08</font> - <font color=green>2031-10-22 15:52:08</font> (3650 days), <font color=green>valid period</font>
     CRLs                    http://crl.localhost:44400/crl/root-ecdsa.crl
     CRL revocation status   <font color=green>certificate not revoked</font>
     OCSP revocation status  <font color=green>certificate not revoked</font>
     OCSP must staple        <font color=green>yes (must staple, must multi-staple)</font>
     Fingerprint SHA1        c4:4a:ba:d7:61:62:84:f6:43:bc:97:bd:5e:7d:d8:67:3e:23:04:64
     Fingerprint SHA256      59:b7:e7:6e:9b:b7:a4:a4:05:32:57:34:bf:16:fe:8e:ab:62:55:a1:1d:2a:3d:14:75:3c:17:05:0d:55:5c:c4

   Certificate #3: Version.v3, self-signed
     Serial number        522419781406433765027913324933085847475332282797 (integer)
                          5b:82:1c:fa:80:b0:7d:3c:61:f3:31:7e:7e:b8:af:b4:aa:ff:79:ad (hex)
     Subject              CN=localhost Root CA ECDSA,O=The TlsMate Company,C=DE
     Issuer               CN=localhost Root CA ECDSA,O=The TlsMate Company,C=DE
     Signature algorithm  ECDSA_SECP256R1_SHA256
     Public key           ECDSA, <font color=green>384 bits</font>
     Key usage            KEY_CERT_SIGN, CRL_SIGN
     Validity period      <font color=green>2021-10-24 15:52:07</font> - <font color=green>2031-10-22 15:52:07</font> (3650 days), <font color=green>valid period</font>
     Fingerprint SHA1     95:d4:be:b1:6f:72:2e:a8:9c:2d:85:cc:d7:b6:64:3c:65:45:9e:37
     Fingerprint SHA256   59:aa:21:6a:13:26:e8:ae:a4:89:7e:2d:c1:b4:8d:f2:27:f7:bc:b6:fe:32:58:bd:b4:4e:94:05:58:b4:95:a7

 <font color=magenta><b>Vulnerabilities</b></font>

   BEAST (CVE-2011-3389)                   <font color=red>vulnerable, TLS1.0 is enabled</font>
   CCS injection (CVE-2014-0224)           <font color=red>vulnerable</font>
   CRIME (CVE-2012-4929)                   <font color=green>not vulnerable</font>
   FREAK (CVE-2015-0204)                   <font color=red>vulnerable, RSA-export cipher suites are enabled</font>
   Heartbleed (CVE-2014-0160)              <font color=red>vulnerable</font>
   Logjam (CVE-2015-0204)                  <font color=red>vulnerable, DH export cipher suites in use (512 bits)</font>
   ROBOT (CVE-2017-13099, ...)             <font color=green>not vulnerable</font>
   Sweet32 (CVE-2016-2183, CVE-2016-6329)  <font color=red>vulnerable, cipher suites with blocksize <= 64 bits used (3DES, IDEA)</font>
   POODLE (CVE-2014-3566)                  <font color=red>vulnerable, SSL30 is enabled</font>
   TLS POODLE                              <font color=green>not vulnerable</font>
   Lucky-Minus-20 (CVE-2016-2107)          <font color=red>vulnerable, see CBC padding oracle details below</font>
   CBC padding oracle                      <font color=red>vulnerable, number of oracles: 1</font>
     scan accuracy                         lowest (scan with minimal set of cipher suites for each TLS version, application data only)

     oracle properties
       strength             <font color=red>weak, high number of oracle queries required for exploitation</font>
       observable           <font color=red>no, different oracle behavior hard to observe</font>
       oracle type(s)       OpenSSL padding oracle "Lucky-Minus-20" (CVE-2016-2107)
       cipher suite groups  TLS10 TLS_RSA_WITH_AES_128_CBC_SHA application data
                            TLS11 TLS_RSA_WITH_AES_128_CBC_SHA application data
                            TLS12 TLS_RSA_WITH_AES_128_CBC_SHA application data

 </pre>
