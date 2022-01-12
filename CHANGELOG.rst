Changelog
#########


v1.2.0 (2022-01-12)
===================

Bugfix
------

* Client certificates provided via command line were ignored (#115)

* Connections over IPv6 were not working (#124)

Added
-----

* Added support for HelloRetryRequest message (TLS1.3) (#113, #114)

* Scanning over an HTTP-proxy is now supported (#122)

* Command line argument added to prefer the use IPv6 addresses after resolving the host name (#124)

* Documentation extended on how to configure the trust store (#125)

* Provide a Docker image (#126)

Changed
-------

* Plugins must be enabled now explicitly (#119)


v1.1.2 (2021-12-02)
===================

Bugfix
------

* In special cases the same issue for a certificate was reported multiple times (#111)

* A timeout to a CCS-injection was reported as "UNDETERMINED" (#109)

* Downgrade protection was wrongly set if SSLv2 and SSLv3 were supported only (#108)

* The Logjam state was not correctly displayed in all cases (#107, #112)


v1.1.1 (2021-11-26)
===================

Bugfix
------

* Support for RSA cipher suites was not detected due to a DECODE_ERROR during the scan (#106)

* Timeout on heatbeat was not detected as such (#105)


v1.1.0 (2021-11-21)
===================

Bugfix
------

* Help text corrected (#102)

* Exception was raised when using older Python versions (#97)

* Exception was raised when "--no-features" was given (#96)

* Support for TLS13 was not always detected (#95)

* EdDSA certificate was not added to the server profile (#94)

* Certificate id 0 was displayed as an empty string (#92)

* Tabular output corrected (#91)

* SSL3 handshake aborted by server on reception of tlsmate's Finished message (#90)

* Exception was raised when scanning for parameter value tolerance (#87)

* Exception was raised if a handshake fails when scanning for TLS-POODLE (#87)

* In some cases the certificate chain was not correctly validated (#85, #99)

* Keyboard interrupt did not stop the scan (#82)

* State for supported TLS versions were not always correct (#80)

* Exception during a scan fixed (#78)

* Problems with features and vulnerability command line arguments fixed (#77)

Added
-----

* Display "extended validation" for certificates (#71)

* Support "must staple" in certificates (#69)

* Support Python3.9 (#66)

* Test coverage increased (#56)

* Colored text output is now configurable (#65, #74, #81)

* Scan for additional vulnerabilities (#84)

* Scan for CBC padding oracles added (#76)

* Scan for Lucky-Minus-20 vulnerability added (#75)

* Scan for downgrade attack prevention added (#70)

* Scan for OCSP stapling (status_request, status_request_v2) added (#64)

* Scan for ephemeral key re-used added (#63, #73)

* Scan for CHACHA20_POLY1305 preference added (#62)


Changed
-------

* Empty sections are not displayed anymore in the text output (#103)

* Stack trace now suppressed if domain name cannot be resolved or TCP connection setup fails (#101)

* Plugin interface refactored (#89)

* Display for renegotiation support improved (#88)

* Exception handling improved (#83)

* For self-signed certificates the signature algorithm is always neutral now (#79)

* Progress indicator improved (#68)


v1.0.1 (2021-06-18)
===================

Bugfix
------

* IPv6 addresses were not correctly processed. Now port is separated in the CLI (#67)

v1.0.0 (2021-06-07)
===================

Bugfix
------

* Heartbleed: a timeout was not clearly indicated in the server profile (#55)

* The supported version extension was setup in the wrong order (#32)

* Resolve exception in case unknown parameters are scanned when no TLS protocol version is supported (#50)

* Don't test for unknown extensions for SSLv3 (#49)

Added
-----

* Documentation for creating test cases has been added (#61)

* Support for the certificate extension "PolicyContraint" has been added (#54)

* Check the certificate revocation status via OCSP (#46)

Changed
-------

* The cipher suite section in the server profile has been cleaned up (#60)

* Extension of the server profile has been simplified (#59)

* CLI is now using subcommands (#40)

* The representation for DH group support has been simplified in the server profile (#57)

* Improve certificate chain validation, take alternate trust paths into account (#45)

* Refactoring: use a separate class for the client profile (#52)

Removed
-------

* Remove dependency on gmpy2, which required to have additional development files installed (#53)

* Signature algorithm preference has been removed as it is not used at all (#58)


v0.1.1 (2021-05-05)
===================

Bugfix
------

* correct packaging error, executing tlsmate failed (#48)

v0.1.0 (2021-05-05)
===================

* Initial release
