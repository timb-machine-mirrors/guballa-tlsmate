Changelog
#########

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
