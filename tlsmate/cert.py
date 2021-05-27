# -*- coding: utf-8 -*-
"""Module for handling a certificate chain
"""
# import basic stuff
import logging

# import own stuff
from tlsmate import tls
from tlsmate import cert_utils
from tlsmate.exception import UntrustedCertificate

# import other stuff
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    rsa,
    dsa,
    ed25519,
    ed448,
)
from cryptography.hazmat.primitives.serialization import Encoding


class Certificate(object):
    """Represents a certificate.

    The arguments der and pem are exclusive.

    Arguments:
        der (bytes): the certificate in DER-format (raw bytes)
        pem (bytes): the certificate in PEM-format
        parse (bool): whether the certificate shall be parsed (i.e., all relevant
            data are extracted from the given der/pem structure), or if it shall just
            be stored. In the latter case the certificate will be parsed if a
            property is accessed.
    """

    def __init__(self, der=None, pem=None, x509_cert=None, parse=False):

        if (der, pem, x509_cert).count(None) != 2:
            raise ValueError("der, pem and x509_cert are exclusive")

        self._bytes = None
        self._pem = None
        self._parsed = None
        self._subject_str = None
        self._self_signed = None
        self.auth_key_id = None
        self.subject_key_id = None
        self.subject_matches = None
        self.fingerprint_sha1 = None
        self.fingerprint_sha256 = None
        self.tls12_signature_algorithms = None
        self.tls13_signature_algorithms = None
        self.crl_status = None
        self.ocsp_status = None
        self.issues = []
        self.trusted = None

        if der is not None:
            self._bytes = der
            if parse:
                self._parsed = x509.load_der_x509_certificate(self._bytes)
                self._parse()

        elif pem is not None:
            if isinstance(pem, str):
                pem = pem.encode()

            self._pem = pem
            self._parsed = x509.load_pem_x509_certificate(pem)
            self._parse()

        else:
            self._parsed = x509_cert
            if parse:
                self._parse()

    def __str__(self):
        return self.subject_str

    def __eq__(self, other):
        return self.bytes == other.bytes

    @property
    def subject_str(self):
        """str: The subject name formatted according to RFC 4514.
        """
        if self._subject_str is None:
            self._subject_str = self._parsed.subject.rfc4514_string()
        return self._subject_str

    @property
    def parsed(self):
        """:obj:`cryptography.x509.Certificate`: the x509 certificate object
        """
        if self._parsed is None:
            self._parsed = x509.load_der_x509_certificate(self._bytes)
            self._parse()
        return self._parsed

    @property
    def bytes(self):
        """bytes: the certificate in raw format"""
        if self._bytes is None:
            self._bytes = self.parsed.public_bytes(Encoding.DER)
        return self._bytes

    @property
    def pem(self):
        """bytes: the certificate in pem format (it is a binary string!)"""
        if self._pem is None:
            self._pem = self.parsed.public_bytes(Encoding.PEM)
        return self._pem

    def _determine_signature_algorithms(self, public_key):
        """For a given public key provide the compatible signature algorithms.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            self.tls12_signature_algorithms = [
                tls.SignatureScheme.RSA_PKCS1_SHA1,
                tls.SignatureScheme.RSA_PKCS1_SHA256,
                tls.SignatureScheme.RSA_PKCS1_SHA384,
                tls.SignatureScheme.RSA_PKCS1_SHA512,
                tls.SignatureScheme.RSA_PKCS1_MD5,
                tls.SignatureScheme.RSA_PKCS1_SHA224,
                # Currently, cryptography does not support RSA-PSS-PSS
                # tls.SignatureScheme.RSA_PSS_PSS_SHA256,
                # tls.SignatureScheme.RSA_PSS_PSS_SHA384,
                # tls.SignatureScheme.RSA_PSS_PSS_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            ]
            self.tls13_signature_algorithms = [
                # tls.SignatureScheme.RSA_PSS_PSS_SHA256,
                # tls.SignatureScheme.RSA_PSS_PSS_SHA384,
                # tls.SignatureScheme.RSA_PSS_PSS_SHA512,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
                tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
            ]

        elif isinstance(public_key, dsa.DSAPublicKey):
            self.tls12_signature_algorithms = [
                tls.SignatureScheme.DSA_MD5,
                tls.SignatureScheme.DSA_SHA1,
                tls.SignatureScheme.DSA_SHA224,
                tls.SignatureScheme.DSA_SHA256,
                tls.SignatureScheme.DSA_SHA384,
                tls.SignatureScheme.DSA_SHA512,
            ]
            self.tls13_signature_algorithms = []

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            size_to_algo = {
                128: tls.SignatureScheme.ECDSA_SHA1,
                224: tls.SignatureScheme.ECDSA_SECP224R1_SHA224,
                256: tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
                384: tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
                512: tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
            }
            sig_scheme = size_to_algo.get(public_key.curve.key_size)
            if sig_scheme is None:
                raise ValueError(
                    f"unknown keysize {public_key.curve.key_size} for ECDSA public key"
                )

            self.tls12_signature_algorithms = [sig_scheme]
            if sig_scheme is tls.SignatureScheme.ECDSA_SHA1:
                self.tls13_signature_algorithms = []
            else:
                self.tls13_signature_algorithms = [sig_scheme]

        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self.tls12_signature_algorithms = [tls.SignatureScheme.ED25519]
            self.tls13_signature_algorithms = [tls.SignatureScheme.ED25519]

        elif isinstance(public_key, ed448.Ed448PublicKey):
            self.tls12_signature_algorithms = [tls.SignatureScheme.ED448]
            self.tls13_signature_algorithms = [tls.SignatureScheme.ED448]

    def _parse(self):
        """Parse the certificate, so that all attributes are set.
        """
        self.fingerprint_sha1 = self._parsed.fingerprint(hashes.SHA1())
        self.fingerprint_sha256 = self._parsed.fingerprint(hashes.SHA256())
        self.signature_algorithm = cert_utils.map_x509_sig_scheme(
            self._parsed.signature_hash_algorithm, self._parsed.signature_algorithm_oid,
        )
        try:
            key_usage = self._parsed.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            if key_usage.value.digital_signature:
                self._determine_signature_algorithms(self._parsed.public_key())
        except x509.ExtensionNotFound:
            self._determine_signature_algorithms(self._parsed.public_key())

        try:
            self.auth_key_id = self._parsed.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            ).value.key_identifier

        except x509.ExtensionNotFound:
            self.auth_key_id = None

        try:
            self.subject_key_id = self._parsed.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value.digest

        except x509.ExtensionNotFound:
            self.subject_key_id = None

    def _common_name(self, name):
        """From a given name, extract the common name

        Note, that there might be multiple common names present, in this case
        simple the first one is returned.
        """
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            raise UntrustedCertificate(f'no common name for "{self}"')
        return cns[0].value

    @property
    def self_signed(self):
        """bool: Provide an indication if the certificate is self-signed.
        """
        if self._self_signed is None:
            self._self_signed = cert_utils.equal_names(
                self.parsed.subject, self.parsed.issuer
            )
        return self._self_signed

    def _raise_untrusted(self, issue, raise_on_failure):
        self.trusted = False
        issue_long = f"certificate {self}: {issue}"
        logging.debug(issue_long)
        self.issues.append(issue)
        if raise_on_failure:
            raise UntrustedCertificate(issue_long)

    def validate_period(self, datetime, raise_on_failure=True):
        """Validate the period of the certificate against a given timestamp.

        Arguments:
            datetime (:obj:`datetime.datetime`): the timestamp
            raise_on_failure (bool): whether an exception shall be raised if the
                validation fails.

        Returns:
            bool: The validation state

        Raises:
            UntrustedCertificate: if the timestamp is outside the validity period and
            raise_on_failure is True
        """

        if datetime < self.parsed.not_valid_before:
            self._raise_untrusted("validity period not yet reached", raise_on_failure)

        if datetime > self.parsed.not_valid_after:
            self._raise_untrusted("validity period exceeded", raise_on_failure)

    def validate_subject(self, domain, raise_on_failure=True):
        """Validate if the certificate matches the given domain

        It takes the subject and the subject alternative name into account, and
        supports wildcards as well.

        Arguments:
            domain (str): the domain to check against (normally used in the SNI)
            raise_on_failure (bool): whether an exception shall be raised if the
                validation fails or not. Useful for a TLS scan, as the scan shall
                continue.

        Returns:
            bool: indication, if the domain name matches the certificate's subject/SAN

        Raises:
            UntrustedCertificate: if the certificate is not issued for the given
            domain
        """
        domain = cert_utils.string_prep(domain)
        no_subdomain = cert_utils.remove_subdomain(domain)

        subject_cn = self._common_name(self.parsed.subject)
        if cert_utils.subject_matches(subject_cn, domain, no_subdomain):
            self.subject_matches = True
            return

        try:
            subj_alt_names = self.parsed.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in subj_alt_names.value.get_values_for_type(x509.DNSName):
                if cert_utils.subject_matches(name, domain, no_subdomain):
                    self.subject_matches = True
                    return
        except x509.ExtensionNotFound:
            pass

        self.subject_matches = False
        self._raise_untrusted("subject name does not match", raise_on_failure)

    def validate_signature(self, sig_scheme, data, signature):
        """Validate a signature using the public key from the certificate.

        Arguments:
            sig_scheme (:class:`tlsmate.tls.SignatureScheme`): The signature
                scheme to use
            data (bytes): the bytes for which the signature is to be validated
            signature (bytes): the signature

        Raises:
            cryptography.exceptions.InvalidSignature: If the signature does not
                validate.

        """
        cert_utils.validate_signature(self, sig_scheme, data, signature)

    def validate_cert_signature(self, cert):
        """Validate the signature within a certificate

        Arguments:
            cert (:obj:`Certificate`): the certificate for which the signature
                shall be checked.

        Raises:
            cryptography.exceptions.InvalidSignature: If the signature does not
                validate.
        """

        self.validate_signature(
            cert.signature_algorithm,
            cert.parsed.tbs_certificate_bytes,
            cert.parsed.signature,
        )
