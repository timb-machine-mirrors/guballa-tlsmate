# -*- coding: utf-8 -*-
"""Module for handling a certificate chain
"""
# import basic stuff
import stringprep
import unicodedata
import logging
import pem
import time

# import own stuff
from tlsmate import tls
from tlsmate.exception import CertValidationError, CertChainValidationError, OcspError
from tlsmate import recorder

# import other stuff
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.oid import SignatureAlgorithmOID as sigalg_oid
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    ec,
    rsa,
    dsa,
    ed25519,
    ed448,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature


def string_prep(label):
    """Prepares a string for comparison according to RFC 3435.

    Copy&Pasted code. Let's hope the best.

    Arguments:
        label (str): The string to prepare

    Returns:
        str: the prepared string
    """
    # Map
    newlabel = []
    for c in label:
        if stringprep.in_table_b1(c):
            # Map to nothing
            continue
        newlabel.append(stringprep.map_table_b2(c))
    label = "".join(newlabel)

    # Normalize
    label = unicodedata.normalize("NFKC", label)

    # Prohibit
    for c in label:
        if (
            stringprep.in_table_c12(c)
            or stringprep.in_table_c22(c)
            or stringprep.in_table_c3(c)
            or stringprep.in_table_c4(c)
            or stringprep.in_table_c5(c)
            or stringprep.in_table_c6(c)
            or stringprep.in_table_c7(c)
            or stringprep.in_table_c8(c)
            or stringprep.in_table_c9(c)
        ):
            raise UnicodeError("Invalid character %r" % c)

    # Check bidi
    RandAL = map(stringprep.in_table_d1, label)
    for c in RandAL:
        if c:
            # There is a RandAL char in the string. Must perform further
            # tests:
            # 1) The characters in section 5.8 MUST be prohibited.
            # This is table C.8, which was already checked
            # 2) If a string contains any RandALCat character, the string
            # MUST NOT contain any LCat character.
            if filter(stringprep.in_table_d2, label):
                raise UnicodeError("Violation of BIDI requirement 2")

            # 3) If a string contains any RandALCat character, a
            # RandALCat character MUST be the first character of the
            # string, and a RandALCat character MUST be the last
            # character of the string.
            if not RandAL[0] or not RandAL[-1]:
                raise UnicodeError("Violation of BIDI requirement 3")

    return label


def remove_subdomain(name):
    """Removes the subdomain from a given URL.

    Example:
        >>> remove_subdomain("www.example.com")
        '.example.com'

    Arguments:
        name (str): the domain

    Returns:
        str: the string with the subdomain removed. The string starts with the dot.

    Raises:
        ValueError: If the URL does not contain a subdomain.
    """
    try:
        pos = name.index(".")
    except ValueError:
        return name
    return name[pos:]


def subject_matches(subject, full_domain, name_no_subdomain):
    """Checks, if a given subject matches either a full domain or a wildcard domain.

    The subject is prepared for string comparison first.

    Arguments:
        subject (str): the subject to be checked
        full_domain (str): the full domain, e.g. "www.example.com". This argument
            should be string-prepped.
        name_no_subdomain (str): the domain without the leading subdomain, e.g.
            ".example.com". This argument should be string_prepped.

    Returns:
        bool: True, if the subject matches either the full domain or the
        name_no_subdomain
    """
    subject = string_prep(subject)
    if subject.startswith("*"):
        return subject[1:] == name_no_subdomain
    return subject == full_domain


def equal_oid(name_attrs1, name_attrs2):
    """Check two attributes for equality

    Arguments:
        name_attrs1 (:obj:`cryptography.x509.NameAttribute`): an attribute name
            object as defined by the library crypthography.
        name_attrs2 (:obj:`cryptography.x509.NameAttribute`): an attribute name
            object as defined by the library crypthography.

    Returns:
        bool: True, if both attributes are equal as defined in RFC 5280.
    """

    values1 = [string_prep(name_attr.value) for name_attr in name_attrs1]
    values2 = [string_prep(name_attr.value) for name_attr in name_attrs2]
    return set(values1) == set(values2)


def equal_rdn(rdn1, rdn2):
    """Check two rdns (Relative Distinguished Name) for equality

    Arguments:
        rdn1 (:obj:`cryptography.x509.RelativeDistinguishedName`): an rdn
            object as defined by the library crypthography.
        rdn2 (:obj:`cryptography.x509.RelativeDistinguishedName`): an rdn
            object as defined by the library crypthography.

    Returns:
        bool: True, if both rdns are equal as defined in RFC 5280.
    """
    return all(
        equal_oid(
            rdn1.get_attributes_for_oid(name_attr.oid),
            rdn2.get_attributes_for_oid(name_attr.oid),
        )
        for name_attr in rdn1
    )


def equal_names(name1, name2):
    """Check two x509 names for equality

    Arguments:
        name1 (:obj:`cryptography.x509.Name`): a name object as defined by the
            library crypthography.
        name2 (:obj:`cryptography.x509.Name`): an name object as defined by the
        library crypthography.

    Returns:
        bool: True, if both names are equal as defined in RFC 5280.
    """
    if len(name1.rdns) != len(name2.rdns):
        return False

    return all(equal_rdn(rdn1, rdn2) for rdn1, rdn2 in zip(name1.rdns, name2.rdns))


_sig_alg = {
    sigalg_oid.RSA_WITH_MD5: tls.SignatureScheme.RSA_PKCS1_MD5,
    sigalg_oid.RSA_WITH_SHA1: tls.SignatureScheme.RSA_PKCS1_SHA1,
    sigalg_oid.RSA_WITH_SHA224: tls.SignatureScheme.RSA_PKCS1_SHA224,
    sigalg_oid.RSA_WITH_SHA256: tls.SignatureScheme.RSA_PKCS1_SHA256,
    sigalg_oid.RSA_WITH_SHA384: tls.SignatureScheme.RSA_PKCS1_SHA384,
    sigalg_oid.RSA_WITH_SHA512: tls.SignatureScheme.RSA_PKCS1_SHA512,
    sigalg_oid.ECDSA_WITH_SHA1: tls.SignatureScheme.ECDSA_SHA1,
    sigalg_oid.ECDSA_WITH_SHA224: tls.SignatureScheme.ECDSA_SECP224R1_SHA224,
    sigalg_oid.ECDSA_WITH_SHA256: tls.SignatureScheme.ECDSA_SECP256R1_SHA256,
    sigalg_oid.ECDSA_WITH_SHA384: tls.SignatureScheme.ECDSA_SECP384R1_SHA384,
    sigalg_oid.ECDSA_WITH_SHA512: tls.SignatureScheme.ECDSA_SECP521R1_SHA512,
    sigalg_oid.DSA_WITH_SHA1: tls.SignatureScheme.DSA_SHA1,
    sigalg_oid.DSA_WITH_SHA224: tls.SignatureScheme.DSA_SHA224,
    sigalg_oid.DSA_WITH_SHA256: tls.SignatureScheme.DSA_SHA256,
    sigalg_oid.ED25519: tls.SignatureScheme.ED25519,
    sigalg_oid.ED448: tls.SignatureScheme.ED448,
}

_pss_sig_alg = {
    "sha256": tls.SignatureScheme.RSA_PSS_RSAE_SHA256,
    "sha384": tls.SignatureScheme.RSA_PSS_RSAE_SHA384,
    "sha512": tls.SignatureScheme.RSA_PSS_RSAE_SHA512,
}


def _verify_rsa_pkcs(cert, signature, data, hash_algo):
    """Verify RSA PKCSv15 signatures
    """
    cert.parsed.public_key().verify(signature, data, padding.PKCS1v15(), hash_algo())


def _verify_dsa(cert, signature, data, hash_algo):
    """Verify DSA signatures
    """
    cert.parsed.public_key().verify(signature, data, hash_algo())


def _verify_ecdsa(cert, signature, data, hash_algo):
    """Verify ECDSA signatures
    """
    cert.parsed.public_key().verify(signature, data, ec.ECDSA(hash_algo()))


def _verify_xcurve(cert, signature, data, hash_algo):
    """Verify X25519 and X488 signatures
    """
    cert.parsed.public_key().verify(signature, data)


def _verify_rsae_pss(cert, signature, data, hash_algo):
    """Verify RSA-PSS signatures
    """
    cert.parsed.public_key().verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo()), salt_length=hash_algo.digest_size),
        hash_algo(),
    )


_sig_schemes = {
    tls.SignatureScheme.RSA_PKCS1_MD5: (_verify_rsa_pkcs, hashes.MD5),
    tls.SignatureScheme.RSA_PKCS1_SHA1: (_verify_rsa_pkcs, hashes.SHA1),
    tls.SignatureScheme.RSA_PKCS1_SHA224: (_verify_rsa_pkcs, hashes.SHA224),
    tls.SignatureScheme.RSA_PKCS1_SHA256: (_verify_rsa_pkcs, hashes.SHA256),
    tls.SignatureScheme.RSA_PKCS1_SHA384: (_verify_rsa_pkcs, hashes.SHA384),
    tls.SignatureScheme.RSA_PKCS1_SHA512: (_verify_rsa_pkcs, hashes.SHA512),
    tls.SignatureScheme.DSA_MD5: (_verify_dsa, hashes.MD5),
    tls.SignatureScheme.DSA_SHA1: (_verify_dsa, hashes.SHA1),
    tls.SignatureScheme.DSA_SHA224: (_verify_dsa, hashes.SHA224),
    tls.SignatureScheme.DSA_SHA256: (_verify_dsa, hashes.SHA256),
    tls.SignatureScheme.DSA_SHA384: (_verify_dsa, hashes.SHA384),
    tls.SignatureScheme.DSA_SHA512: (_verify_dsa, hashes.SHA512),
    tls.SignatureScheme.ECDSA_SHA1: (_verify_ecdsa, hashes.SHA1),
    tls.SignatureScheme.ECDSA_SECP224R1_SHA224: (_verify_ecdsa, hashes.SHA224),
    tls.SignatureScheme.ECDSA_SECP256R1_SHA256: (_verify_ecdsa, hashes.SHA256),
    tls.SignatureScheme.ECDSA_SECP384R1_SHA384: (_verify_ecdsa, hashes.SHA384),
    tls.SignatureScheme.ECDSA_SECP521R1_SHA512: (_verify_ecdsa, hashes.SHA512),
    tls.SignatureScheme.RSA_PSS_PSS_SHA256: (_verify_rsae_pss, hashes.SHA256),
    tls.SignatureScheme.RSA_PSS_PSS_SHA384: (_verify_rsae_pss, hashes.SHA384),
    tls.SignatureScheme.RSA_PSS_PSS_SHA512: (_verify_rsae_pss, hashes.SHA512),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA256: (_verify_rsae_pss, hashes.SHA256),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA384: (_verify_rsae_pss, hashes.SHA384),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA512: (_verify_rsae_pss, hashes.SHA512),
    tls.SignatureScheme.ED25519: (_verify_xcurve, None),
    tls.SignatureScheme.ED448: (_verify_xcurve, None),
}


def validate_signature(cert, sig_scheme, data, signature):
    """Validate a signature with a public key from a given certificate.

    Arguments:
        cert (:obj:`Certificate`): The certificate to use
        sig_scheme (:class:`tlsmate.tls.SignatureScheme`): The signature
            scheme to use
        data (bytes): the bytes for which the signature is to be validated
        signature (bytes): the signature

    Raises:
        cryptography.exceptions.InvalidSignature: If the signature does not validate.
    """
    sig_params = _sig_schemes.get(sig_scheme)
    if sig_params is None:
        raise ValueError(f"signature scheme {sig_scheme} not supported")
    sig_params[0](cert, signature, data, sig_params[1])


def map_x509_sig_scheme(x509_hash, x509_oid):
    """Maps a given x509 hash and oid to the internal signature scheme.

    Arguments:
        x509_hash (:obj:`cryptography.hazmat.primitives.hashes.Hash`): the hash object
        x509_oid (:obj:`cryptography.x509.ObjectIdentifier`): the oid for the signature
            algorithm

    Returns:
        :class:`tlsmate.tls.SignatureScheme`: the signature scheme
    """
    if x509_oid is sigalg_oid.RSASSA_PSS:
        sig_scheme = _pss_sig_alg(x509_hash.name)
        if sig_scheme is None:
            raise ValueError(f"signature algorithm {x509_hash} not supported")
        return sig_scheme
    else:
        sig_scheme = _sig_alg.get(x509_oid)
        if sig_scheme is None:
            raise ValueError(f"signature algorithm {x509_oid} not supported")
        return sig_scheme


class CrlManager(object):
    """Handles all CRL related operations and acts as a cache as well
    """

    def __init__(self):
        self._crls = {}

    def add_crl(self, url, der_crl=None, pem_crl=None):
        """Adds a URL and the CRL to the cache.

        Either der_crl or pem_crl must be given.

        Arguments:
            url (str): the URL of the CRL
            der_crl(bytes): the CRL in DER format given as bytes
            pem_crl(bytes): the CRL in PEM format given as bytes
        """
        crl = None
        if der_crl is not None:
            crl = x509.load_der_x509_crl(der_crl)

        elif pem_crl is not None:
            crl = x509.load_pem_x509_crl(pem_crl)

        self._crls[url] = crl

    def _get_crl_obj(self, url, recorder):
        """Get the plain CRL object for a given URL.
        """

        if url not in self._crls:
            bin_crl = None
            recorder.trace(crl_url=url)
            try:
                if recorder.is_injecting():
                    bin_crl = recorder.inject(crl=None)

                else:
                    crl_resp = requests.get(url, timeout=5)
                    if crl_resp.ok:
                        bin_crl = crl_resp.content

                    recorder.trace(crl=bin_crl)

            except Exception:
                self._crls[url] = None

            else:
                self.add_crl(url, der_crl=bin_crl)

        return self._crls[url]

    def get_crl_status(self, urls, serial_nbr, issuer, issuer_cert, recorder):
        """Determines the CRL revocation status for a given cert/urls.

        Downloads the CRL (if a download fails, the next url is tried), if not yet
        cached, validates the CRL against the issuer & its signature and checks if
        the certicifate is present in the CRL or not.

        Arguments:
            urls (list of str): a list of CRL-urls
            serial_nbr (int): the serial number of the certificate to check
            issuer (:obj:`x509.Name`): the issuer name of the cert to check
            issuer_cert (:obj:`Certificate`): the certificate of the issuer
            recorder (:obj:`tlsmate.recorder.Recorder`): the recorder object. Used
                to trace/inject externally retrieved crl.

        Returns:
            :obj:`tlsmate.tls.CertCrlStatus`: the final status.
        """
        status = None
        for url in urls:
            logging.debug(f"downloading CRL from {url}")
            crl = self._get_crl_obj(url, recorder)
            if crl is None:
                status = tls.CertCrlStatus.CRL_DOWNLOAD_FAILED
                continue
            if not equal_names(issuer, issuer_cert.parsed.subject):
                return tls.CertCrlStatus.WRONG_CRL_ISSUER
            if not crl.is_signature_valid(issuer_cert.parsed.public_key()):
                return tls.CertCrlStatus.CRL_SIGNATURE_INVALID
            if crl.get_revoked_certificate_by_serial_number(serial_nbr) is None:
                return tls.CertCrlStatus.NOT_REVOKED
            else:
                return tls.CertCrlStatus.REVOKED
        return status


class TrustStore(object):
    """Represents a trust store containing trusted root certificates

    Objects of this class are iterable, yielding the certificates one by one.

    Arguments:
        ca_files (list of file names): A list of files which contain certificates in
            PEM-format.
    """

    def __init__(self, recorder):
        self._recorder = recorder
        self._ca_files = None
        self._cert_cache = []
        self._fingerprint_cache = []

    def set_ca_files(self, ca_files):
        """Store the CA files containing certs in PEM format
        """

        if ca_files:
            for ca_file in ca_files:
                logging.debug(f"using {ca_file} as trust store")
            self._ca_files = ca_files

    def __iter__(self):
        """Iterator over all certificates
        """

        for cert in self._cert_cache:
            yield cert

        if self._ca_files:
            for file_name in self._ca_files:
                pem_list = pem.parse_file(file_name)
                for pem_item in pem_list:
                    if not isinstance(pem_item, pem.Certificate):
                        continue
                    yield Certificate(pem=pem_item.as_bytes())

    def add_cert(self, cert):
        """Add a certificate to the trust store if not yet present.

        Arguments:
            cert (:obj:`Certificate`): The certificate to add
        """
        if cert.fingerprint_sha256 not in self._fingerprint_cache:
            logging.debug(
                f'adding certificate "{cert.parsed.subject.rfc4514_string()}" '
                f"to trust store cache"
            )
            self._fingerprint_cache.append(cert.fingerprint_sha256)
            self._cert_cache.append(cert)
            if self._recorder.is_recording():
                cert_pem = cert.parsed.public_bytes(Encoding.DER).hex()
                self._recorder.trace(trust_store=cert_pem)

    def cert_in_trust_store(self, cert):
        """Checks if a given certificate is present in the trust store.

        Arguments:
            cert (:obj:`Certificate`): the certificate to check

        Returns:
            bool: True, if the given certificate is present in the trust store
        """
        if self._ca_files is None and not self._cert_cache:
            return False

        for cert2 in self:
            if cert2 == cert:
                self.add_cert(cert2)
                return True

        return False

    def issuer_in_trust_store(self, issuer_name):
        """Returns the certificate for a given issuer name from the trust store.

        Arguments:
            issuer_name (:obj:`cryptography.x509.Name`): the name of the issuer

        Returns:
            :obj:`Certificate` or None if the certificate is not found.
        """

        for cert in self:
            # TODO: Optimize this, as the issuer_name is string_prepped with
            # always the same result in the loop
            if equal_names(cert.parsed.subject, issuer_name):
                self.add_cert(cert)
                return cert

        return None


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
        self.subject_matches = None
        self.fingerprint_sha1 = None
        self.fingerprint_sha256 = None
        self.tls12_signature_algorithms = None
        self.tls13_signature_algorithms = None
        self.crl_status = None
        self.ocsp_status = None

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
        self.signature_algorithm = map_x509_sig_scheme(
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

    def _common_name(self, name):
        """From a given name, extract the common name

        Note, that there might be multiple common names present, in this case
        simple the first one is returned.
        """
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            raise CertValidationError(f'no common name for "{self}"')
        return cns[0].value

    @property
    def self_signed(self):
        """bool: Provide an indication if the certificate is self-signed.
        """
        if self._self_signed is None:
            self._self_signed = equal_names(self.parsed.subject, self.parsed.issuer)
        return self._self_signed

    def validate_period(self, datetime):
        """Validate the period of the certificate against a given timestamp.

        Arguments:
            datetime (:obj:`datetime.datetime`): the timestamp

        Raises:
            CertValidationError: if the timestamp is outside the validity period
        """

        if datetime < self.parsed.not_valid_before:
            raise CertValidationError(f'validity period for "{self}" not yet reached')

        if datetime > self.parsed.not_valid_after:
            raise CertValidationError(f'validity period for "{self}" exceeded')

    def validate_subject(self, domain, raise_on_failure=True):
        """Validate if the certificate matches the given domain

        It takes the subject and the subject alternative name into account, and
        supports wildcards as well.

        Arguments:
            domain (str): the domain to check against (normally used in the SNI)
            raise_on_failure (bool): whether an exception shall be raised if the
                validation fails or not. Useful for a TLS scan, as the scan shall
                continue.

        Raises:
            CertValidationError: if the certificate is not issued for the given
            domain
        """
        domain = string_prep(domain)
        no_subdomain = remove_subdomain(domain)

        subject_cn = self._common_name(self.parsed.subject)
        if subject_matches(subject_cn, domain, no_subdomain):
            self.subject_matches = True
            return

        try:
            subj_alt_names = self.parsed.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in subj_alt_names.value.get_values_for_type(x509.DNSName):
                if subject_matches(name, domain, no_subdomain):
                    self.subject_matches = True
                    return
        except x509.ExtensionNotFound:
            pass

        self.subject_matches = False
        if raise_on_failure:
            raise CertValidationError(f'subject name does not match for "{self}"')

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
        validate_signature(self, sig_scheme, data, signature)


class CertChain(object):
    """Class representing a certificate chain.

    This object is iterable, yielding the x509 representation of the certificates.
    """

    def __init__(self):
        self.certificates = []
        self._digest = hashes.Hash(hashes.SHA256())
        self._digest_value = None
        self._raise_on_failure = True
        self.issues = []
        self.successful_validation = False
        self.root_cert = None
        self.root_cert_transmitted = False
        self.recorder = None

    def set_recorder(self, recorder):
        """Inject the recorder object "manually"

        Arguments:
            recorder (:obj:`tlsmate.recorder.Recorder`): the recorder to use
        """
        self.recorder = recorder

    def append_bin_cert(self, bin_cert):
        """Append the chain by a certificate given in raw format.

        Arguments:
            bin_cert (bytes): the certificate to append in raw format
        """
        self.certificates.append(Certificate(der=bin_cert, parse=True))
        self._digest.update(bin_cert)

    def append_pem_cert(self, pem_cert):
        """Append the chain by a certificate given in pem format.

        Arguments:
            pem_cert (bytes): the certificate to append in pem format
        """
        cert = Certificate(pem=pem_cert)
        self.certificates.append(cert)
        self._digest.update(cert.bytes)

    @property
    def digest(self):
        """bytes: a SHA256 digest of the complete chain, usable for comparison
        """
        if self._digest_value is None:
            self._digest_value = self._digest.finalize()
        return self._digest_value

    def validate_cert_domain_name(self, cert, domain_name):
        """Validate the certificate against the given domain name.

        Arguments:
            cert (:obj:`Certificate`): the certificate to validate
            domain_name (str): the domain name to validate the host certificate against
        """
        try:
            cert.validate_subject(domain_name, self._raise_on_failure)

        except CertValidationError as exc:
            self.issues.append(exc.issue)
            if self._raise_on_failure:
                raise

    def validate_cert(self, cert, timestamp):
        """Basic validation which does not involve other certificates

        Arguments:
            cert (:obj:`Certificate`): the certificate to validate
            timestamp (datetime.datetime): the timestamp to check against
        """
        try:
            cert.validate_period(timestamp)

        except CertValidationError as exc:
            self.issues.append(exc.issue)
            if self._raise_on_failure:
                raise

    def _check_crl(self, cert, issuer_cert, crl_manager, raise_on_failure, check_crl):
        """Check the CRL state for the given certificate.
        """

        if not check_crl:
            cert.crl_status = tls.CertCrlStatus.UNDETERMINED
            return

        try:
            dist_points = cert.parsed.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
        except x509.ExtensionNotFound:
            return

        crl_urls = []
        for dist_point in dist_points.value:
            if dist_point.full_name is not None:
                for gen_name in dist_point.full_name:
                    if isinstance(gen_name, x509.UniformResourceIdentifier):
                        if gen_name.value.startswith("http://"):
                            crl_urls.append(gen_name.value)
            elif dist_point.relative_me is not None:
                raise NotImplementedError

        cert.crl_status = crl_manager.get_crl_status(
            crl_urls,
            cert.parsed.serial_number,
            cert.parsed.issuer,
            issuer_cert,
            self.recorder,
        )
        logging.debug(f'CRL status for certificate "{cert}": {cert.crl_status}')
        if cert.crl_status is not tls.CertCrlStatus.NOT_REVOKED:
            issue = f'CRL status not ok for certificate "{cert}": {cert.crl_status}'
            self.issues.append(issue)
            if raise_on_failure:
                raise CertChainValidationError(issue)

    def _check_ocsp(self, cert, issuer_cert, raise_on_failure, check_ocsp, timestamp):
        """Check the OCSP status for the given certificate.
        """

        def _ocsp_error(issue):
            issue = f"certificate {cert}: " + issue
            logging.debug(issue)
            self.issues.append(issue)
            if raise_on_failure:
                raise OcspError(issue)

        if not check_ocsp:
            cert.ocsp_status = tls.OcspStatus.UNDETERMINED
            return

        try:
            aia = cert.parsed.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value

        except x509.ExtensionNotFound:
            return

        ocsps = [
            ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP
        ]
        if not ocsps:
            return

        ocsp_url = ocsps[0].access_location.value
        builder = x509.ocsp.OCSPRequestBuilder()

        # Hm, some OCSP server do not support SHA256, so let's use SHA1 until we
        # are told otherwise.
        builder = builder.add_certificate(
            cert.parsed, issuer_cert.parsed, hashes.SHA1()
        )
        req = builder.build()
        start = time.time()
        try:
            if self.recorder.is_injecting():
                ocsp_resp = self.recorder.inject_response()

            else:
                ocsp_resp = requests.post(
                    ocsp_url,
                    headers={"Content-Type": "application/ocsp-request"},
                    data=req.public_bytes(serialization.Encoding.DER),
                    timeout=5,
                )
                self.recorder.trace_response(
                    time.time() - start, recorder.SocketEvent.DATA, ocsp_resp
                )

        except requests.Timeout:
            self.recorder.trace_response(
                time.time() - start, recorder.SocketEvent.TIMEOUT
            )
            cert.ocsp_status = tls.OcspStatus.TIMEOUT
            return _ocsp_error(f"connection to OCSP server {ocsp_url} timed out")

        except Exception:
            self.recorder.trace_response(
                time.time() - start, recorder.SocketEvent.CLOSURE
            )
            cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
            return _ocsp_error(f"connection to OCSP server {ocsp_url} failed")

        if ocsp_resp.ok:
            ocsp_decoded = x509.ocsp.load_der_ocsp_response(ocsp_resp.content)

            if ocsp_decoded.certificates:
                sig_cert = Certificate(x509_cert=ocsp_decoded.certificates[0])
                # TODO: check the certificate chain

            else:
                sig_cert = issuer_cert

            # check signature
            try:
                sig_scheme = map_x509_sig_scheme(
                    ocsp_decoded.signature_hash_algorithm,
                    ocsp_decoded.signature_algorithm_oid,
                )
                sig_cert.validate_signature(
                    sig_scheme, ocsp_decoded.tbs_response_bytes, ocsp_decoded.signature,
                )

            except InvalidSignature:
                cert.ocsp_status = tls.OcspStatus.SIGNATURE_INVALID
                return _ocsp_error(f"signature of OCSP server {ocsp_url} invalid")

            if ocsp_decoded.response_status == x509.ocsp.OCSPResponseStatus.SUCCESSFUL:

                if ocsp_decoded.this_update > timestamp:
                    cert.ocsp_status = tls.OcspStatus.INVALID_TIMESTAMP
                    return _ocsp_error(
                        "invalid timestamp in OCSP response (thisUpdate)"
                    )

                if ocsp_decoded.next_update and ocsp_decoded.next_update < timestamp:
                    cert.ocsp_status = tls.OcspStatus.INVALID_TIMESTAMP
                    return _ocsp_error(
                        "invalid timestamp in OCSP response (nextUpdate)"
                    )

                if ocsp_decoded.certificate_status == x509.ocsp.OCSPCertStatus.GOOD:
                    cert.ocsp_status = tls.OcspStatus.NOT_REVOKED
                    logging.debug(f"certificate {cert}: OCSP status ok")
                    return

                if ocsp_decoded.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
                    cert.ocsp_status = tls.OcspStatus.REVOKED

                else:
                    cert.ocsp_status = tls.OcspStatus.UNKNOWN

                return _ocsp_error(f"certificate {cert}: OCSP status not ok")

            cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
            return _ocsp_error(f"OCSP response not ok: {ocsp_decoded.response_status}")

        cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
        return _ocsp_error(f"HTTP response failed with status {ocsp_resp.status_code}")

    def _validate_linked_certs(
        self,
        cert,
        issuer_cert,
        crl_manager,
        raise_on_failure,
        check_crl,
        check_ocsp,
        timestamp,
    ):
        """Validate a certificate against the issuer certificate.
        """

        try:
            issuer_cert.validate_signature(
                cert.signature_algorithm,
                cert.parsed.tbs_certificate_bytes,
                cert.parsed.signature,
            )
        except InvalidSignature:
            issue = (
                f'signature of certificate "{cert}" cannot be '
                f'validated by issuer certificate "{issuer_cert}"'
            )
            self.issues.append(issue)
            if raise_on_failure:
                raise CertChainValidationError(issue)

        self._check_crl(cert, issuer_cert, crl_manager, raise_on_failure, check_crl)
        self._check_ocsp(cert, issuer_cert, raise_on_failure, check_ocsp, timestamp)

    def validate(
        self,
        timestamp,
        domain_name,
        trust_store,
        crl_manager,
        raise_on_failure,
        check_crl=True,
        check_ocsp=True,
    ):
        """Only the minimal checks are supported.

        If a discrepancy is found, an exception is raised.

        Arguments:
            timestamp (datetime.datetime): the timestamp to check against
            domain_name (str): the domain name to validate the host certificate against
            trust_store (:obj:`TrustStore`): the trust store to validate the chain
                against
            raise_on_failure (bool): An indication if an exception shall be raised or
                if the validation shall continue silently.

        Raises:
            CertValidationError: in case a certificate within the chain cannot be
                validated and `raise_on_failure` is True.
            CertChainValidationError: in case the chain cannot be validated and
                raise_on_failure is True.
        """
        self._raise_on_failure = raise_on_failure
        root_cert = None
        prev_cert = None
        last_idx = len(self.certificates) - 1
        for idx, cert in enumerate(self.certificates):

            if idx == 0:
                # Server certificate
                self.validate_cert_domain_name(cert, domain_name)

            self.validate_cert(cert, timestamp)

            if cert.self_signed:
                root_cert = cert
                if idx != last_idx:
                    issue = f'root certificate "{cert}" not the last one in the chain'
                    self.issues.append(issue)
                    if raise_on_failure:
                        raise CertChainValidationError(issue)
            if prev_cert is not None:

                if not equal_names(prev_cert.parsed.issuer, cert.parsed.subject):
                    issue = (
                        f'certificate "{cert}" is not issuer of certificate '
                        f'"{prev_cert}"'
                    )
                    self.issues.append(issue)
                    if raise_on_failure:
                        raise CertChainValidationError(issue)
                self._validate_linked_certs(
                    prev_cert,
                    cert,
                    crl_manager,
                    raise_on_failure,
                    check_crl,
                    check_ocsp,
                    timestamp,
                )

            logging.debug(f'certificate "{cert}" successfully validated')
            prev_cert = cert

        self.root_cert_transmitted = root_cert is not None
        if root_cert is None:
            cert = trust_store.issuer_in_trust_store(prev_cert.parsed.issuer)
            if cert is None:
                issue = (
                    f'issuer certificate "{prev_cert.parsed.issuer.rfc4514_string()}" '
                    f'for certificate "{prev_cert}" not found in trust store'
                )
                self.issues.append(issue)
                if raise_on_failure:
                    raise CertChainValidationError(issue)
            else:
                self.root_cert = cert
                self.validate_cert(self.root_cert, timestamp)

                self._validate_linked_certs(
                    prev_cert,
                    cert,
                    crl_manager,
                    raise_on_failure,
                    check_crl,
                    check_ocsp,
                    timestamp,
                )
        else:
            if not trust_store.cert_in_trust_store(prev_cert):
                issue = f'root certificate "{root_cert}" not found in trust store'
                self.issues.append(issue)
                if raise_on_failure:
                    raise CertChainValidationError(issue)
        self.successful_validation = len(self.issues) == 0

    def serialize(self):
        """Serialize the certificate chain

        Returns:
            list of str: A list of certificates which build the chain. The format is
            a str, representing the DER-format for each certificate.
        """
        return [cert.bytes.hex() for cert in self.certificates]

    def deserialize(self, chain):
        """Deserializes a certificate chain.

        Arguments:
            chain (list of str): The list of certificates of the chain. Each certificate
                is represented in DER-format as a string.
        """
        for cert in chain:
            self.append_bin_cert(bytes.fromhex(cert))
