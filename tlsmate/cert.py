# -*- coding: utf-8 -*-
"""Module for handling a certificate chain
"""
import stringprep
import unicodedata
import pem
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.oid import SignatureAlgorithmOID as sigalg_oid
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from tlsmate import constants as tls


class CertValidationError(Exception):
    pass


def string_prep(label):
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
    try:
        pos = name.index(".")
    except ValueError:
        return name
    return name[pos:]


def subject_matches(subject, full_domain, name_no_subdomain):
    subject = string_prep(subject)
    if subject.startswith("*"):
        return subject[1:] == name_no_subdomain
    return subject == full_domain


def equal_oid(name_attrs1, name_attrs2):
    values1 = []
    for name_attr in name_attrs1:
        values1.append(string_prep(name_attr.value))

    values2 = []
    for name_attr in name_attrs2:
        values2.append(string_prep(name_attr.value))

    return set(values1) == set(values2)


def equal_rdn(rdn1, rdn2):

    return all(
        equal_oid(
            rdn1.get_attributes_for_oid(name_attr.oid),
            rdn2.get_attributes_for_oid(name_attr.oid),
        )
        for name_attr in rdn1
    )


def equal_names(name1, name2):
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
    cert.public_key().verify(signature, data, padding.PKCS1v15(), hash_algo())


def _verify_dsa(cert, signature, data, hash_algo):
    cert.public_key().verify(signature, data, hash_algo())


def _verify_ecdsa(cert, signature, data, hash_algo):
    cert.public_key().verify(signature, data, ec.ECDSA(hash_algo()))


def _verify_xcurve(cert, signature, data, hash_algo):
    cert.public_key().verify(signature, data)


def _verify_rsae_pss(cert, signature, data, hash_algo):
    cert.public_key().verify(
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
    tls.SignatureScheme.RSA_PSS_RSAE_SHA256: (_verify_rsae_pss, hashes.SHA256),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA384: (_verify_rsae_pss, hashes.SHA384),
    tls.SignatureScheme.RSA_PSS_RSAE_SHA512: (_verify_rsae_pss, hashes.SHA512),
    tls.SignatureScheme.ED25519: (_verify_xcurve, None),
    tls.SignatureScheme.ED448: (_verify_xcurve, None),
}


def validate_signature(cert, sig_scheme, data, signature):
    sig_params = _sig_schemes.get(sig_scheme)
    if sig_params is None:
        raise ValueError(f"signature scheme {sig_scheme} not supported")
    sig_params[0](cert, signature, data, sig_params[1])


def map_x509_sig_scheme(x509_hash, x509_oid):
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


class TrustStore(object):
    def __init__(self, ca_files=None):
        self._ca_files = ca_files
        self._cert_cache = []

    def __iter__(self):

        for cert in self._cert_cache:
            yield cert

        for file_name in self._ca_files:
            pem_list = pem.parse_file(file_name)
            for pem_item in pem_list:
                if not isinstance(pem_item, pem.Certificate):
                    continue
                yield x509.load_pem_x509_certificate(pem_item.as_bytes())

    def cert_in_trust_store(self, cert):
        if self._ca_files is None:
            return False

        for cert2 in self:
            if cert2 == cert:
                self._cert_cache.append(cert2)
                return True

        return False

    def issuer_in_trust_store(self, issuer_name):

        for cert in self:
            # TODO: Optimize this, as the issuer_name is string_prepped with
            # always the same result in the loop
            if equal_names(cert.subject, issuer_name):
                self._cert_cache.append(cert)
                return cert

        return None


class Certificate(object):
    def __init__(self, bin_cert):
        self._bytes = bin_cert
        self._parsed = None
        self._subject = None

    def __str__(self):
        return self._subject

    @property
    def subject(self):

        if self._subject is None:
            self._parse_cert()
        return self._subject

    @property
    def parsed(self):

        if self._parsed is None:
            self._parse_cert()
        return self._parsed

    def _parse_cert(self):
        self._parsed = x509.load_der_x509_certificate(self._bytes)
        self._subject = self._parsed.subject.rfc4514_string()

    def _common_name(self, name):
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            raise CertValidationError(f'no common name for "{self}"')
        return cns[0].value

    def is_self_signed(self):
        return equal_names(self.parsed.subject, self.parsed.issuer)

    def validate_period(self, datetime):

        if datetime < self.parsed.not_valid_before:
            raise CertValidationError(f'validity period for "{self}" not yet reached')

        if datetime > self.parsed.not_valid_after:
            raise CertValidationError(f'validity period for "{self}" exceeded')

    def validate_subject(self, domain):
        domain = string_prep(domain)
        no_subdomain = remove_subdomain(domain)

        subject_cn = self._common_name(self.parsed.subject)
        if subject_matches(subject_cn, domain, no_subdomain):
            return

        subj_alt_names = self.parsed.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in subj_alt_names.value.get_values_for_type(x509.DNSName):
            if subject_matches(name, domain, no_subdomain):
                return

        raise CertValidationError(f'subject name does not match for "{self}"')

    def validate_signature(self, sig_scheme, data, signature):
        validate_signature(self.parsed, sig_scheme, data, signature)


class CertChain(object):
    def __init__(self):
        self._chain = []
        self._digest = hashes.Hash(hashes.SHA256())
        self._digest_value = None

    def append(self, bin_cert):
        self._chain.append(Certificate(bin_cert))
        self._digest.update(bin_cert)

    def __iter__(self):
        for cert in self._chain:
            yield cert.parsed

    @property
    def digest(self):
        if self._digest_value is None:
            self._digest_value = self._digest.finalize()
        return self._digest_value

    def get(self, idx):
        return self._chain[idx]

    def validate(self, timestamp, domain_name, trust_store):
        """Only the minimal checks are supported.
        """
        root_cert = None
        prev_cert = None
        sig_scheme = None
        last_idx = len(self._chain) - 1
        for idx, cert in enumerate(self._chain):

            if idx == 0:
                # Server certificate
                cert.validate_subject(domain_name)
            cert.validate_period(timestamp)

            if cert.is_self_signed():
                root_cert = cert
                if idx != last_idx:
                    raise CertValidationError(
                        f'root certificate "{cert}" not last one in chain'
                    )
            else:
                if prev_cert is not None:
                    if not equal_names(prev_cert.issuer, cert.parsed.subject):
                        raise CertValidationError(
                            f'subject of "{cert}" not equal to issuer of {prev_cert}'
                        )

                    cert.validate_signature(
                        sig_scheme, prev_cert.tbs_certificate_bytes, prev_cert.signature
                    )
            prev_cert = cert.parsed
            sig_scheme = map_x509_sig_scheme(
                prev_cert.signature_hash_algorithm, prev_cert.signature_algorithm_oid
            )

        if root_cert is None:
            cert = trust_store.issuer_in_trust_store(prev_cert.issuer)
            if cert is None:
                raise CertValidationError(
                    f'anchor for certificate "{prev_cert}" not found in trust store'
                )
            validate_signature(
                cert, sig_scheme, prev_cert.tbs_certificate_bytes, prev_cert.signature
            )
        else:
            if not trust_store.cert_in_trust_store(prev_cert):
                raise CertValidationError(
                    f'root certificate "{root_cert}" not found in trust store'
                )
