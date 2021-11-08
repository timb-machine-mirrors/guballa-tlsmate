# -*- coding: utf-8 -*-
"""Module defining some utilities related to certificates
"""

# import basic stuff
import stringprep
import unicodedata

# import own stuff
from tlsmate import tls

# import other stuff
from cryptography.x509.oid import SignatureAlgorithmOID as sigalg_oid
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes


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
    cert.parsed.public_key().verify(signature, bytes(data))


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
