# -*- coding: utf-8 -*-
"""Module containing the server profile class
"""
import abc
import logging
from collections import OrderedDict
from tlsmate import constants as tls
from tlsmate import structures as structs
from tlsmate import utils
from tlsmate import pdu
from tlsmate import mappings
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448, dsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509


class YamlBlockStyle(str):
    """Class used to indicate that a string shall be serialized using the block style.
    """

    pass


class ProfileObject(metaclass=abc.ABCMeta):
    """Abstract base class to derive profile classes from
    """

    def serialize(self):
        raise NotImplementedError


class ProfileBasic(ProfileObject):
    """Profile class for a simple object (!= lists, dicts)

    Arguments:
        value: the value of the simple object
    """

    def __init__(self, value):
        self.set(value)

    def serialize(self):
        """Serializes the object.

        Returns:
            type: the value of the object
        """
        return self._value

    def get(self):
        """Synonym for serialize.
        """
        return self._value

    def set(self, value):
        """Sets the object to a given value

        Arguments:
            value: The new value of the object
        """
        self._value = value


class ProfileBytes(ProfileBasic):
    """Profile class for bytes object
    """

    def serialize(self):
        """Serializes the object.

        Returns:
            str: the value of the object
        """
        return pdu.string(self._value)


class ProfileDateTime(ProfileBasic):
    """Profile class for a datetime object
    """

    def serialize(self):
        """Serializes the object.

        Returns:
            str: the value of the object
        """
        return self._value.isoformat()


class ProfileBasicEnum(ProfileBasic):
    """Class for a Enum object, which will be represented by its name
    """

    def serialize(self):
        """Serializes the name of the enum.

        Returns:
            str: the enum's name
        """
        return self._value.name


class ProfileDict(ProfileObject):
    """Class representing a dict.

    All entries in the dict must have the type :class:`ProfileObject`.
    """

    def __init__(self):
        self._dict = {}

    def add(self, name, obj, keep_existing=False):
        """Add an object to the dict.

        Arguments:
            name (str): the name for the dict key
            obj: the object/value for the new dict entry
            keep_existing (bool): An indication, if an existing entry shall be replaced
                or not. Default is False.

        Raises:
            TypeError: if the object is not a :class:`ProfileObject`
            ValueError: if the entry is already present and keep_existing is False
        """
        if obj is None:
            # it is more a documentational feature than a functional one
            return
        if not isinstance(obj, ProfileObject):
            raise TypeError("only ProfileObject can be added to a profile object")
        if name in self._dict:
            if keep_existing:
                return
            raise ValueError(f"cannot use the same name {name} twice in the profile")
        self._dict[name] = obj

    def serialize(self):
        """Serializes the object

        Returns:
            dict: the serialized object
        """
        obj = {}
        for key, prof_obj in self._dict.items():
            val = prof_obj.serialize()
            if val is not None:
                obj[key] = val
        return obj

    def get(self, name):
        """Return the value for a given key

        Arguments:
            name (str): the key

        Returns:
            type: the value, of None if the key is not present
        """
        return self._dict.get(name)


class ProfileEnum(ProfileDict):
    """Class for an Enum.

    Difference to "ProfileBasicEnum": It is a dict containing the id and the name.
    """

    def __init__(self, enum):
        super().__init__()
        self.add("name", ProfileBasic(enum.name))
        self.add("id", ProfileBasic(enum.value))
        self._enum = enum

    def get_enum(self):
        """Return the enum

        Return:
            (type): the enum
        """
        return self._enum

    def set(self, value):
        """Set the enum

        Arguments:
            value: the enum
        """
        self._value = value


class ProfileList(ProfileObject):
    """Class for a list. The items within the list must be unique.

    Note, that each item in the list must have an identifier, thus it is rather
    similiar to a dict (indeed, internally a dict is used to store the values).
    The main difference is, when it comes to serialization, here a list is returned.
    """

    def __init__(self, key_func):
        self._dict = OrderedDict()
        self._key_func = key_func

    def serialize(self):
        """Serialize the list

        Returns:
            list: the list
        """
        return [item.serialize() for item in self._dict.values()]

    def append(self, obj, keep_existing=False):
        """Appends an item to the list

        Arguments:
            obj: the item to append
            keep_existing (bool): An indication, if an existing entry shall be replaced
                or not. Default is False.

        Raises:
            TypeError: if the object is not a :class:`ProfileObject`
            ValueError: if the entry is already present and keep_existing is False
        """
        if not isinstance(obj, ProfileObject):
            raise TypeError("only ProfileObject can be added to a profile list")
        key = self._key_func(obj)
        if key in self._dict:
            if keep_existing:
                return
            raise ValueError(f"element {key} already present in profile list")
        self._dict[key] = obj

    def key(self, key):
        """Get the item for a given key.

        Arguments:
            key: the key to retrieve

        Returns:
            type: the object of the list
        """
        return self._dict.get(key)

    def all(self):
        """Returns all keys.

        Returns:
            list: a list of all keys
        """
        return list(self._dict.keys())


class ProfileSimpleList(ProfileObject):
    """Class for a list.
    """

    def __init__(self):
        self._list = []

    def append(self, item):
        self._list.append(item)

    def serialize(self):
        return [item.serialize() for item in self._list]


class SPSignatureAlgorithms(ProfileDict):
    """Class to represent the SignatureAlgorithms in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("server_preference", ProfileBasicEnum(tls.SPBool.C_NA))
        self.add("algorithms", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("info", None)


class SPSupportedGroups(ProfileDict):
    """Class to represent the SupportedGroups in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("extension_supported", ProfileBasicEnum(tls.SPBool.C_UNDETERMINED))
        self.add("groups", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("groups_advertised", None)
        self.add("extension_supported", None)


class SPFeatures(ProfileDict):
    """Class to represent the features/procedures in the server profile.
    """

    def __init__(self):
        super().__init__()
        self.add("compression", None)
        self.add("encrypt_then_mac", None)


class SPVersions(ProfileDict):
    """Class to represent the TLS versions in the server profile.
    """

    def __init__(self, version, server_pref):
        super().__init__()
        self.add("version", ProfileEnum(version))
        self.add("server_preference", ProfileBasicEnum(server_pref))
        self.add("cipher_suites", ProfileList(key_func=lambda x: x.get_enum()))
        self.add("supported_groups", SPSupportedGroups())
        self.add("signature_algorithms", None)


class SPCertificateKey(ProfileDict):
    """Class for the certificate's public key.

    Arguments:
        public_key (type): One of RSAPublicKey, DSAPublicKey, EllipticCurvePublicKey,
            Ed25519PublicKey or Ed448PublicKey
    """

    def __init__(self, public_key):
        super().__init__()
        if isinstance(public_key, rsa.RSAPublicKey):
            self._add_rsa_public_key(public_key)
            algo = tls.SignatureAlgorithm.RSA
        elif isinstance(public_key, dsa.DSAPublicKey):
            self._add_dsa_public_key(public_key)
            algo = tls.SignatureAlgorithm.DSA
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self._add_ec_public_key(public_key)
            algo = tls.SignatureAlgorithm.ECDSA
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self._add_ed_public_key(public_key)
            algo = tls.SignatureAlgorithm.ED25519
        elif isinstance(public_key, ed448.Ed448PublicKey):
            self._add_ed_public_key(public_key)
            algo = tls.SignatureAlgorithm.ED448
        else:
            raise ValueError("public key not supported")
        self.add("key_type", ProfileBasicEnum(algo))

    def _add_rsa_public_key(self, public_key):
        self.add("key_size", ProfileBasic(public_key.key_size))
        pub_numbers = public_key.public_numbers()
        self.add("key_exponent", ProfileBasic(pub_numbers.e))
        modulus = pub_numbers.n.to_bytes(int(public_key.key_size / 8), "big")
        self.add("key", ProfileBytes(modulus))

    def _add_dsa_public_key(self, public_key):
        self.add("key_size", ProfileBasic(public_key.key_size))
        pub_numbers = public_key.public_numbers()
        modulus = pub_numbers.y.to_bytes(int(public_key.key_size / 8), "big")
        self.add("key", ProfileBytes(modulus))

        p_bytes = utils.int_to_bytes(pub_numbers.parameter_numbers.p)
        self.add("key_p", ProfileBytes(p_bytes))

        q_bytes = utils.int_to_bytes(pub_numbers.parameter_numbers.q)
        self.add("key_q", ProfileBytes(q_bytes))

        g_bytes = utils.int_to_bytes(pub_numbers.parameter_numbers.g)
        self.add("key_g", ProfileBytes(g_bytes))

    def _add_ec_public_key(self, public_key):
        self.add("key_size", ProfileBasic(public_key.key_size))
        group = mappings.curve_to_group.get(public_key.curve.name)
        if group is None:
            raise ValueError("curve {public_key.curve.name} unknown")
        self.add("curve", ProfileBasicEnum(group))

        key = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.add("key", ProfileBytes(key))

    def _add_ed_public_key(self, public_key):
        key = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.add("key", ProfileBytes(key))

    def _add_public_key(self, public_key):
        if isinstance(public_key, rsa.RSAPublicKey):
            self._add_rsa_public_key(public_key)
            algo = tls.SignatureAlgorithm.RSA
        elif isinstance(public_key, dsa.DSAPublicKey):
            self._add_dsa_public_key(public_key)
            algo = tls.SignatureAlgorithm.DSA
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self._add_ec_public_key(public_key)
            algo = tls.SignatureAlgorithm.ECDSA
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self._add_ed_public_key(public_key)
            algo = tls.SignatureAlgorithm.ED25519
        elif isinstance(public_key, ed448.Ed448PublicKey):
            self._add_ed_public_key(public_key)
            algo = tls.SignatureAlgorithm.ED448
        else:
            raise ValueError("public key not supported")
        self.add("key_type", ProfileBasicEnum(algo))


class SPCertNoticeReference(ProfileDict):
    """Notice Reference
    """

    def __init__(self, notice):
        super().__init__()
        self.add("organization", ProfileBasic(notice.organization))
        numbers = ProfileList(key_func=lambda x: x.get())
        self.add("notice_numbers", numbers)
        for number in notice.notice_numbers:
            numbers.append(ProfileBasic(number))


class SPCertUserNotice(ProfileDict):
    """User Notice
    """

    def __init__(self, user_notice):
        super().__init__()
        if isinstance(user_notice, x509.UserNotice):
            self.add("notice_reference", SPCertNoticeReference(user_notice))
        else:
            self.add("text", ProfileBasic(user_notice))


class SPCertPolicyInfo(ProfileDict):
    """Policy information
    """

    def __init__(self, policy):
        super().__init__()
        self.add("policy_name", ProfileBasic(policy.policy_identifier._name))
        self.add("policy_oid", ProfileBasic(policy.policy_identifier.dotted_string))
        if policy.policy_qualifiers is not None:
            qualifiers = ProfileSimpleList()
            self.add("policy_qualifiers", qualifiers)

            for user_notice in policy.policy_qualifiers:
                qualifiers.append(SPCertUserNotice(user_notice))


class SPCertAccessDescription(ProfileDict):
    """Access Description
    """

    def __init__(self, acc_descr):
        super().__init__()
        self.add("access_method", ProfileBasic(acc_descr.access_method._name))
        self.add("access_location", ProfileBasic(acc_descr.access_location.value))


class SPCertSignedTimestamp(ProfileDict):
    """Signed Certificate Timestamp
    """

    def __init__(self, signed_timestamp):
        super().__init__()
        self.add("version", ProfileBasicEnum(signed_timestamp.version))
        self.add("log_id", ProfileBytes(signed_timestamp.log_id))
        self.add("timestamp", ProfileDateTime(signed_timestamp.timestamp))
        self.add("entry_type", ProfileBasicEnum(signed_timestamp.entry_type))


class SPCertGeneralName(ProfileDict):
    """General Name
    """

    def __init__(self, name):
        super().__init__()
        if isinstance(name, x509.DirectoryName):
            self.add("value", ProfileBasic(name.value.rfc4514_string()))
        elif isinstance(name, x509.RegisteredID):
            self.add("oid", ProfileBasic(name.value.dotted_string))
            if name.value._name is not None:
                self.add("name", ProfileBasic(name.value._name))
        elif isinstance(name, x509.OtherName):
            self.add("bytes", ProfileBytes(name.value))
            self.add("oid", ProfileBasic(name.type_id.dotted_string))
            if name.type_id._name is not None:
                self.add("name", ProfileBasic(name.name.type_id._name._name))
        else:
            self.add("value", ProfileBasic(name.value))

class SPCertExtension(ProfileDict):
    """Certificate extension
    """

    def __init__(self, ext):
        super().__init__()
        self.add("oid", ProfileBasic(ext.oid.dotted_string))
        if not isinstance(ext.value, x509.UnrecognizedExtension):
            self.add("name", ProfileBasic(ext.oid._name))
        self.add("criticality", ProfileBasicEnum(tls.SPBool(ext.critical)))
        func = self._map_ext.get(type(ext.value))
        if func is None:
            pass
        else:
            func(self, ext.value)

    def _ext_key_usage(self, value):
        key_usage = ProfileList(key_func=lambda x: x.get())
        self.add("key_usage", key_usage)

        if value.digital_signature:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.DIGITAL_SIGNATURE))
        if value.content_commitment:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.CONTENT_COMMITMENT))
        if value.key_encipherment:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.KEY_ENCIPHERMENT))
        if value.data_encipherment:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.DATA_ENCIPHERMENT))
        if value.key_agreement:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.KEY_AGREEMENT))
            if value.encipher_only:
                key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.ENCIPHER_ONLY))
            if value.decipher_only:
                key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.DECIPHER_ONLY))
        if value.key_cert_sign:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.KEY_CERT_SIGN))
        if value.crl_sign:
            key_usage.append(ProfileBasicEnum(tls.CertKeyUsage.CRL_SIGN))

    def _ext_basic_constraints(self, value):
        self.add("ca", ProfileBasicEnum(tls.SPBool(value.ca)))
        if value.path_length is not None:
            self.add("path_length", ProfileBasic(value.path_length))

    def _ext_extended_key_usage(self, value):
        key_usage = ProfileList(key_func=lambda x: x.get())
        self.add("extended_key_usage", key_usage)

        for usage in value:
            key_usage.append(ProfileBasic(usage._name))

    def _ext_ocsp_no_check(self, value):
        logging.error("Certificate extensions OcspNoCheck not implemented")

    def _ext_tls_features(self, value):
        features = ProfileList(key_func=lambda x: x.get())
        self.add("tls_features", features)

        for feature in value:
            features.append(ProfileBasicEnum(tls.Extension(feature.value)))

    def _ext_name_constraints(self, value):
        logging.error("Certificate extensions NameContraints not implemented")

    def _ext_authority_key_id(self, value):
        self.add("key_identifier", ProfileBytes(value.key_identifier))
        if value.authority_cert_issuer is not None:
            general_names = ProfileSimpleList()
            self.add("authority_cert_issuer", general_names)

            for gen_name in value.authority_cert_issuer:
                general_names.append(SPCertGeneralName(gen_name))
        if value.authority_cert_serial_number is not None:
            self.add(
                "authority_cert_serial_number",
                ProfileBasic(value.authority_cert_serial_number),
            )

    def _ext_subjec_key_id(self, value):
        self.add("digest", ProfileBytes(value.digest))

    def _ext_subj_alt_name(self, value):
        subj_alt_names = ProfileSimpleList()
        self.add("subject_alternate_names", subj_alt_names)

        for subj_alt_name in value:
            subj_alt_names.append(ProfileBasic(subj_alt_name.value))

    def _ext_issuer_alt_name(self, value):
        logging.error("Certificate extensions IssuerAltName not implemented")

    def _ext_precert_signed_cert_timestamps(self, value):
        signed_timestamps = ProfileSimpleList()
        self.add("signed_certificate_timestamps", signed_timestamps)

        for timestamp in value:
            signed_timestamps.append(SPCertSignedTimestamp(timestamp))

    def _ext_precert_poison(self, value):
        logging.error("Certificate extensions PreCertPoison not implemented")

    def _ext_signed_cert_timestamps(self, value):
        logging.error("Certificate extensions SignedCertTimestamp not implemented")

    def _ext_delta_clr_indicator(self, value):
        logging.error("Certificate extensions DeltaClrIndicator not implemented")

    def _ext_authority_info_access(self, value):
        access_descriptions = ProfileSimpleList()
        self.add("authority_info_access", access_descriptions)

        for descr in value:
            access_descriptions.append(SPCertAccessDescription(descr))

    def _ext_subject_info_access(self, value):
        logging.error("Certificate extensions SubjectInfoAccess not implemented")

    def _ext_freshest_crl(self, value):
        logging.error("Certificate extensions FreshestCrl not implemented")

    def _ext_crl_distribution_points(self, value):
        distr_points = ProfileSimpleList()
        self.add("distribution_points", distr_points)

        for distr_point in value:
            point = ProfileDict()
            distr_points.append(point)
            if distr_point.full_name is not None:
                full_names = ProfileSimpleList()
                point.add("full_name", full_names)
                for name in distr_point.full_name:
                    full_names.append(ProfileBasic(name.value))

            if distr_point.relative_name is not None:
                logging.error(
                    "Certificate extensions CrlDistrPoints: relative name "
                    "not implemented"
                )
            if distr_point.crl_issuer is not None:
                logging.error(
                    "Certificate extensions CrlDistrPoints: crl_issuer not implemented"
                )
            if distr_point.reasons is not None:
                logging.error(
                    "Certificate extensions CrlDistrPoints: reasons not implemented"
                )

    def _ext_inhibit_any_policy(self, value):
        logging.error("Certificate extensions InhibitAnyPolicy not implemented")

    def _ext_policy_constraints(self, value):
        logging.error("Certificate extensions PolicyConstraints not implemented")

    def _ext_crl_number(self, value):
        logging.error("Certificate extensions CrlNumber not implemented")

    def _ext_issuing_dist_point(self, value):
        logging.error("Certificate extensions IssuingDistPoint not implemented")

    def _ext_unrecognized_extension(self, value):
        self.add("bytes", ProfileBytes(value.value))

    def _ext_cert_issuer(self, value):
        logging.error("Certificate extensions CertIssuer not implemented")

    def _ext_crl_reason(self, value):
        logging.error("Certificate extensions CrlReason not implemented")

    def _ext_invalidity_date(self, value):
        logging.error("Certificate extensions InvalidityDate not implemented")

    def _ext_ocsp_nonce(self, value):
        logging.error("Certificate extensions OcspNonce not implemented")

    def _ext_cert_policies(self, value):
        cert_policies = ProfileSimpleList()
        self.add("certificate_policies", cert_policies)

        for policy in value:
            cert_policies.append(SPCertPolicyInfo(policy))

    _map_ext = {
        x509.extensions.KeyUsage: _ext_key_usage,
        x509.extensions.BasicConstraints: _ext_basic_constraints,
        x509.extensions.ExtendedKeyUsage: _ext_extended_key_usage,
        x509.extensions.OCSPNoCheck: _ext_ocsp_no_check,
        x509.extensions.TLSFeature: _ext_tls_features,
        x509.extensions.NameConstraints: _ext_name_constraints,
        x509.extensions.AuthorityKeyIdentifier: _ext_authority_key_id,
        x509.extensions.SubjectKeyIdentifier: _ext_subjec_key_id,
        x509.extensions.SubjectAlternativeName: _ext_subj_alt_name,
        x509.extensions.IssuerAlternativeName: _ext_issuer_alt_name,
        x509.extensions.PrecertificateSignedCertificateTimestamps: (
            _ext_precert_signed_cert_timestamps
        ),
        x509.extensions.PrecertPoison: _ext_precert_poison,
        x509.extensions.SignedCertificateTimestamps: _ext_signed_cert_timestamps,
        x509.extensions.DeltaCRLIndicator: _ext_delta_clr_indicator,
        x509.extensions.AuthorityInformationAccess: _ext_authority_info_access,
        x509.extensions.SubjectInformationAccess: _ext_subject_info_access,
        x509.extensions.FreshestCRL: _ext_freshest_crl,
        x509.extensions.CRLDistributionPoints: _ext_crl_distribution_points,
        x509.extensions.InhibitAnyPolicy: _ext_inhibit_any_policy,
        x509.extensions.PolicyConstraints: _ext_policy_constraints,
        x509.extensions.CRLNumber: _ext_crl_number,
        x509.extensions.IssuingDistributionPoint: _ext_issuing_dist_point,
        x509.extensions.UnrecognizedExtension: _ext_unrecognized_extension,
        x509.extensions.CertificatePolicies: _ext_cert_policies,
        x509.extensions.CertificateIssuer: _ext_cert_issuer,
        x509.extensions.CRLReason: _ext_crl_reason,
        x509.extensions.InvalidityDate: _ext_invalidity_date,
        x509.extensions.OCSPNonce: _ext_ocsp_nonce,
    }


class SPCertificate(ProfileDict):
    """Class to represent a certificate

    Arguments:
        cert (:obj:`tlsmate.cert.Certificate): the certificate object
    """

    def __init__(self, cert):
        super().__init__()
        self.add("pem", ProfileBasic(YamlBlockStyle(cert.pem.decode())))
        self.add("subject", ProfileBasic(cert.subject_str))
        self.add("issuer", ProfileBasic(cert.parsed.issuer.rfc4514_string()))
        self.add("version", ProfileBasicEnum(cert.parsed.version))
        self.add("serial_number_int", ProfileBasic(cert.parsed.serial_number))
        ser_bytes = utils.int_to_bytes(cert.parsed.serial_number)
        self.add("serial_number_bytes", ProfileBytes(ser_bytes))
        self.add("signature", ProfileBytes(cert.parsed.signature))

        self.add("not_valid_before", ProfileDateTime(cert.parsed.not_valid_before))
        self.add("not_valid_after", ProfileDateTime(cert.parsed.not_valid_after))
        diff = cert.parsed.not_valid_after - cert.parsed.not_valid_before
        self.add("validity_period_days", ProfileBasic(diff.days))

        self_signed = tls.SPBool.C_TRUE if cert.self_signed else tls.SPBool.C_FALSE
        self.add("self_signed", ProfileBasicEnum(self_signed))
        if cert.subject_matches is not None:
            match = tls.SPBool.C_TRUE if cert.subject_matches else tls.SPBool.C_FALSE
            self.add("subject_matches", ProfileBasicEnum(match))
        self.add("fingerprint_sha1", ProfileBasic(cert.fingerprint_sha1))
        self.add("fingerprint_sha256", ProfileBasic(cert.fingerprint_sha256))
        self.add("signature_algorithm", ProfileBasicEnum(cert.signature_algorithm))
        self.add("public_key", SPCertificateKey(cert.parsed.public_key()))

        extensions = cert.parsed.extensions
        if len(extensions):
            ext_list = ProfileList(key_func=lambda x: x.get("oid"))
            self.add("extensions", ext_list)
            for ext in extensions:
                ext_list.append(SPCertExtension(ext))


class SPCertificateChain(ProfileDict):
    """Class to represent a certificate chain in the server profile.
    """

    def __init__(self, chain, idx):
        super().__init__()
        self.add("id", ProfileBasic(idx))
        vali = tls.SPBool.C_TRUE if chain.successful_validation else tls.SPBool.C_FALSE
        self.add("successful_validation", ProfileBasicEnum(vali))
        cert_list = ProfileList(key_func=lambda x: x.get("subject"))
        self.add("cert_chain", cert_list)
        for cert in chain.certificates:
            cert_list.append(SPCertificate(cert))
        if chain.issues:
            issue_list = ProfileList(key_func=lambda x: x.get())
            self.add("issues", issue_list)
            for issue in chain.issues:
                issue_list.append(ProfileBasic(issue))
        trans = tls.SPBool.C_TRUE if chain.root_cert_transmitted else tls.SPBool.C_FALSE
        self.add("root_certificate_transmitted", ProfileBasicEnum(trans))
        if chain.root_cert is not None:
            self.add("root_certificate", SPCertificate(chain.root_cert))


class SPCertificateChainList(ProfileList):
    """Class to represent a list of certificate chains in the server profile.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hash = {}

    def append_unique(self, chain):
        """Append a chain only, if not yet present.

        Arguments:
            chain (bytes): the chain to add

        Returns:
            int: the index of the chain, which may be created newly, or it might have
                been present already.
        """
        if chain.digest in self._hash:
            return self._hash[chain.digest]
        idx = len(self._hash) + 1
        self._hash[chain.digest] = idx
        self.append(SPCertificateChain(chain, idx))
        return idx


class ServerProfile(ProfileDict):
    """Class for the base (root) server profile object.
    """

    def __init__(self):
        super().__init__()
        self.add(
            "versions", ProfileList(key_func=lambda x: x.get("version").get_enum())
        )
        self.add("cert_chain", SPCertificateChainList(key_func=lambda x: x.get("id")))
        self.add("features", SPFeatures())

    def get_supported_groups(self, version):
        """Get all supported groups for a given TLS version.

        Arguments:
            version (:class:`tlsmate.constants.Version`): the TLS version to use

        Returns:
            list: a list of all supported groups supported by the server for the given
                TLS version.
        """
        prof_version = self.get("versions").key(version)
        return prof_version.get("supported_groups").get("groups").all()

    def get_signature_algorithms(self, version):
        """Get all signature algorithms for a given TLS version.

        Arguments:
            version (:class:`tlsmate.constants.Version`): the TLS version to use

        Returns:
            list: a list of all signature algorithms supported by the server for the
                given TLS version.
        """
        prof_version = self.get("versions").key(version)
        sig_algs = prof_version.get("signature_algorithms")
        if sig_algs is None:
            return []
        return sig_algs.get("algorithms").all()

    def get_versions(self):
        """Get the supported TLS versions from the profile.

        Returns:
            list of :class:`tlsmate.constants.Version`: all TLS versions supported
                by the server
        """
        return self.get("versions").all()

    def get_cipher_suites(self, version):
        """Get the supported cipher suites from the profile for a given TLS version.

        Returns:
            list of :class:`tlsmate.constants.CipherSuite`: all cipher suites supported
                by the server for the given TLS version
        """
        prof_version = self.get("versions").key(version)
        return prof_version.get("cipher_suites").all()

    def get_profile_values(self, filter_versions, full_hs=False):
        """Get a set of some common attributes for the given TLS version(s).

        Arguments:
            filter_versions (list of :class:`tlsmate.constants.Version`): the list of
                TLS versions to retrieve the data for
            full_hs (bool): an indication if only those cipher suites shall be returned
                for which a full handshake is supported. Defaults to False.

        Returns:
            :obj:`tlsmate.structures.ProfileValues`: a structure that provides a list of
                the versions, the cipher suites, the supported groups and the
                signature algorithms
        """
        versions = []
        cipher_suites = set()
        sig_algos = set()
        groups = set()
        for version in self.get_versions():
            if version not in filter_versions:
                continue
            versions.append(version)
            cipher_suites = cipher_suites.union(set(self.get_cipher_suites(version)))
            sig_algos = sig_algos.union(set(self.get_signature_algorithms(version)))
            groups = groups.union(set(self.get_supported_groups(version)))
        if full_hs:
            cipher_suites = utils.filter_cipher_suites(cipher_suites, full_hs=True)
        return structs.ProfileValues(
            versions=versions,
            cipher_suites=cipher_suites,
            supported_groups=list(groups),
            signature_algorithms=list(sig_algos),
        )
