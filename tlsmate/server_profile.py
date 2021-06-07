# -*- coding: utf-8 -*-
"""Module containing the server profile class

The class :class:`ServerProfile` is the base for storing TLS server scan results.
A basic work flow for a server scan is as follows:

* The server profile is initialized and contains no data at the beginning.

* The scan is started, and the workers do their job. They are storing their
  results in the server profile. For example, first the supported TLS versions
  are determined together with the supported cipher suites. Next, the workers
  scan for the supported groups and the supported signature algorithms.

* At this point in time the server profile can be read by subsequent workers. E.g.,
  DH-parameters are only checked, if the server profile contains cipher suites
  using the DH key exchange. The DH-scanner worker will use the corresponding
  TLS versions, cipher suites and other parameters, knowing that they are all
  supported by the server. Then the worker will store its results in the server
  profile as well.

* After the scan is finished, the server profile can either be stored in a JSON/YAML
  file, or an extract from the server profile can be displayed on the screen (by a
  dedicated worker).

The server profile can also be used as a base for customized test cases: if a
scan has been executed against the target and the server profile has been serialized
to a file, then this server profile can be deserialized, and thus the test case can
use the data from it to evaluate if the feature to be tested is supported by the
target, and if so, the server profile values can be used to initiate connection to
the target with parameters known to be supported. This is exactly what the provided
workers do.

The YAML/JSON schema of a serialized server profile is described by the class
:class:`ServerProfileSchema` (and its nested schema classes). Look at the code
if you want to see the detailed structure.
"""
# import basic stuff
import abc
import logging

# import own stuff
from tlsmate import tls
from tlsmate import utils
from tlsmate import pdu
from tlsmate import mappings
from tlsmate import structs

# import other stuff
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448, dsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509
from marshmallow import fields, Schema, post_load, post_dump, pre_dump, INCLUDE
from marshmallow_oneofschema import OneOfSchema

# #### Helper classes


class _YamlBlockStyle(str):
    """Class used to indicate that a string shall be serialized using the block style.
    """


def _literal_presenter(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_YamlBlockStyle, _literal_presenter)


class FieldsEnumString(fields.String):
    """Adapted marshmallow field for ExtendedEnums.

    An extended enum is serialized to a string field, containing the name of the enum.

    Example:
        ::

            In the schema class:
                field = FieldsEnumString(enum_class=tls.Version)

            In the data object:
                obj.field = tls.Version.TLS10

            Serialized:
                "field": "TLS10"

    Arguments:
        enum_class(:class:`tls.ExtendedEnum`): The enum class used for deserialization.
            This argument is mandatory.
    """

    default_error_messages = fields.String.default_error_messages
    default_error_messages.update({"not_in_enum": "String not defined in enum"})

    def __init__(self, enum_class, **kwargs):
        if enum_class is None:
            raise ValueError("FieldsEnumString: enum_class not given")

        if not issubclass(enum_class, tls.ExtendedEnum):
            raise ValueError("FieldsEnumString: class must be ExtendedEnum")

        self.enum_class = enum_class
        super().__init__(**kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, self.enum_class):
            return None

        return super()._serialize(value.name, attr, obj, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):
        ret = self.enum_class.str2enum(value)
        if ret is None:
            raise self.make_error("not_in_enum")

        return ret


class FieldsBytes(fields.String):
    """Adapted marshmallow field for bytes.

    A bytes object will be serialized to a string where the bytes are separated by
    a colon.

    Example:
        ::

            b"Hallo" will be serialized to "48:61:6c:6c:6f"
    """

    default_error_messages = fields.String.default_error_messages
    default_error_messages.update({"not_in_enum": "String not defined in enum"})

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, (bytes, bytearray)):
            return None

        return pdu.string(value)

    def _deserialize(self, value, attr, data, **kwargs):
        return bytes.fromhex(
            "".join([c for c in value if c in "0123456789abcdefABCDEF"])
        )


class FieldsBlockString(fields.String):
    """Adapted marshmallow field strings which shall be displayed in block style (yaml).
    """

    def _serialize(self, value, attr, obj, **kwargs):
        return _YamlBlockStyle(value)


class ProfileSchema(Schema):
    """Wrapper class for easier deserialization to objects
    """

    _augments = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = INCLUDE

    @post_load
    def deserialize(self, data, **kwargs):
        """Instantiate an object and define the properties according to the given dict.

        Arguments:
            data (dict): dict representing the properties of the object we need to
                deserialize.

        Returns:
            Deserialized data, either a newly instantiated object (if given by the
            __profile_class__ class property), or the original dict.
        """

        cls = getattr(self, "__profile_class__", None)
        if cls is None:
            return data

        cls_data = self._get_schema_data(data)
        obj = cls(data=cls_data)
        for base_cls, ext_cls in self._augments:
            if base_cls is self.__class__:
                cls_data = ext_cls._get_schema_data(data)
                ext_data = ext_cls().load(cls_data)
                for key, val in ext_data.items():
                    setattr(obj, key, val)

        if data:
            fields = ", ".join(data.keys())
            raise ValueError(
                f"fields not defined in schema {self.__class__.__name__}: {fields}"
            )

        return obj

    @post_dump(pass_original=True)
    def serialize(self, data, orig, **kwargs):
        """Deserialize properties not covered by the schema as well.

        Arguments:
            data (dict): the serialized data so far
            orig (object): the original object subject to serialization

        Returns:
            dict: the final dict representing the serialized object
        """

        for base_cls, ext_cls in self._augments:
            if base_cls is self.__class__:
                data.update(ext_cls().dump(orig))
        return data

    @classmethod
    def _get_schema_data(cls, data):
        cls_data = {}
        for key in cls._declared_fields.keys():
            if key in data:
                cls_data[key] = data[key]
                del data[key]
        return cls_data

    @staticmethod
    def augment(base_cls):
        """Decorator to register scheme extensions.

        Arguments:
            base_cls (:class:`ProfileSchema`): the schema class to extend

        Returns:
            the class used to extend the base_cls class
        """

        def inner(ext_cls):
            ProfileSchema._augments.append((base_cls, ext_cls))
            return ext_cls

        return inner


class ProfileEnumSchema(Schema):
    """Wrapper class for simpler (de)serialization of Enums.
    """

    id = fields.Integer()
    name = fields.String()

    @post_load
    def deserialize(self, data, **kwargs):
        return self.__profile_class__(data["id"])

    @pre_dump
    def serialize(self, obj, **kwargs):
        return {"id": obj.value, "name": obj.name}


class SPObject(metaclass=abc.ABCMeta):
    """Basic class for profile data, provides easy deserialization from dicts.

    Arguments:
        data(dict): a dictionary which is converted into object properties.
        obj: an object to initialize the instance from.
    """

    def __init__(self, data=None, **kwargs):
        if data is not None:
            self._init_from_dict(data)

        else:
            self._init_from_args(**kwargs)

    def _init_from_dict(self, data):
        for key, val in data.items():
            if val is not None:
                setattr(self, key, val)

    def _init_from_args(self, **kwargs):
        """Specific method to initialize the instance from an object
        """
        self._init_from_dict(kwargs)


# ### Classes used for the server profile


class SPScanInfo(SPObject):
    """Data class for scan infos.
    """


class SPScanInfoSchema(ProfileSchema):
    """Schema for scan infos.
    """

    __profile_class__ = SPScanInfo
    command = fields.String()
    run_time = fields.Float()
    start_date = fields.DateTime()
    start_timestamp = fields.Float()
    stop_date = fields.DateTime()
    stop_timestamp = fields.Float()
    version = fields.String()


class SPCompressionEnumSchema(ProfileEnumSchema):
    """Schema for compression method (enum)
    """

    __profile_class__ = tls.CompressionMethod


class SPGrease(SPObject):
    """Data class for GREASE
    """


class SPGreaseSchema(ProfileSchema):
    """Schema for GREASE
    """

    __profile_class__ = SPGrease
    version_tolerance = FieldsEnumString(enum_class=tls.SPBool)
    cipher_suite_tolerance = FieldsEnumString(enum_class=tls.SPBool)
    extension_tolerance = FieldsEnumString(enum_class=tls.SPBool)
    group_tolerance = FieldsEnumString(enum_class=tls.SPBool)
    sig_algo_tolerance = FieldsEnumString(enum_class=tls.SPBool)
    psk_mode_tolerance = FieldsEnumString(enum_class=tls.SPBool)


class SPFeatures(SPObject):
    """Data class for TLS features.
    """


class SPFeaturesSchema(ProfileSchema):
    """Schema for TLS features.
    """

    __profile_class__ = SPFeatures
    compression = fields.List(fields.Nested(SPCompressionEnumSchema))
    encrypt_then_mac = FieldsEnumString(enum_class=tls.SPBool)
    extended_master_secret = FieldsEnumString(enum_class=tls.SPBool)
    session_id = FieldsEnumString(enum_class=tls.SPBool)
    session_ticket = FieldsEnumString(enum_class=tls.SPBool)
    session_ticket_lifetime = fields.Integer()
    resumption_psk = FieldsEnumString(enum_class=tls.SPBool)
    early_data = FieldsEnumString(enum_class=tls.SPBool)
    psk_lifetime = fields.Integer()
    insecure_renegotiation = FieldsEnumString(enum_class=tls.SPBool)
    secure_renegotation = FieldsEnumString(enum_class=tls.SPBool)
    scsv_renegotiation = FieldsEnumString(enum_class=tls.SPBool)
    heartbeat = FieldsEnumString(enum_class=tls.SPHeartbeat)
    grease = fields.Nested(SPGreaseSchema)


class SPPublicKey(SPObject):
    """Data class for all types of public key
    """

    def _init_from_args(self, pub_key):
        self.key_size = pub_key.key_size

        if isinstance(pub_key, rsa.RSAPublicKey):
            self.key_type = tls.SignatureAlgorithm.RSA
            pub_numbers = pub_key.public_numbers()
            self.key_exponent = pub_numbers.e
            self.key = pub_numbers.n.to_bytes(int(pub_key.key_size / 8), "big")

        elif isinstance(pub_key, dsa.DSAPublicKey):
            self.key_type = tls.SignatureAlgorithm.DSA
            pub_numbers = pub_key.public_numbers()
            self.key = pub_numbers.y.to_bytes(int(pub_key.key_size / 8), "big")
            self.key_p = utils.int_to_bytes(pub_numbers.parameter_numbers.p)
            self.key_q = utils.int_to_bytes(pub_numbers.parameter_numbers.q)
            self.key_g = utils.int_to_bytes(pub_numbers.parameter_numbers.g)

        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            self.key_type = tls.SignatureAlgorithm.ECDSA
            group = mappings.curve_to_group.get(pub_key.curve.name)
            if group is None:
                raise ValueError("curve {pub_key.curve.name} unknown")
            self.curve = group
            self.key = pub_key.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )

        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            self.key_type = tls.SignatureAlgorithm.ED25519
            self.key = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        elif isinstance(pub_key, ed448.Ed448PublicKey):
            self.key_type = tls.SignatureAlgorithm.ED448
            self.key = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class SPPubKeyRsaSchema(ProfileSchema):
    """Schema for RSA public key.
    """

    __profile_class__ = SPPublicKey
    key_type = FieldsEnumString(enum_class=tls.SignatureAlgorithm)
    key = FieldsBytes()
    key_exponent = fields.Integer()
    key_size = fields.Integer()


class SPPubKeyDsaSchema(ProfileSchema):
    """Schema for DSA public key.
    """

    __profile_class__ = SPPublicKey
    key_type = FieldsEnumString(enum_class=tls.SignatureAlgorithm)
    key = FieldsBytes()
    key_p = FieldsBytes()
    key_q = FieldsBytes()
    key_g = FieldsBytes()


class SPPubKeyEcdsaSchema(ProfileSchema):
    """Schema for ECDSA public key.
    """

    __profile_class__ = SPPublicKey
    key_type = FieldsEnumString(enum_class=tls.SignatureAlgorithm)
    key = FieldsBytes()
    curve = FieldsEnumString(enum_class=tls.SupportedGroups)
    key_size = fields.Integer()


class SPPubKeyEdSchema(ProfileSchema):
    """Schema for ED25519 and ED448 public key
    """

    __profile_class__ = SPPublicKey
    key_type = FieldsEnumString(enum_class=tls.SignatureAlgorithm)
    key = FieldsBytes()


class SPPublicKeySchema(OneOfSchema):
    """Choice of public key types
    """

    type_field = "key_type"
    type_field_remove = False
    type_schemas = {
        "ECDSA": SPPubKeyEcdsaSchema,
        "RSA": SPPubKeyRsaSchema,
        "DSA": SPPubKeyDsaSchema,
        "ED25519": SPPubKeyEdSchema,
        "ED448": SPPubKeyEdSchema,
    }

    def get_obj_type(self, obj):
        return obj.key_type.name


class SPCertGeneralName(SPObject):
    """Data class for general name
    """

    def _init_from_args(self, name):
        if isinstance(name, x509.RFC822Name):
            self.rfc822_name = name.value

        elif isinstance(name, x509.DNSName):
            self.dns_name = name.value

        elif isinstance(name, x509.DirectoryName):
            self.directory_name = name.value.rfc4514_string()

        elif isinstance(name, x509.UniformResourceIdentifier):
            self.uri = name.value

        elif isinstance(name, x509.IPAddress):
            self.ip_address = name.value

        else:
            logging.error(f"certificate extension: general name {name} not supported")


class SPCertGeneralNameSchema(ProfileSchema):
    """Schema for general name
    """

    __profile_class__ = SPCertGeneralName
    rfc822_name = fields.String()
    dns_name = fields.String()
    directory_name = fields.String()
    uri = fields.String()
    ip_address = fields.String()
    registered_id = fields.String()


# TODO: implement other name
#    other_name = fields.Nested(SpCertOtherNameSchema)


class SPCertNoticeReference(SPObject):
    """Data class for notice reference
    """

    def _init_from_args(self, ref):
        self.organization = ref.organization
        self.notice_numbers = [number for number in ref.notice_numbers]


class SPCertNoticeReferenceSchema(ProfileSchema):
    """Schema for notice reference
    """

    __profile_class__ = SPCertNoticeReference
    organization = fields.String()
    notice_numbers = fields.List(fields.Integer())


class SPCertUserNotice(SPObject):
    """Data class for user notice
    """

    def _init_from_args(self, notice):
        if isinstance(notice, x509.UserNotice):
            self.explicit_text = notice.explicit_text
            if notice.notice_reference is not None:
                self.notice_reference = SPCertNoticeReference(
                    ref=notice.notice_reference
                )

        else:
            self.text = notice


class SPCertUserNoticeSchema(ProfileSchema):
    """Schema for user notice
    """

    __profile_class__ = SPCertUserNotice
    explicit_text = fields.String()
    notice_reference = fields.Nested(SPCertNoticeReferenceSchema)
    text = fields.String()


class SPDistrPoint(SPObject):
    """Data class for distribution point
    """

    def _init_from_args(self, point):
        if point.full_name is not None:
            self.full_name = [SPCertGeneralName(name=name) for name in point.full_name]

        if point.relative_name is not None:
            logging.error(
                "Certificate extensions CrlDistrPoints: relative name "
                "not implemented"
            )

        if point.crl_issuer is not None:
            logging.error(
                "Certificate extensions CrlDistrPoints: crl_issuer not implemented"
            )

        if point.reasons is not None:
            logging.error(
                "Certificate extensions CrlDistrPoints: reasons not implemented"
            )


class SPDistrPointSchema(ProfileSchema):
    """Schema for distribution point
    """

    __profile_class__ = SPDistrPoint
    full_name = fields.List(fields.Nested(SPCertGeneralNameSchema))


class SPCertPolicyInfo(SPObject):
    """Data class for policy info
    """

    def _init_from_args(self, policy):
        self.policy_name = policy.policy_identifier._name
        self.policy_oid = policy.policy_identifier.dotted_string
        if policy.policy_qualifiers is not None:
            self.policy_qualifiers = [
                SPCertUserNotice(notice=notice) for notice in policy.policy_qualifiers
            ]


class SPCertPolicyInfoSchema(ProfileSchema):
    """Schema for policy info
    """

    __profile_class__ = SPCertPolicyInfo
    policy_name = fields.String()
    policy_oid = fields.String()
    policy_qualifiers = fields.List(fields.Nested(SPCertUserNoticeSchema))


class SPCertAccessDescription(SPObject):
    """Data class for access description
    """

    def _init_from_args(self, descr):
        self.access_method = descr.access_method._name
        self.access_location = descr.access_location.value


class SPCertAccessDescriptionSchema(ProfileSchema):
    """Schema for access description
    """

    __profile_class__ = SPCertAccessDescription
    access_method = fields.String()
    access_location = fields.String()


class SPCertSignedTimestamp(SPObject):
    """Data class for signed certificate timestamp
    """

    def _init_from_args(self, timestamp):
        self.version = timestamp.version.name
        self.log_id = timestamp.log_id
        self.timestamp = timestamp.timestamp
        self.entry_type = timestamp.entry_type.name


class SPCertSignedTimestampSchema(ProfileSchema):
    """Schema for signed certificate timestamp
    """

    __profile_class__ = SPCertSignedTimestamp
    version = fields.String()
    log_id = FieldsBytes()
    timestamp = fields.DateTime()
    entry_type = fields.String()


class SPCertExtension(SPObject):
    """Data class for all extensions
    """

    def _ext_unrecognized_extension(self, value):
        self.bytes = value.value

    def _ext_key_usage(self, value):
        key_usage = []
        if value.digital_signature:
            key_usage.append(tls.CertKeyUsage.DIGITAL_SIGNATURE)

        if value.content_commitment:
            key_usage.append(tls.CertKeyUsage.CONTENT_COMMITMENT)

        if value.key_encipherment:
            key_usage.append(tls.CertKeyUsage.KEY_ENCIPHERMENT)

        if value.data_encipherment:
            key_usage.append(tls.CertKeyUsage.DATA_ENCIPHERMENT)

        if value.key_agreement:
            key_usage.append(tls.CertKeyUsage.KEY_AGREEMENT)
            if value.encipher_only:
                key_usage.append(tls.CertKeyUsage.ENCIPHER_ONLY)

            if value.decipher_only:
                key_usage.append(tls.CertKeyUsage.DECIPHER_ONLY)

        if value.key_cert_sign:
            key_usage.append(tls.CertKeyUsage.KEY_CERT_SIGN)

        if value.crl_sign:
            key_usage.append(tls.CertKeyUsage.CRL_SIGN)

        self.key_usage = key_usage

    def _ext_basic_constraints(self, value):
        self.ca = tls.SPBool(value.ca)
        if value.path_length is not None:
            self.path_length = value.path_length

    def _ext_extended_key_usage(self, value):
        self.extended_key_usage = [usage._name for usage in value]

    def _ext_subjec_key_id(self, value):
        self.digest = value.digest

    def _ext_ocsp_no_check(self, value):
        logging.error("Certificate extensions OcspNoCheck not implemented")

    def _ext_tls_features(self, value):
        self.tls_features = [tls.Extension(feature.value) for feature in value]

    def _ext_name_constraints(self, value):
        self.permitted_subtrees = [
            SPCertGeneralName(name=name) for name in value.permitted_subtrees
        ]
        self.excluded_subtrees = [
            SPCertGeneralName(name=name) for name in value.excluded_subtrees
        ]

    def _ext_authority_key_id(self, value):
        self.key_identifier = value.key_identifier
        if value.authority_cert_issuer is not None:
            self.authority_cert_issuer = [
                SPCertGeneralName(name=name) for name in value.authority_cert_issuer
            ]

        if value.authority_cert_serial_number is not None:
            self.authority_cert_serial_number = value.authority_cert_serial_number

    def _ext_subj_alt_name(self, value):
        self.subj_alt_names = [subj_alt_name.value for subj_alt_name in value]

    def _ext_issuer_alt_name(self, value):
        self.issuer_alt_name = [issuer_alt_name.value for issuer_alt_name in value]

    def _ext_precert_sign_cert_timestamps(self, value):
        self.signed_certificate_timestamps = [
            SPCertSignedTimestamp(timestamp=timestamp) for timestamp in value
        ]

    def _ext_precert_poison(self, value):
        logging.error("Certificate extensions PreCertPoison not implemented")

    def _ext_signed_cert_timestamps(self, value):
        logging.error("Certificate extensions SignedCertTimestamp not implemented")

    def _ext_delta_clr_indicator(self, value):
        logging.error("Certificate extensions DeltaClrIndicator not implemented")

    def _ext_authority_info_access(self, value):
        self.authority_info_access = [
            SPCertAccessDescription(descr=descr) for descr in value
        ]

    def _ext_subject_info_access(self, value):
        logging.error("Certificate extensions SubjectInfoAccess not implemented")

    def _ext_freshest_crl(self, value):
        logging.error("Certificate extensions FreshestCrl not implemented")

    def _ext_crl_distribution_points(self, value):
        self.distribution_points = [SPDistrPoint(point=point) for point in value]

    def _ext_inhibit_any_policy(self, value):
        logging.error("Certificate extensions InhibitAnyPolicy not implemented")

    def _ext_policy_constraints(self, value):
        if value.require_explicit_policy is not None:
            self.require_explicit_policy = value.require_explicit_policy

        if value.inhibit_policy_mapping is not None:
            self.inhibit_policy_mapping = value.inhibit_policy_mapping

    def _ext_crl_number(self, value):
        logging.error("Certificate extensions CrlNumber not implemented")

    def _ext_issuing_dist_point(self, value):
        logging.error("Certificate extensions IssuingDistPoint not implemented")

    def _ext_cert_policies(self, value):
        self.cert_policies = [SPCertPolicyInfo(policy=policy) for policy in value]

    def _ext_cert_issuer(self, value):
        raise NotImplementedError
        pass

    def _ext_crl_reason(self, value):
        logging.error("Certificate extensions CertIssuer not implemented")

    def _ext_invalidity_date(self, value):
        logging.error("Certificate extensions InvalidityDate not implemented")

    def _ext_ocsp_nonce(self, value):
        logging.error("Certificate extensions OcspNonce not implemented")

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
        x509.extensions.PrecertificateSignedCertificateTimestamps: _ext_precert_sign_cert_timestamps,  # noqa: E501
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

    def _init_from_args(self, ext):
        self.name = ext.value.__class__.__name__
        self.oid = ext.oid.dotted_string
        self.criticality = tls.SPBool(ext.critical)
        func = self._map_ext.get(type(ext.value))
        if func is not None:
            func(self, ext.value)


class SPCertExtUnrecognizedExtensionSchema(ProfileSchema):
    """Data class for unknown certificate extension
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    bytes = FieldsBytes()


class SPCertExtKeyUsageSchema(ProfileSchema):
    """Data class for certificate extension KeyUsage
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    key_usage = fields.List(FieldsEnumString(enum_class=tls.CertKeyUsage))


class SPCertExtBasicConstraintsSchema(ProfileSchema):
    """Data class for certificate extension BasicConstraints
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    ca = FieldsEnumString(enum_class=tls.SPBool)
    path_length = fields.Integer()


class SPCertExtExtendedKeyUsageSchema(ProfileSchema):
    """Data class for certificate extension ExtendedKeyUsage
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    extended_key_usage = fields.List(fields.String())


class SPCertExtOCSPNoCheckSchema(ProfileSchema):
    """Data class for certificate extension OCSPNoCheck
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtTLSFeatureSchema(ProfileSchema):
    """Data class for certificate extension TLSFeature
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    tls_features = fields.List(FieldsEnumString(enum_class=tls.Extension))


class SPCertExtNameConstraintsSchema(ProfileSchema):
    """Data class for certificate extension NameConstraints
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    permitted_subtrees = fields.List(fields.Nested(SPCertGeneralNameSchema))
    excluded_subtrees = fields.List(fields.Nested(SPCertGeneralNameSchema))


class SPCertExtAuthorityKeyIdentifierSchema(ProfileSchema):
    """Data class for certificate extension AuthorityKeyIdentifier
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    key_identifier = FieldsBytes()
    authority_cert_issuer = fields.List(fields.Nested(SPCertGeneralNameSchema))
    authority_cert_serial_number = fields.Integer()


class SPCertExtSubjectKeyIdentifierSchema(ProfileSchema):
    """Data class for certificate extension SubjectKeyIdentifier
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    digest = FieldsBytes()


class SPCertExtSubjectAlternativeNameSchema(ProfileSchema):
    """Data class for certificate extension SubjectAlternativeName
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    subj_alt_names = fields.List(fields.String())


class SPCertExtIssuerAlternativeNameSchema(ProfileSchema):
    """Data class for certificate extension IssuerAlternativeName
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    issuer_alt_name = fields.List(fields.String())


class SPCertExtPrecertSignedCertTimestampsSchema(ProfileSchema):
    """Data class for certificate extension ExtPrecertSignedCertTimestamps
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    signed_certificate_timestamps = fields.List(
        fields.Nested(SPCertSignedTimestampSchema)
    )


class SPCertExtPrecertPoisonSchema(ProfileSchema):
    """Data class for certificate extension PrecertPoison
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtSignedCertificateTimestampsSchema(ProfileSchema):
    """Data class for certificate extension SignedCertificateTimestamps
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    signed_certificate_timestamps = fields.List(
        fields.Nested(SPCertSignedTimestampSchema)
    )


class SPCertExtDeltaCRLIndicatorSchema(ProfileSchema):
    """Data class for certificate extension DeltaCRLIndicator
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtAuthorityInformationAccessSchema(ProfileSchema):
    """Data class for certificate extension AuthorityInformationAccess
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    authority_info_access = fields.List(fields.Nested(SPCertAccessDescriptionSchema))


class SPCertExtSubjectInformationAccessSchema(ProfileSchema):
    """Data class for certificate extension SubjectInformationAccess
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtFreshestCRLSchema(ProfileSchema):
    """Data class for certificate extension FreshestCRL
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtCRLDistributionPointsSchema(ProfileSchema):
    """Data class for certificate extension CRLDistributionPoints
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    distribution_points = fields.List(fields.Nested(SPDistrPointSchema))


class SPCertExtInhibitAnyPolicySchema(ProfileSchema):
    """Data class for certificate extension InhibitAnyPolicy
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtPolicyConstraintsSchema(ProfileSchema):
    """Data class for certificate extension PolicyConstraints
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    require_explicit_policy = fields.Integer()
    inhibit_policy_mapping = fields.Integer()


class SPCertExtCRLNumberSchema(ProfileSchema):
    """Data class for certificate extension CRLNumber
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtIssuingDistributionPointSchema(ProfileSchema):
    """Data class for certificate extension IssuingDistributionPoint
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtCertificatePoliciesSchema(ProfileSchema):
    """Data class for certificate extension CertificatePolicies
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)
    cert_policies = fields.List(fields.Nested(SPCertPolicyInfoSchema))


class SPCertExtCertificateIssuerSchema(ProfileSchema):
    """Data class for certificate extension CertificateIssuer
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtCRLReasonSchema(ProfileSchema):
    """Data class for certificate extension CRLReason
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtInvalidityDateSchema(ProfileSchema):
    """Data class for certificate extension InvalidityDate
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtOCSPNonceSchema(ProfileSchema):
    """Data class for certificate extension OCSPNonce
    """

    __profile_class__ = SPCertExtension
    name = fields.String()
    oid = fields.String()
    criticality = FieldsEnumString(enum_class=tls.SPBool)


class SPCertExtensionSchema(OneOfSchema):
    """Choice of certificate extensions
    """

    type_field = "name"
    type_field_remove = False
    type_schemas = {
        "KeyUsage": SPCertExtKeyUsageSchema,
        "UnrecognizedExtension": SPCertExtUnrecognizedExtensionSchema,
        "BasicConstraints": SPCertExtBasicConstraintsSchema,
        "ExtendedKeyUsage": SPCertExtExtendedKeyUsageSchema,
        "OCSPNoCheck": SPCertExtOCSPNoCheckSchema,
        "TLSFeature": SPCertExtTLSFeatureSchema,
        "NameConstraints": SPCertExtNameConstraintsSchema,
        "AuthorityKeyIdentifier": SPCertExtAuthorityKeyIdentifierSchema,
        "SubjectKeyIdentifier": SPCertExtSubjectKeyIdentifierSchema,
        "SubjectAlternativeName": SPCertExtSubjectAlternativeNameSchema,
        "IssuerAlternativeName": SPCertExtIssuerAlternativeNameSchema,
        "PrecertificateSignedCertificateTimestamps": SPCertExtPrecertSignedCertTimestampsSchema,  # noqa: E501
        "PrecertPoison": SPCertExtPrecertPoisonSchema,
        "SignedCertificateTimestamps": SPCertExtSignedCertificateTimestampsSchema,
        "DeltaCRLIndicator": SPCertExtDeltaCRLIndicatorSchema,
        "AuthorityInformationAccess": SPCertExtAuthorityInformationAccessSchema,
        "SubjectInformationAccess": SPCertExtSubjectInformationAccessSchema,
        "FreshestCRL": SPCertExtFreshestCRLSchema,
        "CRLDistributionPoints": SPCertExtCRLDistributionPointsSchema,
        "InhibitAnyPolicy": SPCertExtInhibitAnyPolicySchema,
        "PolicyConstraints": SPCertExtPolicyConstraintsSchema,
        "CRLNumber": SPCertExtCRLNumberSchema,
        "IssuingDistributionPoint": SPCertExtIssuingDistributionPointSchema,
        "CertificatePolicies": SPCertExtCertificatePoliciesSchema,
        "CertificateIssuer": SPCertExtCertificateIssuerSchema,
        "CRLReason": SPCertExtCRLReasonSchema,
        "InvalidityDate": SPCertExtInvalidityDateSchema,
        "OCSPNonce": SPCertExtOCSPNonceSchema,
    }

    def get_obj_type(self, obj):
        return obj.name


class SPCertificate(SPObject):
    """Data class for a certificate.
    """

    def _init_from_args(self, cert):
        self.pem = cert.pem.decode()
        self.subject = cert.subject_str
        self.issuer = cert.parsed.issuer.rfc4514_string()
        self.version = cert.parsed.version
        self.serial_number_int = cert.parsed.serial_number
        self.serial_number_bytes = utils.int_to_bytes(cert.parsed.serial_number)
        self.signature = cert.parsed.signature
        self.not_valid_before = cert.parsed.not_valid_before
        self.not_valid_after = cert.parsed.not_valid_after
        diff = cert.parsed.not_valid_after - cert.parsed.not_valid_before
        self.validity_period_days = diff.days
        self.self_signed = tls.SPBool(cert.self_signed)
        if cert.subject_matches is not None:
            self.subject_matches = tls.SPBool(cert.subject_matches)
        self.fingerprint_sha1 = cert.fingerprint_sha1
        self.fingerprint_sha256 = cert.fingerprint_sha256
        self.signature_algorithm = cert.signature_algorithm
        self.public_key = SPPublicKey(pub_key=cert.parsed.public_key())
        self.extensions = [SPCertExtension(ext=ext) for ext in cert.parsed.extensions]
        if cert.crl_status is not None:
            self.crl_revocation_status = cert.crl_status
        if cert.ocsp_status is not None:
            self.ocsp_revocation_status = cert.ocsp_status
        if cert.issues:
            self.issues = cert.issues


class SPCertificateSchema(ProfileSchema):
    """Schema for a certificate.
    """

    __profile_class__ = SPCertificate
    pem = FieldsBlockString()
    subject = fields.String()
    issuer = fields.String()
    version = fields.String()
    serial_number_int = fields.Integer()
    serial_number_bytes = FieldsBytes()
    signature = FieldsBytes()
    not_valid_before = fields.DateTime()
    not_valid_after = fields.DateTime()
    validity_period_days = fields.Integer()
    self_signed = FieldsEnumString(enum_class=tls.SPBool)
    subject_matches = FieldsEnumString(enum_class=tls.SPBool)
    fingerprint_sha1 = FieldsBytes()
    fingerprint_sha256 = FieldsBytes()
    signature_algorithm = FieldsEnumString(enum_class=tls.SignatureScheme)
    public_key = fields.Nested(SPPublicKeySchema)
    crl_revocation_status = FieldsEnumString(enum_class=tls.CertCrlStatus)
    ocsp_revocation_status = FieldsEnumString(enum_class=tls.OcspStatus)
    extensions = fields.List(fields.Nested(SPCertExtensionSchema))
    issues = fields.List(fields.String())


class SPCertChain(SPObject):
    """Data class for a certificate chain.
    """

    def _init_from_args(self, chain):
        self.id = chain.id
        self.successful_validation = tls.SPBool(chain.successful_validation)
        self.cert_chain = [SPCertificate(cert=cert) for cert in chain.certificates]
        if chain.issues:
            self.issues = chain.issues

        self.root_cert_transmitted = tls.SPBool(chain.root_cert_transmitted)
        if chain.root_cert is not None:
            self.root_certificate = SPCertificate(cert=chain.root_cert)


class SPCertChainSchema(ProfileSchema):
    """Schema for a certificate chain.
    """

    __profile_class__ = SPCertChain
    id = fields.Integer()
    successful_validation = FieldsEnumString(enum_class=tls.SPBool)
    cert_chain = fields.List(fields.Nested(SPCertificateSchema))
    issues = fields.List(fields.String())
    root_cert_transmitted = FieldsEnumString(enum_class=tls.SPBool)
    root_certificate = fields.Nested(SPCertificateSchema)


class SPVersionEnumSchema(ProfileEnumSchema):
    """Schema for a TLS version (enum).
    """

    __profile_class__ = tls.Version


class SPSupportedGroupEnumSchema(ProfileEnumSchema):
    """Schema for a supported group (enum).
    """

    __profile_class__ = tls.SupportedGroups


class SPSupportedGroups(SPObject):
    """Data class for supported groups.
    """


class SPSupportedGroupsSchema(ProfileSchema):
    """Data class for supported groups.
    """

    __profile_class__ = SPSupportedGroups
    extension_supported = FieldsEnumString(enum_class=tls.SPBool)
    server_preference = FieldsEnumString(enum_class=tls.SPBool)
    groups_advertised = FieldsEnumString(enum_class=tls.SPBool)
    groups = fields.List(fields.Nested(SPSupportedGroupEnumSchema))


class SPSigAlgoEnumSchema(ProfileEnumSchema):
    """Schema for signature algorithms (enum).
    """

    __profile_class__ = tls.SignatureScheme


class SPSignatureAlgorithms(SPObject):
    """Data class for signature algorithms
    """

    def _init_from_args(self):
        self.algorithms = []


class SPSignatureAlgorithmsSchema(ProfileSchema):
    """Schema for signature algorithms
    """

    __profile_class__ = SPSignatureAlgorithms
    algorithms = fields.List(fields.Nested(SPSigAlgoEnumSchema))
    info = fields.List(fields.String)


class SPCipherSuiteSchema(ProfileEnumSchema):
    """Schema for a cipher suite (enum).
    """

    __profile_class__ = tls.CipherSuite


class SPCiphers(SPObject):
    """Data class for ciphers
    """


class SPCiphersSchema(ProfileSchema):
    """Schema for ciphers
    """

    __profile_class__ = SPCiphers
    cipher_suites = fields.List(fields.Nested(SPCipherSuiteSchema))
    server_preference = FieldsEnumString(enum_class=tls.SPBool)


class SPCipherKindSchema(ProfileEnumSchema):
    """Schema for an SSL2 cipher kind (enum).
    """

    __profile_class__ = tls.SSLCipherKind


class SPDhGroup(SPObject):
    """Data class for DH groups
    """


class SPDhGroupSchema(ProfileSchema):
    """Schema for DH groups
    """

    __profile_class__ = SPDhGroup
    name = fields.String()
    size = fields.Integer()
    g_value = fields.Integer()
    p_value = FieldsBytes()


class SPNameResolution(SPObject):
    """Data class for name resolution infos
    """


class SPNameResolutionSchema(ProfileSchema):
    """Schema for name resolution infos
    """

    __profile_class__ = SPNameResolution
    domain_name = fields.String()
    ipv4_addresses = fields.List(fields.String())
    ipv6_addresses = fields.List(fields.String())


class SPServer(SPObject):
    """Data class for the servers' information
    """


class SPServerSchema(ProfileSchema):
    """Schema for the server's information
    """

    __profile_class__ = SPServer
    ip = fields.String()
    name_resolution = fields.Nested(SPNameResolutionSchema)
    port = fields.Integer()
    sni = fields.String()


class SPVersion(SPObject):
    """Data class for a dedicated TLS version.
    """


class SPVersionSchema(ProfileSchema):
    """Schema for a dedicated TLS version.
    """

    __profile_class__ = SPVersion
    cipher_kinds = fields.List(fields.Nested(SPCipherKindSchema))
    ciphers = fields.Nested(SPCiphersSchema)
    dh_group = fields.Nested(SPDhGroupSchema)
    supported_groups = fields.Nested(SPSupportedGroupsSchema)
    signature_algorithms = fields.Nested(SPSignatureAlgorithmsSchema)
    version = fields.Nested(SPVersionEnumSchema)


class SPVulnerabilities(SPObject):
    """Data class for vulnerabilities
    """


class SPVulnerabilitiesSchema(ProfileSchema):
    """Schema for vulnerabilities
    """

    __profile_class__ = SPVulnerabilities
    ccs_injection = FieldsEnumString(enum_class=tls.SPBool)
    heartbleed = FieldsEnumString(enum_class=tls.HeartbleedStatus)
    robot = FieldsEnumString(enum_class=tls.RobotVulnerability)


class ServerProfile(SPObject):
    """Data class for the server profile.

    Attributes:
        cert_chains (list :obj:`SPCertChain`): the list of certificate chains used
            by the server
        features (:obj:`SPFeatures`): the profile structure for the features supported
            by the server
        scan_info (:obj:`SPScanInfo`): object describing basic scan information
        server (:obj:`SPServer`): object describing the sercer's details
        versions (list of :obj:`SPVersion`): list versions supported by the server
        vulnerabilities (:obj:`SPVulnerabilities`): object containing infos regarding
            the vulnerabilities
    """

    def _init_from_args(self):
        self._hash = {}

        self.cert_chains = []
        self.features = SPFeatures()
        self.scan_info = SPScanInfo()
        self.server = SPServer()
        self.versions = []
        self.vulnerabilities = SPVulnerabilities()

    def append_unique_cert_chain(self, chain):
        """Append a certificate chain to the profile, if not yet present.

        Arguments:
            chain (:obj:`tlsmate.cert.CertChain`): the chain to be added

        Returns:
            int: the index of the chain, which may be created newly, or it might have
            been present already.
        """

        if chain.digest in self._hash:
            return self._hash[chain.digest]

        idx = len(self._hash) + 1
        self._hash[chain.digest] = idx
        chain.id = idx
        self.cert_chains.append(SPCertChain(chain=chain))

    def get_versions(self, exclude=None):
        """Get all TLS versions from the profile.

        Returns:
            list(:obj:`tlsmate.tls.Version`): A list of all supported versions.
        """

        if exclude is None:
            exclude = []

        return [obj.version for obj in self.versions if obj.version not in exclude]

    def get_version_profile(self, version):
        """Get the profile entry for a given version.

        Returns:
            :obj:`SPVersion`: the profile entry for the given version or None, if the
            version is not supported by the server.
        """

        for version_obj in self.versions:
            if version_obj.version is version:
                return version_obj

        return None

    def get_cipher_suites(self, version):
        """Get all cipher suites for a given TLS version.

        Arguments:
            version (:obj:`tlsmate.tls.Version`): The version for which to get
                the cipher suites for.

        Returns:
            list(:obj:`tlsmate.tls.Ciphersuite`): The list of cipher suites or None,
            if the version is not supported by the server.
        """

        version_prof = self.get_version_profile(version)
        if version_prof is not None:
            if version is tls.Version.SSL20:
                return version_prof.cipher_kinds

            else:
                return version_prof.ciphers.cipher_suites

        return None

    def get_supported_groups(self, version):
        """Get all supported groups for a given TLS version.

        Arguments:
            version (:class:`tlsmate.tls.Version`): the TLS version to use

        Returns:
            list: a list of all supported groups supported by the server for the given
            TLS version, or None if no supported groups are available.
        """

        version_prof = self.get_version_profile(version)
        try:
            return version_prof.supported_groups.groups

        except AttributeError:
            return None

    def get_signature_algorithms(self, version):
        """Get all signature algorithms for a given TLS version.

        Arguments:
            version (:class:`tlsmate.tls.Version`): the TLS version to use

        Returns:
            list: a list of all signature algorithms supported by the server for the
            given TLS version, or None if no signature algorithms are available.
        """

        version_prof = self.get_version_profile(version)
        if version_prof is not None and hasattr(version_prof, "signature_algorithms"):
            return version_prof.signature_algorithms.algorithms

        return None

    def get_cert_sig_algos(self, key_types=None):
        """Get all signature algorithms from the cert chains for the given key_types

        Arguments:
            key_types (list (:obj:`tlsmate.tls.SignatureAlgorithm`): the type of the
                public key required in the host certificate. Can be None to get
                all signature algorithms of all certs of all chains.

        Returns:
            list(:obj:`tlsmate.tls.SignatureScheme`): the list requested
        """
        sig_algos = []
        for chain in self.cert_chains:
            key_type = chain.cert_chain[0].public_key.key_type
            if key_types is None or key_type in key_types:
                for cert in chain.cert_chain:
                    if cert.signature_algorithm not in sig_algos:
                        sig_algos.append(cert.signature_algorithm)

                if hasattr(chain, "root_certificate"):
                    if chain.root_certificate.signature_algorithm not in sig_algos:
                        sig_algos.append(chain.root_certificate.signature_algorithm)

        return sig_algos

    def get_profile_values(self, filter_versions, full_hs=False):
        """Get a set of some common attributes for the given TLS version(s).

        Arguments:
            filter_versions (list of :class:`tlsmate.tls.Version`): the list of
                TLS versions to retrieve the data for
            full_hs (bool): an indication if only those cipher suites shall be returned
                for which a full handshake is supported. Defaults to False.

        Returns:
            :obj:`tlsmate.structs.ProfileValues`: a structure that provides a list of
            the versions, the cipher suites, the supported groups and the
            signature algorithms
        """

        versions = []
        cipher_suites = []
        sig_algos = []
        groups = []
        key_shares = []

        # We want to treat higer protocol versions first, so that the result
        # provides the most desirable preference
        for version in sorted(self.get_versions(), reverse=True):
            if version not in filter_versions:
                continue

            # So the versions are restored in order from low to high
            versions.insert(0, version)

            vers_cs = self.get_cipher_suites(version)
            cipher_suites.extend([cs for cs in vers_cs if cs not in cipher_suites])

            vers_sig = self.get_signature_algorithms(version)
            if vers_sig is not None:
                sig_algos.extend([algo for algo in vers_sig if algo not in sig_algos])

            # Add the signature algorithms used in the certificate chains as well, if
            # not yet present.
            sig_algos.extend(
                [algo for algo in self.get_cert_sig_algos() if algo not in sig_algos]
            )
            vers_group = self.get_supported_groups(version)
            if vers_group is not None:
                groups.extend([group for group in vers_group if group not in groups])

            if version is tls.Version.TLS13:
                key_shares = vers_group

        if full_hs:
            cipher_suites = utils.filter_cipher_suites(cipher_suites, full_hs=True)

        return structs.ProfileValues(
            versions=versions,
            cipher_suites=cipher_suites,
            supported_groups=groups,
            signature_algorithms=sig_algos,
            key_shares=key_shares,
        )

    def make_serializable(self):
        """Convert the object into seralizable types

        Returns:
            dict: the serializable data provided as a dict.
        """

        return ServerProfileSchema().dump(self)

    def load(self, data):
        ServerProfileSchema(profile=self).load(data)


class ServerProfileSchema(ProfileSchema):
    """Base schema for the server profile.
    """

    __profile_class__ = ServerProfile
    cert_chains = fields.List(fields.Nested(SPCertChainSchema))
    features = fields.Nested(SPFeaturesSchema)
    scan_info = fields.Nested(SPScanInfoSchema)
    server = fields.Nested(SPServerSchema)
    versions = fields.List(fields.Nested(SPVersionSchema))
    vulnerabilities = fields.Nested(SPVulnerabilitiesSchema)

    def __init__(self, profile=None, **kwargs):
        self._profile = profile
        super().__init__(**kwargs)

    @post_load
    def deserialize(self, data, **kwargs):
        if self._profile is not None:
            self._profile._init_from_dict(data)
