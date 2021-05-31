# -*- coding: utf-8 -*-
"""Module for handling a certificate chain
"""
# import basic stuff
import logging
import time

# import own stuff
from tlsmate import tls
from tlsmate.cert import Certificate
from tlsmate import cert_utils
from tlsmate import recorder
from tlsmate.exception import UntrustedCertificate

# import other stuff
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.exceptions import InvalidSignature


class CertChain(object):
    """Class representing a certificate chain.

    This object is iterable, yielding the x509 representation of the certificates.
    """

    def __init__(self):
        from tlsmate.tlsmate import TlsMate

        tlsmate = TlsMate.instance
        self.certificates = []
        self._digest = hashes.Hash(hashes.SHA256())
        self._digest_value = None
        self._raise_on_failure = True
        self.issues = []
        self.successful_validation = False
        self.root_cert = None
        self.root_cert_transmitted = False
        self._recorder = tlsmate.recorder
        self._config = tlsmate.config
        self._trust_store = tlsmate.trust_store
        self._crl_manager = tlsmate.crl_manager

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

    def _check_crl(self, cert, issuer_cert, timestamp, raise_on_failure):
        """Check the CRL state for the given certificate.
        """

        if not self._config.get("crl"):
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

        cert.crl_status = self._crl_manager.get_crl_status(
            crl_urls,
            cert.parsed.serial_number,
            cert.parsed.issuer,
            issuer_cert,
            timestamp,
        )
        logging.debug(f'CRL status for certificate "{cert}": {cert.crl_status}')
        if cert.crl_status is not tls.CertCrlStatus.NOT_REVOKED:
            cert._raise_untrusted(
                f"CRL status not ok: {cert.crl_status}", raise_on_failure
            )

    def _check_ocsp(self, cert, issuer_cert, timestamp, raise_on_failure):
        """Check the OCSP status for the given certificate.
        """

        if not self._config.get("ocsp"):
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
            if self._recorder.is_injecting():
                ocsp_resp = self._recorder.inject_response()

            else:
                ocsp_resp = requests.post(
                    ocsp_url,
                    headers={"Content-Type": "application/ocsp-request"},
                    data=req.public_bytes(serialization.Encoding.DER),
                    timeout=5,
                )
                self._recorder.trace_response(
                    time.time() - start, recorder.SocketEvent.DATA, ocsp_resp
                )

        except requests.Timeout:
            self._recorder.trace_response(
                time.time() - start, recorder.SocketEvent.TIMEOUT
            )
            cert.ocsp_status = tls.OcspStatus.TIMEOUT
            cert._raise_untrusted(
                f"connection to OCSP server {ocsp_url} timed out", raise_on_failure
            )

        except Exception:
            self._recorder.trace_response(
                time.time() - start, recorder.SocketEvent.CLOSURE
            )
            cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
            cert._raise_untrusted(
                f"connection to OCSP server {ocsp_url} failed", raise_on_failure
            )

        if ocsp_resp.ok:
            ocsp_decoded = x509.ocsp.load_der_ocsp_response(ocsp_resp.content)

            if ocsp_decoded.certificates:
                sig_cert = Certificate(
                    x509_cert=ocsp_decoded.certificates[0], parse=True
                )
                self._validate_cert(sig_cert, -1, timestamp, None, raise_on_failure)

            else:
                sig_cert = issuer_cert

            # check signature
            try:
                sig_scheme = cert_utils.map_x509_sig_scheme(
                    ocsp_decoded.signature_hash_algorithm,
                    ocsp_decoded.signature_algorithm_oid,
                )
                sig_cert.validate_signature(
                    sig_scheme, ocsp_decoded.tbs_response_bytes, ocsp_decoded.signature,
                )

            except InvalidSignature:
                cert.ocsp_status = tls.OcspStatus.SIGNATURE_INVALID
                cert._raise_untrusted(
                    f"signature of OCSP server {ocsp_url} invalid", raise_on_failure
                )

            if ocsp_decoded.response_status == x509.ocsp.OCSPResponseStatus.SUCCESSFUL:

                if ocsp_decoded.this_update > timestamp:
                    cert.ocsp_status = tls.OcspStatus.INVALID_TIMESTAMP
                    cert._raise_untrusted(
                        "invalid timestamp in OCSP response (thisUpdate)",
                        raise_on_failure,
                    )

                if ocsp_decoded.next_update and ocsp_decoded.next_update < timestamp:
                    cert.ocsp_status = tls.OcspStatus.INVALID_TIMESTAMP
                    cert._raise_untrusted(
                        "invalid timestamp in OCSP response (nextUpdate)",
                        raise_on_failure,
                    )

                if ocsp_decoded.certificate_status == x509.ocsp.OCSPCertStatus.GOOD:
                    cert.ocsp_status = tls.OcspStatus.NOT_REVOKED
                    logging.debug(f"certificate {cert}: OCSP status ok")
                    return

                if ocsp_decoded.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
                    cert.ocsp_status = tls.OcspStatus.REVOKED

                else:
                    cert.ocsp_status = tls.OcspStatus.UNKNOWN

                cert._raise_untrusted("OCSP status not ok", raise_on_failure)

            else:
                cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
                cert._raise_untrusted(
                    f"OCSP response not ok: {ocsp_decoded.response_status}",
                    raise_on_failure,
                )

        cert.ocsp_status = tls.OcspStatus.INVALID_RESPONSE
        cert._raise_untrusted(
            f"HTTP response failed with status {ocsp_resp.status_code}",
            raise_on_failure,
        )

    def _issuer_certs(self, cert):
        """Get a list of all potential issuers from the certificate chain.
        """
        issuers = []
        for issuer_idx in range(1, len(self.certificates)):
            issuer_cert = self.certificates[issuer_idx]
            if cert.auth_key_id and issuer_cert.subject_key_id:
                match = cert.auth_key_id == issuer_cert.subject_key_id

            else:
                match = cert_utils.equal_names(
                    cert.parsed.issuer, issuer_cert.parsed.subject
                )

            if match:
                issuers.append((issuer_idx, issuer_cert))

        return issuers

    def _validate_cert(self, cert, idx, timestamp, domain_name, raise_on_failure):
        """Validates a certificate against the certificate chain.

        Arguments:
            cert (:obj:`tlsmate.cert.Certificate`): the certificate to check.
                Initially, that's typically the server certificate, which must
                come first in the chain. But other cases are supported as well,
                e.g. checking a certificate from an OCSP response.
            idx (int): the index of the certificate in the chain. The value -1
                is used for OCSP certificates. None is used for certificates
                from the trust store.
            timestamp: The (current) timestamp to check the validity period
            domain_name (str): The domain name or SNI
            raise_on_failure (bool): An indication, if the validation shall abort
                in case exceptional cases are detected. Normally set to False for
                server scans.

        Returns:
            list of int: the sequence of certificate indexes from the chain which were
            used to validate the chain. Can be used to detect gratuitous certificates.
        """
        track = []
        # cert already seen?
        if cert.trusted:
            return track

        elif cert.trusted is False:
            raise UntrustedCertificate(f"certificate {cert} is not trusted")

        cert.validate_period(timestamp, raise_on_failure)
        if idx == 0:
            cert.validate_subject(domain_name, raise_on_failure)

        if idx is None:
            cert.trusted = True
            return track

        if cert.self_signed:
            issuers = [(idx, cert)]
            if not self._trust_store.cert_in_trust_store(cert):
                cert._raise_untrusted(
                    "self-signed certificate not found in trust store", True
                )
            else:
                self.root_cert_transmitted = True
                self.root_cert = None

        else:
            issuers = self._issuer_certs(cert)
            if not issuers:
                root_cert = self._trust_store.issuer_in_trust_store(cert.parsed.issuer)
                if root_cert is None:
                    cert._raise_untrusted(
                        f'issuer certificate "{cert.parsed.issuer.rfc4514_string()}" '
                        f"not found in trust store",
                        True,
                    )
                else:
                    self.root_cert_transmitted = False
                    self.root_cert = root_cert

                issuers = [(None, root_cert)]

        exception = None
        for issuer_idx, issuer_cert in issuers:
            try:
                try:
                    issuer_cert.validate_cert_signature(cert)

                except Exception:
                    cert._raise_untrusted("invalid signature", raise_on_failure)

                if not cert.self_signed:
                    track = self._validate_cert(
                        issuer_cert,
                        issuer_idx,
                        timestamp,
                        domain_name,
                        raise_on_failure,
                    )

                self._check_crl(cert, issuer_cert, timestamp, raise_on_failure)
                self._check_ocsp(cert, issuer_cert, timestamp, raise_on_failure)
                if issuer_idx is not None:
                    if issuer_idx < idx:
                        self.issues.append(
                            "certificates of the chain are not in sequence"
                        )
                cert.trusted = True
                break

            except Exception as exc:
                exception = exc

        if not cert.trusted and raise_on_failure:
            if exception:
                raise exception

            else:
                cert._raise_untrusted("no valid trust path found", raise_on_failure)

        return [idx] + track

    def validate(self, timestamp, domain_name, raise_on_failure):
        """Only the minimal checks are supported.

        If a discrepancy is found, an exception is raised (depending on
        raise_on_failure).

        Arguments:
            timestamp (datetime.datetime): the timestamp to check against
            domain_name (str): the domain name to validate the host certificate against
            raise_on_failure (bool): whether an exception shall be raised if the
                validation fails or not. Useful for a TLS scan, as the scan shall
                continue.

        Raises:
            UntrustedCertificate: in case a certificate within the chain cannot be
                validated and `raise_on_failure` is True.
        """

        track = self._validate_cert(
            self.certificates[0], 0, timestamp, domain_name, raise_on_failure
        )

        self.successful_validation = self.certificates[0].trusted is True

        # And now check for gratuitous certificate in the chain
        if not raise_on_failure:
            for idx, cert in enumerate(self.certificates):
                if idx not in track and cert.trusted is None:
                    cert.issues.append(
                        "gratuitous certificate, not part of trust chain"
                    )

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
