# -*- coding: utf-8 -*-
"""Module for CRL manager
"""

# import basic stuff
import logging

# import own stuff
from tlsmate import tls
from tlsmate import cert_utils

# import other stuff
import requests
from cryptography import x509


class CrlManager(object):
    """Handles all CRL related operations and acts as a cache as well
    """

    def __init__(self, tlsmate=None):
        self._crls = {}
        self._recorder = tlsmate.recorder

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

    def _get_crl_obj(self, url):
        """Get the plain CRL object for a given URL.
        """

        if url not in self._crls:
            bin_crl = None
            self._recorder.trace(crl_url=url)
            try:
                if self._recorder.is_injecting():
                    bin_crl = self._recorder.inject(crl=None)

                else:
                    crl_resp = requests.get(url, timeout=5)
                    if crl_resp.ok:
                        bin_crl = crl_resp.content

                    self._recorder.trace(crl=bin_crl)

            except Exception:
                self._crls[url] = None

            else:
                self.add_crl(url, der_crl=bin_crl)

        return self._crls[url]

    def get_crl_status(self, urls, serial_nbr, issuer, issuer_cert, timestamp):
        """Determines the CRL revocation status for a given cert/urls.

        Downloads the CRL (if a download fails, the next url is tried), if not yet
        cached, validates the CRL against the issuer & its signature and checks if
        the certificate is present in the CRL or not.

        Arguments:
            urls (list of str): a list of CRL-urls
            serial_nbr (int): the serial number of the certificate to check
            issuer (:obj:`x509.Name`): the issuer name of the cert to check
            issuer_cert (:obj:`tlsmate.cert.Certificate`): the certificate of the issuer

        Returns:
            :obj:`tlsmate.tls.CertCrlStatus`: the final status.
        """
        status = None
        for url in urls:
            logging.debug(f"downloading CRL from {url}")
            crl = self._get_crl_obj(url)
            if crl is None:
                status = tls.CertCrlStatus.CRL_DOWNLOAD_FAILED
                continue

            if not cert_utils.equal_names(issuer, issuer_cert.parsed.subject):
                return tls.CertCrlStatus.WRONG_CRL_ISSUER

            if crl.last_update > timestamp or crl.next_update < timestamp:
                return tls.CertCrlStatus.INVALID_TIMESTAMP

            if not crl.is_signature_valid(issuer_cert.parsed.public_key()):
                return tls.CertCrlStatus.CRL_SIGNATURE_INVALID

            if crl.get_revoked_certificate_by_serial_number(serial_nbr) is None:
                return tls.CertCrlStatus.NOT_REVOKED

            else:
                return tls.CertCrlStatus.REVOKED

        return status
