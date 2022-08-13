"""
    intersight_auth.py -  provides a class to support Cisco Intersight
    interactions

    author: Chris Gascoigne (cgascoig@cisco.com), Jeremy Williams, David Soper
"""
# pylint: disable=too-few-public-methods
import re
from base64 import b64encode
from email.utils import formatdate
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec

from requests.auth import AuthBase


def _get_sha256_digest(data):

    hasher = hashes.Hash(hashes.SHA256(), default_backend())

    if data is not None:
        if type(data) == bytes:
            hasher.update(data)
        else:
            hasher.update(data.encode())

    return hasher.finalize()


def _prepare_string_to_sign(req_tgt, hdrs):
    """
    :param req_tgt : Request Target as stored in http header.
    :param hdrs: HTTP Headers to be signed.
    :return: instance of digest object
    """

    signature_string = "(request-target): " + req_tgt + "\n"

    for i, (key, value) in enumerate(hdrs.items()):
        signature_string += key.lower() + ": " + value
        if i < len(list(hdrs.items())) - 1:
            signature_string += "\n"

    return signature_string


def _get_signature_b64(key, string_to_sign):

    if str(key.__module__) == "cryptography.hazmat.backends.openssl.rsa":
        return b64encode(key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA256()))
    elif str(key.__module__) == "cryptography.hazmat.backends.openssl.ec":
        return b64encode(key.sign(string_to_sign, ec.ECDSA(hashes.SHA256())))
    else:
        raise IntersightAuthKeyException("Unsupported key type")


def _get_auth_header(signing_headers, method, path, api_key_id, secret_key):

    string_to_sign = _prepare_string_to_sign(
        method.lower() + " " + path, signing_headers
    )
    b64_signed_auth_digest = _get_signature_b64(secret_key, string_to_sign.encode())

    if str(secret_key.__module__) == "cryptography.hazmat.backends.openssl.rsa":
        algo = "rsa-sha256"
    elif str(secret_key.__module__) == "cryptography.hazmat.backends.openssl.ec":
        algo = "hs2019"

    auth_str = (
        'Signature keyId="'
        + api_key_id
        + '",'
        + 'algorithm="'
        + algo
        + '",headers="(request-target)'
    )

    for key in signing_headers:
        auth_str += " " + key.lower()

    auth_str += '", signature="' + b64_signed_auth_digest.decode("ascii") + '"'

    return auth_str


class IntersightAuth(AuthBase):
    """Implements requests custom authentication for Cisco Intersight.  Specify EITHER the secret_key_filename OR the secret_key_string but not BOTH."""

    def __init__(
        self,
        api_key_id,
        secret_key_filename=None,
        secret_key_string=None,
        secret_key_file_password=None,
    ):
        self.secret_key_filename = secret_key_filename
        self.secret_key_string = secret_key_string
        self.api_key_id = api_key_id
        self.secret_key_file_password = secret_key_file_password

        if secret_key_string and secret_key_filename:
            raise IntersightAuthKeyException(
                "Must not specify both secret_key_string and secret_key_filename"
            )
        if (not secret_key_string) and (not secret_key_filename):
            raise IntersightAuthKeyException(
                "Must specify either secret_key_string or secret_key_filename"
            )

        if secret_key_filename:
            # Process secret key from file
            with open(secret_key_filename, "rb") as secret_key_file:
                self.secret_key = serialization.load_pem_private_key(
                    secret_key_file.read(),
                    password=secret_key_file_password,
                    backend=default_backend(),
                )

        if secret_key_string:
            # Process secret key from string
            self.secret_key = serialization.load_pem_private_key(
                secret_key_string.encode("utf-8"),
                password=secret_key_file_password,
                backend=default_backend(),
            )

    def __call__(self, r):
        """Called by requests to modify and return the authenticated request"""
        date = r.headers.get("Date") or formatdate(
            timeval=None, localtime=False, usegmt=True
        )

        digest = _get_sha256_digest(r.body)

        url = urlparse(r.url)
        path = url.path or "/"
        if url.query:
            path += "?" + url.query

        signing_headers = {
            "Date": date,
            "Host": url.hostname,
            "Content-Type": r.headers.get("Content-Type") or "application/json",
            "Digest": "SHA-256=%s" % b64encode(digest).decode("ascii"),
        }

        auth_header = _get_auth_header(
            signing_headers, r.method, path, self.api_key_id, self.secret_key
        )

        r.headers["Digest"] = "SHA-256=%s" % b64encode(digest).decode("ascii")
        r.headers["Date"] = date
        r.headers["Authorization"] = "%s" % auth_header
        r.headers["Host"] = url.hostname
        r.headers["Content-Type"] = signing_headers["Content-Type"]

        return r


def repair_pem(pem_str):
    """Attempts to repair the whitespace of a PEM formatted value stored as a string"""
    # This function attempts to repair PEM values that were improperly converted
    # to a string.  This is a best-effort function and may not be effective.
    # The basic assumption is that there is an otherwise valid PEM in the input,
    # but the whitespace isn't correct to have a valid PEM.
    try:
        data_regex = re.compile(
            r"\s*-{5}\s*(BEGIN .*?)\s*-{5}(.*?)-{5}\s*(END .*?)\s*-{5}", re.DOTALL
        )
        input_match = data_regex.match(pem_str)
        header = input_match.group(1)
        encapsulated_data = re.sub(
            r"\s", "", input_match.group(2)
        )  # remove whitespace from encapsulated data
        footer = input_match.group(3)
        fixed_pem = "-----" + header + "-----\n"
        fixed_pem += re.sub(
            r"(.{64})", "\\1\n", encapsulated_data
        )  # output 64 bytes of encapsulsted data per line
        fixed_pem += "\n-----" + footer + "-----\n"
        return fixed_pem
    except Exception:
        raise IntersightAuthKeyException("Unable to locate a valid PEM in the string")


class IntersightAuthKeyException(Exception):
    """Raised when there is an error with the supplied key"""

    pass
