from base64 import b64encode
from email.utils import formatdate
from urllib.parse import urlparse

from requests import PreparedRequest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .exceptions import IntersightAuthKeyException


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
    if isinstance(key, rsa.RSAPrivateKey):
        return b64encode(key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA256()))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return b64encode(key.sign(string_to_sign, ec.ECDSA(hashes.SHA256())))
    else:
        raise IntersightAuthKeyException(f"Unsupported key type '{type(key).__name__}'")


def _get_auth_header(signing_headers, method, path, api_key_id, secret_key):
    string_to_sign = _prepare_string_to_sign(
        method.lower() + " " + path, signing_headers
    )
    b64_signed_auth_digest = _get_signature_b64(secret_key, string_to_sign.encode())

    if isinstance(secret_key, rsa.RSAPrivateKey):
        algo = "rsa-sha256"
    if isinstance(secret_key, ec.EllipticCurvePrivateKey):
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


def load_secret_key(secret_key: bytes, secret_key_password):
    try:
        # Process secret key from string
        return serialization.load_pem_private_key(
            secret_key,
            password=secret_key_password,
            backend=default_backend(),
        )
    except:
        raise IntersightAuthKeyException("Error loading API secret key")


def sign_request(r: PreparedRequest, api_key_id, secret_key) -> PreparedRequest:
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
        signing_headers, r.method, path, api_key_id, secret_key
    )

    r.headers["Digest"] = "SHA-256=%s" % b64encode(digest).decode("ascii")
    r.headers["Date"] = date
    r.headers["Authorization"] = "%s" % auth_header
    r.headers["Host"] = url.hostname
    r.headers["Content-Type"] = signing_headers["Content-Type"]

    return r
