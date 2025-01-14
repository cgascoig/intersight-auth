"""
    intersight_auth.py -  provides a class to support Cisco Intersight
    interactions

    author: Chris Gascoigne (cgascoig@cisco.com), Jeremy Williams, David Soper
"""

# pylint: disable=too-few-public-methods
import re

from requests.auth import AuthBase
from enum import Enum

from .signing import load_secret_key, sign_request
from .exceptions import IntersightAuthKeyException, IntersightAuthConfigException
from .oauth import IntersightOAuth


class AuthMode(Enum):
    APIKEY = "apikey"
    OAUTH = "oauth"


class IntersightAuth(AuthBase):
    """Implements requests custom authentication for Cisco Intersight.  Specify EITHER the secret_key_filename OR the secret_key_string but not BOTH."""

    def __init__(
        self,
        api_key_id=None,
        secret_key_filename=None,
        secret_key_string=None,
        secret_key_file_password=None,
        oauth_client_id=None,
        oauth_client_secret=None,
    ):
        self.secret_key_filename = secret_key_filename
        self.secret_key_string = secret_key_string
        self.api_key_id = api_key_id
        self.secret_key_file_password = secret_key_file_password
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret

        mode = None
        if self.api_key_id is not None and (
            self.secret_key_string is not None or self.secret_key_filename is not None
        ):
            mode = AuthMode.APIKEY

        if self.oauth_client_id is not None and self.oauth_client_secret is not None:
            if mode is not None:
                raise IntersightAuthConfigException(
                    "Must not specify both API key authentication and OAuth authentication"
                )
            mode = AuthMode.OAUTH

        if mode is None:
            raise IntersightAuthConfigException(
                "Must specify either API key plus secret or OAuth client_id plus client_secret"
            )

        self.mode = mode

        if mode == AuthMode.APIKEY:
            self.secret_key = load_secret_key(
                secret_key_filename=self.secret_key_filename,
                secret_key_string=self.secret_key_string,
                secret_key_file_password=self.secret_key_file_password,
            )

        if mode == AuthMode.OAUTH:
            self.oauth = IntersightOAuth(self.oauth_client_id, self.oauth_client_secret)

    def __call__(self, r):
        """Called by requests to modify and return the authenticated request"""

        if self.mode == AuthMode.APIKEY:
            r = sign_request(r, self.api_key_id, self.secret_key)
        elif self.mode == AuthMode.OAUTH:
            # r = oauth_request(r, self.oauth_client_id, self.oauth_client_secret)
            r = self.oauth.oauth_request(r)

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
