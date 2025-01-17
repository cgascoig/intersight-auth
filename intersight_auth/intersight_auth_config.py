from enum import Enum
import os
from typing import List, Optional

from .exceptions import IntersightAuthConfigException, IntersightAuthKeyException

ENV_VAR_PREFIXES = ["INTERSIGHT", "IS"]


class IntersightAuthConfig:
    def __init__(
        self,
        api_key_id: Optional[str] = None,
        secret_key_filename=None,
        secret_key_string=None,
        secret_key_password=None,
        oauth_client_id=None,
        oauth_client_secret=None,
    ):
        api_key_id = _get_config_item(api_key_id, ["KEY_ID"])
        secret_key_filename = _get_config_item(secret_key_filename, ["KEY_FILE"])
        secret_key_password = _get_config_item(secret_key_password, ["KEY_PASSWORD"])
        secret_key_string = _get_config_item(secret_key_string, ["KEY"])
        oauth_client_id = _get_config_item(oauth_client_id, ["OAUTH_CLIENT_ID"])
        oauth_client_secret = _get_config_item(
            oauth_client_secret, ["OAUTH_CLIENT_SECRET"]
        )

        # Resolve secret_key from string or file
        secret_key: Optional[bytes] = None
        try:
            if secret_key_string is not None:
                secret_key = secret_key_string.encode("utf-8")
            elif secret_key_filename is not None:
                with open(secret_key_filename, "rb") as f:
                    secret_key = f.read()
        except:
            raise IntersightAuthKeyException("Error loading API key")

        self.mode = None
        if api_key_id is not None and secret_key is not None:
            self.mode = AuthMode.APIKEY
            self.api_key_id = api_key_id
            self.secret_key = secret_key
            self.secret_key_password = secret_key_password

        if oauth_client_id is not None and oauth_client_secret is not None:
            if self.mode is not None:
                raise IntersightAuthConfigException(
                    "Must not specify both API key authentication and OAuth authentication"
                )
            self.mode = AuthMode.OAUTH
            self.oauth_client_id = oauth_client_id
            self.oauth_client_secret = oauth_client_secret

        if self.mode is None:
            raise IntersightAuthConfigException(
                "Must specify either API key plus secret or OAuth client_id plus client_secret"
            )


class AuthMode(Enum):
    APIKEY = "apikey"
    OAUTH = "oauth"


def _get_config_item(
    param: Optional[str], env_vars: Optional[List[str]], default: Optional[str] = None
) -> Optional[str]:
    """
    Resolve the value of a configuration item (e.g. api_key_id) in order of preference:
     - explicit parameter
     - list of environment variables (first item has highest preference)
     - default value
    """
    if param is not None:
        return param

    if env_vars is not None:
        for env_var in env_vars:
            for prefix in ENV_VAR_PREFIXES:
                expanded_env_var = prefix + "_" + env_var
                if expanded_env_var in os.environ:
                    return os.environ[expanded_env_var]

    return default
