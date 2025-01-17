import pytest
import os
from unittest import mock

from intersight_auth import (
    IntersightAuth,
    IntersightAuthConfigException,
    IntersightAuthKeyException,
)
from intersight_auth.intersight_auth import AuthMode
from .sample_keys import v3_key_id, v3_secret_key, oauth_client_id, oauth_client_secret


def test_oauth_config():
    is_auth = IntersightAuth(
        oauth_client_id=oauth_client_id, oauth_client_secret=oauth_client_secret
    )
    assert is_auth.config.mode == AuthMode.OAUTH

    # Invalid combinations should raise exceptions
    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(oauth_client_id=oauth_client_id)

    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(oauth_client_secret=oauth_client_secret)

    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(
            api_key_id=v3_key_id,
            secret_key_string=v3_secret_key,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )


def test_apikey_config():
    is_auth = IntersightAuth(api_key_id=v3_key_id, secret_key_string=v3_secret_key)
    assert is_auth.config.mode == AuthMode.APIKEY

    # Invalid combinations should raise exceptions
    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(api_key_id=v3_key_id)

    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(secret_key_string=v3_secret_key)

    with pytest.raises(IntersightAuthConfigException):
        IntersightAuth(
            api_key_id=v3_key_id,
            secret_key_string=v3_secret_key,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )

    with pytest.raises(IntersightAuthKeyException):
        IntersightAuth(api_key_id=v3_key_id, secret_key_string="xyz")


def test_apikey_env():
    with mock.patch.dict(os.environ, {"IS_KEY_ID": v3_key_id, "IS_KEY": v3_secret_key}):
        is_auth = IntersightAuth()
        assert is_auth.config.mode == AuthMode.APIKEY
        assert is_auth.config.api_key_id == v3_key_id
        assert is_auth.config.secret_key == v3_secret_key.encode()

    with mock.patch.dict(
        os.environ,
        {
            "IS_OAUTH_CLIENT_ID": oauth_client_id,
            "IS_OAUTH_CLIENT_SECRET": oauth_client_secret,
        },
    ):
        is_auth = IntersightAuth()
        assert is_auth.config.mode == AuthMode.OAUTH
        assert is_auth.config.oauth_client_id == oauth_client_id
        assert is_auth.config.oauth_client_secret == oauth_client_secret
