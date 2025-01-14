import pytest
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
    assert is_auth.mode == AuthMode.OAUTH

    # Invalid combinations should raise exceptions
    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(oauth_client_id=oauth_client_id)

    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(oauth_client_secret=oauth_client_secret)

    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(
            api_key_id=v3_key_id,
            secret_key_string=v3_secret_key,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )


def test_apikey_config():
    is_auth = IntersightAuth(api_key_id=v3_key_id, secret_key_string=v3_secret_key)
    assert is_auth.mode == AuthMode.APIKEY

    # Invalid combinations should raise exceptions
    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(api_key_id=v3_key_id)

    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(secret_key_string=v3_secret_key)

    with pytest.raises(IntersightAuthConfigException):
        is_auth = IntersightAuth(
            api_key_id=v3_key_id,
            secret_key_string=v3_secret_key,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )

    with pytest.raises(IntersightAuthKeyException):
        is_auth = IntersightAuth(api_key_id=v3_key_id, secret_key_string="xyz")
