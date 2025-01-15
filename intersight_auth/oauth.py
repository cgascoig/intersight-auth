import requests
from oauthlib.oauth2 import BackendApplicationClient
import time
import logging
from requests import PreparedRequest

from intersight_auth.exceptions import IntersightAuthOAuthException

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class IntersightOAuth:
    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = "https://intersight.com/iam/token"

        self.token = None
        self.token_expires: float = 0

        self.oauth_client = BackendApplicationClient(client_id=client_id)

    def refresh_token(self):
        body = self.oauth_client.prepare_request_body(
            include_client_id=True, client_secret=self.client_secret
        )
        res = requests.post(
            self.token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if res.ok:
            js = res.json()
            self.token = js["access_token"]
            self.token_expires = time.time() + js["expires_in"]
            logger.debug(
                f"Token refreshed successfully. Current time {time.time()}, token_expires {self.token_expires} (expires_in was {js['expires_in']})"
            )
        else:
            raise IntersightAuthOAuthException()

    def oauth_request(self, r: PreparedRequest) -> PreparedRequest:
        if self.token is None or self.token_expires < time.time():
            logger.debug(
                f"Token expired, refreshing (token_expires {self.token_expires})"
            )
            self.refresh_token()
        else:
            logger.debug("Token still valid, not refreshing")

        r.headers["Authorization"] = f"Bearer {self.token}"

        return r
