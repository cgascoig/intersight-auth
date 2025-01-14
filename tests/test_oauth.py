import responses
from requests import Request
from intersight_auth.oauth import IntersightOAuth
from intersight_auth import IntersightAuth
from .sample_keys import oauth_client_id, oauth_client_secret
import time
from unittest import mock

SAMPLE_TOKEN = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnRlcnNpZ2h0Ijp7ImFjY291bnRfaWQiOiI1OWM4NGU0YTE2MjY3YzAwMDFjMjM0MjgiLCJhY2NvdW50X25hbWUiOiJDaXNjby1BdXN0cmFsaWEtTWVsU3lkLUxhYnMiLCJyb2xlcyI6IkFjY291bnQgQWRtaW5pc3RyYXRvciIsInJvbGVfaWRzIjoiNTk2MDkwMWVhOTRlYmEwMDAxMjdlM2M2IiwiZG9tYWluZ3JvdXBfaWQiOiI1YjI1NDE4ZDdhNzY2Mjc0MzQ2NWNmNzIiLCJwZXJtaXNzaW9uX3Jlc3RyaWN0ZWRfdG9fb3JncyI6Im5vIiwicmVnaW9uIjoiaW50ZXJzaWdodC1hd3MtdXMtZWFzdC0xIn0sImF1ZCI6Imh0dHBzOi8vd3d3LmludGVyc2lnaHQuY29tIiwiZXhwIjoxNzM2NDkyMDA3LCJpYXQiOjE3MzY0OTE0MDcsImlzcyI6Imh0dHBzOi8vd3d3LmludGVyc2lnaHQuY29tIiwic3ViIjoiMmNlMzQ2OTYxYjEzNjkxNzgzYWZmZWQ1MGEzMzVjMGFiMzhlMzBiYjdiNjhhMzI1NWY1YmQ5MWEzOTU3YWQ0NS01YjI1NDE4ZDdhNzY2Mjc0MzQ2NWNmNzIifQ.BMOyBb0yQf3rCHI-ioinwSC8ha1_7EwQelQoqp9HlyrAHMJtLQILtAmEMkl9NVM053gkzFvexoHN1RySpZv7Cg'

SAMPLE_TOKEN2 = 'AAAAAGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnRlcnNpZ2h0Ijp7ImFjY291bnRfaWQiOiI1OWM4NGU0YTE2MjY3YzAwMDFjMjM0MjgiLCJhY2NvdW50X25hbWUiOiJDaXNjby1BdXN0cmFsaWEtTWVsU3lkLUxhYnMiLCJyb2xlcyI6IkFjY291bnQgQWRtaW5pc3RyYXRvciIsInJvbGVfaWRzIjoiNTk2MDkwMWVhOTRlYmEwMDAxMjdlM2M2IiwiZG9tYWluZ3JvdXBfaWQiOiI1YjI1NDE4ZDdhNzY2Mjc0MzQ2NWNmNzIiLCJwZXJtaXNzaW9uX3Jlc3RyaWN0ZWRfdG9fb3JncyI6Im5vIiwicmVnaW9uIjoiaW50ZXJzaWdodC1hd3MtdXMtZWFzdC0xIn0sImF1ZCI6Imh0dHBzOi8vd3d3LmludGVyc2lnaHQuY29tIiwiZXhwIjoxNzM2NDkyMDA3LCJpYXQiOjE3MzY0OTE0MDcsImlzcyI6Imh0dHBzOi8vd3d3LmludGVyc2lnaHQuY29tIiwic3ViIjoiMmNlMzQ2OTYxYjEzNjkxNzgzYWZmZWQ1MGEzMzVjMGFiMzhlMzBiYjdiNjhhMzI1NWY1YmQ5MWEzOTU3YWQ0NS01YjI1NDE4ZDdhNzY2Mjc0MzQ2NWNmNzIifQ.BMOyBb0yQf3rCHI-ioinwSC8ha1_7EwQelQoqp9HlyrAHMJtLQILtAmEMkl9NVM053gkzFvexoHN1RySpZv7Cg'

class FakeTime():
    def __init__(self, auto_increment=0):
        self.t = time.time()
        self.auto_increment = auto_increment

    def increment(self, inc):
        self.t = self.t + inc

    def time(self):
        t = self.t
        self.t = self.t + self.auto_increment
        print(f"time.time() called, old time {t}, new time {self.t}")
        return t

ft = FakeTime()

@mock.patch("time.time", new=ft.time)
@responses.activate
def test_oauth_request():
    """
    Test that IntersighOAuth.oauth_request works
    """
    responses.add(
        responses.POST,
        "https://intersight.com/iam/token",
        json={
            'access_token': SAMPLE_TOKEN,
            'expires_in': 600,
            'token_type': 'Bearer'
        }
    )
    responses.add(
        responses.POST,
        "https://intersight.com/iam/token",
        json={
            'access_token': SAMPLE_TOKEN2,
            'expires_in': 600,
            'token_type': 'Bearer'
        }
    )

    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:57:07 GMT"
    in_headers = {
        "Content-Type": content_type,
        "Date": req_date,
    }
    req = Request(
        method="GET",
        url="https://intersight.com/api/v1/ntp/Policies",
        headers=in_headers,
    ).prepare()

    oauth = IntersightOAuth(oauth_client_id, oauth_client_secret)

    new_req = oauth.oauth_request(req)
    assert (new_req.headers["Authorization"] == f'Bearer {SAMPLE_TOKEN}')

    ft.increment(400)
    new_req = oauth.oauth_request(req)
    assert (new_req.headers["Authorization"] == f'Bearer {SAMPLE_TOKEN}')

    ft.increment(400)
    new_req = oauth.oauth_request(req)
    assert (new_req.headers["Authorization"] == f'Bearer {SAMPLE_TOKEN2}')

    assert responses.assert_call_count("https://intersight.com/iam/token", 2)

@responses.activate
def test_oauth():
    """
    Test that IntersighAuth works with oauth creds (i.e. end to end test)
    """
    responses.add(
        responses.POST,
        "https://intersight.com/iam/token",
        json={
            'access_token': SAMPLE_TOKEN,
            'expires_in': 600,
            'token_type': 'Bearer'
        }
    )


    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:57:07 GMT"
    is_auth = IntersightAuth(oauth_client_id=oauth_client_id, oauth_client_secret=oauth_client_secret)
    in_headers = {
        "Content-Type": content_type,
        "Date": req_date,
    }
    req = Request(
        method="GET",
        url="https://intersight.com/api/v1/ntp/Policies",
        headers=in_headers,
    ).prepare()

    new_req = is_auth(req)
    assert (
        new_req.headers["Authorization"]
        == f'Bearer {SAMPLE_TOKEN}'
    )
    assert new_req.headers["Content-Type"] == content_type
    assert new_req.headers["Date"] == req_date
