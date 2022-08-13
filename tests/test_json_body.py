from intersight_auth import __version__
from intersight_auth import IntersightAuth, repair_pem
from requests import Request
from .sample_keys import v2_key_id, v2_secret_key


def test_json_body():
    """
    Ensure that supplying json=<object> instead of data=<string> doesn't cause an exception
    """
    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:57:07 GMT"
    is_auth = IntersightAuth(v2_key_id, secret_key_string=repair_pem(v2_secret_key))
    in_headers = {
        "Content-Type": content_type,
        "Date": req_date,
    }
    req = Request(
        method="POST",
        url="https://intersight.com/api/v1/ntp/Policies",
        headers=in_headers,
        json={"ClassId": "ntp.Policy"},
    ).prepare()

    new_req = is_auth(req)
    assert new_req is not None
