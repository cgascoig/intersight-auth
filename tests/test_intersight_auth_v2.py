from intersight_auth import __version__
from intersight_auth import IntersightAuth, repair_pem
from requests import Request
from .sample_keys import v2_key_id, v2_secret_key

#################################################
# GET - known-good example (v2 key)
#################################################

# DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): intersight.com:443
# send: b'GET /api/v1/ntp/Policies HTTP/1.1\r\nUser-Agent: python-requests/2.28.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nDigest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\nDate: Thu, 23 Jun 2022 00:57:07 GMT\r\nAuthorization: Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="Ioygtr7Uq8dHJirKU0Hq/LLQYGeLHnzgZwaSpsw1yMqkrlx3Atnu7LBISrQ+wO2QkQbvp85VqKawnikuoXoCJVaLb1KtKOMERWUPEbnPgzS/gORWWpPlMXLHbNALdInuvSSogh1qXysKHJtnu2srWmOFqU3g2aZ5gfkrzeQ/eQ97okPzpq8s8N0oUO4FmnXXSSS7MGp/yUbq+7LZkXYPIO0sapPZqSKIAtpfmoU5s218sdoxW2TMAK+pnmux1K4idQVCbz5BX3Yyb2iXR55usH1qk3IUSACeZJ+X7gP8CKYTUTEnkkCQa/TLbtD/hcjrRyqD6K7RXf59ZiimQP5FHA=="\r\nHost: intersight.com\r\nContent-Type: application/json\r\n\r\n'


def test_v2_get():
    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:57:07 GMT"
    is_auth = IntersightAuth(v2_key_id, secret_key_string=repair_pem(v2_secret_key))
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
        new_req.headers["Digest"]
        == "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    )
    assert (
        new_req.headers["Authorization"]
        == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="Ioygtr7Uq8dHJirKU0Hq/LLQYGeLHnzgZwaSpsw1yMqkrlx3Atnu7LBISrQ+wO2QkQbvp85VqKawnikuoXoCJVaLb1KtKOMERWUPEbnPgzS/gORWWpPlMXLHbNALdInuvSSogh1qXysKHJtnu2srWmOFqU3g2aZ5gfkrzeQ/eQ97okPzpq8s8N0oUO4FmnXXSSS7MGp/yUbq+7LZkXYPIO0sapPZqSKIAtpfmoU5s218sdoxW2TMAK+pnmux1K4idQVCbz5BX3Yyb2iXR55usH1qk3IUSACeZJ+X7gP8CKYTUTEnkkCQa/TLbtD/hcjrRyqD6K7RXf59ZiimQP5FHA=="'
    )
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == content_type
    assert new_req.headers["Date"] == req_date


#################################################
# PATCH - known-good example (v2 key)
#################################################

# DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): intersight.com:443
# send: b'PATCH /api/v1/ntp/Policies/629713736275722d31a1ac7c HTTP/1.1\r\nUser-Agent: python-requests/2.28.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 18\r\nDigest: SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc=\r\nDate: Thu, 23 Jun 2022 00:59:53 GMT\r\nAuthorization: Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="S/hT9RE5Wrxxem1RJyuO6futrop9iTfO48u8agLwd+42LCLvgu4wMQgs4pionxKwpChnozM87OF0cMnqKzYeW8X/0bp+/ZHmF47CBuP71Y/tn09bCZvwJ3yf0KJ2IHT1sFF9eZDN7ezX2ZpiVWadtvBWJlLBvqlENhKqNcJK+Nu0UprBJOoUDcPIjb6kJxUL+Lhn8LSga6fWqPyG0X+FweIl8RnQSDzulvzc82gbOPCAg/mFzui9aZ4bySXmgACo7DNBsfw6OgMldVE+8R49YEruLzRXvroMHanxzG9hf+BaDZ5kheDRs4NlZgLu/INwukGGMp//MhsaI6cOuuNs/A=="\r\nHost: intersight.com\r\nContent-Type: application/json\r\n\r\n'


def test_v2_patch():
    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:59:53 GMT"
    is_auth = IntersightAuth(v2_key_id, secret_key_string=repair_pem(v2_secret_key))
    in_headers = {
        "Content-Type": content_type,
        "Date": req_date,
    }
    req = Request(
        method="PATCH",
        url="https://intersight.com/api/v1/ntp/Policies/629713736275722d31a1ac7c",
        headers=in_headers,
        data='{"Enabled": false}',
    ).prepare()

    new_req = is_auth(req)
    assert (
        new_req.headers["Digest"]
        == "SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc="
    )
    assert (
        new_req.headers["Authorization"]
        == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="S/hT9RE5Wrxxem1RJyuO6futrop9iTfO48u8agLwd+42LCLvgu4wMQgs4pionxKwpChnozM87OF0cMnqKzYeW8X/0bp+/ZHmF47CBuP71Y/tn09bCZvwJ3yf0KJ2IHT1sFF9eZDN7ezX2ZpiVWadtvBWJlLBvqlENhKqNcJK+Nu0UprBJOoUDcPIjb6kJxUL+Lhn8LSga6fWqPyG0X+FweIl8RnQSDzulvzc82gbOPCAg/mFzui9aZ4bySXmgACo7DNBsfw6OgMldVE+8R49YEruLzRXvroMHanxzG9hf+BaDZ5kheDRs4NlZgLu/INwukGGMp//MhsaI6cOuuNs/A=="'
    )
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == content_type
    assert new_req.headers["Date"] == req_date
