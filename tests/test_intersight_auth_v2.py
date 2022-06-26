from intersight_auth import __version__
from intersight_auth import IntersightAuth, repair_pem
from requests import Request


# this is not a real/valid key
v2_secret_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvV0n1s8QcR7S7u5rR94//VoUSIxJ7jvLdZRNYRQcQCECxp+H
V6ut+61D5t7YQqNcTIEv71ssC9UNs/wCIFELeN5MweLqvYto03SFJB0bLZ+ycpnp
e9jTqALZqa6uCLycFjtV9s7sW5nZZcuDiyLlNCygtkzXkUdBQ3ycaZpJphKwezQ1
xXgmWaUV6JqihSwVgj9U7sZOQN/6eCbbL2/kLoHnAYVIlbiuV0uTZsFGLsm2ZP1o
A3h2NdqhPHrBlWSmUAdhYIGlu7WNQ0yN5d6PpwHERCUI2+fOKxau8C42EYDttYf1
tnU4VZC7ItmE8ZDlrGn9f5F8virhhlBEESTXkwIDAQABAoIBABfQiVwYembfi4OE
9HT7XGzOUVK2Ye3WE0ZcOkcFMnBWNnUoRusdqinGpo14ZRYsWUU90ft2KdnrF2gV
P2c1Cg5PVrPjh8YCrFI7iyr5hht8xAJpnNV4dVXh1eHjF/v9TFv3Zl49s7fpZ0/I
AmkTIGQpYKTMkSeyIGEOYNVfE/gQljcRz6yf60GmWJY5IglXh/00GtB3GQHJqWLs
rWMi7uwtFCp6dpQDjC7VAanAnmkti4/+hiNC8c+29Zf5LcQYPz2oY3V1UlpynyYH
b+mRL5iFJwcKZs+93waTyD/igFzK+ly9Nw3/vM/D0h5wxw8UPMFHyBKN3MAI4tzW
M1QtbYECgYEA5c3V1mReeOIDx6ilUebKUooryhg0EcKIYA5bUFvlYkB7E688CpdL
nCHoeRjCKcQ0jZzpZcBpB+CoaHNLCvpaKSHzvXGmFUztMX7FMVGERWk8RwvxCVl3
j9LstVvcXklt6OE2E3GLQUhLFbs0xWghlNZWMf/KCx7t/WUChRgGRWECgYEA0vMx
EDlLISZTheR2hKlENn2yAxYfo8XieArPcjt1kivGVVqnItUMtzCRHnF1cjYnbk8g
Tf5x+8LwlOHTCX9VrQQYM98t0WsWVSmkrzss1/K0yu09sYsdOet9UL7Jet7kpA3L
dfRxXQHySJaUPVYFR9f8hQsuJrUdndFiHdHlzXMCgYEAzFNzIXgGo9bZ44mozKS3
GiKugrd4fJ4KIdZCDLZYwz5v8HWrngMeAEoJ6LpB0V8aFxwATi+Bc7amJpD0lWM6
DT6Z+MR3FpNahtqfvJUtVYYXSVhtzZFWBHRXcX2m99K0Pg8YxLr9RWNhF4Znimpn
CW52H2i+nZq3oslQL0TINqECgYA33LTScgmmNqsJmu2TxetNbs3UKWipiv6lAV/c
BUjmM3drJP17qOWcIV1crXkHjLW2bXfFj6sJm57wHjkvm6vJjHsISYKtoWkhlkyJ
JueCLECaOGcM/CT6MJVX654ZTqtHkmudyeS3V4uck1ugPoZZdyXk6YgIMhAsucT8
1pe/ZwKBgGoZAhOaR/s5EM/bwIpqPE870VnWeIbvDc8vMH3tW/q7SysfyNxyZ99w
pQ8EfDaxnEFVuY7Xa8i/qr7mmXo5E+d0TrxkB1bqtwaJJ8ojaW5G/PIkU3aTC6uV
11QYh2F1qu2ow8Y4Q3DZ78jc9M3gHvzuknyencU2K0+VhVgwEVtI
-----END RSA PRIVATE KEY-----
"""
v2_key_id = "59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1"

#################################################
# GET - known-good example (v2 key)
#################################################

# DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): intersight.com:443
# send: b'GET /api/v1/ntp/Policies HTTP/1.1\r\nUser-Agent: python-requests/2.28.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nDigest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\nDate: Thu, 23 Jun 2022 00:57:07 GMT\r\nAuthorization: Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="Ioygtr7Uq8dHJirKU0Hq/LLQYGeLHnzgZwaSpsw1yMqkrlx3Atnu7LBISrQ+wO2QkQbvp85VqKawnikuoXoCJVaLb1KtKOMERWUPEbnPgzS/gORWWpPlMXLHbNALdInuvSSogh1qXysKHJtnu2srWmOFqU3g2aZ5gfkrzeQ/eQ97okPzpq8s8N0oUO4FmnXXSSS7MGp/yUbq+7LZkXYPIO0sapPZqSKIAtpfmoU5s218sdoxW2TMAK+pnmux1K4idQVCbz5BX3Yyb2iXR55usH1qk3IUSACeZJ+X7gP8CKYTUTEnkkCQa/TLbtD/hcjrRyqD6K7RXf59ZiimQP5FHA=="\r\nHost: intersight.com\r\nContent-Type: application/json\r\n\r\n'

def test_v2_get():
    content_type = "application/json"
    req_date = "Thu, 23 Jun 2022 00:57:07 GMT"
    is_auth = IntersightAuth(v2_key_id, secret_key_string=repair_pem(v2_secret_key))
    in_headers={
        "Content-Type": content_type,
        "Date": req_date,
    }
    req = Request(method="GET", url="https://intersight.com/api/v1/ntp/Policies", headers=in_headers).prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="Ioygtr7Uq8dHJirKU0Hq/LLQYGeLHnzgZwaSpsw1yMqkrlx3Atnu7LBISrQ+wO2QkQbvp85VqKawnikuoXoCJVaLb1KtKOMERWUPEbnPgzS/gORWWpPlMXLHbNALdInuvSSogh1qXysKHJtnu2srWmOFqU3g2aZ5gfkrzeQ/eQ97okPzpq8s8N0oUO4FmnXXSSS7MGp/yUbq+7LZkXYPIO0sapPZqSKIAtpfmoU5s218sdoxW2TMAK+pnmux1K4idQVCbz5BX3Yyb2iXR55usH1qk3IUSACeZJ+X7gP8CKYTUTEnkkCQa/TLbtD/hcjrRyqD6K7RXf59ZiimQP5FHA=="'
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
    in_headers={
        "Content-Type": content_type, 
        "Date": req_date,
    }
    req = Request(method="PATCH", url="https://intersight.com/api/v1/ntp/Policies/629713736275722d31a1ac7c", headers=in_headers, data='{"Enabled": false}').prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc="
    assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="S/hT9RE5Wrxxem1RJyuO6futrop9iTfO48u8agLwd+42LCLvgu4wMQgs4pionxKwpChnozM87OF0cMnqKzYeW8X/0bp+/ZHmF47CBuP71Y/tn09bCZvwJ3yf0KJ2IHT1sFF9eZDN7ezX2ZpiVWadtvBWJlLBvqlENhKqNcJK+Nu0UprBJOoUDcPIjb6kJxUL+Lhn8LSga6fWqPyG0X+FweIl8RnQSDzulvzc82gbOPCAg/mFzui9aZ4bySXmgACo7DNBsfw6OgMldVE+8R49YEruLzRXvroMHanxzG9hf+BaDZ5kheDRs4NlZgLu/INwukGGMp//MhsaI6cOuuNs/A=="'
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == content_type
    assert new_req.headers["Date"] == req_date