from intersight_auth import __version__
from intersight_auth import IntersightAuth
from requests import Request


# this is not a real/valid key
v2_secret_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAp1M61mfTtdvH4OSIQElZzSnG246jhg5Olt2InJIcsaqzEViQ
oLzazpuBCzRZObf2R3Jre41cnwZGGg998t2qnhf3bfWvd6+nKM9iJo1nKovm1kqI
kyUcVipLACcw5N0pwJykS/HmtDi5+uWyja0muRxxz5sNvwOa1iyh3fWnsVxVcs3L
kYqBkyaK8cZw9wDM4x5e480jbjb0LS+gkrNoI6hH2gmpzOu/y/3aXyZFCJjcBGdW
TL7aPSdFhQC8oZTgcUxukAujQC69rcStk5DxErcyXf5pmoSRx+gISQCqpsyvPupw
fElL6erspcUOOAIwB61jCXzzfxY9nkZm4z+bzwIDAQABAoIBAQCYriidJgaYBiFA
BCiTyJrJy9op0+FA3OM3ZJRYkjbeo61cIZ1vHoTmTB0XNUBJm6R9k1miVt5yOU5U
T1iU+VHLioD7dFkVdFGqunmMRjEiMKCFX2N6KT3PHi5ryFckLu7/U6/ToLrsLmr+
FwSzpJEWDm+HiaukZcyuq/FT0Omguu7fOcAUMtbYTynwzz4xqAYIjtge/h9MH7KH
TTLsUemc31c1jvKLAtkUygMRtHLlvQCsaI5V8fpv9F/koWoAeeetBdaJi0iB4BSr
WOFM1vrjvq050XzY2mXTfn1w9UzwUP2aV0iYahBqEQLXC9gX7xJKF4iPOiUSdI+F
Pg1JAZphAoGBAMM9pBugAcMxAeZJb/OahMpViXSkjsv949zvadIfnBtEgL0mrAEL
7HOnoNBl5bmSHXVOU8w73nbgwE9QU8wB9mXsZdJAXLVe+rs3rFP3WY7JanwEGmKN
SJL3PiX+2th3RYmlhS+jqeXkP3tVxmV6UT8vl/OmJwxQxOs4mHNI1wBRAoGBANtl
nYNqBhMKhtHJXBJpsKCeAgXWgcBHxrfrVlTuQ9n9x6vmMR/6/iQlwRrTB8T1VCpS
1zKFJLnpaRB11VGRhccAWr+Aq4aU7bCWgwJhVyUTTpVKzDFwegJk9Kh4aYKxDwJP
hE+uQIohdHjx7JJnhVxSs4iBQGLaQGmc9/yjyvIfAoGAQt2gj6l8EQp+uQzbn5WC
9vzWh7E4CpsYZ/lCx6j1wMz0PlO5Qt5/i5iUVesgAy8MkblSr7atWQ9eLYu4Nz1Q
0tVkhd5vIdq2ilnl1hf3fxRyOKj7FFeIzHSKv16KOuqWUS7z7z3hGQ/Twfy9ZtG+
c6JsKxDzfJ9I4bpPU+RVZhECgYEAmwA+eSKFqhwsxbfp2YRb6g3XxgIXZx4Okc+t
DZHL1A3MbHDT0hFETYty0x22hnsAfGpMaP/Rw5rYxG1LSTZzefWRJ2yjQhCjoLel
VSAqLiJmyWivvFoHiPuEMiXn/RJUVUCSbKziIfSi0fOxPHnwqRowhscyEuS4zyS7
uvyJG+cCgYB441+pVf6vyVfHatcQblMdids9ORvTFDqCyfBHJdS5XArcOgw3uMd5
osn6utc9Znq7S+pYnVjpcUgGzGPDhsWtJs1ieQBQpGjooWg4acw80GhsLOHSVDH+
ElnjCmtkmCz7W0RW3whsFgAhIBRX6k12LIx/Bsxbyo2Xzs86sgPthg==
-----END RSA PRIVATE KEY-----
"""
v2_key_id = "59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b2a6e97564612d318f1e7b"

#################################################
# GET - known-good example (v2 key)
#################################################

# DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): intersight.com:443
# send: b'GET /api/v1/ntp/Policies HTTP/1.1\r\nUser-Agent: python-requests/2.28.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nDigest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\nDate: Wed, 22 Jun 2022 05:22:58 GMT\r\nAuthorization: Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b2a6e97564612d318f1e7b",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="H7SVtz1Ht2/xqPwjB5ECLbSsEbReYnXXbEnXaE4Vi08ksuH9cjAJIB5AZuthSoHAZQvvC7/fW38wASZgSNWmRJieAsoS+R7zsIADwKwUEWfbwShbrLzRvsSL/maVWBZRorSHZ6GpaEmYudhSMqxTKRGgLfiubpkN3dOR4bVFJ0ukp+0mnTwJEs+4VnLXmVOK4pGcepeFZRckDTytJ6WfXJ/iKZk2yjAUHnejZFdb9GVuXuSrdFGsxjP2JaNm8gvR3lDKJ3/ghxdQsj/gEtOVOco7gK0LZLY5E/pQfXMZSAMi4s8c7v/RgmPLsDlG+y8ZOmwkiyiLVFzrc+Lrf31hWA=="\r\nHost: intersight.com\r\nContent-Type: application/json\r\n\r\n'
# reply: 'HTTP/1.1 200 OK\r\n'



def test_v2_get():
    is_auth = IntersightAuth(v2_key_id, secret_key_string=v2_secret_key)
    in_headers={
        "Content-Type":"application/json", 
        "Date": "Wed, 22 Jun 2022 05:22:58 GMT",
    }
    req = Request(method="GET", url="https://intersight.com/api/v1/ntp/Policies", headers=in_headers).prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b2a6e97564612d318f1e7b",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="H7SVtz1Ht2/xqPwjB5ECLbSsEbReYnXXbEnXaE4Vi08ksuH9cjAJIB5AZuthSoHAZQvvC7/fW38wASZgSNWmRJieAsoS+R7zsIADwKwUEWfbwShbrLzRvsSL/maVWBZRorSHZ6GpaEmYudhSMqxTKRGgLfiubpkN3dOR4bVFJ0ukp+0mnTwJEs+4VnLXmVOK4pGcepeFZRckDTytJ6WfXJ/iKZk2yjAUHnejZFdb9GVuXuSrdFGsxjP2JaNm8gvR3lDKJ3/ghxdQsj/gEtOVOco7gK0LZLY5E/pQfXMZSAMi4s8c7v/RgmPLsDlG+y8ZOmwkiyiLVFzrc+Lrf31hWA=="'
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == "application/json"
    assert new_req.headers["Date"] == "Wed, 22 Jun 2022 05:22:58 GMT"

#################################################
# PATCH - known-good example (v2 key)
#################################################

# DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): intersight.com:443
# send: b'PATCH /api/v1/ntp/Policies/629713736275722d31a1ac7c HTTP/1.1\r\nUser-Agent: python-requests/2.28.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 18\r\nDigest: SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc=\r\nDate: Wed, 22 Jun 2022 05:27:00 GMT\r\nAuthorization: Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b2a6e97564612d318f1e7b",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="kl5wQxVswjeb//jB5IIiLk+XKcIsmEPrDvXw3hgK6taRQziqcXWMaFrk4i3O/xJszB7VUvImw4NgQN718Cf8F+vfAcrKINfN4fXR4VrzG2qo9mC/3PK1aeDJiQD6rg/kw0S8kiK9VtmW0A0Tr3yzD38K1hxj9VJ1X7rePPvCalO+cRmPTVIBBY4h4bOHVoKxmZz2hOibM/bn/7SqiSTk29hGqrTswpD2s2hRG3zyyF1amjbMX5lw8xLHnrswGAN4jNTQFD+bdWKAE+CD0h4ylUV24aC23dbzxWDmsA9MCcPLDl9ptYlHPcRZYwGDV/7Fr7XsRguC5xZjdAQU8B2CQg=="\r\nHost: intersight.com\r\nContent-Type: application/json\r\n\r\n'
# send: b'{"Enabled": false}'
# reply: 'HTTP/1.1 200 OK\r\n'


def test_v2_patch():
    is_auth = IntersightAuth(v2_key_id, secret_key_string=v2_secret_key)
    in_headers={
        "Content-Type":"application/json", 
        "Date": "Wed, 22 Jun 2022 05:27:00 GMT",
    }
    req = Request(method="PATCH", url="https://intersight.com/api/v1/ntp/Policies/629713736275722d31a1ac7c", headers=in_headers, data='{"Enabled": false}').prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc="
    assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b2a6e97564612d318f1e7b",algorithm="rsa-sha256",headers="(request-target) date host content-type digest", signature="kl5wQxVswjeb//jB5IIiLk+XKcIsmEPrDvXw3hgK6taRQziqcXWMaFrk4i3O/xJszB7VUvImw4NgQN718Cf8F+vfAcrKINfN4fXR4VrzG2qo9mC/3PK1aeDJiQD6rg/kw0S8kiK9VtmW0A0Tr3yzD38K1hxj9VJ1X7rePPvCalO+cRmPTVIBBY4h4bOHVoKxmZz2hOibM/bn/7SqiSTk29hGqrTswpD2s2hRG3zyyF1amjbMX5lw8xLHnrswGAN4jNTQFD+bdWKAE+CD0h4ylUV24aC23dbzxWDmsA9MCcPLDl9ptYlHPcRZYwGDV/7Fr7XsRguC5xZjdAQU8B2CQg=="'
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == "application/json"
    assert new_req.headers["Date"] == "Wed, 22 Jun 2022 05:27:00 GMT"