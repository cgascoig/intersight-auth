from intersight_auth import __version__
from intersight_auth import IntersightAuth, repair_pem
from requests import Request
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature
import base64

# this is not a real/valid key
v3_secret_key = """
-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFpLumf8DcLaJSAM1
pp6rmKCz00eZAewOElJKETFiW/WhRANCAAT0RlNvtEUFP2n6Aq38dnWvsT1AkZjm
B9I2RZyK1NILUMKp1rdSI05SaOS5Ca5YyJ4ZVOfSIN0ZduOSAkWaAPy0
-----END EC PRIVATE KEY-----
"""
v3_key_id = "59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b39fc27564612d319801ce"

#################################################
# GET - known-good example (v3 key)
#################################################

def test_v3_get():
    is_auth = IntersightAuth(v3_key_id, secret_key_string=repair_pem(v3_secret_key))
    in_headers={
        "Content-Type":"application/json", 
        "Date": 'Wed, 22 Jun 2022 23:29:22 GMT',
    }
    req = Request(method="GET", url="https://intersight.com/api/v1/ntp/Policies", headers=in_headers).prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    # assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b39fc27564612d319801ce",algorithm="hs2019",headers="(request-target) date host content-type digest",signature="MEQCIEzjVQqKY70QdMkDiJjS2cc8kTnuiek6OpCFTayW7+8GAiBpPvIQUaubvEmJwQJMHyG/3KhQb+0nbMr5ICzu9JRiaw=="'
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == "application/json"
    assert new_req.headers["Date"] == 'Wed, 22 Jun 2022 23:29:22 GMT'

    # For v3 (ECDSA) authentication, the signature is not deterministic (includes a random nonce) so we can't just use known-good examples. 
    # Instead, we can verify that the signed string is correct and verify against the signature
    signed_string = """(request-target): get /api/v1/ntp/Policies
date: Wed, 22 Jun 2022 23:29:22 GMT
host: intersight.com
content-type: application/json
digest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="""

    assert _verify_signature(new_req.headers["Authorization"], signed_string)

#################################################
# PATCH - known-good example (v3 key)
#################################################

def test_v3_patch():
    is_auth = IntersightAuth(v3_key_id, secret_key_string=repair_pem(v3_secret_key))
    in_headers={
        "Content-Type":"application/json", 
        "Date": 'Thu, 23 Jun 2022 00:46:41 GMT',
    }
    req = Request(method="PATCH", url="https://intersight.com/api/v1/ntp/Policies/629713736275722d31a1ac7c", headers=in_headers, data='{"Enabled": false}').prepare()

    new_req = is_auth(req)
    assert new_req.headers["Digest"] == "SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc="
    # assert new_req.headers["Authorization"] == 'Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b39fc27564612d319801ce",algorithm="hs2019",headers="(request-target) date host content-type digest", signature="MEUCIQDF8UQwsVrQwh3dHBgrFdqACVpcZZ8IUvrSaN5521YzQQIgccDsL82oeAjQ6ppItUXVWABqYCD/U8oz7vOrTiz0jLM="'
    assert new_req.headers["Host"] == "intersight.com"
    assert new_req.headers["Content-Type"] == "application/json"
    assert new_req.headers["Date"] == 'Thu, 23 Jun 2022 00:46:41 GMT'

    # For v3 (ECDSA) authentication, the signature is not deterministic (includes a random nonce) so we can't just use known-good examples. 
    # Instead, we can verify that the signed string is correct and verify against the signature
    signed_string = """(request-target): patch /api/v1/ntp/Policies/629713736275722d31a1ac7c
date: Thu, 23 Jun 2022 00:46:41 GMT
host: intersight.com
content-type: application/json
digest: SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc="""

    assert _verify_signature(new_req.headers["Authorization"], signed_string)

def _verify_signature(authorization_header, signed_string):
    m=re.search(r'signature="([^"]*)"', authorization_header)
    assert m
    assert len(m.groups())==1
    signature = m.group(1)

    try:
        priv_key = serialization.load_pem_private_key(v3_secret_key.encode('utf-8'), password=None, backend=default_backend())
        pub_key = priv_key.public_key()
        pub_key.verify(base64.b64decode(signature), signed_string.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False

    return True