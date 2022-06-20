# intersight-auth

This module provides an authentication helper for requests to make it easy to make [Intersight API](https://intersight.com/apidocs/introduction/overview/) calls using [requests](https://requests.readthedocs.io/en/latest/). 

## Install

```
pip install intersight-auth
```

## Example using a file for the secret key

``` Python
import sys

from intersight_auth import IntersightAuth
from requests import Session

session = Session()
session.auth = IntersightAuth("XYZ/XYZ/XYZ", "key.pem")

response = session.get("https://intersight.com/api/v1/ntp/Policies")

if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    sys.exit(1)

for policy in response.json()["Results"]:
    print(f"{policy['Name']}")
```

## Example using a multiline (a.k.a. heredoc) string for the secret key

The secret key must still be in PEM format even if it's a string instead of a file.

``` Python
my_secret_key='''
-----BEGIN RSA PRIVATE KEY-----
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890/abcdefghizjkl=
-----END RSA PRIVATE KEY-----
'''

session = Session()
session.auth = IntersightAuth(
    api_key_id="XYZ/XYZ/XYZ", 
    secret_key_string=my_secret_key
    )

response = session.get("https://intersight.com/api/v1/ntp/Policies")

if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    sys.exit(1)

for policy in response.json()["Results"]:
    print(f"{policy['Name']}")
```
