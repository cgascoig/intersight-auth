[![CI Tests](https://github.com/cgascoig/intersight-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/cgascoig/intersight-auth/actions/workflows/ci.yml)
# intersight-auth

This module provides an authentication helper for requests to make it easy to make [Intersight API](https://intersight.com/apidocs/introduction/overview/) calls using [requests](https://requests.readthedocs.io/en/latest/).

## Features
- Supports both v2 and v3 Intersight API keys for authentication
- Supports OAuth authentication
- Keys can be supplied as strings or path to a PEM file

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

## Example using OAuth authentication

``` Python
import sys

from intersight_auth import IntersightAuth
from requests import Session

oauth_client_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789"
oauth_client_secret = "1234567890abcdef1234567890abcdef"

session = Session()
session.auth = IntersightAuth(oauth_client_id=oauth_client_id, oauth_client_secret=oauth_client_secret)

response = session.get("https://intersight.com/api/v1/ntp/Policies")

if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    sys.exit(1)

for policy in response.json()["Results"]:
    print(f"{policy['Name']}")
```

## Configuration from environment variables

If you leave the parameters empty, `IntersightAuth` will attempt to automatically discover the API key or OAuth credentials from the environment variables:

``` Python
session = Session()
session.auth = IntersightAuth()

response = session.get("https://intersight.com/api/v1/ntp/Policies")

...
```

The following environment variables can be used:
* IS_KEY_ID
* IS_KEY
* IS_KEY_FILE
* IS_KEY_PASSWORD
* IS_OAUTH_CLIENT_ID
* IS_OAUTH_CLIENT_SECRET
* INTERSIGHT_KEY_ID
* INTERSIGHT_KEY
* INTERSIGHT_KEY_FILE
* INTERSIGHT_KEY_PASSWORD
* INTERSIGHT_OAUTH_CLIENT_ID
* INTERSIGHT_OAUTH_CLIENT_SECRET


## Example of PEM repair

The need to present the secret key in PEM format can be a challenge with some secret management approaches.  The PEM could be collapsed onto a single line, or the whitespace could otherwise be disturbed.  A function is provided to attempt to resolve these kinds of issues.

``` Python

from intersight_auth import IntersightAuth, repair_pem

# This PEM has required the whitespace removed
broken_pem = "-----BEGIN EC PRIVATE KEY-----ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopq-----END EC PRIVATE KEY-----"

session = Session()
session.auth = IntersightAuth(
    api_key_id="XYZ/XYZ/XYZ",
    secret_key_string=repair_pem(broken_pem)
    )

```
