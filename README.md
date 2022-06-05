# intersight-auth

This module provides an authentication helper for requests to make it easy to make [Intersight API](https://intersight.com/apidocs/introduction/overview/) calls using [requests](https://requests.readthedocs.io/en/latest/). 

## Install

```
pip install intersight-auth
```

## Example

```
import sys

from intersight_auth import IntersightAuth
from requests import Session

session = Session()
session.auth = IntersightAuth("key.pem", "XYZ/XYZ/XYZ")

response = session.get("https://intersight.com/api/v1/ntp/Policies")

if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    sys.exit(1)

for policy in response.json()["Results"]:
    print(f"{policy['Name']}")
```

