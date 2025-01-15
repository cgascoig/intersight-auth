#!/usr/bin/env python

import json
import os
import random
import string
import sys
from datetime import datetime, timedelta

from intersight_auth import IntersightAuth
from requests import Session

base_url = "https://intersight.com/api/v1"

session = Session()
if "IS_KEY_ID" in os.environ and "IS_KEY" in os.environ:
    print("Using API key authentication")
    session.auth = IntersightAuth(
        os.environ["IS_KEY_ID"], secret_key_string=os.environ["IS_KEY"]
    )
elif "IS_OAUTH_CLIENT_ID" in os.environ and "IS_OAUTH_CLIENT_SECRET" in os.environ:
    print("Using OAuth authentication")
    session.auth = IntersightAuth(
        oauth_client_id=os.environ["IS_OAUTH_CLIENT_ID"],
        oauth_client_secret=os.environ["IS_OAUTH_CLIENT_SECRET"],
    )
else:
    print(
        "Missing credentials for test in environment variables (either IS_KEY_ID/IS_KEY or IS_OAUTH_CLIENT_ID/IS_OAUTH_CLIENT_SECRET)"
    )
    sys.exit(1)

now = f"{datetime.now().isoformat()[:-6].rstrip('0')}000Z"
correctresponse = (
    f"{(datetime.now() - timedelta(days=1)).isoformat()[:-6].rstrip('0')}000Z"
)

query = json.loads(
    """
{
    "queryType": "timeseries",
    "dataSource": "hx",
    "intervals": [
        "P1D/%s"
    ],
    "granularity":  "all"
}
"""
    % (now)
)

print("Getting timeseries data ...")
response = session.post(url=base_url + "/telemetry/TimeSeries", json=query)

if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

thejson = response.json()
assert response.json()[0]["timestamp"] == correctresponse
print("Successfully retrieved timeseries")
