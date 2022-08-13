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

key_id = os.environ["IS_KEY_ID"]
secret_key = os.environ["IS_KEY"]

session = Session()
session.auth = IntersightAuth(key_id, secret_key_string=secret_key)


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
