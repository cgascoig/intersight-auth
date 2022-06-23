#!/usr/bin/env python

import os
import sys

from intersight_auth import IntersightAuth
from requests import Session

base_url = "https://intersight.com/api/v1"

key_id = os.environ["IS_KEY_ID"]
secret_key = os.environ["IS_KEY"]

session = Session()
session.auth = IntersightAuth(key_id, secret_key_string=secret_key)

# Create an NTP policy
print("Creating NTP policy ...")
response = session.post(base_url+"/ntp/Policies", data='{"Name": "cg-py-ci-test", "Enabled": true, "Organization": {"ClassId":"mo.MoRef", "ObjectType": "organization.Organization", "Selector": "Name eq \'default\'"}, "NtpServers": ["1.1.1.1"]}')
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

moid=response.json()["Moid"]
print("NTP policy created successfully, Moid="+moid)

# Get NTP Policy
print("Getting NTP policy by moid ...")
response = session.get(base_url+"/ntp/Policies/"+moid)
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

assert response.json()["Name"] == "cg-py-ci-test"
print("Successfully got NTP policy by moid")

# Delete NTP Policy
print("Deleting NTP policy ...")
response = session.delete(base_url+"/ntp/Policies/"+moid)
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

print("Successfully deleted NTP policy by moid")