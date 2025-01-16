#!/usr/bin/env python

import os
import sys

from intersight_auth import IntersightAuth
from requests import Session

import string
import random

base_url = "https://intersight.com/api/v1"

session = Session()
# IntersightAuth will automatically use env vars such as IS_KEY_ID/IS_KEY
session.auth = IntersightAuth()

policy_name = "cg-py-ci-test" + "".join(
    random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
)
print(f"Using policy name {policy_name}")

# Create an NTP policy
print("Creating NTP policy ...")
body = (
    '{"Name": "%s", "Enabled": true, "Organization": {"ClassId":"mo.MoRef", "ObjectType": "organization.Organization", "Selector": "Name eq \'default\'"}, "NtpServers": ["1.1.1.1"]}'
    % (policy_name)
)
response = session.post(base_url + "/ntp/Policies", data=body)
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

moid = response.json()["Moid"]
print("NTP policy created successfully, Moid=" + moid)

# Get NTP Policy
print("Getting NTP policy by moid ...")
response = session.get(base_url + "/ntp/Policies/" + moid)
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

assert response.json()["Name"] == policy_name
print("Successfully got NTP policy by moid")

# Delete NTP Policy
print("Deleting NTP policy ...")
response = session.delete(base_url + "/ntp/Policies/" + moid)
if not response.ok:
    print(f"Error: {response.status_code} {response.reason}")
    print(response.text)
    sys.exit(1)

print("Successfully deleted NTP policy by moid")
