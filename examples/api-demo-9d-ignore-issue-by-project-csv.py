# Format of input file:
# IssueId, ProjectId, ReasonType, Reason, ExpirationDate
# ex:
# Reason Types: [not-vulnerable, wont-fix, temporary-ignore]

import argparse
import json
import re
import sys

import csv

import requests
import urllib3

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--orgId", type=str,
                        help="The Snyk Organisation Id", required=True)
    parser.add_argument("--file", type=str,
                        help="File path to inputs", required=True)
    args = parser.parse_args()

    return args


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
filepath = args.file

# Regex to check if the date is valid
datere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]"
datetimere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]T[0-2][0-4]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9]Z"
time = reason = expires = None

client = SnykClient(token=snyk_token)

with open(filepath) as f:
    reader = csv.reader(f)
    data = list(reader)

    for line in data:
        issue_id = line[0]
        project_id = line[1]
        reason_type = line[2]
        try:
            reason = line[3]
        except IndexError:
            reason = None
        try:
            time = line[4]
        except IndexError:
            time = None

        values_object = {
            "ignorePath": "",
            "reasonType": reason_type,
            "disregardIfFixable": False
        }

        if reason is not None:
            values_object["reason"] = reason
        if expires is not None:
            values_object["expires"] = expires

        if time:
            if re.match(datere, time) or re.match(datetimere, time):
                expires = time
            else:
                print("Please use a date in yyyy-mm-ddThh or yyyy-mm-ddThh:mm:ss.aaaZ format")
                sys.exit()

        print("project id: {} vuln: {}".format(issue_id, project_id))
        api_url = "org/" + org_id + "/project/" + project_id + "/ignore/" + issue_id
        r2 = client.post(api_url, values_object)
