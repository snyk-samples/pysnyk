import argparse
import json
import re
import sys
import requests
import urllib3
from snyk import SnykClient
from utils import get_default_token_path, get_token

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--url", type=str, help="The Snyk server URL, blank for public server.")
    parser.add_argument("--orgId", type=str, default="",
                        help="The Snyk Organisation Id", required=True)
    parser.add_argument("--projectId", type=str, default="",
                        help="Work on issues of a single project instead of all projects.")
    parser.add_argument("--issueSeverity", type=str,
                        help="In addition to ignoring issues that are explicitly listed with --issueIdList, also ignore all which have this severity. Example: --issueSeverity=low")
    # Store issueId as list (--issueIdList=SNYK-JS-HANDLEBARS-173692,SNYK-JS-JSYAML-174129 as example)
    parser.add_argument("--issueIdList", type=str,
                        help="The Snyk Issue IdList", required=True)
    parser.add_argument("--reasonType", type=str,
                        help="Ignore Reason Type", required=True)
    parser.add_argument("--expirationTime", type=str,
                        help="Optional. Expiration time of ignore. e.g. yyyy-mm-dd or yyyy-mm-ddThh:mm:ss.aaaZ",)
    parser.add_argument("--reason", type=str,
                        help="Optional. Reason for ignoring e.g. \"We do not use this library.\"",)
    parser.add_argument("--noDryRun", action='store_true', default=False,
                        help="Really ignore issue.")
    args = parser.parse_args()
    return args
snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
issue_ids = args.issueIdList.split(',') # split issue list to run the loop
reason_type = args.reasonType
time = args.expirationTime
reason = args.reason
# Regex to check if the date is valid
datere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]"
datetimere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]T[0-2][0-4]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9]Z"
expires = None
# Logic to check if a reason and/or time was added
if time is None:
    confirm = 0
else:
    if re.match(datere, time) or re.match(datetimere, time):
        print("Valid Time Arguments")
        expires = time
        confirm = 1
    else:
        print("Please use a date in yyyy-mm-ddThh or yyyy-mm-ddThh:mm:ss.aaaZ format")
        sys.exit()
if reason is None:
    print("No reason given")
else:
    if confirm == 1:
        print("Reason given!")
        confirm = 2
    else:
        confirm = 3
client = SnykClient(snyk_token, args.url, debug=True)
# API call to collect every project in all of a customers orgs

if args.projectId != "":
    projects = [client.organizations.get(org_id).projects.get(args.projectId)]
else:
    projects = client.organizations.get(org_id).projects.all()

for proj in projects:
    print("\nProject name: %s" % proj.name)
    print("  Issues Found:")
    print("      High  : %s" % proj.issueCountsBySeverity.high)
    print("      Medium: %s" % proj.issueCountsBySeverity.medium)
    print("      Low   : %s" % proj.issueCountsBySeverity.low)
    url = "org/" + org_id + "/project/" + proj.id + "/issues"
    print(url)
    # API call to grab all of the issue
    r = client.post(url, None)
    # Converts JSON to a python dict
    parsed_input = r.json()
    print (parsed_input)
    issues = parsed_input["issues"]
    if not args.noDryRun:
        print("List the Vulnerbilities")
        print (issues["vulnerabilities"])
    for i in issues["vulnerabilities"]:
        if i["severity"] == args.issueSeverity or i["id"] in issue_ids:
            values_object = {
                "ignorePath": "",
                "reasonType": reason_type,
                "disregardIfFixable": False
            }
            if reason is not None:
                values_object["reason"] = reason
            if expires is not None:
                values_object["expires"] = expires
            api_url = "org/%s/project/%s/ignore/%s" % (org_id, proj.id , i["id"])
            if args.noDryRun:
                client.post(api_url, values_object)
            else:
                print("dry run enabled: would ignore: ", api_url, values_object)
