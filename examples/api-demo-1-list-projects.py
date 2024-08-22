import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId

client = SnykClient(token=snyk_token)
for proj in client.organizations.get(org_id).projects.all():
    print("\nProject name: %s" % proj.attributes.name)
    print("  Issues Found:")
    print("      High  : %s" % proj.meta.latest_issue_counts.high)
    print("      Medium: %s" % proj.meta.latest_issue_counts.medium)
    print("      Low   : %s" % proj.meta.latest_issue_counts.low)