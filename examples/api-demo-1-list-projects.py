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

client = SnykClient(token=snyk_token, debug=True)
for proj in client.organizations.get(org_id).projects.all():
    print("\nProject name: %s" % proj.name)
    print("Project id: %s" % proj.id)
    print("  Issues Found:")
    print("      High  : %s" % proj.issueCountsBySeverity.high)
    print("      Medium: %s" % proj.issueCountsBySeverity.medium)
    print("      Low   : %s" % proj.issueCountsBySeverity.low)

proj1 = client.projects.get("df7667d2-a79f-47ce-875b-99c93bf45426")
proj2 = client.organizations.get(org_id).projects.get(proj1.id)
print(proj1)
print(proj2)