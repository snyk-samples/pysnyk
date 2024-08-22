import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
show_dependencies = True
show_projects = True
client = SnykClient(snyk_token)
projects = client.organizations.get(org_id).projects.all()

for proj in projects:
    project_id = proj.id
    project_name = proj.attributes.name
    ignores = proj.ignores.all()

    if len(ignores) > 0:
        # issues exist for this project
        print("Project ID: %s" % project_id)
        print("Project Name: %s" % project_name)
        for next_issue_id in ignores.keys():
            print("  Ignored Issue ID: %s" % next_issue_id)
            next_issue_ignores = ignores[next_issue_id]
            for next_ignore in next_issue_ignores:
                for i_key in next_ignore.keys():
                    i_value = next_ignore[i_key]
                    reason = i_value["reason"]
                    created_date = i_value["created"]
                    expires_date = i_value["expires"]
                    ignored_by_user = i_value["ignoredBy"]
                    ignored_by_id = ignored_by_user["id"]
                    ignored_by_name = ignored_by_user["name"]
                    ignored_by_email = ignored_by_user["email"]
                    reason_type = i_value["reasonType"]
                    disregard_if_fixable = i_value["disregardIfFixable"]
                    print("    Ignore reason: %s " % reason)
                    print("    Ignore created: %s " % created_date)
                    print("    Ignore expires: %s " % expires_date)
                    print("    Ignored by (User ID): %s " % ignored_by_id)
                    print("    Ignored by (name): %s " % ignored_by_name)
                    print("    Ignored by (email) %s " % ignored_by_email)
                    print("    Ignore type: %s " % reason_type)
                    print(
                        "    Ignore is disregard if fixable: %s " % disregard_if_fixable
                    )

        print("\n")
