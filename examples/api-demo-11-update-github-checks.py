import argparse
import json
from distutils import util

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--projectId", type=str, help="The project ID in Snyk, use 'all' to execute for all projects.", required=True
    )
    parser.add_argument(
        "--pullRequestTestEnabled",
        type=lambda x: bool(util.strtobool(x)),
        help="Whether or not you want to enable PR checks [true|false]",
        required=True,
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId
pullRequestTestEnabled = args.pullRequestTestEnabled


project_settings = {"pullRequestTestEnabled": pullRequestTestEnabled}

client = SnykClient(snyk_token)
projects = client.organizations.get(org_id).projects.all()

github_projects = [
    {"id": p.id, "name": p.attributes.name}
    for p in projects
    if p.attributes.origin == "github"
]

def get_project_by_id(projects, project_id):
    for project in projects:
        if project.id == project_id:
            return project


for proj in github_projects:
    if project_id == proj["id"] or project_id == "all":
        print("%s | %s" % (proj["id"], proj["name"]))
        print("  - updating project settings...")
        resp = get_project_by_id(projects, proj["id"]).settings.update(**project_settings)

        if resp:
            print("  - success: %s" % (proj["id"]))
        else:
            print("  - failed: %s" % (proj["id"]))


print("done")
