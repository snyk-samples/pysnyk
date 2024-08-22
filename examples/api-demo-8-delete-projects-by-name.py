import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    parser.add_argument(
        "--projectName",
        type=str,
        help="Put in your project name as it appears in Snyk",
        required=True,
    )
    parser.add_argument(
        "--projectOrigin",
        choices=[
            "cli",
            "github",
            "github-enterprise",
            "bitbucket-cloud",
            "bitbucket-server",
            "gitlab",
        ],
        help=" Set this if you want to make sure the project is from a particular place (repo, CLI, etc)",
        required=False,
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
# For example, for GitHub projects it is `[org]/[repo-name]`
# For a Docker scan pushed into Snyk via `snyk monitor`, it is `docker-image|[image-name]`
project_name = args.projectName
project_origin = args.projectOrigin

client = SnykClient(snyk_token)
for project in client.organizations.get(org_id).projects.all():
    if project_name == project.attributes.name and (
        project.attributes.origin == project_origin or not project_origin
    ):
        if project.delete():
            print("Project ID %s deleted" % project.id)
