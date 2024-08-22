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

client = SnykClient(
    token=snyk_token,
    debug=True,
    url="https://api.dev.snyk.io/v1",
    rest_api_url="https://api.dev.snyk.io/rest",
)

for proj in client.organizations.get(org_id).projects.all():
    print("\nProject name: %s" % proj.attributes.name)
    print("  Issues Found:")
    print("      High  : %s" % proj.meta.latest_issue_counts.high)
    print("      Medium: %s" % proj.meta.latest_issue_counts.medium)
    print("      Low   : %s" % proj.meta.latest_issue_counts.low)
    print(proj)

client.patch(
    f"orgs/ac5c4820-a6ac-41fa-8271-8065e6c0062c/projects/49269713-3dc7-4f54-847e-a31ed1bf32d8",
    body={
        "data": {
            "attributes": {
                "business_criticality": ["critical", "medium", "low"],
                "tags": [
                    {"key": "keytest13update", "value": "valuetest13update"},
                    {"key": "keytest23update", "value": "valuetest23update"},
                    {"key": "key1", "value": "value1"}
                ],
                "environment": ["backend", "frontend"],
                "lifecycle": ["development", "production"],
            },
            "id": "ac5c4820-a6ac-41fa-8271-8065e6c0062c",
            "relationships": {},
            "type": "project",
        }
    },
)

params = {"tags": [{"key": "key1", "value": "value1"}], "environment": ["frontend", "backend"]}
project_id: str = "49269713-3dc7-4f54-847e-a31ed1bf32d8"
# # client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get("6a3dcde8-2890-4370-a097-a7633c599de4").delete()
# print(client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id))
# print(client.projects.all(params=params))
# print(client.projects.get(project_id, params=params))
proj = client.projects.get(project_id)
print(proj)
tags = client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id).tags.all()
print("before adding new tag: ", tags)
proj.tags.add("added_tag_key", "added_tag_value")
tags = client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id).tags.all()
print("after adding new tag: ", tags)
proj.tags.delete("added_tag_key", "added_tag_value")
tags = client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id).tags.all()
print("after deleting new tag: ", tags)
print(client.projects.filter(environment=["backend", "frontend"], business_criticality=["low", "medium"]))
client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id).deactivate()
client.organizations.get("ac5c4820-a6ac-41fa-8271-8065e6c0062c").projects.get(project_id).activate()
client.projects.filter(tags=[{"key": "key1", "value": "value1"}], environment=["backend", "frontend"])
