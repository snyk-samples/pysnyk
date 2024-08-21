import os
import re

import pytest  # type: ignore

from snyk import SnykClient
from snyk.__version__ import __version__
from snyk.errors import SnykError, SnykNotFoundError
from snyk.models import Organization, Project
from snyk.utils import load_test_data

TEST_DATA = os.path.join(os.path.dirname(__file__), "test_data")

REST_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
REST_URL = "https://api.snyk.io/rest"
REST_VERSION = "2024-06-21"

V3_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
V3_URL = "https://api.snyk.io/v3"
V3_VERSION = "2022-02-16~experimental"


class TestSnykClient(object):
    @pytest.fixture
    def client(self):
        return SnykClient("token")

    def test_default_api_url(self, client):
        assert client.api_url == "https://api.snyk.io/v1"

    def test_overriding_api_url(self):
        url = "https://api.notsnyk.io/v1"
        client = SnykClient("token", url)
        assert client.api_url == url

    def test_token_added_to_headers(self, client):
        assert client.api_headers["Authorization"] == "token token"

    def test_user_agent_added_to_headers(self, client):
        assert client.api_headers["User-Agent"] == "pysnyk/%s" % __version__

    def test_overriding_user_agent(self):
        ua = "test"
        client = SnykClient("token", user_agent=ua)
        assert client.api_headers["User-Agent"] == ua

    def test_token_added_to_post_headers(self, client):
        assert client.api_post_headers["Authorization"] == "token token"

    def test_post_headers_use_correct_mimetype(self, client):
        assert client.api_post_headers["Content-Type"] == "application/json"

    def test_get_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", text="pong")
        assert client.get("sample")

    def test_put_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", text="pong")
        assert client.put("sample", {})

    def test_delete_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample")
        assert client.delete("sample")

    def test_post_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample")
        assert client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_post_raises_error(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_put_retries_and_raises_error(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 4

    def test_delete_retries_and_raises_error(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 4

    def test_get_retries_and_raises_error(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 4

    def test_post_retries_and_raises_error(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 4

    def test_put_raises_error(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 1

    def test_delete_raises_error(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 1

    def test_get_raises_error(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 1

    def test_empty_organizations(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/orgs", json={})
        assert [] == client.organizations.all()

    @pytest.fixture
    def organizations(self):
        return load_test_data(TEST_DATA, "organizations")

    @pytest.fixture
    def projects(self):
        return load_test_data(TEST_DATA, "projects")

    def test_loads_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert len(client.organizations.all()) == 2

    def test_first_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        org = client.organizations.first()
        assert "defaultOrg" == org.name

    def test_first_organizations_on_empty(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/orgs", json={})
        with pytest.raises(SnykNotFoundError):
            client.organizations.first()

    def test_filter_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert 1 == len(client.organizations.filter(name="defaultOrg"))

    def test_filter_organizations_empty(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert [] == client.organizations.filter(name="not present")

    def test_loads_organization(self, requests_mock, client, organizations):
        key = organizations["orgs"][0]["id"]
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        org = client.organizations.get(key)
        assert "defaultOrg" == org.name

    def test_non_existent_organization(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        with pytest.raises(SnykNotFoundError):
            client.organizations.get("not-present")

    def test_organization_type(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert all(type(x) is Organization for x in client.organizations.all())

    def test_organization_attributes(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert client.organizations.first().name == "defaultOrg"

    def test_organization_load_group(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert client.organizations.all()[1].group.name == "ACME Inc."

    def test_empty_projects(self, requests_mock, rest_client, organizations):
        requests_mock.get("https://api.snyk.io/rest/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json={})
        assert [] == rest_client.projects.all()

    def test_projects(
        self, requests_mock, client, rest_client, organizations, projects
    ):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        assert len(client.projects.all()) == 2
        assert all(type(x) is Project for x in client.projects.all())

    def test_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        assert (
            "testing-new-name"
            == client.projects.get(
                "f9fec29a-d288-40d9-a019-cedf825e6efb"
            ).attributes.name
        )

    def test_non_existent_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        with pytest.raises(SnykNotFoundError):
            client.projects.get("not-present")

    @pytest.fixture
    def rest_client(self):
        return SnykClient("token", version="2024-06-21", url="https://api.snyk.io/rest")

    @pytest.fixture
    def v3_client(self):
        return SnykClient(
            "token", version="2022-02-16~experimental", url="https://api.snyk.io/v3"
        )

    @pytest.fixture
    def v3_groups(self):
        return load_test_data(TEST_DATA, "v3_groups")

    @pytest.fixture
    def v3_targets_page1(self):
        return load_test_data(TEST_DATA, "v3_targets_page1")

    @pytest.fixture
    def v3_targets_page2(self):
        return load_test_data(TEST_DATA, "v3_targets_page2")

    @pytest.fixture
    def v3_targets_page3(self):
        return load_test_data(TEST_DATA, "v3_targets_page3")

    @pytest.fixture
    def rest_groups(self):
        return load_test_data(TEST_DATA, "rest_groups")

    @pytest.fixture
    def rest_targets_page1(self):
        return load_test_data(TEST_DATA, "rest_targets_page1")

    @pytest.fixture
    def rest_targets_page2(self):
        return load_test_data(TEST_DATA, "rest_targets_page2")

    @pytest.fixture
    def rest_targets_page3(self):
        return load_test_data(TEST_DATA, "rest_targets_page3")

    def test_v3get(self, requests_mock, v3_client, v3_targets_page1):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        t_params = {"limit": 10}

        targets = v3_client.get(f"orgs/{V3_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_v3_pages(
        self,
        requests_mock,
        v3_client,
        v3_targets_page1,
        v3_targets_page2,
        v3_targets_page3,
    ):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D",
            json=v3_targets_page2,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D",
            json=v3_targets_page3,
        )
        t_params = {"limit": 10}

        data = v3_client.get_v3_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

    def test_rest_get(self, requests_mock, rest_client, rest_targets_page1):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}",
            json=rest_targets_page1,
        )
        t_params = {"limit": 10}

        targets = rest_client.get(f"orgs/{REST_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_rest_pages(
        self,
        requests_mock,
        rest_client,
        rest_targets_page1,
        rest_targets_page2,
        rest_targets_page3,
    ):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}",
            json=rest_targets_page1,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D",
            json=rest_targets_page2,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D",
            json=rest_targets_page3,
        )
        t_params = {"limit": 10}

        data = rest_client.get_rest_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

    def test_rest_limit_deduplication(self, requests_mock, rest_client):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/projects?limit=100&version={REST_VERSION}"
        )
        params = {"limit": 10}
        rest_client.get(f"orgs/{REST_ORG}/projects?limit=100", params)

    def test_patch_update_project_should_return_updated_project(
        self, requests_mock, rest_client, projects
    ):
        project = projects["data"][0]
        matcher = re.compile(
            f"orgs/{REST_ORG}/projects/{project['id']}\\?([^&=]+=[^&=]+&?)+$"
        )
        body = {
            "data": {
                "attributes": {
                    "business_criticality": ["critical"],
                    "environment": ["backend", "internal"],
                    "lifecycle": ["development"],
                    "tags": [{"key": "key-test", "value": "value-test"}],
                }
            }
        }
        project["attributes"] = {**project["attributes"], **body["data"]["attributes"]}
        requests_mock.patch(matcher, json=project, status_code=200)

        response = rest_client.patch(
            f"orgs/{REST_ORG}/projects/{project['id']}",
            body=project,
            params={"expand": "target"},
        )

        response_data = response.json()
        assert response.status_code == 200
        assert response_data == project

    def test_token_added_to_patch_headers(self, client):
        assert client.api_patch_headers["Authorization"] == "token token"

    def test_patch_headers_use_correct_mimetype(self, client):
        assert client.api_patch_headers["Content-Type"] == "application/vnd.api+json"

    def test_patch_has_version_in_query_params(self, client, requests_mock):
        matcher = re.compile("\\?version=2[0-9]{3}-[0-9]{2}-[0-9]{2}$")
        requests_mock.patch(matcher, json={}, status_code=200)
        client.patch(
            f"{REST_URL}/orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb",
            body={},
        )

        assert requests_mock.call_count == 1

    def test_patch_update_project_when_invalid_should_throw_exception(
        self, requests_mock, rest_client
    ):
        matcher = re.compile(
            "projects/f9fec29a-d288-40d9-a019-cedf825e6efb\\?version=2[0-9]{3}-[0-9]{2}-[0-9]{2}$"
        )
        body = {"attributes": {"environment": ["backend"]}}

        requests_mock.patch(matcher, json=body, status_code=400)
        with pytest.raises(SnykError):
            rest_client.patch(
                f"orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb",
                body=body,
            )

        assert requests_mock.call_count == 1

    def test_post_request_rest_api_when_specified(self, requests_mock, client):
        matcher = re.compile(
            f"{REST_URL}/orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb\\?version={REST_VERSION}$"
        )
        requests_mock.post(matcher, json={}, status_code=200)
        params = {"version": REST_VERSION}
        client.post(
            f"{REST_URL}/orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb",
            body={},
            params=params,
            use_rest=True,
        )

        assert requests_mock.call_count == 1

    def test_put_request_rest_api_when_specified(self, requests_mock, client):
        matcher = re.compile(
            f"{REST_URL}/orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb\\?version={REST_VERSION}$"
        )
        requests_mock.put(matcher, json={}, status_code=200)
        params = {"version": REST_VERSION}
        client.put(
            f"{REST_URL}/orgs/{REST_ORG}/projects/f9fec29a-d288-40d9-a019-cedf825e6efb",
            body={},
            params=params,
            use_rest=True,
        )

        assert requests_mock.call_count == 1

    def test_put_request_v1_api_when_specified(self, requests_mock, client):
        matcher = re.compile(
            f"^https://api.snyk.io/v1/org/{REST_ORG}/project/f9fec29a-d288-40d9-a019-cedf825e6efb"
        )
        requests_mock.put(matcher, json={}, status_code=200)
        client.put(
            f"org/{REST_ORG}/project/f9fec29a-d288-40d9-a019-cedf825e6efb",
            body={},
            use_rest=False,
        )

        assert requests_mock.call_count == 1

    def test_delete_use_rest_when_specified(self, requests_mock, client):
        matcher = re.compile(
            "^%s/orgs/%s\\?version=2[0-9]{3}-[0-9]{2}-[0-9]{2}$" % (REST_URL, REST_ORG)
        )
        requests_mock.delete(matcher, json={}, status_code=200)

        client.delete(f"orgs/{REST_ORG}", use_rest=True)
        assert requests_mock.call_count == 1

    def test_delete_use_v1_when_specified(self, requests_mock, client):
        matcher = re.compile("^%s/orgs/%s" % ("https://api.snyk.io/v1", REST_ORG))
        requests_mock.delete(matcher, json={}, status_code=200)

        client.delete(f"orgs/{REST_ORG}")
        assert requests_mock.call_count == 1

    def test_delete_redirects_to_rest_api_for_delete_project(
        self, client, requests_mock, projects
    ):
        project = projects["data"][0]
        matcher = re.compile(
            "orgs/%s/projects/%s\\?version=2[0-9]{3}-[0-9]{2}-[0-9]{2}$"
            % (REST_ORG, project["id"])
        )

        requests_mock.delete(matcher, json={}, status_code=200)

        client.delete(f"org/{REST_ORG}/project/{project['id']}")

        assert requests_mock.call_count == 1
