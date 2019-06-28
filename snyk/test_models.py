import re

import pytest  # type: ignore

from snyk.models import Organization, Project, Member
from snyk.client import SnykClient
from snyk.errors import SnykError, SnykNotFoundError, SnykNotImplementedError


class TestModels(object):
    @pytest.fixture
    def organization(self):
        org = Organization(
            name="My Other Org", id="a04d9cbd-ae6e-44af-b573-0556b0ad4bd2"
    ***REMOVED***
        org.client = SnykClient("token")
        return org

    @pytest.fixture
    def base_url(self):
        return "https://snyk.io/api/v1"

    @pytest.fixture
    def organization_url(self, base_url, organization):
        return "%s/org/%s" % (base_url, organization.id)


class TestOrganization(TestModels):
    @pytest.fixture
    def members(self):
        return [
            {"id": "a", "username": "b", "name": "c", "email": "d", "role": "admin"}
        ]

    @pytest.fixture
    def blank_test(self):
        return {
            "ok": True,
            "packageManager": "blank",
            "dependencyCount": 0,
            "issues": {"licenses": [], "vulnerabilities": []},
        }

    @pytest.fixture
    def fake_file(self):
        class FakeFile(object):
            def read(self):
                return "content"

        return FakeFile()

    def test_empty_members(self, organization, requests_mock):
        matcher = re.compile("members$")
        requests_mock.get(matcher, json=[])
        assert [] == organization.members.all()

    def test_members(self, organization, requests_mock, members):
        matcher = re.compile("members$")
        requests_mock.get(matcher, json=members)
        assert 1 == len(organization.members.all())
        assert all(type(x) is Member for x in organization.members.all())
        assert "admin" == organization.members.first().role

    def test_empty_entitlements(self, organization, requests_mock):
        matcher = re.compile("entitlements$")
        requests_mock.get(matcher, json={})
        assert {} == organization.entitlements.all()

    def test_entitlements(self, organization, requests_mock):
        matcher = re.compile("entitlements$")
        output = {"reports": True}
        requests_mock.get(matcher, json=output)
        assert output == organization.entitlements.all()

    def test_empty_licenses(self, organization, requests_mock):
        matcher = re.compile("licenses$")
        requests_mock.post(matcher, json={})
        assert [] == organization.licenses.all()

    def test_empty_dependencies(self, organization, organization_url, requests_mock):
        requests_mock.post(
            "%s/dependencies" % organization_url, json={"total": 0, "results": []}
    ***REMOVED***
        assert [] == organization.dependencies.all()

    def test_rubygems_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/rubygems/puppet/4.0.0" % base_url, json=blank_test)
        assert organization.test_rubygem("puppet", "4.0.0")

    def test_maven_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get(
            "%s/test/maven/spring/springboot/1.0.0" % base_url, json=blank_test
    ***REMOVED***
        assert organization.test_maven("spring", "springboot", "1.0.0")

    def test_python_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/pip/django/4.0.0" % base_url, json=blank_test)
        assert organization.test_python("django", "4.0.0")

    def test_npm_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/npm/snyk/1.7.100" % base_url, json=blank_test)
        assert organization.test_npm("snyk", "1.7.100")

    def test_pipfile_test_with_string(
        self, organization, base_url, blank_test, requests_mock
***REMOVED***:
        requests_mock.post("%s/test/pip" % base_url, json=blank_test)
        assert organization.test_pipfile("django==4.0.0")

    def test_pipfile_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:
        requests_mock.post("%s/test/pip" % base_url, json=blank_test)
        assert organization.test_pipfile(fake_file)

    def test_gemfilelock_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:
        requests_mock.post("%s/test/rubygems" % base_url, json=blank_test)
        assert organization.test_gemfilelock(fake_file)

    def test_packagejson_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:

        requests_mock.post("%s/test/npm" % base_url, json=blank_test)
        assert organization.test_packagejson(fake_file)

    def test_gradlefile_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:

        requests_mock.post("%s/test/gradle" % base_url, json=blank_test)
        assert organization.test_gradlefile(fake_file)

    def test_sbt_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:

        requests_mock.post("%s/test/sbt" % base_url, json=blank_test)
        assert organization.test_sbt(fake_file)

    def test_pom_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
***REMOVED***:

        requests_mock.post("%s/test/maven" % base_url, json=blank_test)
        assert organization.test_pom(fake_file)

    def test_missing_package_test(self, organization, base_url, requests_mock):
        requests_mock.get("%s/test/rubygems/puppet/4.0.0" % base_url, status_code=404)
        with pytest.raises(SnykError):
            organization.test_rubygem("puppet", "4.0.0")


class TestProject(TestModels):
    @pytest.fixture
    def project(self, organization):
        return Project(
            name="atokeneduser/goof",
            id="6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
            created="2018-10-29T09:50:54.014Z",
            origin="cli",
            type="npm",
            readOnly="false",
            testFrequency="daily",
            totalDependencies=438,
            issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
            lastTestedDate="2019-02-05T06:21:00.000Z",
            organization=organization,
    ***REMOVED***

    @pytest.fixture
    def project_url(self, organization_url, project):
        return "%s/project/%s" % (organization_url, project.id)

    def test_delete(self, project, project_url, requests_mock):
        requests_mock.delete(project_url)
        assert project.delete()

    def test_failed_delete(self, project, project_url, requests_mock):
        requests_mock.delete(project_url, status_code=500)
        with pytest.raises(SnykError):
            project.delete()

    def test_empty_settings(self, project, project_url, requests_mock):
        requests_mock.get("%s/settings" % project_url, json={})
        assert {} == project.settings.all()

    def test_settings(self, project, project_url, requests_mock):
        requests_mock.get(
            "%s/settings" % project_url, json={"PullRequestTestEnabled": True}
    ***REMOVED***
        assert 1 == len(project.settings.all())
        assert project.settings.get("PullRequestTestEnabled")

    def test_update_settings(self, project, project_url, requests_mock):
        requests_mock.put("%s/settings" % project_url)
        assert project.settings.update(pull_request_test_enabled=True)

    def test_empty_ignores(self, project, project_url, requests_mock):
        requests_mock.get("%s/ignores" % project_url, json={})
        assert {} == project.ignores.all()

    def test_ignores(self, project, project_url, requests_mock):
        requests_mock.get("%s/ignores" % project_url, json={"key": [{}]})
        assert 1 == len(project.ignores.all())
        assert [{}] == project.ignores.get("key")

    def test_missing_ignores(self, project, project_url, requests_mock):
        requests_mock.get("%s/ignores" % project_url, json={})
        with pytest.raises(SnykNotFoundError):
            project.ignores.get("not-present")

    def test_filter_not_implemented_on_dict_managers(
        self, project, project_url, requests_mock
***REMOVED***:
        with pytest.raises(SnykNotImplementedError):
            project.ignores.filter(key="value")

    def test_first_fails_on_empty_dict_managers(
        self, project, project_url, requests_mock
***REMOVED***:
        requests_mock.get("%s/ignores" % project_url, json={})
        with pytest.raises(SnykNotFoundError):
            project.ignores.first()

    def test_empty_jira_issues(self, project, project_url, requests_mock):
        requests_mock.get("%s/jira-issues" % project_url, json={})
        assert {} == project.jira_issues.all()

    def test_jira_issues(self, project, project_url, requests_mock):
        requests_mock.get("%s/jira-issues" % project_url, json={"key": [{}]})
        assert 1 == len(project.jira_issues.all())
        assert [{}] == project.jira_issues.get("key")

    def test_empty_dependencies(self, project, organization_url, requests_mock):
        requests_mock.post(
            "%s/dependencies" % organization_url, json={"total": 0, "results": []}
    ***REMOVED***
        assert [] == project.dependencies.all()

    def test_empty_issues(self, project, project_url, requests_mock):
        requests_mock.post(
            "%s/issues" % project_url,
            json={
                "ok": True,
                "packageManager": "fake",
                "dependencyCount": 0,
                "issues": {"vulnerabilities": [], "licenses": []},
            },
    ***REMOVED***
        assert project.issues.all().ok

    def test_filtering_empty_issues(self, project, project_url, requests_mock):
        requests_mock.post(
            "%s/issues" % project_url,
            json={
                "ok": True,
                "packageManager": "fake",
                "dependencyCount": 0,
                "issues": {"vulnerabilities": [], "licenses": []},
            },
    ***REMOVED***
        assert project.issues.filter(ignored=True).ok

    def test_filter_not_implemented_on_singleton_managers(self, project, requests_mock):
        with pytest.raises(SnykNotImplementedError):
            project.dependency_graph.filter(key="value")

    def test_first_not_implemented_on_singleton_managers(self, project, requests_mock):
        with pytest.raises(SnykNotImplementedError):
            project.issues.first()

    def test_get_not_implemented_on_singleton_managers(self, project, requests_mock):
        with pytest.raises(SnykNotImplementedError):
            project.issues.get("key")

    def test_empty_dependency_graph(self, project, project_url, requests_mock):
        requests_mock.get(
            "%s/dep-graph" % project_url,
            json={
                "schemaVersion": "fake",
                "pkgManager": {},
                "pkgs": [],
                "graph": {"rootNodeId": "fake", "nodes": []},
            },
    ***REMOVED***
        assert project.dependency_graph.all()

    def test_empty_licenses(self, project, organization_url, requests_mock):
        requests_mock.post("%s/licenses" % organization_url, json=[])
        assert [] == project.licenses.all()
