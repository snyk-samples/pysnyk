import re

import pytest  # type: ignore

from snyk.client import SnykClient
from snyk.errors import SnykError, SnykNotFoundError, SnykNotImplementedError
from snyk.models import Integration, Member, Organization, Project, Vulnerability


class TestModels(object):
    @pytest.fixture
    def organization(self):
        org = Organization(
            name="My Other Org",
            id="a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
            slug="my-other-org",
            url="https://api.snyk.io/org/my-other-org",
        )
        org.client = SnykClient("token")
        return org

    @pytest.fixture
    def base_url(self):
        return "https://api.snyk.io/v1"

    @pytest.fixture
    def rest_base_url(self):
        return "https://api.snyk.io/rest"

    @pytest.fixture
    def organization_url(self, base_url, organization):
        return "%s/org/%s" % (base_url, organization.id)

    @pytest.fixture
    def organization_rest_url(self, rest_base_url, organization):
        return "%s/orgs/%s" % (rest_base_url, organization.id)


class TestOrganization(TestModels):
    @pytest.fixture
    def members(self):
        return [
            {"id": "a", "username": "b", "name": "c", "email": "d", "role": "admin"}
        ]

    @pytest.fixture
    def project(self):
        return {
            "data": {
                "attributes": {
                    "build_args": {"root_workspace": "string"},
                    "business_criticality": ["medium"],
                    "created": "2018-10-29T09:50:54.014Z",
                    "environment": ["external", "hosted"],
                    "lifecycle": ["production"],
                    "name": "atokeneduser/goof",
                    "origin": "github",
                    "read_only": "false",
                    "settings": {
                        "auto_dependency_upgrade": {
                            "ignored_dependencies": ["typescript"],
                            "is_enabled": "true",
                            "is_major_upgrade_enabled": "true",
                            "limit": 10,
                            "minimum_age": 365,
                        },
                        "auto_remediation_prs": {
                            "is_backlog_prs_enabled": "true",
                            "is_fresh_prs_enabled": "true",
                            "is_patch_remediation_enabled": "true",
                        },
                        "manual_remediation_prs": {
                            "is_patch_remediation_enabled": "true"
                        },
                        "pull_request_assignment": {
                            "assignees": ["my-github-username"],
                            "is_enabled": "true",
                            "type": "auto",
                        },
                        "pull_requests": {
                            "fail_only_for_issues_with_fix": "true",
                            "policy": "all",
                            "severity_threshold": "high",
                        },
                        "recurring_tests": {"frequency": "daily"},
                    },
                    "status": "active",
                    "tags": [{"key": "some-key", "value": "some-value"}],
                    "target_file": "package.json",
                    "target_reference": "main",
                    "target_runtime": "string",
                    "type": "npm",
                },
                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                "meta": {
                    "cli_monitored_at": "2023-01-13T09:50:54.014Z",
                    "latest_dependency_total": {
                        "total": 0,
                        "updated_at": "2023-01-13T09:50:54.014Z",
                    },
                    "latest_issue_counts": {
                        "critical": 1,
                        "high": 13,
                        "low": 8,
                        "medium": 15,
                        "updated_at": "2023-01-13T09:50:54.014Z",
                    },
                },
                "relationships": {
                    "importer": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "organization": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "owner": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "target": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                },
                "type": "project",
            }
        }

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

    def test_empty_integrations(self, organization, requests_mock):
        matcher = re.compile("integrations$")
        requests_mock.get(matcher, json=[])
        assert [] == organization.integrations.all()

    def test_integrations(self, organization, requests_mock):
        matcher = re.compile("integrations$")
        output = {"github": "not-a-real-id"}
        requests_mock.get(matcher, json=output)
        assert 1 == len(organization.integrations.all())
        assert all(type(x) is Integration for x in organization.integrations.all())
        assert "github" == organization.integrations.first().name

    def test_empty_licenses(self, organization, requests_mock):
        matcher = re.compile("licenses$")
        requests_mock.post(matcher, json={})
        assert [] == organization.licenses.all()

    def test_empty_dependencies(self, organization, organization_url, requests_mock):
        requests_mock.post(
            "%s/dependencies" % organization_url, json={"total": 0, "results": []}
        )
        assert [] == organization.dependencies.all()

    def test_rubygems_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/rubygems/puppet/4.0.0" % base_url, json=blank_test)
        assert organization.test_rubygem("puppet", "4.0.0")

    def test_maven_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get(
            "%s/test/maven/spring/springboot/1.0.0" % base_url, json=blank_test
        )
        assert organization.test_maven("spring", "springboot", "1.0.0")

    def test_python_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/pip/django/4.0.0" % base_url, json=blank_test)
        assert organization.test_python("django", "4.0.0")

    def test_npm_test(self, organization, base_url, blank_test, requests_mock):
        requests_mock.get("%s/test/npm/snyk/1.7.100" % base_url, json=blank_test)
        assert organization.test_npm("snyk", "1.7.100")

    def test_pipfile_test_with_string(
        self, organization, base_url, blank_test, requests_mock
    ):
        requests_mock.post("%s/test/pip" % base_url, json=blank_test)
        assert organization.test_pipfile("django==4.0.0")

    def test_pipfile_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/pip" % base_url, json=blank_test)
        assert organization.test_pipfile(fake_file)

    def test_gemfilelock_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/rubygems" % base_url, json=blank_test)
        assert organization.test_gemfilelock(fake_file)

    def test_packagejson_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/npm" % base_url, json=blank_test)
        assert organization.test_packagejson(fake_file)

    def test_packagejson_test_with_files(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/npm" % base_url, json=blank_test)
        assert organization.test_packagejson(fake_file, fake_file)

    def test_gradlefile_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/gradle" % base_url, json=blank_test)
        assert organization.test_gradlefile(fake_file)

    def test_sbt_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/sbt" % base_url, json=blank_test)
        assert organization.test_sbt(fake_file)

    def test_pom_test_with_file(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/maven" % base_url, json=blank_test)
        assert organization.test_pom(fake_file)

    def test_composer_with_files(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/composer" % base_url, json=blank_test)
        assert organization.test_composer(fake_file, fake_file)

    def test_yarn_with_files(
        self, organization, base_url, blank_test, fake_file, requests_mock
    ):
        requests_mock.post("%s/test/yarn" % base_url, json=blank_test)
        assert organization.test_yarn(fake_file, fake_file)

    def test_missing_package_test(self, organization, base_url, requests_mock):
        requests_mock.get("%s/test/rubygems/puppet/4.0.0" % base_url, status_code=404)
        with pytest.raises(SnykError):
            organization.test_rubygem("puppet", "4.0.0")

    def test_clone_integration(self, organization, organization_url, requests_mock):
        output = {"github": "not-a-real-id"}
        requests_mock.get("%s/integrations" % organization_url, json=output)
        requests_mock.post("%s/integrations/not-a-real-id/clone" % organization_url)
        gh = organization.integrations.first()
        assert gh.clone("target-org-id")
        payload = requests_mock.last_request.json()
        assert payload["destinationOrgPublicId"] == "target-org-id"

    def test_import_git(self, organization, requests_mock):
        integration_matcher = re.compile("integrations$")
        import_matcher = re.compile("import$")
        output = {"github": "not-a-real-id"}
        requests_mock.get(integration_matcher, json=output)
        requests_mock.post(import_matcher)
        gh = organization.integrations.first()
        assert gh.import_git("org", "repo", "branch")
        payload = requests_mock.last_request.json()
        assert len(payload["files"]) == 0
        assert payload["target"]["branch"] == "branch"
        assert payload["target"]["name"] == "repo"
        assert payload["target"]["owner"] == "org"

    def test_import_project(self, organization, requests_mock):
        integration_matcher = re.compile("integrations$")
        import_matcher = re.compile("import$")
        output = {"github": "not-a-real-id"}
        requests_mock.get(integration_matcher, json=output)
        requests_mock.post(import_matcher)
        assert organization.import_project("github.com/org/repo")
        payload = requests_mock.last_request.json()
        assert len(payload["files"]) == 0
        assert payload["target"]["branch"] == "master"
        assert payload["target"]["name"] == "repo"
        assert payload["target"]["owner"] == "org"

    def test_import_project_with_files(self, organization, requests_mock):
        integration_matcher = re.compile("integrations$")
        import_matcher = re.compile("import$")
        output = {"github": "not-a-real-id"}
        requests_mock.get(integration_matcher, json=output)
        requests_mock.post(import_matcher)
        assert organization.import_project(
            "github.com/org/repo", files=["Gemfile.lock"]
        )
        payload = requests_mock.last_request.json()
        assert len(payload["files"]) == 1
        assert payload["files"][0]["path"] == "Gemfile.lock"

    def test_invite(self, organization, requests_mock):
        invite_matcher = re.compile("invite$")
        requests_mock.post(
            invite_matcher, json={"email": "example@example.com", "isAdmin": False}
        )
        assert organization.invite("example@example.com")

    def test_invite_admin(self, organization, requests_mock):
        invite_matcher = re.compile("invite$")
        requests_mock.post(
            invite_matcher, json={"email": "example@example.com", "isAdmin": True}
        )
        assert organization.invite("example@example.com", admin=True)

    def test_get_project(self, organization, project, requests_mock):
        matcher = re.compile(
            "projects/6d5813be-7e6d-4ab8-80c2-1e3e2a454545\\?([^&=]+=[^&=]+&?)+$"
        )
        requests_mock.get(matcher, json=project)
        assert (
            "atokeneduser/goof"
            == organization.projects.get(
                "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
            ).attributes.name
        )

    def test_get_project_organization_has_client(
        self, organization, project, requests_mock
    ):
        matcher = re.compile(
            "projects/6d5813be-7e6d-4ab8-80c2-1e3e2a454545\\?([^&=]+=[^&=]+&?)+$"
        )
        requests_mock.get(matcher, json=project)
        assert (
            organization.projects.get(
                "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
            ).organization.client
            is not None
        )

    def test_filter_projects_by_tag_missing_value(self, organization, requests_mock):
        with pytest.raises(SnykError):
            organization.projects.filter(tags=[{"key": "some-key"}])

    def test_filter_projects_by_tag_missing_key(self, organization, requests_mock):
        with pytest.raises(SnykError):
            organization.projects.filter(tags=[{"value": "some-value"}])

    def test_filter_projects_by_tag_with_extra_key(self, organization, requests_mock):
        with pytest.raises(SnykError):
            organization.projects.filter(
                tags=[{"key": "some-key", "value": "some-value", "extra": "extra"}]
            )

    def test_filter_projects_by_tag(self, organization, requests_mock):
        tags = [{"key": "some-key", "value": "some-value"}]
        projects_matcher = re.compile("projects.*$")
        requests_mock.post(projects_matcher, json=[])
        requests_mock.get(projects_matcher, json=[])
        organization.projects.filter(tags=tags)
        assert requests_mock.called

    def test_filter_projects_not_by_tag(self, organization, requests_mock):
        projects_matcher = re.compile("projects.*$")
        requests_mock.get(projects_matcher, json=[])
        assert organization.projects.filter() == []

    def test_tags_cache(self, organization, project, requests_mock):
        matcher = re.compile(
            "projects/6d5813be-7e6d-4ab8-80c2-1e3e2a454545\\?([^&=]+=[^&=]+&?)+$"
        )
        requests_mock.get(matcher, json=project)
        assert organization.projects.get(
            "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
        )._tags == [{"key": "some-key", "value": "some-value"}]

    def test_get_organization_project_has_tags(
        self, organization, project, requests_mock
    ):
        matcher = re.compile(
            "projects/6d5813be-7e6d-4ab8-80c2-1e3e2a454545\\?([^&=]+=[^&=]+&?)+$"
        )
        requests_mock.get(matcher, json=project)
        assert organization.projects.get(
            "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
        ).tags.all() == [{"key": "some-key", "value": "some-value"}]


class TestProject(TestModels):
    @pytest.fixture
    def project(self, organization):
        project = Project.from_dict(
            {
                "attributes": {
                    "build_args": {"root_workspace": "string"},
                    "business_criticality": ["medium"],
                    "created": "2018-10-29T09:50:54.014Z",
                    "environment": ["external", "hosted"],
                    "lifecycle": ["production"],
                    "name": "atokeneduser/goof",
                    "origin": "github",
                    "read_only": "false",
                    "settings": {
                        "auto_dependency_upgrade": {
                            "ignored_dependencies": ["typescript"],
                            "is_enabled": "true",
                            "is_major_upgrade_enabled": "true",
                            "limit": 10,
                            "minimum_age": 365,
                        },
                        "auto_remediation_prs": {
                            "is_backlog_prs_enabled": "true",
                            "is_fresh_prs_enabled": "true",
                            "is_patch_remediation_enabled": "true",
                        },
                        "manual_remediation_prs": {
                            "is_patch_remediation_enabled": "true"
                        },
                        "pull_request_assignment": {
                            "assignees": ["my-github-username"],
                            "is_enabled": "true",
                            "type": "auto",
                        },
                        "pull_requests": {
                            "fail_only_for_issues_with_fix": "true",
                            "policy": "all",
                            "severity_threshold": "high",
                        },
                        "recurring_tests": {"frequency": "daily"},
                    },
                    "status": "active",
                    "tags": [{"key": "some-key", "value": "some-value"}],
                    "target_file": "package.json",
                    "target_reference": "main",
                    "target_runtime": "string",
                    "type": "npm",
                },
                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                "meta": {
                    "cli_monitored_at": "2023-01-13T09:50:54.014Z",
                    "latest_dependency_total": {
                        "total": 0,
                        "updated_at": "2023-01-13T09:50:54.014Z",
                    },
                    "latest_issue_counts": {
                        "critical": 1,
                        "high": 13,
                        "low": 8,
                        "medium": 15,
                        "updated_at": "2023-01-13T09:50:54.014Z",
                    },
                },
                "relationships": {
                    "importer": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "organization": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "owner": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                    "target": {
                        "data": {
                            "id": "4a72d1db-b465-4764-99e1-ecedad03b06a",
                            "type": "resource",
                        },
                        "links": {
                            "related": {
                                "href": "https://example.com/api/resource/4a72d1db-b465-4764-99e1-ecedad03b06a"
                            }
                        },
                    },
                },
                "type": "project",
            }
        )
        project.organization = organization
        return project

    @pytest.fixture
    def project_url(self, organization_url, project):
        return "%s/project/%s" % (organization_url, project.id)

    @pytest.fixture
    def project_rest_url(self, organization_rest_url, project):
        return "%s/projects/%s" % (organization_rest_url, project.id)

    def test_delete(self, project, project_rest_url, requests_mock):
        requests_mock.delete(project_rest_url)
        assert project.delete()

    def test_failed_delete(self, project, project_rest_url, requests_mock):
        requests_mock.delete(project_rest_url, status_code=500)
        with pytest.raises(SnykError):
            project.delete()

    def test_activate(self, project, project_url, requests_mock):
        requests_mock.post("%s/activate" % project_url, json={})
        assert project.activate()

    def test_failed_activate(self, project, project_url, requests_mock):
        requests_mock.post("%s/activate" % project_url, status_code=500, json={})
        with pytest.raises(SnykError):
            project.activate()

    def test_deactivate(self, project, project_url, requests_mock):
        requests_mock.post("%s/deactivate" % project_url, json={})
        assert project.deactivate()

    def test_failed_deactivate(self, project, project_url, requests_mock):
        requests_mock.post("%s/deactivate" % project_url, status_code=500, json={})
        with pytest.raises(SnykError):
            project.deactivate()

    def test_add_tag(self, project, project_rest_url, requests_mock):
        matcher = re.compile(f"projects/{project.id}\\?([^&=]+=[^&=]+&?)+$")
        response = project.to_dict()
        response["attributes"]["tags"].append({"key": "key", "value": "value"})
        del response["organization"]
        requests_mock.patch(matcher, json=response)
        assert project.tags.add("key", "value")

    def test_delete_tag(self, project, project_url, requests_mock):
        matcher = re.compile(f"projects/{project.id}\\?([^&=]+=[^&=]+&?)+$")
        response = project.to_dict()
        response["attributes"]["tags"] = filter(
            lambda x: x["key"] == "key" and x["value"] == "value",
            response["attributes"]["tags"],
        )
        del response["organization"]
        requests_mock.patch(matcher, json={"key": "key", "value": "value"})
        assert project.tags.delete("key", "value")

    def test_tags(self, project, project_url, requests_mock):
        assert [] == project.tags.all()

    def test_tags_cache(self, project, project_url, requests_mock):
        tags = [{"key": "key", "value": "value"}]
        project._tags = tags
        assert tags == project.tags.all()

    def test_empty_settings(self, project, project_url, requests_mock):
        requests_mock.get("%s/settings" % project_url, json={})
        assert {} == project.settings.all()

    def test_settings(self, project, project_url, requests_mock):
        requests_mock.get(
            "%s/settings" % project_url, json={"PullRequestTestEnabled": True}
        )
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
    ):
        with pytest.raises(SnykNotImplementedError):
            project.ignores.filter(key="value")

    def test_first_fails_on_empty_dict_managers(
        self, project, project_url, requests_mock
    ):
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

    def test_create_jira_issue(self, project, project_url, requests_mock):
        issue_id = "npm:qs:20140806-1"
        return_data = {
            "npm:qs:20140806-1": [{"jiraIssue": {"id": "10001", "key": "EX-1"}}]
        }
        adapter = requests_mock.post(
            "%s/issue/%s/jira-issue" % (project_url, issue_id), json=return_data
        )
        fields = {"summary": "something's wrong", "issuetype": {"id": "10000"}}
        out = project.jira_issues.create(issue_id, fields)
        assert adapter.last_request.json() == {"fields": fields}
        assert out["id"] == "10001"
        assert out["key"] == "EX-1"

    def test_create_jira_issue_with_error(self, project, project_url, requests_mock):
        issue_id = "npm:qs:20140806-1"
        adapter = requests_mock.post(
            "%s/issue/%s/jira-issue" % (project_url, issue_id), json={}
        )
        with pytest.raises(SnykError):
            out = project.jira_issues.create(issue_id, {})

    def test_empty_dependencies(self, project, organization_url, requests_mock):
        requests_mock.post(
            "%s/dependencies" % organization_url, json={"total": 0, "results": []}
        )
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
        )
        assert project.issueset.all().ok

    def test_empty_issues_aggregated(self, project, project_url, requests_mock):
        requests_mock.post(
            "%s/aggregated-issues" % project_url,
            json={"issues": []},
        )
        assert [] == project.issueset_aggregated.all().issues

    def test_empty_vulnerabilities(self, project, project_url, requests_mock):
        requests_mock.post(
            "%s/aggregated-issues" % project_url,
            json={"issues": []},
        )
        assert [] == project.vulnerabilities

    def test_vulnerabilities(self, project, project_url, requests_mock):
        issue_id = "npm:ms:20170412"
        requests_mock.post(
            "%s/aggregated-issues" % project_url,
            json={
                "issues": [
                    {
                        "id": issue_id,
                        "issueType": "vuln",
                        "pkgName": "ms",
                        "pkgVersions": ["1.0.0"],
                        "issueData": {
                            "id": "npm:ms:20170412",
                            "title": "Regular Expression Denial of Service (ReDoS)",
                            "severity": "low",
                            "originalSeverity": "high",
                            "url": "https://security.snyk.io/vuln/npm:ms:20170412",
                            "description": "`## Overview\\r\\n[`ms`](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\\r\\n\\r\\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://security.snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to `ms",
                            "identifiers": {"CVE": [], "CWE": ["CWE-400"], "OSVDB": []},
                            "credit": ["Snyk Security Research Team"],
                            "exploitMaturity": "no-known-exploit",
                            "semver": {
                                "vulnerable": ">=0.7.1 <2.0.0",
                                "unaffected": "",
                            },
                            "publicationTime": "2017-05-15T06:02:45Z",
                            "disclosureTime": "2017-04-11T21:00:00Z",
                            "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            "cvssScore": "3.7",
                            "language": "js",
                            "patches": [
                                {
                                    "id": "patch:npm:ms:20170412:0",
                                    "urls": [
                                        "https://snyk-patches.s3.amazonaws.com/npm/ms/20170412/ms_100.patch"
                                    ],
                                    "version": "=1.0.0",
                                    "comments": [],
                                    "modificationTime": "2019-12-03T11:40:45.863964Z",
                                }
                            ],
                            "nearestFixedInVersion": "2.0.0",
                            "path": "[DocId: 1].input.spec.template.spec.containers[snyk2].securityContext.privileged",
                            "violatedPolicyPublicId": "SNYK-CC-K8S-1",
                            "isMaliciousPackage": True,
                        },
                        "introducedThrough": [{"kind": "imageLayer", "data": {}}],
                        "isPatched": False,
                        "isIgnored": False,
                        "ignoreReasons": [
                            {"reason": "", "expires": "", "source": "cli"}
                        ],
                        "fixInfo": {
                            "isUpgradable": False,
                            "isPinnable": False,
                            "isPatchable": False,
                            "isFixable": False,
                            "isPartiallyFixable": False,
                            "nearestFixedInVersion": "2.0.0",
                            "fixedIn": ["2.0.0"],
                        },
                        "priority": {
                            "score": 399,
                            "factors": [
                                {},
                                "name: `isFixable`",
                                "description: `Has a fix available`",
                            ],
                        },
                        "links": {"paths": ""},
                    }
                ]
            },
        )
        requests_mock.get(
            "{}/issue/{}/paths".format(project_url, issue_id),
            json={
                "snapshotId": "bb00717d-4618-4ceb-bebd-ec268a563e98",
                "paths": [
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                        },
                        {"name": "nyc", "version": "11.9.0"},
                        {"name": "istanbul-lib-instrument", "version": "1.10.1"},
                        {"name": "babel-traverse", "version": "6.26.0"},
                        {"name": "lodash", "version": "4.17.10"},
                    ],
                    [
                        {"name": "tap", "version": "11.1.5", "fixVersion": "11.1.5"},
                        {"name": "nyc", "version": "11.9.0"},
                        {"name": "istanbul-lib-instrument", "version": "1.10.1"},
                        {"name": "babel-template", "version": "6.26.0"},
                        {"name": "lodash", "version": "4.17.10"},
                    ],
                ],
                "total": 1,
            },
        )

        expected = [
            Vulnerability(
                id="npm:ms:20170412",
                url="https://security.snyk.io/vuln/npm:ms:20170412",
                title="Regular Expression Denial of Service (ReDoS)",
                description="`## Overview\\r\\n[`ms`](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\\r\\n\\r\\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://security.snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to `ms",
                upgradePath=[
                    "tap@11.1.5",
                    "nyc@11.9.0",
                    "istanbul-lib-instrument@1.10.1",
                    "babel-template@6.26.0",
                    "lodash@4.17.10",
                ],
                package="ms",
                version="1.0.0",
                severity="low",
                exploitMaturity="no-known-exploit",
                isUpgradable=False,
                isPatchable=False,
                isPinnable=False,
                identifiers={"CVE": [], "CWE": ["CWE-400"], "OSVDB": []},
                semver={"vulnerable": ">=0.7.1 <2.0.0", "unaffected": ""},
                fromPackages=[{"kind": "imageLayer", "data": {}}],
                language="js",
                packageManager="npm",
                publicationTime="2017-05-15T06:02:45Z",
                priorityScore=None,
                disclosureTime="2017-04-11T21:00:00Z",
                credit=["Snyk Security Research Team"],
                CVSSv3="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                cvssScore="3.7",
                ignored=None,
                patched=[],
            )
        ]
        assert expected == project.vulnerabilities

    def test_aggregated_issues_missing_optional_fields(
        self, project, project_url, requests_mock
    ):
        requests_mock.post(
            "%s/aggregated-issues" % project_url,
            json={
                "issues": [
                    {
                        "id": "test",
                        "issueType": "vuln",
                        "pkgName": "test",
                        "pkgVersions": ["1.0.0"],
                        "issueData": {
                            "id": "test",
                            "title": "test",
                            "severity": "test",
                            "url": "https://example.com/test",
                            "exploitMaturity": "test",
                        },
                        "isPatched": False,
                        "isIgnored": False,
                        "fixInfo": {
                            "isUpgradable": False,
                            "isPinnable": False,
                            "isPatchable": False,
                            "isFixable": False,
                            "isPartiallyFixable": False,
                            "nearestFixedInVersion": "2.0.0",
                        },
                    }
                ]
            },
        )
        requests_mock.get(
            "{}/issue/test/paths".format(project_url),
            json={
                "snapshotId": "bb00717d-4618-4ceb-bebd-ec268a563e98",
                "paths": [
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                        },
                        {"name": "nyc", "version": "11.9.0"},
                        {"name": "istanbul-lib-instrument", "version": "1.10.1"},
                        {"name": "babel-traverse", "version": "6.26.0"},
                        {"name": "lodash", "version": "4.17.10"},
                    ],
                    [
                        {"name": "tap", "version": "11.1.5", "fixVersion": "11.1.5"},
                        {"name": "nyc", "version": "11.9.0"},
                        {"name": "istanbul-lib-instrument", "version": "1.10.1"},
                        {"name": "babel-template", "version": "6.26.0"},
                        {"name": "lodash", "version": "4.17.10"},
                    ],
                ],
                "total": 1,
            },
        )

        expected = [
            Vulnerability(
                id="test",
                url="https://example.com/test",
                title="test",
                description="",
                upgradePath=[
                    "tap@11.1.5",
                    "nyc@11.9.0",
                    "istanbul-lib-instrument@1.10.1",
                    "babel-template@6.26.0",
                    "lodash@4.17.10",
                ],
                package="test",
                version="1.0.0",
                severity="test",
                exploitMaturity="test",
                isUpgradable=False,
                isPatchable=False,
                isPinnable=False,
                identifiers=None,
                semver=None,
                packageManager="npm",
                credit=None,
                ignored=None,
                patched=[],
            )
        ]
        assert expected == project.vulnerabilities

    def test_filtering_empty_issues(self, project, project_url, requests_mock):
        requests_mock.post(
            "%s/issues" % project_url,
            json={
                "ok": True,
                "packageManager": "fake",
                "dependencyCount": 0,
                "issues": {"vulnerabilities": [], "licenses": []},
            },
        )
        assert project.issueset.filter(ignored=True).ok

    def test_filtering_empty_issues_aggregated(
        self, project, project_url, requests_mock
    ):
        requests_mock.post(
            "%s/aggregated-issues" % project_url,
            json={"issues": []},
        )

        assert [] == project.issueset_aggregated.filter(ignored=True).issues

    def test_empty_dependency_graph(self, project, project_url, requests_mock):
        requests_mock.get(
            "%s/dep-graph" % project_url,
            json={
                "depGraph": {
                    "schemaVersion": "fake",
                    "pkgManager": {},
                    "pkgs": [],
                    "graph": {"rootNodeId": "fake", "nodes": []},
                }
            },
        )
        assert project.dependency_graph

    def test_empty_licenses(self, project, organization_url, requests_mock):
        requests_mock.post("%s/licenses" % organization_url, json=[])
        assert [] == project.licenses.all()

    def test_empty_license_severity(
        self, organization, organization_url, requests_mock
    ):
        requests_mock.post(
            "%s/licenses" % organization_url,
            json={
                "results": [
                    {
                        "id": "MIT",
                        "dependencies": [
                            {
                                "id": "accepts@1.0.0",
                                "name": "accepts",
                                "version": "1.0.0",
                                "packageManager": "npm",
                            }
                        ],
                        "projects": [
                            {
                                "name": "atokeneduser/goof",
                                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                            }
                        ],
                    }
                ]
            },
        )
        licenses = next(iter(organization.licenses.all()))
        assert licenses.severity is None

    def test_missing_package_version_in_dep_graph(
        self, project, project_url, requests_mock
    ):
        requests_mock.get(
            "%s/dep-graph" % project_url,
            json={
                "depGraph": {
                    "pkgManager": {"name": "fake-package-manager"},
                    "pkgs": [
                        {
                            "id": "fake-package@x.y.z",
                            "info": {"name": "fake-package-name"},
                        }
                    ],
                    "schemaVersion": "fake",
                    "graph": {"rootNodeId": "fake", "nodes": []},
                }
            },
        )
        assert next(iter(project.dependency_graph.pkgs)).info.version is None

    def test_get_project_by_id_default_query_parameters_are_passed(
        self, organization, project, requests_mock
    ):
        matcher = re.compile(
            "orgs/%s/projects/%s\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*meta.latest_issue_counts=true).*?(?=.*expand=target)"
            % (organization.id, project.id)
        )
        requests_mock.get(matcher, json={})
        organization.projects.get(project.id)

        assert requests_mock.call_count == 1

    def test_get_all_projects_default_query_parameters_are_passed(
        self, organization, project, requests_mock
    ):
        matcher = re.compile(
            "orgs/%s/projects\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*meta.latest_issue_counts=true).*?(?=.*expand=target).*?(?=.*limit=([1-9]0)|100)"
            % organization.id
        )
        requests_mock.get(matcher, json={})
        organization.projects.all()

        assert requests_mock.call_count == 1

    def test_filter_projects_has_tags_in_query_params(
        self, organization, project, requests_mock
    ):
        tags = [
            {"key": "some-key", "value": "some-value"},
            {"key": "other-key", "value": "other-value"},
        ]
        matcher = re.compile(
            "orgs/"
            + organization.id
            + "/projects\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*meta.latest_issue_counts=true).*?(?=.*expand=target).*?(?=.*limit=([1-9]0)|100).*?(?=.*tags=some-key%3Asome-value%2Cother-key%3Aother-value)"
        )
        requests_mock.get(matcher, json={})
        organization.projects.filter(tags=tags)
        assert requests_mock.call_count == 1

    def test_filter_projects_has_tags_and_params_in_query_params(
        self, organization, requests_mock
    ):
        params = {
            "environment": ["backend", "frontend"],
            "business_criticality": ["critical", "high"],
        }
        tags = [
            {"key": "some-key", "value": "some-value"},
            {"key": "other-key", "value": "other-value"},
        ]
        matcher = re.compile(
            "orgs/"
            + organization.id
            + "/projects\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*meta.latest_issue_counts=true).*?(?=.*expand=target).*?(?=.*limit=([1-9]0)|100).*?(?=.*tags=some-key%3Asome-value%2Cother-key%3Aother-value).*?(?=.*environment=backend%2Cfrontend).*?(?=.*business_criticality=critical%2Chigh)"
        )

        requests_mock.get(matcher, json={})
        organization.projects.filter(tags=tags, **params)

        assert requests_mock.call_count == 1

    def test_get_all_projects_has_query_params_when_passed(
        self, organization, requests_mock
    ):
        params = {
            "environment": ["backend", "frontend"],
            "business_criticality": ["critical", "high"],
            "tags": [
                {"key": "some-key", "value": "some-value"},
                {"key": "other-key", "value": "other-value"},
            ],
        }

        matcher = re.compile(
            "orgs/"
            + organization.id
            + "/projects\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*meta.latest_issue_counts=true).*?(?=.*expand=target).*?(?=.*limit=([1-9]0)|100).*?(?=.*tags=some-key%3Asome-value%2Cother-key%3Aother-value).*?(?=.*environment=backend%2Cfrontend).*?(?=.*business_criticality=critical%2Chigh)"
        )

        requests_mock.get(matcher, json={})
        organization.projects.all(params=params)
        assert requests_mock.call_count == 1

    def test_update_project_has_query_params_when_passed(
        self, organization, project, requests_mock
    ):
        params = {"expand": "target"}
        matcher = re.compile(
            "orgs/%s/projects/%s\\?(?=.*version=[0-9]{4}-[0-9]{2}-[0-9]{2}).*?(?=.*expand=target)"
            % (organization.id, project.id)
        )

        requests_mock.patch(matcher, json={})

        organization.projects.update(project.id, params=params)

        assert requests_mock.call_count == 1

    def test_update_project_with_every_field(
        self, organization, project, requests_mock
    ):
        matcher = re.compile(
            "orgs/%s/projects/%s\\?version=[0-9]{4}-[0-9]{2}-[0-9]{2}$"
            % (organization.id, project.id)
        )
        tags = [{"key": "key-test", "value": "value-test"}]
        environment = ["backend", "frontend"]
        business_criticality = ["critical", "low", "medium"]
        lifecycle = ["development", "production"]
        test_frequency = "daily"
        owner_id = "768af31a-e3b5-49a9-a612-96eb4ba0a66f"
        body = {
            "data": {
                "id": project.id,
                "attributes": {
                    "tags": tags,
                    "environment": environment,
                    "business_criticality": business_criticality,
                    "lifecycle": lifecycle,
                    "test_frequency": test_frequency,
                },
                "relationships": {"owner": {"data": {"id": owner_id, "type": "user"}}},
                "type": "project",
            },
        }
        requests_mock.patch(matcher, json={})

        resp = organization.projects.update(
            project.id,
            tags=tags,
            environment=environment,
            lifecycle=lifecycle,
            business_criticality=business_criticality,
            test_frequency=test_frequency,
            owner_id=owner_id,
        )
        history = requests_mock.request_history
        assert requests_mock.call_count == 1
        assert resp == True
        assert history[0].json() == body
