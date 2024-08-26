import abc
import copy
from typing import Any, Dict, List, Optional

from deprecation import deprecated  # type: ignore

from .errors import SnykError, SnykNotFoundError, SnykNotImplementedError
from .utils import snake_to_camel


class Manager(abc.ABC):
    def __init__(self, klass, client, instance=None):
        self.klass = klass
        self.client = client
        self.instance = instance

    @abc.abstractmethod
    def all(self):
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return next(x for x in self.all() if x.id == id)
        except StopIteration:
            raise SnykNotFoundError

    def first(self):
        try:
            return self.all()[0]
        except IndexError:
            raise SnykNotFoundError

    def _filter_by_kwargs(self, data, **kwargs: Any):
        if kwargs:
            for key, value in kwargs.items():
                data = [x for x in data if getattr(x, key) == value]
        return data

    def filter(self, **kwargs: Any):
        return self._filter_by_kwargs(self.all(), **kwargs)

    @staticmethod
    def factory(klass, client, instance=None):
        try:
            if isinstance(klass, str):
                key = klass
            else:
                key = klass.__name__
            manager = {
                "Project": ProjectManager,
                "Organization": OrganizationManager,
                "Member": MemberManager,
                "License": LicenseManager,
                "Dependency": DependencyManager,
                "Entitlement": EntitlementManager,
                "Setting": SettingManager,
                "Ignore": IgnoreManager,
                "JiraIssue": JiraIssueManager,
                "DependencyGraph": DependencyGraphManager,
                "IssueSet": IssueSetManager,
                "IssueSetAggregated": IssueSetAggregatedManager,
                "Integration": IntegrationManager,
                "IntegrationSetting": IntegrationSettingManager,
                "Tag": TagManager,
                "IssuePaths": IssuePathsManager,
            }[key]
            return manager(klass, client, instance)
        except KeyError:
            raise SnykError


class DictManager(Manager):
    @abc.abstractmethod
    def all(self) -> Dict[str, Any]:
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return self.all()[id]
        except KeyError:
            raise SnykNotFoundError

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError

    def first(self):
        try:
            return next(iter(self.all().items()))
        except StopIteration:
            raise SnykNotFoundError


class SingletonManager(Manager):
    @abc.abstractmethod
    def all(self) -> Any:
        pass  # pragma: no cover

    def first(self):
        raise SnykNotImplementedError  # pragma: no cover

    def get(self, id: str):
        raise SnykNotImplementedError  # pragma: no cover

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError  # pragma: no cover


class OrganizationManager(Manager):
    def all(self):
        resp = self.client.get("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(self.klass.from_dict(org_data))
        for org in orgs:
            org.client = self.client
        return orgs


class TagManager(Manager):
    def all(self):
        return self.instance._tags

    def add(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        new_tags: List[Dict[str, str]] = self.all()
        new_tags.append(tag)
        return bool(self.__update_tags(new_tags))

    def delete(self, key, value) -> bool:
        filtered_tags: List[Dict[str, str]] = [
            tag for tag in self.all() if tag["key"] != key and tag["value"] != value
        ]

        return bool(self.__update_tags(filtered_tags))

    def __update_tags(self, tags: List[Dict[str, str]]):
        path = "orgs/%s/projects/%s" % (
            self.instance.organization.id,
            self.instance.id,
        )
        body: Dict[str, Any] = {
            "data": {
                "attributes": {
                    "tags": tags,
                },
                "id": self.instance.id,
                "relationships": {},
                "type": "project",
            }
        }

        return self.client.patch(path, body)


class ProjectManager(Manager):
    def _query(self, next_url: str = None, params: Dict[str, Any] = {}):
        projects = []
        if "limit" not in params:
            params["limit"] = 100

        if self.instance:
            path = "/orgs/%s/projects" % self.instance.id if not next_url else next_url

            # Append to params if we've got tags
            if "tags" in params and not next_url:
                for tag in params["tags"]:
                    if "key" not in tag or "value" not in tag or len(tag.keys()) != 2:
                        raise SnykError("Each tag must contain only a key and a value")
                data = [f'{d["key"]}:{d["value"]}' for d in params["tags"]]
                params["tags"] = ",".join(data)

            # Append the issue count param to the params if this is the first page
            if not next_url:
                params["meta.latest_issue_counts"] = "true"
                params["expand"] = "target"

            # And lastly, make the API call
            resp = self.client.get(
                path,
                version="2024-06-21",
                params=params,
                exclude_params=True if next_url else False,
                exclude_version=True if next_url else False,
            )

            if "data" in resp.json():
                # Process projects in current response
                for project_data in resp.json()["data"]:
                    project_data["organization"] = self.instance.to_dict()
                    try:
                        project_data["_tags"] = project_data["attributes"]["tags"]
                        del project_data["attributes"]["tags"]
                    except KeyError:
                        pass
                    projects.append(self.klass.from_dict(project_data))

                # If we have another page, then process this page too
                if "next" in resp.json().get("links", {}):
                    next_url = resp.json().get("links", {})["next"]
                    projects.extend(self._query(next_url=next_url, params=params))

            for x in projects:
                x.organization = self.instance
        else:
            for org in self.client.organizations.all():
                projects.extend(org.projects.all(params=params))
        return projects

    def all(self, params: Dict[str, Any] = {}):
        copy_params = copy.deepcopy(params)
        return self._query(params=copy_params)

    def filter(self, tags: List[Dict[str, str]] = [], **kwargs: Any):
        params = {**kwargs, **{"tags": tags}} if len(tags) > 0 else kwargs
        return self.all(params=params)

    def get(self, id: str, params: Dict[str, Any] = {}):
        if self.instance:
            copy_params = copy.deepcopy(params)
            if "meta.latest_issue_counts" not in copy_params:
                copy_params["meta.latest_issue_counts"] = "true"
            if "expand" not in copy_params:
                copy_params["expand"] = "target"
            version = (
                copy_params["version"] if "version" in copy_params else "2024-06-21"
            )
            copy_params.pop("version", None)

            path = "orgs/%s/projects/%s" % (self.instance.id, id)

            if "tags" in copy_params:
                for tag in copy_params["tags"]:
                    if "key" not in tag or "value" not in tag or len(tag.keys()) != 2:
                        raise SnykError("Each tag must contain only a key and a value")
                data = [f'{d["key"]}:{d["value"]}' for d in copy_params["tags"]]
                copy_params["tags"] = ",".join(data)

            resp = self.client.get(path, params=copy_params, version=version)
            project_data = resp.json()
            if "data" in project_data:
                project_data = project_data["data"]
                project_data["organization"] = self.instance.to_dict()
                # We move tags to _tags as a cache, to avoid the need for additional requests
                # when working with tags. We want tags to be the manager
                try:
                    project_data["_tags"] = project_data["attributes"]["tags"]
                    del project_data["attributes"]["tags"]
                except KeyError:
                    pass
                # if project_data.get("totalDependencies") is None:
                #     project_data["totalDependencies"] = 0
                project_klass = self.klass.from_dict(project_data)
                project_klass.organization = self.instance
                return project_klass
        else:
            try:
                return next(x for x in self.all(params=params) if x.id == id)
            except StopIteration:
                raise SnykNotFoundError

    def update(
        self,
        id: str,
        params: Dict[str, Any] = {},
        tags: Optional[List[Dict[str, str]]] = None,
        environment: Optional[List[str]] = None,
        business_criticality: Optional[List[str]] = None,
        lifecycle: Optional[List[str]] = None,
        test_frequency: Optional[str] = None,
        owner_id: Optional[str] = None,
    ) -> bool:
        if not self.instance:
            self.instance = self.get(id).organization

        body: Dict[str, Any] = {
            "data": {
                "id": id,
                "attributes": {},
                "relationships": {},
                "type": "project",
            },
        }

        path: str = "orgs/%s/projects/%s" % (self.instance.id, id)

        if tags:
            body["data"]["attributes"]["tags"] = tags

        if environment:
            body["data"]["attributes"]["environment"] = environment

        if business_criticality:
            body["data"]["attributes"]["business_criticality"] = business_criticality

        if lifecycle:
            body["data"]["attributes"]["lifecycle"] = lifecycle

        if test_frequency:
            body["data"]["attributes"]["test_frequency"] = test_frequency

        if owner_id:
            body["data"]["relationships"] = {
                "owner": {"data": {"id": owner_id, "type": "user"}}
            }

        return bool(self.client.patch(path, body, params=params))


class MemberManager(Manager):
    def all(self):
        path = "org/%s/members" % self.instance.id
        resp = self.client.get(path)
        members = []
        for member_data in resp.json():
            members.append(self.klass.from_dict(member_data))
        return members


class LicenseManager(Manager):
    def all(self):
        if hasattr(self.instance, "organization"):
            path = "org/%s/licenses" % self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            path = "org/%s/licenses" % self.instance.id
            post_body: Dict[str, Dict[str, List[str]]] = {"filters": {}}

        resp = self.client.post(path, post_body)
        license_data = resp.json()
        licenses = []
        if "results" in license_data:
            for license in license_data["results"]:
                licenses.append(self.klass.from_dict(license))
        return licenses


class DependencyManager(Manager):
    def all(self, page: int = 1):
        results_per_page = 1000
        if hasattr(self.instance, "organization"):
            org_id = self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            org_id = self.instance.id
            post_body = {"filters": {}}

        path = "org/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s" % (
            org_id,
            page,
            results_per_page,
        )

        resp = self.client.post(path, post_body)
        dependency_data = resp.json()

        total = dependency_data[
            "total"
        ]  # contains the total number of results (for pagination use)

        results = [self.klass.from_dict(item) for item in dependency_data["results"]]

        if total > (page * results_per_page):
            next_results = self.all(page + 1)
            results.extend(next_results)

        return results


class EntitlementManager(DictManager):
    def all(self) -> Dict[str, bool]:
        path = "org/%s/entitlements" % self.instance.id
        resp = self.client.get(path)
        return resp.json()


class SettingManager(DictManager):
    def all(self) -> Dict[str, Any]:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()

    def update(self, **kwargs: bool) -> bool:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        post_body = {}

        settings = [
            "auto_dep_upgrade_enabled",
            "auto_dep_upgrade_ignored_dependencies",
            "auto_dep_upgrade_min_age",
            "auto_dep_upgrade_limit",
            "pull_request_fail_on_any_vulns",
            "pull_request_fail_only_for_high_severity",
            "pull_request_test_enabled",
            "pull_request_assignment",
            "pull_request_inheritance",
            "pull_request_fail_only_for_issues_with_fix",
            "auto_remediation_prs",
        ]

        for setting in settings:
            if setting in kwargs:
                post_body[snake_to_camel(setting)] = kwargs[setting]

        return bool(self.client.put(path, post_body))


class IgnoreManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/ignores" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class JiraIssueManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/jira-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()

    def create(self, issue_id: str, fields: Any) -> Dict[str, str]:
        path = "org/%s/project/%s/issue/%s/jira-issue" % (
            self.instance.organization.id,
            self.instance.id,
            issue_id,
        )
        post_body = {"fields": fields}
        resp = self.client.post(path, post_body)
        response_data = resp.json()
        # The response we get is not following the schema as specified by the api
        # https://snyk.docs.apiary.io/#reference/projects/project-jira-issues-/create-jira-issue
        if (
            issue_id in response_data
            and len(response_data[issue_id]) > 0
            and "jiraIssue" in response_data[issue_id][0]
        ):
            return response_data[issue_id][0]["jiraIssue"]
        raise SnykError


class IntegrationManager(Manager):
    def all(self):
        path = "org/%s/integrations" % self.instance.id
        resp = self.client.get(path)
        integrations = []
        integrations_data = [{"name": x, "id": resp.json()[x]} for x in resp.json()]
        for data in integrations_data:
            integrations.append(self.klass.from_dict(data))
        for integration in integrations:
            integration.organization = self.instance
        return integrations


class IntegrationSettingManager(DictManager):
    def all(self):
        path = "org/%s/integrations/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class DependencyGraphManager(SingletonManager):
    def all(self) -> Any:
        path = "org/%s/project/%s/dep-graph" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        dependency_data = resp.json()
        if "depGraph" in dependency_data:
            return self.klass.from_dict(dependency_data["depGraph"])
        raise SnykError


@deprecated("API has been removed, use IssueSetAggregatedManager instead")
class IssueSetManager(SingletonManager):
    def _convert_reserved_words(self, data):
        for key in ["vulnerabilities", "licenses"]:
            if "issues" in data and key in data["issues"]:
                for i, vuln in enumerate(data["issues"][key]):
                    if "from" in vuln:
                        data["issues"][key][i]["fromPackages"] = data["issues"][key][
                            i
                        ].pop("from")
        return data

    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        filters = {
            "severities": ["critical", "high", "medium", "low"],
            "types": ["vuln", "license"],
            "ignored": False,
            "patched": False,
        }
        for filter_name in filters.keys():
            if kwargs.get(filter_name):
                filters[filter_name] = kwargs[filter_name]
        post_body = {"filters": filters}
        resp = self.client.post(path, post_body)
        return self.klass.from_dict(self._convert_reserved_words(resp.json()))


class IssueSetAggregatedManager(SingletonManager):
    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/aggregated-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        default_filters = {
            "severities": ["critical", "high", "medium", "low"],
            "exploitMaturity": [
                "mature",
                "proof-of-concept",
                "no-known-exploit",
                "no-data",
            ],
            "types": ["vuln", "license"],
            "priority": {"score": {"min": 0, "max": 1000}},
        }

        post_body = {"filters": default_filters}

        all_filters = list(default_filters.keys()) + ["ignored", "patched"]
        for filter_name in all_filters:
            if filter_name in kwargs.keys():
                post_body["filters"][filter_name] = kwargs[filter_name]

        for optional_field in ["includeDescription", "includeIntroducedThrough"]:
            if optional_field in kwargs.keys():
                post_body[optional_field] = kwargs[optional_field]

        resp = self.client.post(path, post_body)
        return self.klass.from_dict(resp.json())


class IssuePathsManager(SingletonManager):
    def all(self):
        path = "org/%s/project/%s/issue/%s/paths" % (
            self.instance.organization_id,
            self.instance.project_id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return self.klass.from_dict(resp.json())
