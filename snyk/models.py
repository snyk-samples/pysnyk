import base64
import re
from dataclasses import InitVar, dataclass, field
from typing import Any, Dict, List, Optional, Union

from deprecation import deprecated  # type: ignore
from mashumaro.mixins.json import DataClassJSONMixin  # type: ignore

from .errors import SnykError, SnykNotImplementedError
from .managers import Manager
from .utils import flat_map, format_package


@dataclass
class Vulnerability(DataClassJSONMixin):
    id: str
    url: str
    title: str
    description: str
    upgradePath: List[str]
    package: str
    version: str
    severity: str
    exploitMaturity: str
    isUpgradable: bool
    isPatchable: bool
    isPinnable: bool
    identifiers: Any
    semver: Any
    fromPackages: List[str] = field(default_factory=list)
    language: Optional[str] = None
    packageManager: Optional[str] = None
    publicationTime: Optional[str] = None
    priorityScore: Optional[int] = None
    disclosureTime: Optional[str] = None
    credit: Optional[List[Any]] = field(default_factory=list)
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    ignored: Optional[List[Any]] = field(default_factory=list)
    patched: Optional[List[Any]] = field(default_factory=list)


@dataclass
class LicenseIssue(DataClassJSONMixin):
    id: str
    url: str
    title: str
    package: str
    version: str
    severity: str
    fromPackages: List[str] = field(default_factory=list)
    # Although mentioned in the schema as required, currently not returned.
    isIgnored: Optional[bool] = None
    # Although mentioned in the schema as required, currently not returned.
    isPatched: Optional[bool] = None
    language: Optional[str] = None
    priorityScore: Optional[int] = None
    packageManager: Optional[str] = None
    ignored: Optional[List[Any]] = field(default_factory=list)
    patched: Optional[List[Any]] = field(default_factory=list)


@dataclass
class Issue(DataClassJSONMixin):
    vulnerabilities: List[Vulnerability]
    licenses: List[LicenseIssue]


@dataclass
class IssueSet(DataClassJSONMixin):
    ok: bool
    packageManager: str
    dependencyCount: int
    issues: Issue


@dataclass
class IssueData(DataClassJSONMixin):
    id: str
    title: str
    severity: str
    url: str
    exploitMaturity: str
    description: Optional[str] = None
    identifiers: Optional[Any] = None
    credit: Optional[List[str]] = None
    semver: Optional[Any] = None
    publicationTime: Optional[str] = None
    disclosureTime: Optional[str] = None
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    cvssDetails: Optional[List[Any]] = None
    language: Optional[str] = None
    patches: Optional[Any] = None
    nearestFixedInVersion: Optional[str] = None
    ignoreReasons: Optional[List[Any]] = None


@dataclass
class FixInfo(DataClassJSONMixin):
    isUpgradable: bool
    isPinnable: bool
    isPatchable: bool
    isFixable: bool
    isPartiallyFixable: bool
    nearestFixedInVersion: str
    fixedIn: Optional[List[str]] = None


@dataclass
class AggregatedIssue(DataClassJSONMixin):
    id: str
    issueType: str
    pkgName: str
    pkgVersions: List[str]
    issueData: IssueData
    isPatched: bool
    isIgnored: bool
    fixInfo: FixInfo
    introducedThrough: Optional[List[Any]] = None
    ignoreReasons: Optional[List[Any]] = None
    # Not mentioned in schema but returned
    # https://snyk.docs.apiary.io/#reference/projects/aggregated-project-issues/list-all-aggregated-issues
    priorityScore: Optional[int] = None
    priority: Optional[Any] = None


@dataclass
class IssueSetAggregated(DataClassJSONMixin):
    issues: List[AggregatedIssue]


@dataclass
class OrganizationGroup(DataClassJSONMixin):
    name: str
    id: str


@dataclass
class Package(DataClassJSONMixin):
    name: str
    version: Optional[str] = None
    fixVersion: Optional[str] = None


@dataclass
class IssuePaths(DataClassJSONMixin):
    snapshotId: str
    paths: List[List[Package]]
    total: int


@dataclass
class IssueRelations:
    id: str
    organization_id: str
    project_id: str


@dataclass
class Organization(DataClassJSONMixin):
    name: str
    id: str
    slug: str
    url: str
    group: Optional[OrganizationGroup] = None
    client: Optional[Any] = None

    @property
    def projects(self) -> Manager:
        return Manager.factory(Project, self.client, self)

    @property
    def members(self) -> Manager:
        return Manager.factory(Member, self.client, self)

    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.client, self)

    @property
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.client, self)

    @property
    def entitlements(self) -> Manager:
        return Manager.factory("Entitlement", self.client, self)

    @property
    def integrations(self) -> Manager:
        return Manager.factory(Integration, self.client, self)

    """
    Imports need integrations, but exposing a high-level API that
    can find the integration from the URL of the thing you want
    to import should make things simpler. This is currently only
    supported for GitHub as an example. If this works nicely then
    extending the list of integrations, adding support for branches
    and files, and better errors, would be required.
    """

    def import_project(self, url, files: Optional[List[str]] = None) -> bool:
        try:
            components = url.split("/")
            service = components[0]

            if service == "github.com":
                owner = components[1]
                name = components[2]
                parts = name.split("@")
                branch = "master"

                if len(parts) == 2:
                    name = parts[0]
                    branch = parts[1]
            elif service == "docker.io":
                name = "/".join(components[1:])
            else:
                raise SnykNotImplementedError

        except ValueError:
            raise SnykError
        try:
            integrations = {"github.com": "github", "docker.io": "docker-hub"}
            integration_name = integrations[service]
        except KeyError:
            raise SnykError
        try:
            if service == "docker.io":
                return self.integrations.filter(name=integration_name)[0].import_image(
                    name
                )
            else:
                integration = self.integrations.filter(name=integration_name)[0]

                if files:
                    return integration.import_git(owner, name, branch, files)
                else:
                    return integration.import_git(owner, name, branch)

        except KeyError:
            raise SnykError

    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/modify-org-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/get-org-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/organisations/the-snyk-organisation-for-a-request/invite-users
    def invite(self, email: str, admin: bool = False) -> bool:
        path = "org/%s/invite" % self.id
        payload = {"email": email, "isAdmin": admin}

        if self.client is None:
            raise SnykError

        return bool(self.client.post(path, payload))

    def _test(self, path, contents=None, additional=None):
        if contents:
            # Check for a file-like object, allows us to support files
            # and strings in the same interface
            read = getattr(contents, "read", None)

            if callable(read):
                contents = contents.read()
            encoded = base64.b64encode(contents.encode()).decode()
            post_body = {
                "encoding": "base64",
                "files": {"target": {"contents": encoded}},
            }

            # Some test methods carry a second file, often a lock file

            if additional:
                read = getattr(additional, "read", None)

                if callable(read):
                    additional = additional.read()
                encoded = base64.b64encode(additional.encode()).decode()
                post_body["files"]["additional"] = {"contents": encoded}

            resp = self.client.post(path, post_body)
        else:
            resp = self.client.get(path)

        return IssueSet.from_dict(resp.json())

    def test_maven(
        self, package_group_id: str, package_artifact_id: str, version: str
    ) -> IssueSet:
        path = "test/maven/%s/%s/%s?org=%s" % (
            package_group_id,
            package_artifact_id,
            version,
            self.id,
        )

        return self._test(path)

    def test_rubygem(self, name: str, version: str) -> IssueSet:
        path = "test/rubygems/%s/%s?org=%s" % (name, version, self.id)

        return self._test(path)

    def test_python(self, name: str, version: str) -> bool:
        path = "test/pip/%s/%s?org=%s" % (name, version, self.id)

        return self._test(path)

    def test_npm(self, name: str, version: str) -> bool:
        path = "test/npm/%s/%s?org=%s" % (name, version, self.id)

        return self._test(path)

    def test_pipfile(self, contents):
        path = "test/pip?org=%s" % self.id

        return self._test(path, contents)

    def test_gemfilelock(self, contents):
        path = "test/rubygems?org=%s" % self.id

        return self._test(path, contents)

    def test_packagejson(self, contents, lock=None):
        path = "test/npm?org=%s" % self.id

        return self._test(path, contents, lock)

    def test_gradlefile(self, contents):
        path = "test/gradle?org=%s" % self.id

        return self._test(path, contents)

    def test_sbt(self, contents):
        path = "test/sbt?org=%s" % self.id

        return self._test(path, contents)

    def test_pom(self, contents):
        path = "test/maven?org=%s" % self.id

        return self._test(path, contents)

    def test_composer(self, contents, lock):
        path = "test/composer?org=%s" % self.id

        return self._test(path, contents, lock)

    def test_yarn(self, contents, lock):
        path = "test/yarn?org=%s" % self.id

        return self._test(path, contents, lock)


@dataclass
class Integration(DataClassJSONMixin):
    name: str
    id: str
    organization: Optional[Organization] = None

    def clone(self, target_organization_id) -> bool:
        if not self.organization:
            raise SnykError

        path = "org/%s/integrations/%s/clone" % (self.organization.id, self.id)

        if self.organization.client is None:
            raise SnykError

        return bool(
            self.organization.client.post(
                path, {"destinationOrgPublicId": target_organization_id}
            )
        )

    @property
    def settings(self):
        if not self.organization:
            raise SnykError

        return Manager.factory("IntegrationSetting", self.organization.client, self)

    def _import(self, payload) -> bool:
        if not self.organization:
            raise SnykError
        path = "org/%s/integrations/%s/import" % (self.organization.id, self.id)

        if self.organization.client is None:
            raise SnykError

        return bool(self.organization.client.post(path, payload))

    def import_git(
        self, owner: str, name: str, branch: str = "master", files: List[str] = []
    ):
        return self._import(
            {
                "target": {"owner": owner, "name": name, "branch": branch},
                "files": [{"path": x} for x in files],
            }
        )

    def import_image(self, name: str):
        if ":" not in name:
            name = "%s:latest" % name

        return self._import({"target": {"name": name}})

    def import_gitlab(self, id: str, branch: str = "master", files: List[str] = []):
        return self._import(
            {
                "target": {"id": id, "branch": branch},
                "files": [{"path": x} for x in files],
            }
        )

    def import_bitbucket(
        self, project_key: str, name: str, repo_slug: str, files: List[str] = []
    ):
        return self._import(
            {
                "target": {
                    "projectKey": project_key,
                    "name": name,
                    "repoSlug": repo_slug,
                },
                "files": [{"path": x} for x in files],
            }
        )

    def import_heroku(self, app_id: str, slug_id: str, files: List[str] = []):
        return self._import(
            {
                "target": {"appId": app_id, "slugId": slug_id},
                "files": [{"path": x} for x in files],
            }
        )

    def import_lambda(self, function_id: str, files: List[str] = []):
        return self._import(
            {
                "target": {"functionId": function_id},
                "files": [{"path": x} for x in files],
            }
        )

    def import_cloudfoundry(self, app_id: str, files: List[str] = []):
        return self._import(
            {"target": {"appId": app_id}, "files": [{"path": x} for x in files]}
        )


@dataclass
class LicenseDependency(DataClassJSONMixin):
    id: str
    name: str
    version: str
    packageManager: str


@dataclass
class LicenseProject(DataClassJSONMixin):
    id: str
    name: str


@dataclass
class License(DataClassJSONMixin):
    id: str
    dependencies: List[LicenseDependency]
    projects: List[LicenseProject]
    severity: Optional[str] = None


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/update-a-member-in-the-organisation
    def update_role(self, role: str):
        raise SnykNotImplementedError  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/remove-a-member-from-the-organisation
    def delete(self):
        raise SnykNotImplementedError  # pragma: no cover


@dataclass
class IssueCounts(DataClassJSONMixin):
    low: int
    medium: int
    high: int
    # https://updates.snyk.io/critical-severity-level-195891, critical severity is optional since it is still under Snyk preview
    critical: Optional[int] = 0


@dataclass
class DependencyGraphPackageInfo(DataClassJSONMixin):
    name: str
    version: Optional[str] = None


@dataclass
class DependencyGraphPackage(DataClassJSONMixin):
    id: str
    info: DependencyGraphPackageInfo


@dataclass
class Node(DataClassJSONMixin):
    nodeId: str
    pkgId: str
    deps: List[Dict[str, str]]


@dataclass
class Graph(DataClassJSONMixin):
    rootNodeId: str
    nodes: List[Node]


@dataclass
class DependencyGraph(DataClassJSONMixin):
    schemaVersion: str
    pkgManager: Dict[str, str]
    pkgs: List[DependencyGraphPackage]
    graph: Graph


@dataclass
class DependencyLicense(DataClassJSONMixin):
    id: str
    title: str
    license: str


@dataclass
class DependencyProject(DataClassJSONMixin):
    name: str
    id: str


@dataclass
class Dependency(DataClassJSONMixin):
    id: str
    name: str
    version: str
    licenses: List[DependencyLicense]
    projects: List[DependencyProject]
    latestVersion: Optional[str] = None
    latestVersionPublishedDate: Optional[str] = None
    firstPublishedDate: Optional[str] = None
    isDeprecated: Optional[bool] = None
    type: Optional[str] = None
    deprecatedVersions: Optional[List[Any]] = field(default_factory=list)
    dependenciesWithIssues: Optional[List[Any]] = field(default_factory=list)


@dataclass
class User(DataClassJSONMixin):
    id: str
    name: str
    username: str
    email: str

@dataclass
class AutoDependencyUpgrade(DataClassJSONMixin):
    ignored_dependencies: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    is_major_upgrade_enabled: Optional[bool] = None
    limit: Optional[int] = None
    minimum_age: Optional[int] = None


@dataclass
class ManualRemediationPRS(DataClassJSONMixin):
    is_patch_remediation_enabled: Optional[bool] = None


@dataclass
class PullRequestAssignment(DataClassJSONMixin):
    assignees: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    type: Optional[str] = None


@dataclass
class AutoRemediationPRS(DataClassJSONMixin):
    is_backlog_prs_enabled: Optional[bool] = None
    is_fresh_prs_enabled: Optional[bool] = None
    is_patch_remediation_enabled: Optional[bool] = None


@dataclass
class ProjectRecurringTests(DataClassJSONMixin):
    frequency: Optional[str] = None


@dataclass
class ProjectPullRequests(DataClassJSONMixin):
    fail_only_for_issues_with_fix: Optional[bool] = None
    policy: Optional[str] = None
    severity_threshold: Optional[str] = None


@dataclass
class ProjectSettings(DataClassJSONMixin):
    pull_requests: ProjectPullRequests
    recurring_tests: ProjectRecurringTests
    pull_request_assignment: Optional[PullRequestAssignment] = None
    manual_remediation_prs: Optional[ManualRemediationPRS] = None
    auto_remediation_prs: Optional[AutoRemediationPRS] = None
    auto_dependency_upgrade: Optional[AutoDependencyUpgrade] = None


@dataclass
class LatestDependencyTotal(DataClassJSONMixin):
    total: Optional[int] = None
    updated_at: Optional[str] = None


@dataclass
class ProjectMeta(DataClassJSONMixin):
    cli_monitored_at: Optional[str] = None
    latest_dependency_total: Optional[LatestDependencyTotal] = None
    latest_issue_counts: Optional[IssueCounts] = None


@dataclass
class ProjectAttributes(DataClassJSONMixin):
    name: str
    created: str
    origin: str
    type: str
    read_only: bool
    settings: ProjectSettings
    status: str
    target_file: str
    target_reference: str
    type: str
    target_runtime: Optional[str] = None
    build_args: Optional[Dict[str, str]] = None
    business_criticality: Optional[List[str]] = None
    environment: Optional[List[str]] = None
    lifecycle: Optional[List[str]] = None
    tags: Optional[List[Any]] = field(default_factory=list)
    meta: Optional[ProjectMeta] = None


@dataclass
class ProjectOrganizationData(DataClassJSONMixin):
    id: str
    type: str


@dataclass
class LinksHref(DataClassJSONMixin):
    href: str
    meta: Optional[Dict[Any, Any]] = None


@dataclass
class GenericLinks(DataClassJSONMixin):
    related: Optional[Union[str, LinksHref]] = None


@dataclass
class DataLinksMeta(DataClassJSONMixin):
    data: ProjectOrganizationData
    links: GenericLinks
    meta: Optional[Dict[Any, Any]] = None


@dataclass
class ProjectRelationshipsTargetDataAttributes(DataClassJSONMixin):
    display_name: str
    url: Optional[str] = None


@dataclass
class ProjectRelationshipsTargetData(DataClassJSONMixin):
    id: str
    type: str
    attributes: ProjectRelationshipsTargetDataAttributes
    meta: Optional[Dict[str, Dict[Any, Any]]] = None


@dataclass
class ProjectRelationshipsTarget(DataClassJSONMixin):
    data: ProjectRelationshipsTargetData
    links: GenericLinks


@dataclass
class ProjectRelationships(DataClassJSONMixin):
    organization: DataLinksMeta
    target: Union[DataLinksMeta, ProjectRelationshipsTarget]
    owner: Optional[DataLinksMeta] = None
    importer: Optional[DataLinksMeta] = None


@dataclass
class Project(DataClassJSONMixin):
    attributes: ProjectAttributes
    id: str
    type: str
    organization: Organization = None
    meta: Optional[ProjectMeta] = None
    relationships: Optional[ProjectRelationships] = None
    _tags: Optional[List[Any]] = field(default_factory=list)

    def delete(self) -> bool:
        path = "org/%s/project/%s" % (self.organization.id, self.id)

        if self.organization.client is None:
            raise SnykError

        return bool(self.organization.client.delete(path))

    def activate(self) -> bool:
        path = "org/%s/project/%s/activate" % (self.organization.id, self.id)

        if self.organization.client is None:
            raise SnykError

        return bool(self.organization.client.post(path, {}))

    def deactivate(self) -> bool:
        path = "org/%s/project/%s/deactivate" % (self.organization.id, self.id)

        if self.organization.client is None:
            raise SnykError

        return bool(self.organization.client.post(path, {}))

    def move(self, new_org_id: str) -> bool:
        path = "org/%s/project/%s/move" % (self.organization.id, self.id)

        payload = {"targetOrgId": new_org_id}

        if self.organization.client is None:
            raise SnykError

        return bool(self.organization.client.put(path, payload))

    def _get_project_snapshot(self):
        """
        Gets the latest project snapshot
        """
        project_snapshot_result = self.organization.client.post(
            f"org/{self.organization.id}/project/{self.id}/history?perPage=1&page=1",
            {},
        )
        return project_snapshot_result.json().get("snapshots", [{}])[0]

    def __getattr__(self, item):
        """
        Will handle lazy loading of attributes which require further API calls or are computationally expensive. This
        avoids having to load them when we retrieve the full list from the API.
        """
        # These attributes require us to get the latest snapshot
        if item in [
            "totalDependencies",
            "imageId",
            "imageTag",
            "imageBaseImage",
            "imagePlatform",
        ]:
            snapshot = self._get_project_snapshot()
            if item == "totalDependencies":
                return snapshot.get("totalDependencies", 0)
            elif item == "imageId":
                return snapshot.get("imageId")
            elif item == "imageTag":
                return snapshot.get("imageTag")
            elif item == "imageBaseImage":
                return snapshot.get("baseImageName")
            elif item == "imagePlatform":
                return snapshot.get("imagePlatform")
        # These attributes require us to call the user API to get a users details
        elif item in ["importingUser", "owner"]:
            if item == "importingUser":
                selected_user = self.importingUserId
            else:
                selected_user = self.owningUserId
            user_response = self.organization.client.get(
                f"orgs/{self.organization.id}/users/{selected_user}",
                version="2023-05-29~beta",
            )
            user = user_response.json()
            user_data = user.get("data", {})
            user_attributes = user_data.get("attributes", {})
            return User(
                id=self.importingUserId,
                name=user_attributes.get("name"),
                username=user_attributes.get("username"),
                email=user_attributes.get("email"),
            )
        elif item == "browseUrl":
            # Ensure that our browse URL matches the tenant the user is making a request to
            tenant_matches = match = re.match(
                r"^https://api\.(.*?)\.snyk\.io", self.organization.client.api_url
            )
            if tenant_matches:
                # If a tenant is found, insert it into the URL
                url_prefix = f"https://app.{match.group(1)}.snyk.io"
            else:
                # If no tenant is found, use a default URL
                url_prefix = "https://app.snyk.io"
            return f"{url_prefix}/org/{self.organization.slug}/project/{self.id}"
        else:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{item}'"
            )

    @property
    def settings(self) -> Manager:
        return Manager.factory("Setting", self.organization.client, self)

    @property
    def ignores(self) -> Manager:
        return Manager.factory("Ignore", self.organization.client, self)

    @property
    def jira_issues(self) -> Manager:
        return Manager.factory("JiraIssue", self.organization.client, self)

    @property
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.organization.client, self)

    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.organization.client, self)

    @property
    def dependency_graph(self) -> DependencyGraph:
        return Manager.factory(DependencyGraph, self.organization.client, self).all()

    # mypy doesn't support decorated properties
    @property  # type: ignore
    @deprecated("Use issueset_aggregated")
    def issueset(self) -> Manager:
        return Manager.factory(IssueSet, self.organization.client, self)

    @property
    def issueset_aggregated(self) -> Manager:
        return Manager.factory(IssueSetAggregated, self.organization.client, self)

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        vuln_filter = {
            "severities": ["critical", "high", "medium", "low"],
            "types": ["vuln"],
            "ignored": False,
            "patched": False,
        }
        aggregated_vulns = self.issueset_aggregated.filter(**vuln_filter).issues
        foo = flat_map(self._aggregated_issue_to_vulnerabily, aggregated_vulns)
        return foo

    @property
    def tags(self) -> Manager:
        return Manager.factory("Tag", self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/modify-project-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/get-project-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError  # pragma: no cover

    def _aggregated_issue_to_vulnerabily(
        self, issue: AggregatedIssue
    ) -> List[Vulnerability]:
        issue_paths = Manager.factory(
            IssuePaths,
            self.organization.client,
            IssueRelations(
                id=issue.id, organization_id=self.organization.id, project_id=self.id
            ),
        ).all()

        try:
            upgradable_paths = filter(
                lambda path: path[0].fixVersion is not None,
                issue_paths.paths,
            )
            first_path = next(upgradable_paths)
            upgrade_path = list(map(format_package, first_path))
        except StopIteration:
            upgrade_path = []

        return [
            Vulnerability(
                id=issue.issueData.id,
                url=issue.issueData.url,
                title=issue.issueData.title,
                description=issue.issueData.description or "",
                upgradePath=upgrade_path,
                package=issue.pkgName,
                version=version,
                severity=issue.issueData.severity,
                exploitMaturity=issue.issueData.exploitMaturity,
                isUpgradable=issue.fixInfo.isUpgradable,
                isPatchable=issue.fixInfo.isPatchable,
                isPinnable=issue.fixInfo.isPinnable,
                identifiers=issue.issueData.identifiers,
                semver=issue.issueData.semver,
                fromPackages=issue.introducedThrough or [],
                language=issue.issueData.language,
                packageManager=self.type,
                publicationTime=issue.issueData.publicationTime,
                priorityScore=issue.priorityScore,
                disclosureTime=issue.issueData.disclosureTime,
                credit=issue.issueData.credit,
                CVSSv3=issue.issueData.CVSSv3,
                cvssScore=issue.issueData.cvssScore,
                ignored=issue.issueData.ignoreReasons,
                patched=issue.issueData.patches if issue.isPatched else [],
            )
            # Old endpoint returned a new issue if it appeared in multiple
            # versions, emulate that here to preserve upstream api
            for version in issue.pkgVersions
        ]
