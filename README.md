# pysnyk


[![Build status](https://github.com/snyk-labs/pysnyk/actions/workflows/test.yml/badge.svg)](https://github.com/snyk-labs/pysnyk/actions/workflows/test.yml)


A Python client for the [Snyk API](https://snyk.docs.apiary.io/#).

## Client

Using the client requires you to provide your Snyk API token.

```python
import snyk
client = snyk.SnykClient("<your-api-token>")
```

By default the client will connect to the public Snyk service. If you are using a local installation then you can provide the API url as the second argument.

```python
import snyk
client = snyk.SnykClient("<your-api-token>", "<your-instance-of-snyk>")
```

By default the `User-Agent` string for the API requests will be `pysnyk/<version>`. If you would like to send a custom user agent you can do so as follows:

```python
import snyk
client = snyk.SnykClient("<your-api-token>", user_agent="<your-instance-of-snyk>")
```

By default the requests are not retried. If you would like to retry failed requests with `backoff` and `delay` you can do so as follows:

```python
import snyk
client = snyk.SnykClient("<your-api-token>", tries=4, delay=1, backoff=2)
```

- `tries` - the maximum number of attempts. **Default:** `1` (no retries)
- `delay` - initial delay between attempts. **Default:** `1`
- `backoff` - multiplier applied to delay between attempts. **Default:** `2`
- `debug` - run client in debug mode, useful for debugging API requests. **Default:** `False`

## Organizations

With the client we can get a list of Snyk organizations you are a member of:

```python
client.organizations.all()
```

This returns a list of `snyk.models.Organization` objects.

If you already have the ID of the organization you're after you can grab it directly:

```python
client.organizations.get("<organization-id>")
```

This will return a single `snyk.models.Organization` object.

Most of the API is scoped to organizations, so most other methods are found on the `snyk.models.Organization` objects returned by these two methods.

The `snyk.models.Organization` object has the following properties related to the API:

- `entitlements` - returns the set of Snyk features available to this account
- `dependencies`- returns a Manager for packages in use in this organization
- `licenses` - returns a Manager for licenses currently in use by projects in this organisation
- `members` - returns a Manager for members
- `projects` - returns a Manager for associated projects
- `integrations` - returns a Manager for active integrations

### A note on Managers

Managers provide a consistent API for accessing objects from the Snyk API. Each manager implements the following methods:

- `all()` - return a list of all of the relevant objects
- `get("<id>")` - return a single instance of the object if it exists
- `first()` - grab the first instance of the object if one exists
- `filter(<key>="<value>")` - return a list filtered by one or more key/value pairs

### Projects

Once you have an organization you're likely to want to grab the related projects:

```python
client.organizations.first().projects.all()
```

This will return a list of `snyk.models.Project` objects.

In the case where you want to get all of the projects across all of your organizations then you can use the handy method on the client.

```python
client.projects.all()
```

The `snyk.models.Project` object has the following useful properties and methods:

- `delete()` - deletes the project in question. Be careful as this will delete all associated data too
- `move(new_org_id)` - moves the project to a new organization
- `dependencies` - returns a Manager for packages in use in this project
- `dependency_graph` - returns a `snyk.models.DependencyGraph` object which represents the full dependency graph of package dependencies
- `ignores` - returns a Manager for ignore rules set on the project
- `vulnerabilities` - returns a list of `snyk.models.Vulnerability` objects with information about vulnerabilities in this project
- `jira_issues` - returns a Manager with access to any associated Jira issues
- `licenses` - returns a Manager for licenses currently in use by this project
- `settings` - returns a Manager for interacting with the current project settings
- `tags` - returns a Manager for interacting with the current project tags

You can add and delete tags using the manager:

- `tags.add(key, value)` - adds a tag with the provided key/value pair to the project
- `tags.delete(key, value)` - deletes a tag with the provided key/value pair from the project

In the case of Projects, as well as filtering by properties (as mentioned above) you can also filter by tag:

```python
client.organizations.first().projects.filter(tags = [{"key": "some-key", "value": "some-value"}])
```

Note that the `settings` Manager can also be used to update settings like so, assuming you have a `snyk.models.Project` object in the variable `project`.

```python
project.settings.update(pull_request_test_enabled=True)
```

### Importing new projects

The client supports a high-level `import_project` method on organizations for adding new projects to be monitored by Snyk.

```python
org = client.organizations.first()
org.import_project("github.com/user/project@branch")
org.import_project("docker.io/repository:tag")
```

If you are targetting a specific manifest file or files you can pass those as an optional argument, for instance:

```python
org.import_project("github.com/user/project@branch", files=["Gemfile.lock"])
```

This method currently only supports importing projects from GitHub and Docker Hub. For other integrations you will need to grab the lower-level `snyk.models.Integration` object from the `snyk.models.Organization.integrations` manager noted above. Other services will be added to this API soon.

### Testing for vulnerabilities

The API also exposes methods to discover vulnerability information about individual packages. These methods are found on the Organization object.

- `test_maven(<package_group_id>, <package_artifact_id>, <version>)` - returns an IssueSet containing vulnerability information for a Maven artifact
- `test_rubygem(<name>, <version>)` - returns an IssueSet containing vulnerability information for a Ruby Gem
- `test_python(<name>, <version>)` - returns an IssueSet containing vulnerability information for Python package from PyPi
- `test_npm(<name>, <version>)` - returns an IssueSet containing vulnerability information for an NPM package

Here's an example of checking a particular Python package.

```python
>>> org = client.organizations.first()
>>> result = org.test_python("flask", "0.12.2")
>>> assert result.ok
False
# You can access details of the vulnerabilities too, for example
>>> result.issues.vulnerabilities[0].title
'Improper Input Validation'
>>> result.issues.vulnerabilities[0].identifiers
{'CVE': ['CVE-2018-1000656'], 'CWE': ['CWE-20']
```

As well as testing individual packages you can also test all packages found in various dependency management manifests. The client currently supports the following methods:

- `test_pipfile(<file-handle-or-string>)` - returns an IssueSet for all Python dependencies in a `Pipfile`
- `test_gemfilelock(<file-handle-or-string>)` - returns an IssueSet for all Ruby dependencies in a `Gemfile`
- `test_packagejson(<file-handle-or-string>, (<lock-file-handle-or-string>))` - returns an IssueSet for all Javascript dependencies in a `package.json` file. Optionally takes a `package.lock` file
- `test_gradlefile(<file-handle-or-string>)` - returns an IssueSet for all dependencies in a `Gradlefile`
- `test_sbt(<file-handle-or-string>)` - returns an IssueSet for all dependencies defined in a `.sbt` file
- `test_pom(<file-handle-or-string>)` - returns an IssueSet for all dependencies in a Maven `pom.xml` file
- `test_yarn(<file-handle-or-string>, <lock-file-handle-or-string>)` - returns an IssueSet for all dependencies in Yarn `package.json` and `yarn.lock` files
- `test_composer(<file-handle-or-string>, <lock-file-handle-or-string>)` - returns an IssueSet for all dependencies in Composer `composer.json` and `composer.lock` files

For example, here we are testing a Python `Pipfile`.

```python
>>> org = client.organizations.first()
>>> file = open("Pipfile")
>>> org.test_pipfile(file)
```

### Inviting new users

You can invite new users to the organization via the API.

```python
>>> org = client.organizations.first()
>>> org.invite("example@example.com")
```

You can also invite new users as administrators:

```python
>>> org = client.organizations.first()
>>> org.invite("example@example.com", admin=True)
```

### Low-level client

As well as the high-level API of the Snyk client you can use the HTTP methods directly. For these you simply need to pass the path, and optionally a data payload. The full domain, and the authentication details, are already provided by the client.

```python
client.get("<path>")
client.delete("<path>")
client.put("<path>", <data>)
client.post("<path>", <data>)
```

Most of the time you shouldn't need to use these. They are mainly useful if new methods are added to the API which are not yet supported in the client. This can also be useful if you want to pass very specific parameters, or to parse the raw JSON output from the API.

## Experimental rest low-level client

pysnyk >= 0.9.0 now includes support for basic rest (formerly referred to as v3) compatibility. To switch to use a rest client, pass the rest API url and version when initializing a client. Right now it supports the `GET` method. Refer to the [rest API docs](https://apidocs.snyk.io/) for more information and examples.

Getting the rest information of an organization:

```python
# To get this value, get it from a Snyk organizations settings page
snyk_org = "df734bed-d75c-4f11-bb47-1d119913bcc7"

# to use the rest endpoint you MUST include a version value and the url of the v3 api endpoint as shown below
rest_client = SnykClient(snyk_token, version="2022-02-16~experimental", url="https://api.snyk.io/rest")

print(rest_client.get(f"/orgs/{snyk_org}").json())

# this supports overriding rest versions for a specific GET requests:
user = rest_client.get(f"orgs/{snyk_org}/users/{snyk_user}", version="2022-02-01~experimental").json()

# pass parameters such as how many results per page
params = {"limit": 10}

targets = rest_client.get(f"orgs/{snyk_org}/targets", params=params)
```

V1 and rest can work at the same time by instantiating two clients:

```python
snyk_org = "df734bed-d75c-4f11-bb47-1d119913bcc7"

v1client = SnykClient(snyk_token)

rest_client = SnykClient(snyk_token, version="2022-02-16~experimental", url="https://api.snyk.io/rest")

v1_org = v1client.organizations.get(snyk_org)

rest_org = rest_client.get(f"/orgs/{snyk_org}").json()
```

The rest API introduces consistent pagination across all endpoints. The v3 client includes a helper method `.get_rest_pages` which collects the paginated responses and returns a single list combining the contents of the "data" key from all pages. It takes the same values as the get method.

```python
rest_client = SnykClient(snyk_token, version="2022-02-16~experimental", url="https://api.snyk.io/rest")

params = {"limit": 10}

targets = rest_client.get(f"orgs/{snyk_org}/targets", params=params).json()

print(len(targets["data"]))
# returns 10 targets

all_targets = rest_client.get_rest_pages(f"orgs/{snyk_org}/targets", params=params)

print(len(all_targets))
# returns 33 targets, note we don't have to add .json() to the call or access the "data" key, get_rest_pages does that for us

# Override Content-Type header (or others) as needed for 
response = rest_client.post(f"orgs/{snyk_org}/invites", body={"email": "some.body@snyk.io", "role": "f8223479-01a9-4774-8e29-06ce9a0513d6", headers={"Content-Type": "application/vnd.api+json"}})
```

For backwards compatibility the get_rest_pages method has an alternative name of get_v3_pages to not break code already rewritten replatformed to the 0.9.0 pysnyk module.

## Migrating from old project to new project entity

The rest API introduces a new representation for the project class, which offers more information. There are some changes necessary to keep the same functionality
of the application:
- The old project attributes can be accessed using the attributes class. The below example 
```python
project.name -> project.attributes.name
project.created -> project.attributes.created
project.origin -> project.attributes.origin
project.type -> project.attributes.type
project.readOnly -> project.attributes.read_only
project.attributes.criticality -> project.attributes.business_criticality
project.totalDependencies -> project.meta.latest_dependency_total.total
project.issueCountsBySeverity -> project.meta.latest_issue_counts
project.lastTestedDate -> project.meta.cli_monitored_at
project.importingUser.id -> project.relationships.importer.data.id
project.isMonitored -> project.attributes.status
project.targetReference -> project.attributes.target_reference
```

To update an existing project, the Snyk client will be used:
