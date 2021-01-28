# Examples


The following examples require you to have a valid Snyk token file on your system. You can create this by running `snyk auth` with your Snyk CLI. This will create a token file at `.config/configstore`. See [Snyk CLI](https://github.com/snyk/snyk#installation). You can use either a [personal token](https://app.snyk.io/account) or a [service account](https://snyk.io/docs/service-accounts/).

## Running a Script
The sample scripts are all a bit different, so you should try them each out or look at the code.

1. Install `pysnyk` using `pip install pysnyk`
1. You can execute an example in general using:
    ```
    python examples/<script-name.py> --orgId=<your-org_id> ...
    ```

## List Project Issues
```
python examples/api-demo-2-list-issues.py --orgId=<your-snyk-org> --projectId=<snyk-project-id>
```
If you want to catpure the output in an excel spreadsheet:
```
python examples/api-demo-2-list-issues.py --orgId=<your-snyk-org> --projectId=<snyk-project-id> --outputPathExcel=/path/to/output.xlsx
```

## Update GitHub Checks Settings
Use this to update the GitHub checks settings for a particular projectId or all GitHub projects in your Snyk org.
```
python examples/api-demo-11-update-github-checks.py --orgId=<your-snyk-org> --projectId=<snyk-project-id>|all --pullRequestTestEnabled=[true|false]
```

## Project Dependencies and Licenses Report

Requires the python package `XlsxWriter` to be present.
This report generates a list of all dependencies (including transitive dependencies) and all associated licenses either for a specific project within your Snyk org, or across all of them.

There are four output options; you need to chose one or more of them:
* --outputPathExcel=<desired-output-file-path>
* --outputPathCSV=<desired-output-file-path>
* --outputPathNestedJson=<desired-output-file-path>
* --outputPathFlatJson=<desired-output-file-path>

Specify a unique file / path for each option you want.

For example, if you wanted the Excel option only, you'd do something like (after completing the above Getting Started steps):
```
python examples/api-demo-10-project-deps-licenses-report.py --orgId=<your-org_id> --projectId=all --outputPathExcel=my-report.xlsx
```

The `--outputPathNestedJson` is a good one if you want a fully nested Json representation of all project dependencies as opposed to all the other output options in which the dependencies are flattened to be more readable in a tabular format (but still show the complete path of each dependency).

## Testing packages

To test a Java package, use:
```
python examples/api-demo-5-test-java-package.py --orgId=<your-org_id> --groupId=<groupId> --artifactId=<artifactId> --packageVersion=<packageVersion>
```
or
```
python examples/api-demo-5-test-java-package.py --orgId=<your-org_id> <groupId>:<artifactId>@<packageVersion>
```

To test a RubyGem package, use:
```
python examples/api-demo-5b-test-rubygem-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```

To test a Python (pip) package, use:
```
python examples/api-demo-5c-test-python-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```

To test an npm package, use:
```
python examples/api-demo-5d-test-npm-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```

## Jira Integration

To find all the issues that don't have a Jira issue:
```
python examples/api-demo-6-find-issues-without-jira-issues.py --orgId=<your-snyk-org> --projectId=<snyk-project-id>
```

To create a Jira Issue for each project issue:
```
python examples/api-demo-6b-create-jira-issues-for-issues.py --orgId=<your-snyk-org> --projectId=<snyk-project-id> --jiraIssueType=<jira-issue-type-id> --jiraProjectId=<jira-project-id>
```

## Organization Vulnerability Report

To create a report containing all projects and their current vulnerabilities within an organisation:
```
python examples/OrgVulnReport.py --orgIds=<your-snyk-org>
```
If wish to run the script for multiple orgs, add further orgIds separated by space:
```
python examples/OrgVulnReport.py --orgIds=<snyk-org-1> <snyk-org-2>
```
Optional: Manually set API Key
```
python examples/OrgVulnReport.py --apiKey=<snyk-api-key> --orgIds=<your-snyk-org>
```
