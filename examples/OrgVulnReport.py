import argparse
import json
import xlsxwriter

from snyk import SnykClient
from utils import get_default_token_path, get_token

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="OrgVulnReport")
    parser.add_argument(
        "--orgIds", help="Snyk Org ID(s) (Seperated by spaces)", required=True, nargs = '+'
    )
    parser.add_argument(
        "--apiKey", type=str, help="Snyk API Key"
    )
    return parser.parse_args()

args = parse_command_line_args()
org_ids = args.orgIds
if args.apiKey is not None:
    client = SnykClient(token=args.apiKey)
else:
    snyk_token_path = get_default_token_path()
    client = SnykClient(get_token(snyk_token_path))

for orgs in org_ids:
    org_name = client.organizations.get(orgs).name
    excel_workbook = xlsxwriter.Workbook(org_name + '.xlsx')
    format_colTitle = excel_workbook.add_format({"bold": True})
    proj_ids = []
    proj_names = []
    loading = "|/-\\"
    loading_index = 0
    for project in client.organizations.get(orgs).projects.all():
        proj_ids.append(project.id)
        proj_names.append(project.name)
    for project in proj_ids:
        print("(" + str(org_ids.index(orgs) + 1) + "/" + str(len(org_ids)) + ") " + "Creating report for " + org_name + " org" +' (' + str(len(proj_ids)) + " projects) " + loading[loading_index % len(loading)], end="\r")
        loading_index += 1
        vuln_list = []
        worksheet_name = proj_names[proj_ids.index(project)][::-1]
        worksheet_name = worksheet_name.translate({ord(c): " " for c in "[]:*?/\\"})
        if len(worksheet_name) >= 31:
            worksheet_name = (worksheet_name[:29] + '..')
        worksheet_name = worksheet_name[::-1]
        excel_worksheet = excel_workbook.add_worksheet(worksheet_name)
        issue_set = client.organizations.get(orgs).projects.get(project).issueset.all()
        if len(issue_set.issues.vulnerabilities) == 0:
            output_item = {
                    "title": " ",
                    "id": " ",
                    "url": " ",
                    "package": " ",
                    "severity": " ",
                    "cvssScore": " ",
                }
            vuln_list.append(output_item)
        else:
            for i in issue_set.issues.vulnerabilities:
                output_item = {
                    "title": i.title,
                    "id": i.id,
                    "url": i.url,
                    "package": "%s@%s" % (i.package, i.version),
                    "severity": i.severity,
                    "cvssScore": i.cvssScore,
                }
                if output_item not in vuln_list:
                    vuln_list.append(output_item)
        row_index = 0
        col_index = 0
        lst_col_headers = list(vuln_list[0].keys())
        for ch in lst_col_headers:
            excel_worksheet.write(
                row_index, col_index, lst_col_headers[col_index], format_colTitle
            )
            col_index += 1
        for v in vuln_list:
            row_index += 1
            col_index = 0
            for k in lst_col_headers:
                excel_worksheet.write(row_index, col_index, v[k])
                col_index += 1
    excel_workbook.close()
    print('\n' + org_name + '.xlsx' + ' created.')
