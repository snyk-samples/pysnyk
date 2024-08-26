import argparse
import json

import xlsxwriter

import ProjectDependenciesReport
from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--projectId",
        type=str,
        help="The project ID in Snyk. Use --projectId=all for all projects.",
        required=True,
    )
    parser.add_argument(
        "--outputPathExcel",
        type=str,
        help="The desired output if you want Excel output (use .xlsx).",
    )
    parser.add_argument(
        "--outputPathCSV", type=str, help="The desired output if you want CSV output."
    )
    parser.add_argument(
        "--outputPathNestedJson",
        type=str,
        help="The desired output if you want a nested JSON output.",
    )
    parser.add_argument(
        "--outputPathFlatJson",
        type=str,
        help="The desired output if you want a flattened JSON output.",
    )
    args = parser.parse_args()
    if (
        args.outputPathExcel is None
        and args.outputPathCSV is None
        and args.outputPathNestedJson is None
        and args.outputPathFlatJson is None
    ):
        parser.error("You must specify one or more output options.")
        parser.print_help()
    return args


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId

output_excel_path = args.outputPathExcel
output_csv_path = args.outputPathCSV
output_nested_json_path = args.outputPathNestedJson
output_flat_json_path = args.outputPathFlatJson


def get_flat_dependencies(dep_list):
    flat_dep_list = []
    for d in dep_list:
        package_id = d["pkgId"]
        licences = d["licenses"]
        path = d["path"]

        simplified_liceses_list = [l.title for l in licences]
        licenses_str = ", ".join(simplified_liceses_list)

        license_issues_list = [l.severity for l in licences]
        license_issues_str = ", ".join(license_issues_list)

        flat_dep_list.append(
            {
                "pkgId": package_id,
                "path": path,
                "licenses": licenses_str,
                "license_issues": license_issues_str,
            }
        )
        flat_child_deps_list = get_flat_dependencies(d["dependencies"])
        flat_dep_list.extend(flat_child_deps_list)
    return flat_dep_list


# Get all projects (except for Docker ones)
allowed_origins = [
    "cli",
    "github",
    "bitbucket-server",
    "bitbucket-cloud",
    "github-enterprise",
    "gitlab",
]

all_projects_list = []
client = SnykClient(snyk_token)
projects = client.organizations.get(org_id).projects.all()
for proj in projects:
    if proj.attributes.origin in allowed_origins:
        all_projects_list.append({"project_id": proj.id, "project_name": proj.attributes.name})

project_trees = []
flattened_project_dependencies_lists = []
all_project_info = []
all_flattenend_project_dependencies_list = []

for next_project in all_projects_list:
    next_project_id = next_project["project_id"]

    if args.projectId == "all" or next_project_id == args.projectId:
        # Deprecated, check api-demo-2c-list-issues-aggregated
        next_project_tree = ProjectDependenciesReport.get_project_tree(
            snyk_token, org_id, next_project_id
        )
        project_trees.append(next_project_tree["project"]["dependencies"])

        next_project_flat_deps_list = get_flat_dependencies(
            next_project_tree["project"]["dependencies"]
        )
        flattened_project_dependencies_lists.append(next_project_flat_deps_list)
        all_flattenend_project_dependencies_list.extend(next_project_flat_deps_list)

        all_project_info.append(
            {
                "project_id": next_project_id,
                "project_name": next_project["project_name"],
                "project_tree": next_project_tree,
                "flat_deps_list": next_project_flat_deps_list,
            }
        )


def write_all_projects_nested_json(all_project_info, output_path):
    all_projects_with_flattened_dependencies_tree_removed = []

    for p in all_project_info:
        new_proj_info = dict(p)
        del new_proj_info["flat_deps_list"]
        all_projects_with_flattened_dependencies_tree_removed.append(new_proj_info)

    projects_obj = {"projects": all_projects_with_flattened_dependencies_tree_removed}

    with open(output_path, "w") as output_json:
        json.dump(projects_obj, output_json, indent=4)


def write_all_projects_flat_json(all_project_info, output_path):
    all_projects_with_flattened_dependencies_tree_removed = []

    for p in all_project_info:
        new_proj_info = dict(p)
        del new_proj_info["project_tree"]
        all_projects_with_flattened_dependencies_tree_removed.append(new_proj_info)

    projects_obj = {"projects": all_projects_with_flattened_dependencies_tree_removed}

    with open(output_path, "w") as output_json:
        json.dump(projects_obj, output_json, indent=4)


def write_all_project_output_csv(all_project_info, output_path):
    # using tab delimitation because I used ',' for the licenses

    with open(output_path, "w") as output_csv:
        for next_project in all_project_info:
            str_csv_line = "%s  %s  %s  %s" % (
                next_project["project_name"],
                "License(s)",
                "License Issue(s)",
                "Application and Path",
            )
            output_csv.write("%s\n" % str_csv_line)

            flattened_dependencies_list = next_project["flat_deps_list"]
            for next_dep in flattened_dependencies_list:
                str_csv_line = "%s  %s  %s  %s" % (
                    next_dep["pkgId"],
                    next_dep["licenses"],
                    next_dep["license_issues"],
                    next_dep["path"],
                )
                output_csv.write("%s\n" % str_csv_line)

            output_csv.write("\n")  # empty row to separate projects


def write_all_project_output_excel(all_project_info, output_path):
    excel_workbook = xlsxwriter.Workbook(output_path)
    excel_worksheet = excel_workbook.add_worksheet()
    format_bold = excel_workbook.add_format({"bold": True})

    row_index = 0

    for next_project in all_project_info:
        excel_worksheet.write(row_index, 0, next_project["project_name"], format_bold)
        excel_worksheet.write(row_index, 1, "License(s)", format_bold)
        excel_worksheet.write(row_index, 2, "License Issue(s)", format_bold)
        excel_worksheet.write(row_index, 3, "Application and Path", format_bold)
        row_index += 1

        flattened_dependencies_list = next_project["flat_deps_list"]

        for next_dep in flattened_dependencies_list:
            excel_worksheet.write(row_index, 0, next_dep["pkgId"])
            excel_worksheet.write(row_index, 1, next_dep["licenses"])
            excel_worksheet.write(row_index, 2, next_dep["license_issues"])
            excel_worksheet.write(row_index, 3, next_dep["path"])
            row_index += 1

        row_index += 1  # empty row to separate projects

    excel_workbook.close()


if output_excel_path:
    write_all_project_output_excel(all_project_info, output_excel_path)

if output_csv_path:
    write_all_project_output_csv(all_project_info, output_csv_path)

if output_nested_json_path:
    write_all_projects_nested_json(all_project_info, output_nested_json_path)

if output_flat_json_path:
    write_all_projects_flat_json(all_project_info, output_flat_json_path)
