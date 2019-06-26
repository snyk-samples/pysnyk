from typing import Any, List, Dict, Optional, Union

import requests

from .models import Organization, Project
from .errors import (
    SnykError,
    SnykNotFoundError,
    SnykProjectNotFoundError,
    SnykNotImplementedError,
)
from .managers import OrganizationManager


class SnykClient(object):
    API_URL = "https://snyk.io/api/v1"

    def __init__(self, token: str, url: Optional[str] = None):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.api_headers = {"Authorization": "token %s" % self.api_token}
        self.api_post_headers = self.api_headers
        self.api_post_headers["Content-Type"] = "application/json"

    def post(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.post(url, json=body, headers=self.api_post_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def put(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.put(url, json=body, headers=self.api_post_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def get(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.get(url, headers=self.api_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def delete(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.delete(url, headers=self.api_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    @property
    def organizations(self) -> OrganizationManager:
        return OrganizationManager(self)

    @property
    def projects(self) -> List[Project]:
        projects = []
        for org in self.organizations.all():
            projects.extend(org.projects)
        return projects

    def project(self, id) -> Union[Project, None]:
        for org in self.organizations.all():
            try:
                return org.project(id)
            except SnykProjectNotFoundError:
                pass
        raise SnykProjectNotFoundError

    # https://snyk.docs.apiary.io/#reference/general/the-api-details/get-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-notification-settings/modify-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/groups/organisations-in-groups/create-a-new-organisation-in-the-group
    # https://snyk.docs.apiary.io/#reference/0/list-members-in-a-group/list-all-members-in-a-group
    # https://snyk.docs.apiary.io/#reference/0/members-in-an-organisation-of-a-group/add-a-member-to-an-organisation-from-another-organisation-in-the-group
    def groups(self):
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/reporting-api/issues/get-list-of-issues
    def issues(self):
        raise SnykNotImplementedError
