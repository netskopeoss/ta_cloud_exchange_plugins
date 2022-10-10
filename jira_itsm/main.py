"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""Jira ITSM plugin."""


from typing import List, Dict
import requests
import json
from requests.auth import HTTPBasicAuth

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    TaskStatus,
    Alert,
)
from netskope.common.utils import add_user_agent

# TODO: States are dynamic per project in Jira
STATE_MAPPINGS = {
    "in progress": TaskStatus.IN_PROGRESS,
    "new": TaskStatus.NEW,
    "on hold": TaskStatus.ON_HOLD,
    "closed": TaskStatus.CLOSED,
}


class JiraPlugin(PluginBase):
    """Jira plugin implementation."""

    def _get_issue(self, issue_id):
        """Fetch the issue with given ID from Jira."""
        params = self.configuration["auth"]
        response = requests.get(
            f"{params['url'].strip('/')}/rest/api/3/issue/{issue_id}",
            auth=HTTPBasicAuth(params["email"], params["api_token"]),
            headers=add_user_agent(),
            proxies=self.proxy,
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            self.logger.info(
                f"Jira ITSM: Could not fetch status of issue: {issue_id}. "
                f"Either it does not exist or configured user "
                f"does not have permission to access it."
            )
        else:
            raise requests.HTTPError(
                f"Could not fetch status of issue with ID {issue_id} from Jira."
            )

    def _get_atlassian_document(self, text):
        """Return Atlassian document format."""
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"text": text, "type": "text"}],
                }
            ],
        }

    def _get_createmeta(self, configuration, query_params):
        """Get metadata for creating an issue on Jira."""
        params = configuration["auth"]
        response = requests.get(
            f"{params['url'].strip('/')}/rest/api/3/issue/createmeta",
            auth=HTTPBasicAuth(params["email"], params["api_token"]),
            headers=add_user_agent(),
            params=query_params,
            proxies=self.proxy,
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            self.logger.error(
                f"Jira ITSM: Error occurred. {'; '.join(response.json().get('errors', {}).values())}"
            )
        else:
            raise requests.HTTPError(
                "Jira ITSM: Could not fetch create-metadata for Jira issue."
            )

    def _filter_mappings(self, create_meta, mappings):
        """Filter mappings based on project and issue type."""
        # First get screen fields for given project and issue type
        fields = []
        for _, field_meta in create_meta.get("fields").items():
            fields.append(field_meta.get("key"))

        # Create new mapping which only contains the on-screen attributes
        # That implies removing mappings which are not available in given
        # project and issue type create screen
        return {attr: mappings[attr] for attr in fields if attr in mappings}

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform."""
        params = self.configuration["auth"]
        project_id, issue_type = queue.value.split(":")
        jira_comment = {}
        if "comment" in mappings:
            jira_comment["comment_while_create"] = mappings["comment"]
        # Filter out the mapped attributes based on given project and issue_type
        create_meta = self._get_createmeta(
            self.configuration,
            {
                "expand": "projects.issuetypes.fields",
                "projectIds": project_id,  # This will return a list of single project
                "issuetypeNames": issue_type,  # This will return a list of single issue type
            },
        )
        if not create_meta.get("projects") or not create_meta.get("projects")[
            0
        ].get("issuetypes"):
            self.logger.error(
                f"Jira ITSM: Project or issue type {queue.label} may no longer exist."
            )
            raise requests.HTTPError(
                "Jira ITSM: Could not create the Jira ticket."
            )
        create_meta = create_meta.get("projects")[0].get("issuetypes")[0]
        mappings = self._filter_mappings(create_meta, mappings)
        body = {"fields": mappings}
        # Set fields with nested structure
        body["fields"]["issuetype"] = {"name": issue_type}
        body["fields"]["project"] = {"id": project_id}
        if "summary" in mappings:
            body["fields"]["summary"] = body["fields"]["summary"].replace(
                "\n", " "
            )
        if "description" in mappings:
            body["fields"]["description"] = self._get_atlassian_document(
                mappings["description"]
            )
        if "labels" in body["fields"]:
            try:
                body["fields"]["labels"] = [
                    label.strip()
                    for label in json.loads(body["fields"]["labels"])
                ]
            except json.decoder.JSONDecodeError:
                body["fields"]["labels"] = [
                    label.strip()
                    for label in body["fields"]["labels"].split(",")
                ]
            except Exception as err:
                self.logger.error(
                    f"JIRA ITSM: Error occurred while parsing label: {err}"
                )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        response = requests.post(
            f"{params['url'].strip('/')}/rest/api/3/issue",
            json=body,
            auth=HTTPBasicAuth(params["email"], params["api_token"]),
            headers=add_user_agent(headers),
            proxies=self.proxy,
        )

        if response.status_code == 201:
            result = response.json()
            # Fetch the recently created issue
            issue = self._get_issue(result.get("key"))
            issue_status = str(
                issue.get("fields", {}).get("status", {}).get("name")
            ).lower()
            task = Task(
                id=result.get("key"),
                status=STATE_MAPPINGS.get(issue_status, TaskStatus.OTHER),
                link=(
                    f"{self.configuration['auth']['url'].strip('/')}/browse/"
                    f"{result.get('key')}"
                ),
            )
            if jira_comment:
                self.update_task(task, alert, jira_comment, queue)
            return task
        elif response.status_code == 400:
            self.logger.error(
                f"Jira ITSM: Error occurred. {'; '.join(response.json().get('errors', {}).values())}"
            )
            raise requests.HTTPError(
                "Jira ITSM: Could not create the Jira ticket."
            )
        else:
            raise requests.HTTPError(
                "Jira ITSM: Could not create the Jira ticket."
            )

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        params = self.configuration["auth"]
        task_ids = [task.id for task in tasks]
        task_statuses = {}
        body = {
            "jql": f"key IN ({','.join(task_ids)})",
            "maxResults": 100,
            "fields": ["status"],  # We only need status of Jira tickets
            "startAt": 0,
            "validateQuery": "none",
        }

        while True:
            response = requests.post(
                f"{params['url'].strip('/')}/rest/api/3/search",
                headers=add_user_agent(),
                json=body,
                auth=HTTPBasicAuth(params["email"], params["api_token"]),
                proxies=self.proxy,
            )
            response.raise_for_status()
            if response.status_code == 200:
                json_res = response.json()
                body["startAt"] += json_res["maxResults"]

                if len(json_res["issues"]) == 0:
                    break

                for issue in json_res["issues"]:
                    task_statuses[issue.get("key")] = (
                        issue.get("fields", {}).get("status", {}).get("name")
                    ).lower()

        for task in tasks:
            if task_statuses.get(task.id):
                task.status = STATE_MAPPINGS.get(
                    task_statuses.get(task.id), TaskStatus.OTHER
                )
            else:
                task.status = TaskStatus.DELETED
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing Jira issue."""
        params = self.configuration["auth"]
        if mappings.get("comment_while_create", None):
            data = mappings["comment_while_create"]
        elif mappings.get("comment", None):
            data = mappings["comment"]
        else:  # default
            data = f"New alert received at {str(alert.timestamp)}."
        comment = {"body": self._get_atlassian_document(data)}
        response = requests.post(
            f"{params['url'].strip('/')}/rest/api/3/issue/{task.id}/comment",
            headers=add_user_agent(),
            json=comment,
            auth=HTTPBasicAuth(params["email"], params["api_token"]),
            proxies=self.proxy,
        )
        if response.status_code == 201:
            return task
        elif response.status_code == 404:
            self.logger.info(
                f"Jira ITSM: Issue with ID {task.id} no longer exists on Jira"
                f" or the configured user does not have permission to add"
                f"comment(s)."
            )
            return task
        else:
            raise requests.HTTPError(
                f"Could not add comment the existing issue on Jira with ID {task.id}."
            )

    def _validate_auth(self, configuration):
        """Validate the authentication step."""
        try:
            params = configuration["auth"]
            if params["url"].strip().lower()[:8] != "https://":
                return ValidationResult(
                    success=False,
                    message='Format of Jira URL should be "https://<your-domain>.atlassian.net"',
                )
            response = requests.get(
                f"{params['url'].strip('/')}/rest/api/3/myself",
                auth=HTTPBasicAuth(params["email"], params["api_token"]),
                headers=add_user_agent(),
                proxies=self.proxy,
            )
            response.raise_for_status()
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except Exception as ex:
            self.logger.error(
                "Jira ITSM: Could not validate authentication credentials."
            )
            self.logger.error(repr(ex))
        return ValidationResult(
            success=False,
            message="Error occurred while validating account credentials.",
        )

    def _get_valid_issue_types(self, configuration):
        """Fetch valid issue types for all projects for configured Jira instance."""
        create_meta = self._get_createmeta(configuration, {})
        valid_issue_types = []
        for project in create_meta.get("projects"):
            for issue_type in project.get("issuetypes"):
                valid_issue_types.append(issue_type.get("name"))
        return valid_issue_types

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters."""
        params = configuration["params"]
        if "issue_type" not in params or len(params["issue_type"]) == 0:
            return ValidationResult(
                success=False,
                message="Jira issue type(s) can not be empty.",
            )

        # split the CSVs
        configured_issue_types = [
            x.strip() for x in params["issue_type"].split(",")
        ]
        valid_issue_types = self._get_valid_issue_types(configuration)
        invalid_issue_types = list(
            set(configured_issue_types) - set(valid_issue_types)
        )

        if invalid_issue_types:
            return ValidationResult(
                success=False,
                message=f"Found invalid Jira issue type(s): {', '.join(invalid_issue_types)}",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the available fields for issues/tickets."""
        params = configuration["auth"]

        response = requests.get(
            f"{params['url'].strip('/')}/rest/api/3/field",
            auth=HTTPBasicAuth(params["email"], params["api_token"]),
            headers=add_user_agent(),
            proxies=self.proxy,
        )

        response.raise_for_status()
        if response.status_code == 200:
            return list(
                map(
                    lambda item: MappingField(
                        label=item.get("name"), value=item.get("key")
                    )
                    if item.get("key") not in ["comment"]
                    else MappingField(
                        label=item.get("name"),
                        value=item.get("key"),
                        updateAble=True,
                    ),
                    response.json(),
                )
            )
        else:
            raise requests.HTTPError(
                "Jira ITSM: Could not fetch available fields from Jira."
            )

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="summary",
                    custom_message="Netskope $appCategory alert: $alertName",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                        "Alert Type: $alertType\nApp Category: $appCategory\nUser: $user"
                    ),
                ),
            ],
            "dedup": [],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        params = self.configuration["auth"]
        start_at, is_last = 0, False
        projects = []
        issue_types = self.configuration["params"]["issue_type"]
        issue_types = list(map(lambda x: x.strip(), issue_types.split(",")))
        total_ids = []
        while not is_last:
            response = requests.get(
                f"{params['url'].strip('/')}/rest/api/3/project/search",
                params={"startAt": start_at, "maxResults": 50},
                headers=add_user_agent(),
                auth=HTTPBasicAuth(params["email"], params["api_token"]),
                proxies=self.proxy,
            )

            response.raise_for_status()
            if response.status_code == 200:
                json_res = response.json()
                is_last = json_res["isLast"]
                start_at += json_res["maxResults"]
                # Create combination of projects and issue types
                for project in json_res.get("values"):
                    total_ids.append(project.get("id"))
                # batches of 650 Project ids if we pass more than that
                # it will throw 500 server error
                if is_last or (start_at % 650) == 0:
                    total_project_ids = ",".join(total_ids)
                    meta = self._get_createmeta(
                        self.configuration,
                        {"projectIds": total_project_ids},
                    )
                    projects_list = meta.get("projects")
                    for project in projects_list:
                        if not project:
                            continue
                        for issue_type in project.get("issuetypes"):
                            # Issue type is defined as a "key:value" string
                            # Value of queue is defined as "project_id:issue_type" string
                            if issue_type.get("name") not in issue_types:
                                continue
                            projects.append(
                                Queue(
                                    label=f"{project.get('name')} - {issue_type.get('name')}",
                                    value=f"{project.get('id')}:{issue_type.get('name')}",
                                )
                            )
                    total_ids = []  # restart the batch ids
            else:
                raise requests.HTTPError(
                    "Jira ITSM: Could not fetch projects from Jira."
                )
        return projects
