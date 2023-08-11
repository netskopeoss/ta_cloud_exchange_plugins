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
import traceback
from typing import List, Dict
import requests
import json
from requests.auth import HTTPBasicAuth
import os
import time
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
PLATFORM_NAME = "Jira ITSM"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "1.1.0"
MAX_RETRY_COUNT = 4
LIMIT = 50


class JiraITSMException(Exception):
    """JiraITSMException exception class."""

    pass


class JiraPlugin(PluginBase):
    """Jira plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize ServiceNow plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details. Error: {}".format(exp)
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _add_user_agent(self, headers=None) -> str:
        """Add Client Name to request plugin make.

        Returns:
            str: String containing the Client Name.
        """
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent_str = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower(),
            self.plugin_version,
        )

        headers["User-Agent"] = user_agent_str
        return headers

    def _get_issue(self, issue_id):
        """Fetch the issue with given ID from Jira."""
        params = self.configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        response = self._api_helper(
            lambda: requests.get(
                "{}/rest/api/3/issue/{}".format(
                    url.strip("/").strip(), issue_id
                ),
                auth=HTTPBasicAuth(email.strip(), api_token),
                headers=self._add_user_agent(),
                proxies=self.proxy,
            ),
            "fetching issue details",
            False,
        )
        if response.status_code == 200:
            return self.parse_response(response)
        elif response.status_code == 404:
            err_msg = (
                "Could not fetch status of issue: {}. "
                "Either it does not exist or configured "
                "user does not have permission to access it.".format(issue_id),
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received response: {response.text}",
            )
            raise JiraITSMException(err_msg)

        else:
            err_msg = (
                "Could not fetch status of issue with ID {} from Jira.".format(
                    issue_id
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received response: {response.text}",
            )

            response.raise_for_status()
            raise JiraITSMException(err_msg)

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
        params = configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        msg = "fetching create-metadata"
        err_msg = "Could not fetch create-metadata for Jira issue."

        response = self._api_helper(
            lambda: requests.get(
                "{}/rest/api/3/issue/createmeta".format(
                    url.strip("/").strip()
                ),
                auth=HTTPBasicAuth(email.strip(), api_token),
                headers=self._add_user_agent(),
                params=query_params,
                proxies=self.proxy,
            ),
            msg,
            False,
        )
        if response.status_code == 200:
            return self.parse_response(response)
        elif response.status_code == 400:
            resp_json = self.parse_response(response)
            errors = list(resp_json.get("errors", {}).values())
            errorMessages = list(resp_json.get("errorMessages", []))
            errors.extend(errorMessages)
            self.logger.error(
                message="{}: Error occurred while {}. Error: {}".format(
                    self.log_prefix, msg, "; ".join(errors)
                ),
                details=f"Received response: {response.text}",
            )
            raise JiraITSMException(err_msg)
        else:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received response: {response.text}",
            )
            response.raise_for_status()
            raise JiraITSMException(err_msg)

    def _filter_mappings(self, create_meta, mappings):
        """Filter mappings based on project and issue type."""
        # First get screen fields for given project and issue type
        fields = []
        for _, field_meta in create_meta.get("fields", {}).items():
            fields.append(field_meta.get("key"))

        # Create new mapping which only contains the on-screen attributes
        # That implies removing mappings which are not available in given
        # project and issue type create screen

        filtered_mappings = {}
        for attr in fields:
            if attr in mappings:
                try:
                    filtered_mappings[attr] = json.loads(mappings[attr])
                except json.decoder.JSONDecodeError:
                    filtered_mappings[attr] = mappings[attr]

        return filtered_mappings

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform."""
        params = self.configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        project_id, issue_type = queue.value.split(":")
        msg = "creating task/issue"
        err_msg = "Could not create the Jira ticket."
        jira_comment = {}
        if "comment" in mappings:
            jira_comment["comment_while_create"] = mappings.get("comment")
        # Filter out the mapped attributes based on
        # given project and issue_type
        create_meta = self._get_createmeta(
            self.configuration,
            {
                "expand": "projects.issuetypes.fields",
                "projectIds": project_id,
                # This will return a list of single project
                "issuetypeNames": issue_type,
                # This will return a list of single issue type
            },
        )
        if not create_meta.get("projects", []) or not create_meta.get(
            "projects", [{}]
        )[0].get("issuetypes"):
            self.logger.error(
                "{}: Project or issue type {} "
                "may no longer exist.".format(self.log_prefix, queue.label)
            )
            raise JiraITSMException(
                "{}: Could not create the Jira ticket.".format(self.log_prefix)
            )
        create_meta = create_meta.get("projects", [{}])[0].get(
            "issuetypes", [{}]
        )[0]
        mappings = self._filter_mappings(create_meta, mappings)

        body = {"fields": mappings}
        # Set fields with nested structure
        body["fields"]["issuetype"] = {"name": issue_type}
        body["fields"]["project"] = {"id": project_id}
        if "summary" in mappings:
            body["fields"]["summary"] = (
                body.get("fields", {}).get("summary").replace("\n", " ")
            )
        if "description" in mappings and not isinstance(
            mappings["description"], dict
        ):
            body["fields"]["description"] = self._get_atlassian_document(
                str(mappings.get("description"))
            )
        if "labels" in mappings:
            labels = mappings.get("labels")
            if isinstance(labels, str):
                body["fields"]["labels"] = [
                    label.strip() for label in labels.split(",")
                ]
            elif not isinstance(labels, list):
                self.logger.warn(
                    "{}: invalid input provided for Labels. "
                    "Valid input: comma-separated values or a list of values "
                    '(e.g., label1, label2 or ["label1", "label2"])'.format(
                        self.log_prefix
                    )
                )

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        response = self._api_helper(
            lambda: requests.post(
                f"{url.strip('/').strip()}/rest/api/3/issue",
                json=body,
                auth=HTTPBasicAuth(email.strip(), api_token),
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
            ),
            msg,
            False,
        )
        if response.status_code == 201:
            resp_json = self.parse_response(response)

            # Fetch the recently created issue
            issue_key = resp_json.get("key")
            issue = self._get_issue(issue_key)
            issue_status = str(
                issue.get("fields", {}).get("status", {}).get("name")
            ).lower()
            task = Task(
                id=issue_key,
                status=STATE_MAPPINGS.get(issue_status, TaskStatus.OTHER),
                link="{}/browse/{}".format(
                    url.strip("/").strip(),
                    issue_key,
                ),
            )
            if jira_comment:
                self.update_task(task, alert, jira_comment, queue)
            return task
        elif response.status_code == 400:
            resp_json = self.parse_response(response)
            errors = list(resp_json.get("errors", {}).values())
            errorMessages = list(resp_json.get("errorMessages", []))
            errors.extend(errorMessages)

            self.logger.error(
                message="{}: Error occurred while {}. Error: {}".format(
                    self.log_prefix, msg, "; ".join(errors)
                ),
                details=f"Received response: {response.text}",
            )
            raise JiraITSMException(err_msg)
        else:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received response: {response.text}",
            )
            response.raise_for_status()
            raise JiraITSMException(err_msg)

    def chunks(self, lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        params = self.configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        msg = "syncing task states"
        task_ids = [task.id for task in tasks]
        task_statuses = {}
        count = 0
        for total in self.chunks(task_ids, 10000):
            body = {
                "jql": f"key IN ({','.join(total)})",
                "maxResults": 100,
                "fields": ["status"],  # We only need status of Jira tickets
                "startAt": 0,
                "validateQuery": "none",
            }
            issue_count = 0

            while True:
                json_res = self._api_helper(
                    lambda: requests.post(
                        "{}/rest/api/3/search".format(url.strip("/").strip()),
                        headers=self._add_user_agent(),
                        json=body,
                        auth=HTTPBasicAuth(email.strip(), api_token),
                        proxies=self.proxy,
                    ),
                    msg,
                )

                body["startAt"] += json_res.get("maxResults")

                for issue in json_res.get("issues", []):
                    task_statuses[issue.get("key")] = (
                        issue.get("fields", {})
                        .get("status", {})
                        .get("name", "")
                    ).lower()
                issue_count = len(json_res.get("issues", []))

                self.logger.info(
                    "{}: Successfully synced {} ticket(s) from Jira ITSM "
                    "in current page. Total {} Tickets(s) synced so far "
                    "in the current sync cycle.".format(
                        self.log_prefix,
                        issue_count,
                        issue_count + count,
                    )
                )
                count += issue_count
                if issue_count == 0 or body.get("startAt", len(total)) >= len(
                    total
                ):
                    break

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
        params = self.configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        if mappings.get("comment_while_create", None):
            data = mappings.get("comment_while_create")
        elif mappings.get("comment", None):
            data = mappings.get("comment")
        else:  # default
            data = f"New alert received at {str(alert.timestamp)}."

        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            pass
        if not isinstance(data, dict):
            comment = {"body": self._get_atlassian_document(str(data))}
        else:
            comment = {"body": data}
        response = self._api_helper(
            lambda: requests.post(
                "{}/rest/api/3/issue/{}/comment".format(
                    url.strip("/").strip(), task.id
                ),
                headers=self._add_user_agent(),
                json=comment,
                auth=HTTPBasicAuth(email.strip(), api_token),
                proxies=self.proxy,
            ),
            "updating task with id {}".format(task.id),
            False,
        )
        if response.status_code == 201:
            return task
        elif response.status_code == 404:
            self.logger.warn(
                "{}: Issue with ID {} no longer exists on Jira "
                "or the configured user does not have permission to add"
                "comment(s).".format(self.log_prefix, task.id)
            )
            return task
        else:
            err_msg = (
                "Could not add comment the existing issue on "
                "Jira with ID {}."
            ).format(task.id)

            self.logger.error(
                message="{}: {}.".format(self.log_prefix, err_msg),
                details=f"Received response: {response.text}",
            )
            response.raise_for_status()
            raise JiraITSMException(err_msg)

    def _validate_auth(self, configuration):
        """Validate the authentication step."""
        try:
            params = configuration.get("auth", {})
            url = params.get("url")
            email = params.get("email")
            api_token = params.get("api_token")
            if "url" not in params or type(url) != str or not url.strip():
                err_msg = "Jira Cloud Instance URL is required field."
                self.logger.error(
                    "{}: Validation error occurred, Error: {}".format(
                        self.log_prefix, err_msg
                    )
                )
                return ValidationResult(success=False, message=err_msg)

            elif url.strip().lower()[:8] != "https://":
                return ValidationResult(
                    success=False,
                    message=(
                        "Format of Jira URL should be "
                        '"https://<your-domain>.atlassian.net"'
                    ),
                )

            if (
                "email" not in params
                or type(email) != str
                or not email.strip()
            ):
                err_msg = "Email Address is required field."
                self.logger.error(
                    "{}: Validation error occurred, Error: {}".format(
                        self.log_prefix, err_msg
                    )
                )
                return ValidationResult(success=False, message=err_msg)

            if (
                "api_token" not in params
                or type(api_token) != str
                or not api_token
            ):
                err_msg = "API Token is required field."
                self.logger.error(
                    "{}: Validation error occurred, Error: {}".format(
                        self.log_prefix, err_msg
                    )
                )
                return ValidationResult(success=False, message=err_msg)
            header = {"Accept": "application/json"}
            response = self._api_helper(
                lambda: requests.get(
                    "{}/rest/api/3/myself".format(url.strip("/").strip()),
                    auth=HTTPBasicAuth(email.strip(), api_token),
                    headers=self._add_user_agent(header),
                    proxies=self.proxy,
                ),
                " validating credentials",
                False,
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 401:
                err_msg = "Invalid Email Address or API Token provided."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif response.status_code == 403:
                err_msg = (
                    "The requested operation is not permitted for this user."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            else:
                response.raise_for_status()
                resp_json = self.parse_response(response)
                msg = "Authentication Failed. Check logs for more details."

                err_msg = (
                    f"Validation error occurred with response {resp_json}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: Validation error occurred.",
                    details=f"Error Details: {err_msg}",
                )
                return ValidationResult(success=False, message=msg)

        except JiraITSMException as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))

    def _get_valid_issue_types(self, configuration):
        """Fetch valid issue types for all projects for
        configured Jira instance."""
        create_meta = self._get_createmeta(configuration, {})
        valid_issue_types = []
        for project in create_meta.get("projects", []):
            for issue_type in project.get("issuetypes", []):
                valid_issue_types.append(issue_type.get("name"))
        return valid_issue_types

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters."""
        params = configuration.get("params", {})
        issue_type = params.get("issue_type")
        if "issue_type" not in params or len(issue_type) == 0:
            return ValidationResult(
                success=False,
                message="Jira issue type(s) can not be empty.",
            )

        # split the CSVs
        configured_issue_types = [x.strip() for x in issue_type.split(",")]
        valid_issue_types = self._get_valid_issue_types(configuration)
        invalid_issue_types = list(
            set(configured_issue_types) - set(valid_issue_types)
        )

        if invalid_issue_types:
            return ValidationResult(
                success=False,
                message="Found invalid Jira issue type(s): {}".format(
                    ", ".join(invalid_issue_types)
                ),
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
        params = configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")

        response = self._api_helper(
            lambda: requests.get(
                "{}/rest/api/3/field".format(url.strip("/").strip()),
                auth=HTTPBasicAuth(email.strip(), api_token),
                headers=self._add_user_agent(),
                proxies=self.proxy,
            ),
            "fetching all available fields for issues/tickets",
        )

        return list(
            map(
                lambda item: MappingField(
                    label=item.get("name"), value=item.get("id")
                )
                if item.get("id") not in ["comment"]
                else MappingField(
                    label=item.get("name"),
                    value=item.get("id"),
                    updateAble=True,
                ),
                response,
            )
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
                        "Alert Type: $alertType\nApp Category: $appCategory\n"
                        "User: $user"
                    ),
                ),
            ],
            "dedup": [],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        params = self.configuration.get("auth", {})
        url = params.get("url")
        email = params.get("email")
        api_token = params.get("api_token")
        start_at, is_last = 0, False
        projects = []
        issue_types = self.configuration.get("params", {}).get("issue_type")
        issue_types = list(map(lambda x: x.strip(), issue_types.split(",")))
        total_ids = []

        while not is_last:
            response = self._api_helper(
                lambda: requests.get(
                    "{}/rest/api/3/project/search".format(
                        url.strip("/").strip()
                    ),
                    params={"startAt": start_at, "maxResults": 50},
                    headers=self._add_user_agent(),
                    auth=HTTPBasicAuth(email.strip(), api_token),
                    proxies=self.proxy,
                ),
                "fetching projects from Jira as queues",
            )

            is_last = response.get("isLast")
            start_at += response.get("maxResults")
            # Create combination of projects and issue types
            for project in response.get("values", []):
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
                        # Value of queue is defined
                        # as "project_id:issue_type" string
                        if issue_type.get("name") not in issue_types:
                            continue
                        projects.append(
                            Queue(
                                label="{} - {}".format(
                                    project.get("name"),
                                    issue_type.get("name"),
                                ),
                                value="{}:{}".format(
                                    project.get("id"),
                                    issue_type.get("name"),
                                ),
                            )
                        )
                total_ids = []  # restart the batch ids

        return projects

    def parse_response(self, response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = "Invalid JSON response received. Error: {}".format(err)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(err_msg)

    def handle_error(self, response, logger_msg):
        """Handle API Status code errors.

        Args:
            response (Requests response object): Response object of requests.
        """
        resp_json = self.parse_response(response)

        if response.status_code in [200, 201]:
            return resp_json
        elif response.status_code == 401:
            err_msg = (
                "Received exit code {} while {}. Verify "
                "Username or Password provided in "
                "configuration parameters.".format(
                    response.status_code, logger_msg
                )
            )
        elif response.status_code == 403:
            err_msg = (
                "Received exit code {} while {}. This error may "
                "occur if configured user does not have access "
                "to perform this operation.".format(
                    response.status_code, logger_msg
                )
            )
        elif response.status_code >= 400 and response.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP Client error while {}.".format(
                    response.status_code, logger_msg
                )
            )
        elif response.status_code >= 500 and response.status_code < 600:
            err_msg = (
                "Received exit code {}. HTTP Server Error while {}.".format(
                    response.status_code, logger_msg
                )
            )
        else:
            err_msg = "Received exit code {}, HTTP error while {}.".format(
                response.status_code, logger_msg
            )
        resp_err_msg = resp_json.get(
            "error",
            {"message": "No error details found in response."},
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=str(resp_err_msg),
        )
        raise JiraITSMException(err_msg)

    def _api_helper(self, request, logger_msg, is_handle_error_required=True):
        """Helper function for api call."""

        try:
            for retry_counter in range(MAX_RETRY_COUNT):
                response = request()
                if response.status_code == 429:
                    resp_json = self.parse_response(response)
                    resp_err_msg = resp_json.get(
                        "error",
                        {"message": "No error details found in response."},
                    )
                    if retry_counter == MAX_RETRY_COUNT - 1:
                        err_msg = (
                            "Received exit code 429, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code 429.".format(logger_msg)
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=resp_err_msg,
                        )
                        raise JiraITSMException(err_msg)
                    retry_after = response.headers.get("Retry-After")
                    if retry_after is None:
                        self.logger.info(
                            "{}: No Retry-After value received from"
                            "API hence plugin will retry after 60 "
                            "seconds.".format(self.log_prefix)
                        )
                        time.sleep(60)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = abs(retry_after - time.time())
                    if diff_retry_after > 300:
                        err_msg = (
                            "'Retry-After' value received from "
                            "response headers while {} is greater than 5  "
                            "minutes hence returning status code 429.".format(
                                logger_msg
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise JiraITSMException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code 429, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                logger_msg,
                                diff_retry_after,
                                MAX_RETRY_COUNT - 1 - retry_counter,
                            )
                        ),
                        details=resp_err_msg,
                    )
                    time.sleep(diff_retry_after)

                else:
                    return (
                        self.handle_error(response, logger_msg)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as exp:
            err_msg = (
                "ProxyError occurred while {}. "
                "Verify proxy configuration. Error: {}".format(logger_msg, exp)
            )
            toast_msg = "Invalid Proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(toast_msg)
        except requests.exceptions.ConnectionError as exp:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}. Proxy server or {} "
                "is not reachable or Invalid Jira Cloud "
                "Instance URL provided. Error: {}".format(
                    PLATFORM_NAME, logger_msg, PLATFORM_NAME, exp
                )
            )
            toast_msg = (
                "Proxy server or {} is not reachable or "
                "Invalid Jira Cloud Instance URL provided.".format(
                    PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(toast_msg)
        except requests.exceptions.RequestException as exp:
            err_msg = (
                "Error occurred while requesting"
                " to {} server for {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            toast_msg = (
                "Request exception occurred. Check logs for more details"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(toast_msg)
        except Exception as exp:
            err_msg = (
                "Exception occurred while making API call to"
                " {} server while {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            toast_msg = "Exception occurred. Check logs for more details"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise JiraITSMException(toast_msg)
