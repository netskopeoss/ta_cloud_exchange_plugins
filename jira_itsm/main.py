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

CTO Jira plugin.
"""
import json
import re
import traceback
from typing import List, Dict, Tuple, Union
from urllib.parse import urlparse

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
    Event,
    UpdatedTaskValues
)

from .utils.constants import (
    LIMIT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
)
from .utils.helper import (
    JiraITSMPluginHelper,
    JiraITSMPluginException,
)


class JiraPlugin(PluginBase):
    """Jira CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Jira plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.jira_helper = JiraITSMPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = JiraPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_issue(self, issue_id):
        """Fetch the issue details with given ID from Jira.

        Args:
            issue_id (str): ID of the issue.

        Returns:
            dict: Dictionary containing issue details.
        """
        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/issue/{issue_id}"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )
        log_msg = f"details of the ticket with ID '{issue_id}' from {PLATFORM_NAME}"
        self.logger.info(
            f"{self.log_prefix}: Fetching {log_msg}."
        )
        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"fetching {log_msg}",
            )
            return response
        except JiraITSMPluginException:
            raise
        except Exception as error:
            error_message = "Unexpected error occurred"
            err_msg = (
                f"{error_message} while getting mapping "
                f"fields from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}"
            )
            raise JiraITSMPluginException(err_msg)

    def _get_atlassian_document(self, text):
        """
        Return Atlassian document format.

        Args:
            text (str): Text to be converted into Atlassian document format.

        Returns:
            dict: Dictionary containing Atlassian document format.
        """
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

    def _get_project_issues(self, log_msg: str, configuration: dict):
        """Get issues of all projects from Jira.

        Args:
            log_msg (str): Log message.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            list: List of projects with issues.
        """
        start_at, is_last = 0, False
        projects = []

        url, email_address, api_token = self.jira_helper.get_auth_params(configuration)
        endpoint = f"{url}/rest/api/3/project/search"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )

        while not is_last:
            try:
                params = {"startAt": start_at, "maxResults": LIMIT, "expand": "issueTypes"}
                response = self.jira_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=log_msg,
                    is_validation=True
                )
                page_projects = response.get("values", [])
                projects.extend(page_projects)

                is_last = response.get("isLast", False)
                start_at += LIMIT
            except JiraITSMPluginException:
                raise
            except Exception as error:
                err_msg = (
                    f"Error occurred while {log_msg}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=str(traceback.format_exc())
                )
                raise JiraITSMPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(projects)} project(s) from the {PLATFORM_NAME}."
        )
        return projects

    def _filter_mappings(self, issue_fields, mappings):
        """
        Filter mappings based on project and issue type.

        Args:
            issue_fields (list): List of issue fields returned by Jira.
            mappings (dict): Dictionary of the mapped fields.

        Returns:
            dict: Filtered mappings which only contains the on-screen attributes.
        """
        # First get screen fields for given project and issue type
        fields = []
        for field in issue_fields:
            fields.append(field.get("key", ""))

        # Create new mapping which only contains the on-screen attributes
        # That implies removing mappings which are not available in given
        # project and issue type create screen

        filtered_mappings = {}
        for attr in mappings.keys():
            if attr in fields:
                try:
                    filtered_mappings[attr] = json.loads(mappings[attr])
                except json.decoder.JSONDecodeError:
                    filtered_mappings[attr] = mappings[attr]

        return filtered_mappings

    def _make_body(self, mappings, project_id="", issue_type_id="", is_update=False):
        """Create body for Jira issue creation/update.

        Args:
            mappings (dict): Dictionary of the mapped fields.
            project_id (str): Project id.
            issue_type_id (str): Issue type id.
            is_update (bool): True if update else False.

        Returns:
            dict: Body for Jira issue creation/update.
        """
        body = {"fields": mappings}
        # Set fields with nested structure
        if not is_update:
            body["fields"]["issuetype"] = {"id": issue_type_id}
            body["fields"]["project"] = {"id": project_id}

        if "summary" in mappings:
            body["fields"]["summary"] = (
                body.get("fields", {}).get("summary", "").replace("\n", " ")
            )
        if "description" in mappings and not isinstance(
            mappings["description"], dict
        ):
            body["fields"]["description"] = self._get_atlassian_document(
                str(mappings.get("description", ""))
            )
        if "labels" in mappings:
            labels = mappings.get("labels", "")
            if isinstance(labels, str):
                body["fields"]["labels"] = [
                    label.strip() for label in labels.split(",")
                ]
            elif not isinstance(labels, list):
                self.logger.error(
                    f"{self.log_prefix}: invalid input provided for Labels. "
                    "Valid input: comma-separated values or a list of values "
                    '(e.g., label1, label2 or ["label1", "label2"])'
                )

        return body

    def _ce_to_jira_status_mappings(self, jira_status: dict):
        """Get status mappings.

        Args:
            mapping_config (Dict): Mapping config.
            mappings (Dict): Mappings.

        Returns:
            dict: mappings with updated status mappings.
        """
        mapping_config = self.configuration.get("mapping_config", {})
        ce_to_jira_status = mapping_config.get("status_mapping", {})
        status_to_set = ce_to_jira_status.get(jira_status, "to do")

        return status_to_set

    def _get_status_mapping(self):
        """Get status mapping.

        Returns:
            dict: Status mapping.
        """
        mapping_config = self.configuration.get("mapping_config", {})
        jira_to_ce_status = {
            value.lower(): key for key, value in mapping_config.get("status_mapping", {}).items()
        }
        return {
            "status": jira_to_ce_status
        }

    def _update_task_details(self, task: Task, jira_data: dict):
        """Update task fields with ServiceNow data.

        Args:
            task (Task): CE task.
            jira_data (dict): Updated data from Jira.
        """
        if task.dataItem and task.dataItem.rawData:
            old_status = task.dataItem.rawData.get("status", TaskStatus.OTHER)
            if task.updatedValues:
                task.updatedValues.oldStatus = (
                    old_status if old_status.upper() in TaskStatus.__members__ else TaskStatus.OTHER
                )
                task.updatedValues.oldAssignee = task.dataItem.rawData.get(
                    "assignee", None
                )
            else:
                task.updatedValues = UpdatedTaskValues(
                    status=None,
                    oldStatus=(
                        old_status if old_status.upper() in TaskStatus.__members__
                        else TaskStatus.OTHER
                    ),
                    assignee=None,
                    oldAssignee=task.dataItem.rawData.get("assignee", None),
                )
        mapping_config = self._get_status_mapping()
        STATUS_MAPPINGS = mapping_config.get("status", {})

        if task.updatedValues:
            task.updatedValues.status = STATUS_MAPPINGS.get(
                jira_data.get("status"), TaskStatus.OTHER
            )

        if jira_data["assignee"]:
            task.updatedValues.assignee = jira_data["assignee"]

        task.status = STATUS_MAPPINGS.get(
            jira_data.get("status"), TaskStatus.OTHER
        )
        return task

    def _set_jira_status(self, task_id: str, jira_status: str):
        """Set Jira ticket status(transition).

        Args:
            task_id (str): Jira ticket id.
            jira_status (str): Jira status.
        """
        logger_message = f"Jira ticket '{task_id}'"
        jira_status_to_set = self._ce_to_jira_status_mappings(jira_status.lower())

        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/issue/{task_id}/transitions"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )

        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching available transitions for {logger_message}"
                ),
            )
            transitions = response.get("transitions", [])
            if not transitions:
                self.logger.info(
                    f"{self.log_prefix}: Transitions are not found for {logger_message}. "
                    f"Hence, skipping setting status for {logger_message}."
                )
                return
            for transition in transitions:
                if transition.get("name", "").lower() == jira_status_to_set.lower():
                    payload = {
                        "transition": {
                            "id": transition.get("id", "")
                        }
                    }
                    response = self.jira_helper.api_helper(
                        url=endpoint,
                        method="POST",
                        headers=headers,
                        json=payload,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=(
                            f"setting '{jira_status}' status for {logger_message}"
                        ),
                        is_handle_error_required=False
                    )
                    if response.status_code == 204:
                        self.logger.info(
                            f"{self.log_prefix}: Successfully set '{jira_status}' "
                            f"status for {logger_message}."
                        )
                        return
                    else:
                        self.jira_helper.handle_error(
                            resp=response,
                            logger_msg=(
                                f"setting status for {logger_message}."
                            )
                        )
        except JiraITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while setting status for {logger_message}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise JiraITSMPluginException(err_msg)

        return jira_status_to_set

    def _get_issue_fields(
        self,
        project_id,
        project_name,
        issue_type,
        issue_name,
        base_url,
        auth_headers
    ):
        """Get issue fields for a given project and issue type.

        Args:
            project_id (str): Project id.
            project_name (str): Project name.
            issue_type (str): Issue type.
            issue_name (str): Issue name.
            base_url (str): Base URL.
            auth_headers (dict): Authentication headers.

        Returns:
            list: List of issue fields.
        """
        logger_message = (
            f"fields for project '{project_name}' and issue type '{issue_name}' "
            f"from {PLATFORM_NAME} platform"
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching {logger_message}."
        )
        endpoint = f"{base_url}/rest/api/3/issue/createmeta/{project_id}/issuetypes/{issue_type}"
        max_results = 200
        params = {"startAt": 0, "maxResults": max_results}
        total_fields = []

        while True:
            try:
                response = self.jira_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    params=params,
                    headers=auth_headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"fetching {logger_message}"
                    ),
                    is_handle_error_required=False
                )
                if response.status_code == 200:
                    resp_json = self.jira_helper.parse_response(
                        response, f"fetching {logger_message}"
                    )
                    fields = resp_json.get("fields", [{}])
                    total_fields.extend(fields)
                    if len(fields) < max_results:
                        break
                    params["startAt"] += max_results
                elif response.status_code == 404:
                    err_msg = (
                        f"Could not create {PLATFORM_NAME} ticket. "
                        f"Project '{project_name}' or issue type '{issue_name}' "
                        f"may not exist on {PLATFORM_NAME} platform."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg}"
                    )
                    raise JiraITSMPluginException(err_msg)
                else:
                    self.jira_helper.handle_error(
                        resp=response,
                        logger_msg=f"fetching {logger_message}",
                    )
            except JiraITSMPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Error occurred while fetching {logger_message}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                raise JiraITSMPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_fields)} {logger_message}."
        )
        return total_fields

    def _get_edit_issue_fields(self, issue_id):
        """Get edit issue fields for given issue id.

        Args:
            issue_id (str): Issue id.

        Returns:
            list: List of issue fields.
        """
        logger_message = (
            f"edit fields for ticket '{issue_id}' "
            f"from {PLATFORM_NAME} platform"
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching {logger_message}."
        )
        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/issue/{issue_id}/editmeta"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )

        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching {logger_message}"
                ),
                is_handle_error_required=False
            )
            if response.status_code == 200:
                resp_json = self.jira_helper.parse_response(response, f"fetching {logger_message}")
                fields = resp_json.get("fields", {})
                edit_fields = list(fields.values())

            elif response.status_code == 404:
                return []
            else:
                self.jira_helper.handle_error(
                    resp=response,
                    logger_msg=f"fetching {logger_message}",
                )
        except JiraITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while fetching {logger_message}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise JiraITSMPluginException(err_msg)

        return edit_fields

    def create_task(self, alert, mappings: Dict, queue: Queue) -> Task:
        """Create an incident/issue on ServiceNow platform.

        Args:
            alert (Alert/Event): Alert/Event object.
            mappings (Dict): Field mappings.
            queue (Queue): Queue object.

        Returns:
            Task: Task object.
        """
        if not mappings:
            err_msg = (
                "No mappings found in Queue Configuration."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Queue mapping "
                f"is required to create a ticket on {PLATFORM_NAME}."
            )
            raise JiraITSMPluginException(err_msg)

        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"

        logger_message = (
            f"a Jira ticket for {event_type} ID '{alert.id}' on {PLATFORM_NAME} platform"
        )
        self.logger.info(
            f"{self.log_prefix}: Creating {logger_message}."
        )

        project_id, issue_type_id = queue.value.split(":")
        project_name, issue_name = re.match(r"(.*) - (.*)$", queue.label).groups()

        jira_comment = {}
        jira_status = ""
        if "comment" in mappings:
            jira_comment["comment_while_create"] = mappings.get("comment", "")
        if "status" in mappings:
            jira_status = mappings.get("status", "")

        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/issue"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )
        issue_fields = self._get_issue_fields(
            project_id,
            project_name,
            issue_type_id,
            issue_name,
            url,
            headers
        )

        mappings = self._filter_mappings(issue_fields, mappings)
        body = self._make_body(mappings, project_id, issue_type_id)

        headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="POST",
                json=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"creating {logger_message}"
                ),
                is_handle_error_required=False
            )
            if response.status_code == 201:
                resp_json = self.jira_helper.parse_response(response, f"creating {logger_message}")

                issue_key = resp_json.get("key", "")
                status = getattr(alert, "rawData").get("status", TaskStatus.OTHER)
                task = Task(
                    id=issue_key,
                    status=status if status.upper() in TaskStatus.__members__ else TaskStatus.OTHER,
                    link=f"{url.strip('/').strip()}/browse/{issue_key}",
                    dataItem=alert
                )
                if jira_comment:
                    self.update_task(task, alert, jira_comment, queue)
                if jira_status:
                    self._set_jira_status(task.id, jira_status)
                # Fetch the recently created issue
                issue = self._get_issue(issue_key)
                issue_status = str(
                    issue.get("fields", {}).get("status", {}).get("name", "")
                ).lower()
                assignee = issue.get("fields", {}).get("assignee", {})
                if isinstance(assignee, dict):
                    issue_assignee = assignee.get("emailAddress", "")
                else:
                    issue_assignee = None
                task = self._update_task_details(task, {
                    "status": issue_status,
                    "assignee": issue_assignee
                })
                self.logger.info(
                    f"{self.log_prefix}: Successfully created a Jira ticket with ID "
                    f"'{issue_key}' for {event_type} ID '{alert.id}' on {PLATFORM_NAME}."
                )
                return task
            elif response.status_code == 400:
                resp_json = self.jira_helper.parse_response(response, f"creating {logger_message}")
                errors = list(resp_json.get("errors", {}).values())
                errorMessages = list(resp_json.get("errorMessages", []))
                errors.extend(errorMessages)

                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while creating {logger_message}. "
                        f"Error: {'; '.join(errors)}"
                    ),
                    details=f"Received response: {response.text}",
                )
                raise JiraITSMPluginException(f"Error occurred while creating {logger_message}.")
            else:
                _ = self.jira_helper.handle_error(resp=response, logger_msg=f"creating {logger_message}")
        except JiraITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {logger_message}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise JiraITSMPluginException(err_msg)

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync States.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(tasks)} "
            f"ticket(s) with {PLATFORM_NAME}."
        )
        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/search/jql"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )

        task_ids = [task.id for task in tasks]
        task_statuses = {}
        skip, size = 0, 100
        batch_count = 1
        total_count = 0
        next_page_token = None
        while True:
            log_msg = (
                f"getting ticket(s) for batch {batch_count} from {PLATFORM_NAME}"
            )
            try:
                if not task_ids:
                    break

                body = {
                    "jql": f"key IN ({','.join(task_ids)})",
                    "maxResults": size,
                    "fields": ["status", "assignee"],
                    "nextPageToken": next_page_token,
                }

                response = self.jira_helper.api_helper(
                    url=endpoint,
                    method="POST",
                    json=body,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=log_msg,
                )
                issues = response.get("issues", [])
                next_page_token = response.get("nextPageToken")

                for issue in issues:
                    assignee = issue.get("fields", {}).get("assignee", {})
                    if isinstance(assignee, dict):
                        issue_assignee = assignee.get("emailAddress", "")
                    else:
                        issue_assignee = None
                    task_statuses[issue.get("key", "")] = {
                        "status": (
                            issue.get("fields", {}).get("status", {}).get("name", "").lower()
                        ),
                        "assignee": issue_assignee
                    }

                issue_count = len(issues)
                total_count += issue_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully synced {issue_count} ticket(s) "
                    f"from {PLATFORM_NAME} in batch {batch_count}. "
                    f"Total ticket(s) synced: {total_count}."
                )

                skip += size
                batch_count += 1

                if not next_page_token:
                    break
               
            except JiraITSMPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Error occurred while syncing status for ticket(s) "
                    f"from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                raise JiraITSMPluginException(err_msg)

        for task in tasks:
            if task_statuses.get(task.id, ""):
                task = self._update_task_details(task, task_statuses.get(task.id))
            else:
                if task.updatedValues.status and task.updatedValues.status != TaskStatus.DELETED:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        task.updatedValues.status, TaskStatus.DELETED
                    )
                else:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        TaskStatus.DELETED, TaskStatus.DELETED
                    )
                task.status = TaskStatus.DELETED
        self.logger.info(
            f"{self.log_prefix}: Successfully synced "
            f"{len(tasks)} ticket(s) with the {PLATFORM_NAME}."
        )
        return tasks

    def update_task(
        self,
        task: Task,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
        upsert_task=False
    ) -> Task:
        """Add a comment in existing Jira incident/issue.

        Args:
            task (Task): Existing task/ticket created in Tickets page.
            alert (Union[Alert, Event]): Alert or Event received from tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        body = {"fields": {}}
        jira_status = ""
        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"

        if mappings.get("comment_while_create", None):
            comment_data = mappings.pop("comment_while_create")
        elif mappings.get("comment", None):
            comment_data = mappings.pop("comment")
        else:
            comment_data = (
                f"New {event_type.lower()} with ID '{alert.id}' received "
                f"at {str(alert.timestamp)}."
            )

        if upsert_task:
            if "issuekey" in mappings:
                mappings.pop("issuekey")  # special field; do not allow overriding
            for key, value in list(mappings.items()):
                if type(value) is not str:
                    mappings[key] = str(value)
            if "status" in mappings:
                jira_status = mappings.pop("status")

            edit_issue_fields = self._get_edit_issue_fields(issue_id=task.id)
            mappings = self._filter_mappings(edit_issue_fields, mappings)
            body = self._make_body(mappings, is_update=True)

        try:
            comment_data = json.loads(comment_data)
        except json.decoder.JSONDecodeError:
            pass
        if not isinstance(comment_data, dict):
            body.update(
                {
                    "update": {
                        "comment": [
                            {
                                "add": {"body": self._get_atlassian_document(str(comment_data))}
                            }
                        ]
                    }
                }
            )
        else:
            body.update(
                {
                    "update": {
                        "comment": [
                            {
                                "add": {"body": comment_data}
                            }
                        ]
                    }
                }
            )

        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/issue/{task.id}"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )
        log_msg = f"updating ticket with ID '{task.id}' on {PLATFORM_NAME} platform"

        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="PUT",
                json=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                logger_msg=log_msg,
            )

            if response.status_code in [200, 201, 204]:
                if jira_status:
                    self._set_jira_status(task.id, jira_status)
                # Fetch the recently created issue
                issue = self._get_issue(task.id)
                issue_status = str(
                    issue.get("fields", {}).get("status", {}).get("name", "")
                ).lower()
                assignee = issue.get("fields", {}).get("assignee", {})
                if isinstance(assignee, dict):
                    issue_assignee = assignee.get("emailAddress", "")
                else:
                    issue_assignee = None
                task.dataItem = alert
                task = self._update_task_details(task, {
                    "status": issue_status,
                    "assignee": issue_assignee
                })
                self.logger.info(
                    f"{self.log_prefix}: Successfully updated ticket with "
                    f"ID {task.id} on {PLATFORM_NAME} platform."
                )
                return task
            elif response.status_code == 404:
                if task.updatedValues.status and task.updatedValues.status != TaskStatus.DELETED:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        task.updatedValues.status, TaskStatus.DELETED
                    )
                else:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        TaskStatus.DELETED, TaskStatus.DELETED
                    )
                task.status = TaskStatus.DELETED
                self.logger.info(
                    f"{self.log_prefix}: Ticket with ID '{task.id}' "
                    f"no longer exists on {PLATFORM_NAME} platform."
                )
                return task
            else:
                self.jira_helper.handle_error(
                    response,
                    log_msg,
                    False
                )
        except JiraITSMPluginException:
            raise
        except Exception as exp:
            err_msg = f"Error occurred while {log_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise JiraITSMPluginException(err_msg)

    def _validate_connectivity(
        self,
        url: str,
        email_address: str,
        api_token: str,
    ) -> ValidationResult:
        """Validate connectivity with Jira server.

        Args:
            url (str): Jira Cloud Instance URL.
            email_address (str): Jira Cloud Instance Email.
            api_token (str): Jira Cloud Instance API Token.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            logger_msg = (
                f"connectivity with {PLATFORM_NAME} server"
            )
            self.logger.debug(
                f"{self.log_prefix}: Validating {logger_msg}."
            )
            headers = self.jira_helper.basic_auth(
                email=email_address, api_token=api_token
            )

            api_endpoint = f"{url}/rest/api/3/myself"
            self.jira_helper.api_helper(
                url=api_endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating {logger_msg}"
                ),
                is_validation=True,
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"{logger_msg}."
            )
            return ValidationResult(
                success=True,
                message=(
                    f"Validation successful for {MODULE_NAME} "
                    f"{self.plugin_name} plugin configuration."
                ),
            )
        except JiraITSMPluginException as exp:
            return ValidationResult(
                success=False,
                message=f"{str(exp)}"
            )
        except Exception as exp:
            err_msg = f"Unexpected validation error occurred while validating {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme and parsed.netloc

    def _validate_auth(self, configuration):
        """Validate plugin authentication parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        auth_params = configuration.get("auth", {})
        validation_error = "Validation error occurred."

        # Validate URL
        url = auth_params.get("url", "").strip().strip("/")
        if not url:
            err_msg = "Jira Cloud Instance URL is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            isinstance(url, str) and self._validate_url(url)
        ):
            err_msg = "Invalid Jira Cloud Instance URL provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Email Address
        email_address = auth_params.get("email", "").strip()
        if not email_address:
            err_msg = "Email Address is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(email_address, str):
            err_msg = "Invalid Email Address provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate API Token
        api_token = auth_params.get("api_token")
        if not api_token:
            err_msg = "API Token is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_token, str):
            err_msg = "Invalid API Token provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity with ServiceNow server.
        return self._validate_connectivity(
            url=url,
            email_address=email_address,
            api_token=api_token,
        )

    def _get_valid_issue_types(self, configuration):
        """Fetch valid issue types for all projects for configured Jira instance.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            List[str]: List of valid issue types.
        """
        log_msg = f"fetching list of valid issue types from {PLATFORM_NAME} platform"
        projects_issues = self._get_project_issues(log_msg=log_msg, configuration=configuration)
        valid_issue_types = [
            issue_type.get("name", "") for project in projects_issues
            for issue_type in project.get("issueTypes", [])
        ]
        return valid_issue_types

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        logger_msg = (
            "Jira Issue Type(s) provided in Configuration parameters"
        )
        self.logger.debug(
            f"{self.log_prefix}: Validating {logger_msg}."
        )
        params = configuration.get("params", {})
        validation_error = "Validation error occurred."

        # Validate Issue Type
        issue_type = params.get("issue_type", "").strip()
        if not issue_type:
            err_msg = "Jira Issue Type is required Configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(issue_type, str):
            err_msg = "Invalid Jira Issue Type provided in Configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # split the CSVs
        configured_issue_types = [x.strip() for x in issue_type.split(",")]
        valid_issue_types = self._get_valid_issue_types(configuration=configuration)
        invalid_issue_types = list(
            set(configured_issue_types) - set(valid_issue_types)
        )

        if invalid_issue_types:
            return ValidationResult(
                success=False,
                message=f"Invalid Jira issue type(s) found: {', '.join(invalid_issue_types)}",
            )
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated {logger_msg}."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step.

        Args:
            name (str): Configuration step name.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the available fields for tickets.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        url, email_address, api_token = self.jira_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/rest/api/3/field"
        headers = self.jira_helper.basic_auth(
            email=email_address, api_token=api_token
        )
        log_msg = f"fetching list of all the available fields for tickets from {PLATFORM_NAME}"
        try:
            response = self.jira_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=log_msg,
                is_validation=True
            )
        except JiraITSMPluginException:
            raise
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while getting mapping "
                f"fields from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}"
            )
            raise JiraITSMPluginException(err_msg)

        if response:
            return list(
                map(
                    lambda item: MappingField(
                        label=item.get("name", ""), value=item.get("id", ""),
                    )
                    if item.get("id") not in ["comment"]
                    else MappingField(
                        label=item.get("name", ""),
                        value=item.get("id", ""),
                        updateAble=True,
                    ),
                    response,
                )
            )
        else:
            err_msg = (
                "Error occurred while getting "
                f"fields from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
            )
            raise JiraITSMPluginException(err_msg)

    def get_default_mappings(self, configuration: dict) -> Dict[str, List[FieldMapping]]:
        """Get default mappings.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            dict: Default mappings.
        """
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="summary",
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName, Event Name: $alert_name"
                    )
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\nAlert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\n"
                        "Alert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                ),
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="comment",
                    custom_message=(
                        "Received new alert/event with Alert/Event ID: $id and "
                        "Alert Name: $alertName, Event Name: $alert_name in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues.

        Returns:
            List[Queue]: List of queues.
        """
        log_msg = f"fetching list of {PLATFORM_NAME} projects as queues"
        queues = []

        projects_list = self._get_project_issues(log_msg=log_msg, configuration=self.configuration)

        issue_types = self.configuration.get("params", {}).get("issue_type", "")
        issue_types = [x.strip() for x in issue_types.split(",")]

        for project in projects_list:
            if not project:
                continue
            for issue_type in project.get("issueTypes", []):
                # Value of queue is defined as "project_id:issue_type_id" string
                if issue_type.get("name", "") not in issue_types:
                    continue
                queues.append(
                    Queue(
                        label=f"{project.get('name', '')} - {issue_type.get('name', '')}",
                        value=f"{project.get('id', '')}:{issue_type.get('id', '')}",
                    )
                )

        return queues
