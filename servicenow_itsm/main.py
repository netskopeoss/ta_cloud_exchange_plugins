"""
BSD 3-Clause License.

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

ServiceNow ITSM plugin.
"""

import re
import traceback
from typing import List, Tuple, Union
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
    Severity,
    Alert,
    Event,
    UpdatedTaskValues,
)

from .utils.servicenow_itsm_constants import (
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    LIMIT,
    MAIN_ATTRS
)
from .utils.servicenow_itsm_helper import (
    ServiceNowITSMPluginHelper,
    ServiceNowITSMPluginException,
)


class ServiceNowITSMPlugin(PluginBase):
    """ServiceNow CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Service Now plugin initializer.

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
        self.servicenow_helper = ServiceNowITSMPluginHelper(
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
            manifest_json = ServiceNowITSMPlugin.metadata
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

    def substitute_vars(self, message, alert):
        """Replace variables in a string with values from alert.

        Args:
            message (str): String containing variables.
            alert (Alert): Alert object.

        Returns:
            str: String with resolved variables.
        """
        raw_key = "rawData"

        def get_value(match):
            """Resolve variable name."""
            if match.group(1) in MAIN_ATTRS:
                return getattr(alert, match.group(1), "value_unavailable")
            else:
                return getattr(alert, raw_key).get(match.group(1), "value_unavailable")

        var_regex = r"(?<!\\)\$([a-zA-Z0-9_]+)"
        return re.sub(
            var_regex,
            lambda match: str(get_value(match)),
            message,
        )

    def map_values(self, alert, mappings):
        """Generate a mapped dictionary based on the given alert and field mappings.

        Args:
            alert (Alert): Alert object.
            mappings (List): List of field mappings.

        Returns:
            dict: Mapped dictionary.
        """
        result = {}
        raw_key = "rawData"
        for mapping in mappings:
            if mapping.extracted_field not in [None, "custom_message"]:
                if mapping.extracted_field in MAIN_ATTRS:
                    result[mapping.destination_field] = getattr(
                        alert, mapping.extracted_field, None
                    )
                else:
                    result[mapping.destination_field] = getattr(alert, raw_key).get(
                        mapping.extracted_field, None
                    )
            else:
                result[mapping.destination_field] = self.substitute_vars(
                    mapping.custom_message, alert
                )
            if result[mapping.destination_field] is None:
                result.pop(mapping.destination_field)
        return result

    def get_severity_status_mapping(self):
        """Get severity status mapping.

        Returns:
            dict: Severity status mapping.
        """
        mapping_config = self.configuration.get("mapping_config", {})
        ns_to_ce_severity = {
            value: key for key, value in mapping_config.get("severity_mapping", {}).items()
        }
        ns_to_ce_status = {
            value: key for key, value in mapping_config.get("status_mapping", {}).items()
        }
        return {
            "severity": ns_to_ce_severity,
            "status": ns_to_ce_status
        }

    def ce_to_snow_state_severity_mappings(
        self,
        mapping_config: dict,
        mappings: dict
    ):
        """Get state severity mappings.

        Args:
            mapping_config (Dict): Mapping config.
            mappings (Dict): Mappings.

        Returns:
            dict: mappings with updated state severity mappings.
        """
        ce_to_snow_severity = mapping_config.get("severity_mapping", {})
        ce_to_snow_state = mapping_config.get("status_mapping", {})
        severity_field = "severity"
        if self.configuration.get("params", {}).get("table", "") == "sn_grc_issue":
            severity_field = "impact"
        for k, v in {severity_field: ce_to_snow_severity, "state": ce_to_snow_state}.items():
            if k == "severity" and k in mappings.keys():
                mappings.update(
                    {
                        k: v.get(mappings.get(k), "3")
                    }
                )
            elif k == "state" and k in mappings.keys():
                mappings.update(
                    {
                        k: v.get(mappings.get(k), "1")
                    }
                )
            elif k == "impact" and k in mappings.keys():
                mappings.update(
                    {
                        k: v.get(mappings.get(k), "3")
                    }
                )
        return mappings

    def create_task(self, alert, mappings, queue) -> Task:
        """Create an incident/issue on ServiceNow platform.

        Args:
            alert (Alert): Alert object.
            mappings (Dict): Field mappings.
            queue (Queue): Queue object.

        Returns:
            Task: Task object.
        """
        config_params = self.configuration.get("params", {})
        mapping_config = self.configuration.get("mapping_config", {})
        table = config_params.get("table", "")
        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"
        ticket_type = "incident"
        if table == "sn_grc_issue":
            ticket_type = "issue"
        if config_params.get("default_mappings", "no") == "yes":
            mappings_default = self.get_default_mappings(self.configuration)
            mappings_list = mappings_default.get("mappings", [])
            mappings = self.map_values(alert, mappings_list)

        if not mappings:
            err_msg = (
                "No mappings found in Queue Configuration."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Queue mapping "
                f"is required to create an {ticket_type} if 'Use Default Mappings' "
                "is set to 'No' in Configuration Parameters."
            )
            raise ServiceNowITSMPluginException(err_msg)

        mappings = self.ce_to_snow_state_severity_mappings(mapping_config, mappings)
        for key, value in list(mappings.items()):
            if type(value) is not str:
                mappings[key] = str(value)
        values = (
            mappings
            if queue.value == "no_queue"
            else {**mappings, "assignment_group": queue.value}
        )
        if "sys_id" in values:
            values.pop("sys_id")  # special field; do not allow overriding

        url, username, password = self.servicenow_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/api/now/table/{table}"

        self.logger.info(
            f"{self.log_prefix}: Creating an {ticket_type} for {event_type} ID {alert.id}"
            f" on {PLATFORM_NAME}."
        )
        headers = self.servicenow_helper.basic_auth(username, password)
        headers.update({
            "Content-Type": "application/json",
        })

        try:
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="POST",
                json=values,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"creating an {ticket_type} for {event_type} ID '{alert.id}' "
                    f"on {PLATFORM_NAME} platform"
                ),
            )

            result = response.get("result", {})
            sys_id = result.get("sys_id", "")
            severity = getattr(alert, "rawData").get("severity", Severity.OTHER)
            state = getattr(alert, "rawData").get("status", TaskStatus.OTHER)
            task = Task(
                id=sys_id,
                status=state if state.upper() in TaskStatus.__members__ else TaskStatus.OTHER,
                severity=severity if severity.upper() in Severity.__members__ else Severity.OTHER,
                link=(
                    f"{url}/{table}.do?sys_id={sys_id}"
                ),
                dataItem=alert
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully created an {ticket_type} "
                f"with ID '{sys_id}' "
                f"for {event_type} ID '{alert.id}' on {PLATFORM_NAME}."
            )
            results = self.fetch_assignee_usernames([result])
            result = results[0] if len(results) > 0 else {}
            task = self.update_task_details(task, {
                "state": result.get("state", ""),
                "severity": (
                    result.get("severity", "") if table != "sn_grc_issue"
                    else result.get("impact", "")
                ),
                "assignee": result.get("user_name", "")
            })
            return task
        except ServiceNowITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating an {ticket_type} "
                f"for {event_type} ID {alert.id}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def fetch_assignee_usernames(self, results: list):
        """Fetch assignee usernames from ServiceNow.

        Args:
            results (list): List of results.
        """
        usernames_ids = {}
        for result in results:
            usernames_ids[result["sys_id"]] = ""
            assignee = result.get("assigned_to", {})
            if assignee:
                usernames_ids[result["sys_id"]] = assignee["value"]
        ids = list(usernames_ids.values())

        self.logger.info(
            f"{self.log_prefix}: Fetching assignee usernames "
            f" from {PLATFORM_NAME}."
        )
        url, username, password = self.servicenow_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/api/now/table/sys_user"
        headers = self.servicenow_helper.basic_auth(username, password)

        params = {
            "sysparm_fields": "sys_id,user_name",
            "sysparm_query": (f"sys_idIN{','.join(ids)}"),
        }

        try:
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                params=params,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching usernames from {PLATFORM_NAME} platform"
                ),
            )

            user_results = response.get("result", [])
            user_results = {
                result["sys_id"]: result["user_name"]
                for result in user_results
            }
        except ServiceNowITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while fetching usernames from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ServiceNowITSMPluginException(err_msg)

        for result in results:
            if not usernames_ids[result["sys_id"]]:
                result["user_name"] = ""
                continue
            result["user_name"] = user_results.get(
                usernames_ids[result["sys_id"]], ""
            )
        return results

    def update_task_details(self, task: dict, servicenow_data: dict):
        """Update task fields with ServiceNow data.

        Args:
            task (Task): CE task.
            servicenow_data (dict): Updated data from servicenow.
        """
        if task.dataItem and task.dataItem.rawData:
            old_status = task.dataItem.rawData.get("status", TaskStatus.OTHER)
            old_severity = task.dataItem.rawData.get("severity", Severity.OTHER)
            if task.updatedValues:
                task.updatedValues.oldSeverity = (
                    old_severity if old_severity.upper() in Severity.__members__ else Severity.OTHER
                )
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
                        old_status if old_status.upper() in TaskStatus.__members__ else TaskStatus.OTHER
                    ),
                    assignee=None,
                    oldAssignee=task.dataItem.rawData.get("assignee", None),
                    severity=None,
                    oldSeverity=(
                        old_severity if old_severity.upper() in Severity.__members__ else Severity.OTHER
                    ),
                )
        mapping_config = self.get_severity_status_mapping()

        SEVERITY_MAPPING = mapping_config.get("severity", {})
        STATE_MAPPINGS = mapping_config.get("status", {})

        if task.updatedValues:
            task.updatedValues.status = STATE_MAPPINGS.get(
                servicenow_data.get("state"), TaskStatus.OTHER
            )

        if servicenow_data["severity"]:
            task.updatedValues.severity = SEVERITY_MAPPING.get(
                servicenow_data.get("severity"), Severity.OTHER
            )

        if servicenow_data["assignee"]:
            task.updatedValues.assignee = servicenow_data["assignee"]

        task.status = STATE_MAPPINGS.get(
            servicenow_data.get("state"), TaskStatus.OTHER
        )
        task.severity = SEVERITY_MAPPING.get(
            servicenow_data.get("severity"), Severity.OTHER
        )
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync States.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        table = self.configuration.get("params", {}).get("table", "")
        ticket_type = "incident"
        if table == "sn_grc_issue":
            ticket_type = "issue"
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(tasks)} "
            f"tickets with {PLATFORM_NAME} {ticket_type}s."
        )

        url, username, password = self.servicenow_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/api/now/table/{table}"
        headers = self.servicenow_helper.basic_auth(username, password)

        sys_ids = [task.id for task in tasks]
        skip, size = 0, 50
        batch_count = 1
        data = {}

        while True:
            try:
                ids = sys_ids[skip:skip + size]
                if not ids:
                    break

                params = {
                    "sysparm_fields": (
                        "sys_id,state,severity,assigned_to" + ",impact"
                        if table == "sn_grc_issue" else "",
                    ),
                    "sysparm_query": (f"sys_idIN{','.join(ids)}"),
                }
                response = self.servicenow_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"getting {ticket_type}s for batch {batch_count} "
                        f"from {PLATFORM_NAME}"
                    ),
                )
                results = response.get("result", [])
                results = self.fetch_assignee_usernames(results)

                for result in results:
                    data[result.get("sys_id", "")] = {
                        "state": result.get("state", ""),
                        "severity": (
                            result.get("severity", "") if table != "sn_grc_issue"
                            else result.get("impact", "")
                        ),
                        "assignee": result.get("user_name", "")
                    }
                skip += size
                batch_count += 1
            except ServiceNowITSMPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Error occurred while getting {ticket_type}s "
                    f"from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                raise ServiceNowITSMPluginException(err_msg)

        for task in tasks:
            if data.get(task.id, ""):
                task = self.update_task_details(task, data.get(task.id))
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
        self, task: Task, alert: Union[Alert, Event], mappings, queue, upsert_task=False
    ) -> Task:
        """Add a comment in existing ServiceNow incident/issue.

        Args:
            task (Task): Existing task/ticket created in Tickets page.
            alert (Alert): Alert or Event received from tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        updates = {}
        config_params = self.configuration.get("params", {})
        mapping_config = self.configuration.get("mapping_config", {})
        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"
        if upsert_task:
            if config_params.get("default_mappings", "no") == "yes":
                mappings_default = self.get_default_mappings(self.configuration)
                mappings_list = mappings_default.get("mappings", [])
                mappings = self.map_values(alert, mappings_list)
            if "sys_id" in mappings:
                mappings.pop("sys_id")  # special field; do not allow overriding
            for key, value in list(mappings.items()):
                if type(value) is not str:
                    mappings[key] = str(value)
            mappings = self.ce_to_snow_state_severity_mappings(mapping_config, mappings)
            updates = mappings

        if mappings.get("work_notes", None):
            data = mappings.get("work_notes", "")
        else:
            data = f"New {event_type.lower()} with ID '{alert.id}' received at {str(alert.timestamp)}."
        updates["work_notes"] = data

        table = config_params.get("table", "")
        ticket_type = "incident"
        if table == "sn_grc_issue":
            ticket_type = "issue"
        url, username, password = self.servicenow_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/api/now/table/{table}/{task.id}"

        headers = self.servicenow_helper.basic_auth(username, password)
        headers.update({
            "Content-Type": "application/json",
        })
        params = {
            "sysparm_fields": (
                "sys_id,state,severity,assigned_to" + ",impact"
                if table == "sn_grc_issue" else "",
            )
        }

        log_msg = (
            f"updating an {ticket_type} having ID '{task.id}' "
            f"on {PLATFORM_NAME} platform"
        )

        try:
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="PATCH",
                json=updates,
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                logger_msg=log_msg,
            )

            if response.status_code in [200, 201]:
                response = response.json()
                result = response.get("result", {})
                results = self.fetch_assignee_usernames([result])
                result = results[0] if len(results) > 0 else {}
                task.dataItem = alert
                task = self.update_task_details(task, {
                    "state": result.get("state"),
                    "severity": (
                        result.get("severity") if table != "sn_grc_issue"
                        else result.get("impact", "")
                    ),
                    "assignee": result.get("user_name", "")
                })
                self.logger.info(
                    f"{self.log_prefix}: Successfully updated an {ticket_type} having"
                    f" ID {task.id} on {PLATFORM_NAME} platform."
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
                    f"{self.log_prefix}: {ticket_type.title()} with sys_id '{task.id}' "
                    f"no longer exists on {PLATFORM_NAME} platform."
                )
                return task
            else:
                self.servicenow_helper.handle_error(
                    response,
                    log_msg,
                    False
                )
        except ServiceNowITSMPluginException:
            raise
        except Exception as exp:
            err_msg = f"Error occurred while {log_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme and parsed.netloc

    def _validate_connectivity(
        self,
        url: str,
        username: str,
        password: str,
        configuration: dict,
    ) -> ValidationResult:
        """Validate connectivity with ServiceNow server.

        Args:
            url (str): Instance URL.
            username (str): Instance username.
            password (str): Instance password.
            configuration (dict): Configuration dictionary.

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
            headers = self.servicenow_helper.basic_auth(
                username=username, password=password
            )
            table = configuration.get("params", {}).get("table", "")

            api_endpoint = f"{url}/api/now/table/{table}"
            params = {"sysparm_limit": 1}
            self.servicenow_helper.api_helper(
                url=api_endpoint,
                method="GET",
                params=params,
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
        except ServiceNowITSMPluginException as exp:
            return ValidationResult(
                success=False,
                message=f"{str(exp)}"
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_auth(self, configuration) -> ValidationResult:
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
            err_msg = "Instance URL is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            isinstance(url, str) and self._validate_url(url)
        ):
            err_msg = "Invalid Instance URL provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate username
        username = auth_params.get("username", "").strip()
        if not username:
            err_msg = "Username is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(username, str):
            err_msg = "Invalid username provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate password
        password = auth_params.get("password")
        if not password:
            err_msg = "Password is required Authentication parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(password, str):
            err_msg = "Invalid password provided in Authentication parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity with ServiceNow server.
        return self._validate_connectivity(
            url=url,
            username=username,
            password=password,
            configuration=configuration,
        )

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        params = configuration.get("params", {})
        validation_error = "Validation error occurred."

        # Validate table field
        table = params.get("table", "")
        if not table:
            err_msg = "Destination Table is required Configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif table not in ["sn_si_incident", "incident", "sn_grc_issue"]:
            err_msg = (
                "Invalid 'Destination Table' provided in Configuration parameters. "
                "Valid selections are 'Security Incidents' or 'Incidents' or 'GRC Issues'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate use default mappings field
        default_mappings = params.get("default_mappings", "")
        if not default_mappings:
            err_msg = "Use Default Mappings is required Configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif default_mappings not in ["yes", "no"]:
            err_msg = (
                "Invalid 'Use Default Mappings' provided in Configuration parameters. "
                "Valid selections are 'Yes' or 'No'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def _validate_mapping_param(self, configuration):
        """Validate mapping configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        config = configuration.get("mapping_config", {})
        validation_error = "Validation error occurred."

        # Validate status mapping
        status_mapping = config.get("status_mapping", {})
        if not status_mapping:
            err_msg = "Status Mapping is required in Mapping Configurations."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(status_mapping, dict):
            err_msg = "Invalid Status Mapping provided in Mapping Configurations."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate severity mapping
        severity_mapping = config.get("severity_mapping", {})
        if not severity_mapping:
            err_msg = "Severity Mapping is required in Mapping Configurations."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(severity_mapping, dict):
            err_msg = "Invalid Severity Mapping provided in Mapping Configurations."
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(self, name, configuration):
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
        elif name == "mapping_config":
            return self._validate_mapping_param(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def get_available_fields(self, configuration):
        """Get list of all the available fields.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        config_params = configuration.get("params", {})
        default_mappings = config_params.get(
            "default_mappings", "no"
        )
        if default_mappings == "yes":
            return []

        if config_params.get("table", "") == "sn_si_incident":
            query = "name=sn_si_incident^ORname=task^internal_type!=collection"
        elif config_params.get("table", "") == "incident":
            query = "name=incident^ORname=task^internal_type!=collection"
        else:
            query = "name=sn_grc_issue^ORname=task^internal_type!=collection"

        fields = []
        url, username, password = self.servicenow_helper.get_auth_params(configuration)
        endpoint = f"{url}/api/now/table/sys_dictionary"
        headers = self.servicenow_helper.basic_auth(username, password)
        log_msg = f"fetching list of all the available fields from {PLATFORM_NAME}"

        params = {
            "sysparm_query": query,
            "sysparm_fields": "column_label,element",
            "sysparm_offset": 0,
            "sysparm_limit": LIMIT,
        }
        while True:
            try:
                response = self.servicenow_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=log_msg,
                )

                fields.extend(response.get("result", []))

                if len(response.get("result", [])) < LIMIT:
                    break
                params["sysparm_offset"] += LIMIT

            except ServiceNowITSMPluginException:
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
                raise ServiceNowITSMPluginException(err_msg)

        if fields:
            return list(
                map(
                    lambda item: MappingField(
                        label=item.get("column_label", ""),
                        value=item.get("element", ""),
                    )
                    if item.get("element", "") not in ["work_notes"]
                    else MappingField(
                        label=item.get("column_label", ""),
                        value=item.get("element", ""),
                        updateAble=True,
                    ),
                    fields,
                )
            )
        else:
            err_msg = (
                "Error occurred while getting "
                f"fields from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            raise ServiceNowITSMPluginException(err_msg)

    def get_default_mappings(self, configuration):
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
                    destination_field="short_description",
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName, Event Name: $alert_name"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\nAlert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\nAlert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                ),
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="work_notes",
                    custom_message=(
                        "Received new alert/event with Alert/Event ID: $id and "
                        "Alert Name: $alertName, Event Name: $alert_name in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of ServiceNow groups as queues.

        Returns:
            List[Queue]: List of queues.
        """
        no_queue_list = [Queue(label="No Queue", value="no_queue")]
        queue = []
        url, username, password = self.servicenow_helper.get_auth_params(self.configuration)
        endpoint = f"{url}/api/now/table/sys_user_group"
        headers = self.servicenow_helper.basic_auth(username, password)
        log_msg = f"fetching list of {PLATFORM_NAME} groups as queues"
        params = {
            "sysparm_fields": "name,sys_id",
            "sysparm_limit": LIMIT,
            "sysparm_offset": 0,
        }
        while True:
            try:
                response = self.servicenow_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=log_msg,
                )

                queue.extend(response.get("result", []))

                if len(response.get("result", [])) < LIMIT:
                    break
                params["sysparm_offset"] += LIMIT
            except ServiceNowITSMPluginException:
                raise
            except Exception as error:
                error_message = "Unexpected error occurred"
                err_msg = (
                    f"{error_message} while getting groups "
                    f"as queues from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}"
                )
                raise ServiceNowITSMPluginException(err_msg)
        if queue:
            queue_list = list(
                map(
                    lambda item: Queue(
                        label=item.get("name", ""),
                        value=item.get("sys_id", ""),
                    ),
                    queue,
                )
            )
            queue_list = no_queue_list + queue_list
            return queue_list
        else:
            err_msg = (
                "Error occurred while getting "
                f"queues from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            raise ServiceNowITSMPluginException(err_msg)
