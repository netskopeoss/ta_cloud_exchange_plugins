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
from typing import Dict, List, Tuple, Union

from netskope.integrations.itsm.models import (
    Alert,
    CustomFieldMapping,
    CustomFieldsSectionWithMappings,
    Event,
    FieldMapping,
    Queue,
    Severity,
    Task,
    TaskStatus,
    UpdatedTaskValues,
)
from netskope.integrations.itsm.plugin_base import (
    MappingField,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    BATCH_SIZE,
    CUSTOM_TABLE,
    CUSTOM_TABLE_CONFIG_FIELDS,
    GRC_ISSUE_TABLE,
    IMPACT_FIELD,
    INCIDENT_TABLE,
    LIMIT,
    MAIN_ATTRS,
    MANAGER_ASSIGNEE_FIELD,
    MANAGER_ASSIGNEE_LABEL,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    SECURITY_INCIDENT_TABLE,
    SYS_DICTIONARY_ENDPOINT,
    SYS_USER_GROUP_ENDPOINT,
    TABLE_ENDPOINT,
    USER_EMAIL_CACHE_KEY,
    VALID_TABLES,
)
from .utils.exceptions import ServiceNowITSMPluginException
from .utils.helper import ServiceNowITSMPluginHelper


class ServiceNowITSMPlugin(PluginBase):
    """ServiceNow CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """ServiceNow plugin initializer.

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

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _get_storage(self) -> dict:
        """Return the persistent storage dictionary.

        Returns:
            dict: CE persistent storage; an empty dict when storage is
                unavailable (caching then degrades to a no-op for that
                call without affecting correctness).
        """
        return self.storage if self.storage is not None else {}

    def _get_event_type(self, alert: Union[Alert, Event]) -> str:
        """Return 'Event' for Event objects and 'Alert' otherwise.

        Args:
            alert (Union[Alert, Event]): The triggering alert or event.

        Returns:
            str: "Event" or "Alert".
        """
        return "Event" if "eventType" in alert.model_dump() else "Alert"

    def _get_ticket_type(self, table: str) -> str:
        """Return the human-readable ticket type for the given table.

        Args:
            table (str): Destination table name.

        Returns:
            str: "issue" for the GRC Issue table, else "incident".
        """
        return "issue" if table == GRC_ISSUE_TABLE else "incident"

    def _build_sysparm_fields(self, table_config) -> str:
        """Build the sysparm_fields query value for a ticket lookup.

        Args:
            table_config (TableConfig): Resolved table configuration.

        Returns:
            str: Comma-separated field list, including the impact field for
                the GRC Issue table.
        """
        fields = (
            f"sys_id,{table_config.status_field},"
            f"{table_config.severity_field},{table_config.assignee_field}"
        )
        if table_config.table == GRC_ISSUE_TABLE:
            fields += f",{IMPACT_FIELD}"
        return fields

    def _severity_from_result(self, result: dict, table_config) -> str:
        """Extract the severity value from a ServiceNow ticket record.

        The GRC Issue table stores severity in the 'impact' field; all
        other tables use the configured severity field.

        Args:
            result (dict): Ticket record returned by ServiceNow.
            table_config (TableConfig): Resolved table configuration.

        Returns:
            str: Severity value from the record.
        """
        if table_config.table == GRC_ISSUE_TABLE:
            return result.get(IMPACT_FIELD, "")
        return result.get(table_config.severity_field, "")

    def _build_task_data(self, result: dict, table_config) -> dict:
        """Build the status/severity/assignee dict from a ticket record.

        Args:
            result (dict): Ticket record returned by ServiceNow, with the
                'user_name' key already populated by
                fetch_assignee_usernames.
            table_config (TableConfig): Resolved table configuration.

        Returns:
            dict: Mapping of the configured status, severity and assignee
                field names to their values.
        """
        return {
            table_config.status_field: result.get(
                table_config.status_field, ""
            ),
            table_config.severity_field: self._severity_from_result(
                result, table_config
            ),
            table_config.assignee_field: result.get("user_name", ""),
        }

    def substitute_vars(self, message, alert):
        """Replace variables in a string with values from the alert.

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
                return getattr(alert, raw_key).get(
                    match.group(1), "value_unavailable"
                )

        var_regex = r"(?<!\\)\$([a-zA-Z0-9_]+)"
        return re.sub(
            var_regex,
            lambda match: str(get_value(match)),
            message,
        )

    def map_values(self, alert, mappings):
        """Generate a mapped dictionary from the alert and field mappings.

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
                    result[mapping.destination_field] = getattr(
                        alert, raw_key
                    ).get(mapping.extracted_field, None)
            else:
                result[mapping.destination_field] = self.substitute_vars(
                    mapping.custom_message, alert
                )
            if result[mapping.destination_field] is None:
                result.pop(mapping.destination_field)
        return result

    # ------------------------------------------------------------------
    # Task shaping
    # ------------------------------------------------------------------

    def _mark_task_deleted(self, task: Task) -> Task:
        """Mark a CE task as DELETED and update its updatedValues.

        Called whenever a ticket no longer exists on ServiceNow (404) or is
        missing from a sync response.

        Args:
            task (Task): CE task to mark as deleted.

        Returns:
            Task: Task with status set to TaskStatus.DELETED.
        """
        current_status = (
            task.updatedValues.status if task.updatedValues else None
        )
        if current_status and current_status != TaskStatus.DELETED:
            old_status = current_status
        else:
            old_status = TaskStatus.DELETED

        if task.updatedValues:
            task.updatedValues.oldStatus = old_status
            task.updatedValues.status = TaskStatus.DELETED
        else:
            task.updatedValues = UpdatedTaskValues(
                oldStatus=old_status, status=TaskStatus.DELETED
            )
        task.status = TaskStatus.DELETED
        return task

    def update_task_details(
        self,
        task: Task,
        servicenow_data: dict,
        severity_field,
        status_field,
        assignee_field,
    ) -> Task:
        """Update task fields with data fetched from ServiceNow.

        Args:
            task (Task): CE task.
            servicenow_data (dict): Updated data from ServiceNow.
            severity_field (str): Severity field based on the table.
            status_field (str): Status field based on the table.
            assignee_field (str): Assignee field based on the table.

        Returns:
            Task: Task with updated status, severity and assignee.
        """
        if task.updatedValues:
            task.updatedValues.status = servicenow_data.get(
                status_field, TaskStatus.OTHER
            )
            task.updatedValues.oldAssignee = task.dataItem.rawData.get(
                "assignee", None
            )
        else:
            # Status and Severity are managed from core.
            task.updatedValues = UpdatedTaskValues(
                assignee=None,
                oldAssignee=task.dataItem.rawData.get("assignee", None),
            )

        if servicenow_data.get(severity_field):
            task.updatedValues.severity = servicenow_data.get(
                severity_field, Severity.OTHER
            )

        if servicenow_data.get(assignee_field):
            task.updatedValues.assignee = servicenow_data.get(assignee_field)

        task.status = servicenow_data.get(status_field, TaskStatus.OTHER)
        task.severity = servicenow_data.get(severity_field, Severity.OTHER)
        return task

    # ------------------------------------------------------------------
    # Assignee / manager resolution
    # ------------------------------------------------------------------

    def _resolve_manager_assignee(
        self,
        mappings: dict,
        alert: Union[Alert, Event],
        assignee_field: str,
    ) -> None:
        """Resolve the assignee when the 'Assigned to Manager' field is set.

        Runs only when the queue maps the virtual 'Assigned to Manager'
        field, so the normal assignment flow is completely unchanged.
        Resolution order:
          1. Assign to the acting user's manager (preferred).
          2. If the manager cannot be resolved, fall back to the user
             mapped to the assignee field (e.g. the acting user), resolving
             their email to the user's sys_id.
          3. If neither resolves, leave the assignee empty so the ticket is
             created without an assignee.

        The mappings dictionary is mutated in place. No-op when the virtual
        manager field is not mapped.

        Args:
            mappings (dict): Resolved destination-field to value mapping.
                Mutated in place.
            alert (Union[Alert, Event]): The triggering alert or event.
            assignee_field (str): Assignee column name for the configured
                table ('assigned_to' or the custom assignee field).
        """
        if MANAGER_ASSIGNEE_FIELD not in mappings:
            return

        manager_email = str(mappings.pop(MANAGER_ASSIGNEE_FIELD, "")).strip()
        # Keep the user mapped to the assignee field (if any) as a fallback
        # for when the manager cannot be resolved.
        fallback_email = str(mappings.get(assignee_field, "")).strip()
        event_type = self._get_event_type(alert)

        # 1. Prefer the acting user's manager.
        manager_sys_id = (
            self.servicenow_helper.fetch_manager_sys_id(
                self.configuration,
                manager_email,
                self.ssl_validation,
                self.proxy,
            )
            if manager_email
            else None
        )
        if manager_sys_id:
            mappings[assignee_field] = manager_sys_id
            self.logger.info(
                f"{self.log_prefix}: Ticket for {event_type} ID "
                f"'{alert.id}' will be assigned to the manager of "
                f"'{manager_email}' on {PLATFORM_NAME}."
            )
            return

        # 2. Manager not found; fall back to the user mapped to the
        #    assignee field, resolving their email to the user's sys_id.
        user_sys_id = (
            self.servicenow_helper.fetch_user_sys_id(
                self.configuration,
                fallback_email,
                self.ssl_validation,
                self.proxy,
            )
            if fallback_email
            else None
        )
        if user_sys_id:
            mappings[assignee_field] = user_sys_id
            self.logger.info(
                f"{self.log_prefix}: Manager not found for {event_type} "
                f"ID '{alert.id}'. Falling back to the mapped user "
                f"'{fallback_email}' on {PLATFORM_NAME}."
            )
            return

        # 3. Nothing resolved; leave the ticket unassigned.
        mappings.pop(assignee_field, None)
        self.logger.info(
            f"{self.log_prefix}: Could not determine an assignee for "
            f"{event_type} ID '{alert.id}'. The ticket will be created "
            "without an assignee."
        )

    def fetch_assignee_usernames(
        self, results: list, assignee_field: str
    ) -> list:
        """Resolve assignee sys_ids to email addresses for ticket records.

        Each record's 'user_name' key is populated with the assignee's
        email address (or an empty string when there is no assignee or it
        cannot be resolved).

        A persistent sys_id -> email cache (in CE storage) is used so that
        only assignee sys_ids not seen before are looked up on ServiceNow.
        The sys_id -> email identity is stable, so caching it is safe; the
        ticket's current assignee sys_id is always read fresh from the
        ticket response and never from the cache.

        Args:
            results (list): List of ticket records from ServiceNow.
            assignee_field (str): Assignee field based on the table.

        Returns:
            list: The same records with a 'user_name' key added.
        """
        assignee_sys_ids = {}
        for result in results:
            sys_id = result.get("sys_id", "")
            assignee = result.get(assignee_field, {})
            if assignee and isinstance(assignee, dict):
                assignee_sys_ids[sys_id] = assignee.get("value", "")
            else:
                assignee_sys_ids[sys_id] = ""

        # Distinct assignee sys_ids that actually need resolving.
        required_ids = {
            sys_id for sys_id in assignee_sys_ids.values() if sys_id
        }
        if not required_ids:
            for result in results:
                result["user_name"] = ""
            return results

        # Resolve sys_id -> email via the persistent cache, querying
        # ServiceNow only for sys_ids not already cached.
        cache = self._get_storage().setdefault(USER_EMAIL_CACHE_KEY, {})
        unknown_ids = [
            sys_id for sys_id in required_ids if sys_id not in cache
        ]
        if unknown_ids:
            self.logger.debug(
                f"{self.log_prefix}: Fetching {len(unknown_ids)} "
                f"assignee(s) from {PLATFORM_NAME}."
            )
            try:
                fetched = self.servicenow_helper.fetch_user_emails(
                    self.configuration,
                    unknown_ids,
                    self.ssl_validation,
                    self.proxy,
                )
                cache.update(fetched)
                # Cache sys_ids that returned no record as empty so they
                # are not re-queried on every cycle.
                for sys_id in unknown_ids:
                    cache.setdefault(sys_id, "")
            except Exception as exp:
                # Assignee resolution must never block ticket creation,
                # updates, or the sync cycle. Log and continue; the
                # unresolved sys_ids are left uncached so they are retried
                # on the next cycle.
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while resolving "
                        f"assignee email(s) from {PLATFORM_NAME}. The "
                        "assignee will be left empty for this cycle. "
                        f"Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the configured Username has read "
                        f"access to the 'sys_user' table on {PLATFORM_NAME}."
                    ),
                )

        for result in results:
            assignee_sys_id = assignee_sys_ids.get(result.get("sys_id", ""))
            result["user_name"] = (
                cache.get(assignee_sys_id, "") if assignee_sys_id else ""
            )
        return results

    # ------------------------------------------------------------------
    # Ticket operations
    # ------------------------------------------------------------------

    def _apply_default_mappings(
        self, alert: Union[Alert, Event], mappings: Dict
    ) -> Dict:
        """Return default mappings when 'Use Default Mappings' is enabled.

        When the 'Use Default Mappings' configuration parameter is 'yes',
        the queue mappings are replaced by the plugin's default field
        mappings resolved against the alert. Otherwise the provided
        mappings are returned unchanged.

        Args:
            alert (Union[Alert, Event]): The triggering alert or event.
            mappings (Dict): Queue-provided field mappings.

        Returns:
            Dict: The mappings to use for the ticket operation.
        """
        config_params = self.configuration.get("params", {})
        if config_params.get("default_mappings", "no") == "yes":
            mappings_default = self.get_default_mappings(self.configuration)
            return self.map_values(
                alert, mappings_default.get("mappings", [])
            )
        return mappings

    def _resolve_and_stringify_mappings(
        self,
        mappings: Dict,
        alert: Union[Alert, Event],
        assignee_field: str,
    ) -> Dict:
        """Resolve the manager assignee and coerce all values to strings.

        Resolves the virtual 'Assigned to Manager' field (a no-op when it
        is not mapped) and converts every mapped value to a string so the
        payload is JSON-serialisable. Mutates and returns the same dict.

        Args:
            mappings (Dict): Field mappings to prepare (mutated in place).
            alert (Union[Alert, Event]): The triggering alert or event.
            assignee_field (str): Assignee column name for the table.

        Returns:
            Dict: The prepared mappings.
        """
        self._resolve_manager_assignee(mappings, alert, assignee_field)
        for key, value in list(mappings.items()):
            if not isinstance(value, str):
                mappings[key] = str(value)
        return mappings

    def create_task(
        self,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
    ) -> Task:
        """Create an incident/issue on the ServiceNow platform.

        Args:
            alert (Union[Alert, Event]): Alert or Event object.
            mappings (Dict): Field mappings.
            queue (Queue): Queue object.

        Returns:
            Task: Task object.
        """
        table_config = self.servicenow_helper.get_table_config(
            self.configuration
        )
        table = table_config.table
        status_field = table_config.status_field
        severity_field = table_config.severity_field
        assignee_field = table_config.assignee_field
        assignment_group_field = table_config.assignment_group_field

        event_type = self._get_event_type(alert)
        ticket_type = self._get_ticket_type(table)

        mappings = self._apply_default_mappings(alert, mappings)

        if not mappings:
            err_msg = "No mappings found in Queue Configuration."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Queue mapping "
                f"is required to create an {ticket_type} if "
                "'Use Default Mappings' is set to 'No' in "
                "the Configuration Parameters."
            )
            raise ServiceNowITSMPluginException(err_msg)

        # Resolve the manager assignee (no-op unless the virtual field is
        # mapped) and coerce all mapped values to strings.
        self._resolve_and_stringify_mappings(mappings, alert, assignee_field)
        values = (
            mappings
            if queue.value == "no_queue"
            else {**mappings, assignment_group_field: queue.value}
        )
        # 'sys_id' is a special field; do not allow overriding it.
        values.pop("sys_id", None)

        url, username, password = self.servicenow_helper.get_auth_params(
            self.configuration
        )
        endpoint = f"{url}{TABLE_ENDPOINT.format(table=table)}"

        self.logger.info(
            f"{self.log_prefix}: Creating an {ticket_type} for "
            f"{event_type} ID {alert.id} on {PLATFORM_NAME}."
        )
        headers = self.servicenow_helper.get_headers(
            username, password, with_content_type=True
        )

        try:
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="POST",
                json=values,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"creating an {ticket_type} for {event_type} "
                    f"ID '{alert.id}' on {PLATFORM_NAME} platform"
                ),
            )

            result = response.get("result", {})
            sys_id = result.get("sys_id", "")
            if not sys_id:
                err_msg = (
                    "Received an empty ticket ID in the response while "
                    f"creating {ticket_type} for {event_type} ID "
                    f"'{alert.id}' on {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Received response: {response}",
                )
                raise ServiceNowITSMPluginException(err_msg)
            severity = getattr(alert, "rawData").get(
                "severity", Severity.OTHER
            )
            state = getattr(alert, "rawData").get("status", TaskStatus.OTHER)
            task = Task(
                id=sys_id,
                status=state if state else TaskStatus.OTHER,
                severity=severity if severity else Severity.OTHER,
                link=f"{url}/{table}.do?sys_id={sys_id}",
                dataItem=alert,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully created an {ticket_type} "
                f"with ID '{sys_id}' for {event_type} ID '{alert.id}' on "
                f"{PLATFORM_NAME}."
            )
            results = self.fetch_assignee_usernames([result], assignee_field)
            result = results[0] if results else {}
            task = self.update_task_details(
                task,
                self._build_task_data(result, table_config),
                severity_field,
                status_field,
                assignee_field,
            )
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
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the queue mapping is valid and the "
                    "configured Username has sufficient permissions to "
                    f"create {ticket_type}s on {PLATFORM_NAME}."
                ),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def update_task(
        self,
        task: Task,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
        upsert_task: bool = False,
    ) -> Task:
        """Update an existing ServiceNow incident/issue.

        When ``upsert_task`` is True the mapped fields (and the resolved
        manager assignee, if mapped) are written to the ticket in addition
        to the work note; otherwise only a dedup work note is added.

        Args:
            task (Task): Existing task/ticket created in the Tickets page.
            alert (Union[Alert, Event]): Alert or Event received from the
                tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.
            upsert_task (bool): True if this is an incident event.

        Returns:
            Task: Task containing the ticket ID and status.
        """
        updates = {}
        table_config = self.servicenow_helper.get_table_config(
            self.configuration
        )
        table = table_config.table
        status_field = table_config.status_field
        severity_field = table_config.severity_field
        assignee_field = table_config.assignee_field
        update_field = table_config.update_field

        event_type = self._get_event_type(alert)
        ticket_type = self._get_ticket_type(table)

        if upsert_task:
            mappings = self._apply_default_mappings(alert, mappings)
            # 'sys_id' is a special field; do not allow overriding it.
            mappings.pop("sys_id", None)
            # Resolve the manager assignee (no-op unless the virtual field
            # is mapped) and coerce all mapped values to strings.
            self._resolve_and_stringify_mappings(
                mappings, alert, assignee_field
            )
            updates = mappings

        if mappings.get(update_field, None):
            data = mappings.get(update_field, "")
        else:
            data = (
                f"New {event_type.lower()} with ID '{alert.id}' received "
                f"at {str(alert.timestamp)}."
            )
        updates[update_field] = data

        url, username, password = self.servicenow_helper.get_auth_params(
            self.configuration
        )
        endpoint = f"{url}{TABLE_ENDPOINT.format(table=table)}/{task.id}"
        headers = self.servicenow_helper.get_headers(
            username, password, with_content_type=True
        )
        params = {"sysparm_fields": self._build_sysparm_fields(table_config)}

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
                results = self.fetch_assignee_usernames(
                    [result], assignee_field
                )
                result = results[0] if results else {}
                task.dataItem = alert
                task = self.update_task_details(
                    task,
                    self._build_task_data(result, table_config),
                    severity_field,
                    status_field,
                    assignee_field,
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully updated an "
                    f"{ticket_type} having ID {task.id} on "
                    f"{PLATFORM_NAME} platform."
                )
                return task
            elif response.status_code == 404:
                self._mark_task_deleted(task)
                self.logger.info(
                    f"{self.log_prefix}: {ticket_type.title()} "
                    f"with sys_id '{task.id}' no longer exists on "
                    f"{PLATFORM_NAME} platform."
                )
                return task
            else:
                # handle_error raises for genuine errors; for a no-content
                # success (e.g. 204) it returns without raising, in which
                # case the update succeeded, so return the task as-is.
                self.servicenow_helper.handle_error(response, log_msg, False)
                return task
        except ServiceNowITSMPluginException:
            raise
        except Exception as exp:
            err_msg = f"Error occurred while {log_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    f"Ensure that the {ticket_type} exists and the "
                    "configured Username has sufficient permissions to "
                    f"update {ticket_type}s on {PLATFORM_NAME}."
                ),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync ticket status, severity and assignee from ServiceNow.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task list with updated status.
        """
        table_config = self.servicenow_helper.get_table_config(
            self.configuration
        )
        table = table_config.table
        status_field = table_config.status_field
        severity_field = table_config.severity_field
        assignee_field = table_config.assignee_field

        ticket_type = self._get_ticket_type(table)
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(tasks)} "
            f"tickets with {PLATFORM_NAME} {ticket_type}s."
        )

        url, username, password = self.servicenow_helper.get_auth_params(
            self.configuration
        )
        endpoint = f"{url}{TABLE_ENDPOINT.format(table=table)}"
        headers = self.servicenow_helper.get_headers(username, password)
        sysparm_fields = self._build_sysparm_fields(table_config)

        sys_ids = [task.id for task in tasks]
        skip, size = 0, BATCH_SIZE
        batch_count = 1
        data = {}
        # sys_ids that were successfully queried this cycle. Only these are
        # eligible to be marked DELETED when absent from the response; tasks
        # in a failed batch are left untouched so a transient error does not
        # wrongly delete them.
        processed_ids = set()

        while True:
            ids = sys_ids[skip:skip + size]
            if not ids:
                break
            try:
                params = {
                    "sysparm_fields": sysparm_fields,
                    "sysparm_query": f"sys_idIN{','.join(ids)}",
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
                results = self.fetch_assignee_usernames(
                    results, assignee_field
                )

                for result in results:
                    data[result.get("sys_id", "")] = self._build_task_data(
                        result, table_config
                    )
                processed_ids.update(ids)
            except Exception as exp:
                # A single batch failure must not abort the whole sync
                # cycle. Log and continue; the tasks in this batch are left
                # unchanged (not marked DELETED) and retried next cycle.
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while getting "
                        f"{ticket_type}s for batch {batch_count} from "
                        f"{PLATFORM_NAME}. Skipping this batch for the "
                        f"current sync cycle. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the configured Username has "
                        f"sufficient permissions to read {ticket_type}s "
                        f"on {PLATFORM_NAME}."
                    ),
                )
            skip += size
            batch_count += 1

        for task in tasks:
            if data.get(task.id, ""):
                task = self.update_task_details(
                    task,
                    data.get(task.id),
                    severity_field,
                    status_field,
                    assignee_field,
                )
            elif task.id in processed_ids:
                # Successfully queried but not returned by ServiceNow, so
                # the ticket no longer exists on the platform.
                self._mark_task_deleted(task)
            # else: this task's batch failed this cycle; leave it unchanged.
        self.logger.info(
            f"{self.log_prefix}: Successfully synced "
            f"{len(tasks)} ticket(s) with the {PLATFORM_NAME}."
        )
        return tasks

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_step(self, name, configuration):
        """Validate a given configuration step.

        Args:
            name (str): Configuration step name.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: Validation result with success flag and
                message.
        """
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth(self, configuration) -> ValidationResult:
        """Validate plugin authentication parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        auth_params = configuration.get("auth", {})
        validation_err_msg = "Validation error occurred."

        url = auth_params.get("url", "").strip().strip("/")
        if result := self.servicenow_helper.validate_parameters(
            field_name="Instance URL",
            field_value=url,
            field_type=str,
            parameter_type="Authentication",
            custom_validation_func=self.servicenow_helper._validate_url,
            validation_err_msg=validation_err_msg,
        ):
            return result

        username = auth_params.get("username", "").strip()
        if result := self.servicenow_helper.validate_parameters(
            field_name="Username",
            field_value=username,
            field_type=str,
            parameter_type="Authentication",
            validation_err_msg=validation_err_msg,
        ):
            return result

        password = auth_params.get("password")
        if result := self.servicenow_helper.validate_parameters(
            field_name="Password",
            field_value=password,
            field_type=str,
            parameter_type="Authentication",
            validation_err_msg=validation_err_msg,
        ):
            return result

        table = auth_params.get("table", "")
        if result := self.servicenow_helper.validate_parameters(
            field_name="Destination Table",
            field_value=table,
            field_type=str,
            parameter_type="Authentication",
            validation_err_msg=validation_err_msg,
        ):
            return result
        if table not in VALID_TABLES:
            err_msg = (
                "Invalid 'Destination Table' provided in Authentication "
                "parameters. Valid selections are 'Security Incidents', "
                "'Incidents', 'GRC Issues' or 'Custom Table'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity with the ServiceNow server.
        return self._validate_connectivity(
            url=url,
            username=username,
            password=password,
            table_name=table,
            configuration=configuration,
        )

    def _validate_params(self, configuration) -> ValidationResult:
        """Validate plugin configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and
                message.
        """
        params = configuration.get("params", {})
        auth_params = configuration.get("auth", {})
        validation_err_msg = "Validation error occurred."
        table = auth_params.get("table", "")

        if table == CUSTOM_TABLE:
            return self._validate_custom_table(
                params, auth_params, validation_err_msg
            )

        default_mappings = params.get("default_mappings", "")
        if result := self.servicenow_helper.validate_parameters(
            field_name="Use Default Mappings",
            field_value=default_mappings,
            field_type=str,
            parameter_type="Configuration",
            validation_err_msg=validation_err_msg,
        ):
            return result
        if default_mappings not in ["yes", "no"]:
            err_msg = (
                "Invalid 'Use Default Mappings' provided in Configuration "
                "parameters. Valid selections are 'Yes' or 'No'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        validation_msg = "Successfully validated Configuration Parameters."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(success=True, message=validation_msg)

    def _validate_custom_table(
        self,
        config_params: dict,
        auth_params: dict,
        validation_err_msg: str,
    ) -> ValidationResult:
        """Check the custom table and its fields exist on ServiceNow.

        Args:
            config_params (Dict): Configuration parameters dictionary.
            auth_params (Dict): Authentication parameters dictionary.
            validation_err_msg (str): Validation error message prefix.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            custom_table_name = config_params.get(
                "custom_table_name", ""
            ).strip()
            if result := self.servicenow_helper.validate_parameters(
                field_name="Custom Table Name",
                field_value=custom_table_name,
                field_type=str,
                parameter_type="Configuration",
                validation_err_msg=validation_err_msg,
            ):
                return result

            url = auth_params.get("url", "").strip().strip("/")
            username = auth_params.get("username", "").strip()
            password = auth_params.get("password")
            logger_msg = (
                f"custom table '{custom_table_name}' and its fields on "
                f"the {PLATFORM_NAME}"
            )
            self.logger.debug(f"{self.log_prefix}: Validating {logger_msg}.")
            headers = self.servicenow_helper.get_headers(
                username=username, password=password
            )
            endpoint = f"{url}{SYS_DICTIONARY_ENDPOINT}"
            params = {
                "sysparm_query": f"name={custom_table_name}",
                "sysparm_fields": "element",
                "sysparm_offset": 0,
                "sysparm_limit": LIMIT,
            }

            custom_fields = []
            while True:
                response = self.servicenow_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=f"validating {logger_msg}",
                    is_validation=True,
                )
                fields = response.get("result", [])
                custom_fields.extend(fields)
                if len(fields) < LIMIT:
                    break
                params["sysparm_offset"] += LIMIT

            if not custom_fields:
                err_msg = (
                    f"Custom table '{custom_table_name}' is not present on "
                    "the ServiceNow. Verify the custom table provided in "
                    "Configuration Parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            custom_table_fields = [item["element"] for item in custom_fields]
            for key, value in config_params.items():
                if (
                    key == "custom_table_name"
                    or key not in CUSTOM_TABLE_CONFIG_FIELDS
                ):
                    continue
                value = value.strip()
                if value and value not in custom_table_fields:
                    field_name = CUSTOM_TABLE_CONFIG_FIELDS.get(key, "")
                    err_msg = (
                        f"{field_name} '{value}' field is not present in "
                        f"the table '{custom_table_name}' on "
                        f"the {PLATFORM_NAME}. Verify the {field_name} "
                        "provided in Configuration Parameters."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    )
                    return ValidationResult(success=False, message=err_msg)

            validation_msg = f"Successfully validated {logger_msg}."
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(success=True, message=validation_msg)
        except ServiceNowITSMPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Instance URL and Authentication "
                    "parameters provided in the configuration are correct."
                ),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_connectivity(
        self,
        url: str,
        username: str,
        password: str,
        table_name: str,
        configuration: dict,
    ) -> ValidationResult:
        """Validate connectivity with the ServiceNow server.

        Args:
            url (str): Instance URL.
            username (str): Instance username.
            password (str): Instance password.
            table_name (str): Selected destination table.
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            logger_msg = f"connectivity with {PLATFORM_NAME} server"

            if table_name == CUSTOM_TABLE:
                return ValidationResult(
                    success=True,
                    message=(
                        f"Validation successful for {MODULE_NAME} "
                        f"{self.plugin_name} plugin configuration."
                    ),
                )

            self.logger.debug(f"{self.log_prefix}: Validating {logger_msg}.")
            headers = self.servicenow_helper.get_headers(
                username=username, password=password
            )
            api_endpoint = f"{url}{TABLE_ENDPOINT.format(table=table_name)}"
            params = {"sysparm_limit": 1}
            self.servicenow_helper.api_helper(
                url=api_endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"validating {logger_msg}",
                is_validation=True,
            )

            validation_msg = f"Successfully validated {logger_msg}."
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(success=True, message=validation_msg)
        except ServiceNowITSMPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Instance URL and Authentication "
                    "parameters provided in the configuration are correct."
                ),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    # ------------------------------------------------------------------
    # Fields, mappings and queues
    # ------------------------------------------------------------------

    def get_available_fields(self, configuration):
        """Get the list of all the available fields.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        config_params = configuration.get("params", {})
        auth_params = configuration.get("auth", {})
        update_field = "work_notes"
        table = auth_params.get("table", "")
        if table != CUSTOM_TABLE:
            default_mappings = config_params.get("default_mappings", "no")
            if default_mappings == "yes":
                return []

        if table == SECURITY_INCIDENT_TABLE:
            query = "name=sn_si_incident^ORname=task^internal_type!=collection"
        elif table == INCIDENT_TABLE:
            query = "name=incident^ORname=task^internal_type!=collection"
        elif table == CUSTOM_TABLE:
            table_config = self.servicenow_helper.get_table_config(
                configuration
            )
            table = table_config.table
            update_field = table_config.update_field
            query = f"name={table}"
        else:
            query = "name=sn_grc_issue^ORname=task^internal_type!=collection"

        fields = []
        url, username, password = self.servicenow_helper.get_auth_params(
            configuration
        )
        endpoint = f"{url}{SYS_DICTIONARY_ENDPOINT}"
        headers = self.servicenow_helper.get_headers(username, password)
        log_msg = (
            f"fetching list of all the available fields from {PLATFORM_NAME}"
        )

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
                err_msg = (
                    "Unexpected error occurred while getting mapping "
                    f"fields from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the configured Username has read "
                        "access to the 'sys_dictionary' table on "
                        f"{PLATFORM_NAME}."
                    ),
                )
                raise ServiceNowITSMPluginException(err_msg)

        if fields:
            mapping_fields = [
                MappingField(
                    label=item.get("column_label", ""),
                    value=item.get("element", ""),
                    updateAble=item.get("element", "") in [update_field],
                )
                for item in fields
                if (
                    not item.get("element", "").startswith("sys_")
                    and item.get("element", "")
                )
            ]
            # Virtual destination field: assign the ticket to the alert
            # user's manager. Not a real ServiceNow column; the plugin
            # intercepts it at ticket creation/update time and injects the
            # resolved manager sys_id into the assignee field.
            mapping_fields.append(
                MappingField(
                    label=MANAGER_ASSIGNEE_LABEL,
                    value=MANAGER_ASSIGNEE_FIELD,
                    updateAble=False,
                )
            )
            return mapping_fields
        else:
            err_msg = (
                f"Error occurred while getting fields from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured Username has read access "
                    f"to the 'sys_dictionary' table on {PLATFORM_NAME}."
                ),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def get_default_mappings(self, configuration):
        """Get default mappings.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            dict: Default mappings.
        """
        auth_params = configuration.get("auth", {})
        table = auth_params.get("table", "")
        if table == CUSTOM_TABLE:
            table_config = self.servicenow_helper.get_table_config(
                configuration
            )
            update_field = table_config.update_field
            return {
                "mappings": [],
                "dedup": (
                    [
                        FieldMapping(
                            extracted_field="custom_message",
                            destination_field=update_field,
                            custom_message=(
                                "Received new alert/event with Alert/Event "
                                "ID: $id and Alert Name: $alertName, Event "
                                "Name: $alert_name in Cloud Exchange."
                            ),
                        ),
                    ]
                    if update_field
                    else []
                ),
            }
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="short_description",
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName, "
                        "Event Name: $alert_name"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\n"
                        "Alert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\n"
                        "Alert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                ),
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="work_notes",
                    custom_message=(
                        "Received new alert/event with Alert/Event ID: "
                        "$id and Alert Name: $alertName, Event Name: "
                        "$alert_name in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_queues(self) -> List[Queue]:
        """Get the list of ServiceNow groups as queues.

        Returns:
            List[Queue]: List of queues.
        """
        no_queue_list = [Queue(label="No Queue", value="no_queue")]
        queue = []
        url, username, password = self.servicenow_helper.get_auth_params(
            self.configuration
        )
        endpoint = f"{url}{SYS_USER_GROUP_ENDPOINT}"
        headers = self.servicenow_helper.get_headers(username, password)
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
                err_msg = (
                    "Unexpected error occurred while getting groups "
                    f"as queues from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the configured Username has read "
                        "access to the 'sys_user_group' table on "
                        f"{PLATFORM_NAME}."
                    ),
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
            return no_queue_list + queue_list
        else:
            err_msg = (
                f"Error occurred while getting queues from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured Username has read access "
                    f"to the 'sys_user_group' table on {PLATFORM_NAME}."
                ),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def get_fields(self, name: str, configuration: dict):
        """Get dynamic configuration fields.

        Args:
            name (str): Stepper name.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            list: List of fields.
        """
        fields = []
        if name == "params":
            table = configuration.get("auth", {}).get("table", "")
            if table == CUSTOM_TABLE:
                fields.extend(
                    [
                        {
                            "label": "Custom Table Name",
                            "key": "custom_table_name",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Provide name of your custom table. "
                                "Custom table can be generated from "
                                "System Definition > Tables > "
                                "Click on New and provide Name."
                            ),
                        },
                        {
                            "label": "Custom Status",
                            "key": "custom_status",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Status field Column name of your "
                                "custom table. Go to System Definition > "
                                "Tables > Select Custom Table > Columns > "
                                "Status field Column name."
                            ),
                        },
                        {
                            "label": "Custom Severity",
                            "key": "custom_severity",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Severity field Column name of your "
                                "custom table. Go to System Definition > "
                                "Tables > Select Custom Table > Columns > "
                                "Severity field Column name."
                            ),
                        },
                        {
                            "label": "Custom Assignee",
                            "key": "custom_assignee",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Assignee field Column name of your "
                                "custom table if it reference to "
                                "the 'sys_user' table of the ServiceNow. "
                                "Go to System Definition > Tables > "
                                "Select Custom Table > Columns > "
                                "Assignee field Column name."
                            ),
                        },
                        {
                            "label": "Custom Group",
                            "key": "custom_group",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Group field Column name of your "
                                "custom table if it reference to "
                                "the 'sys_user_group' table of "
                                "the ServiceNow. This field will be used "
                                "as the queue in Queue configuration. "
                                "Go to System Definition > "
                                "Tables > Select Custom Table > Columns > "
                                "Group field Column name."
                            ),
                        },
                        {
                            "label": "Custom Update",
                            "key": "custom_update",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Update field Column name of your "
                                "custom table. This field will be "
                                "used to add message when dedup "
                                "rule is executed. Go to System Definition > "
                                "Tables > Select Custom Table > Columns > "
                                "Update field Column name."
                            ),
                        },
                    ]
                )
            else:
                fields.extend(
                    [
                        {
                            "label": "Use Default Mappings",
                            "key": "default_mappings",
                            "type": "choice",
                            "choices": [
                                {"key": "Yes", "value": "yes"},
                                {"key": "No", "value": "no"},
                            ],
                            "default": "no",
                            "mandatory": True,
                            "description": (
                                "Select 'No' if the user wants to configure "
                                "the mapping fields while configuring the "
                                "queue and select 'Yes' if the user wants "
                                "to use the default mapping. Note: To "
                                "configure the mapping fields while "
                                "configuring the queue, the user should "
                                "have read access to the 'sys_dictionary' "
                                "table. Refer plugin guide for "
                                "default mapping."
                            ),
                        }
                    ]
                )
        return fields

    def get_default_custom_mappings(
        self,
    ) -> List[CustomFieldsSectionWithMappings]:
        """Get default custom field mappings for the Netskope ITSM plugin.

        Returns:
            List[CustomFieldsSectionWithMappings]: List of sections with
                field-to-value mappings.
        """
        return [
            CustomFieldsSectionWithMappings(
                section="status",
                event_field="status",
                destination_label="ServiceNow",
                field_mappings=[
                    CustomFieldMapping(
                        name="New", mapped_value="1", is_default=True
                    ),
                    CustomFieldMapping(
                        name="In Progress", mapped_value="2", is_default=True
                    ),
                    CustomFieldMapping(
                        name="On Hold", mapped_value="3", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Closed", mapped_value="7", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Deleted", mapped_value="", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Other", mapped_value="", is_default=True
                    ),
                ],
            ),
            CustomFieldsSectionWithMappings(
                section="severity",
                event_field="severity",
                destination_label="ServiceNow",
                field_mappings=[
                    CustomFieldMapping(
                        name="Critical", mapped_value="", is_default=True
                    ),
                    CustomFieldMapping(
                        name="High", mapped_value="1", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Medium", mapped_value="2", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Low", mapped_value="3", is_default=True
                    ),
                    CustomFieldMapping(
                        name="Informational",
                        mapped_value="",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="Other", mapped_value="", is_default=True
                    ),
                ],
            ),
        ]
