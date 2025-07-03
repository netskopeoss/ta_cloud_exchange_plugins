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

BMC Helix ITSM Plugin.
"""

import json
import traceback
from typing import List, Dict
from urllib.parse import urlparse

from .utils.bmc_helix_exceptions import (
    BMCHelixPluginException,
)
from .utils.bmc_helix_api_helper import (
    BMCHelixPluginHelper,
)
from .utils.bmc_helix_constants import (
    INCIDENT_FIELDS_URL,
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    TASK_URL,
    UPDATE_FIELDS_LIST,
    GET_TASK_URL,
    INCIDENT_PAGE_SIZE,
    GROUPS_PAGE_SIZE,
    LIST_GROUPS_URL,
    INCIDENT_REQUIRED_FIELDS_VALUES
)

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)

from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Severity,
    Task,
    TaskStatus,
    Alert,
    UpdatedTaskValues
)


class BMCHelixPlugin(PluginBase):
    """BMCHelixPlugin Plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize BMCHelixPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.bmc_helix_helper = BMCHelixPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = BMCHelixPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

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
        elif name == "mapping_config":
            return self._validate_mapping_configs(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth(self, configuration):
        """Validate the plugin authentication parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        auth_params = configuration.get("auth", {})

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        # Validate BMC Helix Base URL
        servername = auth_params.get("servername", "").strip().strip("/")
        if not servername:
            err_msg = (
                "BMC Helix API Base URL is a required "
                "Authentication parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(servername, str) or not self._validate_url(
            servername
        ):
            err_msg = (
                "Invalid BMC Helix API Base URL provided in the "
                "Authentication parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Username
        username = auth_params.get("username", "").strip()
        if not username:
            err_msg = "Username is a required Authentication parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(username, str):
            err_msg = (
                "Invalid Username provided in the Authentication parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Password
        password = auth_params.get("password")
        if not password:
            err_msg = "Password is a required Authentication parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(password, str):
            err_msg = (
                "Invalid Password provided in the Authentication parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration, validation_err_msg)

    def _validate_mapping_configs(self, configuration):
        """Validate the plugin mapping configurations.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        mapping_configs = configuration.get("mapping_config", {})

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        if (
            "status_mapping" not in mapping_configs
            or not isinstance(mapping_configs["status_mapping"], dict)
        ):
            err_msg = (
                "Invalid status mapping found in the Mapping Configurations."
            )
            self.logger.error(
                f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        if (
            "severity_mapping" not in mapping_configs
            or not isinstance(mapping_configs["severity_mapping"], dict)
        ):
            err_msg = (
                "Invalid severity mapping found in the Mapping Configurations."
            )
            self.logger.error(
                f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            "Mapping Configurations."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_auth_params(self, configuration, validation_err_msg):
        """Validate the plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cto.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            base_url, username, password = (
                self.bmc_helix_helper._get_auth_params(configuration)
            )
            self.bmc_helix_helper._generate_auth_token(
                verify=self.ssl_validation,
                proxies=self.proxy,
                base_url=base_url,
                username=username,
                password=password,
                is_validation=True,
                log_msg=(
                    "validating authentication parameters"
                ),
            )
            log_msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{PLATFORM_NAME} plugin configuration parameters."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=True,
                message=log_msg,
            )

        except BMCHelixPluginException as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(exp),
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

    def get_available_fields(self, configuration):
        """Get list of all the available fields for tickets.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        log_msg = (
            f"fetching list of available incident fields from {PLATFORM_NAME}"
        )
        (
            base_url,
            username,
            password
        ) = self.bmc_helix_helper._get_auth_params(self.configuration)
        endpoint = f"{base_url}/{INCIDENT_FIELDS_URL}"
        headers = self.bmc_helix_helper._generate_auth_token(
            verify=self.ssl_validation,
            proxies=self.proxy,
            base_url=base_url,
            username=username,
            password=password,
            log_msg=log_msg
        )
        headers.update(
            {"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            response = self.bmc_helix_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                logger_msg=log_msg,
            )
        except BMCHelixPluginException:
            raise
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while getting available "
                f"incident fields from the {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}"
            )
            raise BMCHelixPluginException(err_msg)

        if response:
            fields = [
                MappingField(
                    label=item.get("name", "").replace("_", " "),
                    value=item.get("name", ""),
                    updateAble=item.get("name", "") in UPDATE_FIELDS_LIST
                )
                for item in response
                if (
                    not item.get("field_option", "") == "SYSTEM" and
                    item.get("name", "")
                )
            ]
            return fields
        else:
            err_msg = (
                "Error occurred while getting available "
                f"incident fields from the {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            raise BMCHelixPluginException(err_msg)

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            Dict[str, List[FieldMapping]]: Default mappings.
        """
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Description",
                    custom_message=(
                        "Incident created by Netskope CE."
                    )
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Short Description",
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName, "
                        "Event Name: $alert_name"
                    )
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Detailed_Decription",
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\n"
                        "Alert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\n"
                        "Alert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="First_Name",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Last_Name",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Status",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Impact",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Urgency",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Reported Source",
                    custom_message=""
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Service_Type",
                    custom_message=""
                )
            ],
            "dedup": [],
        }

    def _ce_to_bmc_state_severity_mappings(
        self,
        mappings: dict,
    ):
        """Get state severity mappings.

        Args:
            mapping_config (Dict): Mapping config.
            mappings (Dict): Mappings.
            status_field (str): Status field based on table.
            severity_field (str): Severity field based on table.

        Returns:
            dict: mappings with updated state severity mappings.
        """
        mapping_config = self.configuration.get("mapping_config", {})
        ce_to_bmc_status = mapping_config.get("status_mapping", {})
        ce_to_bmc_severity = mapping_config.get("severity_mapping", {})
        for k, v in {
            "Status": ce_to_bmc_status,
            "Impact": ce_to_bmc_severity
        }.items():
            if k == "Status" and k in mappings.keys():
                mapped_status = mappings.get(k)
                if (
                    mapped_status in
                    INCIDENT_REQUIRED_FIELDS_VALUES.get("Status", [])
                ):
                    continue
                mappings.update(
                    {
                        k: v.get(mapped_status, "New")
                    }
                )
            elif k == "Impact" and k in mappings.keys():
                mapped_impact = mappings.get(k)
                if (
                    mapped_impact in
                    INCIDENT_REQUIRED_FIELDS_VALUES.get("Impact", [])
                ):
                    continue
                mappings.update(
                    {
                        k: v.get(mapped_impact, "4-Minor/Localized")
                    }
                )
        return mappings

    def _get_severity_status_mapping(self):
        """Get severity status mapping.

        Returns:
            dict: Severity status mapping.
        """
        mapping_config = self.configuration.get("mapping_config", {})
        ns_to_ce_severity = {
            value: key for key, value in mapping_config.get(
                "severity_mapping", {}
            ).items()
        }
        ns_to_ce_status = {
            value: key for key, value in mapping_config.get(
                "status_mapping", {}
            ).items()
        }
        return {
            "severity": ns_to_ce_severity,
            "status": ns_to_ce_status
        }

    def _update_task_details(
        self,
        task: Task,
        bmc_helix_data: dict,
    ):
        """Update task fields with BMC Helix data.

        Args:
            task (Task): CE task.
            bmc_helix_data (dict): Updated data from BMC Helix incident.

        Returns:
            Task: Updated task object.
        """
        if task.dataItem and task.dataItem.rawData:
            old_status = task.dataItem.rawData.get(
                "status", TaskStatus.OTHER
            )
            old_severity = task.dataItem.rawData.get(
                "severity", Severity.OTHER
            )
            if task.updatedValues:
                task.updatedValues.oldSeverity = (
                    old_severity if old_severity.upper() in
                    Severity.__members__ else Severity.OTHER
                )
                task.updatedValues.oldStatus = (
                    old_status if old_status.upper() in
                    TaskStatus.__members__ else TaskStatus.OTHER
                )
                task.updatedValues.oldAssignee = task.dataItem.rawData.get(
                    "assignee", None
                )
            else:
                task.updatedValues = UpdatedTaskValues(
                    status=None,
                    oldStatus=(
                        old_status if old_status.upper() in
                        TaskStatus.__members__ else TaskStatus.OTHER
                    ),
                    assignee=None,
                    oldAssignee=task.dataItem.rawData.get("assignee", None),
                    severity=None,
                    oldSeverity=(
                        old_severity if old_severity.upper() in
                        Severity.__members__ else Severity.OTHER
                    ),
                )
        mapping_config = self._get_severity_status_mapping()

        SEVERITY_MAPPING = mapping_config.get("severity", {})
        STATE_MAPPINGS = mapping_config.get("status", {})

        if task.updatedValues:
            task.updatedValues.status = STATE_MAPPINGS.get(
                bmc_helix_data.get("Status"), TaskStatus.OTHER
            )

        if bmc_helix_data["Impact"]:
            task.updatedValues.severity = SEVERITY_MAPPING.get(
                bmc_helix_data.get("Impact"), Severity.OTHER
            )

        if bmc_helix_data["Assignee"]:
            task.updatedValues.assignee = bmc_helix_data["Assignee"]

        task.status = STATE_MAPPINGS.get(
            bmc_helix_data.get("Status"), TaskStatus.OTHER
        )
        task.severity = SEVERITY_MAPPING.get(
            bmc_helix_data.get("Impact"), Severity.OTHER
        )
        return task

    def _validate_required_fields_and_values(self, mappings):
        """Validate required fields and values.

        Args:
            mappings (Dict): Mappings.

        Returns:
            tuple: Tuple of missing fields and invalid value fields.
        """
        missing_fields, invalid_value_fields = [], []
        for key, available_values in INCIDENT_REQUIRED_FIELDS_VALUES.items():
            if key not in mappings:
                missing_fields.append(key)
            elif available_values and mappings[key] not in available_values:
                invalid_value_fields.append(key)
        return missing_fields, invalid_value_fields

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an incident on BMC Helix platform.

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
                f"{self.log_prefix}: {err_msg} Queue mapping is required "
                f"to create an incident on the {PLATFORM_NAME} platform."
            )
            raise BMCHelixPluginException(err_msg)

        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"

        mappings = self._ce_to_bmc_state_severity_mappings(mappings)
        (
            missing_fields,
            invalid_value_fields
        ) = self._validate_required_fields_and_values(mappings)
        if missing_fields:
            err_msg = (
                f"{', '.join(missing_fields)} field(s) are missing in "
                "the Queue mapping and are required to create "
                f"an incident on the {PLATFORM_NAME} platform"
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}."
            )
            raise BMCHelixPluginException(err_msg)
        if invalid_value_fields:
            err_msg = (
                f"Invalid value(s) found for  "
                f"{', '.join(invalid_value_fields)} field(s) in "
                "the Queue mapping"
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}."
            )
            raise BMCHelixPluginException(err_msg)

        queue_values = json.loads(queue.value)
        data = (
            mappings
            if queue_values == {"no_group": "no_group"}
            else {
                **mappings,
                "Assigned Group": queue_values.get("Support Group Name", ""),
                "Assigned Support Company": (
                    queue_values.get("Company", "")
                ),
                "Assigned Support Organization": (
                    queue_values.get("Support Organization", "")
                )
            }
        )
        if "Incident Number" in data:
            data.pop("Incident Number")
        data.update({"z1D_Action": "CREATE"})

        payload = {
            "values": data
        }

        (
            base_url,
            username,
            password
        ) = self.bmc_helix_helper._get_auth_params(self.configuration)
        endpoint = f"{base_url}/{TASK_URL}"
        logger_message = (
            f"an incident for {event_type} ID '{alert.id}' "
            f"on the {PLATFORM_NAME} platform"
        )
        self.logger.info(
            f"{self.log_prefix}: Creating {logger_message}."
        )
        headers = self.bmc_helix_helper._generate_auth_token(
            verify=self.ssl_validation,
            proxies=self.proxy,
            base_url=base_url,
            username=username,
            password=password,
            log_msg=f"creating {logger_message}"
        )

        params = {
            "fields": (
                "values(Request ID, Incident Number, Status, "
                "Impact, Urgency, Service_Type, "
                "Reported Source, Assigned Group, Assignee)"
            )
        }

        try:
            response = self.bmc_helix_helper.api_helper(
                url=endpoint,
                method="POST",
                json=payload,
                headers=headers,
                params=params,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                logger_msg=(
                    f"creating {logger_message}"
                ),
            )

            result = response.get("values", {})
            incident_number = result.get("Incident Number", "")
            severity = getattr(alert, "rawData").get(
                "severity", Severity.OTHER
            )
            status = getattr(alert, "rawData").get(
                "status", TaskStatus.OTHER
            )
            if "restapi" in base_url:
                incident_link = base_url.replace("restapi", "smartit")
            task = Task(
                id=incident_number,
                status=(
                    status if status.upper() in TaskStatus.__members__ else
                    TaskStatus.OTHER
                ),
                severity=(
                    severity if severity.upper() in Severity.__members__ else
                    Severity.OTHER
                ),
                link=(
                    f"{incident_link}/smartit/app/#/incident"
                    f"/displayid/{incident_number}"
                ),
                dataItem=alert
            )

            task = self._update_task_details(
                task,
                {
                    "Status": result.get("Status", ""),
                    "Impact": result.get("Impact", ""),
                    "Assignee": result.get("Assignee", "")
                }
            )

            self.logger.info(
                f"{self.log_prefix}: Successfully created an incident "
                f"with ID '{incident_number}' for {event_type} ID "
                f"'{alert.id}' on the {PLATFORM_NAME} platform."
            )
            return task

        except BMCHelixPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {logger_message}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise BMCHelixPluginException(err_msg)

    def update_task(self, task: Task, alert: Alert, mappings, queue):
        """Return the task as it is."""
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync States.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        self.logger.info(
            f"{self.log_prefix}: Syncing incident details for "
            f"{len(tasks)} ticket(s) with the {PLATFORM_NAME} platform."
        )
        total_count = 0
        skip_count = 0
        batch_count = 1
        skip = 0
        updated_incidents = {}
        task_ids = [task.id for task in tasks]
        (
            base_url,
            username,
            password
        ) = self.bmc_helix_helper._get_auth_params(self.configuration)
        endpoint = f"{base_url}/{GET_TASK_URL}"

        headers = self.bmc_helix_helper._generate_auth_token(
            verify=self.ssl_validation,
            proxies=self.proxy,
            base_url=base_url,
            username=username,
            password=password,
            log_msg=(
                "syncing incident details from the "
                f"{PLATFORM_NAME} platform"
            )
        )
        headers.update(
            {"Content-Type": "application/x-www-form-urlencoded"}
        )
        while True:
            try:
                ids = task_ids[skip:skip + INCIDENT_PAGE_SIZE]
                if not ids:
                    break

                params = {
                    "fields": (
                        "values(Request ID, Incident Number, Status, "
                        "Impact, Assignee)"
                    ),
                    "q": (
                        "'Incident Number' IN (\"" + "\", \"".join(ids) + "\")"
                    )
                }

                logger_message = (
                    f"getting incident details for batch {batch_count} "
                    f"from the {PLATFORM_NAME} platform"
                )
                response = self.bmc_helix_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    logger_msg=logger_message,
                )
                page_incidents = response.get("entries", [])
                for incident in page_incidents:
                    values = incident.get("values", {})
                    if values:
                        incident_number = values.get("Incident Number", "")
                        updated_incidents[incident_number] = {
                            "Status": values.get("Status", ""),
                            "Impact": values.get("Impact", ""),
                            "Assignee": values.get("Assignee", "")
                        }
                page_count = len(page_incidents)
                total_count += page_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully synced {page_count} "
                    f"ticket(s) from the {PLATFORM_NAME} platform "
                    f"in batch {batch_count}. "
                    f"Total ticket(s) synced: {total_count}."
                )
                skip += INCIDENT_PAGE_SIZE
                batch_count += 1
            except (BMCHelixPluginException, Exception) as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"syncing incident details from the {PLATFORM_NAME} "
                        f"platform. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_count += len(ids)

        for task in tasks:
            if updated_incidents.get(task.id, ""):
                task = self._update_task_details(
                    task=task,
                    bmc_helix_data=updated_incidents.get(task.id),
                )
            else:
                if (
                    task.updatedValues.status and
                    task.updatedValues.status != TaskStatus.DELETED
                ):
                    task.updatedValues.oldStatus,
                    task.updatedValues.status = (
                        task.updatedValues.status, TaskStatus.DELETED
                    )
                else:
                    task.updatedValues.oldStatus,
                    task.updatedValues.status = (
                        TaskStatus.DELETED, TaskStatus.DELETED
                    )
                task.status = TaskStatus.DELETED

        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Failed to sync {skip_count} ticket(s) "
                f"with the {PLATFORM_NAME} platform."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully synced "
            f"{total_count} ticket(s) with the {PLATFORM_NAME} platform."
        )
        return tasks

    def get_queues(self) -> List[Queue]:
        """Get list of BMC Helix groups as queues.

        Returns:
            List[Queue]: List of queues.
        """
        log_msg = (
            f"fetching groups as queues from the {PLATFORM_NAME} platform"
        )
        no_group = [
            Queue(label="No Group", value=json.dumps({"no_group": "no_group"}))
        ]
        groups = []
        (
            base_url,
            username,
            password
        ) = self.bmc_helix_helper._get_auth_params(self.configuration)
        endpoint = f"{base_url}/{LIST_GROUPS_URL}"

        headers = self.bmc_helix_helper._generate_auth_token(
            verify=self.ssl_validation,
            proxies=self.proxy,
            base_url=base_url,
            username=username,
            password=password,
            log_msg=log_msg
        )
        headers.update(
            {"Content-Type": "application/x-www-form-urlencoded"}
        )

        params = {
            "fields": (
                "values(Company,Support Organization,Support Group Name,"
                "Confidential Support Group)"
            ),
            "q": "'Status'=\"Enabled\"",
            "limit": GROUPS_PAGE_SIZE
        }
        while True:
            try:
                response = self.bmc_helix_helper.api_helper(
                    url=endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    logger_msg=log_msg,
                )
                page_groups = response.get("entries", [])
                if page_groups:
                    queue_list = list(
                        map(
                            lambda item: Queue(
                                label=(
                                    f"{item.get('values', {}).get('Support Group Name', '')} "  # noqa
                                    f"({item.get('values', {}).get('Support Organization', '')})"  # noqa
                                ),
                                value=json.dumps(item.get("values", {})),
                            ),
                            page_groups,
                        )
                    )
                groups.extend(queue_list)

                is_next_page = response.get("_links", {}).get("next", [])
                if not is_next_page:
                    break

                endpoint = is_next_page[0].get("href", "")
                params = {}
            except BMCHelixPluginException:
                raise
            except Exception as error:
                error_message = "Unexpected error occurred"
                err_msg = (
                    f"{error_message} while getting groups "
                    f"as queues from the {PLATFORM_NAME} platform."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}"
                )
                raise BMCHelixPluginException(err_msg)
        if groups:
            return no_group + groups
        else:
            err_msg = (
                "Error occurred while getting "
                f"queues from {PLATFORM_NAME}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            raise BMCHelixPluginException(err_msg)
