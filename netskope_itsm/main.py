"""Netskope ITSM plugin."""

import json
import os
import re
import requests
import time
import traceback
from typing import List, Union, Tuple
from datetime import datetime

from netskope.common.utils import (
    AlertsHelper,
    add_user_agent,
    add_installation_id,
    resolve_secret,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)
from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.itsm.models import (
    Alert,
    Event,
    DataType,
    Task,
    Severity,
    TaskStatus
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

helper = AlertsHelper()
plugin_provider_helper = PluginProviderHelper()

IGNORED_RAW_KEYS = [
    "_id",
    "alert_name",
    "alert_type",
    "app",
    "appcategory",
    "type",
    "file_type",
    "user",
    "timestamp",
]
REQUEST_RATE_LIMIT_DELAY = 30
REQUEST_RATE_LIMIT_DELAY_ON_ERROR = 2
MAX_RETRIES_ON_RATE_LIMIT = 3
INCIDENT_UPDATE_API = "{}/api/v2/incidents/update"
MODULE_NAME = "CTO"
PLUGIN_NAME = "Netskope CTO"
PLUGIN_VERSION = "2.1.0"
DEFAULT_STATUS_VALUE_MAP = {
    "New": "new",
    "In Progress": "in_progress",
    "Resolved": "closed"
}
INCIDENT_BATCH_SIZE = 10


class NetskopePlugin(PluginBase):
    """Netskope plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function."""
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple:
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
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _validate_params(self, configuration):
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(self, name, configuration, tenant_name=None):
        """Validate a given step."""
        if name == "params":
            config = configuration.get(name, {})
            if "alert_types" not in config or type(config["alert_types"]) is not list:
                self.logger.error(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid alert types found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid alert type provided."
                )
            if "event_types" not in config or type(config["event_types"]) is not list:
                self.logger.info(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid event types found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid event type provided."
                )
            if not config.get("alert_types") and not config.get("event_types"):
                return ValidationResult(
                    success=False,
                    message="Alert types or Event types either should be provided.",
                )
            hours = config.get("hours")
            if hours is None:
                err_msg = "Initial Range for Events is a required configuration parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(hours, int):
                err_msg = (
                    "Invalid Initial Range for Events provided in configuration parameter."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif hours < 0 or hours > 8760:
                err_msg = (
                    "Invalid Initial Range for Events provided in configuration"
                    " parameters. Valid value should be in range 0 to 8760."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            days = config.get("days")
            if days is None:
                err_msg = "Initial Range for Alerts is a required configuration parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(days, int):
                err_msg = (
                    "Invalid Initial Range for Alerts provided in configuration parameter."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif days < 0 or days > 365:
                err_msg = (
                    "Invalid Initial Range for Alerts provided in configuration"
                    " parameters. Valid value should be in range 0 to 365."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            tenant_name = configuration.get("tenant")
            if not configuration.get("tenant"):
                tenant_name = helper.get_tenant_itsm(self.name).name
            provider = plugin_provider_helper.get_provider(tenant_name=tenant_name)
            type_map = {}
            if config.get("alert_types"):
                type_map["alerts"] = config["alert_types"]
            if config.get("event_types"):
                type_map["events"] = config["event_types"]
            try:
                provider.permission_check(type_map, plugin_name=self.plugin_name, configuration_name=self.name)
            except ValueError as error:
                return ValidationResult(
                    success=False,
                    message=str(error),
                )
        elif name == "incident_update_config":
            config = configuration.get(name, {})
            if "user_email" not in config or type(config["user_email"]) is not str:
                self.logger.error(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid user email found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid user email provided."
                )
            if not config.get("user_email"):
                return ValidationResult(
                    success=False,
                    message="User Email can not be empty.",
                )
            else:
                matched = re.match(
                    r"^[\w\-\.]+@([\w-]+\.)+[\w-]{2,4}$", config["user_email"]
                )
                if not matched:
                    return ValidationResult(
                        success=False,
                        message="User email should be valid email.",
                    )
            if (
                "status_mapping" not in config
                or type(config["status_mapping"]) is not dict
            ):
                self.logger.error(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid status mapping found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid status mapping provided."
                )
            if not config.get("status_mapping"):
                return ValidationResult(
                    success=False,
                    message="Status Mapping can not be empty.",
                )
            if (
                "severity_mapping" not in config
                or type(config["severity_mapping"]) is not dict
            ):
                self.logger.error(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid severity mapping found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid severity mapping provided."
                )
            if not config.get("severity_mapping"):
                return ValidationResult(
                    success=False,
                    message="Severity Mapping can not be empty.",
                )
        return ValidationResult(success=True, message="Validation successful.")

    def get_types_to_pull(self, data_type: str):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        if data_type == "alerts":
            return self.configuration.get("params", {}).get("alert_types", [])
        else:
            return self.configuration.get("params", {}).get("event_types", [])

    def _get_raw_dict(self, data):
        """Get raw dict."""
        data_item = {k: str(v) for k, v in data.items() if k not in IGNORED_RAW_KEYS}
        for k, v in self.get_severity_status_mapping().items():
            if k == "severity" and k in data_item.keys():
                data_item.update(
                    {
                        k: v.get(data_item.get(k), Severity.OTHER)
                        if data_item.get(k) != "informational" else Severity.INFO
                    }
                )
            elif k == "status" and k in data_item.keys():
                data_item.update(
                    {
                        k: v.get(data_item.get(k), TaskStatus.OTHER)
                    }
                )
        if "assignee" in data_item.keys() and (
            data_item.get("assignee", "") == "" or data_item.get("assignee", "none").lower() == "none"
        ):
            data_item.update({"assignee": None})
        return data_item

    def get_severity_status_mapping(self):
        """Get severity status mapping."""
        ns_to_ce_severity = {}
        for key, value in self.configuration[
            "incident_update_config"
        ].get("severity_mapping", {}).items():
            if key == Severity.OTHER or key == Severity.INFO:
                continue
            ns_to_ce_severity[value] = key
        ns_to_ce_status = {}
        for key, value in self.configuration[
            "incident_update_config"
        ].get("status_mapping", {}).items():
            if value in DEFAULT_STATUS_VALUE_MAP.keys():
                value = DEFAULT_STATUS_VALUE_MAP[value]
            ns_to_ce_status[value] = key
        return {
            "severity": ns_to_ce_severity,
            "status": ns_to_ce_status
        }

    def convert_raw_data_in_model(self, raw_data: dict):
        """Convert raw data in model."""
        raw_fields = self._get_raw_dict(raw_data)
        if self.data_type == DataType.EVENT:
            return Event(
                id=raw_data["_id"],
                eventType=self.sub_type,
                user=raw_data.get("user"),
                fileType=raw_data["file_type"],
                timestamp=datetime.fromtimestamp(raw_data["timestamp"]),
                rawData=raw_fields,
            )
        return Alert(
            id=raw_data["_id"],
            alertName=raw_data.get("alert_name"),
            alertType=raw_data.get("alert_type"),
            app=raw_data.get("app"),
            appCategory=raw_data.get("appcategory"),
            type=raw_data.get("type"),
            user=raw_data.get("user"),
            timestamp=datetime.fromtimestamp(raw_data["timestamp"]),
            rawData=raw_fields,
        )

    def pull_alerts(self) -> Union[List[Alert], List[Event]]:
        """Pull alerts from the Netskope platform."""
        results = []
        # all_alerts = helper.alerts
        all_data = self.data

        for raw_data in all_data:
            try:
                results.append(self.convert_raw_data_in_model(raw_data))
            except KeyError:
                self.logger.error(
                    "Error occurred while getting fields from "
                    f"alert with id={raw_data.get('_id')}.",
                    details=traceback.format_exc(),
                    error_code="CTO_1021",
                )
        filters = self.configuration.get("filters", {}) or {}
        query = filters.get("query", "")
        if query != "":
            from netskope.integrations.itsm.tasks.pull_data_items import (
                _filter_data_items,
            )

            results = _filter_data_items(results, query)
        return results

    def handle_update_incident_api_call(self, url, data, field, batch_no):
        """Call and Handle update incident API call."""
        (
            success,
            response,
        ) = handle_exception(
            self.session.patch,
            error_code="CTO_1030",
            custom_message=f"Error occurred while updating the incidents' {field}"
            f" of batch {batch_no} to Netskope Tenant",
            plugin=self.log_prefix,
            url=url,
            json=data,
        )
        if response.status_code in [429, 409]:
            count_of_tries = 1
            while (
                response.status_code in [429, 409]
                and count_of_tries <= MAX_RETRIES_ON_RATE_LIMIT
            ):
                self.logger.error(
                    f"{self.log_prefix}: Retrying to update {field}"
                    f" of the incidents of batch {batch_no}."
                    f"Performing retry for url {url}. "
                    f"Received exit code {response.status_code}."
                )
                time.sleep(REQUEST_RATE_LIMIT_DELAY)
                count_of_tries += 1
                (
                    success,
                    response,
                ) = handle_exception(
                    self.session.patch,
                    error_code="CTO_1030",
                    custom_message=f"Error occurred while updating the "
                    f"incidents' {field} of batch {batch_no} "
                    "to Netskope Tenant",
                    plugin=self.log_prefix,
                    url=url,
                    json=data,
                )
        return success, response

    def create_incident_update_payload(self, incidents_map):
        """Create payloads to update an incident."""
        updates = ["status", "assignee", "severity"]
        for update in updates:
            payload = []
            for object_id, incident in incidents_map.items():
                if (
                    update == "status"
                    and incident.updatedValues
                    and incident.updatedValues.status != incident.updatedValues.oldStatus
                ):
                    status_mapping = self.configuration["incident_update_config"][
                        "status_mapping"
                    ]
                    if not status_mapping.get(
                        incident.updatedValues.status.value
                    ):
                        continue
                    new_value = status_mapping[
                        incident.updatedValues.status.value
                    ]
                    if new_value in DEFAULT_STATUS_VALUE_MAP:
                        new_value = DEFAULT_STATUS_VALUE_MAP[new_value]
                    old_value = (
                            status_mapping.get(
                                incident.updatedValues.oldStatus.value,
                                incident.updatedValues.oldStatus.value
                            )
                            if incident.updatedValues.oldStatus
                            else "Other"
                    )
                    if old_value in DEFAULT_STATUS_VALUE_MAP:
                        old_value = DEFAULT_STATUS_VALUE_MAP[old_value]
                    payload.append({
                        "field": "status",
                        "new_value": new_value,
                        "object_id": object_id,
                        "old_value": old_value,
                        "user": (
                            self.configuration["incident_update_config"]
                            .get("user_email")
                        ),
                    })
                if (
                    update == "assignee"
                    and incident.updatedValues
                    and incident.updatedValues.assignee != incident.updatedValues.oldAssignee
                ):
                    payload.append({
                        "field": "assignee",
                        "new_value": incident.updatedValues.assignee or "None",
                        "object_id": object_id,
                        "old_value": (
                            incident.updatedValues.oldAssignee
                            or "None"
                        ),
                        "user": (
                            self.configuration["incident_update_config"]
                            .get("user_email")
                        ),
                    })
                if (
                    update == "severity"
                    and incident.updatedValues
                    and incident.updatedValues.severity != incident.updatedValues.oldSeverity
                ):
                    severity_mapping = self.configuration["incident_update_config"][
                        "severity_mapping"
                    ]
                    payload.append({
                        "field": "severity",
                        "new_value": severity_mapping.get(
                            incident.updatedValues.severity.value,
                            incident.updatedValues.severity.value
                        ),
                        "object_id": object_id,
                        "old_value": (
                            severity_mapping.get(
                                incident.updatedValues.oldSeverity,
                                incident.updatedValues.oldSeverity
                            )
                            if incident.updatedValues.oldSeverity
                            else "Other"
                        ),
                        "user": (
                            self.configuration["incident_update_config"]
                            .get("user_email")
                        ),
                    })
            if payload:
                yield {"payload": payload}, update

    def sync_incident_batch(self, incidents: List[Task], batch_no) -> dict:
        """Sync a incident."""
        incidents_map = {}
        results = {
            "success": [],
            "failed": []
        }
        for incident in incidents:
            object_id = getattr(
                incident.dataItem, "rawData", None
            ).get("object_id")
            if not object_id:
                error_message = (
                    f"{self.log_prefix}: Could not find object id for the "
                    f"incident with id {incident.id}"
                )
                self.logger.error(
                    error_message,
                    error_code="CTO_1032",
                )
                if incident not in results["failed"]:
                    results["failed"].append(incident)
            else:
                incidents_map[object_id] = incident
        tenant_name = self.tenant.parameters["tenantName"].strip()
        for data, field in self.create_incident_update_payload(
            incidents_map
        ):
            try:
                success, response = self.handle_update_incident_api_call(
                    INCIDENT_UPDATE_API.format(tenant_name),
                    data,
                    field,
                    batch_no
                )
                if not success:
                    error_message = (
                        f"{self.log_prefix}: Error occurred while updating the"
                        f" incidents' {field} to Netskope Tenant for batch no. {batch_no}")
                    self.logger.error(
                        error_message,
                        details=response.text,
                    )
                    for incident in incidents_map.values():
                        if incident not in results["failed"]:
                            results["failed"].append(incident)
                    continue
                response = handle_status_code(
                    response,
                    error_code="CTO_1031",
                    custom_message="Error occurred while updating the"
                    f" incidents' {field} to Netskope Tenant for batch no. {batch_no}",
                    plugin=self.log_prefix,
                )
                if bool(response["ok"]):
                    updated_incidents = int(response["result"])
                    self.logger.info(
                        f"{self.log_prefix}: Successfully updated {field} for"
                        f" {updated_incidents} incident(s) out of "
                        f"{len(incidents)} to the Netskope Tenant for batch no. {batch_no}."
                    )
                    for incident in incidents_map.values():
                        if incident not in results["failed"]:
                            results["success"].append(incident)
                    continue
            except requests.exceptions.HTTPError:
                self.logger.error(
                    f"{self.log_prefix}: Error occured while updating the {field}"
                    f" for the incidents on the Netskope Tenant for batch no. {batch_no}.",
                    details=traceback.format_exc(),
                    error_code="CTO_1044",
                )
                for incident in incidents_map.values():
                    if incident not in results["failed"]:
                        results["failed"].append(incident)
                return results
            for incident in incidents_map.values():
                if incident not in results["failed"]:
                    results["failed"].append(incident)
            self.logger.error(
                f"{self.log_prefix}: Incidents' {field } are not updated"
                f" on the Netskope Tenant for the batch no. {batch_no}.",
                details=(
                    "Same response received from the Netskope Tenant which"
                    " says that the incidents are not updated."
                ),
                error_code="CTO_1045",
            )
        return results

    def get_in_batch(
        self,
        incidents: List[Task],
        batch_size: int
    ) -> List[Task]:
        """Get incidents in batches."""
        n_incidents = len(incidents)
        for ndx in range(0, n_incidents, batch_size):
            yield incidents[
                ndx:min(ndx + batch_size, n_incidents)
            ]

    def sync_incidents(self, incidents: List[Task]) -> PushResult:
        """Sync incidents back to platform."""
        results = {"success": [], "failed": []}
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_itsm(self.name)
        self.session = requests.Session()
        self.session.headers.update(
            add_installation_id(
                add_user_agent(
                    {
                        "Netskope-API-Token": resolve_secret(
                            self.tenant.parameters["v2token"]
                        ),
                    }
                )
            )
        )
        batch_no = 1
        for n_incidents in self.get_in_batch(incidents, INCIDENT_BATCH_SIZE):
            result = self.sync_incident_batch(n_incidents, batch_no)
            results["failed"].extend(result["failed"])
            results["success"].extend(result["success"])
            batch_no += 1

        message = f"Updated {len(results['success'])} incident(s)"
        message += (
            f" and failed to update {len(results['failed'])} incident(s)."
            if len(results["failed"]) > 0
            else "."
        )
        return PushResult(
            message=message,
            success=True,
            results=results
        )
