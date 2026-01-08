"""Netskope ITSM plugin."""

import json
import os
import re
import requests
import time
import traceback
from typing import List, Union, Tuple, Generator, Dict
from datetime import datetime
from jsonschema import validate, ValidationError

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
    UpdatedTaskValues,
    Severity,
    TaskStatus,
    CustomFieldsSectionWithMappings,
    CustomFieldMapping,
    Queue,
    Filters,
)
from netskope.integrations.itsm.utils import alert_event_query_schema
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from .utils.netskope_itsm_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLATFORM_NAME,
    MAX_API_CALLS,
    PLUGIN_VERSION,
    IGNORED_RAW_KEYS,
    INCIDENT_BATCH_SIZE,
    INCIDENT_UPDATE_API,
    VALID_SEVERITY_VALUES,
    INCIDENT_DETAILS_LINK,
    REQUEST_RATE_LIMIT_DELAY,
)

helper = AlertsHelper()
plugin_provider_helper = PluginProviderHelper()


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
            # Validate alert_types
            if "alert_types" not in config or not isinstance(config["alert_types"], list):
                self.logger.error(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid alert types found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid alert type provided."
                )
            # Validate event_types
            if "event_types" not in config or not isinstance(config["event_types"], list):
                self.logger.info(
                    "Netskope ITSM Plugin: Validation error occurred. Error: "
                    "Invalid event types found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid event type provided."
                )
            # Validate either alert_types or event_types is provided
            if not config.get("alert_types") and not config.get("event_types"):
                return ValidationResult(
                    success=False,
                    message="Alert types or Event types either should be provided.",
                )
            # Validate hours
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
            # Validate days
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
            # Validate incident_forensics
            incident_forensics = config.get("incident_forensics", "")
            if (
                not isinstance(incident_forensics, str)
                or not incident_forensics
                or incident_forensics not in ["yes", "no"]
            ):
                err_msg = (
                    "Invalid DLP Incident Forensics option "
                    "provided in configuration parameter."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            filters_payload = config.get("filters", {})
            filters_validation_result = self.validate_filters(filters_payload)
            if not filters_validation_result.success:
                return filters_validation_result

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
            if "user_email" not in config or not isinstance(config["user_email"], str):
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
        elif name == "mapping_config":
            config = configuration.get(name, {})
            if (
                "severity" not in config
                or not isinstance(config.get("severity", {}).get("mappings"), list)
                or not len(config.get("severity", {}).get("mappings", [])) > 0
            ):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Severity mapping not found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid severity mapping provided."
                )
            # Validate each severity
            severity_mappings = config.get("severity").get("mappings")
            invalid_mapping = next(
                (
                    mapping for mapping in severity_mappings
                    if (
                        not isinstance(mapping, dict)
                        or
                        any(
                            value not in VALID_SEVERITY_VALUES for _, value in mapping.items()
                        )
                    )
                ),
                None
            )
            if invalid_mapping:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Incorrect Severity mapping found in the configuration parameters.",
                    error_code="CTO_1029",
                )
                return ValidationResult(
                    success=False, message="Invalid severity mapping provided."
                )
            # If all validations are successful, update tenant storage with incident
            # enrichment option
            tenant_name = configuration.get("tenant")
            if not configuration.get("tenant"):
                tenant_name = helper.get_tenant_itsm(self.name).name
            incident_forensics = configuration.get(
                "params", {}
            ).get("incident_forensics", "")

            provider = plugin_provider_helper.get_provider(tenant_name=tenant_name)
            provider.update_incident_enrichment_option_to_storage(
                tenant_name=tenant_name,
                module_name="cto",
                plugin_name=self.name,
                incident_enrichment_option=incident_forensics,
                operation="set",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def validate_filters(self, filters: dict) -> ValidationResult:
        """Validate Alert/Event filters configured for the plugin."""

        # Validate that filters is a dictionary
        if not isinstance(filters, dict):
            err_msg = "Please provide a valid alert/event query."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            mongo_value = filters.get("mongo", "{}")
            if isinstance(mongo_value, dict):
                mongo_value = json.dumps(mongo_value)
            elif not isinstance(mongo_value, str):
                raise ValueError("Alert/Event mongo query must be a dictionary or JSON string.")

            query_value = filters.get("query", "")
            if isinstance(query_value, dict):
                query_value = json.dumps(query_value)

            filters_model = Filters(
                query=query_value or "",
                mongo=mongo_value or "{}",
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            err_msg = "Invalid Alert/Event query provided in filters."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)

        if filters_model.isValid is False:
            err_msg = (
                "Alert/Event filters are invalid. Reconfigure the Alert/Event query "
                "using the Edit button in the CTO Module -> Plugins page."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)

        mongo_query = filters_model.mongo
        try:
            mongo_query = json.loads(mongo_query or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            err_msg = "Invalid Alert/Event query provided in filters."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            [*_, query_schema] = alert_event_query_schema()
            validate(mongo_query, query_schema)
        except ValidationError as error:
            err_msg = (
                "Invalid Alert/Event query provided in filters. "
                f"{error.message}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)
        except Exception:
            err_msg = "Error occurred while validating Alert/Event query."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                error_code="CTO_1022",
            )
            return ValidationResult(success=False, message=err_msg)

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

        data_item = {
            k: (
                str(v)
                if not (
                    v is None or isinstance(v, int) or isinstance(v, float) or isinstance(v, bool)
                )
                else v
            )
            for k, v in data.items()
            if k not in IGNORED_RAW_KEYS
        }
        if "assignee" in data_item.keys() and (
            data_item.get("assignee", "") == "" or data_item.get("assignee", "none").lower() == "none"
        ):
            data_item.update({"assignee": None})
        return data_item

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
        if "severity" in raw_fields.keys() and raw_fields.get("severity"):
            raw_fields["severity"] = raw_fields.get("severity", "").capitalize()
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
        filters = self.configuration.get("params", {}).get("filters", {}) or {}
        query = filters.get("mongo", "{}")
        try:
            [*_, QUERY_SCHEMA] = alert_event_query_schema()
            validate(json.loads(json.dumps(query)), QUERY_SCHEMA)
        except ValidationError:
            self.logger.error(
                f"{self.log_prefix}: Storing of {len(all_data)} alert(s)/event(s)"
                " have failed because one or more field data types"
                f" are incompatible in Alert/Event query for configuration {self.name}."
                " Reconfigure Alert/Event query using the Edit button in the CTO Module -> Plugins page."
            )
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while validating Alert/Event Query for "
                f"configuration {self.name}.",
                details=traceback.format_exc(),
                error_code="CTO_1022",
            )
            raise e
        if query != "":
            from netskope.integrations.itsm.utils.tickets import (
                _filter_data_items,
            )

            results = _filter_data_items(results, json.dumps(query))
            self.logger.info(
                f"{self.log_prefix}: Storing {len(results)} alert(s)/event(s) "
                f"out of {len(all_data)} alert(s)/event(s) "
                f"based on Alert/Event query for configuration {self.name}."
            )
        return results

    def handle_update_incident_api_call(self, url, data, field, batch_no):
        """Call and Handle update incident API call."""
        for attempt in range(MAX_API_CALLS):
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

            is_retryable_error = (
                hasattr(response, "status_code") and response.status_code in [429, 409]
            )

            if not is_retryable_error:
                break

            if attempt < MAX_API_CALLS - 1:
                self.logger.error(
                    f"{self.log_prefix}: Retrying to update {field}"
                    f" of the incidents of batch {batch_no}."
                    f" Performing retry for url {url}. "
                    f"Received exit code {response.status_code}."
                )
                time.sleep(REQUEST_RATE_LIMIT_DELAY)

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
                    if not incident.updatedValues.status:
                        continue
                    new_value = incident.updatedValues.status

                    old_value = incident.updatedValues.oldStatus if incident.updatedValues.oldStatus else TaskStatus.OTHER

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
                    new_value = incident.updatedValues.severity
                    old_value = incident.updatedValues.oldSeverity
                    if not new_value or new_value not in VALID_SEVERITY_VALUES:
                        self.logger.error(
                            f"{self.log_prefix}: The severity update for "
                            "the ticket has been skipped because "
                            "the current severity level does "
                            "not match the expected severity levels "
                            "defined by the Netskope Tenant "
                            "[Critical, High, Medium, Low]."
                        )
                        continue
                    if not old_value or old_value not in VALID_SEVERITY_VALUES:
                        self.logger.error(
                            f"{self.log_prefix}: The severity update for "
                            "the ticket has been skipped because "
                            "the old severity level does "
                            "not match the expected severity levels "
                            "defined by the Netskope Tenant "
                            "[Critical, High, Medium, Low]."
                        )
                        continue
                    payload.append({
                        "field": "severity",
                        "new_value": new_value,
                        "object_id": object_id,
                        "old_value": old_value,
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
                    f"{self.log_prefix}: Error occurred while updating the {field}"
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
    ) -> Generator[List[Task], None, None]:
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

    def cleanup(self, action_type: str):
        """Unsert Incident option"""
        tenant_name = helper.get_tenant_itsm(self.name).name
        provider = plugin_provider_helper.get_provider(
            tenant_name=tenant_name
        )

        provider.update_incident_enrichment_option_to_storage(
            tenant_name=tenant_name,
            module_name="cto",
            plugin_name=self.name,
            incident_enrichment_option="no",
            operation="unset",
        )

    def get_default_custom_mappings(self) -> list[CustomFieldsSectionWithMappings]:
        """
        Get default custom field mappings with values for Netskope ITSM plugin.

        Returns:
            list[CustomFieldsSectionWithMappings]: List of sections with field-to-value mappings
        """
        return [
            CustomFieldsSectionWithMappings(
                section="status",
                event_field="status",
                destination_label="Netskope Tenant",
                field_mappings=[
                    CustomFieldMapping(name="New", mapped_value="new", is_default=True),
                    CustomFieldMapping(name="In Progress", mapped_value="in_progress", is_default=True),
                    CustomFieldMapping(name="On Hold", mapped_value="", is_default=True),
                    CustomFieldMapping(name="Closed", mapped_value="closed", is_default=True),
                    CustomFieldMapping(name="Deleted", mapped_value="closed", is_default=True),
                    CustomFieldMapping(name="Other", mapped_value="", is_default=True),
                ]
            ),
            CustomFieldsSectionWithMappings(
                section="severity",
                event_field="severity",
                destination_label="Netskope Tenant",
                field_mappings=[
                    CustomFieldMapping(name="Critical", mapped_value="Critical", is_default=True),
                    CustomFieldMapping(name="High", mapped_value="High", is_default=True),
                    CustomFieldMapping(name="Medium", mapped_value="Medium", is_default=True),
                    CustomFieldMapping(name="Low", mapped_value="Low", is_default=True),
                    CustomFieldMapping(name="Informational", mapped_value="Low", is_default=True),
                    CustomFieldMapping(name="Other", mapped_value="Low", is_default=True),
                ]
            )
        ]

    def get_queues(self) -> List[Queue]:
        """Get list of ServiceNow groups as queues.

        Returns:
            List[Queue]: List of queues.
        """
        return [Queue(label="Resolve Incident", value="resolve_incident")]
