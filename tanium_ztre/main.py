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

CRE Tanium plugin.
"""

from copy import deepcopy
import traceback
from pydantic import ValidationError
from typing import Tuple, List
from urllib.parse import urlparse

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    MODULE_NAME,
    DEVICE_PAGE_COUNT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    DEVICE_FIELD_MAPPING,
    TANIUM_GRAPHQL_QUERY,
    RISK_INFO_FIELDS,
)

from .utils.helper import TaniumPluginException, TaniumPluginHelper


class TaniumPlugin(PluginBase):
    """Tanium plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Tanium plugin initializer.

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
        self.tanium_helper = TaniumPluginHelper(
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
            manifest_json = TaniumPlugin.metadata
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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [ActionWithoutParams(label="No action", value="generate")]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate"]:
            return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Tanium action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value not in ["generate"]:
            resolution = (
                "Ensure that the action(s) is selected from the "
                "supported action(s). Supported action(s): 'No action'."
            )
            self.logger.error(
                message=(
                    f'{self.log_prefix}: Unsupported action "{action_value}" '
                    "provided in the action configuration."
                ),
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            f"action configuration for '{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        action_label = action.label

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

    def execute_actions(self, actions: List[Action]):
        """Execute actions on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        first_action = actions[0]
        action_label = first_action.label
        if first_action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {len(actions)} records."
                "Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        return event

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def _extract_entity_fields(self, event: dict, entity_name: str) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.
            entity_name (str): Entity name.

        Returns:
            dict: Dictionary containing required fields.
        """
        extracted_fields = {}
        for field_name, field_value in DEVICE_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        username = extracted_fields.get("Device User Name", "")
        if username and "Error: " in username:
            extracted_fields["Device User Name"] = ""

        ip_addr = event.get("node", {}).get("ipAddresses", [])
        if ip_addr and isinstance(ip_addr, list):
            self.add_field(
                extracted_fields,
                "IP Addresses",
                ip_addr,
            )

        mac_addr = event.get("node", {}).get("macAddresses", [])
        if mac_addr and isinstance(mac_addr, list):
            self.add_field(
                extracted_fields,
                "Mac Addresses",
                mac_addr,
            )

        risk_info = (
            event.get("node", {}).get("sensorReadings", {}).get("columns", [])
        )
        if risk_info:
            for risk_column in risk_info:
                column_name = risk_column.get("name", "")
                column_value = ""
                if risk_column.get("values", []):
                    column_value = risk_column.get("values", [])[0]
                if column_name in RISK_INFO_FIELDS and column_value:
                    try:
                        column_value = float(column_value)
                    except ValueError:
                        column_value = column_value
                    self.add_field(
                        extracted_fields,
                        RISK_INFO_FIELDS.get(column_name),
                        column_value,
                    )

        installed_apps = event.get("node", {}).get("installedApplications", [])
        if installed_apps:
            self.add_field(
                extracted_fields,
                "Installed Applications",
                [apps.get("name", "") for apps in installed_apps if apps.get("name")],
            )

        return extracted_fields

    def _fetch_devices(
        self,
        api_base_url: str,
        headers: dict,
    ) -> List:
        """Fetch devices from Tanium.

        Args:
            api_base_url (str): API Base URL of Tanium.
            headers (dict): Headers with API Token.

        Returns:
            List: List of devices.
        """
        total_devices = []
        page_count = 1
        total_skip_count = 0
        api_endpoint = f"{api_base_url}/plugin/products/gateway/graphql"
        graphql_query = deepcopy(TANIUM_GRAPHQL_QUERY)
        graphql_query.update(
            {
                "variables": {
                    "first": DEVICE_PAGE_COUNT
                }
            }
        )
        while True:
            try:
                logger_msg = (
                    f"devices for page {page_count} "
                    f"from {PLATFORM_NAME} platform"
                )
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {logger_msg}."
                )
                resp_json = self.tanium_helper.api_helper(
                    url=api_endpoint,
                    method="POST",
                    json=graphql_query,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"fetching {logger_msg}"
                    ),
                )
                # If response is empty then break the loop
                if not resp_json or not isinstance(resp_json, dict):
                    break
                
                data = resp_json.get("data", {})
                if not data or not isinstance(data, dict):
                    break
                endpoints = data.get("endpoints", {})
                if not endpoints or not isinstance(endpoints, dict):
                    break
                page_devices_list = endpoints.get("edges", [])
                if (
                    not page_devices_list or
                    not isinstance(page_devices_list, list)
                ):
                    break
                curr_devices_count = len(page_devices_list)
                page_devices_count = 0
                page_devices_skip_count = 0
                for device in page_devices_list:
                    try:
                        extracted_fields = self._extract_entity_fields(
                            event=device, entity_name="Devices"
                        )
                        if extracted_fields:
                            total_devices.append(extracted_fields)
                            page_devices_count += 1
                        else:
                            page_devices_skip_count += 1
                    except Exception as err:
                        device_id = device.get("node", {}).get("id", "")
                        err_msg = (
                            "Unable to extract fields from "
                            f"device with ID '{device_id}' "
                            f"from page {page_count}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                        page_devices_skip_count += 1

                if page_devices_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped "
                        f"{page_devices_skip_count} "
                        f"device record(s) in page {page_count}."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_devices_count} device record(s) "
                    f"in page {page_count}. "
                    f"Total devices fetched: {len(total_devices)}."
                )
                page_count += 1
                total_skip_count += page_devices_skip_count

                # If current page has less than DEVICE_PAGE_COUNT(5000)
                # records or hasNextPage value in pageInfo is False then
                # break the loop
                data = resp_json.get("data", {})
                if not data or not isinstance(data, dict):
                    break
                endpoints = data.get("endpoints", {})
                if not endpoints or not isinstance(endpoints, dict):
                    break
                page_info = endpoints.get("pageInfo", {})
                if not page_info or not isinstance(page_info, dict):
                    break
                hasNextPage = page_info.get("hasNextPage", False)
                if (
                    not hasNextPage or not isinstance(hasNextPage, bool)
                    or (curr_devices_count < DEVICE_PAGE_COUNT)
                ):
                    break

                after_cursor = page_info.get("endCursor", "")
                graphql_query["variables"]["after"] = after_cursor
            except TaniumPluginException:
                raise
            except Exception as exp:
                error_message = (
                    "Error occurred"
                    if isinstance(exp, ValidationError)
                    else "Unexpected error occurred"
                )
                error_message += f" while fetching {logger_msg}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise TaniumPluginException(error_message)

        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                "device record(s) because they either do not "
                "have an 'Device ID' or fields could not be "
                "extracted from the device record."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_devices)} "
            f"device record(s) from {PLATFORM_NAME} platform."
        )
        return total_devices

    def fetch_records(self, entity: str) -> List:
        """Fetch device records from Tanium.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        (
            api_base_url,
            api_token,
        ) = self.tanium_helper.get_config_params(self.configuration)
        headers = self.tanium_helper.get_auth_header(api_token=api_token)
        try:
            if entity == "Devices":
                records.extend(self._fetch_devices(api_base_url, headers))
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Devices' Entity."
                )
                resolution = (
                    "Ensure that the entity is 'Devices'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                raise TaniumPluginException(err_msg)
        except TaniumPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching device "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise TaniumPluginException(err_msg)
        return records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        entity_name = entity.lower()
        skip_count = 0
        norm_score_skip_count = 0
        updated_records = []

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )

        (
            api_base_url,
            api_token,
        ) = self.tanium_helper.get_config_params(self.configuration)
        headers = self.tanium_helper.get_auth_header(api_token=api_token)
        try:
            if entity == "Devices":
                device_ids = {
                    record.get("Device ID", ""): record
                    for record in records if record.get("Device ID", "")
                }

                log_msg = (
                    f"{len(device_ids)} {entity_name} record(s) will be "
                    f"updated out of {len(records)} records."
                )

                skipped_count = len(records) - len(device_ids)
                if skipped_count > 0:
                    log_msg += (
                        f" {skipped_count} {entity_name} record(s) "
                        "will be skipped as they do not contain "
                        "'Device ID' field."
                    )

                self.logger.info(f"{self.log_prefix}: {log_msg}")
                device_list = self._fetch_devices(api_base_url, headers)
                device_update_count = 0
                for device in device_list:
                    current_id = device.get("Device ID", "")
                    if current_id in device_ids:
                        record = device_ids[current_id]
                        risk_score = device.get("Risk Score", "")
                        if isinstance(risk_score, float) and 0 <= risk_score <= 1000:
                            device["Netskope Normalized Score"] = (
                                self._normalize_risk_scores(risk_score)
                            )
                        else:
                            resolution = (
                                "Ensure that the 'Risk Score' field "
                                "is a number between 0 and 1000 on "
                                f"{PLATFORM_NAME} platform for "
                                f"Device ID: {current_id}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Invalid "
                                    f"{PLATFORM_NAME} Risk Score received "
                                    f"for Device ID: {current_id}. "
                                    "Netskope Normalized Score will not be "
                                    "calculated for this device. "
                                    "Valid Risk Score range is 0 to 1000."
                                ),
                                resolution=resolution,
                                details=f"Risk Score: '{risk_score}'",
                            )
                            norm_score_skip_count += 1
                        record.update(device)
                        device_update_count += 1
                        updated_records.append(record)
                    else:
                        skip_count += 1
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Devices' Entity."
                )
                resolution = (
                    "Ensure that the entity is 'Devices'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                raise TaniumPluginException(err_msg)
        except TaniumPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while updating {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise TaniumPluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped updating {skip_count} "
                f"{entity_name} record(s) as records are not fetched "
                f"from the {PLATFORM_NAME} platform."
            )
        if norm_score_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating "
                "Netskope Normalized Score for "
                f"{norm_score_skip_count} {entity_name} record(s) "
                "as invalid Risk Score value received from the "
                f"{PLATFORM_NAME} platform."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{device_update_count} {entity_name} record(s) "
            f"from {PLATFORM_NAME} platform."
        )
        return updated_records

    def _normalize_risk_scores(self, tanium_risk_score: float) -> int:
        """Normalize the Tanium Risk score.

        Args:
            tanium_risk_score (int): Tanium risk score.

        Returns:
            int: Netskope Normalized Score.
        """
        netskope_normalized_score = round(abs(1000 - tanium_risk_score), 2)
        return netskope_normalized_score

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_msg = "Validation error occurred."
        # Validate API Base URL.
        api_base_url = configuration.get("api_base_url", "").strip().strip("/")
        if not api_base_url:
            err_msg = "API Base URL is a required configuration parameter."
            resolution = (
                "Ensure that the API Base URL is provided in "
                "the plugin configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        elif not (
            isinstance(api_base_url, str) and self._validate_url(api_base_url)
        ):
            err_msg = (
                "Invalid API Base URL provided in "
                "the configuration parameters."
            )
            resolution = (
                "Ensure that the API Base URL is provided in "
                "the plugin configuration parameters. "
                "API Base URL should be an non-empty string."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate API Token.
        api_token = configuration.get("api_token")
        if not api_token:
            err_msg = "API Token is a required configuration parameter."
            resolution = (
                "Ensure that the API Token is provided in "
                "the plugin configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(api_token, str)):
            err_msg = (
                "Invalid API Token provided in the "
                "configuration parameters."
            )
            resolution = (
                "Ensure that the API Token is provided in "
                "the plugin configuration parameters. "
                "API Token should be an non-empty string."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity to the Tanium server.
        return self._validate_connectivity(
            api_base_url=api_base_url,
            api_token=api_token
        )

    def _validate_connectivity(
        self,
        api_base_url: str,
        api_token: str
    ) -> ValidationResult:
        """Validate connectivity with Tanium server.

        Args:
            api_base_url (str): API Base URL.
            api_token (str): API Token.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )
            headers = self.tanium_helper.get_auth_header(api_token=api_token)

            # Tanium API Endpoint
            api_endpoint = f"{api_base_url}/plugin/products/gateway/graphql"
            graphql_query = deepcopy(TANIUM_GRAPHQL_QUERY)
            graphql_query.update(
                {
                    "variables": {
                        "first": 1
                    }
                }
            )
            self.tanium_helper.api_helper(
                url=api_endpoint,
                method="POST",
                json=graphql_query,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity "
                    f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )

            logger_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True,
                message=logger_msg,
            )
        except TaniumPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp)
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

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.STRING,
                        required=True
                    ),
                    EntityField(
                        name="Device Name",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Computer ID",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="System ID",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Domain Name",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Manufacturer",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="IP Address",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="IP Addresses",
                        type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="Mac Addresses",
                        type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="Device User Name",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device User Email",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="OS",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="OS Platform",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="OS Generation",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER
                    ),
                    EntityField(
                        name="Risk Score Level",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Asset Criticality",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Installed Applications",
                        type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER
                    ),
                ]
            )
        ]
