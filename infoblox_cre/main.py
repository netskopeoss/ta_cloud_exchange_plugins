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

CRE Infoblox plugin.
"""

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
    EntityFieldType
)

from .utils.infoblox_constants import (
    MODULE_NAME,
    DEVICE_PAGE_COUNT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    APPLICATION_FIELD_MAPPING,
    DEVICE_FIELD_MAPPING,
)

from .utils.infoblox_helper import InfobloxPluginException, InfobloxPluginHelper


class InfobloxPlugin(PluginBase):
    """Infoblox plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Infoblox plugin initializer.

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
        self.infoblox_helper = InfobloxPluginHelper(
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
            manifest_json = InfobloxPlugin.metadata
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
        return [
            ActionWithoutParams(label="Update application status", value="update_app_status"),
            ActionWithoutParams(label="No action", value="generate")
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate"]:
            return []

        if action.value == "update_app_status":
            return [
                {
                    "label": "Application Name",
                    "key": "application_name",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Application name to perform the action on. If application "
                        "does not exist on Infoblox BloxOne, it will be created."
                    )
                },
                {
                    "label": "Status",
                    "key": "application_status",
                    "type": "choice",
                    "choices": [
                        {"key": "Approved", "value": "APPROVED"},
                        {"key": "Unapproved", "value": "UNAPPROVED"},
                    ],
                    "default": "APPROVED",
                    "mandatory": True,
                    "description": "Select status for the application.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Wiz action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        action_params = action.parameters
        if action_value not in ["generate", "update_app_status"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration. "
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "update_app_status":
            application_name = action_params.get("application_name", "")
            if not application_name:
                err_msg = "Application Name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(application_name, str):
                err_msg = "Application Name provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            application_status = action_params.get("application_status", "")
            if not application_status:
                err_msg = "Application Status is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif "$" in application_status:
                err_msg = (
                    "Status contains the Source Field. "
                    "Please select Status from Static Field dropdown only."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False, message=err_msg
                )
            elif application_status not in [
                "APPROVED",
                "UNAPPROVED"
            ]:
                err_msg = (
                    "Invalid Status provided. "
                    "Supported status are: 'Approved', 'Unapproved'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False, message=err_msg
                )

        return ValidationResult(
            success=True,
            message="Validation successful."
        )

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        action_label = action.label
        action_parameters = action.parameters

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

        application_name = action_parameters.get("application_name", "").strip()
        application_status = action_parameters.get("application_status", "").strip()
        if not application_name:
            err_msg = (
                "Application Name not found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return
        elif not isinstance(application_name, str):
            err_msg = (
                "Invalid Application Name found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action. "
                "Selected 'Source' field should be of type string."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return

        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for application '{application_name}'."
        )

        (
            base_url,
            api_key,
        ) = self.infoblox_helper.get_config_params(self.configuration)
        headers = self.infoblox_helper.get_auth_header(
            api_key=api_key
        )

        try:
            logger_msg = (
                f"performing '{action_label}' on "
                f"application '{application_name}'"
            )
            api_endpoint = f"{base_url}/api/atcfw/v1/app_approvals"
            payload = {
                "inserted_approvals": [
                    {
                        "app_name": application_name,
                        "status": application_status
                    }
                ]
            }
            _ = self.infoblox_helper.api_helper(
                url=api_endpoint,
                method="PATCH",
                headers=headers,
                json=payload,
                configuration=self.configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=logger_msg,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated status of "
                f"the '{application_name}' application."
            )
        except InfobloxPluginException as err:
            raise InfobloxPluginException(err)
        except Exception as err:
            err_msg = (
                f"Error occurred while updating status of "
                f"the '{application_name}' application. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise InfobloxPluginException(err_msg)

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
        if isinstance(value, int):
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
        entity_field_mapping = (
            APPLICATION_FIELD_MAPPING
            if entity_name == "applications"
            else DEVICE_FIELD_MAPPING
        )
        for field_name, field_value in entity_field_mapping.items():
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

        if entity_name == "devices":
            if event.get("tags", {}):
                self.add_field(
                    extracted_fields,
                    "Device Tags",
                    [f"{k} = {v}" for k, v in event.get("tags", {}).items()],
                )

            if event.get("net_info", {}).get("mac_addr", []):
                self.add_field(
                    extracted_fields,
                    "Device MAC Address",
                    [mac_addr for mac_addr in event.get("net_info", {}).get("mac_addr", [])],
                )

        return extracted_fields

    def _fetch_applications(self, base_url: str, headers: dict) -> List:
        """Fetch applications from Infoblox.

        Args:
            base_url (str): Base URL of Infoblox.
            headers (dict): Headers with API key.

        Returns:
            List: List of applications.
        """
        total_applications = []
        total_skip_count = 0
        api_endpoint = f"{base_url}/api/atcfw/v1/app_approvals"
        try:
            self.logger.debug(
                f"{self.log_prefix}: Fetching applications "
                f"from {PLATFORM_NAME} platform."
            )
            resp_json = self.infoblox_helper.api_helper(
                url=api_endpoint,
                method="GET",
                headers=headers,
                configuration=self.configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching applications from {PLATFORM_NAME} platform"
                )
            )
            application_list = resp_json.get("results", [])
            for application in application_list:
                try:
                    extracted_fields = self._extract_entity_fields(
                        event=application, entity_name="applications"
                    )
                    if extracted_fields:
                        total_applications.append(extracted_fields)
                    else:
                        total_skip_count += 1
                except Exception as err:
                    app_name = application.get("app_name", "")
                    err_msg = (
                        "Unable to extract fields from "
                        f"application with name '{app_name}'."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} Error: {err}."
                        ),
                        details=f"Application: {application}"
                    )
                    total_skip_count += 1
        except InfobloxPluginException:
            raise
        except Exception as exp:
            error_message = (
                "Error occurred"
                if isinstance(exp, ValidationError)
                else "Unexpected error occurred"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"while fetching application record(s) from {PLATFORM_NAME} "
                    f"platform. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                f"application record(s) due to some error occurred while fetching."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_applications)} "
            f"application record(s) from {PLATFORM_NAME} platform."
        )
        return total_applications

    def _fetch_devices(self, base_url: str, headers: dict) -> List:
        """Fetch devices from Infoblox.

        Args:
            base_url (str): Base URL of Infoblox.
            headers (dict): Headers with API key.

        Returns:
            List: List of devices.
        """
        total_devices = []
        page_count = 1
        total_skip_count = 0
        api_endpoint = f"{base_url}/api/atcep/v1/roaming_devices"
        device_params = {
            "_limit": DEVICE_PAGE_COUNT,
            "_offset": 0,
        }
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Fetching devices for page {page_count} "
                    f"from {PLATFORM_NAME} platform."
                )
                resp_json = self.infoblox_helper.api_helper(
                    url=api_endpoint,
                    method="GET",
                    params=device_params,
                    headers=headers,
                    configuration=self.configuration,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"fetching devices for page {page_count} "
                        f"from {PLATFORM_NAME} platform"
                    )
                )
                page_devices_list = resp_json.get("results", [])
                curr_devices_count = len(page_devices_list)
                page_devices_count = 0
                page_devices_skip_count = 0
                for device in page_devices_list:
                    try:
                        extracted_fields = self._extract_entity_fields(
                            event=device, entity_name="devices"
                        )
                        if extracted_fields:
                            total_devices.append(extracted_fields)
                            page_devices_count += 1
                        else:
                            page_devices_skip_count += 1
                    except Exception as err:
                        device_client_id = device.get("client_id", "")
                        err_msg = (
                            "Unable to extract fields from "
                            f"device with ID '{device_client_id}'."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}."
                            ),
                            details=f"Device: {device}"
                        )
                        page_devices_skip_count += 1

                if page_devices_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped {page_devices_skip_count} "
                        f"device record(s) in page {page_count}."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_devices_count} device record(s) in page {page_count}. "
                    f"Total devices fetched: {len(total_devices)}."
                )
                page_count += 1
                total_skip_count += page_devices_skip_count
                total_result_count = resp_json.get("total_result_count", None)
                # If current page has less than DEVICE_PAGE_COUNT records then
                # break the loop
                if (
                    curr_devices_count < DEVICE_PAGE_COUNT or
                    len(total_devices) == total_result_count
                ):
                    break
                device_params["_offset"] += DEVICE_PAGE_COUNT
            except InfobloxPluginException:
                raise
            except Exception as exp:
                error_message = (
                    "Error occurred"
                    if isinstance(exp, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"while fetching device record(s) from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                f"device record(s) due to some error occurred while fetching."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_devices)} "
            f"device record(s) from {PLATFORM_NAME} platform."
        )
        return total_devices

    def fetch_records(self, entity: str) -> List:
        """Pull Users records from Infoblox.

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
            base_url,
            api_key,
        ) = self.infoblox_helper.get_config_params(self.configuration)
        headers = self.infoblox_helper.get_auth_header(
            api_key=api_key
        )
        try:
            if entity_name == "applications":
                records.extend(
                    self._fetch_applications(base_url, headers)
                )
            elif entity_name == "devices":
                records.extend(
                    self._fetch_devices(base_url, headers)
                )
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} only supports "
                    "Applications and Device Entities."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise InfobloxPluginException(err_msg)
        except InfobloxPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxPluginException(err_msg)
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
        total_records_count = 0

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )

        (
            base_url,
            api_key,
        ) = self.infoblox_helper.get_config_params(self.configuration)
        headers = self.infoblox_helper.get_auth_header(
            api_key=api_key
        )
        try:
            if entity_name == "applications":
                record_uid_list = {record["Application Name"]: record for record in records}
                application_list = self._fetch_applications(base_url, headers)
                app_update_count = 0
                for application in application_list:
                    current_uid = application.get("Application Name", "")
                    if current_uid in record_uid_list:
                        record = record_uid_list[current_uid]
                        record.update(
                            {
                                "Application Status": application.get("Application Status", ""),
                            }
                        )
                        app_update_count += 1
                total_records_count += app_update_count
            elif entity_name == "devices":
                record_uid_list = {record["Device ID"]: record for record in records}
                device_list = self._fetch_devices(base_url, headers)
                device_update_count = 0
                for device in device_list:
                    current_uid = device.get("Device ID", "")
                    if current_uid in record_uid_list:
                        record = record_uid_list[current_uid]
                        record.update(
                            {
                                "Device Name": device.get("Device Name", ""),
                                "Device Country": device.get("Device Country", ""),
                                "Device Region": device.get("Device Region", ""),
                                "Device Public IP": device.get("Device Public IP", ""),
                                "Device State": device.get("Device State", ""),
                                "Device Tags": device.get("Device Tags", []),
                                "Device MAC Address": device.get("Device MAC Address", []),
                            }
                        )
                        device_update_count += 1
                total_records_count += device_update_count
        except InfobloxPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{total_records_count} {entity_name} record(s) "
            f"out of {len(records)} from {PLATFORM_NAME} platform."
        )
        return records

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate Base URL.
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            err_msg = (
                "Invalid Base URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate API key.
        api_key = configuration.get("api_key")
        if not api_key:
            err_msg = (
                "API key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(api_key, str)):
            err_msg = (
                "Invalid API key provided in the "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity to the Infoblox server.
        return self._validate_connectivity(
            base_url=base_url,
            api_key=api_key
        )

    def _validate_connectivity(
        self, base_url: str, api_key: str
    ) -> ValidationResult:
        """Validate connectivity with Infoblox server.

        Args:
            base_url (str): Base URL.
            api_key (Dict): API key.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )
            headers = self.infoblox_helper.get_auth_header(
                api_key=api_key
            )

            # Application API Endpoint
            app_endpoint = f"{base_url}/api/atcfw/v1/app_approvals"
            self.infoblox_helper.api_helper(
                url=app_endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity for applications "
                    f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
                regenerate_auth_token=False
            )

            # Device API Endpoint
            device_endpoint = f"{base_url}/api/atcep/v1/roaming_devices"
            device_params = {
                "_limit": 1
            }
            self.infoblox_helper.api_helper(
                url=device_endpoint,
                method="GET",
                params=device_params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity for devices "
                    f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
                regenerate_auth_token=False
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"connectivity with {PLATFORM_NAME} server and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message=(
                    f"Validation successful for {MODULE_NAME} "
                    f"{self.plugin_name} plugin configuration."
                ),
            )
        except InfobloxPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
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
                name="Applications",
                fields=[
                    EntityField(
                        name="Application Name", type=EntityFieldType.STRING, required=True
                    ),
                    EntityField(name="Application Status", type=EntityFieldType.STRING),
                ]
            ),
            Entity(
                name="Devices",
                fields=[
                    EntityField(name="Device ID", type=EntityFieldType.STRING, required=True),
                    EntityField(name="Device Name", type=EntityFieldType.STRING),
                    EntityField(name="Device Country", type=EntityFieldType.STRING),
                    EntityField(name="Device Region", type=EntityFieldType.STRING),
                    EntityField(name="Device Public IP", type=EntityFieldType.STRING),
                    EntityField(name="Device State", type=EntityFieldType.STRING),
                    EntityField(name="Device Tags", type=EntityFieldType.LIST),
                    EntityField(name="Device MAC Address", type=EntityFieldType.LIST),
                ]
            )
        ]
