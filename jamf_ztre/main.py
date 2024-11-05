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
OF THIS SOFTWARE, EVEN IF IDVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CRE Jamf Plugin.
"""

import traceback
import requests
from typing import List

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    ACTION_ENDPOINT,
    DEVICE_ENDPOINT,
    DEVICE_FIELD_MAPPING,
    PAGE_SIZE,
)
from .utils.helper import (
    JamfPluginException,
    JamfPluginHelper,
)


class JamfPlugin(PluginBase):
    """JAMF plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.jamf_helper = JamfPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = JamfPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_device_ids_list(self, device_ids: str) -> tuple:
        """
        Extract comma-separated values from a string.

        args:
            device_ids: The input string containing comma-separated values.

        returns:
            A tuple of the extracted values and a boolean
            indicating whether any empty strings were found.
        """
        # Split the input string by commas
        values = [value.strip() for value in device_ids.split(",")]

        # Check if any of the split values are empty
        contains_empty_string = any(value.strip() == "" for value in values)

        return values, contains_empty_string

    def _handle_action_response(
        self,
        response=requests.models.Response,
        action_label=str,
        logger_msg=str,
    ):
        """Handle action response.

        Args:
            resp (Response): Response object
            action_label (str): Action label
        """
        if response.status_code == 204:
            self.logger.info(
                f"{self.log_prefix}: Successfully triggered '{action_label}' "
                f"action for {logger_msg}."
            )
            return
        elif response.status_code == 400:
            resp_json = self.jamf_helper.parse_response(response=response)
            api_err_code = resp_json.get(
                "error", "No error details found in API response."
            )
            api_err_msg = resp_json.get(
                "message", "No error message found in API response."
            )

            raise_msg = (
                f"Unable to trigger '{action_label}' "
                f"action for {logger_msg}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {raise_msg} Error code:"
                    f" {api_err_code} Message: {str(api_err_msg)} "
                ),
                details=f"API response: {response.text}",
            )
            raise JamfPluginException(raise_msg)
        elif response.status_code == 403:
            raise_msg = (
                f"Unable to trigger '{action_label}' "
                f"action for {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {raise_msg}",
                details=f"API response: {response.text}",
            )
            raise JamfPluginException(raise_msg)

        self.jamf_helper.handle_error(response, logger_msg)

    def _trigger_action(
        self,
        action_label: str,
        device_ids_list: List[str],
        risk_level: str,
        logger_msg: str,
        headers: dict = {},
    ):
        self.logger.info(
            f"{self.log_prefix}: Performing '{action_label}' on {logger_msg}."
        )

        base_url, username, password = self.jamf_helper.get_credentials(
            configuration=self.configuration
        )

        url = f"{base_url}/{ACTION_ENDPOINT}"
        access_token = self.jamf_helper.get_access_token(
            headers, base_url, username, password
        )
        headers["Authorization"] = f"Bearer {access_token}"
        data = {}
        if action_label == "Override Risk Level":
            data = {
                "risk": risk_level,
                "source": "MANUAL",
                "deviceIds": device_ids_list,
            }
        elif action_label == "Revert Risk Level":
            data = {
                "source": "WANDERA",
                "deviceIds": device_ids_list,
            }

        response = self.jamf_helper.api_helper(
            url=url,
            method="PUT",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            json=data,
            logger_msg=f"performing '{action_label}' on {logger_msg} ",
            is_handle_error_required=False,
        )

        self._handle_action_response(
            response=response, action_label=action_label, logger_msg=logger_msg
        )

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(
                label="Override Risk Level", value="override_risk_level"
            ),
            ActionWithoutParams(
                label="Revert Risk Level", value="revert_risk_level"
            ),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []

        if action.value == "override_risk_level":
            return [
                {
                    "label": "Risk Level",
                    "key": "risk_level",
                    "type": "choice",
                    "choices": [
                        {"key": "SECURE", "value": "SECURE"},
                        {"key": "LOW", "value": "LOW"},
                        {"key": "MEDIUM", "value": "MEDIUM"},
                        {"key": "HIGH", "value": "HIGH"},
                    ],
                    "default": "SECURE",
                    "mandatory": True,
                    "description": (
                        "Select the risk level to be set for the device."
                    ),
                },
                {
                    "label": "Device IDs",
                    "key": "device_ids",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "List of comma separated Device IDs to be updated."
                    ),
                },
            ]
        elif action.value == "revert_risk_level":
            return [
                {
                    "label": "Device IDs",
                    "key": "device_ids",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "List of comma separated Device IDs to revert risk."
                    ),
                },
            ]

    def execute_action(self, action: Action):
        """Execute action on the devices.

        Args:
            action (Action): Action that needs to be perform on devices.

        Returns:
            None
        """
        action_label = action.label
        action_parameters = action.parameters

        if action.value == "generate":
            return

        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action."
        )
        headers = self.get_headers()

        try:
            if not action_parameters.get("device_ids", ""):
                err_msg = (
                    "Invalid Device IDs found in action parameters."
                    f" Cannot perform {action_label} action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                raise JamfPluginException(err_msg)
            
            device_ids = action_parameters.get("device_ids", "").strip()
            risk_level = action_parameters.get("risk_level", "").strip()
            device_ids_list, _ = self._get_device_ids_list(device_ids)
            log_msg = f" devices with IDs {device_ids}"

            if action.value == "override_risk_level":

                self._trigger_action(
                    action_label=action_label,
                    device_ids_list=device_ids_list,
                    risk_level=risk_level,
                    logger_msg=log_msg,
                    headers=headers,
                )

            elif action.value == "revert_risk_level":

                self._trigger_action(
                    action_label=action_label,
                    device_ids_list=device_ids_list,
                    risk_level="",
                    logger_msg=log_msg,
                    headers=headers,
                )

        except JamfPluginException:
            raise
        except Exception as err:
            err_msg = "Unexpected error occurred while executing action."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=traceback.format_exc(),
            )
            raise JamfPluginException(err_msg)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate JAMF action configuration."""
        try:
            validation_msg = "Validation successful."
            validation_err_msg = "Unsupported action provided."
            action_value = action.value
            action_params = action.parameters
            if action_value not in [
                "override_risk_level",
                "revert_risk_level",
                "generate",
            ]:
                self.logger.error(
                    message=f"{self.log_prefix}: {validation_err_msg}",
                )
                return ValidationResult(
                    success=False,
                    message=(
                        f"{validation_err_msg} Supported actions are "
                        "'Override Risk Level' and 'No actions'."
                    ),
                )

            if action_value == "generate":
                return ValidationResult(success=True, message=validation_msg)

            if action_value == "override_risk_level":
                risk_level = action_params.get("risk_level", "").strip()
                if not risk_level:
                    err_msg = (
                        "Risk level is a required action parameter for "
                        "'Override Risk Level' action."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif not isinstance(risk_level, str):
                    err_msg = (
                        "Invalid risk level found in the action parameters. "
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif risk_level not in ["SECURE", "LOW", "MEDIUM", "HIGH"]:
                    err_msg = (
                        "Invalid risk level provided in the action parameters."
                        "Valid risk levels are 'SECURE', 'LOW', 'MEDIUM',"
                        " 'HIGH' for 'Override Risk Level' action."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                device_ids = action_params.get("device_ids", "").strip()
                _, contains_empty_string = self._get_device_ids_list(
                    device_ids
                )
                if not device_ids:
                    err_msg = (
                        "Device IDs not found in the action parameters "
                        "for 'Override Risk Level' action."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif not isinstance(device_ids, str):
                    err_msg = (
                        "Invalid Device IDs found in the action parameters. "
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif contains_empty_string:
                    err_msg = (
                        "Invalid Device IDs found in 'Override Risk Level'"
                        " action parameters. Valid value should be a string"
                        " containing Device IDs separated by comma."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            elif action_value == "revert_risk_level":
                device_ids = action_params.get("device_ids", "").strip()
                _, contains_empty_string = self._get_device_ids_list(
                    device_ids
                )
                if not device_ids:
                    err_msg = (
                        "Device IDs not found in the action parameters "
                        "for 'Revert Risk Level' action."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif not isinstance(device_ids, str):
                    err_msg = (
                        "Invalid Device IDs found in the action parameters. "
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif contains_empty_string:
                    err_msg = (
                        "Invalid Device IDs found in 'Revert Risk Level'"
                        " action parameters. Valid value should be a string"
                        " containing Device IDs separated by comma."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            return ValidationResult(success=True, message=validation_msg)
        except Exception as exp:
            err_msg = f"Exception occurred in validate action. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)

    def get_headers(self):
        """Get headers with additional fields.

        Args:
            headers (dict): Request headers

        Returns:
            headers: headers with additional fields.
        """
        headers = {}
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "*/*"
        return headers

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate base_url
        validation_err_msg = "Validation error occurred."
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(base_url, str):
            err_msg = "Invalid Base URL provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate username
        username = configuration.get("application_id", "").strip()
        if not username:
            err_msg = "Application ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(username, str):
            err_msg = (
                "Invalid Application ID value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate password
        password = configuration.get("application_secret")
        if not password:
            err_msg = (
                "Application Secret is a required configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(password, str):
            err_msg = (
                "Invalid Application Secret value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with JAMF platform.

        Args: configuration (dict): Contains the below keys:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate
                OAUTH2 token.
            tenant_id (str): Tenant ID that user wants

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            base_url, username, password = self.jamf_helper.get_credentials(
                configuration=configuration
            )
            headers = self.get_headers()

            access_token = self.jamf_helper.get_access_token(
                headers,
                base_url,
                username,
                password,
                is_validation=True,
            )
            headers["Authorization"] = f"Bearer {access_token}"

            url = f"{base_url}/{DEVICE_ENDPOINT}"

            self.jamf_helper.api_helper(
                url=url,
                method="GET",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"checking connectivity with {PLATFORM_NAME} platform"
                ),
                is_validation=True,
                regenerate_auth_token=False,
            )

            msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{PLATFORM_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {msg}")
            return ValidationResult(
                success=True,
                message=msg,
            )

        except JamfPluginException as exp:
            return ValidationResult(success=False, message=str(exp))

        except Exception as exp:
            err_msg = (
                "Validation error occurred while checking "
                f"connectivity with {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

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

    def _extract_each_device_fields(
        self, event: dict, include_normalization: bool = True
    ) -> dict:
        """Extract IOA fields.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
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

        if event.get("riskCategory") and include_normalization:
            risk_level = event.get("riskCategory")
            normalized_score = None
            if risk_level == "SECURE":
                normalized_score = 875
            elif risk_level == "LOW":
                normalized_score = 875
            elif risk_level == "MEDIUM":
                normalized_score = 625
            elif risk_level == "HIGH":
                normalized_score = 375
            else:
                err_msg = (
                    f"Invalid risk level '{risk_level}' found in response."
                )
                self.logger.error(message=f"{self.log_prefix}: {err_msg}")
                raise JamfPluginException(err_msg)
            self.add_field(
                extracted_fields, "Netskope Normalized Score", normalized_score
            )

        return extracted_fields

    def fetch_records(self, entity: str) -> List:
        """Pull Records from JAMF.

        Returns:
            List: List of records to be stored on the platform.
        """
        total_records = []
        if entity == "Devices":
            entity_name = entity.lower()
            self.logger.info(
                f"{self.log_prefix}: Fetching {entity_name} from "
                f"{PLATFORM_NAME} platform."
            )
            base_url, username, password = self.jamf_helper.get_credentials(
                configuration=self.configuration
            )
            headers = self.get_headers()
            url = f"{base_url}/{DEVICE_ENDPOINT}"

            access_token = self.jamf_helper.get_access_token(
                headers, base_url, username, password
            )
            headers["Authorization"] = f"Bearer {access_token}"

            page_count = 1
            skip_count = 0

            while True:
                try:
                    params = {"page": page_count - 1, "pageSize": PAGE_SIZE}
                    resp_json = self.jamf_helper.api_helper(
                        url=url,
                        method="GET",
                        headers=headers,
                        params=params,
                        proxies=self.proxy,
                        verify=self.ssl_validation,
                        logger_msg=(
                            f"fetching {entity_name} for page "
                            f"{page_count} from {PLATFORM_NAME}"
                        ),
                    )

                    user_device_list = resp_json.get("userDeviceList", [])

                    current_device_count = len(user_device_list)

                    for each_device in user_device_list:
                        try:
                            extracted_fields = (
                                self._extract_each_device_fields(
                                    each_device,
                                    include_normalization=False,
                                )
                            )
                            if extracted_fields:
                                total_records.append(extracted_fields)
                            else:
                                skip_count += 1
                        except JamfPluginException:
                            skip_count += 1
                        except Exception as err:
                            guid = each_device.get("guid")
                            err_msg = (
                                "Unable to extract fields from device"
                                f' having Device ID "{guid}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} Error: {err}"
                                ),
                                details=f"Record: {each_device}",
                            )
                            skip_count += 1
                            
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{current_device_count} device(s) "
                        f"in page {page_count} Total {entity_name}"
                        f" fetched: {len(total_records)}."
                    )

                    if not user_device_list:
                        break

                    page_count += 1

                except JamfPluginException:
                    raise
                except Exception as exp:
                    err_msg = (
                        f"Unexpected error occurred "
                        f"while fetching {entity_name} from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(traceback.format_exc()),
                    )
                    raise JamfPluginException(err_msg)
            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} {entity_name}"
                    f" because they might not contain Device ID"
                    " in their response or fields could "
                    "not be extracted from them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {len(total_records)} {entity_name} "
                f"from {PLATFORM_NAME} platform."
            )
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise JamfPluginException(err_msg)

        return total_records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update devices scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = []
        if entity == "Devices":
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)} {entity.lower()}"
                f" records from {PLATFORM_NAME}."
            )
            guid_list = []
            for record in records:
                if record.get("Device ID"):
                    guid_list.append(record.get("Device ID"))

            self.logger.info(
                f"{self.log_prefix}: {len(guid_list)} device record(s)"
                f" will be updated and skipped "
                f"{len(records) - len(guid_list)} records as they "
                "do not have Device ID field in it."
            )

            base_url, username, password = self.jamf_helper.get_credentials(
                configuration=self.configuration
            )
            headers = self.get_headers()
            url = f"{base_url}/{DEVICE_ENDPOINT}"

            access_token = self.jamf_helper.get_access_token(
                headers, base_url, username, password
            )
            headers["Authorization"] = f"Bearer {access_token}"
            page_count = 1
            skip_count = 0
            total_device_update_count = 0
            entity_name = entity.lower()

            while True:
                try:
                    params = {"page": page_count - 1, "pageSize": PAGE_SIZE}

                    resp_json = self.jamf_helper.api_helper(
                        url=url,
                        method="GET",
                        headers=headers,
                        params=params,
                        proxies=self.proxy,
                        verify=self.ssl_validation,
                        logger_msg=(
                            f"fetching {entity_name} for page "
                            f"{page_count} from {PLATFORM_NAME}"
                        ),
                    )

                    user_device_list = resp_json.get("userDeviceList", [])
                    device_update_count = 0
                    for each_device in user_device_list:
                        try:
                            extracted_fields = (
                                self._extract_each_device_fields(
                                    each_device,
                                    include_normalization=True,
                                )
                            )

                            if extracted_fields:
                                current_uid = extracted_fields.get(
                                    "Device ID", ""
                                )
                                if current_uid in guid_list:
                                    updated_records.append(extracted_fields)
                                    device_update_count += 1

                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1
                        except JamfPluginException:
                            skip_count += 1
                        except Exception as err:
                            guid = each_device.get("guid")
                            err_msg = (
                                "Unable to extract fields from device"
                                f' having Device ID "{guid}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} Error: {err}"
                                ),
                                details=f"Record: {each_device}",
                            )
                            skip_count += 1

                    total_device_update_count += device_update_count
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully updated records for "
                        f"{device_update_count} {entity_name} in"
                        f" page {page_count}. Total record(s) "
                        f"updated: {total_device_update_count}."
                    )

                    if not user_device_list:
                        break

                    page_count += 1

                except JamfPluginException:
                    raise
                except Exception as exp:
                    err_msg = (
                        f"Unexpected error occurred "
                        f"while updating {entity_name} from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(traceback.format_exc()),
                    )
                    raise JamfPluginException(err_msg)

            self.logger.info(
                f"{self.log_prefix}: Successfully updated "
                f"{total_device_update_count} {entity_name} record(s)"
                f" out of {len(records)} from {PLATFORM_NAME}."
            )
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise JamfPluginException(err_msg)
        return updated_records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="User Name", type=EntityFieldType.STRING),
                    EntityField(
                        name="User Email", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Name", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device System Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(name="App Name", type=EntityFieldType.STRING),
                    EntityField(
                        name="App Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Platform", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Risk Category",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
