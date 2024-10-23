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

CRE Microsoft Defender for Endpoint Plugin.
"""

import datetime
import json
import jwt
import traceback
import requests
from typing import List

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)

from .utils.constants import (
    DEFAULT_BASE_URL,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PAGE_RECORD_SCORE
)
from .utils.helper import (
    MicrosoftDefenderEndpointPluginException,
    MicrosoftDefenderEndpointPluginHelper
)


class MicrosoftDefenderEndpointPlugin(PluginBase):
    """Microsoft Defender Endpoint plugin implementation."""

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
        self.defender_endpoint_helper = MicrosoftDefenderEndpointPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            configuration=self.configuration
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MicrosoftDefenderEndpointPlugin.metadata
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

    def _handle_action_response(
        self,
        response=requests.models.Response,
        action_label=str,
        logger_msg=str
    ):
        """Handle action response.

        Args:
            resp (Response): Response object
            action_label (str): Action label
        """
        if response.status_code == 201:
            self.logger.info(
                f"{self.log_prefix}: Successfully triggered '{action_label}' "
                f"action for {logger_msg}."
            )
            return
        elif response.status_code == 400:
            resp_json = self.defender_endpoint_helper.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            ).get("message", "No error message found in API response.")
            msg = f"Unexpected error occurred while executing '{action_label}' action."
            if resp_json.get("error", {}).get("code", "") == "OsPlatformNotSupported":
                msg = (
                    f"This error may occur if device OS is not "
                    f"supported '{action_label}' action."
                )
            elif resp_json.get("error", {}).get("code", "") == "InvalidInput":
                msg = (
                    "This error may occur if provided "
                    "comment length is more than 4000 characters."
                )
            raise_msg = (
                f"Unable to trigger '{action_label}' "
                f"action for {logger_msg}. {msg}"
            )
            self.logger.error(
                f"{self.log_prefix}: {raise_msg} Error: {str(api_err_msg)}"
            )
            raise MicrosoftDefenderEndpointPluginException(raise_msg)
        elif response.status_code == 404:
            raise_msg = (
                f"Unable to trigger '{action_label}' "
                f"action for {logger_msg}. This error may occur if device "
                f"does not exist on Microsoft Defender."
            )
            self.logger.error(
                f"{self.log_prefix}: {raise_msg}"
            )
            return

        self.defender_endpoint_helper.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _trigger_action(
        self,
        action_label: str,
        machine_id: str,
        action_endpoint: str,
        comment: str,
        logger_msg: str,
        isolation_type: str = None,
        scan_type: str = None,
        headers: dict = {}
    ):
        self.logger.info(
            f"{self.log_prefix}: Performing '{action_label}' on {logger_msg}."
        )

        base_url = self.configuration.get("base_url", DEFAULT_BASE_URL).strip("/")
        url = f"{base_url}/api/machines/{machine_id}/{action_endpoint}"

        data = {
            "Comment": comment,
        }

        if isolation_type:
            data["IsolationType"] = isolation_type

        if scan_type:
            data["ScanType"] = scan_type

        response = self.defender_endpoint_helper.api_helper(
            url=url,
            method="POST",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            data=json.dumps(data),
            logger_msg=f"performing '{action_label}' on {logger_msg} ",
            is_handle_error_required=False,
        )

        self._handle_action_response(
            response=response,
            action_label=action_label,
            logger_msg=logger_msg
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
            ActionWithoutParams(label="Isolate device", value="isolate_machine"),
            ActionWithoutParams(label="Undo isolation", value="undo_isolation"),
            ActionWithoutParams(label="Restrict app execution", value="restrict_app_execution"),
            ActionWithoutParams(label="Remove app restriction", value="remove_app_restriction"),
            ActionWithoutParams(label="Run antivirus scan", value="run_antivirus_scan"),
            ActionWithoutParams(label="Offboard device", value="offboard_machine"),
            ActionWithoutParams(
                label="Collect investigation package", value="collect_investigation_package"
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

        if action.value == "isolate_machine":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Isolation Type",
                    "key": "isolation_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Full", "value": "Full"},
                        {"key": "Selective", "value": "Selective"},
                    ],
                    "default": "Selective",
                    "mandatory": True,
                    "description": "Select type of isolation to perform.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Isolate device action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "undo_isolation":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Undo isolation action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "restrict_app_execution":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Restrict app execution action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "remove_app_restriction":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Remove app restriction action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "run_antivirus_scan":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Scan Type",
                    "key": "scan_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Quick", "value": "Quick"},
                        {"key": "Full", "value": "Full"},
                    ],
                    "default": "Quick",
                    "mandatory": True,
                    "description": "Select type of scan to perform.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Run antivirus scan action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "offboard_machine":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Offboard device action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

        elif action.value == "collect_investigation_package":
            return [
                {
                    "label": "Device ID/Computer DNS Name",
                    "key": "machine_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Device ID or Computer DNS Name of the device to perform the action on.",
                },
                {
                    "label": "Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "Collect investigation package action triggered by Netskope CE.",
                    "mandatory": True,
                    "description": "Add comment associated with the action.",
                }
            ]

    def execute_action(self, action: Action):
        """Execute action on the user.

        Args:
            action (Action): Action that needs to be perform on user.

        Returns:
            None
        """
        action_label = action.label
        action_parameters = action.parameters
        if action.value == "generate":
            return

        machine_id = action_parameters.get("machine_id", "").strip()
        if not machine_id:
            err_msg = (
                "Device ID/Computer DNS Name not found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return
        elif not isinstance(machine_id, str):
            err_msg = (
                "Invalid Device ID/Computer DNS Name found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return

        comment = action_parameters.get("comment", "").strip()
        if not comment:
            err_msg = (
                "Comment not found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' "
                f"for device '{machine_id}'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return
        elif not isinstance(comment, str):
            err_msg = (
                "Invalid comment found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' "
                f"for device '{machine_id}'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return
        elif len(comment) > 4000:
            err_msg = (
                "Comment is too long. "
                f"Hence, skipping execution of '{action_label}' "
                f"for device '{machine_id}'. "
                "Comment length should be less than 4000 characters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return

        self.logger.debug(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for device '{machine_id}'."
        )


        logger_msg = f"executing '{action_label}' action"
        headers = self.defender_endpoint_helper.get_auth_json(
            self.configuration,
            self.proxy,
            logger_msg
        )
        headers = self.get_headers(headers)

        log_msg = f"device '{machine_id}'"
        if action.value == "isolate_machine":
            try:
                isolation_type = action_parameters.get("isolation_type", "")
                log_msg += f" with isolation type '{isolation_type}'"
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="isolate",
                    comment=comment,
                    logger_msg=log_msg,
                    isolation_type=isolation_type,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while isolating device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "undo_isolation":
            try:
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="unisolate",
                    comment=comment,
                    logger_msg=log_msg,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while releasing isolation from device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "restrict_app_execution":
            try:
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="restrictCodeExecution",
                    comment=comment,
                    logger_msg=log_msg,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while restricting execution of all applications "
                    f"from device '{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "remove_app_restriction":
            try:
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="unrestrictCodeExecution",
                    comment=comment,
                    logger_msg=log_msg,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while removing application restriction from device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "run_antivirus_scan":
            try:
                scan_type = action_parameters.get("scan_type", "")
                log_msg += f" with scan type '{scan_type}'"
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="runAntiVirusScan",
                    comment=comment,
                    logger_msg=log_msg,
                    scan_type=scan_type,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while running antivirus scan on device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "offboard_machine":
            try:
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="offboard",
                    comment=comment,
                    logger_msg=log_msg,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while offboarding device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        elif action.value == "collect_investigation_package":
            try:
                self._trigger_action(
                    action_label=action_label,
                    machine_id=machine_id,
                    action_endpoint="collectInvestigationPackage",
                    comment=comment,
                    logger_msg=log_msg,
                    headers=headers
                )
            except Exception as err:
                err_msg = (
                    f"Error occurred while collecting investigation package on device "
                    f"'{machine_id}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Microsoft Defender Endpoint action configuration."""
        try:
            action_value = action.value
            action_params = action.parameters
            if action_value not in [
                "isolate_machine",
                "undo_isolation",
                "restrict_app_execution",
                "remove_app_restriction",
                "run_antivirus_scan",
                "offboard_machine",
                "collect_investigation_package",
                "generate"
            ]:
                return ValidationResult(
                    success=False, message="Unsupported action provided."
                )

            if action_value in ["generate"]:
                return ValidationResult(
                    success=True, message="Validation successful."
                )

            machine_id = action_params.get("machine_id", "")

            if not machine_id:
                err_msg = "Device ID/Computer DNS Name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(machine_id, str):
                err_msg = "Invalid Device ID/Computer DNS Name provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if action_value == "isolate_machine":
                if "$" in action_params.get("isolation_type", ""):
                    err_msg = (
                        "Isolation Type contains the Business Rule Record Field."
                        " Please select Isolation Type from Static Field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                elif action_params.get("isolation_type", "") not in [
                    "Full",
                    "Selective"
                ]:
                    err_msg = (
                        "Invalid Isolation Type provided. "
                        "Supported isolation types are: 'Full', 'Selective'"
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False, message=err_msg
                    )

            if action_value == "run_antivirus_scan":
                if "$" in action_params.get("scan_type", ""):
                    err_msg = (
                        "Scan Type contains the Business Rule Record Field."
                        " Please select Scan Type from Static Field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                elif action_params.get("scan_type", "") not in [
                    "Quick",
                    "Full"
                ]:
                    err_msg = (
                        "Invalid Scan Type provided. "
                        "Supported scan types are: 'Quick', 'Full'"
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False, message=err_msg
                    )

            comment = action_params.get("comment", "").strip()
            if not comment:
                err_msg = "Comment is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(comment, str):
                err_msg = "Invalid Comment provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except Exception as exp:
            self.logger.error(
                "{}: Exception Occurred in Validate Action. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderEndpointPluginException(traceback.format_exc())

    def get_headers(self, headers):
        """Get headers with additional fields.

        Args:
            headers (dict): Request headers

        Returns:
            headers: headers with additional fields.
        """
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "*/*"
        return headers

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:
            base_url (str): Base URL of Microsoft Defender Endpoint.
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
                                token.
            tenant_id (str): Tenant ID that user wants

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate base_url
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif base_url not in [
            "https://api.security.microsoft.com",
            "https://us.api.security.microsoft.com",
            "https://eu.api.security.microsoft.com",
            "https://uk.api.security.microsoft.com",
            "https://au.api.security.microsoft.com",
            "https://swa.api.security.microsoft.com",
            "https://api-gcc.securitycenter.microsoft.us",
            "https://api-gov.securitycenter.microsoft.us",
        ] or not isinstance(base_url, str):
            err_msg = (
                "Invalid Base URL value provided. "
                "Select value from the given options only."
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate tenant_id
        tenant_id = configuration.get("tenant_id", "").strip()
        if not tenant_id:
            err_msg = "Tenant ID is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(tenant_id, str):
            err_msg = "Invalid Tenant ID value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate client_id
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client (Application) ID is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_id, str):
            err_msg = "Invalid Client (Application) ID value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate client_secret
        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with Microsoft Defender Endpoint platform.

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
            isValid = False
            logger_msg = "validating authentication credentials"
            auth_token = self.defender_endpoint_helper.get_auth_json(
                configuration,
                self.proxy,
                logger_msg,
                True
            )

            alg = jwt.get_unverified_header(auth_token)["alg"]
            decoded_auth_token = jwt.decode(
                auth_token,
                algorithms=alg,
                options={"verify_signature": False},
            )
            roles = set(decoded_auth_token.get("roles", []))
            if ("Machine.ReadWrite.All" in roles or "Machine.Read.All" in roles) and "User.Read.All" in roles:
                isValid = True

            if isValid:
                headers = {
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                }

                # get the top 1 user from Microsoft Graph for checking
                # whether we are connected to the API
                base_url = configuration.get("base_url", "").strip("/")
                query_endpoint = f"{base_url}/api/machines?$top=1"

                self.defender_endpoint_helper.api_helper(
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"checking connectivity with {PLATFORM_NAME} platform",
                    is_validation=True,
                    regenerate_auth_token=False
                )

                return ValidationResult(
                    success=True,
                    message=(
                        "Validation successful for {} {} Plugin.".format(
                            MODULE_NAME, self.plugin_name
                        )
                    ),
                )
            else:
                err_msg = (
                    "Couldn't find required API permissions. "
                    "'Machine.Read.All' or 'Machine.ReadWrite.All' and 'User.Read.All'"
                    " permissions is required."
                )
                self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                    )
                raise MicrosoftDefenderEndpointPluginException(err_msg)

        except MicrosoftDefenderEndpointPluginException as exp:
            self.logger.error(
                message="{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))

        except Exception as exp:
            err_msg = "Validation error occurred while validating credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _fetch_users(
        self,
        device_id,
        base_url,
        headers
    ):
        self.logger.info(
            f"{self.log_prefix}: Fetching user(s) associated with device"
            f" '{device_id}' from {PLATFORM_NAME} platform."
        )
        user_list = []

        url = f"{base_url}/api/machines/{device_id}/logonusers"
        resp_json = self.defender_endpoint_helper.api_helper(
            url=url,
            method="GET",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=(
                f"fetching user(s) associated with device "
                f"'{device_id}' from {PLATFORM_NAME}"
            )
        )
        users = resp_json.get("value", [])

        if users:
            for user in users:
                user_fetched = {
                    "User ID": user.get("id", ""),
                    "User Name": user.get("accountName", ""),
                    "User Domain": user.get("accountDomain", ""),
                    "First Seen": (
                        datetime.datetime.strptime(
                            user.get("firstSeen", ""),
                            "%Y-%m-%dT%H:%M:%SZ"
                        )
                    ),
                    "Computer Name": device_id
                }
                user_list.append(user_fetched)

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(user_list)}"
                f" user(s) associated with device '{device_id}' from {PLATFORM_NAME} platform."
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: No user(s) associated with "
                f"device '{device_id}' are fetched from {PLATFORM_NAME} platform."
            )
        return user_list

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Microsoft Defender Endpoint.

        Returns:
            List: List of records to be stored on the platform.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching records from "
            f"{PLATFORM_NAME} platform."
        )
        base_url = self.configuration.get("base_url", DEFAULT_BASE_URL).strip("/")
        url = f"{base_url}/api/machines"

        logger_msg = "fetching records"
        total_records = []
        page_count = 1
        skip_count = 0
        entity_name = entity.lower()

        headers = self.defender_endpoint_helper.get_auth_json(
            self.configuration,
            self.proxy,
            logger_msg
        )
        headers = self.get_headers(headers)
        while True:
            try:
                self.logger.info(
                    f"{self.log_prefix}: Fetching {entity_name} for page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                params = {
                    "$top": PAGE_RECORD_SCORE,
                    "$skip": skip_count
                }
                resp_json = self.defender_endpoint_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"fetching {entity_name} for page {page_count} from {PLATFORM_NAME}",  # noqa
                )

                current_user_list = resp_json.get("value", [])
                current_user_count = len(current_user_list)

                # We get all the user id and store it in total user id list
                for each_user in current_user_list:
                    try:
                        if entity == "Devices":
                            currRecord = {
                                "Device ID": each_user.get("id", ""),
                                "Computer Name": each_user.get("computerDnsName", ""),
                                "OS": each_user.get("osPlatform", ""),
                                "Last IP Address": each_user.get("lastIpAddress", ""),
                                "Risk Score": each_user.get("riskScore", "")
                            }
                            total_records.append(currRecord)
                        elif entity == "Users":
                            device_id = each_user.get("computerDnsName", "")
                            currRecord = self._fetch_users(device_id, base_url, headers)
                            total_records.extend(currRecord)
                    except Exception as err:
                        self.logger.error(
                            message="{}: Skipping {} with id {}.".format(
                                self.log_prefix,
                                entity[:-1],
                                each_user.get("id", "Device ID Not Found."),
                            ),
                            details="Error Details: {}. \nRecord Data: {}".format(
                                err, each_user
                            ),
                        )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched {'user(s) from' if entity == 'Users' else ''} "
                    f"{current_user_count} device(s) in page {page_count}."
                    f" Total {entity_name} fetched: {len(total_records)}."
                )
                page_count += 1
                # if number of records is less than page size, we know that
                # this is the last page of the request. Hence, we break
                if current_user_count < int(PAGE_RECORD_SCORE):
                    break

                if not current_user_list:
                    break

                skip_count = skip_count + int(PAGE_RECORD_SCORE)
            except MicrosoftDefenderEndpointPluginException:
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
                raise MicrosoftDefenderEndpointPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_records)}"
            f" {entity_name} from {PLATFORM_NAME} platform."
        )
        return total_records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch devices scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        entity_name = entity.lower()
        if entity == "Users":
            self.logger.debug(
                f"{self.log_prefix}: No fields to update for"
                f" {entity_name} record(s) from {PLATFORM_NAME} platform."
            )
            return []

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)}"
            f" {entity_name} record(s) from {PLATFORM_NAME} platform."
        )
        base_url = self.configuration.get("base_url", DEFAULT_BASE_URL).strip("/")
        url = f"{base_url}/api/machines"

        logger_msg = f"updating {entity_name} records"
        score_users = {}
        page_count = 1
        skip_count = 0

        headers = self.defender_endpoint_helper.get_auth_json(
            self.configuration,
            self.proxy,
            logger_msg
        )
        headers = self.get_headers(headers)
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Updating records for {entity_name} in page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                params = {
                    "$top": PAGE_RECORD_SCORE,
                    "$skip": skip_count
                }
                resp_json = self.defender_endpoint_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"updating records for {entity_name} from {PLATFORM_NAME}",
                )

                current_user_list = resp_json.get("value", [])
                current_user_count = len(current_user_list)

                record_uid_list = []

                # store just emails in an array
                for record in records:
                    record_uid_list.append(record["Computer Name"])

                for each_user in current_user_list:
                    current_uid = each_user.get("computerDnsName", "")
                    if current_uid in record_uid_list:
                        current_score = each_user.get("riskScore", "")
                        # store email as key and score as value
                        score_users[current_uid] = current_score

                self.logger.debug(
                        f"{self.log_prefix}: Successfully updated records for "
                        f"{current_user_count} {entity_name} in page {page_count}."
                        f" Total record(s) updated: {len(score_users)}."
                    )
                page_count += 1

                if current_user_count < int(PAGE_RECORD_SCORE):
                    break

                if not current_user_list:
                    break

                skip_count = skip_count + int(PAGE_RECORD_SCORE)
            except MicrosoftDefenderEndpointPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Unexpected error occurred "
                    f"while updating records from {PLATFORM_NAME} "
                    f"platform. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftDefenderEndpointPluginException(err_msg)
        user_count = 0
        for record in records:
            try:
                if record["Computer Name"] in score_users:
                    record["Risk Score"] = score_users[record["Computer Name"]]

                    risk_level = record.get("Risk Score", "")
                    if (
                        risk_level == "None"
                        or risk_level == "Informational"
                    ):
                        record["Netskope Normalized Score"] = None
                    elif risk_level == "Low":
                        record["Netskope Normalized Score"] = 875
                    elif risk_level == "Medium":
                        record["Netskope Normalized Score"] = 625
                    elif risk_level == "High":
                        record["Netskope Normalized Score"] = 375
                    user_count += 1
                for k, v in list(record.items()):
                    if v is None:
                        record.pop(k)
            except Exception as error:
                self.logger.error(
                    message={
                        "{}: Error occurred while updating record"
                        " for device {}.".format(self.log_prefix, record["computerDnsName"])
                    },
                    details=f"Error details: {error}",
                )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{user_count} record(s) from {PLATFORM_NAME} platform."
        )
        return records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(name="Device ID", type=EntityFieldType.STRING),
                    EntityField(name="Computer Name", type=EntityFieldType.STRING, required=True),
                    EntityField(name="OS", type=EntityFieldType.STRING),
                    EntityField(name="Last IP Address", type=EntityFieldType.STRING),
                    EntityField(name="Risk Score", type=EntityFieldType.STRING),
                    EntityField(name="Netskope Normalized Score", type=EntityFieldType.NUMBER)
                ],
            ),
            Entity(
                name="Users",
                fields=[
                    EntityField(name="User ID", type=EntityFieldType.STRING, required=True),
                    EntityField(name="User Name", type=EntityFieldType.STRING),
                    EntityField(name="User Domain", type=EntityFieldType.STRING),
                    EntityField(name="First Seen", type=EntityFieldType.DATETIME),
                    EntityField(name="Computer Name", type=EntityFieldType.REFERENCE)
                ],
            )
        ]
