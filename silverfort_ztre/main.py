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

CRE Silverfort plugin.
"""

import traceback
from typing import List, Dict, Union, Callable
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
)
from .utils import constants as CONST
from .utils.helper import SilverfortPluginHelper, SilverfortPluginException


class SilverfortRiskPlugin(PluginBase):
    """CRE Silverfort Plugin."""

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
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.silverfort_helper = SilverfortPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = SilverfortRiskPlugin.metadata
            plugin_name = metadata_json.get("name", CONST.PLUGIN_NAME)
            plugin_version = metadata_json.get("version", CONST.PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        CONST.MODULE_NAME, CONST.PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [Entity(name="", fields=[])]

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
        check_dollar: bool = False,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str:
            field_value = field_value.strip()
        if check_dollar and "$" in field_value:
            err_msg = (
                f"{field_name} contains the Source Field"
                " hence validation for this field will be performed"
                " while executing the action."
            )
            self.logger.info(
                message=f"{self.log_prefix}: {err_msg}",
            )
            return
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if (
            is_required
            and not isinstance(field_value, field_type)
            or (
                custom_validation_func
                and not custom_validation_func(field_value)
            )
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            if len(allowed_values) <= 5:
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. Allowed values are"
                    f" {', '.join(value for value in allowed_values)}."
                )
            else:
                err_msg = (
                    f"Invalid value for '{field_name}' provided "
                    f"in the configuration parameters."
                )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        (
            instance_url,
            auth_id,
            webhook_id,
        ) = self.silverfort_helper.get_credentials(configuration)

        # Validate Base URL
        if validation_result := self._validate_configuration_parameters(
            field_name="Silverfort Base URL",
            field_value=instance_url,
            field_type=str,
            custom_validation_func=self.silverfort_helper.validate_url,
            is_required=True,
        ):
            return validation_result

        # Validate auth_id
        if validation_result := self._validate_configuration_parameters(
            field_name="Auth ID",
            field_value=auth_id,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate webhook_id
        if validation_result := self._validate_configuration_parameters(
            field_name="Webhook ID",
            field_value=webhook_id,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        return ValidationResult(
            success=True,
            message="Validation successful.",
        )

    def fetch_records(self, entity: Entity) -> List:
        """Pull Records from AWS Security Hub.

        Returns:
            List: List of records to be stored on the platform.
        """
        return []

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch device scores.

        Args:
            entity (str): Entity name.
            records (list[dict]): List of records.

        Returns:
            List: List of records with scores assigned.
        """
        return []

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Update Silverfort Risk",
                value="update_risk",
            ),
            ActionWithoutParams(
                label="No action",
                value="generate",
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            (list): Returns a list of details for UI to display Tiers.

        """
        if action.value in ["generate"]:
            return []
        if action.value == "update_risk":
            return [
                {
                    "label": "User Email",
                    "key": "email",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Email of the user whose risk Severity is to be"
                        " updated on Silverfort."
                    ),
                },
                {
                    "label": "Silverfort Risk Severity",
                    "key": "silverfort_risk",
                    "type": "choice",
                    "choices": [
                        {"key": "Low", "value": "low"},
                        {"key": "Medium", "value": "medium"},
                        {"key": "High", "value": "high"},
                        {"key": "Critical", "value": "critical"},
                    ],
                    "default": "low",
                    "mandatory": True,
                    "description": (
                        "Select the Risk Severity which is to be"
                        " updated on Silverfort."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Silverfort action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_params = action.parameters
        action_value = action.value
        if action_value not in CONST.SUPPORTED_ACTIONS:
            err_msg = "Unsupported action provided."
            return ValidationResult(success=False, message=err_msg)
        if action_value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        email = action_params.get("email", "").strip()

        # validate email
        if validation_result := self._validate_configuration_parameters(
            field_name="Email",
            field_value=email,
            field_type=str,
            custom_validation_func=self.silverfort_helper.validate_email,
            is_required=True,
            check_dollar=True,
        ):
            return validation_result

        # validate silverfort risk
        silverfort_risk = action_params.get("silverfort_risk", "")
        if validation_result := self._validate_configuration_parameters(
            field_name="Silverfort Risk",
            field_value=silverfort_risk,
            field_type=str,
            is_required=True,
            allowed_values=CONST.ALLOWED_RISK_VALUES,
            check_dollar=True,
        ):
            return validation_result

        self.logger.debug(f"{self.log_prefix}: Validation successful.")
        return ValidationResult(success=True, message="Validation successful.")

    def _execute_action_helper(
        self,
        action_params: dict,
    ):
        """Helper function to execute action."""

        (
            base_url,
            auth_id,
            webhook_id,
        ) = self.silverfort_helper.get_credentials(self.configuration)

        silverfort_risk = action_params.get("silverfort_risk", "")
        email = action_params.get("email", "").strip()
        url = CONST.RISK_ENDPOINT.format(
            base_url=base_url, webhook_id=webhook_id
        )

        headers = {
            "Authorization": auth_id,
            "Content-Type": "application/json",
        }

        data = {"riskLevel": silverfort_risk, "email": email}

        log_msg = f"Silverfort Risk for user: '{email}'"
        self.logger.info(f"{self.log_prefix}: Updating {log_msg}.")

        self.silverfort_helper.api_helper(
            method="POST",
            logger_msg=f"updating {log_msg}",
            url=url,
            headers=headers,
            json=data,
            verify=self.ssl_validation,
            proxies=self.proxy,
        )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"Silverfort Risk for user: '{email}'."
        )

    def execute_action(self, action: Action):
        """Execute action on the record.
        Args:
            action (Action): Action object having all
            the configurable parameters.
        """

        self.logger.info(
            f"{self.log_prefix}: Executing Silverfort Update Risk Action."
        )

        action_label = action.label
        action_params = action.parameters

        if action.value not in CONST.SUPPORTED_ACTIONS:
            self.logger.error(
                f"{self.log_prefix}: Unsupported action"
                f" provided: '{action.value}'"
            )
            return

        if action.value == "generate":
            self.logger.info(
                f'{self.log_prefix}: Successfully executed "{action_label}"'
                " action. Note: No processing will be done from plugin for "
                f'the "{action_label}" action.'
            )
            return

        try:
            self._execute_action_helper(
                action_params=action_params,
            )
        except SilverfortPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "{} {}: Unexpected Error occurred while"
                " updating silverfort risk. Error: {}".format(
                    CONST.MODULE_NAME, CONST.PLUGIN_NAME, exp
                )
            )
            self.silverfort_helper.handle_and_raise(
                message=err_msg,
                err=exp,
                details=traceback.format_exc(),
            )
