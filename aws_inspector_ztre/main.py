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

CRE AWS Inspector Plugin.
"""

import json
import re
import traceback
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Literal, Optional, Tuple, Union

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.client import AWSInspectorClient
from .utils.constants import (
    ACTION_CREATE_SUPPRESSION_RULE,
    ACTION_NO_OP,
    AUTHENTICATION_METHODS,
    ENRICHMENT_FIELD_MAPPING,
    BATCH_SIZE,
    DEFAULT_SUPPRESSION_REASON,
    DEFAULT_SUPPRESSION_RULE_NAME,
    EC2_RESOURCE_TYPE,
    ENRICHMENT_BATCH_SIZE,
    ENTITY_NAME,
    INSPECTOR_FINDING_ARN_PATTERN,
    LIST_FILTERS_MAX_RESULTS,
    MAX_INITIAL_RANGE_DAYS,
    MAX_SUPPRESSION_RULE_NAME_LENGTH,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    REGION_CHOICES,
    REGIONS,
    SOURCE_FIELD_PREFIX,
    SUPPRESSION_ACTION_VALUES,
    SUPPRESSION_FILTER_FIELD_CHOICES,
    SUPPRESSION_FILTER_FIELD_MAP,
    SUPPRESSION_FILTER_FIELD_VALUES,
    USER_AGENT,
)

from .utils.exceptions import AWSInspectorException
from .utils.helper import AWSInspectorPluginHelper
from .utils.validator import AWSInspectorValidator

_INSPECTOR_FINDING_ARN_RE = re.compile(INSPECTOR_FINDING_ARN_PATTERN)


class AWSInspectorPlugin(PluginBase):
    """AWS Inspector CRE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Init.

        Args:
            name (str): Configuration name from CE.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.aws_inspector_helper = AWSInspectorPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Read plugin name + version from manifest.json metadata.

        Returns:
            tuple: Plugin name and version (plugin_name, plugin_version).
        """
        try:
            manifest_json = AWSInspectorPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLATFORM_NAME, PLUGIN_VERSION

    def get_dynamic_fields(self):
        """Get the dynamic fields from plugin."""
        authentication_method = self.configuration.get(
            "authentication_method", None
        )
        if (
            authentication_method
            and authentication_method == "aws_iam_roles_anywhere"
        ):
            return [
                {
                    "label": "Private Key",
                    "key": "private_key_file",
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Private Key for decrypting the AWS Private CA"
                        " Certificate. Required for 'AWS IAM Roles"
                        " Anywhere' authentication type."
                    ),
                },
                {
                    "label": "Certificate Body",
                    "key": "public_certificate_file",
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Certificate Body for AWS Public/Private CA"
                        " Certificate. Required for 'AWS IAM Roles"
                        " Anywhere' authentication type."
                    ),
                },
                {
                    "label": "Password Phrase",
                    "key": "pass_phrase",
                    "type": "password",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Password Phrase for decrypting the CA Certificate."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication type."
                    ),
                },
                {
                    "label": "Profile ARN",
                    "key": "profile_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "AWS Profile ARN for AWS client authentication."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication type."
                    ),
                },
                {
                    "label": "Role ARN",
                    "key": "role_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "AWS Role ARN for AWS client authentication."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication type."
                    ),
                },
                {
                    "label": "Trust Anchor ARN",
                    "key": "trust_anchor_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "AWS Trust Anchor ARN for AWS client authentication."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication type."
                    ),
                },
                {
                    "label": "AWS Region Name",
                    "key": "region_name",
                    "type": "choice",
                    "choices": REGION_CHOICES,
                    "default": "us-east-1",
                    "mandatory": True,
                    "description": (
                        "AWS Region in which AWS Inspector is enabled."
                        " Ensure that the region matches the region in"
                        " the Profile ARN and Trust Anchor ARN."
                    ),
                },
                {
                    "label": "Initial Range (in days)",
                    "key": "days",
                    "type": "number",
                    "mandatory": True,
                    "default": 7,
                    "description": (
                        "Number of days to pull the data for the initial"
                        f" run. Value must be in range of 1 to"
                        f" {MAX_INITIAL_RANGE_DAYS}."
                    ),
                },
            ]
        else:
            return [
                {
                    "label": "AWS Region Name",
                    "key": "region_name",
                    "type": "choice",
                    "choices": REGION_CHOICES,
                    "default": "us-east-1",
                    "mandatory": True,
                    "description": (
                        "AWS Region in which AWS Inspector is enabled."
                        " Ensure that the region matches the region in"
                        " the Profile ARN and Trust Anchor ARN when"
                        " 'AWS IAM Roles Anywhere' authentication method"
                        " is selected."
                    ),
                },
                {
                    "label": "Initial Range (in days)",
                    "key": "days",
                    "type": "number",
                    "mandatory": True,
                    "default": 7,
                    "description": (
                        "Number of days to pull the data for the initial"
                        f" run. Value must be in range of 1 to"
                        f" {MAX_INITIAL_RANGE_DAYS}."
                    ),
                },
            ]

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: List of supported actions.
        """
        return [
            ActionWithoutParams(label="No actions", value=ACTION_NO_OP),
            ActionWithoutParams(
                label="Create Suppression Rule",
                value=ACTION_CREATE_SUPPRESSION_RULE,
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get action parameters for the given action.

        Args:
            action (Action): Action object.

        Returns:
            list: List of action parameter configurations.
        """
        if action.value == ACTION_NO_OP:
            return []
        if action.value == ACTION_CREATE_SUPPRESSION_RULE:
            return [
                {
                    "label": "Rule Name",
                    "key": "rule_name",
                    "type": "text",
                    "default": DEFAULT_SUPPRESSION_RULE_NAME,
                    "mandatory": True,
                    "description": (
                        "Name of the Suppression rule to create in "
                        "AWS Inspector. Provide rule name in Static field."
                        f" Maximum {MAX_SUPPRESSION_RULE_NAME_LENGTH}"
                        " characters are allowed."
                    ),
                },
                {
                    "label": "Rule Description",
                    "key": "rule_description",
                    "type": "text",
                    "default": DEFAULT_SUPPRESSION_REASON,
                    "mandatory": False,
                    "description": (
                        "Description for Suppression rule."
                        " Provide description in Static field."
                        f" Maximum {MAX_SUPPRESSION_RULE_NAME_LENGTH}"
                        " characters are allowed."
                    ),
                },
                {
                    "label": "Filter Key",
                    "key": "rule_filter",
                    "type": "choice",
                    "choices": SUPPRESSION_FILTER_FIELD_CHOICES,
                    "default": "finding_arn",
                    "mandatory": True,
                    "description": (
                        "AWS Inspector field to use as the suppression"
                        " filter criteria. Select from Static field"
                        " dropdown."
                    ),
                },
                {
                    "label": "Filter Value",
                    "key": "filter_value",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Value to match for the selected filter field. "
                        "Map to a source field or"
                        " provide a static value."
                    ),
                },
            ]
        return []

    def _validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: Literal["configuration", "action"],
        allowed_values=None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred.",
        check_dollar: bool = False,
        is_source_field_allowed: bool = True,
        min_value: Optional[Union[int, float]] = None,
        max_value: Optional[Union[int, float]] = None,
    ) -> Union[ValidationResult, None]:
        """Validate a single configuration or action parameter.

        Args:
            field_name (str): Human-readable parameter name shown in messages.
            field_value: Raw parameter value to validate.
            field_type (type): Expected Python type.
            parameter_type (str): "configuration" or "action".
            allowed_values: Optional collection of valid values.
            custom_validation_func (Callable, optional): Extra validation;
                called with field_value and should return bool.
            is_required (bool): Whether an empty/missing value is an error.
            validation_err_msg (str): Prefix prepended to every error message.
            check_dollar (bool): When True, skip deep validation if the value
                still looks like an unresolved source field ("$...").
            is_source_field_allowed (bool): When False, reject "$..." values.
            min_value (int | float, optional): Inclusive lower bound for
                numeric fields. Checked only when field_value is numeric.
            max_value (int | float, optional): Inclusive upper bound for
                numeric fields. Checked only when field_value is numeric.

        Returns:
            ValidationResult if validation fails, None if it passes.
        """
        if (
            not is_source_field_allowed
            and isinstance(field_value, str)
            and field_value.strip().startswith("$")
        ):
            err_msg = (
                f"'{field_name}' can only contain the Static Field."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that Static is selected for the '{field_name}'"
                    " field in the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        # CE delivers number-type fields as float; cast to int so that
        # isinstance checks and range comparisons work correctly.
        if field_type is int and isinstance(field_value, float):
            field_value = int(field_value)

        if (
            check_dollar
            and isinstance(field_value, str)
            and field_value.startswith("$")
        ):
            self.logger.info(
                f"{self.log_prefix}: '{field_name}' contains the Source Field"
                " hence validation for this field will be performed"
                " while executing the action."
            )
            return None

        if (
            is_required
            and not isinstance(field_value, (int, float))
            and not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required {parameter_type} parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Provide a valid value for the '{field_name}'"
                    f" {parameter_type} parameter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that a valid {field_type.__name__} value is"
                    f" provided for '{field_name}'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if custom_validation_func and not custom_validation_func(field_value):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that a valid value is provided for"
                    f" '{field_name}'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values and isinstance(field_value, str):
            if field_value not in allowed_values:
                if len(allowed_values) <= 5:
                    err_msg = (
                        f"Invalid value provided for the {parameter_type}"
                        f" parameter '{field_name}'. Allowed values are:"
                        f" {', '.join(str(v) for v in allowed_values)}."
                    )
                else:
                    err_msg = (
                        f"Invalid value provided for the {parameter_type}"
                        f" parameter '{field_name}'."
                    )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    ),
                    resolution=(
                        f"Select a valid value for '{field_name}' from the"
                        " available options."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        if (
            (min_value is not None or max_value is not None)
            and isinstance(field_value, (int, float))
        ):
            out_of_range = (
                (min_value is not None and field_value < min_value)
                or (max_value is not None and field_value > max_value)
            )
            if out_of_range:
                low = min_value if min_value is not None else ""
                high = max_value if max_value is not None else ""
                err_msg = (
                    f"Invalid value provided for the {parameter_type}"
                    f" parameter '{field_name}'. Value must be in"
                    f" range of {low} to {high}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    ),
                    resolution=(
                        f"Provide a value between {low} and {high}"
                        f" for '{field_name}'."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        return None

    def validate_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate action configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """
        if action.value == ACTION_NO_OP:
            return ValidationResult(
                success=True, message="Validation successful."
            )

        if action.value not in SUPPRESSION_ACTION_VALUES:
            err_msg = (
                f"Unsupported action '{action.value}' provided in"
                " the action configuration. Supported actions are:"
                " 'No actions' and 'Create Suppression Rule'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select a valid action from the list of supported"
                    " actions in the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        params = action.parameters or {}
        validation_err_msg = "Validation error occurred."

        rule_name = params.get("rule_name") or ""
        if validation_result := self._validate_parameters(
            field_name="Rule Name",
            field_value=rule_name,
            field_type=str,
            parameter_type="action",
            is_required=True,
            is_source_field_allowed=False,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result
        if len(rule_name.strip()) > MAX_SUPPRESSION_RULE_NAME_LENGTH:
            err_msg = (
                f"'Rule Name' must not exceed"
                f" {MAX_SUPPRESSION_RULE_NAME_LENGTH} characters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that the 'Rule Name' value does not exceed"
                    f" {MAX_SUPPRESSION_RULE_NAME_LENGTH} characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        rule_description = params.get("rule_description") or ""
        if validation_result := self._validate_parameters(
            field_name="Rule Description",
            field_value=rule_description,
            field_type=str,
            parameter_type="action",
            is_required=False,
            is_source_field_allowed=False,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        if len(rule_description.strip()) > MAX_SUPPRESSION_RULE_NAME_LENGTH:
            err_msg = (
                f"'Rule Description' must not exceed"
                f" {MAX_SUPPRESSION_RULE_NAME_LENGTH} characters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that the 'Rule Description' value does not exceed"
                    f" {MAX_SUPPRESSION_RULE_NAME_LENGTH} characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        rule_filter = params.get("rule_filter") or ""
        if validation_result := self._validate_parameters(
            field_name="Filter Key",
            field_value=rule_filter,
            field_type=str,
            parameter_type="action",
            is_required=True,
            is_source_field_allowed=False,
            allowed_values=SUPPRESSION_FILTER_FIELD_VALUES,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        filter_value = params.get("filter_value") or ""
        if validation_result := self._validate_parameters(
            field_name="Filter Value",
            field_value=filter_value,
            field_type=str,
            parameter_type="action",
            is_required=True,
            check_dollar=True,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def execute_actions(self, actions: List[Action]):
        """Execute bulk actions.

        Args:
            actions (List[Action]): List of Action objects.

        Returns:
            ActionResult: Result of the bulk action execution.
        """
        if not actions:
            return ActionResult(
                success=True,
                message="No actions to execute.",
                failed_action_ids=[],
            )

        first_action_params = actions[0].get("params", {})
        action_value = first_action_params.value
        action_label = first_action_params.label

        if action_value == ACTION_NO_OP:
            self.logger.debug(
                f"{self.log_prefix}: Skipping 'No actions' for "
                f"{len(actions)} record(s)."
            )
            return ActionResult(
                success=True,
                message="No action performed.",
                failed_action_ids=[],
            )

        if action_value not in SUPPRESSION_ACTION_VALUES:
            err_msg = (
                f"Unsupported action '{action_value}' provided"
                " in the action configuration. Supported actions are:"
                " 'No actions' and 'Create Suppression Rule'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the action is selected from the list"
                    " of supported actions in the action configuration."
                ),
            )
            raise AWSInspectorException(err_msg)

        return self._execute_create_suppression_rules(
            actions=actions,
            action_label=action_label,
        )

    # ------------------------------------------------------------------
    # Suppression action helpers
    # ------------------------------------------------------------------
    def _extract_action_params(
        self, action_dict: dict
    ) -> Tuple[dict, Optional[str]]:
        """Extract parameters dict and action ID from a CE action dict.

        Args:
            action_dict (dict): CE action dict with 'params' and 'id' keys.

        Returns:
            Tuple[dict, Optional[str]]: (parameters dict, action id or None)
        """
        params = action_dict.get("params", {}).parameters or {}
        act_id = action_dict.get("id")
        return params, act_id

    @staticmethod
    def _coerce_param(value) -> str:
        """Coerce a CE parameter value to a plain string.

        CE resolves source fields (e.g. '$Finding ID') to their actual
        value at execution time, which may arrive as a list rather than a
        scalar string. This helper normalises both cases so the rest of the
        action code can always work with a plain str.

        Args:
            value: Raw parameter value (str, list, or None).

        Returns:
            str: First non-empty element if value is a list, otherwise
                 str(value).strip(). Returns "" for None / empty input.
        """
        if value is None:
            return ""
        if isinstance(value, list):
            for item in value:
                coerced = str(item).strip() if item is not None else ""
                if coerced:
                    return coerced
            return ""
        return str(value).strip()

    def _get_action_params(self, action_dict: dict) -> dict:
        """Extract parameters dict from a CE action dict.

        Args:
            action_dict (dict): CE action dict with 'params' key.

        Returns:
            dict: Parameters dictionary.
        """
        params, _ = self._extract_action_params(action_dict)
        return params

    def _execute_create_suppression_rules(
        self, actions: List, action_label: str
    ) -> ActionResult:
        """Execute Create Suppression Rule for each record individually.

        Each record is processed on its own. A rule is created only when
        no existing filter with the same name AND same criteria is found.
        Records with the same rule name but different filter criteria each
        attempt their own CreateFilter call; if the name is already taken by
        a different criteria, that record is skipped with a warning.

        Args:
            actions (List): CE action dicts from execute_actions.
            action_label (str): Human-readable action label for logging.

        Returns:
            ActionResult: Result with any failed action IDs.
        """
        inspector_client = self._get_inspector_client()
        failed_action_ids: List = []
        created = 0
        skipped = 0

        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"on {len(actions)} record(s)."
        )

        for action_dict in actions:
            params, act_id = self._extract_action_params(action_dict)
            rule_name = self._coerce_param(params.get("rule_name"))
            rule_filter = self._coerce_param(params.get("rule_filter"))
            filter_value = self._coerce_param(params.get("filter_value"))
            reason = self._coerce_param(params.get("rule_description"))

            if not rule_name or not rule_filter:
                self.logger.debug(
                    f"{self.log_prefix}: Skipping record. 'Rule Name' or"
                    " 'Filter Key' is empty."
                )
                if act_id:
                    failed_action_ids.append(act_id)
                continue

            if (
                not filter_value
                or filter_value.startswith(SOURCE_FIELD_PREFIX)
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping record for rule"
                        f" '{rule_name}'. 'Filter Value' is empty or an"
                        " unresolved source field."
                    ),
                    resolution=(
                        "Ensure the 'Filter Value' action parameter is"
                        " mapped to a source field that resolves to a"
                        " non-empty value at execution time."
                    ),
                )
                if act_id:
                    failed_action_ids.append(act_id)
                continue

            try:
                outcome = self._execute_create_suppression_rule(
                    inspector_client=inspector_client,
                    rule_name=rule_name,
                    rule_filter=rule_filter,
                    filter_value=filter_value,
                    reason=reason,
                )
                if outcome == "created":
                    created += 1
                else:
                    skipped += 1
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to perform"
                        f" '{action_label}' action for rule '{rule_name}'"
                        f" on record '{act_id}'. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                    resolution=(
                        "Ensure that the AWS credentials have "
                        "inspector2:CreateFilter and "
                        "inspector2:ListFilters permissions."
                    ),
                )
                if act_id:
                    failed_action_ids.append(act_id)

        self.logger.info(
            f"{self.log_prefix}: Successfully executed '{action_label}' "
            f"action. {created} rule(s) created, {skipped} rule(s) skipped"
            f" as rule already exists, {len(failed_action_ids)} failed."
        )
        return ActionResult(
            success=len(failed_action_ids) == 0,
            message=(
                f"Processed {len(actions)} record(s): "
                f"{created} created, {skipped} skipped, "
                f"{len(failed_action_ids)} failed."
            ),
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _build_single_criterion(self, filter_type: str, value: str) -> dict:
        """Convert a raw string value into one Inspector filter entry.

        Args:
            filter_type (str): One of string, map, number, port.
            value (str): Raw user-provided value.

        Returns:
            dict: Inspector filter criterion dict.

        Raises:
            AWSInspectorException: When the value format is invalid.
        """
        if filter_type == "string":
            return {"comparison": "EQUALS", "value": value}

        if filter_type == "map":
            if ":" not in value:
                err_msg = (
                    f"Resource Tag filter value '{value}' must be in"
                    " 'key:value' format, e.g. 'env:prod'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide the 'Filter Value' in 'key:value' format"
                        " when using the 'Resource Tag' filter field."
                    ),
                )
                raise AWSInspectorException(err_msg)
            k, _, v = value.partition(":")
            return {
                "comparison": "EQUALS",
                "key": k.strip(),
                "value": v.strip(),
            }

        if filter_type == "number":
            parts = value.split("-")
            try:
                low = float(parts[0].strip())
                high = float(parts[1].strip()) if len(parts) == 2 else low
            except (ValueError, IndexError):
                err_msg = (
                    f"Inspector Score filter value '{value}' must be a"
                    " number or a range in 'low-high' format, e.g."
                    " '7.0-10.0'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide the 'Filter Value' as a single number or"
                        " a 'low-high' range when using the 'Inspector"
                        " Score' filter field."
                    ),
                )
                raise AWSInspectorException(err_msg)
            return {"lowerInclusive": low, "upperInclusive": high}

        if filter_type == "port":
            parts = value.split("-")
            try:
                begin = int(parts[0].strip())
                end = int(parts[1].strip()) if len(parts) == 2 else begin
            except (ValueError, IndexError):
                err_msg = (
                    f"Open Port filter value '{value}' must be a port"
                    " number."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide the 'Filter Value' as a single port."
                    ),
                )
                raise AWSInspectorException(err_msg)
            return {"beginInclusive": begin, "endInclusive": end}

        err_msg = f"Unknown filter type '{filter_type}'."
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=(
                "Select a valid Filter Key from the action configuration"
                " dropdown."
            ),
        )
        raise AWSInspectorException(err_msg)

    def _build_suppression_criteria(
        self, filter_field: str, filter_type: str, values: List[str]
    ) -> dict:
        """Build the Inspector filterCriteria dict for create_filter.

        Args:
            filter_field (str): Inspector filterCriteria key.
            filter_type (str): Entry type: string, map, number, or port.
            values (List[str]): Unique resolved filter values.

        Returns:
            dict: filterCriteria payload ready for the AWS API.

        Raises:
            AWSInspectorException: When values list is empty.
        """
        if not values:
            err_msg = (
                f"No resolved filter values provided for Inspector"
                f" field '{filter_field}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure the 'Filter Value' action parameter have"
                    " a non-empty value before the action executes."
                ),
            )
            raise AWSInspectorException(err_msg)
        criteria_entries = []
        for v in values:
            criteria_entries.append(
                self._build_single_criterion(filter_type, v)
            )
        return {filter_field: criteria_entries}

    def _execute_create_suppression_rule(
        self,
        inspector_client,
        rule_name: str,
        rule_filter: str,
        filter_value: str,
        reason: str = "",
    ) -> str:
        """Build filterCriteria for a single record and create the rule in AWS.

        Args:
            inspector_client: Boto3 inspector2 client.
            rule_name (str): Name for the SUPPRESS filter.
            rule_filter (str): Filter field key from
                SUPPRESSION_FILTER_FIELD_MAP.
            filter_value (str): Single resolved filter value for this record.
            reason (str): Optional suppression reason / description.

        Returns:
            str: "created" if a new rule was created, "skipped" otherwise.
        """
        field_meta = SUPPRESSION_FILTER_FIELD_MAP.get(rule_filter)
        if not field_meta:
            err_msg = (
                f"Unknown Filter Key '{rule_filter}'. Cannot create"
                " suppression criteria."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select a valid Filter Key from the action"
                    " configuration dropdown."
                ),
            )
            raise AWSInspectorException(err_msg)
        filter_field = field_meta["key"]
        filter_type = field_meta["type"]

        criteria = self._build_suppression_criteria(
            filter_field, filter_type, [filter_value]
        )
        success, result = self._create_suppression_rule(
            inspector_client,
            rule_name=rule_name,
            criteria=criteria,
            reason=reason,
        )

        if success and result and result.startswith("arn:"):
            self.logger.info(
                f"{self.log_prefix}: Successfully created suppression rule"
                f" '{rule_name}' using filter key '{rule_filter}' with"
                f" value '{filter_value}'."
            )
            return "created"
        return "skipped"

    @staticmethod
    def _criteria_to_canonical_json(criteria: dict) -> str:
        """Serialize filterCriteria to a canonical JSON string for comparison.
        Args:
            criteria (dict): Filter criteria dictionary to serialize.

        Returns:
            str: Canonical JSON string representation of criteria.
        """
        canonical = {}
        for key in sorted(criteria.keys()):
            entries = criteria.get(key)
            if isinstance(entries, list):
                canonical[key] = sorted(
                    [
                        json.dumps(e, sort_keys=True, default=str)
                        for e in entries
                    ]
                )
            else:
                canonical[key] = json.dumps(
                    entries, sort_keys=True, default=str
                )
        return json.dumps(canonical, sort_keys=True)

    def _find_existing_rule(
        self, inspector_client, rule_name: str, criteria: dict
    ) -> Tuple[Optional[str], str]:
        """Check if an identical rule (same name AND criteria) already exists.

        Only an exact match on both name AND criteria causes a skip.
        A rule with the same name but different criteria is treated as
        'none' so that creation is permitted — each unique criteria set
        produces its own suppression filter even when names are shared.

        Args:
            inspector_client: Boto3 inspector2 client.
            rule_name (str): Name of the rule to check.
            criteria (dict): Filter criteria to search for.

        Returns:
            Tuple[Optional[str], str]: (existing_rule_name, match_type)
                - match_type: 'name_and_criteria' or 'none'
        """
        target_json = self._criteria_to_canonical_json(criteria)
        next_token = None

        try:
            while True:
                kwargs = {
                    "action": "SUPPRESS",
                    "maxResults": LIST_FILTERS_MAX_RESULTS,
                }
                if next_token:
                    kwargs["nextToken"] = next_token
                response = inspector_client.list_filters(**kwargs)
                for f in response.get("filters", []) or []:
                    existing_name = f.get("name", "")
                    if existing_name != rule_name:
                        continue
                    existing_json = self._criteria_to_canonical_json(
                        f.get("criteria") or {}
                    )
                    if existing_json == target_json:
                        return existing_name, "name_and_criteria"

                next_token = response.get("nextToken")
                if not next_token:
                    break

            return None, "none"

        except ClientError as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not list existing "
                    f"suppression filters for duplicate check. "
                    f"Error: {exp}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the credentials have "
                    "inspector2:ListFilters permission."
                ),
            )
            return None, "none"

    def _create_suppression_rule(
        self,
        inspector_client,
        rule_name: str,
        criteria: dict,
        reason: str,
    ) -> Tuple[bool, str]:
        """Create a SUPPRESS filter in AWS Inspector.

        Skips creation only when a rule with the same name AND same criteria
        already exists. All other cases proceed to CreateFilter.

        Args:
            inspector_client: Boto3 inspector2 client.
            rule_name (str): Name for the new filter.
            criteria (dict): filterCriteria payload for the AWS API.
            reason (str): Free-text suppression reason.

        Returns:
            Tuple[bool, str]: (success, filter_arn_or_name).

        Raises:
            AWSInspectorException: When the AWS API call fails.
        """
        existing_rule_name, match_type = self._find_existing_rule(
            inspector_client, rule_name, criteria
        )

        if match_type == "name_and_criteria":
            self.logger.debug(
                f"{self.log_prefix}: Suppression rule '{existing_rule_name}'"
                " already exists with same name and filter criteria."
                " Skipping to create Suppression rule."
            )
            return True, existing_rule_name

        try:
            kwargs: dict = {
                "name": rule_name,
                "action": "SUPPRESS",
                "filterCriteria": criteria,
            }
            if reason:
                kwargs["description"] = reason
            response = inspector_client.create_filter(**kwargs)
            arn = response.get("arn", "")
            return True, arn
        except ClientError as exp:
            err_msg = (
                f"AWS API error while creating suppression rule "
                f"'{rule_name}': {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Common causes are missing inspector2:CreateFilter"
                    " IAM permission or"
                    " the filter criteria value"
                    " violates AWS Inspector schema constraints."
                ),
            )
            raise AWSInspectorException(err_msg)

    # ------------------------------------------------------------------
    # Configuration validation
    # ------------------------------------------------------------------
    def _validate_auth_params(
        self, configuration, user_agent, validation_err_msg
    ):
        """Run the credential resolution path end-to-end as a smoke test.

        Args:
            configuration (dict): Plugin configuration parameters.
            user_agent (str): User agent string for AWS API calls.
            validation_err_msg (str): Error message prefix.

        Returns:
            tuple: (success: bool, message: str) indicating validation result.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating authentication parameters."
            )
            aws_client = AWSInspectorClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_validator = AWSInspectorValidator(
                configuration.get("region_name", "").strip(),
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
            inspector_client = aws_client.get_aws_inspector_client()
            aws_validator.validate_aws_inspector(inspector_client)
            return True, "success"
        except AWSInspectorException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Verify the authentication parameters and ensure "
                    "the IAM role has inspector2:ListFindings "
                    "permission in the configured region."
                ),
            )
            return False, str(exp)
        except Exception as exp:
            error_msg = (
                "Invalid authentication parameters provided. "
                "Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Verify the authentication parameters; for IAM "
                    "Roles Anywhere ensure the Profile / Role / "
                    "Trust Anchor ARNs and certificate are valid."
                ),
            )
            return False, error_msg

    def validate(self, configuration) -> ValidationResult:
        """Validate the plugin configuration before saving it.

        Args:
            configuration (dict): Plugin configuration parameters to validate.

        Returns:
            ValidationResult: Validation result with status and message.
        """
        validation_err_msg = "Validation error occurred."
        user_agent = USER_AGENT

        authentication_method = configuration.get(
            "authentication_method", ""
        )
        if validation_result := self._validate_parameters(
            field_name="Authentication Method",
            field_value=authentication_method,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            allowed_values=AUTHENTICATION_METHODS,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result
        authentication_method = authentication_method.strip()

        if authentication_method == "aws_iam_roles_anywhere":
            validation = self._validate_iam_roles_anywhere_params(
                configuration, validation_err_msg
            )
            if validation is not None:
                return validation

        # Region
        region_name = configuration.get("region_name", "")
        if validation_result := self._validate_parameters(
            field_name="AWS Region Name",
            field_value=region_name,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            allowed_values=REGIONS,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        # Initial range
        days = configuration.get("days")
        if validation_result := self._validate_parameters(
            field_name="Initial Range",
            field_value=days,
            field_type=int,
            parameter_type="configuration",
            is_required=True,
            min_value=1,
            max_value=MAX_INITIAL_RANGE_DAYS,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        success, message = self._validate_auth_params(
            configuration, user_agent, validation_err_msg
        )
        if not success:
            return ValidationResult(success=False, message=f"{message}")

        validation_msg = "Successfully validated configuration parameters."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(success=True, message=validation_msg)

    def _validate_iam_roles_anywhere_params(
        self, configuration, validation_err_msg
    ):
        """Validate fields that are only required for IAM Roles Anywhere.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Error message prefix.

        Returns:
            ValidationResult: Validation result if fails, None if successful.
        """
        pass_phrase = configuration.get("pass_phrase")
        if validation_result := self._validate_parameters(
            field_name="Password Phrase",
            field_value=pass_phrase,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        private_key_file = configuration.get("private_key_file", "")
        if validation_result := self._validate_parameters(
            field_name="Private Key",
            field_value=private_key_file,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result
        private_key_file = private_key_file.strip()
        try:
            serialization.load_pem_private_key(
                private_key_file.encode("utf-8"), None
            )
        except Exception:
            try:
                serialization.load_pem_private_key(
                    private_key_file.encode("utf-8"),
                    password=str.encode(pass_phrase),
                )
            except Exception:
                err_msg = (
                    "Invalid Private Key or Password Phrase provided."
                    " Verify that the Private Key is in valid pem format"
                    " and the Password Phrase is correct."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    ),
                    resolution=(
                        "Provide a valid Private Key and Password Phrase. "
                        "Private Key should be in a valid pem format."
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)

        public_certificate_file = configuration.get(
            "public_certificate_file", ""
        )
        if validation_result := self._validate_parameters(
            field_name="Certificate Body",
            field_value=public_certificate_file,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result
        public_certificate_file = public_certificate_file.strip()
        try:
            x509.load_pem_x509_certificate(public_certificate_file.encode())
        except Exception:
            err_msg = (
                "Invalid Certificate Body provided. Certificate Body should"
                " be in valid pem format."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    "Provide a valid Certificate Body in pem format."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

        for label, key in (
            ("Profile ARN", "profile_arn"),
            ("Role ARN", "role_arn"),
            ("Trust Anchor ARN", "trust_anchor_arn"),
        ):
            value = configuration.get(key, "")
            if validation_result := self._validate_parameters(
                field_name=label,
                field_value=value,
                field_type=str,
                parameter_type="configuration",
                is_required=True,
                validation_err_msg=validation_err_msg,
            ):
                return validation_result

        return None

    # ------------------------------------------------------------------
    # Inspector client helpers
    # ------------------------------------------------------------------
    def _get_inspector_client(self):
        """Resolve credentials and return an inspector2 boto3 client.

        Returns:
            boto3.client: Configured AWS Inspector client.
        """
        aws_client = AWSInspectorClient(
            self.configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            USER_AGENT,
        )
        aws_client.set_credentials()
        return aws_client.get_aws_inspector_client()

    def _build_filter_criteria(self, start_time, end_time) -> dict:
        """Build the filterCriteria block for list_findings.

        Args:
            start_time (datetime): Start time for filtering findings.
            end_time (datetime): End time for filtering findings.

        Returns:
            dict: Filter criteria dictionary for AWS Inspector API.
        """
        criteria = {
            "resourceType": [
                {"comparison": "EQUALS", "value": EC2_RESOURCE_TYPE}
            ],
            "updatedAt": [
                {
                    "startInclusive": start_time,
                    "endInclusive": end_time,
                }
            ],
            "findingStatus": [
                {
                    "comparison": "EQUALS", "value": "ACTIVE"
                }
            ]
        }
        return criteria

    # ------------------------------------------------------------------
    # Fetch
    # ------------------------------------------------------------------
    def _list_inspector_findings(self, start_time, end_time) -> list:
        """Page through Inspector list_findings and build CRE records.

        Args:
            start_time (datetime): Start time for filtering findings.
            end_time (datetime): End time for filtering findings.

        Returns:
            list: List of workload records extracted from Inspector findings.
        """
        inspector_client = self._get_inspector_client()

        records = []
        page_count = 1
        skip_count = 0
        next_token = None

        params = {
            "filterCriteria": self._build_filter_criteria(
                start_time, end_time
            ),
            "sortCriteria": {
                "field": "LAST_OBSERVED_AT",
                "sortOrder": "ASC",
            },
            "maxResults": BATCH_SIZE,
        }

        while True:
            try:
                if next_token:
                    params["nextToken"] = next_token

                self.logger.debug(
                    f"{self.log_prefix}: Fetching workload record(s)"
                    f" for page {page_count}."
                )
                response = inspector_client.list_findings(**params)
                page_findings = response.get("findings", []) or []

                page_records_count = 0
                page_skip_count = 0
                for finding in page_findings:
                    try:
                        extracted = (
                            self.aws_inspector_helper
                            .extract_records_from_finding(finding)
                        )
                        if extracted:
                            records.extend(extracted)
                            page_records_count += len(extracted)
                        else:
                            page_skip_count += 1
                    except Exception as err:
                        finding_arn = finding.get("findingArn", "")
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unable to extract"
                                f" fields from finding record with ARN"
                                f" '{finding_arn}' in page {page_count}."
                                f" Error: {err}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        page_skip_count += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {page_records_count} workload record(s)"
                    + (
                        (
                            f" ,skipped {page_skip_count} finding record(s)"
                            " as they did not contain valid EC2 resource"
                            f" information. in page {page_count}."
                            f" Total workload record(s): {len(records)}."
                        )
                        if page_skip_count > 0
                        else (
                            f" in page {page_count}. "
                            f"Total workload record(s): {len(records)}."
                        )
                    )
                )

                page_count += 1
                skip_count += page_skip_count

                next_token = response.get("nextToken")
                if not next_token or len(page_findings) < BATCH_SIZE:
                    break
            except AWSInspectorException:
                raise
            except Exception as exp:
                error_message = (
                    "Unexpected error occurred while fetching"
                    f" workload record(s) for page {page_count}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                    resolution=(
                        "Ensure that the AWS EC2 Instance has"
                        " inspector2:ListFindings IAM permission, or a "
                        "region in which Inspector is enabled."
                    ),
                )
                raise AWSInspectorException(error_message)

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)}"
            " workload record(s)."
            + (
                f" Skipped {skip_count} finding record(s) as they did"
                " not contain valid EC2 resource information."
                if skip_count > 0
                else ""
            )
        )
        return records

    def fetch_records(self, entity: Entity) -> List:
        """Fetch Inspector EC2 finding records for the given entity.

        Args:
            entity (Entity): Entity type to fetch records for.

        Returns:
            List: List of workload records from AWS Inspector.
        """
        records = []
        entity_name = entity.lower() if isinstance(entity, str) else entity
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} record(s)."
        )

        storage = self.storage if self.storage is not None else {}
        end_time = datetime.now(timezone.utc)

        if storage and storage.get("checkpoint"):
            start_time = self._parse_checkpoint(storage.get("checkpoint"))
        elif self.last_run_at:
            start_time = self._ensure_aware(self.last_run_at)
        else:
            initial_range = self.configuration.get("days")
            self.logger.info(
                f"{self.log_prefix}: Performing"
                f" initial data fetch for the {initial_range}"
                " day(s)."
            )
            start_time = end_time - timedelta(days=initial_range)

        try:
            if entity == ENTITY_NAME:
                records.extend(
                    self._list_inspector_findings(start_time, end_time)
                )
            else:
                err_msg = (
                    f"Invalid entity found. Plugin only"
                    f" supports '{ENTITY_NAME}' entity."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        f"Configure the entity to '{ENTITY_NAME}' in the "
                        "business rule."
                    ),
                )
                raise AWSInspectorException(err_msg)
        except AWSInspectorException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while fetching"
                " workload record(s)."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSInspectorException(err_msg)

        self._save_checkpoint(end_time)
        return records

    def _enrich_records_in_place(self, records: list) -> list:
        """Update workload records with Risk Score / EPSS Score.

        Returns a DELTA-only record list containing only the enrichment
        fields so that CE merges only the changed values.

        Args:
            records (list): List of workload records to update.

        Returns:
            list: List of delta records containing only update fields.
        """
        if not records:
            return []

        finding_arns = [
            r.get("Finding ID") for r in records if r.get("Finding ID")
        ]
        if not finding_arns:
            self.logger.info(
                f"{self.log_prefix}: No Finding IDs found in workload"
                " record(s). Skipping to update"
                " workload record(s)."
            )
            return []

        try:
            enrichment_index = self._fetch_finding_details(finding_arns)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to fetch additional"
                    " details. Workload record(s) will not have Risk"
                    f" Score and EPSS Score. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the credentials have"
                    " inspector2:BatchGetFindingDetails permission."
                ),
            )
            return []

        delta_records = []
        updated_count = 0
        no_data_count = 0
        for record in records:
            finding_id = record.get("Finding ID")
            if not finding_id:
                continue
            details = enrichment_index.get(finding_id)
            if not details:
                no_data_count += 1
                continue

            # Build a delta containing ONLY the key + new update fields.
            # Do not include any field already written by fetch_records
            # (Private IP, Severity, Title, etc.).
            patch = {"Finding ID": finding_id}
            for field_name, field_meta in ENRICHMENT_FIELD_MAPPING.items():
                value = self.aws_inspector_helper._extract_path(
                    field_meta.get("key"), details
                )
                if value is not None:
                    patch[field_name] = value

            if len(patch) > 1:
                delta_records.append(patch)
                updated_count += 1
            else:
                no_data_count += 1

        log_msg = (
            f"{self.log_prefix}: Successfully updated {updated_count} workload"
            f" record(s)."
        )
        if no_data_count:
            log_msg += (
                f" Skipped to update {no_data_count} workload record(s) as"
                f" Risk Score or EPSS Score might not be available on"
                f" {PLATFORM_NAME} platform."
            )
        self.logger.info(log_msg)
        return delta_records

    def _parse_checkpoint(self, checkpoint):
        """Parse the stored checkpoint back into a tz-aware datetime.

        Args:
            checkpoint: Stored checkpoint value (datetime or string).

        Returns:
            datetime: Timezone-aware datetime object.
        """
        if isinstance(checkpoint, datetime):
            return self._ensure_aware(checkpoint)
        try:
            parsed = datetime.fromisoformat(
                str(checkpoint).replace("Z", "+00:00")
            )
            return self._ensure_aware(parsed)
        except Exception:
            return datetime.now(timezone.utc) - timedelta(
                days=self.configuration.get("days", 7)
            )

    def _ensure_aware(self, value: datetime) -> datetime:
        """Return value as a UTC tz-aware datetime.

        Args:
            value (datetime): Datetime object to convert.

        Returns:
            datetime: UTC timezone-aware datetime object.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _save_checkpoint(self, end_time):
        """Persist end_time as the next poll start boundary.

        Args:
            end_time (datetime): End time to save as checkpoint.
        """
        if self.storage is None:
            return
        self.storage.update({"checkpoint": end_time.isoformat()})

    # ------------------------------------------------------------------
    # Update / enrichment
    # ------------------------------------------------------------------
    def _batch(self, items, size):
        """Yield successive size-sized chunks from items.

        Args:
            items (list): List of items to batch.
            size (int): Size of each batch.

        Yields:
            list: Batch of items.
        """
        for idx in range(0, len(items), size):
            yield items[idx:idx + size]

    def _fetch_finding_details(self, finding_arns: list) -> dict:
        """Call BatchGetFindingDetails for the given ARNs.

        Args:
            finding_arns (list): List of Inspector finding ARNs.

        Returns:
            dict: Dictionary mapping finding ARNs to their detail objects.
        """
        inspector_client = self._get_inspector_client()
        index = {}

        valid_arns = []
        invalid_count = 0
        for arn in finding_arns:
            if arn and _INSPECTOR_FINDING_ARN_RE.match(arn):
                valid_arns.append(arn)
            else:
                invalid_count += 1

        if invalid_count:
            self.logger.debug(
                f"{self.log_prefix}: Skipped {invalid_count} ARN(s) that"
                " did not match the Inspector finding ARN pattern."
                " These workload record(s) will not be updated."
            )

        if not valid_arns:
            return index

        # Clamp to the AWS-documented BatchGetFindingDetails array maximum
        # (10) so a misconfigured ENRICHMENT_BATCH_SIZE constant cannot
        # produce a request that the API rejects outright.
        chunk_size = max(1, min(ENRICHMENT_BATCH_SIZE, 10))

        batch_no = 1
        total_fetched = 0
        for chunk in self._batch(valid_arns, chunk_size):
            try:
                response = inspector_client.batch_get_finding_details(
                    findingArns=chunk
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to fetch additional"
                        f" details for {len(chunk)} finding ARN(s) in"
                        f" batch {batch_no}. Hence batch {batch_no}"
                        f" will be skipped. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                batch_no += 1
                continue

            batch_fetched = 0
            for details in response.get("findingDetails", []) or []:
                arn = details.get("findingArn")
                if arn:
                    index[arn] = details
                    batch_fetched += 1

            errors = response.get("errors") or []
            total_fetched += batch_fetched
            log_msg = (
                f"{self.log_prefix}: Successfully fetched details for"
                f" {batch_fetched} finding(s)"
            )
            if errors:
                log_msg += (
                    f" , skipped fetching details for {len(errors)} finding(s)"
                    " as no additional details are available"
                )
            log_msg += (
                    f" from {len(chunk)} finding(s) in batch {batch_no}. "
                    f"Total details fetched: {total_fetched}."
                )
            self.logger.info(log_msg)
            batch_no += 1

        return index

    def update_records(
        self, entity: str, records: list[dict]
    ) -> list[dict]:
        """Update workload records with Risk Score / EPSS Score.

        Calls BatchGetFindingDetails for each record and returns a
        delta-only list so that CE merges only the changed values.

        Args:
            entity (str): Entity type being updated.
            records (list[dict]): List of workload records to update.

        Returns:
            list[dict]: List of delta records with updated fields.
        """
        if entity != ENTITY_NAME:
            err_msg = (
                f"Invalid entity found. Plugin only"
                f" supports '{ENTITY_NAME}' entity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Configure the entity to '{ENTITY_NAME}' in the "
                    "business rule."
                ),
            )
            raise AWSInspectorException(err_msg)

        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )

        if not records:
            return []

        return self._enrich_records_in_place(records)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def get_entities(self) -> list[Entity]:
        """Return the CRE entity schema this plugin produces.

        Returns:
            list[Entity]: List of Entity objects with field definitions.
        """
        return [
            Entity(
                name=ENTITY_NAME,
                fields=[
                    EntityField(
                        name="Finding ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Resource ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Region",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Private IP",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Public IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="VPC ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Subnet ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Inspector Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Exploit Available",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Finding Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Title",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Vulnerability ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="First Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Port",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Protocol",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="EPSS Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
