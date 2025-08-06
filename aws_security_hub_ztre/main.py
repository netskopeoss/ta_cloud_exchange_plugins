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

CRE AWS Security Hub Plugin.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from dateutil import parser

from datetime import datetime, timedelta
import traceback
from typing import List

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.helper import AWSSecurityHubPluginHelper
from .utils.exceptions import AWSSecurityHubException
from .utils.client import AWSSecurityHubClient
from .utils.validator import AWSSecurityHubValidator
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    AUTHENTICATION_METHODS,
    DEVICE_FIELD_MAPPING,
    BATCH_SIZE,
    REGIONS,
    DATE_FORMAT,
    NORMALIZATION_MAPPING,
)


class AWSSecurityHubPlugin(PluginBase):
    """AWS Security Hub plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """AWS Security Hub plugin Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.aws_security_hub_helper = AWSSecurityHubPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = AWSSecurityHubPlugin.metadata
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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def execute_action(self, action: Action):
        """Execute action on the AWS Security Hub.

        Args:
            action (Action): Action that needs to be perform on \
                AWS Security Hub.

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
        """Execute actions in bulk.

        Args:
            actions (List[Action]): List of Action objects.
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
        """Validate AWS Security Hub action configuration."""
        if action.value not in [
            "generate",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.value in ["generate"]:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth_params(
        self, configuration, user_agent, validation_err_msg
    ):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
            user_agent (str): User agent string.
        """
        try:
            aws_client = AWSSecurityHubClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_validator = AWSSecurityHubValidator(
                configuration.get("region_name", "").strip(),
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
            securityhub_client = aws_client.get_aws_securityhub_client()
            aws_validator.validate_aws_securityhub(securityhub_client)
            return True, "success"
        except AWSSecurityHubException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, str(exp)
        except Exception as exp:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}"
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, error_msg

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            ValidationResult:
            ValidateResult object with success flag and message.
        """
        validation_err_msg = "Validation error occurred."
        user_agent = self.aws_security_hub_helper._add_user_agent()

        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if not authentication_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(authentication_method, str):
            err_msg = (
                "Invalid Authentication Method found in the "
                "configuration parameters. Authentication Method "
                "should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        if authentication_method not in AUTHENTICATION_METHODS:
            error_msg = (
                "Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )
        if authentication_method == "aws_iam_roles_anywhere":
            pass_phrase = configuration.get("pass_phrase")
            if not pass_phrase:
                err_msg = (
                    "Password Phrase is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            elif not isinstance(pass_phrase, str):
                err_msg = (
                    "Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )

            # Validate Private Key File.
            private_key_file = configuration.get(
                "private_key_file", ""
            ).strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(private_key_file, str):
                err_msg = (
                    "Invalid Private Key found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            else:
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
                            "Invalid Private Key or Password Phrase provided. "
                            "Verify the Private Key and Password Phrase. "
                            "Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg} "
                                f"Error: {err_msg}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        return ValidationResult(
                            success=False,
                            message=f"{err_msg}",
                        )

            # Validate Certificate Body.
            public_certificate_file = configuration.get(
                "public_certificate_file", ""
            ).strip()

            if not public_certificate_file:
                error_msg = (
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' "
                    "is selected as Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(public_certificate_file, str):
                err_msg = (
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            else:
                try:
                    x509.load_pem_x509_certificate(
                        public_certificate_file.encode()
                    )
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid Pem Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_err_msg} "
                            f"Error: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}",
                    )

            # Validate Profile ARN.
            profile_arn = configuration.get("profile_arn", "").strip()
            if not profile_arn:
                error_msg = (
                    "Profile ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                err_msg = (
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                err_msg = (
                    "Invalid Role ARN found in the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get(
                "trust_anchor_arn", ""
            ).strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                err_msg = (
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = "Region Name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif not isinstance(region_name, str):
            error_msg = (
                "Invalid AWS Region Name value found in "
                "the configuration parameters. AWS Region Name "
                "should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}"
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=error_msg
            )
        elif region_name not in REGIONS:
            error_msg = (
                "Invalid AWS Region Name provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}"
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=error_msg
            )

        # Validate Initial Range
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(days, int) or days <= 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer greater than 0."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days > 709999:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters. "
                "Valid value should be in range of 1 to 709999."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        success, message = self._validate_auth_params(
            configuration, user_agent, validation_err_msg
        )
        if not success:
            return ValidationResult(
                success=False,
                message=f"{message}",
            )

        # validation successful
        validation_msg = f"Validation Successful for {PLATFORM_NAME} plugin."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(
            success=True,
            message=validation_msg,
        )

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

        def extract(keys, value):
            if not keys:
                return value

            k = keys[0]
            rest = keys[1:]

            if isinstance(value, list):
                results = []
                for item in value:
                    extracted = extract(keys, item)
                    if extracted != default:
                        # Flatten lists at every level
                        if isinstance(extracted, list):
                            results.extend(extracted)
                        else:
                            results.append(extracted)
                return results if results else default

            if not isinstance(value, dict) or k not in value:
                return default

            return extract(rest, value.get(k, None))

        value = extract(keys, event)

        # Special handling for Resource Tags: always return a list of dicts
        if key == "Resources.Tags":
            if isinstance(value, dict):
                return [f"{k}:{v}" for k, v in value.items()]
            elif isinstance(value, list):
                tag_list = []
                for tag_dict in value:
                    if isinstance(tag_dict, dict):
                        tag_list.extend(
                            [f"{k}:{v}" for k, v in tag_dict.items()]
                        )
                return tag_list
            elif value is None:
                return []
            else:
                return [str(value)]

        if transformation == "string":
            return str(value)
        return value

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

    def _extract_entity_fields(self, event: dict) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.

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

        extracted_fields = self._post_process_fields(extracted_fields)

        normalized_score = self._normalize_risk_scores(
            event.get("Severity", {})
        )
        extracted_fields["Netskope Normalize Score"] = normalized_score
        extracted_fields["Last Seen"] = (
            parser.parse(extracted_fields.get("Last Seen"))
        )

        # Special handling for "IPv4 Address"
        ipv4_value = extracted_fields.get("IPv4 Address", [])
        if isinstance(ipv4_value, list):
            # Create a new dict for each IPv4 Address,
            # keeping other fields the same
            results = []
            for ip in ipv4_value:
                new_event = extracted_fields.copy()
                new_event["IPv4 Address"] = ip
                results.append(new_event)
            return results, len(results)

        return [extracted_fields], len(extracted_fields)

    def _flatten_field(self, value):
        """Flatten the field value.

        Args:
            value (list): List of values.

        Returns:
            str: Flattened string.
        """
        if isinstance(value, list):
            if len(value) == 1:
                return value[0]
            elif len(value) > 1:
                return ", ".join(str(v) for v in value)
            else:
                return ""
        if isinstance(value, dict):
            return str(value)
        return value

    def _post_process_fields(self, extracted_fields):
        """Post process fields.

        Args:
            extracted_fields (dict): Extracted fields.

        Returns:
            dict: Processed fields.
        """
        fields_to_flatten = [
            "VPC ID", "Subnet ID", "Region", "Resource ID"
        ]
        for field in fields_to_flatten:
            if field in extracted_fields:
                extracted_fields[field] = self._flatten_field(
                    extracted_fields[field]
                )
        return extracted_fields

    def _normalize_risk_scores(self, aws_securityhub_severity: dict) -> int:
        """Normalize the AWS SecurityHub severity score.

        Args:
            aws_securityhub_severity (dict): AWS SecurityHub severity.

        Returns:
            int: Netskope Normalized Score.
        """
        label = aws_securityhub_severity.get("Label", "").upper()
        normalized = NORMALIZATION_MAPPING.get(label, "-")
        return normalized

    def get_securityhub_findings(self, start_time, end_time):
        """
        Get SecurityHub Findings from the specified log group.

        Args:
            log_group_name (str): The name of the log group.
            start_time (str): The start time of the logs.
            end_time (str): The end time of the logs.

        Returns:
            list: List of SecurityHub Findings.
        """
        user_agent = self.aws_security_hub_helper._add_user_agent()
        # Create a SecurityHub client
        aws_client = AWSSecurityHubClient(
            self.configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            user_agent,
        )
        aws_client.set_credentials()
        securityhub_client = aws_client.get_aws_securityhub_client()

        total_devices = []
        page_count = 1
        total_findings_skip_count = 0
        next_token = None

        params = {
            "Filters": {
                "ResourceType": [
                    {"Value": "AwsEc2Instance", "Comparison": "EQUALS"},
                ],
                "UpdatedAt": [
                    {
                        "Start": start_time,
                        "End": end_time,
                    }
                ],
            },
            "SortCriteria": [
                {
                    "Field": "UpdatedAt",
                    "SortOrder": "DESC",
                }
            ],
            "MaxResults": BATCH_SIZE,
        }

        while True:
            try:
                logger_msg = (
                    f"devices for page {page_count} "
                    f"from {PLATFORM_NAME} platform"
                )
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {logger_msg}."
                )
                response = securityhub_client.get_findings(**params)
                page_findings = response.get("Findings", [])
                page_findings_count = len(page_findings)
                page_devices_count = 0
                page_findings_skip_count = 0
                for finding in page_findings:
                    try:
                        (
                            extracted_fields,
                            extracted_fields_count,
                        ) = self._extract_entity_fields(event=finding)
                        if extracted_fields:
                            total_devices.extend(extracted_fields)
                            page_devices_count += extracted_fields_count
                        else:
                            page_findings_skip_count += 1
                    except Exception as err:
                        finding_id = finding.get("Id", "")
                        err_msg = (
                            "Unable to extract fields from "
                            f"finding with ID '{finding_id}' "
                            f"from page {page_count}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                        page_findings_skip_count += 1

                if page_findings_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped fetching device "
                        f"record(s) from {page_findings_skip_count} "
                        f"findings in page {page_count} due to missing "
                        "required field(s)."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_devices_count} device record(s) "
                    f"from {page_findings_count} findings "
                    f"in page {page_count}. "
                    f"Total devices fetched: {len(total_devices)}."
                )
                page_count += 1
                total_findings_skip_count += page_findings_skip_count

                # Check for NextToken for pagination
                next_token = response.get("NextToken", None)
                if next_token:
                    params["NextToken"] = next_token
                else:
                    break
            except AWSSecurityHubException:
                raise
            except Exception as exp:
                error_message = (
                    "Unexpected error occurred while fetching "
                    f"{logger_msg}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise AWSSecurityHubException(error_message)

        if total_findings_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped fetching device "
                f"record(s) from {total_findings_skip_count} "
                "findings due to missing required field(s)."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_devices)} "
            f"device record(s) from {PLATFORM_NAME} platform."
        )
        return total_devices

    def fetch_records(self, entity: Entity) -> List:
        """Pull Records from AWS Security Hub.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        storage = self.storage if self.storage is not None else {}
        if storage and storage.get("checkpoint"):
            start_time_str = storage.get("checkpoint")
            end_time = datetime.now().strftime(DATE_FORMAT)
        elif self.last_run_at:
            start_time_str = self.last_run_at.strftime(
                DATE_FORMAT
            )
            end_time = datetime.now().strftime(DATE_FORMAT)
        else:
            initial_range = self.configuration.get("days")
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying findings for "
                f"last {initial_range} days."
            )
            start_time = datetime.now() - timedelta(days=initial_range)
            start_time_str = (
                f"{start_time.year:04d}-"
                f"{start_time.strftime('%m-%dT%H:%M:%S.%f')}"
            )
            end_time = datetime.now().strftime(DATE_FORMAT)

        try:
            if entity == "Devices":
                records.extend(
                    self.get_securityhub_findings(start_time_str, end_time)
                )
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Devices' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise AWSSecurityHubException(err_msg)
        except AWSSecurityHubException:
            raise
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred "
                    f"while fetching device records from {PLATFORM_NAME}."
                    f" Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise AWSSecurityHubException(exp)
        self.storage.update({"checkpoint": end_time})
        return records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch device scores.

        Args:
            entity (str): Entity name.
            records (list[dict]): List of records.

        Returns:
            List: List of records with scores assigned.
        """
        return []

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(
                        name="Finding ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Resource ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="IPv4 Address",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Region",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IPv6 Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Subnet ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="VPC ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Product Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Finding Title",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Finding Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Compliance Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Workflow Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Netskope Normalize Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ]
            )
        ]
