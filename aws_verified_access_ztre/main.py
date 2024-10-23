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

CRE AWS Verified Access Plugin.
"""

import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
from netskope.common.utils import add_user_agent


from .lib.botocore.exceptions import NoCredentialsError
from .utils.exceptions import AWSVerifiedAccessException
from .utils.client import AWSVerifiedAccessClient
from .utils.validator import AWSVerifiedAccessValidator
from .utils.constants import (
    PLUGIN_NAME,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    DATE_FORMAT,
)


class AWSVerifiedAccessPlugin(PluginBase):
    """AWS Verified Access plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """AWS Verified Access plugin Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = AWSVerifiedAccessPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )

        return PLUGIN_NAME, PLUGIN_VERSION

    def _add_user_agent(self, header=None) -> str:
        """Add User-Agent to any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            str: String containing user agent.
        """
        header = add_user_agent(header)
        ce_added_agent = header.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        return user_agent

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
        """Execute action on the user.

        Args:
            record: Record of a user on which action will be
            performed.
            action (Action): Action that needs to be perform on user.

        Returns:
            None
        """
        if action.value == "generate":
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
        """Validate AWS verified access action configuration."""
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

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        validation_err_msg = "Validation error occurred"

        aws_validator = AWSVerifiedAccessValidator(
            configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            self._add_user_agent(),
        )
        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if not authentication_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if authentication_method not in [
            "aws_iam_roles_anywhere",
            "deployed_on_aws",
        ]:
            error_msg = (
                "Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}." f" {error_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
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
                    f"{self.log_prefix}: {validation_err_msg}. {error_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
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
                            "Invalid Private Key or Password Phrase provided."
                            " Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. {err_msg}"
                            ),
                            details=traceback.format_exc(),
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
                    f"{self.log_prefix}: {validation_err_msg}. {error_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
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
                            f"{self.log_prefix}: {validation_err_msg}."
                            f" {err_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                err_msg = (
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                err_msg = (
                    "Invalid Role ARN found in the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg}. {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                err_msg = (
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = "Region Name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. "
                f"Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif not (
            isinstance(region_name, str)
            and aws_validator.validate_region_name(region_name)
        ):
            error_msg = (
                "Invalid Region Name found in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f" Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate Log Group Name.
        log_group_name = configuration.get("log_group_name", "").strip()
        if not log_group_name:
            err_msg = (
                "CloudWatch Log Group Name is a required "
                "configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. "
                f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}",
            )
        elif not isinstance(log_group_name, str):
            err_msg = (
                "Invalid CloudWatch Log Group Name found in the"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Initial Range
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer greater than zero."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days > 365:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range of 1 to 365."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        try:
            aws_client = AWSVerifiedAccessClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                self._add_user_agent(),
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
            cloudwatch_logs = aws_client.get_aws_client()
        except AWSVerifiedAccessException as exp:
            self.logger.error(
                message=(f"{self.log_prefix}: {validation_err_msg}. {exp}"),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{validation_err_msg}. {exp}",
            )
        except Exception as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Authentication Failed. {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )
        try:
            log_group_name = configuration.get("log_group_name", "").strip()
            response = cloudwatch_logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
            )
            for log_stream in response.get("logStreams", []):
                log_stream_name = log_stream.get("logStreamName")
                _ = cloudwatch_logs.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name,
                    limit=1,
                )
                break
        except NoCredentialsError as exp:
            err_msg = (
                "Unable to find the credentials from the host machine."
                " Verify the role attached to instance."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error"
                    f" occurred, Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

        except Exception as exp:
            err_msg = ""
            if "AccessDeniedException" in str(exp):
                msg = (
                    "Certificates"
                    if authentication_method == "aws_iam_roles_anywhere"
                    else "IAM Role attached to the instance."
                )
                err_msg = (
                    "Access Denied, Verify the permissions provided"
                    f" to {msg}"
                )
            elif "BadRequestException" in str(exp):
                err_msg = (
                    "Bad Request, Verify Detector ID and Region Name provided"
                    " in the configuration parameters."
                )
            else:
                err_msg = f"{validation_err_msg}. Check logs for more details."
            self.logger.error(
                message=(f"{self.log_prefix}: {validation_err_msg}. {exp}"),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_cloudwatch_logs(self, log_group_name, start_time, end_time):
        """
        Get CloudWatch Logs from the specified log group.

        Args:
            log_group_name (str): The name of the log group.
            start_time (str): The start time of the logs.
            end_time (str): The end time of the logs.

        Returns:
            list: List of CloudWatch Logs.
        """
        # Create a CloudWatch Logs client
        aws_client = AWSVerifiedAccessClient(
            self.configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            self._add_user_agent(),
        )

        if start_time:
            start_time = int(start_time.timestamp() * 1000)
        if end_time:
            end_time = int(end_time.timestamp() * 1000)

        seen = set()
        unique_list = []
        describe_log_next_token = None

        # Get the log events from the specified log group
        logstream_count = 0
        total_records_fetched = 0
        total_len = 0
        while True:
            aws_client.set_credentials()
            cloudwatch_logs = aws_client.get_aws_client()
            if describe_log_next_token:
                describe_log_streams_params = {
                    "logGroupName": log_group_name,
                    "orderBy": "LogStreamName",
                    "descending": True,
                    "nextToken": describe_log_next_token,
                }
            else:
                describe_log_streams_params = {
                    "logGroupName": log_group_name,
                    "orderBy": "LogStreamName",
                    "descending": True,
                }
            response = cloudwatch_logs.describe_log_streams(
                **describe_log_streams_params
            )
            try:
                for log_stream in response.get("logStreams", []):
                    expiration = aws_client.set_credentials()
                    expiration_data = expiration.get("credentials", {}).get(
                        "expiration"
                    )
                    if expiration_data:
                        expiration_time = datetime.strptime(
                            expiration_data,
                            DATE_FORMAT,
                        )
                    cloudwatch_logs = aws_client.get_aws_client()
                    logstream_count += 1
                    log_stream_name = log_stream.get("logStreamName")
                    next_token = None
                    current_logstream_record_count = 0
                    while True:
                        if next_token is None:
                            params = {
                                "logGroupName": log_group_name,
                                "logStreamName": log_stream_name,
                                "startFromHead": True,
                                "startTime": start_time,
                                "endTime": end_time,
                            }
                        else:
                            params = {
                                "logGroupName": log_group_name,
                                "logStreamName": log_stream_name,
                                "startFromHead": True,
                                "startTime": start_time,
                                "endTime": end_time,
                                "nextToken": next_token,
                            }
                        three_minutes_after_current_time = (
                            datetime.utcnow() + timedelta(minutes=3)
                        )
                        if (
                            expiration_data
                            and three_minutes_after_current_time
                            >= expiration_time
                        ):
                            expiration = aws_client.set_credentials()
                            cloudwatch_logs = aws_client.get_aws_client()
                            expiration_data = expiration.get(
                                "credentials", {}
                            ).get("expiration")
                            if expiration_data:
                                expiration_time = datetime.strptime(
                                    expiration_data,
                                    DATE_FORMAT,
                                )

                        response_events = cloudwatch_logs.get_log_events(
                            **params
                        )
                        total_len += len(response_events.get("events", []))
                        current_logstream_record_count += len(
                            response_events.get("events", [])
                        )
                        for event in response_events.get("events", []):
                            try:
                                json_event = json.loads(event.get("message"))
                                metadata = json_event.get("metadata")
                                name = None
                                vendor_name = None
                                if metadata and metadata.get("product"):
                                    name = metadata.get("product").get("name")
                                    vendor_name = metadata.get("product").get(
                                        "vendor_name"
                                    )
                                if (name and vendor_name) and (
                                    name == "Verified Access"
                                    and vendor_name == "AWS"
                                ):
                                    actor = json_event.get("actor")
                                    if actor:
                                        user = actor.get("user")
                                        if user:
                                            currRecord = {
                                                "UUID": user.get("uuid"),
                                                "Username": user.get("name"),
                                                "Email Address": user.get(
                                                    "email_addr"
                                                ),
                                            }
                                            value = user.get("uuid")
                                            if value and (value not in seen):
                                                seen.add(value)
                                                unique_list.append(currRecord)
                                            total_records_fetched += 1

                            except json.JSONDecodeError:
                                continue
                            except Exception:
                                err_msg = (
                                    "An unexpected error occurred while "
                                    "fetching records."
                                )
                                self.logger.error(
                                    message=(f"{self.log_prefix}: {err_msg}"),
                                    details=traceback.format_exc(),
                                )
                                raise AWSVerifiedAccessException(err_msg)
                        next_forward_token = response_events.get(
                            "nextForwardToken"
                        )
                        if (
                            next_forward_token
                            and next_forward_token
                            == params.get("nextToken", None)
                        ):
                            break
                        else:
                            nexttoken = next_forward_token
                            next_token = nexttoken
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{current_logstream_record_count} records "
                        f"from LogStream {logstream_count} ({log_stream_name}). "
                        f"Total records fetched: {total_len}."
                    )
            except Exception:
                err_msg = (
                    "An unexpected error occurred while fetching records."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while fetching users from {PLATFORM_NAME}."
                    ),
                    details=str(traceback.format_exc()),
                )
                raise AWSVerifiedAccessException(err_msg)

            response_next_token = response.get("nextToken", None)
            if response_next_token:
                describe_log_next_token = response_next_token
            else:
                break

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{(total_len)} records from {PLATFORM_NAME}."
        )

        return unique_list, total_records_fetched, total_len

    def fetch_records(self, entity: Entity) -> List:
        """Pull Records from aws verified access.

        Returns:
            List: List of records to be stored on the platform.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching records from " f"{PLATFORM_NAME}."
        )

        try:
            log_group_name = self.configuration.get(
                "log_group_name", ""
            ).strip()
            initial_range = self.configuration.get("days", 7)

            current_date_utc = datetime.utcnow()
            delta = timedelta(days=initial_range)
            start_time = current_date_utc - delta
            end_time = datetime.utcnow()

            records, total_records_fetched, total_len = (
                self.get_cloudwatch_logs(log_group_name, start_time, end_time)
            )

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(records)} unique users"
                f" from {total_len} LogStream records"
                f" on {PLATFORM_NAME}."
            )
            return records

        except AWSVerifiedAccessException:
            raise
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred "
                    f"while fetching users from {PLATFORM_NAME}."
                    f" Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise AWSVerifiedAccessException(exp)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        return []

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(name="UUID", type=EntityFieldType.STRING),
                    EntityField(name="Username", type=EntityFieldType.STRING),
                    EntityField(
                        name="Email Address",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                ],
            )
        ]
