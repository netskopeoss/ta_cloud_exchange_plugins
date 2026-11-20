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

AWS S3 Events, Alerts Plugin.
"""

import json
import os
import traceback
from tempfile import NamedTemporaryFile
from typing import List, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.aws_s3_events_alerts_validator import (
    AWSS3EventsAlertsValidator,
)
from .utils.aws_s3_events_alerts_client import (
    AWSS3EventsAlertsClient,
)
from .utils.aws_s3_events_alerts_exception import (
    AWSS3EventsAlertsException,
)
from .utils.aws_s3_events_alerts_helper import (
    get_mappings,
    map_json_data,
)
from .utils.aws_s3_events_alerts_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    REGION_CHOICES,
    USER_AGENT,
    VALIDATION_ERROR_MESSAGE,
)


class AWSS3EventsAlertsPlugin(PluginBase):
    """The AWS S3 Events, Alerts plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize AWSS3EventsAlertsPlugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest metadata.

        Returns:
            tuple: (plugin_name, plugin_version)
        """
        try:
            manifest_json = AWSS3EventsAlertsPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_config_params(
        self,
        configuration: dict,
        params_to_get: List[str] = None,
    ):
        """Get required configuration parameters.

        Args:
            configuration (dict): Plugin configuration dict.
            params_to_get (List[str]): Subset of param keys to return.
                If None, returns all params as a tuple.

        Returns:
            tuple or single value of the requested parameters.
        """
        all_params = {
            "authentication_method": configuration.get(
                "authentication_method", ""
            ).strip(),
            "private_key_file": configuration.get(
                "private_key_file", ""
            ).strip(),
            "public_certificate_file": configuration.get(
                "public_certificate_file", ""
            ).strip(),
            "pass_phrase": configuration.get("pass_phrase"),
            "profile_arn": configuration.get(
                "profile_arn", ""
            ).strip(),
            "role_arn": configuration.get("role_arn", "").strip(),
            "trust_anchor_arn": configuration.get(
                "trust_anchor_arn", ""
            ).strip(),
            "region_name": configuration.get(
                "region_name", ""
            ).strip(),
            "bucket_name": configuration.get(
                "bucket_name", ""
            ).strip(),
            "externally_provisioned_bucket": configuration.get(
                "externally_provisioned_bucket", "no"
            ).strip().lower(),
        }

        if not params_to_get:
            return tuple(all_params.values())

        result = [all_params.get(param) for param in params_to_get]
        return result[0] if len(result) == 1 else tuple(result)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        is_required: bool = True,
        allowed_values: list = None,
        validation_err_msg: str = VALIDATION_ERROR_MESSAGE,
        required_field_message: str = None,
    ) -> Union[ValidationResult, None]:
        """Validate a configuration field.

        Args:
            field_name (str): Name of the field to validate.
            field_value: Value of the field to validate.
            field_type (type): Expected type of the field.
            is_required (bool): Whether the field is required.
            allowed_values (list): List of allowed values for the field.
            validation_err_msg (str): Base validation error message.
            required_field_message (str): Custom message when field is
                required but empty.

        Returns:
            ValidationResult on failure, None on success.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if is_required and not isinstance(field_value, int) and \
                not field_value:
            err_msg = (
                required_field_message
                if required_field_message
                else (
                    f"{field_name} is a required"
                    " configuration parameter."
                )
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} value is provided in"
                    " the configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if field_value and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    f"Ensure that valid value for {field_name} is"
                    " provided in the configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            allowed_values
            and field_type is str
            and field_value not in allowed_values
        ):
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {', '.join(str(v) for v in allowed_values)}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    f"Ensure that valid value for {field_name} is"
                    " provided in the configuration parameters and it"
                    " should be one of"
                    f" {', '.join(str(v) for v in allowed_values)}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    @staticmethod
    def get_subtype_mapping(mappings: dict, subtype: str) -> dict:
        """Retrieve subtype mappings case-insensitively.

        Args:
            mappings (dict): Mapping dict keyed by subtype name.
            subtype (str): Subtype name to look up.

        Returns:
            dict: Mapping for the given subtype, or {} if not found.
        """
        lower_mappings = {k.lower(): v for k, v in mappings.items()}
        return lower_mappings.get(subtype.lower(), {})

    def get_dynamic_fields(self) -> list:
        """Return dynamic configuration fields for the selected auth method.

        Returns:
            list: List of dynamic field definitions.
        """
        authentication_method = self._get_config_params(
            self.configuration, ["authentication_method"]
        )
        region_field = {
            "label": "AWS S3 Bucket Region Name",
            "key": "region_name",
            "type": "choice",
            "choices": REGION_CHOICES,
            "default": "us-east-1",
            "mandatory": True,
            "description": (
                "AWS region where the target S3 bucket resides."
                " Make sure the region matches the region in the"
                " Profile ARN and Trust Anchor ARN when using"
                " IAM Roles Anywhere."
            ),
        }
        bucket_field = {
            "label": "AWS S3 Bucket Name",
            "key": "bucket_name",
            "type": "text",
            "default": "",
            "mandatory": True,
            "description": (
                "Name of the target AWS S3 bucket where Netskope"
                " Alerts, Events data will be stored."
                " Example: netskope-alerts-bucket."
            ),
        }
        ep_field = {
            "label": "Externally Provisioned Bucket",
            "key": "externally_provisioned_bucket",
            "type": "choice",
            "choices": [
                {"key": "Yes", "value": "yes"},
                {"key": "No", "value": "no"},
            ],
            "default": "no",
            "mandatory": True,
            "description": (
                "Select 'Yes' if the S3 bucket is located in an"
                " external AWS account. Select 'No' if the bucket is"
                " in your own AWS account. If 'No' is selected and"
                " the bucket does not already exist, the plugin will"
                " create it. If 'Yes' is selected, the bucket must"
                " already exist, as the plugin will not create it."
            ),
        }

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
                        "PEM-encoded private key used to decrypt the"
                        " AWS Private CA Certificate. Required for"
                        " 'AWS IAM Roles Anywhere' authentication."
                    ),
                },
                {
                    "label": "Certificate Body",
                    "key": "public_certificate_file",
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "PEM-encoded X.509 certificate body issued by"
                        " your AWS Private or Public CA. Required for"
                        " 'AWS IAM Roles Anywhere' authentication."
                    ),
                },
                {
                    "label": "Password Phrase",
                    "key": "pass_phrase",
                    "type": "password",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Passphrase used to decrypt the CA certificate"
                        " if it is encrypted. Required for 'AWS IAM"
                        " Roles Anywhere' authentication."
                    ),
                },
                {
                    "label": "Profile ARN",
                    "key": "profile_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ARN of the IAM Roles Anywhere profile."
                        " Format: arn:aws:rolesanywhere:{region}:"
                        "{account-id}:profile/{profile-id}."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication."
                    ),
                },
                {
                    "label": "Role ARN",
                    "key": "role_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ARN of the IAM role to be assumed."
                        " Format: arn:aws:iam::{account-id}:role/"
                        "{role-name}. Required for 'AWS IAM Roles"
                        " Anywhere' authentication."
                    ),
                },
                {
                    "label": "Trust Anchor ARN",
                    "key": "trust_anchor_arn",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ARN of the IAM Roles Anywhere trust anchor."
                        " Format: arn:aws:rolesanywhere:{region}:"
                        "{account-id}:trust-anchor/{anchor-id}."
                        " Required for 'AWS IAM Roles Anywhere'"
                        " authentication."
                    ),
                },
                ep_field,
                region_field,
                bucket_field,
            ]
        else:
            return [
                ep_field,
                region_field,
                bucket_field,
            ]

    def validate_mappings(self) -> ValidationResult:
        """Validate the mappings for all data types.

        Parses the jsonData mapping string, checks it is non-empty, and
        validates the taxonomy.json structure.

        Returns:
            ValidationResult: Success or failure with a descriptive
                message.
        """
        aws_validator = AWSS3EventsAlertsValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

        def _validate_json_data(json_string):
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON: {err}")
            except Exception as err:
                raise ValueError(
                    f"Error occurred while validating JSON: {err}."
                )
            return json_object

        try:
            mappings = _validate_json_data(self.mappings.get("jsonData"))
        except Exception as err:
            return ValidationResult(success=False, message=str(err))

        if not aws_validator.validate_mappings(mappings):
            err_msg = (
                "Invalid mapping configuration. Please check the"
                " mapping settings in Settings > Log Shipper."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the mapping configuration is valid and"
                    " correctly structured under"
                    " Settings > Log Shipper."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(
            success=True, message="Mappings validation successful."
        )

    # ─────────────────────── TRANSFORM FLOW ──────────────────────────

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform raw Netskope JSON data using configured mappings.

        Args:
            raw_data (list): Raw records from Netskope.
            data_type (str): Data type — 'alerts', 'events', or 'webtx'.
            subtype (str): Subtype — e.g. 'dlp', 'page', 'v2'.

        Returns:
            List: Transformed records ready for S3 upload.
        """
        skipped_logs = 0
        try:
            mappings = get_mappings(self.mappings, data_type)
        except Exception as err:
            err_msg = (
                f"[{data_type}][{subtype}] "
                "An error occurred while fetching mappings."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=traceback.format_exc(),
            )
            raise AWSS3EventsAlertsException(err_msg)

        transformed_data = []
        try:
            subtype_mappings = self.get_subtype_mapping(
                mappings, subtype
            )
        except Exception as err:
            err_msg = (
                f"[{data_type}][{subtype}] An error occurred while"
                " fetching subtype mappings."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=traceback.format_exc(),
            )
            raise AWSS3EventsAlertsException(err_msg)

        if not subtype_mappings:
            return raw_data

        for data in raw_data:
            if not data:
                skipped_logs += 1
                continue
            try:
                mapped = map_json_data(subtype_mappings, data)
                if mapped:
                    transformed_data.append(mapped)
                else:
                    skipped_logs += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}]"
                        " An error occurred while transforming record."
                        f" {err}"
                    ),
                    details=traceback.format_exc(),
                )
                skipped_logs += 1

        if skipped_logs > 0:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}]"
                f" Plugin couldn't process {skipped_logs} record(s)"
                " because they either had no data or contained"
                " invalid/missing fields according to the configured"
                " JSON mapping. Those records were skipped."
            )
        return transformed_data

    # ─────────────────────── PUSH FLOW ───────────────────────────────

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Push transformed data to the AWS S3 bucket as NDJSON.

        Args:
            transformed_data (List): Transformed log records.
            data_type (str): Data type — 'alerts', 'events', or 'webtx'.
            subtype (str): Subtype — e.g. 'dlp', 'page', 'v2'.

        Returns:
            PushResult: Result with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}]"
            f" Initializing the sharing of {len(transformed_data)}"
            f" log(s) to {PLATFORM_NAME} AWS S3 Bucket."
        )
        bucket_name = self._get_config_params(
            self.configuration, ["bucket_name"]
        )
        try:
            aws_client = AWSS3EventsAlertsClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                USER_AGENT,
            )
            aws_client.set_credentials()

            filtered_list = list(
                filter(lambda d: bool(d), transformed_data)
            )
            empty_dict_count = len(transformed_data) - len(filtered_list)
            if empty_dict_count > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Received empty log(s) from"
                    " tenant or failed to write to the object file"
                    f" for {empty_dict_count} log(s) — ingestion of"
                    " those log(s) was skipped."
                )
            if not filtered_list:
                log_msg = (
                    f"[{data_type}][{subtype}] No log(s) to push to"
                    f" {self.plugin_name} AWS S3 Bucket {bucket_name}."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return PushResult(success=True, message=log_msg)

            temp_obj_file = None
            try:
                temp_obj_file = NamedTemporaryFile("w", delete=False)
                temp_obj_file.write(json.dumps(filtered_list))
                temp_obj_file.flush()
                aws_client.push(
                    temp_obj_file.name, data_type, subtype
                )
            except Exception as err:
                err_msg = (
                    f"[{data_type}][{subtype}] An error occurred while"
                    f" pushing log(s) to {PLATFORM_NAME} AWS S3"
                    f" Bucket {bucket_name}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(err),
                )
                raise AWSS3EventsAlertsException(err_msg)
            finally:
                if temp_obj_file:
                    temp_obj_file.close()
                    os.unlink(temp_obj_file.name)

            log_msg = (
                f"[{data_type}][{subtype}] Successfully ingested"
                f" {len(filtered_list)} log(s) to {self.plugin_name}"
                f" AWS S3 Bucket {bucket_name}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)
        except AWSS3EventsAlertsException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while pushing log(s) to AWS S3"
                f" Bucket {bucket_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSS3EventsAlertsException(err_msg)

    # ─────────────────────── CONNECTIVITY VALIDATION ─────────────────

    def _validate_connectivity(
        self,
        configuration: dict,
        aws_validator: "AWSS3EventsAlertsValidator",
        bucket_name: str,
    ) -> Union[ValidationResult, None]:
        """Validate connectivity to AWS S3.

        Runs two checks in order:
          1. AWS credentials (HeadBucket)
          2. S3 bucket accessible, created if needed, region verified

        Args:
            configuration (dict): Plugin configuration parameters.
            aws_validator (AWSS3EventsAlertsValidator): Validator
                instance.
            bucket_name (str): Configured S3 bucket name.

        Returns:
            ValidationResult: Failure result if any check fails.
            None: All checks passed.
        """
        validation_err_msg = VALIDATION_ERROR_MESSAGE

        # 1. Validate AWS credentials via HeadBucket
        try:
            aws_client = AWSS3EventsAlertsClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                USER_AGENT,
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
        except AWSS3EventsAlertsException as exp:
            err_msg = (
                f"Error occurred while validating AWS credentials. {exp}"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    "Ensure that the AWS credentials are correct and"
                    " the IAM role or instance profile has the required"
                    " S3 permissions."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = (
                "Error occurred while validating AWS credentials."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}"
                    f" {err_msg} {err}"
                ),
                resolution=(
                    "Ensure that the AWS authentication parameters are"
                    " correct and the IAM role has the required"
                    " permissions."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

        # 2. Verify S3 bucket (existence, creation if needed, region)
        try:
            if not aws_client.verify_bucket_exists():
                err_msg = (
                    f"AWS S3 Bucket '{bucket_name}' does not exist or"
                    " is not accessible."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}"
                        f" {err_msg}"
                    ),
                    resolution=(
                        "Recreate the S3 bucket or provide a valid"
                        " existing bucket name in the configuration."
                        " Also make sure that IAM role has"
                        " s3:GetBucketLocation, s3:PutObject,"
                        " s3:ListBucket permissions."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        except AWSS3EventsAlertsException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = (
                "Error occurred while verifying AWS S3 bucket."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}"
                    f" {err_msg} {err}"
                ),
                resolution=(
                    "Ensure that the AWS IAM role has permission to"
                    " access the S3 bucket."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    # ─────────────────────── VALIDATION FLOW ─────────────────────────

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate all plugin configuration parameters.

        Validation order:
          1. transformData format check (JSON-only plugin)
          2. Authentication Method
          3. Conditional IAM Roles Anywhere parameters
          4. AWS S3 Bucket Region Name
          5. AWS S3 Bucket Name
          6. Externally Provisioned Bucket
          7. Mappings structure
          8. Connectivity: AWS credentials → S3 bucket

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result with success flag and
                message.
        """
        validation_err_msg = VALIDATION_ERROR_MESSAGE

        # Extract all configuration parameters up-front
        (
            authentication_method,
            private_key_file,
            public_certificate_file,
            pass_phrase,
            profile_arn,
            role_arn,
            trust_anchor_arn,
            region_name,
            bucket_name,
            externally_provisioned_bucket,
        ) = self._get_config_params(configuration)

        aws_validator = AWSS3EventsAlertsValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

        # 1. Validate transformData — JSON-only plugin
        if configuration.get("transformData", "json") != "json":
            err_msg = (
                "This Plugin is designed to send JSON data to S3"
                " Bucket. Please select the format as 'JSON' to"
                " continue."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    "Select 'JSON' as the data format in the plugin"
                    " configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # 2. Validate Authentication Method
        if auth_result := self._validate_configuration_parameters(
            field_name="Authentication Method",
            field_value=authentication_method,
            field_type=str,
            is_required=True,
            allowed_values=[
                "deployed_on_aws",
                "aws_iam_roles_anywhere",
            ],
            validation_err_msg=validation_err_msg,
        ):
            return auth_result

        # 3. Conditional IAM Roles Anywhere parameters
        if authentication_method == "aws_iam_roles_anywhere":

            # Password Phrase (validated first — needed to parse key)
            if phrase_result := self._validate_configuration_parameters(
                field_name="Password Phrase",
                field_value=pass_phrase,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Password Phrase is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' is"
                    " selected as Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return phrase_result

            # Private Key — required then PEM parse
            if key_result := self._validate_configuration_parameters(
                field_name="Private Key",
                field_value=private_key_file,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as"
                    " Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return key_result
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
                        "Invalid Private Key or Password Phrase"
                        " provided. Private Key must be in valid"
                        " PEM format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_err_msg}"
                            f" {err_msg}"
                        ),
                        resolution=(
                            "Ensure that the Private Key is in valid"
                            " PEM format and the Password Phrase"
                            " matches the key encryption."
                        ),
                        details=traceback.format_exc(),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )

            # Certificate Body — required then PEM parse
            if cert_result := self._validate_configuration_parameters(
                field_name="Certificate Body",
                field_value=public_certificate_file,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' is"
                    " selected as Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return cert_result
            try:
                x509.load_pem_x509_certificate(
                    public_certificate_file.encode()
                )
            except Exception:
                err_msg = (
                    "Invalid Certificate Body provided. Certificate"
                    " Body must be in valid PEM format."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}"
                        f" {err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Certificate Body is a valid"
                        " PEM-encoded X.509 certificate."
                    ),
                    details=traceback.format_exc(),
                )
                return ValidationResult(success=False, message=err_msg)

            # Profile ARN
            if profile_result := self._validate_configuration_parameters(
                field_name="Profile ARN",
                field_value=profile_arn,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Profile ARN is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as"
                    " Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return profile_result

            # Role ARN
            if role_result := self._validate_configuration_parameters(
                field_name="Role ARN",
                field_value=role_arn,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Role ARN is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as"
                    " Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return role_result

            # Trust Anchor ARN
            if anchor_result := self._validate_configuration_parameters(
                field_name="Trust Anchor ARN",
                field_value=trust_anchor_arn,
                field_type=str,
                is_required=True,
                required_field_message=(
                    "Trust Anchor ARN is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' is"
                    " selected as Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return anchor_result

        # 4. Validate AWS S3 Bucket Region Name
        if region_result := self._validate_configuration_parameters(
            field_name="AWS S3 Bucket Region Name",
            field_value=region_name,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return region_result
        if not aws_validator.validate_region_name(region_name):
            err_msg = (
                "Invalid AWS S3 Bucket Region Name found in the"
                " configuration parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    "Select a valid AWS region from the available"
                    " choices in the configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # 5. Validate AWS S3 Bucket Name
        if bucket_result := self._validate_configuration_parameters(
            field_name="AWS S3 Bucket Name",
            field_value=bucket_name,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return bucket_result

        # 6. Validate Externally Provisioned Bucket
        if ep_result := self._validate_configuration_parameters(
            field_name="Externally Provisioned Bucket",
            field_value=externally_provisioned_bucket,
            field_type=str,
            is_required=True,
            allowed_values=["yes", "no"],
            validation_err_msg=validation_err_msg,
        ):
            return ep_result

        # 7. Validate mappings structure
        mappings_result = self.validate_mappings()
        if not mappings_result.success:
            return mappings_result

        # 8. Connectivity: AWS credentials + S3 bucket verification
        if connectivity_result := self._validate_connectivity(
            configuration=configuration,
            aws_validator=aws_validator,
            bucket_name=bucket_name,
        ):
            return connectivity_result

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated configuration"
            " parameters."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )
