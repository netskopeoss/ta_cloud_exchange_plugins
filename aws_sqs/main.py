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

AWS SQS Plugin.
"""
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import traceback
from typing import List, Dict
from netskope.common.utils import add_user_agent

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.validator import (
    AWSSQSValidator,
)
from .utils.mapping_validator import MappingValidator
from .utils.client import AWSSQSClient
from .utils.exceptions import (
    AWSSQSException,
    MappingValidationError,
)
from .utils.constants import MODULE_NAME, PLUGIN_NAME, PLUGIN_VERSION, BATCH_SIZE

# boto exceptions


class AWSSQSPlugin(PluginBase):
    """The AWS SQS plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize AWS SQS Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSSQSPlugin.metadata
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
        plugin_name, plugin_version = self._get_plugin_info()

        header = add_user_agent(header)
        user_agent = f"{header.get('User-Agent', 'netskope-ce')}-{MODULE_NAME.lower()}-{plugin_name.lower().replace(',','').replace(' ','_')}-v{plugin_version.lower()}"  # noqa
        return user_agent

    @staticmethod
    def map_data(mappings: Dict, data: List) -> Dict:
        """Filter the raw data and returns the filtered data,
        which will be further pushed to AWS S3.

        Args:
            mappings (Dict): List of fields to be pushed to AWS S3
            (read from mapping string)
            data (List): Data to be mapped (retrieved from Netskope)

        Returns:
            Dict: Mapped Dictionary.
        """
        mandatory_fields = ["_id", "alert_name", "alert_type"]

        for field in mandatory_fields:
            if field not in mappings:
                mappings.append(field)

        mapped_dict = {}
        ignored_fields = []
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]
            else:
                ignored_fields.append(key)
        return mapped_dict

    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> Dict:
        """Retrieve subtype mappings (mappings for subtypes of alerts/events)
        case insensitively.

        Args:
            mappings (Dict): Mapping JSON from which subtypes are to
            be retrieved
            subtype (str): Subtype (e.g. DLP for alerts) for which the
            subtype mapping is to be fetched

        Returns:
            Dict: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def validate_subtype(self, instance):
        """Validate the subtype object mapped in mapping JSON files.

        Args:
            instance: The subtype object to be validated
        """
        schema = {
            "type": "array",
        }
        validate(instance=instance, schema=schema)

    def get_mappings(self, mappings: Dict, data_type: str, log_prefix) -> Dict:
        """Return the dict of mappings to be applied to raw data.

        Args:
            mappings (Dict): Mapping String
            data_type (str): Data type (alert/event) for which the
            mappings are to be fetched

        Returns:
            Dict: Read mappings
        """
        mappings = mappings["taxonomy"]["json"][data_type]

        # Validate each subtype
        for _, subtype_map in mappings.items():
            try:
                self.validate_subtype(subtype_map)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(err)
        return mappings

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported
        data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested
            (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        skipped_logs = 0
        try:
            mappings = self.get_mappings(self.mappings, data_type, self.log_prefix)
        except MappingValidationError as err:
            err_msg = "Mapping validation error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" {err_msg}. Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise AWSSQSException(err_msg)
        except Exception as err:
            err_msg = (
                f"An error occurred while mapping data using "
                f"given mapping [{data_type}][{subtype}]."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}] "
                    f"{err_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise AWSSQSException(err_msg)
        transformed_data = []
        subtype_mappings = self.get_subtype_mapping(mappings, subtype)
        if not subtype_mappings:
            return raw_data
        for data in raw_data:
            try:
                data = self.map_data(subtype_mappings, data)
                if data:
                    transformed_data.append(data)
                else:
                    skipped_logs += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Could not transform data of"
                        f" [{data_type}][{subtype}]. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                skipped_logs += 1
        if skipped_logs > 0:
            self.logger.debug(
                "{}: [{}][{}] Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the configured JSON mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(
                    self.log_prefix, data_type, subtype, skipped_logs
                )
            )
        return transformed_data

    def push(self, transformed_data: List, data_type: str, subtype: str) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (List): Transformed Data
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested
            (DLP, anomaly etc. in case of alerts)

        Returns:
            PushResult: Push result object with message and status.
        """
        try:
            queue_name = self.configuration.get("sqs_queue_name", "").strip()
            user_agent = self._add_user_agent()
            aws_client = AWSSQSClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            sqs_client = aws_client.get_sqs_client()
            queue_url = sqs_client.get_queue_url(QueueName=queue_name).get(
                "QueueUrl", None
            )
            if queue_url:
                filtered_list = list(filter(lambda d: bool(d), transformed_data))
                empty_dict_count = len(transformed_data) - len(filtered_list)
                batches = []
                failed_alerts_count = 0
                for index, data in enumerate(filtered_list):
                    send_data = {}
                    send_data["Id"] = data.get("_id", "")
                    send_data["MessageBody"] = str(data)
                    send_data["MessageAttributes"] = {
                        "Name": {
                            "DataType": "String",
                            "StringValue": data.get("alert_name", ""),
                        },
                        "Type": {
                            "DataType": "String",
                            "StringValue": data.get("alert_type", ""),
                        },
                    }
                    batches.append(send_data)
                    if (index + 1) % BATCH_SIZE == 0:
                        try:
                            response = sqs_client.send_message_batch(
                                QueueUrl=queue_url, Entries=batches
                            )
                            batches = []
                        except Exception:
                            failed_alerts_count += BATCH_SIZE
                            batches = []
                            continue
                if batches:
                    response = sqs_client.send_message_batch(
                        QueueUrl=queue_url, Entries=batches
                    )
                    failed = response.get("response", {}).get("Failed", [])
                    if failed:
                        failed_alerts_count += len(failed)
                if empty_dict_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Received empty log(s) from tenant "
                        f"or failed to ingest to the SQS queue for {empty_dict_count}"
                        " log(s) hence ingestion of those log(s) were skipped."
                    )
                log_msg = (
                    "[{}] [{}] Successfully ingested {} log(s)"
                    " to AWS SQS queue {} and {} log(s) failed to ingest.".format(
                        data_type,
                        subtype,
                        len(filtered_list) - failed_alerts_count,
                        queue_name,
                        failed_alerts_count,
                    )
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return PushResult(
                    success=True,
                    message=log_msg,
                )
            else:
                # queueUrl does not exist
                err_msg = "SQS Queue {} does not exist.".format(queue_name)
                raise AWSSQSException(err_msg)
        except AWSSQSException as exp:
            err_msg = (
                f"Error occurred while pushing log(s) to AWS SQS Queue {queue_name}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()) if traceback.format_exc() else "",
            )
            raise AWSSQSException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while pushing log(s) to AWS SQS Queue {queue_name}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSSQSException(err_msg)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation Result.
        """
        user_agent = self._add_user_agent()
        aws_validator = AWSSQSValidator(
            configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            user_agent,
        )

        if configuration.get("transformData", False):
            err_msg = (
                "This Plugin is designed to send raw data to SQS Queue "
                "- Please disable the transformation toggle to continue."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. " f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Authentication Method
        authentication_method = configuration.get("authentication_method", "").strip()
        if not authentication_method:
            err_msg = "Authentication Method is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. " f"Error: {err_msg}"
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
                f"{self.log_prefix}: Validation error occurred." f" Error: {error_msg}"
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
                    f"{self.log_prefix}: Validation error occurred. "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            elif not isinstance(pass_phrase, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Password Phrase provided.",
                )
            # Validate Private Key File.
            private_key_file = configuration.get("private_key_file", "").strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(private_key_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Private Key found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Private Key provided.",
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
                            " Verify the Private Key and Password Phrase."
                            " Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. Error: {err_msg}"
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
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(public_certificate_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Certificate Body provided.",
                )
            else:
                try:
                    x509.load_pem_x509_certificate(public_certificate_file.encode())
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid PEM Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error occurred. "
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
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Profile ARN provided."
                )

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"Invalid Role ARN found in the configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Role ARN provided."
                )

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get("trust_anchor_arn", "").strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Trust Anchor ARN provided."
                )

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = "AWS Region Name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. " f"Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif not (
            isinstance(region_name, str)
            and aws_validator.validate_region_name(region_name)
        ):
            error_msg = (
                "Invalid AWS Region Name found in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred." f" Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate SQS Queue
        sqs_queue = configuration.get("sqs_queue_name", "").strip()
        if not sqs_queue:
            err_msg = "AWS SQS Queue name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: " f"{err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(sqs_queue, str):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid AWS SQS Queue Name found in the"
                " configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid AWS SQS Queue Name provided."
            )
        # Mapping File Validation
        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        mapping_validator = MappingValidator(self.logger, self.log_prefix)
        if not isinstance(mappings, dict) or not mapping_validator.validate_mapping(
            mappings
        ):
            name = self.mappings.get("name", None)
            err_msg = f"Invalid attribute was provided in the mapping file {name}."
            self.logger.error(f"{self.log_prefix}: Error while validating mapping {name}. Error: {err_msg} This plugin only supports alert-type ingestion. Please exclude events from the Mapping file.")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        
        # Validate Auth Credentials and Queue Name.
        try:
            aws_client = AWSSQSClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
            aws_validator.validate_queue_or_create_new(aws_client, sqs_queue)
        except AWSSQSException as exp:
            return ValidationResult(
                success=False,
                message=f"Validation error occurred. {exp}",
            )
        except Exception as err:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred." f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )
        return ValidationResult(success=True, message="Validation successful.")
