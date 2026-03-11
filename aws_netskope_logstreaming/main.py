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

AWS Netskope LogStreaming plugin.
"""

import gzip
import threading
import traceback
import json
import pandas as pd
import csv
import time
import requests
from typing import List, Tuple, Dict, Any, Generator, Union, Callable
from io import BytesIO, StringIO
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from urllib.parse import unquote_plus
from botocore.exceptions import ClientError

# Netskope imports
from netskope.common.utils import (
    Notifier,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.models.other import ActionType
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import back_pressure
from netskope.common.models import NetskopeFieldType, FieldDataType

# helper imports
from .utils.exceptions import AWSD2CProviderException
from .utils.client import AWSD2CProviderClient
from .utils import constants as CONST
from .utils.helper import (
    log_message,
    handle_and_raise,
)

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()


class AWSD2CProviderPlugin(PluginBase):
    """AWS Netskope LogStreaming ProviderPlugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.should_exit = threading.Event()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSD2CProviderPlugin.metadata
            plugin_name = manifest_json.get("name", CONST.PLATFORM_NAME)
            plugin_version = manifest_json.get("version", CONST.PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        CONST.MODULE_NAME, CONST.PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (CONST.PLATFORM_NAME, CONST.PLUGIN_VERSION)

    def validate(self, configuration: Dict[str, Any]) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            ValidationResult: ValidateResult object with success flag and message.
        """

        validation_err_msg = "Validation error occurred."

        # validate authentication parameters
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()

        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if authentication_method := self._validate_configuration_parameters(
            field_name="Authentication Method",
            field_value=authentication_method,
            field_type=str,
            allowed_values=CONST.AUTHENTICATION_METHODS,
            is_required=True,
        ):
            return authentication_method

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
                return ValidationResult(success=False, message=f"{err_msg}")
            elif not isinstance(pass_phrase, str):
                err_msg = (
                    "Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
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
                    f"{self.log_prefix} {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=error_msg)
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
                            " Verify the Private Key and Password Phrase."
                            " Private Key should be in a valid PEM format."
                        )
                        handle_and_raise(
                            logger=self.logger,
                            log_prefix=self.log_prefix,
                            err=err_msg,
                            err_msg=validation_err_msg,
                            details_msg=str(traceback.format_exc()),
                            if_raise=False,
                            return_validation_result=True,
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
                    f"{self.log_prefix} {validation_err_msg} Error: "
                    f"{error_msg}"
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
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
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
                        "Certificate Body should be in valid PEM Format."
                    )
                    handle_and_raise(
                        logger=self.logger,
                        log_prefix=self.log_prefix,
                        err=err_msg,
                        err_msg=validation_err_msg,
                        details_msg=str(traceback.format_exc()),
                        if_raise=False,
                        return_validation_result=True,
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
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(profile_arn, str):
                err_msg = (
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
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
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )

            elif not isinstance(role_arn, str):
                err_msg = (
                    "Invalid Role ARN found in the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

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
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )

            elif not isinstance(trust_anchor_arn, str):
                err_msg = (
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="AWS Region Name",
            field_value=region_name,
            field_type=str,
            allowed_values=CONST.REGIONS,
            is_required=True,
        ):
            return validation_result

        # Validate AWS SQS Queue name.
        queue_name = configuration.get("queue_name", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="AWS SQS Queue Name",
            field_value=queue_name,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Authentication Parameters.
        success, message = self._validate_auth_params(
            configuration, queue_name, validation_err_msg
        )

        if not success:
            return ValidationResult(
                success=False,
                message=f"{message}",
            )

        # validation successful
        validation_msg = (
            f"Validation Successful for {CONST.PLATFORM_NAME} plugin."
        )
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(
            success=True,
            message=validation_msg,
        )

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
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

    def _validate_auth_params(
        self,
        configuration: dict,
        queue_name: str,
        validation_err_msg: str,
    ) -> Tuple[bool, str]:
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
            queue_name (str): Queue name.
        """
        try:
            aws_client = AWSD2CProviderClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
            )
            aws_client.set_credentials()
            sqs_client = aws_client.get_sqs_client()
            aws_client.validate_queue_url_using_name(sqs_client, queue_name)
            return True, "success"
        except AWSD2CProviderException as exp:
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=exp,
                err_msg=validation_err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return False, str(exp)
        except Exception as err:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=validation_err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return False, error_msg

    def transform(
        self,
        raw_data: List[Dict[str, Any]],
        data_type: str,
        subtype: str,
        **kwargs,
    ) -> List:
        """Transform the raw netskope target platform supported.

        Args:
            raw_data (List): Raw data to be transformed.
            data_type (str): Data type of the raw data.
            subtype (str): Subtype of the raw data.

        Returns:
            List: List of transformed data
        """
        return raw_data

    def pull(
        self, start_time=None, end_time=None
    ) -> Generator[Tuple[Tuple[bytes, str, str], None], None, None]:
        """Pull data from container using azure storage queue.

        Args:
            start_time: start time for historical pulling.
            end_time: end time for historical pulling.
        """

        if start_time is not None or end_time is not None:
            self.logger.info(
                f"{self.log_prefix}: {CONST.HISTORICAL_PULL} "
                f"is not supported for {CONST.PLATFORM_NAME}."
            )
            return CONST.SUCCESS_FALSE

        page_data = []
        log_data_type = CONST.TYPE_ALERT
        sub_type = CONST.INITIAL_SUB_TYPE
        try:
            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            for page_data, log_data_type, sub_type in self.load_maintenance(
                self.configuration
            ):
                log_message(
                    self.logger,
                    self.log_prefix,
                    CONST.PLATFORM_NAME,
                    page_data,
                    log_data_type,
                    sub_type,
                    CONST.MAINTENANCE_PULL,
                )
                if sub_type != "v2":
                    page_data = gzip.compress(
                        json.dumps({CONST.RESULT: page_data}).encode("utf-8"),
                        compresslevel=3,
                    )
                else:
                    page_data = gzip.compress(
                        json.dumps(page_data).encode("utf-8"),
                        compresslevel=3,
                    )

                yield (page_data, log_data_type, sub_type), None

        except AWSD2CProviderException:
            yield (page_data, log_data_type, sub_type), None
        except Exception as err:
            error_msg = (
                "Error occurred while fetching alerts, events and webtx logs "
                f"from {CONST.PLATFORM_NAME}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=error_msg,
                details_msg=str(traceback.format_exc()),
            )

    def _get_messages_from_response(
        self, sqs_client: AWSD2CProviderClient, queue_url: str
    ) -> List[Dict[str, Any]]:
        """get messages from response
        Args:
            sqs_client: sqs client
            response: response
        """
        messages = []

        try:
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=2,
                MessageAttributeNames=["All"],
            )
            sqs_messages = response.get("Messages")
            if sqs_messages and isinstance(sqs_messages, list):
                for msg in sqs_messages:
                    if msg:
                        messages.append(msg)
                        sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=msg["ReceiptHandle"],
                        )
        except (requests.exceptions.RequestException, ClientError) as e:
            err_msg = "Error occurred while communicating with SQS queue."
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=e,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except Exception as e:
            err_msg = (
                "Unexpected error occurred while receiving "
                "messages from SQS queue."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=e,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

        return messages

    def _process_incident_event(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process incident data to convert some int fields to sting

        Args:
            incident_data: Incidnet data to be processed
        """
        for key in CONST.STRING_FIELDS:
            if key in incident_data and incident_data[key]:
                incident_data[key] = str(incident_data[key])
        return incident_data

    def _bifurcate_data(
        self,
        data_list: List[Dict[str, Any]],
        container_name: str,
        blob_name: str,
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Bifurcate the data.

        Args:
            data (bytes): The json data.
        """
        result = {}
        skip_count = 0
        for data in data_list:
            try:
                record_type = data.get("record_type")
                alert_type = data.get("alert_type")
                if record_type and record_type in CONST.NLS_EVENTS_MAPPINGS:
                    target_key = CONST.NLS_EVENTS_MAPPINGS.get(record_type)
                    if record_type == "incident":
                        incident_data = self._process_incident_event(data)
                        result.setdefault(target_key, []).append(incident_data)
                    else:
                        result.setdefault(target_key, []).append(data)
                elif (
                    record_type
                    and record_type == "alert"
                    and alert_type
                    and alert_type in CONST.NLS_ALERTS_MAPPINGS
                ):
                    target_key = CONST.NLS_ALERTS_MAPPINGS.get(alert_type)
                    result.setdefault(target_key, []).append(data)
                elif data.get("x-cs-timestamp"):
                    result.setdefault("v2", []).append(data)
                else:
                    skip_count += 1
            except Exception:
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} out "
                f"of {len(data_list)} logs from file '{blob_name}' "
                f"from container '{container_name}' either due to invalid"
                " data, unsupported subtype or missing required fields."
            )
        for subtype, data in result.items():
            datatype = None
            if data:
                if subtype.lower() in CONST.ALERTS:
                    datatype = "alerts"
                elif subtype.lower() in CONST.EVENTS:
                    datatype = "events"
                elif subtype.lower() in CONST.WEBTX:
                    datatype = "webtx"

                yield data, datatype, subtype

    def _process_gzipped_csv_in_batches(
        self, data: bytes, object_key: str, bucket_name: str, batch_size: int
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Process the gzipped CSV data in batches.

        Args:
            data (bytes): The gzipped CSV data.
            s3_client (boto3.client): The S3 client.
        """
        try:
            with gzip.GzipFile(fileobj=BytesIO(data), mode="rb") as gz:

                # Read the CSV content
                csv_content = gz.read().decode("utf-8")
                # Automatically detect delimiter
                sniffer = csv.Sniffer()
                # Default delimiter
                delimiter = ","
                try:
                    delimiter = sniffer.sniff(
                        csv_content.split("\n")[0]
                    ).delimiter
                except Exception as e:
                    err_msg = (
                        "Error occurred while detecting delimiter from"
                        " csv file. Using default delimiter ','."
                    )
                    handle_and_raise(
                        logger=self.logger,
                        log_prefix=self.log_prefix,
                        err=e,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                        if_raise=False,
                    )
                # batching for the batch size
                for chunk in pd.read_csv(
                    StringIO(csv_content),
                    delimiter=delimiter,
                    engine="python",
                    on_bad_lines="skip",
                    chunksize=batch_size,
                ):
                    chunk.replace(
                        to_replace=r"^-$",
                        value="",
                        regex=True,
                        inplace=True,
                    )

                    file_data = json.loads(chunk.to_json(orient="records"))

                    for data, datatype, subtype in self._bifurcate_data(
                        file_data, object_key, bucket_name
                    ):
                        yield data, datatype, subtype

        except Exception as e:
            err_msg = (
                "Unexpected error occurred while processing s3 bucket file."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=e,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def _process_messages(
        self, aws_client: AWSD2CProviderClient, messages: list
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Process the messages.

        Args:
            messages (list): List of messages.
            configuration (dict): The configuration dictionary.
        """
        file_data = []
        skip_count = 0
        for msg in messages:
            try:
                body = {}
                if msg.get("Body") and isinstance(msg.get("Body"), str):
                    body = json.loads(msg.get("Body"))

                for record in body.get("Records", []):
                    s3_info = record.get("s3", {})
                    bucket_name = s3_info.get("bucket", {}).get("name")
                    object_key_raw = s3_info.get("object", {}).get("key")
                    object_key = (
                        unquote_plus(object_key_raw) if object_key_raw else ""
                    )

                    if object_key and object_key.endswith(".csv.gz"):
                        self.logger.debug(
                            f"{self.log_prefix}: Fetching '{object_key}'"
                            f" file data from '{bucket_name}' s3 bucket."
                        )
                        aws_client.set_credentials()
                        s3 = aws_client.get_s3_client()

                        response = s3.get_object(
                            Bucket=bucket_name, Key=object_key
                        )

                        data = response["Body"].read()

                        for (
                            file_data,
                            datatype,
                            subtype,
                        ) in self._process_gzipped_csv_in_batches(
                            data,
                            object_key,
                            bucket_name,
                            batch_size=CONST.BATCH_SIZE,
                        ):
                            yield file_data, datatype, subtype
                    else:
                        skip_count += 1
                        continue
            except AWSD2CProviderException:
                skip_count += 1
                continue
            except Exception as e:
                if "s3:ListBucket" in str(e):
                    err_msg = (
                        "Invalid file format"
                        " recieved from AWS S3 bucket."
                        f" Skipping this file: '{object_key}'."
                    )
                else:
                    err_msg = (
                        "Error occurred while processing SQS queue messages "
                        f"for {CONST.PLATFORM_NAME}."
                    )
                handle_and_raise(
                    logger=self.logger,
                    log_prefix=self.log_prefix,
                    err=e,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                    if_raise=False,
                )
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Skipped processing data for {skip_count}"
                " messages from SQS queue because either the file format"
                " or the data is of unsupported format."
            )

    def _get_bucket_data_in_batches(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Get the bucket data in batches.

        Args:
            configuration (dict): The configuration dictionary.
        """
        try:
            queue_name = configuration.get("queue_name", "").strip()
            aws_client = AWSD2CProviderClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
            )
            aws_client.set_credentials()
            sqs_client = aws_client.get_sqs_client()

            try:
                response = sqs_client.get_queue_url(QueueName=queue_name)
            except Exception as e:
                err_msg = (
                    "Error occurred while getting SQS queue url "
                    f"for {CONST.PLATFORM_NAME}."
                )
                handle_and_raise(
                    logger=self.logger,
                    log_prefix=self.log_prefix,
                    err=e,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )

            # sqs queue url
            queue_url = response.get("QueueUrl", "").strip()

            # get the messages from the sqs queue
            messages = []
            messages = self._get_messages_from_response(sqs_client, queue_url)

            if len(messages) > 0:
                self.logger.debug(
                    f"{self.log_prefix}: {len(messages)} message(s) from queue"
                    f" '{queue_name}' will be processed."
                )
            else:
                self.logger.debug(
                    f"{self.log_prefix}: No message(s) available to process"
                    f" from queue '{queue_name}'."
                )

            # process the messages
            for batch_data, datatype, subtype in self._process_messages(
                aws_client, messages
            ):
                yield batch_data, datatype, subtype

        except AWSD2CProviderException:
            raise
        except ClientError as err:
            err_msg = (
                "Error occurred while connecting to "
                f"AWS s3 client for {CONST.PLATFORM_NAME}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except Exception as e:
            err_msg = (
                "Error unexpected occurred while processing"
                f" s3 bucket data for {CONST.PLATFORM_NAME}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=e,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def load_maintenance(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """maintainence pulling from the storage queue.

        Args:
            configuration (dict): The configuration dictionary.
        """

        if back_pressure.STOP_PULLING:
            self.logger.debug(
                f"{self.log_prefix}: Maintenance pulling"
                f" for plugin {CONST.PLATFORM_NAME} "
                "is paused due to back pressure."
            )
            time.sleep(CONST.BACK_PRESSURE_WAIT_TIME)

        for (
            file_data,
            datatype,
            subtype,
        ) in self._get_bucket_data_in_batches(configuration):
            yield file_data, datatype, subtype

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=NetskopeFieldType.EVENT,
        sub_type=None,
    ):
        """Extract and store keys from list of dictionaries.

        Args:
            items (List[dict]): List of dictionaries. i.e. alerts, or events.
            typeOfField (str): Alert or Event
            sub_type (str): Subtype of alerts or events.
        """
        typeOfField = typeOfField.rstrip("s")
        fields = set()

        for item in items:
            if not isinstance(item, dict):
                item = item.dict()

            item_id = item.get("_id", None)
            if not sub_type and typeOfField == CONST.TYPE_EVENT:
                sub_type = item.get("record_type", None)
            elif not sub_type and typeOfField == CONST.TYPE_ALERT:
                sub_type = item.get("alert_type", None)
            elif not sub_type and typeOfField == CONST.TYPE_WEBTX:
                sub_type = "v2"
            if not item_id:
                item_id = item.get("id")
            for field, field_value in item.items():
                if field in fields:
                    continue
                if not field_value:
                    continue
                field_obj = plugin_provider_helper.get_stored_field(field)
                if typeOfField == CONST.TYPE_WEBTX and not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new"
                        f" field '{field}' in the WebTx logs."
                        " Configure CLS to use this field if "
                        "you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in"
                        " the WebTx logs. Configure CLS to use this field if"
                        " you wish to sent it to the SIEM."
                    )

                elif not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use "
                        "this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use this"
                        " field if you wish to sent it to the SIEM."
                    )
                datatype = (
                    FieldDataType.BOOLEAN
                    if isinstance(field_value, bool)
                    else (
                        FieldDataType.NUMBER
                        if isinstance(field_value, int)
                        or isinstance(field_value, float)
                        else FieldDataType.TEXT
                    )
                )
                plugin_provider_helper.store_new_field(
                    field,
                    typeOfField,
                    (
                        FieldDataType.TEXT
                        if field in CONST.STRING_FIELDS
                        else datatype
                    ),
                )
            fields = fields.union(item.keys())

    def cleanup(self, action_type: str = ActionType.DELETE.value) -> None:
        """Remove all related dependencies of the record before
        its deletion, ensuring data integrity."""
        pass
