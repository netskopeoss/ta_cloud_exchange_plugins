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

CLS Microsoft Azure Sentinel  Plugin.
"""

import json
import re
import traceback
from typing import List

from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.sentinel_client import AzureSentinelClient
from .utils.sentinel_constants import (
    ATTRIBUTE_DTYPE_MAP,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    VALIDATION_ALPHANUM_PATTERN,
    VALIDATION_DIGITS_PATTERN,
)
from .utils.sentinel_exception import (
    AzureSentinelException,
    MappingValidationError,
)
from .utils.sentinel_helper import (
    conversion_map,
    get_sentinel_mappings,
    map_sentinel_data,
)
from .utils.sentinel_validator import AzureSentinelValidator


class AzureSentinelPlugin(PluginBase):
    """The CLS Microsoft Azure Sentinel plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
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
            manifest_json = AzureSentinelPlugin.metadata
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

    @staticmethod
    def get_subtype_mapping(mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events)
        case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which the mapping is
        to be fetched
        :return: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    @staticmethod
    def _utf8len(string):
        """Calculate the size of given string in bytes.

        :param string: The string for which the size is to be calculated
        :return: The total size of the given string
        """
        # The reason for encoding is that, in Python 3, some single-character
        # strings will require multiple bytes to
        # be represented. For example chinese characters.
        return len(string.encode("utf-8"))

    def _convert_dtype(self, key, value):
        """Convert the data type of given value to string.

        :param key: The attribute name from the Netskope response
        :param value: The value of the given attribute whose data type is to
        be converted to string
        :return: value in form of String
        """
        try:
            if key in ATTRIBUTE_DTYPE_MAP:
                return conversion_map[ATTRIBUTE_DTYPE_MAP[key]](value)
            return value
        except Exception:
            return None

    def _normalize_key(self, key):
        """Normalize the given key by removing any special characters.

        :param key: The key string to be normalized
        :return: normalized key
        """
        # Check if it contains characters other than alphanumeric and
        # underscores
        if not re.match(VALIDATION_ALPHANUM_PATTERN, key):
            # Replace characters other than underscores and alphanumeric
            key = re.sub(r"[^0-9a-zA-Z_]+", "_", key)
        return key

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Azure Sentinel.

        :param data_type: The type of data being pushed. Current possible
        values: alerts and events
        :param transformed_data: Transformed data to be ingested to Azure
        Sentinel in chunks
        :param subtype: The subtype of data being pushed. E.g. subtypes of
        alert is "dlp", "policy" etc.
        """
        sentinel_client = AzureSentinelClient(
            self.configuration,
            self.logger,
            self.ssl_validation,
            self.proxy,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        try:
            sentinel_client.push(
                transformed_data,
                data_type,
                sub_type=subtype,
                logger_msg=f"ingesting data into {PLUGIN_NAME}",
            )
        except AzureSentinelException as err:
            raise err
        except Exception as err:
            err_msg = (
                f"Error occurred while ingesting [{data_type}][{subtype}]."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err)

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform Netskope data (alerts/events) into Azure Sentinel
        Compatible data.

        :param data_type: Type of data to be transformed: Currently alerts
        and events
        :param raw_data: Raw data retrieved from Netskope which is supposed to
        be transformed
        :param subtype: The subtype of data being transformed

        :return List of alerts/events to be ingested
        """
        """
        Different cases related mapping file:

            1. If mapping file is not found or contains invalid JSON, all the
            data will be ingested
            2. If the file contains few valid fields, only that fields will be
            considered for ingestion
            3. Fields which are not in Netskope response, but are present in
            mappings file will be ignored with logs.
        """
        if self.configuration.get("transformData", True):
            error_message = (
                "Error occurred - this plugin only supports sharing of"
                f' JSON formatted data to {PLUGIN_NAME}: "{data_type}"'
                f' (subtype "{subtype}"). '
                "Transformation will be skipped."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise AzureSentinelException(error_message)

        skipped_logs = 0
        try:
            mappings = get_sentinel_mappings(self.mappings, data_type)
        except MappingValidationError as err:
            err_msg = "Mapping validation error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}] "
                    f"{err_msg} Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
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
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)

        transformed_data = []
        # First apply the filters based on the given mapping file
        subtype_mappings = self.get_subtype_mapping(mappings, subtype)
        for data in raw_data:
            try:
                if not subtype_mappings:
                    mapped_data = data
                else:
                    mapped_data = map_sentinel_data(subtype_mappings, data)
                if mapped_data:
                    """
                    Now we have filtered record as per the mapping file, so
                    we can proceed with transformation and data
                    normalization (like replacing characters other
                    than letters, numbers and underscores etc.)

                    First convert all the keys to lowercase, and all the
                    keys should only contain letters, numbers and
                    underscores(_).
                    """
                    transformed_record = {"tenant_name": self.source}
                    for key, value in mapped_data.items():
                        # Check whether the value exceeds the size limit of
                        # each field (32KB). Reference:
                        # https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api#data-limits
                        val_size = self._utf8len(str(value)) / 1000

                        # Skip the field and issue a log
                        if val_size > 32:
                            self.logger.error(
                                "{}: The size of the value for the key"
                                ' "{}" is {}KB which exceeds the maximum '
                                "threshold allowed of 32KB. Field will"
                                " be skipped.".format(
                                    self.log_prefix, key, val_size
                                )
                            )
                            continue

                        # Before normalization, first convert the data
                        # types of ID and timestamps to corresponding
                        # strings
                        value = self._convert_dtype(key, value)
                        if value is None:
                            continue

                        # Convert the key to lowercase
                        key = str(key).lower()

                        # Now check if it contains characters other than
                        # alphanumeric and underscores
                        key = self._normalize_key(key)

                        transformed_record[key] = value

                    transformed_data.append(transformed_record)
                else:
                    skipped_logs += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Could not transform data of"
                        f" [{data_type}][{subtype}]. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_logs += 1
        if skipped_logs > 0:
            self.logger.info(
                "{}: [{}][{}] Plugin couldn't process {} records because"
                " they either had no data or contained invalid/missing "
                "fields according to the configured JSON mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(
                    self.log_prefix, data_type, subtype, skipped_logs
                )
            )
        return transformed_data

    def _validate_auth_credentials(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate Auth Credentials.

        :param configuration (dict): Configuration parameters dictionary.

        :return ValidationResult: Validation Result.
        """
        try:
            sentinel_client = AzureSentinelClient(
                configuration,
                self.logger,
                self.ssl_validation,
                self.proxy,
                log_prefix=self.log_prefix,
                plugin_name=self.plugin_name,
                plugin_version=self.plugin_version,
            )
            sentinel_client.push(
                data=[],
                data_type="alerts",
                sub_type="",
                logger_msg="validating credentials",
                is_validation=True,
            )
        except AzureSentinelException as error:
            return ValidationResult(
                success=False,
                message=str(error),
            )
        except Exception as exp:
            err_msg = "Authentication Failed."
            self.logger.error(
                message="{} Error: {}".format(self.validation_msg, str(exp)),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        :param configuration (dict): Configuration parameters dictionary.

        :return ValidationResult: Validation Result.
        """
        sentinel_validator = AzureSentinelValidator(
            self.logger, self.log_prefix
        )
        self.validation_msg = f"{self.log_prefix}: Validation error occurred."
        workspace_id = configuration.get("workspace_id", "").strip()
        if configuration.get("transformData", True):
            err_msg = (
                "This plugin only supports JSON formatted data - "
                "Please disable the transformation toggle."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not workspace_id:
            err_msg = "Workspace ID is a required configuration parameter."
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(workspace_id, str):
            err_msg = (
                "Invalid Workspace ID found in the configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        primary_key = configuration.get("primary_key")
        if not primary_key:
            err_msg = "Primary key is a required configuration parameter."
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if not isinstance(primary_key, str):
            err_msg = (
                "Invalid Primary Key found in the configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        alert_log_type_name = configuration.get(
            "alerts_log_type_name", ""
        ).strip()
        if not alert_log_type_name:
            err_msg = (
                "Alerts Log Type Name is a required configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(alert_log_type_name, str):
            err_msg = (
                "Invalid Alerts Log Type Name found in the "
                "configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif len(alert_log_type_name) > 100:
            err_msg = (
                "Value of Alerts Log Type Name should not exceed the length of"
                " 100 characters."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not re.match(
            VALIDATION_ALPHANUM_PATTERN, alert_log_type_name
        ) or re.match(VALIDATION_DIGITS_PATTERN, alert_log_type_name):
            err_msg = (
                "Alerts Log Type Name should only contain letters, numbers and"
                " underscores. Also it should contain atleast 1 alphabet."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        events_log_type_name = configuration.get(
            "events_log_type_name", ""
        ).strip()
        if not events_log_type_name:
            err_msg = (
                "Events Log Type Name is a required configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(events_log_type_name, str):
            err_msg = (
                "Invalid Events Log Type Name found in "
                "the configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif len(events_log_type_name) > 100:
            err_msg = (
                "Value of Events Log Type Name should "
                "not exceed the length of 100 characters."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not re.match(
            VALIDATION_ALPHANUM_PATTERN, events_log_type_name
        ) or re.match(VALIDATION_DIGITS_PATTERN, events_log_type_name):
            err_msg = (
                "Events Log Type Name should only contain letters, numbers and"
                " underscores. Also it should contain atleast 1 alphabet."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        webtx_log_type_name = configuration.get(
            "webtx_log_type_name", ""
        ).strip()
        if not webtx_log_type_name:
            err_msg = (
                "WebTX Log Type Name is a required configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(webtx_log_type_name, str):
            err_msg = (
                "Invalid WebTX Log Type Name found in the "
                "configuration parameter."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif len(webtx_log_type_name) > 100:
            err_msg = (
                "Value of WebTX Log Type Name should not exceed the length of"
                " 100 characters."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not re.match(
            VALIDATION_ALPHANUM_PATTERN, webtx_log_type_name
        ) or re.match(VALIDATION_DIGITS_PATTERN, webtx_log_type_name):
            err_msg = (
                "WebTX Log Type Name should only contain letters, numbers and"
                " underscores. Also it should contain atleast 1 alphabet."
            )
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(
            mappings, dict
        ) or not sentinel_validator.validate_mappings(mappings):
            err_msg = "Invalid azure sentinel attribute mapping provided."
            self.logger.error(f"{self.validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_credentials(configuration)
