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
"""

"""Azure Sentinel Plugin."""


import re
import json
from typing import List

from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult
from .utils.sentinel_client import (
    AzureSentinelClient,
)
from .utils.sentinel_validator import (
    AzureSentinelValidator,
)
from .utils.sentinel_constants import (
    attribute_dtype_map,
)
from .utils.sentinel_exception import (
    MaxRetriesExceededError,
)
from .utils.sentinel_helper import (
    get_sentinel_mappings,
    map_sentinel_data,
    conversion_map,
)


class AzureSentinelPlugin(PluginBase):
    """The Netskope CLS plugin implementation class."""

    @staticmethod
    def get_subtype_mapping(mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events) case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which the mapping is to be fetched
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
        # The reason for encoding is that, in Python 3, some single-character strings will require multiple bytes to
        # be represented. For example chinese characters.
        return len(string.encode("utf-8"))

    def _convert_dtype(self, key, value):
        """Convert the data type of given value to string.

        :param key: The attribute name from the Netskope response
        :param value: The value of the given attribute whose data type is to be converted to string
        :return: value in form of String
        """
        if key in attribute_dtype_map:
            return conversion_map[attribute_dtype_map[key]](value)

        return value

    def _normalize_key(self, key, transform_map):
        """Normalize the given key by removing any special characters.

        :param key: The key string to be normalized
        :return: normalized key
        """
        # Check if it contains characters other than alphanumeric and underscores
        if not re.match(r"^[a-zA-Z0-9_]+$", key):
            # Replace characters other than underscores and alphanumeric
            transform_map[key] = re.sub(r"[^0-9a-zA-Z_]+", "_", key)
            key = transform_map[key]
        return key

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Azure Sentinel.

        :param data_type: The type of data being pushed. Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to Azure Sentinel in chunks
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """
        self.sentinel_client = AzureSentinelClient(
            self.configuration, self.logger, self.ssl_validation, self.proxy
        )
        try:
            self.sentinel_client.push(transformed_data, data_type)
        except MaxRetriesExceededError as err:
            # Raise this exception from here so that it does not update the checkpoint,
            # as this means data ingestion is failed even after a few retries.
            raise err

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform Netskope data (alerts/events) into Azure Sentinel Compatible data.

        :param data_type: Type of data to be transformed: Currently alerts and events
        :param raw_data: Raw data retrieved from Netskope which is supposed to be transformed
        :param subtype: The subtype of data being transformed

        :return List of alerts/events to be ingested
        """
        """
        Different cases related mapping file:

            1. If mapping file is not found or contains invalid JSON, all the data will be ingested
            2. If the file contains few valid fields, only that fields will be considered for ingestion
            3. Fields which are not in Netskope response, but are present in mappings file will be ignored with logs.
        """
        try:
            mappings = get_sentinel_mappings(self.mappings, data_type)
        except Exception as err:
            self.logger.error(
                "An error occurred while mapping data using given mapping strin.\
                    Error: {}.".format(
                    str(err)
                )
            )
            raise

        transformed_data = []
        for data in raw_data:
            transform_map = {}
            try:
                # First apply the filters based on the given mapping file
                subtype_mappings = self.get_subtype_mapping(mappings, subtype)

                # If subtype mappings are provided, use only those fields, otherwise map all the fields
                if subtype_mappings:
                    data = map_sentinel_data(
                        subtype_mappings, data, self.logger, data_type, subtype
                    )

                """
                Now we have filtered record as per the mapping file, so we can proceed with transformation and data
                normalization (like replacing characters other than letters, numbers and underscores etc.)

                First convert all the keys to lowercase, and all the keys should only contain letters, numbers and
                underscores(_).
                """
                transformed_record = {"tenant_name": self.source}
                for key, value in data.items():

                    # Check whether the value exceeds the size limit of each field (32KB). Reference:
                    # https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api#data-limits
                    val_size = self._utf8len(str(value)) / 1000

                    # Skip the field and issue a log
                    if val_size > 32:
                        self.logger.warn(
                            'The size of the value for the key "{}" is {}KB which exceeds the maximum '
                            "threshold allowed of 32KB. Field will be skipped.".format(
                                key, val_size
                            )
                        )
                        continue

                    # Before normalization, first convert the data types of ID and timestamps to corresponding strings
                    value = self._convert_dtype(key, value)

                    # Convert the key to lowercase
                    key = str(key).lower()

                    # Now check if it contains characters other than alphanumeric and underscores
                    key = self._normalize_key(key, transform_map)

                    transformed_record[key] = value

                transformed_data.append(transformed_record)
            except Exception as err:
                self.logger.error(
                    "Could not transform data \n{}.\n Error:{}".format(
                        data, err
                    )
                )

        return transformed_data

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        sentinel_validator = AzureSentinelValidator(self.logger)

        if (
            "workspace_id" not in configuration
            or type(configuration["workspace_id"]) != str
            or not configuration["workspace_id"].strip()
        ):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Invalid workspace ID in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid workspace ID provided."
            )

        if (
            "primary_key" not in configuration
            or type(configuration["primary_key"]) != str
            or not configuration["primary_key"].strip()
        ):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Invalid primary key in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid primary key provided."
            )

        if (
            "alerts_log_type_name" not in configuration
            or type(configuration["alerts_log_type_name"]) != str
            or not configuration["alerts_log_type_name"].strip()
        ):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Invalid Alert Log Type Name in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Alert Log Type Name provided."
            )

        if len(configuration["alerts_log_type_name"]) > 100:
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Log Type Name for alerts should not exceed the length of 100 characters."
            )
            return ValidationResult(
                success=False,
                message="Log Type Name for alerts should not exceed the length of 100 characters.",
            )

        if not re.match(
            r"^[a-zA-Z0-9_]+$", str(configuration["alerts_log_type_name"])
        ) or re.match(r"^[\d_]+$", str(configuration["alerts_log_type_name"])):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Log Type Name for alerts should only contain letters, numbers and underscores. "
                "Log Type Name should contain atleast 1 letter."
            )
            return ValidationResult(
                success=False,
                message="Log Type Name for alerts should only contain letters, numbers and underscores. "
                "Log Type Name should contain atleast 1 letter.",
            )

        if (
            "events_log_type_name" not in configuration
            or type(configuration["events_log_type_name"]) != str
            or not configuration["events_log_type_name"].strip()
        ):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Invalid Event Log Type Name in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Event Log Type Name provided."
            )

        if len(configuration["events_log_type_name"]) > 100:
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Log Type Name for events should not exceed the length of 100 characters."
            )
            return ValidationResult(
                success=False,
                message="Log Type Name for events should not exceed the length of 100 characters.",
            )

        if not re.match(
            r"^[a-zA-Z0-9_]+$", str(configuration["events_log_type_name"])
        ) or re.match(r"^[\d_]+$", str(configuration["events_log_type_name"])):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Log Type Name for events should only contain letters, numbers and underscores. "
                "Log Type Name should contain atleast 1 letter."
            )
            return ValidationResult(
                success=False,
                message="Log Type Name for events should only contain letters, numbers and underscores. "
                "Log Type Name should contain atleast 1 letter.",
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if type(mappings) != dict or not sentinel_validator.validate_mappings(
            mappings
        ):
            self.logger.error(
                "Azure Sentinel Plugin: Validation error occurred. Error: "
                "Invalid azure sentinel attribute mapping found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid azure sentinel attribute mapping provided.",
            )

        return ValidationResult(success=True, message="Validation successful.")
