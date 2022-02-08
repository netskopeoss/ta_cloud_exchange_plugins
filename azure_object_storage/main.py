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

"""Azure Plugin."""


import re
import os
from typing import List
from azure.storage.blob import BlobServiceClient
from tempfile import NamedTemporaryFile
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.azure_validator import (
    AzureValidator,
)
from .utils.azure_client import (
    AzureClient,
)

REGEX_FOR_CONTAINER = r"^(?!-)(?!.*--)[A-Za-z0-9-]+(?<!-)$"


class AzurePlugin(PluginBase):
    """The Netskope CLS plugin implementation class."""

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Azure.

        :param data_type: The type of data being pushed. Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to Azure in chunks
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """
        try:
            self.azure_client = AzureClient(self.configuration, self.logger, self.proxy)
            temp_obj_file = NamedTemporaryFile("wb", delete=False)
            for data in transformed_data:
                temp_obj_file.write(data)
            temp_obj_file.flush()
            try:
                self.azure_client.push(temp_obj_file.name, data_type, subtype)
            except Exception:
                raise
            finally:
                temp_obj_file.close()
                os.unlink(temp_obj_file.name)
        except Exception as e:
            self.logger.error(
                f"Error while pushing to Azure Storage Plugin: {e}"
            )
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        azure_validator = AzureValidator(self.logger)
        if (
            "azure_connection_string" not in configuration
            or type(configuration["azure_connection_string"]) != str
            or not configuration["azure_connection_string"].strip()
        ):
            self.logger.error(
                "Azure Storage Plugin: Validation error occurred. Error: "
                "Invalid azure connection string in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Connection String provided."
            )
        try:
            blob_service_client = BlobServiceClient.from_connection_string(
                configuration["azure_connection_string"]
            )
            name = []
            list_container = blob_service_client.list_containers(
                name_starts_with=None, timeout=1, proxies=self.proxy
            )
            for i in list_container:
                name.append(i["name"])
        except Exception:
            self.logger.error(
                "Azure Storage Plugin: Validation error occurred. Error: "
                "Invalid Connection String in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Connection String provided."
            )

        if (
            "container_name" not in configuration
            or not configuration["container_name"].strip()
            or not configuration["container_name"].islower()
            or not len(configuration["container_name"]) > 2
            or not len(configuration["container_name"]) < 64
            or not re.compile(REGEX_FOR_CONTAINER).match(
                configuration["container_name"].strip()
            )
        ):
            self.logger.error(
                "Azure Storage Plugin: Validation error occurred. Error: "
                "Invalid Container Name in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Container Name provided."
            )

        if (
            "max_file_size" not in configuration
            or not azure_validator.validate_max_file_size(
                configuration["max_file_size"]
            )
        ):
            self.logger.error(
                "Azure Storage Plugin: Validation error occurred. Error: "
                "Invalid Max File Size found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max File Size provided."
            )

        if (
            "max_duration" not in configuration
            or not azure_validator.validate_max_duration(
                configuration["max_duration"]
            )
        ):
            self.logger.error(
                "Azure Storage Plugin: Validation error occurred. Error: "
                "Invalid Max Duration found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max Duration provided."
            )

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform Netskope data (alerts/events) into Azure Sentinel Compatible data.

        :param data_type: Type of data to be transformed: Currently alerts and events
        :param raw_data: Raw data retrieved from Netskope which is supposed to be transformed
        :param subtype: The subtype of data being transformed

        :return List of alerts/events to be ingested

        Different cases related mapping file:

            1. If mapping file is not found or contains invalid JSON, all the data will be ingested
            2. If the file contains few valid fields, only that fields will be considered for ingestion
            3. Fields which are not in Netskope response, but are present in mappings file will be ignored with logs.
        """
        return raw_data
