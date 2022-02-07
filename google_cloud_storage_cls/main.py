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

"""GCP Storage Plugin."""


import os
from typing import List
from tempfile import NamedTemporaryFile
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult
from .utils.gcp_validator import (
    GCPValidator,
)
from .utils.gcp_client import (
    GCPClient,
)


class GCPStoragePlugin(PluginBase):
    """The GCP Storage plugin implementation class."""

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to GCP Storage by creating a authenticated session with GCP.

        :param data_type: The type of data being pushed. Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to GCP in chunks of 1
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """
        try:
            gcp_client = GCPClient(self.configuration, self.logger)

            temp_obj_file = NamedTemporaryFile("wb", delete=False)
            for data in transformed_data:
                temp_obj_file.write(data)
            temp_obj_file.flush()

            try:
                gcp_client.push(temp_obj_file.name, data_type, subtype)
            except Exception:
                raise
            finally:
                temp_obj_file.close()
                os.unlink(temp_obj_file.name)
        except Exception as e:
            self.logger.error(f"Error while pushing to GCP Storage: {e}")
            raise

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform a Netskope alerts into a Google Cloud Security Command Center Finding.

        :param data_type: Type of data to be transformed: Currently webtx
        :param raw_data: Raw data retrieved from pub/sub which is supposed to be transformed
        :param subtype: The subtype of data being transformed

        :return: list of transformed data.
        """
        return raw_data

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration of cscc plugin.

        Args:
            configuration (dict): dictionary containing all parameters to be validated

        Returns:
            ValidationResult: class that contains the success status of the configurations
        """
        gcp_validator = GCPValidator(self.logger)
        if (
            "key_file" not in configuration
            or type(configuration["key_file"]) != str
            or not configuration["key_file"].strip()
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Key File found in configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid key file provided"
            )
        if (
            "bucket_name" not in configuration
            or type(configuration["bucket_name"]) != str
            or not configuration["bucket_name"].strip()
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Bucket Name found in the configuration parameter"
            )
            return ValidationResult(
                success=False, message="Invalid Bucket Name provided."
            )
        if (
            "location" not in configuration
            or type(configuration["location"]) != str
            or not gcp_validator.validate_location_name(
                configuration["location"].strip()
            )
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Region(s) Name found in configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid Region(s) Name provided."
            )
        if (
            "storage_class" not in configuration
            or type(configuration["storage_class"]) != str
            or not gcp_validator.validate_storage_class(
                configuration["storage_class"].strip()
            )
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Storage class found in configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid storage class provided."
            )
        if (
            "obj_prefix" not in configuration
            or type(configuration["obj_prefix"]) != str
            or not configuration["obj_prefix"].strip()
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Object Prefix found in the configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid Object Prefix provided."
            )
        if (
            "max_file_size" not in configuration
            or not gcp_validator.validate_max_file_size(
                configuration["max_file_size"]
            )
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Max File Size found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max File Size provided."
            )
        if (
            "max_duration" not in configuration
            or not gcp_validator.validate_max_duration(
                configuration["max_duration"]
            )
        ):
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid Maximum Duration found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Maximum Duration provided."
            )
        try:
            gcp_validator.auth_key_file_and_create_bucket(
                configuration["key_file"].strip(),
                configuration["bucket_name"].strip(),
                configuration["location"].strip(),
                configuration["storage_class"].strip(),
            )
        except Exception:
            return ValidationResult(
                success=False,
                message="Invalid key file/Bucket Name provided in configuration parameters. Check logs.",
            )

        return ValidationResult(success=True, message="Validation successful.")
