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

"""AWS S3 Events, Alerts Plugin."""


import os
import json
from typing import List
from tempfile import NamedTemporaryFile

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
    BucketNameAlreadyTaken
)
from .utils.aws_s3_events_alerts_helper import (
    get_mappings,
    map_data
)


class AWSS3EventsAlertsPlugin(PluginBase):
    """The AWS S3 Events, Alerts plugin implementation class."""
    
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

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        try:
            mappings = get_mappings(self.mappings, data_type)
        except Exception as err:
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: An error occurred while mapping data using given mapping [{}][{}].\
                    Error: {}.".format(
                    data_type, subtype, str(err)
                )
            )
            raise
        transformed_data = []
        for data in raw_data:
            try:
                # First apply the filters based on the given mapping file
                subtype_mappings = self.get_subtype_mapping(mappings, subtype)
                if subtype_mappings:
                    data = map_data(
                        subtype_mappings, data, self.logger, data_type, subtype
                    )
                if data:
                    transformed_data.append(data)
            except Exception as err:
                self.logger.error(
                    "AWS S3 Events, Alerts Plugin: Could not transform data of [{}][{}]. Error:{}".format(
                        data_type, subtype, err
                    )
                )      
        return transformed_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        try:
            aws_client = AWSS3EventsAlertsClient(
                self.configuration, self.logger, self.proxy
            )

            temp_obj_file = NamedTemporaryFile("w", delete=False)
            temp_obj_file.write(json.dumps(transformed_data))
            temp_obj_file.flush()

            try:
                aws_client.push(temp_obj_file.name, data_type, subtype)
            except Exception:
                raise
            finally:
                temp_obj_file.close()
                os.unlink(temp_obj_file.name)
        except Exception as e:
            self.logger.error(f"AWS S3 Events, Alerts Plugin: Error while pushing to AWS S3 [{data_type}][{subtype}]: {e}")
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        aws_validator = AWSS3EventsAlertsValidator(self.logger, self.proxy)
        
        if configuration.get("transformData", False):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "This Plugin is designed to send raw data to S3 Bucket - Please disable the toggle 'Transform the raw logs' to continue."
            )
            return ValidationResult(
                success=False,
                message="This Plugin is designed to send raw data to S3 Bucket - Please disable the toggle 'Transform the raw logs' to continue.",
            )

        if (
            "aws_public_key" not in configuration
            or type(configuration["aws_public_key"]) != str
            or not configuration["aws_public_key"].strip()
        ):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid AWS Access Key ID (Public Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Access Key ID (Public Key) provided.",
            )

        if (
            "aws_private_key" not in configuration
            or type(configuration["aws_private_key"]) != str
            or not configuration["aws_private_key"].strip()
        ):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid AWS Secret Access Key (Private Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Secret Access Key (Private Key) provided.",
            )

        if (
            "region_name" not in configuration
            or type(configuration["region_name"]) != str
            or not aws_validator.validate_region_name(
                configuration["region_name"]
            )
        ):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid Region Name found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Region Name provided.",
            )

        if (
            "bucket_name" not in configuration
            or type(configuration["bucket_name"]) != str
            or not configuration["bucket_name"].strip()
        ):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid Bucket Name found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Bucket Name provided."
            )

        if (
            "obj_prefix" not in configuration
            or type(configuration["obj_prefix"]) != str
            or not configuration["obj_prefix"].strip()
        ):
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid Object Prefix found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Object Prefix provided."
            )

        try:
            aws_validator.validate_credentials(
                configuration["aws_public_key"].strip(),
                configuration["aws_private_key"].strip(),
            )
        except Exception:
            self.logger.error(
                "AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Invalid AWS Access Key ID (Public Key) and AWS Secret Access Key "
                "(Private Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Access Key ID (Public Key) or AWS Secret Access "
                "Key (Private Key) found in the configuration parameters.",
            )

        try:
            aws_client = AWSS3EventsAlertsClient(configuration, self.logger, self.proxy)
            aws_client.get_bucket()
        except BucketNameAlreadyTaken:
            self.logger.error(
                f"AWS S3 Events, Alerts Plugin: Validation error occurred. Error: "
                "Provided bucket name already exists at a different region. Please try with different name or use the correct region."
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Provided bucket name already exists at a different region. Please try with different name or use the correct region.",
            )
        except Exception as err:
            self.logger.error(
                f"AWS S3 Events, Alerts Plugin: Validation error occurred. Error: {err}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")
