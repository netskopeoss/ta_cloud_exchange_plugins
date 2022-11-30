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

"""Amazon Security Lake Plugin."""


import os
import re
import json
import traceback
import collections
from tempfile import NamedTemporaryFile
from .lib.unflatten import unflatten

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.amazon_security_lake_validator import (
    AmazonSecurityLakeValidator,
)
from .utils.amazon_security_lake_client import (
    AmazonSecurityLakeClient,
    BucketNameAlreadyTaken
)

from netskope.integrations.cls.utils.converter import type_converter

class CustomTransformedData:
    def __init__(self, data: dict):
        self.data = data

    def __len__(self):
        items = list(self.data.keys())
        if not items:
            return 0
        return len(self.data[items[0]])


class AmazonSecurityLakePlugin(PluginBase):
    """The Amazon Security Lake plugin implementation class."""

    def _transform_value(self, data_type, subtype, field, value, transformation):
        transformed_value = None
        converters = type_converter()
        extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )
        try: 
            transformed_value = extension_converter(
                key_name=field,
                converter=converters[transformation]
            ).converter(value, field)
        except Exception as e:
            self.logger.error(
                'Amazon Security Lake Plugin: [{}][{}]- An error occurred while transforming data for field: "{}". Error: {}. '
                "'None' will be sent as field value.".format(
                    data_type, subtype, field, str(e)
                )
            )
        return transformed_value

    def _transform_and_append(self, data_type: str, subtype: str, data: dict, mappings: dict, table: dict):
        temp_json = {}
        for field, mapping_dict in mappings.items():
            value = None
            if "mapping_field" in mapping_dict:
                if mapping_dict["mapping_field"] in data:
                    value = self._transform_value(
                            data_type,
                            subtype,
                            field,
                            data[mapping_dict["mapping_field"]],
                            mapping_dict.get("transformation", None),
                        )
                    del data[mapping_dict["mapping_field"]]
                elif "default_value" in mapping_dict:
                    value = mapping_dict["default_value"]
            elif "default_value" in mapping_dict:
                value = mapping_dict["default_value"]
            temp_json[field] = value
        temp_json["data"] = data
        converted_json = unflatten(temp_json)
        for key, value in converted_json.items():
            table[key].append(value)
                
    def _get_key(self, key):
        key = key.split(".")[0]
        if re.search(r"\[\d+\]", key):
            index = len(key) - 1
            while (index >= 0):
                if key[index] == "[":
                    key = key[:index]
                    break
                index -= 1
        return key

    def transform(self, raw_data, data_type, subtype) -> CustomTransformedData:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event/webtx)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            CustomTransformedData: Dictionary of transformed data.
        """
        if not self.configuration.get("transformData", True):
            self.logger.error(
                'Amazon Security Lake Plugin: Error occurred - cannot send raw data to Amazon Security Lake: "{}" (subtype "{}"). '
                "Transformation will be skipped.".format(
                    data_type, subtype
                )
            )
            return None
        else:
            table = {}
            table["data"] = []
            try:
                try:
                    mappings = self.mappings["taxonomy"][data_type][subtype]["extension"]
                except KeyError:
                    self.logger.error(
                        f"Amazon Security Lake Plugin: Error occurred while retrieving mappings for datatype '{data_type}', subtype '{subtype}'. "
                        "Transformation of current data will be skipped."
                    )
                    return None
                for key in mappings.keys():
                    key = self._get_key(key)
                    table[key] = []
                for data in raw_data:
                    self._transform_and_append(data_type, subtype, data, mappings, table)
                return CustomTransformedData(data=table)
            except Exception as e:
                self.logger.error(
                    "Amazon Security Lake Plugin: Error - {}".format(str(e)),
                    details=traceback.format_exc(),
                )

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        try:
            aws_client = AmazonSecurityLakeClient(
                self.configuration, self.logger, self.proxy
            )
            data = json.dumps(transformed_data.data)
            temp_obj_file = NamedTemporaryFile("w", delete=False)
            temp_obj_file.write(data)
            temp_obj_file.flush()
            try:
                aws_client.push(temp_obj_file.name, data_type, subtype)
            except Exception:
                raise
            finally:
                temp_obj_file.close()
                os.unlink(temp_obj_file.name)

        except Exception as e:
            self.logger.error(f"Amazon Security Lake Plugin: Following error occured while pushing to Amazon Security Lake - {e}")
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        aws_validator = AmazonSecurityLakeValidator(self.logger, self.proxy)

        if not configuration.get("transformData", True):
            self.logger.error(
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
                "Cannot send raw data to Amazon Security Lake - Please enable the toggle 'Transform the raw logs'."
            )
            return ValidationResult(
                success=False,
                message="Cannot send raw data to Amazon Security Lake - Please enable the toggle 'Transform the raw logs'.",
            )
            
        if (
            "aws_public_key" not in configuration
            or type(configuration["aws_public_key"]) != str
            or not configuration["aws_public_key"].strip()
        ):
            self.logger.error(
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
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
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
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
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
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
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
                "Invalid Bucket Name found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Bucket Name provided."
            )

        try:
            aws_validator.validate_credentials(
                configuration["aws_public_key"].strip(),
                configuration["aws_private_key"].strip(),
            )
        except Exception:
            self.logger.error(
                "Amazon Security Lake Plugin: Validation error occurred. Error: "
                "Invalid AWS Access Key ID (Public Key) or AWS Secret Access Key "
                "(Private Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Access Key ID (Public Key) or AWS Secret Access "
                "Key (Private Key) found in the configuration parameters.",
            )

        try:
            aws_client = AmazonSecurityLakeClient(configuration, self.logger, self.proxy)
            aws_client.get_bucket()
        except BucketNameAlreadyTaken:
            self.logger.error(
                f"Amazon Security Lake Plugin: Validation error occurred. Error: "
                "Provided bucket name already exists at a different region. Please try with different name or use the correct region."
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Provided bucket name already exists at a different region. Please try with different name or use the correct region.",
            )
        except Exception as err:
            self.logger.error(
                f"Amazon Security Lake Plugin: Validation error occurred. Error: {err}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")
