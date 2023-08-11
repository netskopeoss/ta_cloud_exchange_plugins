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
from datetime import datetime

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
    BucketNameAlreadyTaken,
)

from netskope.integrations.cls.utils.converter import type_converter
from netskope.common.utils import add_user_agent

MODULE_NAME = "CLS"
PLUGIN_NAME = "Amazon Security Lake"
PLUGIN_VERSION = "1.1.0"


class AmazonSecurityLakePluginException(Exception):
    """AmazonSecurityLakePluginException custom exception class."""
    pass


class CustomTransformedData:
    """Custom Transform Data Class"""

    def __init__(self, data: dict):
        self.data = data

    def __len__(self):
        items = list(self.data.keys())
        if not items:
            return 0
        return len(self.data[items[0]])


class AmazonSecurityLakePlugin(PluginBase):
    """The Amazon Security Lake plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize AmazonSecurityLakePlugin class."""
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
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", "")
                return (plugin_name, plugin_version)

        except Exception:
            return (PLUGIN_NAME, PLUGIN_VERSION)

    def _add_user_agent(self, header=None):
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        plugin_version = self._get_plugin_info()

        header = add_user_agent(header)
        header.update(
            {
                "User-Agent": f"{header.get('User-Agent', 'netskope-ce')}-cls-amazon_security_lake-v{plugin_version[1]}",
            }
        )
        return str(header)

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings (mappings for subtypes of \
            alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the \
                mapping is to be fetched

        Returns:
            Fetched mapping JSON object
        """
        try:
            mappings = {k.lower(): v for k, v in mappings.items()}
            if subtype.lower() in mappings:
                return mappings[subtype.lower()]
            else:
                return mappings[subtype.upper()]
        except Exception:
            raise

    def _transform_value(
        self,
        data_type,
        subtype,
        field,
        value,
        transformation
    ):
        transformed_value = None
        converters = type_converter()
        extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )
        try:
            transformed_value = extension_converter(
                key_name=field, converter=converters[transformation]
            ).converter(value, field)
        except Exception as e:
            error_message = (
                f"{self.log_prefix}: [{data_type}][{subtype}]- "
                f'An error occurred while transforming data for field: "{field}". '
                f"Error: {str(e)}. "
                "'None' will be sent as field value."
            )
            self.logger.debug(
                error_message
            )
        return transformed_value

    def _transform_and_append(
        self,
        data_type: str,
        subtype: str,
        data: dict,
        mappings: dict,
        table: dict
    ):
        temp_json = {}
        for field, mapping_dict in mappings.items():
            value = None
            if "mapping_field" in mapping_dict:
                if mapping_dict["mapping_field"] == "date:time":
                    try:
                        if data.get("date") and data.get("time"):
                            date_time = f"{data['date']}T{data['time']}Z"
                            value = int(datetime.strptime(date_time, "%Y-%m-%dT%H:%M:%SZ").timestamp())
                            del data["date"]
                            del data["time"]
                        else:
                            return
                    except:
                        return

                elif mapping_dict["mapping_field"] in data:
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
        try:
            temp_json["data"] = {"data": json.dumps(data)}
        except Exception:
            error_message = (
                f"{self.log_prefix}: Error occurred - "
                'sending unmapped data to Amazon Security Lake will be '
                f'skipped: "{data_type}" (subtype "{subtype}"). '
            )
            self.logger.error(
                message=error_message,
                details=traceback.format_exc()
            )
        converted_json = unflatten(temp_json)

        updated_observables = []
        for observable in converted_json.get("observables", []):
            if observable.get("value") and observable.get("value") != "None":
                updated_observables.append(observable)
        converted_json["observables"] = updated_observables

        updated_enrichments = []
        for enrichment in converted_json.get("enrichments", []):
            if not enrichment.get("data"):
                enrichment["data"] = {"data": ""}
            else:
                enrichment["data"] = {"data": json.dumps(enrichment.get("data", {}))}
            if(
                enrichment.get("value", None) and
                not(
                    "value not available" in enrichment.get(
                        "value", "value not available"
                    ) and not enrichment.get("data", {}).get("data")
                )
            ):
                updated_enrichments.append(enrichment)
        converted_json["enrichments"] = updated_enrichments

        for key, value in converted_json.items():
            if key not in table:
                table[key] = [value]
            else:
                table[key].append(value)

    def _get_key(self, key):
        key = key.split(".")[0]
        if re.search(r"\[\d+\]", key):
            index = len(key) - 1
            while index >= 0:
                if key[index] == "[":
                    key = key[:index]
                    break
                index -= 1
        return key

    def transform(self, raw_data, data_type, subtype) -> CustomTransformedData:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested
            (alert/event/webtx)
            subtype (str): The subtype of data to be ingested (DLP,
            anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            CustomTransformedData: Dictionary of transformed data.
        """
        if not self.configuration.get("transformData", True):
            error_message = (
                f'{self.log_prefix}: Error occurred - '
                f'cannot send raw data to Amazon Security Lake: "{data_type}"'
                f' (subtype "{subtype}"). '
                "Transformation will be skipped."
            )
            self.logger.error(
                message=error_message,
                details=traceback.format_exc()
            )
            raise AmazonSecurityLakePluginException(error_message)
        else:
            table = {}
            table["data"] = []
            try:
                amazon_security_lake_subtype_mapping = self.get_subtype_mapping(
                    self.mappings["taxonomy"][data_type],
                    subtype
                )
            except KeyError as err:
                error_message = (
                    f"{self.log_prefix}: Error occurred while "
                    f"retrieving mappings for datatype '{data_type}', "
                    f"subtype '{subtype}'. "
                    "Transformation of current data will be skipped."
                )
                self.logger.error(
                    message=error_message,
                    details=traceback.format_exc()
                )
                raise AmazonSecurityLakePluginException(err)
            try:
                for key in amazon_security_lake_subtype_mapping["extension"].keys():
                    key = self._get_key(key)
                    table[key] = []
                for data in raw_data:
                    self._transform_and_append(
                        data_type, subtype,
                        data,
                        amazon_security_lake_subtype_mapping["extension"],
                        table
                    )
                return CustomTransformedData(data=table)
            except Exception as e:
                self.logger.error(
                    f"{self.log_prefix}: Error - "
                    f"{(str(e))}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakePluginException(e)

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        try:
            user_agent = self._add_user_agent()
            aws_client = AmazonSecurityLakeClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
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
            error_mesage = (
                f"{self.log_prefix}: Following error occurred "
                f"while pushing to Amazon Security Lake - {e}"
            )
            self.logger.error(
                message=error_mesage,
                details=traceback.format_exc()
            )
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        aws_validator = AmazonSecurityLakeValidator(
            configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix
        )

        if not configuration.get("transformData", True):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                "Error: Cannot send raw data to Amazon Security Lake - "
                "Please enable the toggle 'Transform the raw logs'."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Cannot send raw data to Amazon Security Lake - "
                    "Please enable the toggle 'Transform the raw logs'."
                ),
            )

        if (
            "authentication_method" not in configuration
            or not configuration.get("authentication_method", "").strip()
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                "Error: Authentication Method is a required field."
            )
            return ValidationResult(
                success=False,
                message="Authentication Method is a required field."
            )

        if configuration.get("authentication_method", "").strip() not in [
            "aws_iam_roles_anywhere",
            "deployed_on_aws",
        ]:
            error_msg = (
                "Error: Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
                )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred "
                f"{error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )

        if configuration.get("authentication_method", "").strip() == "aws_iam_roles_anywhere":
            if (
                "private_key_file" not in configuration
                or not configuration.get("private_key_file", "").strip()
            ):
                error_msg = (
                    "Private Key File is a required field when "
                    "'AWS IAM Roles Anywhere' is selected as "
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
            elif type(configuration.get("private_key_file", "").strip()) != str:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Private Key File found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Private Key File provided.",
                )

            if (
                "public_certificate_file" not in configuration
                or not configuration.get("public_certificate_file", "").strip()
            ):
                error_msg = (
                    "Certificate Body is a required field when "
                    "'AWS IAM Roles Anywhere' is selected as "
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
            elif type(configuration.get("public_certificate_file", "").strip()) != str:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Public Certificate provided.",
                )

            if(
                "profile_arn" not in configuration
                or not configuration.get("profile_arn", "").strip()
            ):
                error_msg = (
                    "Profile ARN is a required field when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}"
                )

            elif type(configuration.get("profile_arn", "").strip()) != str:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"Invalid Profile ARN found in the configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Profile ARN provided."
                )

            if(
                "role_arn" not in configuration
                or not configuration.get("role_arn", "").strip()
            ):
                error_msg = (
                    "Role ARN is a required field when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}"
                )

            elif type(configuration.get("role_arn", "").strip()) != str:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"Invalid Role ARN found in the configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Role ARN provided."
                )

            if (
                "trust_anchor_arn" not in configuration
                or not configuration.get("trust_anchor_arn", "").strip()
            ):
                error_msg = (
                    "Trust Anchor ARN is a required field when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}"
                )

            elif type(configuration.get("trust_anchor_arn", "").strip()) != str:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Trust Anchor ARN provided."
                )

        if (
            "region_name" not in configuration
            or type(configuration.get("region_name", "").strip()) != str
            or not aws_validator.validate_region_name(
                configuration.get("region_name", "").strip()
            )
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                "Error: Invalid AWS S3 Source Bucket Region found in the "
                "configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS S3 Source Bucket Region provided.",
            )

        if (
            "bucket_name" not in configuration
            or not configuration.get("bucket_name", "").strip()
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                "Error: AWS S3 Source Bucket is a required parameter."
            )
            return ValidationResult(
                success=False, message="AWS S3 Source Bucket is a required parameter."
            )

        if (
            type(configuration.get("bucket_name", "").strip()) != str
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                "Error: Invalid AWS S3 Source Bucket found in the "
                "configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid AWS S3 Source Bucket provided."
            )

        try:
            user_agent = self._add_user_agent()
            aws_client = AmazonSecurityLakeClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
        except Exception as err:
            error_msg = "Invalid authentication parameters provided."
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. Error: {err}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )

        try:
            aws_client.get_bucket()
        except BucketNameAlreadyTaken:
            error_msg = (
                f"{self.log_prefix}: Validation error occurred. "
                "Error: Provided AWS S3 Source Bucket already exists at a "
                "different region. Please try with different name or "
                "use the correct region."
            )
            self.logger.error(
                message=error_msg,
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=(
                    "Validation Error. Provided AWS S3 Source Bucket already exists "
                    "at a different region. Please try with different name "
                    "or use the correct region."
                ),
            )
        except ValueError as err:
            error_msg = (
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err}"
            )
            self.logger.error(
                message=error_msg,
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Check logs for more details.",
            )
        except Exception as err:
            error_msg = (
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err}"
            )
            self.logger.error(
                message=error_msg,
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")
