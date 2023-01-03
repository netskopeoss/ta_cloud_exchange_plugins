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

"""Microsoft Azure Monitor Plugin."""

import datetime
import json
import sys
from time import sleep
from typing import List
from jsonpath import jsonpath
import requests

from netskope.integrations.cls.plugin_base import(
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import AlertsHelper
from .utils.monitor_validator import (
    AzureMonitorValidator,
)
from .utils.monitor_helper import (
    get_monitor_mappings,
)
from .utils.monitor_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    MonitorAuthTokenException,
    MicrosoftAzureMonitorPluginException,
)
from .utils.monitor_cef_generator import (
    CEFGenerator,
)


def chunks(transformed_data):
    """Divide list of transformed data into chunks of 1mb each"""
    transformed_data_chunks = []
    temp_chunks= []
    size_of_chunk = 0
    for data in transformed_data:
        size_of_chunk += sys.getsizeof(f"{data}") / (1024 * 1024)
        if size_of_chunk < 1:
            temp_chunks.append(data)
        else:
            if temp_chunks:
                transformed_data_chunks.append(temp_chunks)
                temp_chunks = []
                size_of_chunk = sys.getsizeof(f"{data}") / (1024 * 1024)
    return transformed_data_chunks

class AzureMonitorPlugin(PluginBase):
    """The Microsoft Azure Monitor CLS plugin implementation class."""

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

    def generate_auth_token(self, tenantid, appid, appsecret):
        try:
            url = f"https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/token"
            body = {
                "client_id": f"{appid}",
                "client_secret": f"{appsecret}",
                "scope": "https://monitor.azure.com//.default",
                "grant_type": "client_credentials",
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            resp = requests.get(
                url, data=body,
                headers=headers,
                proxies=self.proxy
            )
            if resp.status_code != 200:
                err_msg = resp.json().get("error", {}).get("message")
                raise MonitorAuthTokenException(
                    err_msg
                )
            auth_token = resp.json().get("access_token")
            if not auth_token:
                raise MonitorAuthTokenException(
                    "Unable to fetch the access token"
                )
            return {"Authorization": f"Bearer {auth_token}"}
        except Exception as e:
            self.logger.error(
                "Unable to Generate Access Token using provided credentials."
            )
            return None

    def push_data_to_monitor(
        self, header, url_endpoint, transformed_data, retry_count=1
    ):
        try:
            push_resp = requests.post(
                url_endpoint,
                headers=header,
                json=transformed_data,
                proxies=self.proxy
            )
            if push_resp.status_code == 429:
                retry_after = push_resp.headers.get("Retry-After", 60)
                if retry_count <= 3 and retry_after.isdigit() and int(retry_after) <= 300:
                    self.logger.info(
                        "Plugin: Microsoft Azure Monitor, 429 Client Error - "
                        "Too Many Requests, Retrying after "
                        f"{retry_after} seconds"
                    )
                    sleep(int(retry_after))
                    return self.push_data_to_monitor(
                        header, url_endpoint, transformed_data, retry_count + 1
                    )
            return push_resp
        except Exception as err:
            err_msg = f"Error occurred :{err}"
            self.logger.info(
                f"Microsoft Azure Monitor CLS Plugin: {err_msg}"
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Microsoft Azure Monitor.

        :param data_type: The type of data being pushed.
         Current possible values: alerts, events and webtx
        :param transformed_data: Transformed data to be ingested to
        Microsoft Azure Monitor in chunks
        :param subtype: The subtype of data being pushed.
        E.g. subtypes of alert is "dlp", "policy" etc.
        """

        batch_size = sys.getsizeof(f"{transformed_data}") / (1024 * 1024)
        if batch_size > 1:
            transformed_data = chunks(transformed_data)
        else:
            transformed_data = [transformed_data]

        url_endpoint = (
            f"{self.configuration['dce_uri'].strip()}/"
            f"dataCollectionRules/{self.configuration['dcr_immutable_id'].strip()}/"
            f"streams/Custom-{self.configuration['custom_log_table_name'].strip()}?api-version=2021-11-01-preview"
        )
        header = self.generate_auth_token(
            self.configuration["tenantid"].strip(),
            self.configuration["appid"].strip(),
            self.configuration["appsecret"].strip(),
        )
        if not header:
            raise MonitorAuthTokenException(
                "Unable to Generate Access Token for the provided "
                "Application credentials"
            )
        try:
            for chunk in transformed_data:
                push_resp = self.push_data_to_monitor(
                    header,
                    url_endpoint,
                    chunk
                )
                if push_resp.status_code != 204:
                    if push_resp.status_code == 429:
                        message = (
                            "Microsoft Azure Monitor CLS Plugin: Received error code 429. "
                            "Retry after some time."
                        )
                        self.logger.error(message)
                        raise MicrosoftAzureMonitorPluginException(message)
                    error_response = push_resp.json()
                    err_message = error_response.get("error", {}).get("message")
                    self.logger.error(
                        "Microsoft Azure Monitor CLS Plugin: "
                        f"Received error code {push_resp.status_code}. "
                        f"Error: {err_message}"
                    )
                    raise MicrosoftAzureMonitorPluginException(err_message)
        except Exception as err:
            # Raise this exception from here so that it does not update
            # the checkpoint, as this means data ingestion is failed
            # even after a few retries.
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: "
                f"Error: {err}"
            )
            raise MicrosoftAzureMonitorPluginException(err)

    def get_mapping_value_from_json_path(self, data, json_path):
        """To Fetch the value from given JSON object using given JSON path.

        Args:
            data: JSON object from which the value is to be fetched
            json_path: JSON path indicating the path of the value in given JSON

        Returns:
            fetched value.
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """To Fetch the value from given field.

        Args:
            data: JSON object from which the value is to be fetched
            field: Field whose value is to be fetched

        Returns:
            fetched value.
        """
        return data[field] if data[field] or isinstance(data[field], int) else "null"

    def get_extensions(self, extension_mappings, data, data_type, subtype):
        """Fetch extensions from given mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []

        # Iterate over mapped extensions
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                extension[cef_extension] = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )
            except FieldNotFoundError as err:
                missing_fields.append(str(err))
        return extension

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of CEF headers from given header mappings for given Netskope alert/event record.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: CEF header mapping with Netskope fields
            data: The alert/event for which the CEF header is being generated

        Returns:
            header dict
        """
        headers = {}
        mapping_variables = {}
        if data_type != "webtx":
            helper = AlertsHelper()
            tenant = helper.get_tenant_cls(self.source)
            mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header] = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )

                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[headers[cef_header].lower()]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
            is_json_path: Whether the mapped value is JSON path or direct
            field name

        Returns:
            Fetched values of extension

        ---------------------------------------------------------------------
             Mapping          |    Response    |    Retrieved Value
        ----------------------|                |
        default  |  Mapping   |                |
        ---------------------------------------------------------------------
           P     |     P      |        P       |           Mapped
           P     |     P      |        NP      |           Default
           P     |     NP     |        P       |           Default
           NP    |     P      |        P       |           Mapped
           P     |     NP     |        NP      |           Default
           NP    |     P      |        NP      |           -
           NP    |     NP     |        P       |           - (Not possible)
           NP    |     NP     |        NP      |           - (Not possible)
        -----------------------------------------------------------------------
        """
        if(
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data,
                # map that field, else skip by raising exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    return ",".join([str(val) for val in value])
                else:
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:  # case #1 and case #4
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"]
                else:  # case #6
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
        else:
            # If mapping is not present, 'default_value' must be there
            # because of validation (case #3 and case #5)
            return extension_mapping["default_value"]

    def map_json_data(self, mappings, data, data_type, subtype):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """
        if mappings == []:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]
        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into target platform supported data formats."""

        if not self.configuration.get("transformData", True):
            formatted_raw_data = []
            if data_type not in ["alerts", "events"]:
                for data in raw_data:
                    formatted_raw_data.append(
                    {
                        "RawData": data,
                        "Application": "Netskope CE",
                        "DataType": data_type,
                        "SubType": subtype,
                        "TimeGenerated": f"{datetime.datetime.now()}"
                    }
                )
                return formatted_raw_data

            try:
                delimiter, cef_version, monitor_mappings = get_monitor_mappings(
                    self.mappings, "json"
                )
            except KeyError as err:
                self.logger.error(
                    "Error in monitor mapping file. Error: {}".format(str(err))
                )
                raise MicrosoftAzureMonitorPluginException(err)
            except MappingValidationError as err:
                self.logger.error(str(err))
                raise MicrosoftAzureMonitorPluginException(err)
            except Exception as err:
                self.logger.error(
                    "An error occurred while mapping data "
                    "using given json mappings. Error: {}".format(
                        str(err)
                    )
                )
                raise MicrosoftAzureMonitorPluginException(err)

            try:
                subtype_mapping = self.get_subtype_mapping(
                    monitor_mappings["json"][data_type], subtype
                )
            except Exception as err:
                self.logger.error(
                    'Error occurred while retrieving mappings for datatype: "{}" (subtype "{}"). '
                    "Transformation will be skipped.".format(
                        data_type, subtype
                    )
                )
                raise MicrosoftAzureMonitorPluginException(err)

            transformed_data = []
            formatted_transformed_data = []
            for data in raw_data:
                transformed_data.append(
                    self.map_json_data(subtype_mapping, data, data_type, subtype)
                )
            for data in transformed_data:
                formatted_transformed_data.append(
                    {
                        "RawData": data,
                        "Application": "Netskope CE",
                        "DataType": data_type,
                        "SubType": subtype,
                        "TimeGenerated": f"{datetime.datetime.now()}"
                    }
                )
            return formatted_transformed_data

        else:
            try:
                delimiter, cef_version, monitor_mappings = get_monitor_mappings(
                    self.mappings, data_type
                )
            except KeyError as err:
                self.logger.error(
                    "Error in monitor mapping file. Error: {}".format(str(err))
                )
                raise MicrosoftAzureMonitorPluginException(err)
            except MappingValidationError as err:
                self.logger.error(str(err))
                raise MicrosoftAzureMonitorPluginException(err)
            except Exception as err:
                self.logger.error(
                    "An error occurred while mapping data using given "
                    "json mappings. Error: {}".format(
                        str(err)
                    )
                )
                raise MicrosoftAzureMonitorPluginException(err)

            cef_generator = CEFGenerator(
                self.mappings,
                delimiter,
                cef_version,
                self.logger,
            )
            transformed_data = []
            formatted_transformed_data = []
            for data in raw_data:
                # First retrieve the mapping of subtype being transformed
                try:
                    subtype_mapping = self.get_subtype_mapping(
                        monitor_mappings[data_type], subtype
                    )
                except Exception:
                    self.logger.error(
                        'Error occurred while retrieving mappings for subtype "{}". '
                        "Transformation of current record will be skipped.".format(
                            subtype
                        )
                    )
                    continue

                # Generating the CEF header
                try:
                    header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: Error occurred while creating CEF header: "
                        "{}. Transformation of "
                        "current record will be skipped.".format(
                            data_type, subtype, str(err)
                        )
                    )
                    continue

                try:
                    extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: Error occurred while creating CEF extension: "
                        "{}. Transformation of "
                        "the current record will be skipped".format(
                            data_type, subtype, str(err)
                        )
                    )
                    continue

                try:
                    transformed_data.append(
                        cef_generator.get_cef_event(
                            data,
                            header,
                            extension,
                            data_type,
                            subtype,
                        )
                    )
                except EmptyExtensionError:
                    self.logger.error(
                        "[{}][{}]: Got empty extension during transformation."
                        "Transformation of current record will be skipped".format(
                            data_type, subtype
                        )
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: An error occurred during transformation."
                        " Error: {}".format(data_type, subtype, str(err))
                    )
            try:
                for data in transformed_data:
                    formatted_transformed_data.append(
                        {
                            "RawData": data,
                            "Application": "Netskope CE",
                            "DataType": data_type,
                            "SubType": subtype,
                            "TimeGenerated": f"{datetime.datetime.now()}"
                        }
                    )
                return formatted_transformed_data
            except Exception as err:
                self.logger.error(
                        "Exception Occurred while transforming data, "
                        f"Error: {err}"
                    )

    def validate_credentials(self, configuration):
        url = (
            "https://login.microsoftonline.com/"
            f"{configuration['tenantid'].strip()}/oauth2/v2.0/token"
        )
        body = {
            "client_id": f"{configuration['appid'].strip()}",
            "client_secret": f"{configuration['appsecret'].strip()}",
            "scope": "https://monitor.azure.com//.default",
            "grant_type": "client_credentials",
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            auth_resp = requests.get(
                url, data=body, headers=headers, proxies=self.proxy
            )
            return auth_resp
        except Exception as err:
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {err}"
            )
            return ValidationResult(
                success=False,
                message="Microsoft Azure Monitor CLS Plugin: "
                f"Validation error occurred. {err}"
            )

    def validate_workspace_credentials(self, configuration):
        header = self.generate_auth_token(
            configuration["tenantid"].strip(),
            configuration["appid"].strip(),
            configuration["appsecret"].strip(),
        )
        if not header:
            raise MonitorAuthTokenException(
                "Unable to Generate Access Token using the provided "
                "credentials of Azure Application."
            )
        url_endpoint = (
            f"{configuration['dce_uri'].strip()}/"
            f"dataCollectionRules/{configuration['dcr_immutable_id'].strip()}/"
            f"streams/Custom-{configuration['custom_log_table_name'].strip()}?api-version=2021-11-01-preview"
        )
        try:
            push_resp = self.push_data_to_monitor(header, url_endpoint, [])
            return push_resp
        except Exception as err:
            raise MicrosoftAzureMonitorPluginException(err)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        monitor_validator = AzureMonitorValidator(self.logger)
        if(
            "tenantid" not in configuration
            or not configuration["tenantid"].strip()
        ):
            error_message = "Tenant ID is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["tenantid"]) != str:
            error_message = "Invalid Tenant Id provided."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if "appid" not in configuration or not configuration["appid"].strip():
            error_message = "App ID is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["appid"]) != str:
            error_message = "Invalid App Id provided."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if(
            "appsecret" not in configuration
            or not configuration["appsecret"].strip()
        ):
            error_message = "App Secret is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["appsecret"]) != str:
            error_message = "Invalid App Secret provided."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if(
            "dce_uri" not in configuration
            or not configuration["dce_uri"].strip()
        ):
            error_message = "DCE URI is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["dce_uri"]) != str:
            error_message = "Invalid DCE URI provided."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if (
            "dcr_immutable_id" not in configuration
            or not configuration["dcr_immutable_id"].strip()
        ):
            error_message = "DCR Immutable ID is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["dcr_immutable_id"]) != str:
            error_message = "Invalid DCR Immutable ID provided."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if (
            "custom_log_table_name" not in configuration
            or not configuration["custom_log_table_name"]
        ):
            error_message = "Custom Log Table Name is a required field."
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if type(configuration["custom_log_table_name"]) != str:
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. Error: "
                "Invalid Custom Log Table Name in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Custom Log Table Name provided."
            )

        if not configuration["custom_log_table_name"].strip().endswith("_CL"):
            configuration["custom_log_table_name"] = configuration["custom_log_table_name"].strip() + "_CL"

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if(
            type(mappings) != dict
            or not monitor_validator.validate_monitor_map(
                mappings
            )
        ):
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                "Error: Invalid Microsoft Azure Monitor attribute mapping found in the "
                "configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Microsoft Azure Monitor attribute mapping provided.",
            )

        validate_resp = self.validate_credentials(configuration)

        if validate_resp.status_code == 200:
            try:
                validate_workspace_resp = self.validate_workspace_credentials(configuration)
            except MonitorAuthTokenException as err:
                err_msg = (
                    "Error Occurred while validating the credentials. "
                    "Check Logs for more details"
                )
                self.logger.error(
                        message=f"Microsoft Azure Monitor CLS Plugin: {err_msg}",
                        details=f"{err}"
                    )
                return ValidationResult(
                    success=False,
                    message=err_msg
                )
            except MicrosoftAzureMonitorPluginException as err:
                err_msg = (
                    "Error Occurred while validating the credentials. "
                    "Make sure that the DCE URL is correct."
                )
                self.logger.error(
                        message=f"Microsoft Azure Monitor CLS Plugin: {err_msg}",
                        details=f"{err}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg
                )
            if validate_workspace_resp is None:
                self.logger.error(
                        "Microsoft Azure Monitor CLS Plugin: "
                        "Error Occurred while validating the credentials. "
                        "Make sure that the DCE URI is correct."
                    )
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid Credentials provided. "
                        "Make sure that the DCE URI is correct."
                    )
                )
            else:
                if validate_workspace_resp.status_code != 204:
                    error_response = validate_workspace_resp.json()
                    err_code = error_response.get("error", {}).get("code")
                    if err_code == "InvalidStream":
                        self.logger.error(
                            "Microsoft Azure Monitor CLS Plugin: "
                            "Invalid Custom Log Table Name found, make sure "
                            "that the Table exists in your "
                            "Log Analytics Workspace."
                        )
                        return ValidationResult(
                            success=False,
                            message=(
                                "Invalid Custom Log Table Name provided"
                            ),
                        )
                    elif err_code == "NotFound":
                        err_message = error_response.get("error", {}).get("message")
                        self.logger.error(
                            "Microsoft Azure Monitor CLS Plugin: "
                            f"{err_message}"
                            "Make sure that the DCE URI and DCR Immutable Rule "
                            "are in the same region."
                        )
                        return ValidationResult(
                            success=False,
                            message=(
                                "Microsoft Azure Monitor CLS Plugin: "
                                f"{err_message}"
                                "Make sure that the DCE URI and DCR Immutable Rule "
                                "are of the same region."
                            ),
                        )
                    elif validate_workspace_resp.status_code == 403:
                        err_message = error_response.get("error", {}).get("message")
                        self.logger.error(
                            "Microsoft Azure Monitor CLS Plugin: "
                            f"Received error code {validate_workspace_resp.status_code}. "
                            f"Error: {err_message}"
                        )
                        return ValidationResult(
                            success=False,
                            message=(
                                "Ensure that you have the correct permissions "
                                "for your application to the DCR and the permissions "
                                "are assigned to the same application for which the "
                                "Application credentials are provided."
                            )
                        )
                    else:
                        err_message = error_response.get("error", {}).get("message")
                        self.logger.error(
                            "Microsoft Azure Monitor CLS Plugin: "
                            f"Received error code {validate_workspace_resp.status_code}. "
                            f"Error: {err_message}"
                        )
                        return ValidationResult(success=False, message=err_message)

            return ValidationResult(
                success=True,
                message="Validation successful."
            )
        else:
            self.logger.error(
                "Microsoft Azure Monitor CLS Plugin: Validation error occurred. "
                "Error: Invalid Tenant ID, Client ID, "
                "or Client Scecret provided."
            )
            return ValidationResult(
                success=False,
                message="Validation error occurred. "
                "Error: Invalid Tenant ID, Client ID, or "
                "Client Scecret provided.",
            )