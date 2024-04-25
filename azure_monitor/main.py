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

Microsoft Azure Monitor Plugin."""

import datetime
import traceback
import json
import sys
import requests
import time
from typing import List
from jsonpath import jsonpath

from netskope.common.utils import add_user_agent

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import AlertsHelper
from .utils.monitor_validator import (
    AzureMonitorValidator,
)
from .utils.monitor_helper import get_monitor_mappings, split_into_size
from .utils.monitor_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    MicrosoftAzureMonitorPluginException,
)
from .utils.monitor_cef_generator import (
    CEFGenerator,
)
from .utils.monitor_constants import (
    GENERATE_TOKEN_BASE_URL,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    MAX_RETRIES,
    RETRY_SLEEP_TIME,
    MAX_WAIT_TIME,
    API_SCOPE,
    GRANT_TYPE,
)


class AzureMonitorPlugin(PluginBase):
    """The Microsoft Azure Monitor CLS plugin implementation class."""

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
            manifest_json = AzureMonitorPlugin.metadata
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

    def generate_auth_token(self, tenantid, appid, appsecret, is_validation=False):
        try:
            url = GENERATE_TOKEN_BASE_URL.format(tenantid)
            body = {
                "client_id": appid,
                "client_secret": appsecret,
                "scope": API_SCOPE,
                "grant_type": GRANT_TYPE,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = self.api_helper(
                "generating token",
                url,
                "POST",
                headers=self._add_user_agent(headers),
                data=body,
                proxies=self.proxy,
                is_validation=is_validation,
            )
            if response and "access_token" in response:
                return response.get("access_token")

            return None
        except MicrosoftAzureMonitorPluginException as err:
            raise err
        except Exception as e:
            err_msg = "Error occurred while generating access token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {e}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def push_data_to_monitor(
        self, logger_msg, header, url_endpoint, transformed_data, is_validation=False
    ):
        try:
            self.api_helper(
                logger_msg,
                url_endpoint,
                "POST",
                data=transformed_data,
                headers=header,
                proxies=self.proxy,
                is_validation=is_validation,
            )
        except Exception as err:
            raise MicrosoftAzureMonitorPluginException(str(err))

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Microsoft Azure Monitor.

        :param data_type: The type of data being pushed.
         Current possible values: alerts, events and webtx
        :param transformed_data: Transformed data to be ingested to
        Microsoft Azure Monitor in chunks
        :param subtype: The subtype of data being pushed.
        E.g. subtypes of alert is "dlp", "policy" etc.
        """
        try:
            batch_size = sys.getsizeof(f"{transformed_data}") / (1024 * 1024)
            if batch_size > 1:
                transformed_data = split_into_size(transformed_data)
            else:
                transformed_data = [transformed_data]

            url_endpoint = (
                f"{self.configuration.get('dce_uri').strip()}/"
                f"dataCollectionRules/{self.configuration.get('dcr_immutable_id').strip()}/"
                f"streams/Custom-{self.configuration.get('custom_log_table_name').strip()}?api-version=2023-01-01"
            )
            auth_token = self.generate_auth_token(
                self.configuration.get("tenantid").strip(),
                self.configuration.get("appid").strip(),
                self.configuration.get("appsecret"),
            )
            if not auth_token:
                raise MicrosoftAzureMonitorPluginException(
                    "Unable to Generate Access Token for the provided "
                    "Application credentials."
                )
            skipped_count = 0
            total_count = 0
            page = 0
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            headers = self._add_user_agent(headers)
            for chunk in transformed_data:
                page += 1
                try:
                    self.push_data_to_monitor(
                        f"ingesting data to {self.plugin_name} for page {page}",
                        headers,
                        url_endpoint,
                        json.dumps(chunk),
                    )
                    log_msg = "[{}]:[{}] Successfully ingested {} {}(s) for page {} to {}.".format(
                        data_type,
                        subtype,
                        len(chunk),
                        data_type,
                        page,
                        self.plugin_name,
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                    total_count += len(chunk)
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: [{}]:[{}] Error occurred while ingesting data. Error: {}".format(
                                self.log_prefix, data_type, subtype, err
                            )
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skipped_count += len(chunk)
                    continue
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} records due to some unexpected error occurred, check logs for more details."
                )

            log_msg = "[{}]:[{}] Successfully ingested {} {}(s) to {}.".format(
                data_type,
                subtype,
                total_count,
                data_type,
                self.plugin_name,
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
        except MicrosoftAzureMonitorPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting [{data_type}]:[{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as err:
            # Raise this exception from here so that it does not update
            # the checkpoint, as this means data ingestion is failed
            # even after a few retries.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting [{data_type}]:[{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err

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
        return (
            (data[field], True)
            if data[field] or isinstance(data[field], int)
            else ("null", False)
        )

    def get_extensions(self, extension_mappings, data):
        """Fetch extensions from given mappings.

        Args:
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped extensions
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                extension[cef_extension], mapped_field = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    is_json_path="is_json_path" in extension_mapping,
                )
                if mapped_field:
                    mapped_field_flag = mapped_field
            except (Exception, FieldNotFoundError) as err:
                missing_fields.append(str(err))
        return extension, mapped_field_flag

    def get_headers(self, header_mappings, data, data_type):
        """To Create a dictionary of CEF headers from given header mappings for given Netskope alert/event record.

        Args:
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
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header], mapped_field = self.get_field_value_from_data(
                    header_mapping, data, False
                )
                if mapped_field:
                    mapped_field_flag = mapped_field

                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[headers[cef_header].lower()]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers, mapped_field_flag

    def get_field_value_from_data(self, extension_mapping, data, is_json_path=False):
        """To Fetch the value of extension based on "mapping" and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
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
        mapped_field = False
        if "mapping_field" in extension_mapping and extension_mapping["mapping_field"]:
            if is_json_path:
                # If mapping field specified by JSON path is present in data,
                # map that field, else skip by raising exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:  # case #1 and case #4
                    if (
                        extension_mapping.get("transformation") == "Time Stamp"
                        and data[extension_mapping["mapping_field"]]
                    ):
                        try:
                            mapped_field = True
                            return (
                                int(data[extension_mapping["mapping_field"]]),
                                mapped_field,
                            )
                        except Exception:
                            pass
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"], mapped_field
                else:  # case #6
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
        else:
            # If mapping is not present, 'default_value' must be there
            # because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
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

        skip_count = 0
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
                            "TimeGenerated": f"{datetime.datetime.now()}",
                        }
                    )
                return formatted_raw_data

            try:
                delimiter, cef_version, monitor_mappings = get_monitor_mappings(
                    self.mappings, "json"
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while fetching the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while validating the mapping file. {str(err)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while mapping "
                        f"data using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            try:
                subtype_mapping = self.get_subtype_mapping(
                    monitor_mappings["json"][data_type], subtype
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while retrieving "
                        f"mappings for datatype: {data_type} "
                        f"(subtype: {subtype}) Transformation will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            formatted_transformed_data = []
            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    formatted_transformed_data.append(
                        {
                            "RawData": data,
                            "Application": "Netskope CE",
                            "DataType": data_type,
                            "SubType": subtype,
                            "TimeGenerated": f"{datetime.datetime.now()}",
                        }
                    )
                else:
                    skip_count += 1
            if skip_count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, skip_count)
                )
            return formatted_transformed_data

        else:
            try:
                delimiter, cef_version, monitor_mappings = get_monitor_mappings(
                    self.mappings, data_type
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while fetching the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while validating the mapping file. {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while mapping data "
                        f"using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            cef_generator = CEFGenerator(
                self.mappings, delimiter, cef_version, self.logger, self.log_prefix
            )

            try:
                subtype_mapping = self.get_subtype_mapping(
                    monitor_mappings[data_type], subtype
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while retrieving "
                        f"mappings for subtype {subtype}. "
                        "Transformation of current batch will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                return []
            transformed_data = []
            for data in raw_data:
                if not data:
                    skip_count += 1
                    continue
                # Generating the CEF header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- "
                            f"Error occurred while creating CEF header: {err}."
                            " Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Error "
                            f"occurred while creating CEF extension: {err}. "
                            "Transformation of the current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        skip_count += 1
                        continue
                    cef_generated_event = cef_generator.get_cef_event(
                        data, header, extension, data_type, subtype
                    )
                    if cef_generated_event:
                        transformed_data.append(
                            {
                                "RawData": cef_generated_event,
                                "Application": "Netskope CE",
                                "DataType": data_type,
                                "SubType": subtype,
                                "TimeGenerated": f"{datetime.datetime.now()}",
                            }
                        )

                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Got"
                            " empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- An "
                            f"error occurred during transformation. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1

            if skip_count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, skip_count)
                )

        return transformed_data

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        monitor_validator = AzureMonitorValidator(self.logger, self.log_prefix)
        validation_msg = f"{self.log_prefix}: Validation error occurred."
        tenant_id = configuration.get("tenantid", "").strip()
        if not tenant_id:
            error_message = (
                "Directory (tenant) ID is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(tenant_id, str):
            error_message = "Invalid Directory (tenant) ID provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        app_id = configuration.get("appid", "").strip()
        if not app_id:
            error_message = (
                "Application (client) ID is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(app_id, str):
            error_message = "Invalid Application (client) ID provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        app_secret = configuration.get("appsecret")
        if not app_secret:
            error_message = "Client Secret is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(app_secret, str):
            error_message = "Invalid Client Secret provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        dce_uri = configuration.get("dce_uri", "").strip()
        if not dce_uri:
            error_message = "DCE URI is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(dce_uri, str):
            error_message = "Invalid DCE URI provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        dcr_immutable_id = configuration.get("dcr_immutable_id", "").strip()
        if not dcr_immutable_id:
            error_message = "DCR Immutable ID is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(dcr_immutable_id, str):
            error_message = "Invalid DCR Immutable ID provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        custom_log_table_name = configuration.get("custom_log_table_name", "").strip()
        if not custom_log_table_name:
            error_message = (
                "Custom Log Table Name is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(custom_log_table_name, str):
            error_message = "Invalid Custom Log Table Name provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        if not custom_log_table_name.endswith("_CL"):
            configuration["custom_log_table_name"] = custom_log_table_name + "_CL"

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(mappings, dict) or not monitor_validator.validate_monitor_map(
            mappings
        ):
            err_msg = "Invalid Microsoft Azure Monitor attribute mapping provided."
            self.logger.error(f"{validation_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        try:
            auth_token = self.generate_auth_token(
                tenant_id, app_id, app_secret, is_validation=True
            )

            if auth_token is None:
                err_msg = "Invalid Directory (tenant) ID, Application (client) ID, or Client Secret provided in configuration parameters."
                self.logger.error(f"{validation_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except MicrosoftAzureMonitorPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )

        try:
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            url_endpoint = (
                f"{dce_uri}/"
                f"dataCollectionRules/{dcr_immutable_id}/"
                f"streams/Custom-{custom_log_table_name}?api-version=2023-01-01"
            )
            self.push_data_to_monitor(
                "validating credentials",
                self._add_user_agent(headers),
                url_endpoint,
                json.dumps([]),
                True,
            )

        except MicrosoftAzureMonitorPluginException as err:
            err_msg = (
                "Error occurred while validating the credentials. "
                "Make sure that the DCE URL is correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"{err}",
            )
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = "Error occurred while validating the credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"{err}",
            )
            return ValidationResult(
                success=False, message=err_msg + " Check Logs for more details."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def _add_user_agent(self, headers) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def parse_response(self, response: requests.models.Response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {str(err)}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def handle_error(self, resp: requests.models.Response, logger_msg, is_validation):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.status_code

        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
            404: "Not Found",
        }
        if status_code in [200, 201]:
            return self.parse_response(response=resp)
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            error_response = self.parse_response(response=resp)
            error_val = error_response.get("error")
            err_msg = error_dict[status_code]
            if isinstance(error_val, dict):
                validation_msg = ". Verify the DCE URI and DCR Immutable ID provided in configuration parameters. Check logs for more details."
                err_code = error_response.get("error", {}).get("code")
                err_message = error_response.get("error", {}).get("message")
                if err_code == "InvalidStream":
                    err_msg = (
                        err_msg
                        + ". Invalid Custom Log Table Name found, make sure that the Table exists in your Log Analytics Workspace."
                    )
                elif err_code == "InvalidDcrImmutableId":
                    err_msg = (
                        err_msg
                        + ". Make sure that the DCE URI and DCR Immutable Rule are in the same region."
                    )
                elif err_code == "OperationFailed":
                    err_msg = err_msg + (
                        ". Ensure that you have the correct permissions "
                        "for your application to the DCR and the permissions "
                        "are assigned to the same application for which the "
                        "Application credentials are provided."
                    )
                elif err_message:
                    err_msg = err_msg + ". " + err_message
                else:
                    err_msg = err_msg + validation_msg
            elif isinstance(error_val, str):
                if error_val == "unauthorized_client":
                    err_msg = (
                        err_msg
                        + ". Invalid Application (client) ID provided in configuration parameters."
                    )
                elif error_val == "invalid_client":
                    err_msg = (
                        err_msg
                        + ". Invalid Client Secret provided in configuration parameters."
                    )
                else:
                    err_msg = (
                        err_msg
                        + ". Invalid Directory (tenant) ID, Application (client) ID, or Client Secret provided in configuration parameters. Check logs for more details."
                    )

            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )

            raise MicrosoftAzureMonitorPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + "."
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        verify=True,
        proxies=None,
        is_validation=False,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.
            is_validation : API call from validation method or not

        Returns:
            dict: Response dictionary.
        """
        try:
            display_headers = {
                k: v for k, v in headers.items() if k not in {"Authorization"}
            }
            debuglog_msg = f"{self.log_prefix} : API Request for {logger_msg}. URL={url}, Headers={display_headers}"
            if params:
                debuglog_msg += f", params={params}"

            self.logger.debug(debuglog_msg)
            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                )
                self.logger.debug(
                    f"{self.log_prefix} : Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if not is_validation and response.status_code == 429:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get("error", {}).get("message", str(response.text)),
                    )
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = (
                            "Received exit code {}, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MicrosoftAzureMonitorPluginException(err_msg)
                    retry_after = response.headers.get("Retry-After")
                    if retry_after is None:
                        self.logger.info(
                            "{}: No Retry-After value received from"
                            "API hence plugin will retry after {} "
                            "seconds.".format(self.log_prefix, RETRY_SLEEP_TIME)
                        )
                        time.sleep(RETRY_SLEEP_TIME)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = round(abs(retry_after - time.time()), 2)
                    if diff_retry_after > MAX_WAIT_TIME:
                        err_msg = (
                            "'Retry-After' value received from "
                            "response headers while {} is greater than {}  "
                            "seconds hence returning status code {}.".format(
                                logger_msg, MAX_WAIT_TIME, response.status_code
                            )
                        )
                        self.logger.error(message=f"{self.log_prefix}: {err_msg}")
                        raise MicrosoftAzureMonitorPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                diff_retry_after,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(diff_retry_after)

                elif not is_validation and (
                    response.status_code >= 500 and response.status_code <= 600
                ):
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = (
                            "Received exit code {}, while"
                            " {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(response.text),
                        )
                        raise MicrosoftAzureMonitorPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds. {} "
                            "retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                RETRY_SLEEP_TIME,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(RETRY_SLEEP_TIME)
                else:
                    return self.handle_error(response, logger_msg, is_validation)

        except requests.exceptions.ProxyError as error:
            err_msg = f"Proxy error occurred while {logger_msg}. Verify the provided proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} while {logger_msg}."
                " Check DCE URI provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except MicrosoftAzureMonitorPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
