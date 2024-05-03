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

Datadog Plugin.
"""

import traceback
import sys
import json
import gzip
from datetime import datetime
from typing import List
from jsonpath import jsonpath

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.datadog_cef_generator import CEFGenerator
from .utils.datadog_validator import DatadogValidator
from .utils.datadog_helper import get_datadog_mappings

from .utils.datadog_constants import (
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    DATADOG_SITES,
    LOGS_TIME_FORMAT
)

from .utils.datadog_api_helper import (
    DatadogPluginHelper,
)

from .utils.datadog_exceptions import (
    DatadogPluginException,
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
)


class DatadogPlugin(PluginBase):
    """Datadog Plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize DatadogPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.datadog_helper = DatadogPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = DatadogPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def convert_string_to_timestamp(self, date_string, format):
        """
        Convert string to timestamp
        """
        try:
            timestamp = datetime.strptime(
                date_string, format).strftime(LOGS_TIME_FORMAT)
            return timestamp
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" converting string to timestamp. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )

        return date_string

    def add_timestamp_datatype_wise(self, data, data_type):
        """
        Add timestamp datatype to the data.

        Args:
            data (dict): The data to be processed

        Returns:
            dict: The data with timestamp datatype added
        """
        if data_type == "webtx":
            x_c_timestamp = data.get("x-cs-timestamp", None)
            if x_c_timestamp:
                return int(x_c_timestamp) * 1000
        elif data_type == "logs":
            createdAt = data.get("createdAt", None)
            if createdAt:
                return self.convert_string_to_timestamp(createdAt, "%m/%d/%Y %I:%M:%S %p")
        else:
            timestamp = data.get("timestamp")
            if timestamp:
                return timestamp * 1000

    def get_api_headers(self, configuration):
        """
        Generates the headers for the API request.

        Args:
            configuration (dict): The plugin configuration parameters

        Returns:
            dict: The headers to be used in the API request.
        """
        dd_api_key = configuration.get("dd_api_key")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "DD-API-KEY": dd_api_key,
        }
        return self.datadog_helper._add_user_agent(headers)

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :return: Mapped data based on fields given in mapping file
        """

        if not (mappings and data):
            # If mapping is empty or data is empty return data.
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

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
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type):
        """To Create a dictionary of CEF headers from given header mappings\
              for given Netskope alert/event record.

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
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header], mapped_field, = self.get_field_value_from_data(
                    header_mapping, data, False
                )

                if mapped_field:
                    mapped_field_flag = mapped_field

                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[
                        headers[cef_header].lower()
                    ]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers, mapped_field_flag

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
                (
                    extension[cef_extension],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    is_json_path="is_json_path" in extension_mapping,
                )

                if mapped_field:
                    mapped_field_flag = mapped_field
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension, mapped_field_flag

    def get_field_value_from_data(
        self, extension_mapping, data, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" \
            and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            is_json_path: Whether the mapped value is \
                JSON path or direct field name

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
        # mapped_field will be returned as true only if the value returned is\
        # using the mapping_field and not default_value
        mapped_field = False
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data,\
                #  map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field, \
                # else skip by raising exception
                if (
                    extension_mapping["mapping_field"] in data
                ):  # case #1 and case #4
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
                    # If mapped value is not found in response and default is \
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"], mapped_field
                else:  # case #6
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
        else:
            # If mapping is not present, 'default_value' must be there\
            #  because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cls.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        datadog_validator = DatadogValidator(self.logger, self.log_prefix)
        dd_site = configuration.get("dd_site", "").strip()
        if not dd_site:
            err_msg = "Datadog Site is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(dd_site, str):
            err_msg = "Invalid Datadog Site provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif dd_site not in DATADOG_SITES:
            err_msg = "Invalid Datadog Site provided in configuration parameters. Select the Datadog Site from the available options."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        dd_api_key = configuration.get("dd_api_key", "")
        if not dd_api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(dd_api_key, str):
            err_msg = "Invalid API Key provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        dd_tags = configuration.get("dd_tags", "").strip()
        if dd_tags and (not isinstance(dd_tags, str) or not datadog_validator.validate_datadog_tags(dd_tags)):
            err_msg = "Invalid Datadog Tags provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(mappings, dict) or not datadog_validator.validate_datadog_map(
            mappings
        ):
            err_msg = "Invalid attribute mapping provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(configuration, validation_err_msg)

    def validate_auth_params(self, configuration, validation_err_msg):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cls.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            headers = self.get_api_headers(configuration)
            body = {"message": ""}
            params = {
                "hostname": "netskope-ce",
                "ddtags": configuration.get("dd_tags", "").strip(),
            }

            self.datadog_helper.api_helper(
                logger_msg="validating authentication parameters",
                url=f"https://http-intake.logs.{configuration.get('dd_site').strip()}/api/v2/logs",
                method="POST",
                data=json.dumps(body),
                params=params,
                headers=headers,
                is_validation=True,
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except DatadogPluginException as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Unexpected error occurred. Check logs for more details.",
            )

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into target platform \
            supported data formats."""
        count = 0
        if not self.configuration.get("transformData", True):
            try:
                delimiter, cef_version, datadog_mappings = get_datadog_mappings(
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
                        f"{self.log_prefix}: An error occurred while validating the mapping file. {err}"
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
                    datadog_mappings["json"][data_type], subtype
                )
                if subtype_mapping == []:
                    transformed_data = []
                    for data in raw_data:
                        if data:
                            data["timestamp"] = self.add_timestamp_datatype_wise(
                                data, data_type)
                            transformed_data.append(
                                {"message": json.dumps(data)})
                        else:
                            count += 1
                    if count > 0:
                        self.logger.debug(
                            "{}: Plugin couldn't process {} records because they "
                            "either had no data or contained invalid/missing "
                            "fields according to the configured JSON mapping. "
                            "Therefore, the transformation and ingestion for those "
                            "records were skipped.".format(
                                self.log_prefix, count)
                        )
                    return transformed_data
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

            transformed_data = []
            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    mapped_dict["timestamp"] = self.add_timestamp_datatype_wise(
                        mapped_dict, data_type)
                    transformed_data.append(
                        {"message": json.dumps(mapped_dict)})
                else:
                    count += 1

            if count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, count)
                )

            return transformed_data
        else:
            try:
                delimiter, cef_version, datadog_mappings = get_datadog_mappings(
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
                        f"{self.log_prefix}: An error occurred while mapping "
                        f"data using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            cef_generator = CEFGenerator(
                self.mappings,
                delimiter,
                cef_version,
                self.logger,
                self.log_prefix,
            )

            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    datadog_mappings[data_type], subtype
                )
            except KeyError:
                self.logger.info(
                    f"{self.log_prefix}: Unable to find the "
                    f"[{data_type}]:[{subtype}] mappings in the mapping file, "
                    "Transformation of current batch will be skipped."
                )
                return []
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
                    count += 1
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
                    count += 1
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
                    count += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        count += 1
                        continue
                    cef_generated_event = cef_generator.get_cef_event(
                        data,
                        header,
                        extension,
                        data_type,
                        subtype,
                    )
                    if cef_generated_event:
                        transformed_data.append(
                            {"message": cef_generated_event})
                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Got"
                            " empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- An "
                            f"error occurred during transformation. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
            if count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, count)
                )

            return transformed_data

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to Datadog.

        :param data_type: The type of data being pushed.
        E.g. Current possible values: alerts, events and webtx
        :param transformed_data: Transformed data to be ingested to
        Datadog in chunks
        :param subtype: The subtype of data being pushed.
        E.g. subtypes of alert is "dlp", "policy" etc.
        """
        try:
            batch_size = sys.getsizeof(f"{transformed_data}") / (1024 * 1024)
            if batch_size > 1:
                transformed_data = self.datadog_helper.split_into_size(
                    transformed_data)
            else:
                transformed_data = [transformed_data]

            skipped_count = 0
            total_count = 0
            page = 0
            headers = self.get_api_headers(self.configuration)
            tenant = None
            if data_type != "webtx":
                helper = AlertsHelper()
                tenant = helper.get_tenant_cls(self.source)

            params = {
                "ddsource": "netskope-ce",
                "ddtags": self.configuration.get("dd_tags", ""),
                "hostname": tenant.name if tenant and tenant.name else "",
            }
            for chunk in transformed_data:
                page += 1
                try:
                    json_data = json.dumps(chunk)

                    if data_type == "webtx":
                        headers["Content-Encoding"] = "gzip"

                        # Convert to bytes
                        encoded = json_data.encode('utf-8')
                        # Compress
                        json_data = gzip.compress(encoded)

                    self.datadog_helper.api_helper(
                        logger_msg="ingesting data for page {}".format(page),
                        url=f"https://http-intake.logs.{self.configuration.get('dd_site').strip()}/api/v2/logs",
                        method="POST",
                        params=params,
                        data=json_data,
                        headers=headers,
                        is_validation=False,
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
                except (DatadogPluginException, Exception) as err:
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
        except DatadogPluginException as err:
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
