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

"""MCAS Plugin."""

import os
import traceback
import json
import jsonpath

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult
from .utils.mcas_helper import (
    get_mcas_mappings,
)
from .utils.mcas_validator import (
    MCASValidator,
)
from .utils.mcas_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    MaxRetriesExceededError,
    MCASPluginException
)
from .utils.mcas_cef_generator import (
    CEFGenerator,
)

from .utils.mcas_client import (
    MCASClient,
)

from .utils.mcas_constants import (
    PLUGIN_VERSION,
    PLATFORM_NAME,
    MODULE_NAME,
)


class MCASPlugin(PluginBase):
    """MCAS Plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize MCASPlugin class."""
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

    def get_mapping_value_from_json_path(self, data, json_path):
        """Fetch the value from given JSON object using given JSON path.

        :param data: JSON object from which the value is to be fetched
        :param json_path: JSON path indicating the path of the value in given JSON
        :return: fetched value
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """Fetch the value from given field.

        :param data: JSON object from which the value is to be fetched
        :param field: Field whose value is to be fetched
        :return: fetched value
        """
        return (
            (data[field], True)
            if data[field] or isinstance(data[field], int)
            else ("null", False)
        )

    def get_subtype_mapping(self, mappings, subtype):
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

    def get_headers(self, header_mappings, data, data_type, subtype):
        """Create a dictionary of CEF headers from given header mappings for given Netskope alert/event record.

        :param subtype: Subtype for which the headers are being transformed
        :param data_type: Data type for which the headers are being transformed
        :param header_mappings: CEF header mapping with Netskope fields
        :param data: The alert/event for which the CEF header is being generated
        :return: header dict
        """
        headers = {}
        helper = AlertsHelper()
        tenant = helper.get_tenant_cls(self.source)
        mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header], mapped_field = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
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

    def get_extensions(self, extension_mappings, data, data_type, subtype):
        """Get extensions.

        :param subtype: Subtype for which the extension are being transformed
        :param data_type: Data type for which the headers are being transformed
        :param extension_mappings: Mapping of extensions
        :param data: The the to be transformed
        :return:
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
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )
                if mapped_field:
                    mapped_field_flag = mapped_field
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension, mapped_field_flag

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """Fetch the value of extension based on "mapping" and "default" fields.

        :param extension_mapping: Dict containing "mapping" and "default" fields
        :param data: Data instance retrieved from Netskope
        :param subtype: Subtype for which the extension are being transformed
        :param data_type: Data type for which the headers are being transformed
        :param is_json_path: Whether the mapped value is JSON path or direct field name
        :return: Fetched values of extension

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
                # If mapping field specified by JSON path is present in data, map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
            else:
                # If mapping is present in data, map that field, else skip by raising exception
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
                    # If mapped value is not found in response and default is mapped, map the default value (case #2)
                    return extension_mapping["default_value"], mapped_field
                else:  # case #6
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
        else:
            # If mapping is not present, 'default_value' must be there because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
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

    def transform(self, raw_data, data_type, subtype):
        """Transform the raw netskope JSON data to mcas CEF format.

        :param raw_data: data to be transformed
        :param data_type: type of data being transformed (alert/event)
        :param subtype: subtype of data being transformed
        :return: list of transformed data
        """
        skip_count = 0
        if not self.configuration.get("transformData", True):
            try:
                delimiter, cef_version, mcas_mappings = get_mcas_mappings(
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
                        f"{self.log_prefix}: An error occurred while mapping data "
                        f"using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            try:
                subtype_mapping = self.get_subtype_mapping(
                    mcas_mappings["json"][data_type], subtype
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while retrieving "
                        f"mappings for datatype: {data_type} (subtype: {subtype}) "
                        "Transformation will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            transformed_data = []

            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    transformed_data.append(mapped_dict)
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

            return transformed_data

        else:
            try:
                delimiter, cef_version, mcas_mappings = get_mcas_mappings(
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

            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    mcas_mappings[data_type], subtype
                )
            except KeyError as err:
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
                    skip_count += 1
                    continue

                # Generating the CEF header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Error "
                            f"occurred while creating CEF header: {err}. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
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
                        header, extension, data_type, subtype
                    )
                    if cef_generated_event:
                        transformed_data.append(cef_generated_event)

                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Got "
                            "empty extension during transformation. "
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

    def push(self, transformed_data, data_type, subtype):
        """Ingest the given transformed data into MCAS platform.

        :param data_type: The type of data being pushed.
        :param transformed_data: Transformed data to be ingested to MCAS Platform in chunks.
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """
        # Initialize the MCAS REST API client to ingest the data
        mcas_client = MCASClient(
            self.configuration,
            self.logger,
            verify_ssl=self.ssl_validation,
            proxy=self.proxy,
            log_prefix=self.log_prefix,
        )
        try:
            mcas_client.push(transformed_data, data_type, subtype)
        except MaxRetriesExceededError as err:
            self.logger.error(
                message=str(err),
                details=str(traceback.format_exc()),
            )
            raise err
        except MCASPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting [{data_type}]:[{subtype}]."
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting [{data_type}]:[{subtype}]."
                    f"Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise exp

    def validate(self, configuration):
        """Validate configuration.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Result of the validation with a message.
        """
        mcas_validator = MCASValidator(self.logger, self.log_prefix)

        if (
            "portal_url" not in configuration
            or type(configuration["portal_url"]) != str
            or not configuration["portal_url"].strip()
        ):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Portal url found in the configuration parameters."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False, message="Invalid Portal url provided."
            )

        if not mcas_validator.validate_portal_url(configuration["portal_url"]):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid portal url found in the configuration parameters."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Invalid Portal url provided. Portal url should not start with 'http(s)://'",
            )

        if (
            "token" not in configuration
            or type(configuration["token"]) != str
            or not configuration.get("token")
        ):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid token found in the configuration parameters."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message="Invalid token provided.")

        if (
            "data_source" not in configuration
            or type(configuration["data_source"]) != str
            or not mcas_validator.validate_data_source(configuration["data_source"])
        ):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid data source found in the configuration parameters."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Invalid data source provided. Data source should contain "
                "letters, numbers and special characters(_-)",
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(mappings, dict) or not mcas_validator.validate_mcas_map(
            mappings
        ):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid attribute mapping found in the configuration parameters."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Invalid attribute mapping provided.",
            )

        try:
            mcas_client = MCASClient(
                configuration,
                self.logger,
                verify_ssl=self.ssl_validation,
                proxy=self.proxy,
                log_prefix=self.log_prefix,
            )
            mcas_client.validate_token()
        except MCASPluginException as e:
            self.logger.error(
                message=(f"{self.log_prefix}: Validation error occurred. Error: {e}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(e),
            )
        except Exception as e:
            self.logger.error(
                message=(f"{self.log_prefix}: Validation error occurred. Error: {e}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Invalid portal url or token.",
            )
        

        return ValidationResult(success=True, message="Validation successful.")

    @staticmethod
    def plugin_type():
        """Return the type of this plugin.

        :return: Type of this plugin
        """
        return "mcas"

    @staticmethod
    def chunk_size():
        """Return supported chunk size for MCAS.

        :return: data chunk size
        """
        return 5000
