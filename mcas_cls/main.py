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
)
from .utils.mcas_cef_generator import (
    CEFGenerator,
)

from .utils.mcas_client import (
    MCASClient,
)


class MCASPlugin(PluginBase):
    """MCAS Plugin class."""

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
            data[field]
            if data[field] or isinstance(data[field], int)
            else "null"
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
                    headers[cef_header] = mapping_variables[
                        headers[cef_header].lower()
                    ]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers

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
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data, map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    return ",".join([str(val) for val in value])
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field, else skip by raising exception
                if (
                    extension_mapping["mapping_field"] in data
                ):  # case #1 and case #4
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is mapped, map the default value (case #2)
                    return extension_mapping["default_value"]
                else:  # case #6
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
        else:
            # If mapping is not present, 'default_value' must be there because of validation (case #3 and case #5)
            return extension_mapping["default_value"]

    def transform(self, raw_data, data_type, subtype):
        """Transform the raw netskope JSON data to mcas CEF format.

        :param raw_data: data to be transformed
        :param data_type: type of data being transformed (alert/event)
        :param subtype: subtype of data being transformed
        :return: list of transformed data
        """
        try:
            delimiter, cef_version, mcas_mappings = get_mcas_mappings(
                self.mappings, data_type
            )
        except KeyError as err:
            self.logger.error(
                "Error in mcas mapping file. Error: {}".format(str(err))
            )
            raise
        except MappingValidationError as err:
            self.logger.error(str(err))
            raise
        except Exception as err:
            self.logger.error(
                "An error occurred while mapping data using given json mappings. Error: {}".format(
                    str(err)
                )
            )
            raise

        cef_generator = CEFGenerator(
            self.configuration["valid_extensions"],
            delimiter,
            cef_version,
            self.logger,
        )

        transformed_data = []

        for data in raw_data:

            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    mcas_mappings[data_type], subtype
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
                    "[{}][{}]: Error occurred while creating CEF header: {}. Transformation of "
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
                    "[{}][{}]: Error occurred while creating CEF extension: {}. Transformation of "
                    "the current record will be skipped".format(
                        data_type, subtype, str(err)
                    )
                )
                continue

            try:
                transformed_data.append(
                    cef_generator.get_cef_event(
                        header, extension, data_type, subtype
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
        )
        try:
            mcas_client.push(
                transformed_data,
                data_type,
            )
        except MaxRetriesExceededError as err:
            self.logger.error(f"Error while pushing data: {err}")
            raise err

    def validate(self, configuration):
        """Validate configuration.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Result of the validation with a message.
        """
        mcas_validator = MCASValidator(self.logger)

        if (
            "portal_url" not in configuration
            or type(configuration["portal_url"]) != str
            or not configuration["portal_url"].strip()
        ):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid Portal url found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Portal url provided."
            )

        if not mcas_validator.validate_portal_url(configuration["portal_url"]):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid portal url found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Portal url provided. Portal url should not start with 'http(s)://'",
            )

        if (
            "token" not in configuration
            or type(configuration["token"]) != str
            or not configuration.get("token").strip()
        ):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid token found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid token provided."
            )

        if (
            "data_source" not in configuration
            or type(configuration["data_source"]) != str
            or not mcas_validator.validate_data_source(
                configuration["data_source"]
            )
        ):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid data source found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid data source provided. Data source should contain "
                "letters, numbers and special characters(_-)",
            )

        if (
            "valid_extensions" not in configuration
            or type(configuration["valid_extensions"]) != str
            or not configuration["valid_extensions"].strip()
            or not mcas_validator.validate_valid_extensions(
                configuration["valid_extensions"]
            )
        ):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid extensions found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid extensions provided."
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if type(mappings) != dict or not mcas_validator.validate_mcas_map(
            mappings
        ):
            self.logger.error(
                "MCAS Plugin: Validation error occurred. Error: "
                "Invalid mcas attribute mapping found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid mcas attribute mapping provided.",
            )

        try:
            mcas_client = MCASClient(
                configuration,
                self.logger,
                verify_ssl=self.ssl_validation,
                proxy=self.proxy,
            )
            mcas_client.validate_token()
        except Exception as e:
            self.logger.error(
                f"MCAS Plugin: Validation error occurred. Error: {e}"
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
