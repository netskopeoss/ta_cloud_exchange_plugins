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

CLS MCAS Plugin.
"""

import json
import traceback

import jsonpath
from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.mcas_cef_generator import CEFGenerator
from .utils.mcas_client import MCASClient
from .utils.mcas_constants import MODULE_NAME, PLATFORM_NAME, PLUGIN_VERSION
from .utils.mcas_exceptions import (
    EmptyExtensionError,
    FieldNotFoundError,
    MappingValidationError,
    MaxRetriesExceededError,
    MCASPluginException,
)
from .utils.mcas_helper import get_mcas_mappings
from .utils.mcas_validator import MCASValidator


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
            manifest_json = MCASPlugin.metadata
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
        """To Retrieve subtype mappings (mappings
        for subtypes of alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the mapping is
             to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of CEF headers from given header mappings
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
        helper = AlertsHelper()
        tenant = helper.get_tenant_cls(self.source)
        mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header], mapped_field = (
                    self.get_field_value_from_data(
                        header_mapping, data, data_type, subtype, False
                    )
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
        mapped_field_flag = False

        # Iterate over mapped extensions
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                extension[cef_extension], mapped_field = (
                    self.get_field_value_from_data(
                        extension_mapping,
                        data,
                        data_type,
                        subtype,
                        is_json_path="is_json_path" in extension_mapping,
                    )
                )
                if mapped_field:
                    mapped_field_flag = mapped_field
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension, mapped_field_flag

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping"
            and "default" fields.

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
        mapped_field = False
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data,
                # map that field, else skip by raising
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
                # If mapping is present in data, map that field, else skip
                # by raising exception
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
                    # If mapped value is not found in response and default is
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"], mapped_field
                else:  # case #6
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
        else:
            # If mapping is not present, 'default_value' must be there because
            # of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def transform(self, raw_data, data_type, subtype):
        """Transform the raw netskope JSON data to mcas CEF format.

        Args:
            raw_data (List[Dict]): Data to be transformed.
            data_type (str): Type of data being transformed (alert/event).
            subtype (str): Subtype of data being transformed

        Returns:
            List: list of transformed data
        """
        skip_count = 0
        transformData = self.configuration.get("transformData", True)
        if not transformData:
            err_msg = (
                "Plugin doesn't support sending raw (json) data to "
                f"{PLATFORM_NAME}. Enable 'Transformation Toggle' from"
                " Basic Information to transform and send CEF logs."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MCASPluginException(err_msg)

        try:
            delimiter, cef_version, mcas_mappings = get_mcas_mappings(
                self.mappings, data_type
            )
        except KeyError as err:
            err_msg = "An error occurred while fetching the mappings."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except MappingValidationError as err:
            err_msg = "An error occurred while validating the mapping file"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except Exception as err:
            err_msg = (
                "An unexpected error occurred while mapping data "
                "using provided json mappings."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)

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
                mcas_mappings[data_type], subtype
            )
        except KeyError:
            err_msg = (
                f"Unable to find the mapping for data type "
                f'"{data_type}" and subtype "{subtype}" '
                "in the mapping file hence transformation "
                "of current batch is skipped."
            )
            self.logger.info(f"{self.log_prefix}: {err_msg}")
            return []
        except Exception:
            err_msg = (
                "Unable to retrieve mapping for data type "
                f'"{data_type}" and subtype "{subtype}" '
                "in the mapping file hence transformation "
                "of current batch is skipped."
            )
            self.logger.error(
                message=err_msg,
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)

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
                        f"{self.log_prefix}: [{data_type}][{subtype}]- "
                        f"Error occurred while creating CEF header: {err}."
                        " Transformation of current record will "
                        "be skipped."
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
                        f"{self.log_prefix}: [{data_type}][{subtype}]- "
                        f"Error occurred while creating CEF extension: "
                        f"{err}. Transformation of the current record "
                        "will be skipped."
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
                        f"error occurred during transformation. "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_count += 1

        if skip_count > 0:
            self.logger.info(
                "{}: Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the configured mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(self.log_prefix, skip_count)
            )
        return transformed_data

    def push(self, transformed_data, data_type, subtype):
        """Ingest the given transformed data into MCAS platform.

        Args:
            transformed_data (List): Transformed data to be ingested
              to MCAS Platform in chunks.
            data_type (str): The type of data being pushed.
            subtype (str): The subtype of data being pushed. E.g. subtypes
              of alert is "dlp", "policy" etc.
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
            raise MCASPluginException(err)
        except MCASPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"ingesting [{data_type}] [{subtype}] data"
                    f" to {PLATFORM_NAME}."
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as exp:
            err_msg = (
                f"Error occurred while ingesting [{data_type}] "
                f"[{subtype}] data to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)

    def validate(self, configuration):
        """Validate configuration.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Result of the validation with a message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        transformData = configuration.get("transformData", True)
        if not transformData:
            err_msg = (
                "Plugin doesn't support sending raw (json) data to "
                f"{PLATFORM_NAME}. Enable 'Transformation Toggle' from"
                " Basic Information to transform and send CEF logs."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        mcas_validator = MCASValidator(self.logger, self.log_prefix)
        portal_url = configuration.get("portal_url", "").strip()
        if not portal_url:
            err_msg = "Portal url is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(
            portal_url, str
        ) or not mcas_validator.validate_portal_url(portal_url):
            err_msg = "Invalid Portal url provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        auth_method = configuration.get("auth_method", "legacy").strip()
        if not auth_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif auth_method not in ["legacy", "oauth"]:
            err_msg = (
                "Invalid Authentication Method provided. Authentication"
                " Method should be 'Legacy Method (API Token)' or 'OAuth 2.0"
                " (Application context)'."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if auth_method == "legacy":
            token = configuration.get("token", "")
            if not token:
                err_msg = "API Token is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(token, str):
                err_msg = "Invalid API Token provided."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
        else:
            tenant_id = configuration.get("tenant_id", "").strip()
            if not tenant_id:
                err_msg = "Tenant ID is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(tenant_id, str):
                err_msg = "Invalid Tenant ID provided."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            client_id = configuration.get("client_id", "").strip()
            if not client_id:
                err_msg = "Client ID is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(client_id, str):
                err_msg = "Invalid Client ID provided."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            client_secret = configuration.get("client_secret", "")
            if not client_secret:
                err_msg = (
                    "Client Secret is a required configuration parameter."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(client_secret, str):
                err_msg = "Invalid Client Secret provided."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        data_source = configuration.get("data_source", "").strip()
        if not data_source:
            err_msg = "Data Source is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(
            data_source, str
        ) or not mcas_validator.validate_data_source(data_source):
            err_msg = (
                "Invalid Data Source provided. Data Source should contain "
                "letters, numbers and special characters(_-)"
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(
            mappings, dict
        ) or not mcas_validator.validate_mcas_map(mappings):
            err_msg = "Invalid attribute mapping provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

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
                message=(f"{validation_err_msg} Error: {e}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(e),
            )
        except Exception as e:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {e}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Unexpected error occurred, check logs for"
                    " more details."
                ),
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
