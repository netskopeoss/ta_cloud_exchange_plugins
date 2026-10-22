"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin.
"""

import copy
import json
import time
import traceback
from typing import List, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jsonpath import jsonpath
from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.batch_manager import AWSCloudWatchBatchManager
from .utils.cef_generator import CEFGenerator
from .utils.client import AWSCloudWatchClient
from .utils.constants import (
    AUTHENTICATION_METHODS,
    AWS_IAM_ROLES_ANYWHERE,
    CUSTOM_REGION_VALUE,
    AWS_IAM_ROLES_ANYWHERE_CONFIG,
    CHUNK_SIZE,
    COMMON_CONFIG,
    LOG_NAME_MAX_LENGTH,
    LOG_NAME_MIN_LENGTH,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    USER_AGENT,
    VALIDATION_ERROR_MESSAGE,
    VALIDATION_MAX_RETRIES,
)
from .utils.exceptions import (
    AWSCloudWatchPluginError,
    AWSCloudWatchResourceNotFoundError,
    EmptyExtensionError,
    FieldNotFoundError,
    MappingValidationError,
)
from .utils.helper import (
    get_aws_cloudwatch_mappings,
    get_region_partition,
    validate_aws_cloudwatch_mappings,
)
from .utils.validator import AWSCloudWatchValidator


class AWSCloudWatchPlugin(PluginBase):
    """The AWS CloudWatch CLS plugin implementation class."""

    def __init__(self, name, *args, **kwargs):
        """Initialize AWSCloudWatchPlugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.config_name = name
        self.alerts_helper = AlertsHelper()

    def _get_plugin_info(self) -> tuple:
        """Read the plugin name and version from the manifest.

        Returns:
            tuple: Plugin name and plugin version.
        """
        try:
            manifest_json = AWSCloudWatchPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Could not read the plugin"
                    f" details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    # ───────────────────────── CONFIGURATION ─────────────────────────────

    def _transformation_compatibility_check(self, configuration: dict) -> bool:
        """Check whether the selected format is JSON.

        CE 5.1.2 and older send transformData as a boolean, where True
        means CEF. Newer CE builds send the string "cef" or "json".

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            bool: True when the data must be sent as JSON.
        """
        transform_data = configuration.get("transformData", "json")
        if isinstance(transform_data, bool):
            # Cloud Exchange 5.1.2 and older sent a boolean. Kept as a
            # cheap guard even though minimum_version is 6.1.0.
            return not transform_data
        return str(transform_data).strip().lower() == "json"

    @staticmethod
    def _safe_strip(configuration: dict, key: str) -> str:
        """Read a text parameter and remove the surrounding spaces.

        A value that is missing, None, or not a string is reported as an
        empty string so the field checks can report it cleanly instead of
        raising.

        Args:
            configuration (dict): Plugin configuration parameters.
            key (str): Configuration key to read.

        Returns:
            str: Clean value, or an empty string.
        """
        value = configuration.get(key, "")
        if isinstance(value, str):
            return value.strip()
        return "" if value is None else value

    def _get_config_params(
        self, configuration: dict, params_to_get: List[str] = None
    ):
        """Read the configuration parameters the plugin needs.

        Args:
            configuration (dict): Plugin configuration parameters.
            params_to_get (List[str]): Keys to read. All keys are read
                when this is not given.

        Returns:
            tuple or single value of the requested parameters.
        """
        # Every entry is built only when it is asked for. The pass phrase
        # is read as it is, because stripping a password can break a
        # valid credential.
        builders = {
            "authentication_method": lambda: self._safe_strip(
                configuration, "authentication_method"
            ),
            "private_key_file": lambda: self._safe_strip(
                configuration, "private_key_file"
            ),
            "public_certificate_file": lambda: self._safe_strip(
                configuration, "public_certificate_file"
            ),
            "pass_phrase": lambda: configuration.get("pass_phrase"),
            "profile_arn": lambda: self._safe_strip(
                configuration, "profile_arn"
            ),
            "role_arn": lambda: self._safe_strip(configuration, "role_arn"),
            "trust_anchor_arn": lambda: self._safe_strip(
                configuration, "trust_anchor_arn"
            ),
            "region_name": lambda: self._safe_strip(
                configuration, "region_name"
            ),
            "log_group_name": lambda: self._safe_strip(
                configuration, "log_group_name"
            ),
            "log_stream_name": lambda: self._safe_strip(
                configuration, "log_stream_name"
            ),
        }

        if not params_to_get:
            return tuple(builder() for builder in builders.values())

        result = [
            builders[param]() if param in builders else None
            for param in params_to_get
        ]
        return result[0] if len(result) == 1 else tuple(result)

    def get_dynamic_fields(self) -> list:
        """Return the configuration fields for the selected auth method.

        Returns:
            list: Field definitions rendered by the CE user interface.
        """
        authentication_method = self._get_config_params(
            self.configuration, ["authentication_method"]
        )
        if authentication_method == AWS_IAM_ROLES_ANYWHERE:
            fields = AWS_IAM_ROLES_ANYWHERE_CONFIG + COMMON_CONFIG
        else:
            fields = COMMON_CONFIG
        # Hand out copies so the caller can never change the constants.
        return copy.deepcopy(fields)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
        allowed_values: list = None,
        validation_err_msg: str = VALIDATION_ERROR_MESSAGE,
        required_field_message: str = None,
    ) -> Union[ValidationResult, None]:
        """Validate one configuration field.

        Args:
            field_name (str): Label of the field.
            field_value: Value of the field.
            field_type (type): Type the field must have.
            is_required (bool): Whether the field must have a value.
            allowed_values (list): Values the field may take.
            validation_err_msg (str): Prefix used in the error log.
            required_field_message (str): Message used when a required
                field has no value.

        Returns:
            ValidationResult on failure, None on success.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                required_field_message
                if required_field_message
                else f"{field_name} is a required configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Provide a value for {field_name} in the configuration"
                    " parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if field_value and not isinstance(field_value, field_type):
            err_msg = (
                "Invalid value provided for the configuration parameter"
                f" '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Provide a valid value for {field_name} in the"
                    " configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            allowed_values
            and field_type is str
            and field_value not in allowed_values
        ):
            err_msg = (
                "Invalid value provided for the configuration parameter"
                f" '{field_name}'. Allowed values are"
                f" {', '.join(str(value) for value in allowed_values)}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Set {field_name} to one of"
                    f" {', '.join(str(value) for value in allowed_values)}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for '{field_name}'."
        )
        return None

    # ───────────────────────── MAPPING HELPERS ───────────────────────────

    def get_mapping_value_from_json_path(self, data, json_path):
        """Read a value from a record using a JSON path.

        Args:
            data: Record to read from.
            json_path: JSON path of the value.

        Returns:
            Value found at the JSON path.
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """Read a value from a record using a field name.

        Args:
            data: Record to read from.
            field: Field name.

        Returns:
            tuple: Value and a flag saying the field was mapped.
        """
        return (
            (data[field], True)
            if data[field] or isinstance(data[field], int)
            else ("null", False)
        )

    def get_nested_field_value(self, data, field_path):
        """Read a value from a record using a dotted field path.

        Args:
            data: Record to read from.
            field_path (str): Dotted path, for example host_info.os.

        Returns:
            tuple: Value and a flag saying the field was found.
        """
        try:
            current_data = data
            field_parts = field_path.split(".")

            for part in field_parts:
                if isinstance(current_data, dict) and part in current_data:
                    current_data = current_data[part]
                else:
                    return None, False

            return current_data, True
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not read the nested field"
                    f" '{field_path}'. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return None, False

    def get_subtype_mapping(self, mappings, subtype):
        """Read the mapping of one subtype, ignoring letter case.

        Args:
            mappings (dict): Mappings of one data type.
            subtype (str): Subtype to read.

        Returns:
            Mapping of the subtype.

        Raises:
            MappingValidationError: When the subtype is not in the file.
        """
        lower_mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in lower_mappings:
            return lower_mappings[subtype.lower()]
        if subtype.upper() in mappings:
            return mappings[subtype.upper()]
        raise MappingValidationError(
            f"Could not find the mapping of the subtype '{subtype}' in the"
            " mapping file."
        )

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """Read one mapped value from a record.

        The mapped field is used first. When it is missing, the default
        value is used. When there is no default value either, the field
        is reported as missing.

        Args:
            extension_mapping (dict): Mapping of one CEF field.
            data (dict): Record to read from.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.
            is_json_path (bool): Whether the mapping is a JSON path.

        Returns:
            tuple: Value and a flag saying the value came from the record.

        Raises:
            FieldNotFoundError: When the mapped field is missing and there
                is no default value.
        """
        mapped_field = False
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join(map(str, value)), mapped_field
                raise FieldNotFoundError(
                    extension_mapping["mapping_field"]
                )

            if extension_mapping["mapping_field"] in data:
                if (
                    extension_mapping.get("transformation") == "Time Stamp"
                    and data[extension_mapping["mapping_field"]]
                ):
                    try:
                        mapped_field = True
                        timestamp_value = int(
                            data[extension_mapping["mapping_field"]]
                        )
                        return (timestamp_value, mapped_field)
                    except Exception:
                        pass

                return self.get_mapping_value_from_field(
                    data, extension_mapping["mapping_field"]
                )

            nested_value, field_exists = self.get_nested_field_value(
                data, extension_mapping["mapping_field"]
            )

            if field_exists:
                if (
                    extension_mapping.get("transformation") == "Time Stamp"
                    and nested_value
                ):
                    try:
                        mapped_field = True
                        return int(nested_value), mapped_field
                    except Exception:
                        pass

                return (
                    (nested_value, True)
                    if nested_value or isinstance(nested_value, int)
                    else ("null", False)
                )
            if "default_value" in extension_mapping:
                return extension_mapping["default_value"], mapped_field
            raise FieldNotFoundError(extension_mapping["mapping_field"])

        return extension_mapping["default_value"], mapped_field

    def get_headers(self, header_mappings, data, data_type, subtype):
        """Build the CEF headers of one record.

        Args:
            header_mappings (dict): Header part of the subtype mapping.
            data (dict): Record to transform.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.

        Returns:
            tuple: Headers and a flag saying at least one value came from
                the record.
        """
        headers = {}
        mapping_variables = {}
        if data_type != "webtx":
            if not hasattr(self, "tenant"):
                self.tenant = self.alerts_helper.get_tenant_cls(self.source)
            mapping_variables = {"$tenant_name": self.tenant.name}

        missing_fields = []
        mapped_field_flag = False
        for cef_header, header_mapping in header_mappings.items():
            try:
                (
                    headers[cef_header],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )

                if mapped_field:
                    mapped_field_flag = mapped_field

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
        """Build the CEF extensions of one record.

        Args:
            extension_mappings (dict): Extension part of the mapping.
            data (dict): Record to transform.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.

        Returns:
            tuple: Extensions and a flag saying at least one value came
                from the record.
        """
        extension = {}
        missing_fields = []
        mapped_field_flag = False

        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                (
                    extension[cef_extension],
                    mapped_field,
                ) = self.get_field_value_from_data(
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

    def map_json_data(self, mappings, data):
        """Keep only the fields listed in the JSON mapping.

        Args:
            mappings (list): Field names to keep.
            data (dict): Record to filter.

        Returns:
            dict: Filtered record. The whole record is returned when the
                mapping list is empty.
        """
        if mappings == [] or not data:
            return data

        mapped_dict = {}
        data_keys = data.keys()
        for key in mappings:
            if key in data_keys:
                mapped_dict[key] = data[key]
            else:
                value, field_exist = self.get_nested_field_value(data, key)
                if field_exist:
                    mapped_dict[key] = value

        return mapped_dict

    def validate_mappings(self) -> ValidationResult:
        """Check the mapping file selected for this configuration.

        Returns:
            ValidationResult: Result of the mapping check.
        """
        validation_err_msg = (
            f"{self.log_prefix}: Mapping validation error occurred."
        )
        err_msg = "Invalid attribute mapping provided."
        aws_validator = AWSCloudWatchValidator(self.logger, self.log_prefix)

        def _validate_json_data(json_string):
            """Check that the mapping data is a non empty JSON object."""
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON: {err}")
            except ValueError:
                raise
            except Exception as err:
                raise ValueError(
                    f"Error occurred while validating JSON: {err}."
                )
            return json_object

        try:
            mappings = _validate_json_data(self.mappings.get("jsonData"))
        except Exception as err:
            return ValidationResult(success=False, message=str(err))

        if not isinstance(
            mappings, dict
        ) or not aws_validator.validate_aws_cloudwatch_map(mappings):
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        for data_type in mappings.get("taxonomy", {}).keys():
            try:
                validate_aws_cloudwatch_mappings(
                    mappings, data_type, self.name
                )
            except Exception as mapping_validation_error:
                self.logger.error(
                    message=(
                        f"{validation_err_msg} {err_msg} Error:"
                        f" {mapping_validation_error}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)

        return ValidationResult(
            success=True, message="Mappings validation successful."
        )

    # ───────────────────────── TRANSFORM FLOW ────────────────────────────

    def _get_cef_generator(
        self, delimiter: str, cef_version: str
    ) -> CEFGenerator:
        """Return the CEF generator for the current mapping file.

        Building the generator walks the whole taxonomy twice, so it is
        kept on the instance. The cache is tied to the mapping object it
        was built from, so editing the mapping rebuilds it.

        Args:
            delimiter (str): CEF field delimiter.
            cef_version (str): CEF version string.

        Returns:
            CEFGenerator: Generator matching the current mapping file.
        """
        cached = getattr(self, "_cef_generator_cache", None)
        if cached is not None and cached[0] is self.mappings:
            return cached[1]

        cef_generator = CEFGenerator(
            self.mappings,
            delimiter,
            cef_version,
            self.logger,
            self.log_prefix,
        )
        self._cef_generator_cache = (self.mappings, cef_generator)
        return cef_generator

    def transform(self, raw_data, data_type, subtype) -> List:
        """Turn the raw Netskope records into CEF or JSON log lines.

        Args:
            raw_data (list): Raw records from Netskope.
            data_type (str): Data type, for example alerts or events.
            subtype (str): Subtype, for example dlp or page.

        Returns:
            List: Log lines ready to be pushed.

        Raises:
            AWSCloudWatchPluginError: When the mapping file cannot be read.
        """
        transform_data_json = self._transformation_compatibility_check(
            self.configuration
        )

        if not raw_data:
            return []

        try:
            (
                delimiter,
                cef_version,
                aws_cloudwatch_mappings,
            ) = get_aws_cloudwatch_mappings(self.mappings)
        except KeyError as err:
            error_msg = (
                f"[{data_type}][{subtype}] Could not read the mapping file."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)
        except MappingValidationError as err:
            error_msg = (
                f"[{data_type}][{subtype}] The mapping file is not valid."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)
        except Exception as err:
            error_msg = (
                f"[{data_type}][{subtype}] Could not map the data with the"
                " given mapping file."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)

        if transform_data_json:
            return self._transform_json(
                raw_data,
                data_type,
                subtype,
                aws_cloudwatch_mappings,
            )

        return self._transform_cef(
            raw_data,
            data_type,
            subtype,
            aws_cloudwatch_mappings,
            delimiter,
            cef_version,
        )

    def _transform_json(
        self,
        raw_data,
        data_type,
        subtype,
        aws_cloudwatch_mappings,
    ) -> List:
        """Build the JSON log lines of one batch of records.

        Args:
            raw_data (list): Raw records from Netskope.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.
            aws_cloudwatch_mappings (dict): Taxonomy from the mapping file.

        Returns:
            List: JSON log lines.
        """
        count = 0
        try:
            subtype_mapping = self.get_subtype_mapping(
                aws_cloudwatch_mappings["json"][data_type], subtype
            )
        except MappingValidationError:
            # No JSON mapping is configured for this subtype. Send
            # nothing rather than falling back to the whole raw record:
            # an administrator who removes a subtype to stop shipping it
            # would otherwise get every field of it instead (review F9).
            # An empty field list is different, and still means "send
            # the whole record" — get_subtype_mapping() returns that
            # without raising.
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] No JSON"
                " mapping is configured for this subtype, so no log was"
                " sent. Add the subtype under Settings > Log Shipper to"
                " start sending it."
            )
            return []
        except Exception as err:
            error_msg = (
                f"[{data_type}][{subtype}] Could not read the JSON mapping"
                " of this subtype."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)

        transformed_data = []
        for data in raw_data:
            if not data:
                count += 1
                continue
            try:
                mapped_dict = self.map_json_data(subtype_mapping, data)
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f" not map 1 record. Error: {err}. This record will"
                        " be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                count += 1
                continue

            if not mapped_dict:
                count += 1
                continue

            transformed_data.append(json.dumps(mapped_dict))

        if count > 0:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                f" {count} record(s). They were empty or had none of the"
                " fields listed in the JSON mapping."
            )

        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Transformed"
            f" {len(transformed_data)} record(s) to JSON."
        )
        return transformed_data

    def _transform_cef(
        self,
        raw_data,
        data_type,
        subtype,
        aws_cloudwatch_mappings,
        delimiter,
        cef_version,
    ) -> List:
        """Build the CEF log lines of one batch of records.

        Args:
            raw_data (list): Raw records from Netskope.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.
            aws_cloudwatch_mappings (dict): Taxonomy from the mapping file.
            delimiter (str): CEF field delimiter.
            cef_version (str): CEF version string.

        Returns:
            List: CEF log lines.

        Raises:
            AWSCloudWatchPluginError: When the subtype mapping is missing.
        """
        count = 0
        cef_generator = self._get_cef_generator(delimiter, cef_version)

        try:
            subtype_mapping = self.get_subtype_mapping(
                aws_cloudwatch_mappings[data_type], subtype
            )
        except (KeyError, MappingValidationError) as err:
            error_msg = (
                f"[{data_type}][{subtype}] Unable to find the mappings in"
                " the mapping file."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)
        except Exception as err:
            error_msg = (
                f"[{data_type}][{subtype}] Could not read the CEF mapping"
                " of this subtype."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)

        transformed_data = []
        for data in raw_data:
            if not data:
                count += 1
                continue

            try:
                header, mapped_flag_header = self.get_headers(
                    subtype_mapping["header"], data, data_type, subtype
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f" not build the CEF header of 1 record: {err}."
                        " This record will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                count += 1
                continue

            try:
                extension, mapped_flag_extension = self.get_extensions(
                    subtype_mapping["extension"], data, data_type, subtype
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f" not build the CEF extension of 1 record: {err}."
                        " This record will be skipped."
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
                    transformed_data.append(cef_generated_event)
                else:
                    count += 1
            except EmptyExtensionError:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Got an"
                        " empty CEF extension for 1 record. This record"
                        " will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                count += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f" not transform 1 record. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                count += 1

        if count > 0:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                f" {count} record(s). They were empty or had none of the"
                " fields listed in the CEF mapping."
            )

        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Transformed"
            f" {len(transformed_data)} record(s) to CEF."
        )
        return transformed_data

    # ───────────────────────── PUSH FLOW ─────────────────────────────────

    def _get_aws_client(self) -> AWSCloudWatchClient:
        """Return the AWS client shared by every push on this instance.

        Cloud Exchange serves many push() calls from one plugin object,
        one per data type and subtype. Reusing the client lets the
        IAM Roles Anywhere credentials be fetched once instead of once
        per push (review F4).

        Returns:
            AWSCloudWatchClient: Client bound to this configuration.
        """
        if getattr(self, "_aws_client", None) is None:
            self._aws_client = AWSCloudWatchClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                USER_AGENT,
                lambda: self.ssl_validation,
            )
        return self._aws_client

    def _send_batch(
        self,
        aws_client: AWSCloudWatchClient,
        cloudwatch_client,
        batch: list,
        data_type: str,
        subtype: str,
    ) -> dict:
        """Send one batch, and retry once if the target was removed.

        Args:
            aws_client (AWSCloudWatchClient): Plugin AWS client.
            cloudwatch_client: boto3 CloudWatch Logs client.
            batch (list): Log events to send.
            data_type (str): Data type being pushed.
            subtype (str): Subtype being pushed.

        Returns:
            dict: PutLogEvents response.
        """
        try:
            return aws_client.put_log_events(cloudwatch_client, batch)
        except AWSCloudWatchResourceNotFoundError:
            self.logger.info(
                f"{self.log_prefix}: [{data_type}][{subtype}] The log group"
                " or the log stream was not found. Creating it again and"
                " sending the batch once more."
            )
            aws_client.create_log_group_and_stream(cloudwatch_client)
            return aws_client.put_log_events(cloudwatch_client, batch)

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Send the transformed log lines to AWS CloudWatch Logs.

        On the first batch that fails, the log(s) that already reached
        CloudWatch are removed from ``transformed_data`` in place and the
        error is re-raised. Cloud Exchange retries push() with the same
        list object, so only the un-sent remainder is sent again: no log
        is lost and none is duplicated. Log(s) that a retry could never
        fix, meaning events over the AWS size limit and events AWS
        rejects as too old, too new or expired, are counted and skipped
        instead, so one bad record cannot stall the configuration.

        Args:
            transformed_data (List): Log lines built by transform().
                Trimmed in place when a batch fails.
            data_type (str): Data type, for example alerts or events.
            subtype (str): Subtype, for example dlp or page.

        Returns:
            PushResult: Result of the push.

        Raises:
            AWSCloudWatchPluginError: When the push cannot start, or when
                a batch fails after earlier batches succeeded.
        """
        log_group_name, log_stream_name = self._get_config_params(
            self.configuration, ["log_group_name", "log_stream_name"]
        )
        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Starting to send"
            f" {len(transformed_data)} log(s) to {PLATFORM_NAME} log group"
            f" {log_group_name} and log stream {log_stream_name}."
        )

        try:
            messages, source_index = [], []
            for index, line in enumerate(transformed_data):
                if not line:
                    continue
                messages.append(
                    json.dumps(line) if isinstance(line, dict) else line
                )
                source_index.append(index)
            skipped_empty = len(transformed_data) - len(messages)
            if skipped_empty > 0:
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                    f" {skipped_empty} empty log(s)."
                )

            if not messages:
                log_msg = (
                    f"[{data_type}][{subtype}] No log(s) to send to"
                    f" {PLATFORM_NAME} log group {log_group_name} and log"
                    f" stream {log_stream_name}."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return PushResult(success=True, message=log_msg)

            aws_client = self._get_aws_client()
            aws_client.set_credentials()
            cloudwatch_client = aws_client.get_cloudwatch_client()
            # No DescribeLogGroups or DescribeLogStreams here. Those are
            # account wide, low quota APIs (10 and 25 TPS) and throttling
            # them would block ingestion entirely. validate() checks the
            # target instead, and _send_batch() creates it on demand if
            # it disappears (review F3).

            batch_manager = AWSCloudWatchBatchManager(
                self.logger, self.log_prefix
            )
            # One ingest time for every log of this push. This keeps
            # the batch in time order and inside the 14 day, 2 hour and
            # 24 hour span windows AWS enforces.
            #
            # Note: this makes CloudWatch @timestamp the time Cloud
            # Exchange pushed the record, not the time the event
            # happened at the tenant. To query by event time use the
            # record's own field: 'timestamp' in JSON, or 'rt' / 'end'
            # in CEF.
            timestamp_ms = int(time.time() * 1000)
            batches, batch_starts, oversize_count = (
                batch_manager.build_batches(
                    messages, source_index, timestamp_ms, data_type, subtype
                )
            )

            total_count = 0
            # Failures a retry can never fix, so they never stop the run.
            rejected_total = 0
            total_batches = len(batches)

            for page, batch in enumerate(batches, start=1):
                try:
                    response = self._send_batch(
                        aws_client,
                        cloudwatch_client,
                        batch,
                        data_type,
                        subtype,
                    )
                except AWSCloudWatchPluginError:
                    # Stop at the first failed batch, drop what already
                    # reached CloudWatch, and let Cloud Exchange resend
                    # the rest. Cloud Exchange retries push() with this
                    # same list object, so the list is trimmed in place.
                    #
                    # Sending the later batches first and trimming
                    # afterwards would duplicate them on the retry, so
                    # the loop stops here. This is the pattern used by
                    # snowflake_cls, syslog and darktrace.
                    del transformed_data[:batch_starts[page - 1]]
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]"
                            f" Batch {page} of {total_batches} failed, so"
                            f" the push stopped. {total_count} log(s)"
                            " already reached"
                            f" {PLATFORM_NAME} and were removed from the"
                            f" retry. {len(transformed_data)} log(s) will"
                            " be sent again by Cloud Exchange."
                        ),
                        resolution=(
                            "Check the AWS credentials, the IAM"
                            " permissions on the log group and the"
                            " network connection."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    raise

                rejected_count = batch_manager.count_rejected_events(
                    response, len(batch)
                )
                if rejected_count > 0:
                    rejected_total += rejected_count
                    self.logger.debug(
                        f"{self.log_prefix}: [{data_type}][{subtype}] AWS"
                        f" rejected {rejected_count} log(s) of batch"
                        f" {page}. Rejected details:"
                        f" {response.get('rejectedLogEventsInfo')}"
                    )

                sent_count = len(batch) - rejected_count
                total_count += sent_count
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Sent"
                    f" {sent_count} log(s) in batch {page} of"
                    f" {total_batches} to {PLATFORM_NAME}."
                )

            log_msg = (
                f"[{data_type}][{subtype}] Successfully ingested"
                f" {total_count} log(s) to {PLATFORM_NAME} log group"
                f" {log_group_name} and log stream {log_stream_name}."
            )
            if rejected_total > 0:
                log_msg += (
                    f" {rejected_total} log(s) were rejected by AWS as too"
                    " old, too new or expired."
                )
            if oversize_count > 0:
                log_msg += (
                    f" {oversize_count} log(s) were skipped because they"
                    " are larger than the AWS limit for a single log"
                    " event."
                )
            if skipped_empty > 0:
                log_msg += (
                    f" {skipped_empty} empty log(s) were skipped."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)
        except AWSCloudWatchPluginError:
            raise
        except Exception as exp:
            err_msg = (
                f"[{data_type}][{subtype}] Error occurred while pushing"
                f" log(s) to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(err_msg)

    # ───────────────────────── VALIDATION FLOW ───────────────────────────

    def _validate_iam_roles_anywhere_params(
        self,
        configuration: dict,
        validation_err_msg: str,
    ) -> Union[ValidationResult, None]:
        """Validate the fields needed for IAM Roles Anywhere.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Prefix used in the error log.

        Returns:
            ValidationResult on failure, None on success.
        """
        (
            private_key_file,
            public_certificate_file,
            pass_phrase,
            profile_arn,
            role_arn,
            trust_anchor_arn,
        ) = self._get_config_params(
            configuration,
            [
                "private_key_file",
                "public_certificate_file",
                "pass_phrase",
                "profile_arn",
                "role_arn",
                "trust_anchor_arn",
            ],
        )

        # The order follows AWS_IAM_ROLES_ANYWHERE_CONFIG so the first
        # error the user sees matches the first empty field on screen.
        if key_result := self._validate_configuration_parameters(
            field_name="Private Key",
            field_value=private_key_file,
            field_type=str,
            is_required=True,
            required_field_message=(
                "Private Key is a required configuration parameter when"
                " 'AWS IAM Roles Anywhere' is selected as Authentication"
                " Method."
            ),
            validation_err_msg=validation_err_msg,
        ):
            return key_result

        if cert_result := self._validate_configuration_parameters(
            field_name="Certificate Body",
            field_value=public_certificate_file,
            field_type=str,
            is_required=True,
            required_field_message=(
                "Certificate Body is a required configuration parameter"
                " when 'AWS IAM Roles Anywhere' is selected as"
                " Authentication Method."
            ),
            validation_err_msg=validation_err_msg,
        ):
            return cert_result

        if phrase_result := self._validate_configuration_parameters(
            field_name="Password Phrase",
            field_value=pass_phrase,
            field_type=str,
            is_required=True,
            required_field_message=(
                "Password Phrase is a required configuration parameter"
                " when 'AWS IAM Roles Anywhere' is selected as"
                " Authentication Method."
            ),
            validation_err_msg=validation_err_msg,
        ):
            return phrase_result

        # The PEM checks run after every field is present, because
        # loading an encrypted key needs the passphrase.
        try:
            serialization.load_pem_private_key(
                private_key_file.encode("utf-8"), None
            )
        except Exception:
            try:
                serialization.load_pem_private_key(
                    private_key_file.encode("utf-8"),
                    password=str.encode(pass_phrase),
                )
            except Exception:
                err_msg = (
                    "Invalid Private Key or Password Phrase provided."
                    " Verify the Private Key and Password Phrase. Private"
                    " Key should be in a valid PEM format."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    ),
                    resolution=(
                        "Provide a Private Key in PEM format and a Password"
                        " Phrase that matches the key."
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)

        try:
            x509.load_pem_x509_certificate(
                public_certificate_file.encode()
            )
        except Exception:
            err_msg = (
                "Invalid Certificate Body provided. Certificate Body"
                " should be in valid PEM Format."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                resolution=(
                    "Provide a valid PEM encoded X.509 certificate as the"
                    " Certificate Body."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

        for field_name, field_value in (
            ("Profile ARN", profile_arn),
            ("Role ARN", role_arn),
            ("Trust Anchor ARN", trust_anchor_arn),
        ):
            if arn_result := self._validate_configuration_parameters(
                field_name=field_name,
                field_value=field_value,
                field_type=str,
                is_required=True,
                required_field_message=(
                    f"{field_name} is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as"
                    " Authentication Method."
                ),
                validation_err_msg=validation_err_msg,
            ):
                return arn_result

        return None

    def _validate_custom_region(
        self,
        configuration: dict,
        aws_validator: AWSCloudWatchValidator,
        validation_err_msg: str,
    ) -> Union[ValidationResult, None]:
        """Validate the custom region typed by the user.

        Only the host label rule is applied, because the region is
        placed into manually built URLs. AWS itself validates the region
        at the connection check.

        Args:
            configuration (dict): Plugin configuration parameters.
            aws_validator (AWSCloudWatchValidator): Validator instance.
            validation_err_msg (str): Prefix used in the error log.

        Returns:
            ValidationResult on failure, None on success.
        """
        custom_region = self._safe_strip(
            configuration, "custom_region_name"
        )
        if lbl_result := self._validate_configuration_parameters(
            field_name="AWS CloudWatch Custom Region",
            field_value=custom_region,
            field_type=str,
            is_required=True,
            required_field_message=(
                "AWS CloudWatch Custom Region is a required configuration"
                " parameter when 'Custom Region' is selected as AWS"
                " CloudWatch Region Name."
            ),
            validation_err_msg=validation_err_msg,
        ):
            return lbl_result

        if not aws_validator.validate_custom_region_name(custom_region):
            err_msg = (
                "Invalid AWS CloudWatch Custom Region provided. It must"
                " be a valid AWS region code: letters, digits and"
                " hyphens, 1 to 63 characters, not starting or ending"
                " with a hyphen."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Provide the AWS region code of the log group, for"
                    " example us-west-1."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # The Roles Anywhere host and the SigV4 scope are built by hand,
        # so a partition that cannot be expressed must be refused here.
        if (
            configuration.get("authentication_method")
            == AWS_IAM_ROLES_ANYWHERE
            and get_region_partition(custom_region) is None
        ):
            err_msg = (
                "AWS IAM Roles Anywhere is not supported for the region"
                f" '{custom_region}'. The ISO and AWS European Sovereign"
                " Cloud regions cannot be used with this authentication"
                " method."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Use 'Deployed on AWS', or a region of the aws,"
                    " aws-cn or aws-us-gov partition."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def _validate_connectivity(
        self, configuration: dict, validation_err_msg: str
    ) -> Union[ValidationResult, None]:
        """Check the AWS credentials, the permissions and the target.

        The check only reads and creates resources. No log event is
        written to CloudWatch Logs.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Prefix used in the error log.

        Returns:
            ValidationResult on failure, None on success.
        """
        try:
            aws_client = AWSCloudWatchClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                USER_AGENT,
                lambda: self.ssl_validation,
            )
            aws_client.set_credentials()
            cloudwatch_client = aws_client.get_cloudwatch_client(
                validation_retries=VALIDATION_MAX_RETRIES
            )
            aws_client.validate_credentials(cloudwatch_client)
            aws_client.ensure_log_group_and_stream(cloudwatch_client)
        except AWSCloudWatchPluginError as exp:
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                f"Error occurred while connecting to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    f" Error: {exp}"
                ),
                resolution=(
                    "Check the Authentication Method, the AWS CloudWatch"
                    " Region Name and the network connection."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters.

        The checks run in this order:
          1. Authentication Method
          2. IAM Roles Anywhere parameters, when that method is selected
          3. AWS CloudWatch Region Name
          4. Log Group Name
          5. Log Stream Name
          6. Mapping file
          7. AWS connection, permissions and target resources

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Result of the validation.
        """
        validation_err_msg = VALIDATION_ERROR_MESSAGE
        aws_validator = AWSCloudWatchValidator(self.logger, self.log_prefix)

        (
            authentication_method,
            region_name,
            log_group_name,
            log_stream_name,
        ) = self._get_config_params(
            configuration,
            [
                "authentication_method",
                "region_name",
                "log_group_name",
                "log_stream_name",
            ],
        )

        # 1. Authentication Method
        if auth_result := self._validate_configuration_parameters(
            field_name="Authentication Method",
            field_value=authentication_method,
            field_type=str,
            is_required=True,
            allowed_values=AUTHENTICATION_METHODS,
            validation_err_msg=validation_err_msg,
        ):
            return auth_result

        # 2. IAM Roles Anywhere parameters
        if authentication_method == AWS_IAM_ROLES_ANYWHERE:
            if iam_result := self._validate_iam_roles_anywhere_params(
                configuration, validation_err_msg
            ):
                return iam_result

        # 3. AWS CloudWatch Region Name
        if region_result := self._validate_configuration_parameters(
            field_name="AWS CloudWatch Region Name",
            field_value=region_name,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return region_result
        if region_name == CUSTOM_REGION_VALUE:
            if custom_result := self._validate_custom_region(
                configuration, aws_validator, validation_err_msg
            ):
                return custom_result
        elif not aws_validator.validate_region_name(region_name):
            err_msg = (
                "Invalid AWS CloudWatch Region Name found in the"
                " configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Select an AWS CloudWatch Region Name from the list of"
                    " available choices."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # 4. Log Group Name
        if group_result := self._validate_configuration_parameters(
            field_name="Log Group Name",
            field_value=log_group_name,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return group_result
        if not aws_validator.validate_log_group_name(log_group_name):
            err_msg = (
                "Invalid Log Group Name provided. It must be"
                f" {LOG_NAME_MIN_LENGTH} to {LOG_NAME_MAX_LENGTH}"
                " characters long and can contain letters, digits and the"
                " characters . - _ / #"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Provide a Log Group Name that follows the AWS naming"
                    " rules."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # 5. Log Stream Name
        if stream_result := self._validate_configuration_parameters(
            field_name="Log Stream Name",
            field_value=log_stream_name,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return stream_result
        if not aws_validator.validate_log_stream_name(log_stream_name):
            err_msg = (
                "Invalid Log Stream Name provided. It must be"
                f" {LOG_NAME_MIN_LENGTH} to {LOG_NAME_MAX_LENGTH}"
                " characters long and must not contain : or *"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Provide a Log Stream Name that follows the AWS naming"
                    " rules."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # 6. Mapping file
        mappings_result = self.validate_mappings()
        if not mappings_result.success:
            return mappings_result

        # 7. AWS connection, permissions and target resources
        if connectivity_result := self._validate_connectivity(
            configuration, validation_err_msg
        ):
            return connectivity_result

        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def chunk_size(self) -> int:
        """Return the number of records handed to one push call.

        Returns:
            int: Chunk size per thread.
        """
        return CHUNK_SIZE
