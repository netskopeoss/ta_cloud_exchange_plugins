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

Amazon Security Lake Plugin."""

import json
import re
import traceback
import collections
from .lib.unflatten import unflatten
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from typing import Callable, Dict, List, Union

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.amazon_security_lake_client import (
    AmazonSecurityLakeClient,
)
from .utils.amazon_security_lake_batch_manager import (
    ParquetBatchWriter,
)
from .utils.amazon_security_lake_exceptions import (
    AmazonSecurityLakeException,
)
from .utils.amazon_security_lake_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    REGIONS,
    MAX_RETRIES,
    AUTHENTICATION_METHODS,
    TRANSFORM_DATE_FORMAT,
    CUSTOM_SOURCE_DETAILS_CONFIG,
    CUSTOM_SOURCE_NAME_PATTERN,
    COMMON_CONFIG,
    AWS_IAM_ROLES_ANYWHERE_CONFIG,
    SUBTYPE_MAPPING
)

from netskope.integrations.cls.utils.converter import type_converter


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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AmazonSecurityLakePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_custom_source_name(self, subtype):
        """Get the custom source name for a given subtype.
        
        Args:
            subtype (str): The subtype (e.g., 'dlp', 'c2', 'application').
        
        Returns:
            tuple: (custom_source_name, event_classes).
        
        Raises:
            AmazonSecurityLakeException: If subtype is not found in mapping
                or custom source is not configured for the subtype.
        """
        # Normalize subtype
        normalized_subtype = subtype.lower().replace(" ", "").replace("-", "")
        
        # Get config key and event classes from mapping
        if normalized_subtype in SUBTYPE_MAPPING:
            config_key = SUBTYPE_MAPPING[normalized_subtype]["config_key"]
            event_classes = SUBTYPE_MAPPING[normalized_subtype]["event_classes"]
        else:
            err_msg = (
                f"{self.log_prefix}: Subtype '{subtype}' "
                "not found in SUBTYPE_MAPPING."
            )
            self.logger.error(
                message=err_msg,
                details=traceback.format_exc()
            )
            raise AmazonSecurityLakeException(err_msg)

        # Get custom source name from configuration
        custom_source_name = self.configuration.get(config_key, "").strip()
        
        # If not configured, raise an error - do not fall back to default
        if not custom_source_name:
            err_msg = (
                f"Custom Data Source Name is not configured for "
                f"subtype '{subtype}' (config key: '{config_key}'). "
                f"Please configure a custom source name for this subtype "
                f"in the plugin configuration before pushing data."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc()
            )
            raise AmazonSecurityLakeException(err_msg)

        return custom_source_name, event_classes

    def _ensure_custom_source_exists(
        self, 
        subtype: str, 
        aws_client: AmazonSecurityLakeClient
    ):
        """Ensure custom source exists and return S3 location.
        
        This method checks
            1. if the custom source exists in storage. 
            2. If not, it creates or fetches it from AWS and stores the S3 location.
        
        Args:
            subtype (str): The subtype (e.g., 'dlp', 'c2', 'application').
            aws_client (AmazonSecurityLakeClient): The AWS client.
        
        Returns:
            tuple: (custom_source_name, source_details)
            custom_source_name: The name of the custom source.
            source_details: Dict with S3 location and provider role ARN.
        """
        # Get custom source name and event classes
        custom_source_name, event_classes = self._get_custom_source_name(
            subtype
        )

        # Ensure storage structure exists
        if self.storage is None:
            self.storage = {}

        # Check if S3 location metadata is already in storage
        if "custom_sources" not in self.storage:
            self.storage["custom_sources"] = {}
        
        # Check if this custom source is already in storage with complete metadata
        source_details = self.storage["custom_sources"].get(custom_source_name)
        if source_details:
            s3_location = source_details.get("s3_location")
            provider_role_arn = source_details.get("provider_role_arn")
            trust_policy_checked = source_details.get("trust_policy_checked", False)
            trust_policy_checked = False if trust_policy_checked is None else trust_policy_checked

            if s3_location and provider_role_arn:
                # Re-verify trust policy if not marked checked
                if trust_policy_checked is not True:
                    trust_policy_checked = aws_client._ensure_trust_policy_if_applicable(
                        provider_role_arn, custom_source_name
                    )
                source_details["trust_policy_checked"] = trust_policy_checked
                self.storage["custom_sources"][custom_source_name] = source_details

                self.logger.debug(
                    f"{self.log_prefix} [{subtype}]: Using cached metadata for "
                    f"'{custom_source_name}' (trust_policy_checked={trust_policy_checked}): "
                    f"{source_details}"
                )
                return custom_source_name, source_details
            
            self.logger.info(
                f"{self.log_prefix} [{subtype}]: Cached metadata for '{custom_source_name}' "
                "is incomplete. Refreshing from AWS."
            )
        else:
            self.logger.info(
                f"{self.log_prefix} [{subtype}]: No cached metadata for '{custom_source_name}'. "
                "Fetching from AWS..."
            )
        
        # Get or create the custom source
        source_details = aws_client.get_or_create_custom_log_source(
            source_name=custom_source_name,
            event_classes=event_classes,
            max_retries=MAX_RETRIES
        )

        # Store in storage
        self.storage["custom_sources"][custom_source_name] = source_details
        
        self.logger.info(
            f"{self.log_prefix} [{subtype}]: Stored S3 location for '{custom_source_name}': "
            f"{source_details.get('s3_location')}"
        )
        
        return custom_source_name, source_details

    # transform
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

    def _get_nested_value(self, data: dict, path: str):
        """Safely retrieve a nested value using a dot-separated path.
        
        Use this for paths without array indexing (e.g., 'user.name').
        For paths with array indexing, use _get_nested_value_with_index.
        """
        if not path or not isinstance(data, dict):
            return None

        current = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _get_nested_value_with_index(self, data: dict, path: str):
        """Safely retrieve a nested value using dot-separated path with array indexing.
        
        Supports paths like:
        - 'users[0].name'
        - 'data[0][1]'
        - 'users[0].addresses[1].city'
        
        Returns None for invalid/malformed paths (unclosed brackets, empty index,
        non-numeric index, negative index, out-of-range index, type mismatch).
        """
        if not path or not isinstance(data, dict):
            return None

        current = data
        for segment in path.split("."):
            if not segment:
                return None
            
            # Process segment which may contain array indices like "users[0][1]"
            while segment:
                bracket_pos = segment.find("[")
                
                if bracket_pos == -1:
                    # No more brackets, treat remaining segment as dict key
                    if not isinstance(current, dict) or segment not in current:
                        return None
                    current = current[segment]
                    break
                
                # Extract dict key before the bracket (may be empty for consecutive indices)
                dict_key = segment[:bracket_pos]
                if dict_key:
                    if not isinstance(current, dict) or dict_key not in current:
                        return None
                    current = current[dict_key]
                
                # Find closing bracket
                close_bracket_pos = segment.find("]", bracket_pos)
                if close_bracket_pos == -1:
                    # Malformed: unclosed bracket
                    return None
                
                # Extract and validate index
                idx_str = segment[bracket_pos + 1:close_bracket_pos]
                if not idx_str or not idx_str.isdigit():
                    # Malformed: empty index, non-numeric, or negative (has '-')
                    return None
                
                idx = int(idx_str)
                if not isinstance(current, (list, tuple)) or idx >= len(current):
                    # Type mismatch or out-of-range
                    return None
                current = current[idx]
                
                # Continue with remainder after the closing bracket
                segment = segment[close_bracket_pos + 1:]
                # After an index, only another index is allowed within the same segment.
                # This makes paths like "users[0]name" invalid; users must write "users[0].name".
                if segment and not segment.startswith("["):
                    return None
        
        return current

    def _normalize_epoch_to_millis(self, epoch_value: Union[int, float]) -> int:
        """Normalize epoch timestamps to milliseconds.

        Accept seconds/milliseconds/microseconds/nanoseconds and convert to
        epoch milliseconds (int).
        """
        # bool is a subclass of int; treat it as invalid timestamp input
        if isinstance(epoch_value, bool):
            raise ValueError("Boolean is not a valid epoch timestamp.")

        v = float(epoch_value)
        av = abs(v)

        # Heuristics by magnitude:
        # - seconds: ~1e9 (2020s)
        # - millis : ~1e12
        # - micros : ~1e15
        # - nanos  : ~1e18
        if av < 10_000_000_000:  # < 1e10 => seconds
            return int(v * 1000)
        if av < 10_000_000_000_000:  # < 1e13 => milliseconds
            return int(v)
        if av < 10_000_000_000_000_000:  # < 1e16 => microseconds
            return int(v / 1000)
        # otherwise assume nanoseconds
        return int(v / 1_000_000)

    def _convert_time_stamp(self, val, debug_name: str) -> int:
        """Convert epoch/datetime representations to epoch milliseconds (Long).

        Rules:
        - If val is int/float => treat as epoch and normalize to milliseconds.
        - If val is string:
          - if it's numeric => treat as epoch and normalize to milliseconds
          - else try parsing as datetime (via dateutil parser) => convert to UTC => ms
          - if neither numeric nor parseable datetime => return None
        """
        if val is None or val == "":
            return None

        # bool is a subclass of int; treat it as invalid timestamp input
        if isinstance(val, bool):
            return None

        if isinstance(val, (int, float)):
            try:
                return self._normalize_epoch_to_millis(val)
            except Exception:
                return None

        s = str(val).strip()
        if not s:
            return None

        # Numeric epoch in string form
        if re.fullmatch(r"[+-]?\d+(\.\d+)?", s):
            try:
                return self._normalize_epoch_to_millis(float(s))
            except Exception:
                return None

        # Datetime string
        dt = None
        try:
            # Preferred: dateutil is more flexible than hardcoded formats
            from dateutil import parser as dateutil_parser  # type: ignore

            dt = dateutil_parser.parse(s)
        except Exception:
            # Fallback: handle common ISO-ish strings if dateutil isn't available
            try:
                s_iso = s[:-1] + "+00:00" if s.endswith("Z") else s
                dt = datetime.fromisoformat(s_iso)
            except Exception:
                return None

        if dt is None:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        return int(dt.timestamp() * 1000)

    def _transform_value(
        self,
        data_type,
        subtype,
        field,
        value,
        transformation,
        default_value,
    ):
        """Transform value using configured converter; defaults are converted too.

        Args:
            data_type (str): Data type label for logging.
            subtype (str): Subtype label for logging.
            field (str): Target field name.
            value: Source value (may be None).
            transformation (str): Converter key.
            default_value: Default to use when value is None.
        Returns:
            Any: Converted value or None on failure.
        """
        converters = type_converter()
        extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )

        # Choose value or default for conversion
        chosen_value = value if value is not None else default_value
        if chosen_value is None:
            return None

        try:
            if transformation:
                # Override CE core behavior for Time Stamp:
                # always return epoch milliseconds (Long) and accept datetime strings.
                if str(transformation).strip().lower() in {
                    "time stamp",
                }:
                    return self._convert_time_stamp(chosen_value, field)
                return extension_converter(
                    key_name=field, converter=converters[transformation]
                ).converter(chosen_value, field)
            return chosen_value
        except Exception as e:
            error_message = (
                f"{self.log_prefix}: [{data_type}][{subtype}]- "
                "An error occurred while transforming "
                f'data for field: "{field}". '
                f"Error: {str(e)}. "
            )
            self.logger.debug(
                message=error_message,
                details=str(traceback.format_exc())
            )
            return None

    def _transform_and_append(
        self,
        data_type: str,
        subtype: str,
        data: dict,
        mappings: dict,
    ):
        """Transform a single record using two-pass mapping, enums, and sync.

        Args:
            data_type (str): Data type label for logging.
            subtype (str): Subtype label for logging.
            data (dict): Source record.
            mappings (dict): Mapping definition for the subtype.
        Returns:
            dict: Transformed record (nested) including raw_data and any
            explicitly mapped fields (e.g., unmapped.*).
        """
        raw_temp = {}
        final_temp = {}

        # Phase 1: raw mapping (no conversion)
        for field, mapping_dict in mappings.items():
            try:
                raw_value = self._extract_raw_value(
                    data_type,
                    subtype,
                    field,
                    mapping_dict,
                    data,
                )
            except Exception as exp:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] "
                        f'Error extracting field "{field}": {str(exp)}. Using None.'
                    ),
                    details=str(traceback.format_exc()),
                )
                raw_value = None
            raw_temp[field] = raw_value

        # Phase 2: fields conversion
        for field, mapping_dict in mappings.items():
            value = raw_temp.get(field)
            try:
                final_temp[field] = self._transform_value(
                    data_type,
                    subtype,
                    field,
                    value,
                    mapping_dict.get("transformation", None),
                    mapping_dict.get("default_value", None),
                )
            except Exception as exp:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] "
                        f'Error transforming field "{field}": {str(exp)}. Using None.'
                    ),
                    details=str(traceback.format_exc()),
                )
                final_temp[field] = None

        # Phase 3: Unflatten + finalize

        # Unflatten to create nested structure
        converted_json = unflatten(final_temp)

        # Handle raw_data field based on mapping configuration:
        # 1. If no raw_data field in mapping -> not added
        # 2. If default_value="raw_data" -> add json dump of original event
        # 3. If mapping_field -> handled by normal transformation
        if "raw_data" in mappings:
            raw_data_mapping = mappings["raw_data"]
            mapping_field = raw_data_mapping.get("mapping_field", "")
            default_value = raw_data_mapping.get("default_value", "")
            if default_value == "raw_data" and not mapping_field:
                converted_json["raw_data"] = json.dumps(data)

        return converted_json

    def _safe_int(self, value):
        """Attempt int conversion.

        Args:
            value: Value to convert.
        Returns:
            int | None: Parsed int or None on failure/blank.
        """
        if value is None or value == "":
            return None
        try:
            return int(value)
        except Exception:
            return None

    def _reverse_lookup_enum(self, enum_map: dict, caption: str):
        """Find enum id by caption (case-insensitive).

        Args:
            enum_map (dict): Map of id -> caption.
            caption (str): Caption to search.
        Returns:
            int | None: Matching enum id or None.
        """
        if caption is None:
            return None
        caption_norm = str(caption).strip().lower()
        for enum_id, enum_caption in enum_map.items():
            if enum_caption is None:
                continue
            if str(enum_caption).strip().lower() == caption_norm:
                return enum_id
        return None

    def _extract_raw_value(
        self,
        data_type,
        subtype,
        field,
        mapping_dict,
        data,
    ):
        """First-pass extraction without conversion.

        Args:
            data_type (str): Data type label for logging.
            subtype (str): Subtype label for logging.
            field (str): Target field name.
        mapping_dict (dict): Mapping definition.
        data (dict): Source record.
        Returns:
            Any: Raw value or default (no conversion).
        """
        value = None
        if "mapping_field" in mapping_dict:
            mapping_field = mapping_dict.get("mapping_field")

            if mapping_field == "date:time":
                if data.get("date") and data.get("time"):
                    date_time = f"{data['date']}T{data['time']}Z"
                    value = int(
                        datetime.strptime(
                            date_time, TRANSFORM_DATE_FORMAT
                        ).timestamp()
                    )
            elif mapping_field:
                if "[" in mapping_field:
                    # Path with array indexing (e.g., 'users[0].name')
                    nested_value = self._get_nested_value_with_index(data, mapping_field)
                    if nested_value is not None:
                        value = nested_value
                elif "." in mapping_field:
                    # Dot-only nested path (e.g., 'user.name')
                    nested_value = self._get_nested_value(data, mapping_field)
                    if nested_value is not None:
                        value = nested_value
                elif mapping_field in data:
                    value = data[mapping_field]
            if value is None and "default_value" in mapping_dict:
                value = mapping_dict.get("default_value")
        elif "default_value" in mapping_dict:
            value = mapping_dict.get("default_value")

        return value

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform
         supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested
            (alert/event/webtx)
            subtype (str): The subtype of data to be ingested (DLP,
            anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: List of transformed data.
        """
        transform_data = self.configuration.get("transformData", "ocsf").strip()
        if transform_data != "ocsf":
            err_msg = (
                f"{self.log_prefix}: This plugin is designed to send"
                " transformed data to Amazon Security Lake Bucket"
                " - Please select OCSF format."
            )
            self.logger.error(
                message=err_msg,
                details=traceback.format_exc()
            )
            raise AmazonSecurityLakeException(err_msg)

        result_list = []
        try:
            amazon_security_lake_subtype_mapping = self.get_subtype_mapping(  # noqa: E501
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
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the provided mapping configuration for "
                    f"subtype '{subtype}' is valid and matches the expected format."
                ),
            )
            raise AmazonSecurityLakeException(err)
        try:
            success = 0
            failed = 0
            skipped = 0
            for data in raw_data:
                try:
                    if not data:
                        skipped += 1
                        continue
                    transformed_dict = self._transform_and_append(
                        data_type,
                        subtype,
                        data,
                        amazon_security_lake_subtype_mapping["extension"],
                    )
                    if transformed_dict is not None:
                        result_list.append(transformed_dict)
                        success += 1
                    else:
                        failed += 1
                except Exception as exp:
                    failed += 1
                    self.logger.debug(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] "
                            f"Skipping record due to error: {str(exp)}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    continue

            total = len(raw_data)
            self.logger.info(
                f"{self.log_prefix}: [{data_type}][{subtype}] "
                f"Processed {total} records: {success} succeeded, {failed} failed, {skipped} empty records skipped."
            )
            return result_list
        except Exception as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while transforming data. "
                    f"Error: {str(e)}"
                ),
                details=traceback.format_exc(),
            )
            raise AmazonSecurityLakeException(e)

    def log_success_msg(
        self, data_type, subtype, successful_log_push_counter
    ):
        """Log the success message.
        
        Args:
            data_type: Data type.
            subtype: Subtype.
            successful_log_push_counter: Successful log push counter.
        """
        log_msg = ""
        if successful_log_push_counter > 0:
            log_msg = (
                f"[{data_type}] [{subtype}]: Successfully "
                f"added {successful_log_push_counter} log(s)"
                " to the AWS Security Lake upload file. "
                "The file will be uploaded to the AWS Security Lake bucket"
                " once either 256 MB file size or 5 minutes upload "
                "condition is met."
            )
        if log_msg:
            self.logger.info(f"{self.log_prefix} {log_msg}")
        return log_msg

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform.
        
        Args:
            transformed_data: Transformed data (list of dicts).
            data_type: Data type.
            subtype: Subtype.
        Returns:
            PushResult: Push result.
        """
        try:
            current_batch_size = len(transformed_data)
            
            if self.storage is None:
                self.storage = {}
            
            # Ensure custom source exists and get S3 location
            aws_client = AmazonSecurityLakeClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                f"{self.log_prefix} [{subtype}]",
            )
            aws_client.set_credentials()

            custom_source_name, source_details = self._ensure_custom_source_exists(
                subtype, aws_client=aws_client
            )
            s3_location = source_details.get("s3_location")
            provider_role_arn = source_details.get("provider_role_arn")

            batch_writer = ParquetBatchWriter(
                aws_client=aws_client,
                logger=self.logger,
                log_prefix=self.log_prefix,
                subtype=subtype,
                s3_location=s3_location,
                provider_role_arn=provider_role_arn,
                custom_source_name=custom_source_name,
            )
            # Push list of dicts directly to batch writer
            batch_writer.push(transformed_data)
            log_msg = self.log_success_msg(
                data_type, subtype, current_batch_size
            )
            return PushResult(
                success=True,
                message=log_msg,
            )
        except AmazonSecurityLakeException:
            raise
        except Exception as e:
            error_mesage = (
                f"{self.log_prefix}: An unexpected error occurred "
                f"while pushing data to Amazon Security Lake "
                f"sub_type: {subtype}. "
                f"data_type: {data_type}. "
                f"Error: {str(e)}"
            )
            self.logger.error(
                message=error_mesage,
                details=traceback.format_exc()
            )
            raise AmazonSecurityLakeException(error_mesage)

    # validate
    def _validate_auth_params(
        self, configuration, validation_err_msg, validation_source_key
    ):
        """Validate the Plugin configuration parameters.

        Args:
            configuration: Dict object having all the Plugin
            configuration parameters.
            validation_err_msg: Error message.
            validation_source_key: The config key of the first configured
            custom source to use for validation test.
        """
        try:
            aws_client = AmazonSecurityLakeClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
            )
            aws_client.set_credentials()
            aws_client.validate_credentials()
            
            # Use the first configured custom source for validation test
            source_name = configuration.get(validation_source_key, "").strip()
            
            subtype = next(
                (
                    subtype_key
                    for subtype_key, details in SUBTYPE_MAPPING.items()
                    if details.get("config_key") == validation_source_key
                ),
                None,
            )
            if not subtype:
                err_msg = (
                    f"{self.log_prefix}: No subtype found for config key "
                    f"'{validation_source_key}'."
                )
                self.logger.error(message=err_msg)
                return False, err_msg
            
            # Get event classes for this subtype
            source_event_classes = SUBTYPE_MAPPING.get(
                subtype, {}
            ).get("event_classes", None)
            if not source_event_classes:
                err_msg = (
                    f"{self.log_prefix}: No event classes found for subtype '{subtype}'."
                )
                self.logger.error(
                    message=err_msg,
                    details=traceback.format_exc()
                )
                return False, err_msg
            
            self.logger.info(
                f"{self.log_prefix}: Validating custom source creation with "
                f"'{source_name}' (subtype: {subtype})..."
            )
            
            # Create or get custom source with 1 retry
            source_details = aws_client.get_or_create_custom_log_source(
                source_name=source_name,
                event_classes=source_event_classes,
                max_retries=1
            )
            if not source_details or not source_details.get("s3_location"):
                err_msg = (
                    f"{self.log_prefix}: Failed to validate custom source "
                    f"creation with '{source_name}' (subtype: {subtype})."
                )
                self.logger.error(
                    message=err_msg,
                    details=traceback.format_exc()
                )
                return False, err_msg
            
            self.logger.info(
                f"{self.log_prefix}: Successfully validated custom source "
                f"creation with '{source_name}' (subtype: {subtype})."
            )
            
            return True, "success"
        except AmazonSecurityLakeException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, str(exp)
        except Exception as exp:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}"
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, error_msg

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if isinstance(field_value, str):
            field_value = field_value.strip()
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            if len(allowed_values) <= 5:
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. Allowed values are"
                    f" {', '.join(value for value in allowed_values)}."
                )
            else:
                err_msg = (
                    f"Invalid value for '{field_name}' provided "
                    f"in the configuration parameters."
                )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration: Configuration parameters dict.

        Returns:
            ValidationResult: Validation result.
        """
        validation_err_msg = "Validation error occurred."


        transform_data = configuration.get("transformData", "ocsf").strip() 
        if transform_data != "ocsf":
            err_msg = (
                "Cannot send raw data to Amazon Security Lake - "
                "Please select OCSF format."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if authentication_method := self._validate_configuration_parameters(
            field_name="Authentication Method",
            field_value=authentication_method,
            field_type=str,
            allowed_values=AUTHENTICATION_METHODS,
            is_required=True,
        ):
            return authentication_method

        if authentication_method == "aws_iam_roles_anywhere":
            pass_phrase = configuration.get("pass_phrase")
            if not pass_phrase:
                err_msg = (
                    "Password Phrase is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            elif not isinstance(pass_phrase, str):
                err_msg = (
                    "Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )

            # Validate Private Key File.
            private_key_file = configuration.get(
                "private_key_file", ""
            ).strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(private_key_file, str):
                err_msg = (
                    "Invalid Private Key found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            else:
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
                            "Invalid Private Key or Password Phrase provided. "
                            "Verify the Private Key and Password Phrase. "
                            "Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg} "
                                f"Error: {err_msg}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        return ValidationResult(
                            success=False,
                            message=f"{err_msg}",
                        )

            # Validate Certificate Body.
            public_certificate_file = configuration.get(
                "public_certificate_file", ""
            ).strip()

            if not public_certificate_file:
                error_msg = (
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' "
                    "is selected as Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(public_certificate_file, str):
                err_msg = (
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            else:
                try:
                    x509.load_pem_x509_certificate(
                        public_certificate_file.encode()
                    )
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid Pem Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_err_msg} "
                            f"Error: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}",
                    )

            # Validate Profile ARN.
            profile_arn = configuration.get("profile_arn", "").strip()
            if not profile_arn:
                error_msg = (
                    "Profile ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                err_msg = (
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                err_msg = (
                    "Invalid Role ARN found in the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get(
                "trust_anchor_arn", ""
            ).strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                err_msg = (
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            auto_update_trust_policy = (
                configuration.get("auto_update_trust_policy", "yes") or "yes"
            )
            auto_update_trust_policy = str(auto_update_trust_policy).strip().lower()
            if validation_result := self._validate_configuration_parameters(
                field_name="Auto-update Provider Role Trust Policy",
                field_value=auto_update_trust_policy,
                field_type=str,
                allowed_values=["yes", "no"],
                is_required=True,
            ):
                return validation_result

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="AWS S3 Source Bucket Region",
            field_value=region_name,
            field_type=str,
            allowed_values=REGIONS,
            is_required=True,
        ):
            return validation_result
        
        # Validate Account ID.
        account_id = configuration.get("account_id", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="AWS Account ID",
            field_value=account_id,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Prefix.
        prefix = configuration.get("prefix", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Parquet File Name Prefix",
            field_value=prefix,
            field_type=str,
            is_required=False,
        ):
            return validation_result

        # Validate AWS Crawler Role ARN.
        crawler_role_arn = configuration.get("crawler_role_arn", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="AWS Crawler Role ARN",
            field_value=crawler_role_arn,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Provider External ID.
        provider_external_id = configuration.get("provider_external_id", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Provider External ID",
            field_value=provider_external_id,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Provider Principal.
        provider_principal = configuration.get("provider_principal", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Provider Principal",
            field_value=provider_principal,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Custom Source Details Config fields.
        # At least one custom source must be configured.
        custom_source_fields = [
            field["key"] for field in CUSTOM_SOURCE_DETAILS_CONFIG
        ]
        configured_custom_sources = []
        for field_key in custom_source_fields:
            field_value = configuration.get(field_key, "").strip()
            if field_value:  # Only validate type if value is provided
                configured_custom_sources.append(field_key)
                formatted_name = (
                    field_key.removeprefix("custom_source_name_")
                    .replace("_", " ")
                    .title()
                )
                if validation_result := self._validate_configuration_parameters(
                    field_name=f"Custom Data Source Name for ({formatted_name})",
                    field_value=field_value,
                    field_type=str,
                    is_required=False,
                ):
                    return validation_result
                if not re.fullmatch(CUSTOM_SOURCE_NAME_PATTERN, field_value):
                    err_msg = (
                        f"Custom Data Source Name for '{formatted_name}' "
                        "contains invalid characters. Only letters, numbers, "
                        "underscore (_), hyphen (-), colon (:), and dot (.) are allowed."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                # Validate length (must be <= 20 characters)
                if len(field_value) > 20:
                    return ValidationResult(
                        success=False,
                        message=(
                            f"Custom Data Source Name for '{formatted_name}' "
                            f"exceeds 20 character limit (length: {len(field_value)})."
                        ),
                    )

        # Ensure at least one custom source is configured
        if not configured_custom_sources:
            err_msg = (
                "At least one Custom Data Source Name must be configured. "
                "Please provide a value for at least one custom source field."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # validate authentication parameters
        # Pass the first configured custom source for validation test
        success, message = self._validate_auth_params(
            configuration, validation_err_msg, configured_custom_sources[0]
        )
        if not success:
            return ValidationResult(
                success=False,
                message=f"{message}",
            )

        # validation successful
        validation_msg = f"Validation Successful for {PLUGIN_NAME} plugin."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(
            success=True,
            message=validation_msg,
        )

    def get_dynamic_fields(self):
        """Get the dynamic fields from plugin."""
        authentication_method = self.configuration.get("authentication_method", None)
        if authentication_method and authentication_method == "aws_iam_roles_anywhere":
            return AWS_IAM_ROLES_ANYWHERE_CONFIG + COMMON_CONFIG + CUSTOM_SOURCE_DETAILS_CONFIG
        else:
            return COMMON_CONFIG + CUSTOM_SOURCE_DETAILS_CONFIG
