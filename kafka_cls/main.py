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

CLS Kafka Plugin.
"""

import json
import os
import re
from ssl import SSLError
import tempfile
import time
import traceback
from typing import List

from jsonpath import jsonpath

import sys
kafka_path = os.path.join(os.path.dirname(__file__), 'lib')
if kafka_path not in sys.path:
    sys.path.insert(0, kafka_path)

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import (
    AuthenticationFailedError,
    AuthenticationMethodNotSupported,
    ClusterAuthorizationFailedError,
    InvalidTopicError,
    KafkaConnectionError,
    KafkaTimeoutError,
    MessageSizeTooLargeError,
    NoBrokersAvailable,
    TopicAuthorizationFailedError,
)
from kafka.partitioner import DefaultPartitioner
from netskope.common.utils import AlertsHelper, add_user_agent
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.kafka_cef_generator import CEFGenerator
from .utils.kafka_constants import (
    ACKS,
    COMPRESSION_TYPE,
    IDENTIFIER_ALLOWED_VALUES,
    KAFKA_SECURITY_PROTOCOLS,
    LINGER_MS,
    MODULE_NAME,
    TIMEOUT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    BATCH_SIZE,
    RETRIES,
    TIMEOUT_MS,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.kafka_exceptions import (
    EmptyExtensionError,
    FieldNotFoundError,
    MappingValidationError,
)
from .utils.kafka_helper import (
    get_kafka_mappings,
    get_nested_field_value,
    get_subtype_mapping,
    map_json_data,
)
from .utils.kafka_validator import KafkaValidator


class KafkaException(Exception):
    "Custom Exception class for Kafka Plugin."
    pass


class KafkaPlugin(PluginBase):
    """The kafka plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize KafkaPlugin class."""
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
                    f"{self.log_prefix}: Error occurred while getting "
                    f"plugin details. Error: {exp}"
                ),
                resolution=(
                    "Ensure that the plugin's manifest.json file is "
                    "present and readable."
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_user_agent(self) -> str:
        """Add Client Name to request plugin make.

        Returns:
            str: String containing the Client Name.
        """
        headers = add_user_agent()
        plugin_name = PLATFORM_NAME.lower()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-cls-{}-v{}".format(
            ce_added_agent, plugin_name, self.plugin_version
        )
        return user_agent

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

    def get_nested_field_value(self, data, field_path):
        """Extract a value from a nested dict using dot notation.

        Thin delegator to the shared
        :func:`utils.kafka_helper.get_nested_field_value` helper so the
        lookup logic lives in one reusable place.

        Args:
            data: The record dictionary to search.
            field_path: Dot-separated field path.

        Returns:
            tuple: (value, exists) where exists is True only if every
            segment of the path resolved.
        """
        return get_nested_field_value(
            data, field_path, self.logger, self.log_prefix
        )

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings (mappings for subtypes of
            alerts/events) case insensitively.

        Thin delegator to the shared
        :func:`utils.kafka_helper.get_subtype_mapping` helper, used by
        both the CEF and JSON transform paths.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the
                mapping is to be fetched

        Returns:
            Fetched mapping JSON object
        """
        return get_subtype_mapping(mappings, subtype)

    def get_headers(self, header_mappings, data, data_type, subtype):
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
                (
                    headers[cef_header],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
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

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default"
        fields.

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

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        Thin delegator to the shared
        :func:`utils.kafka_helper.map_json_data` helper. Each listed
        field name is resolved as a literal top-level key first; if
        that fails, it falls back to a dot-notation nested lookup
        (e.g. "host_info.device_make") so selective field ingestion
        also works for nested Netskope fields. A name that resolves
        neither way is simply omitted from the output.

        Args:
            mappings (list): List of fields to be pushed
            data (dict): Data to be mapped (retrieved from Netskope)

        Returns:
            dict: Mapped data based on fields given in mapping file
        """
        return map_json_data(mappings, data, self.logger, self.log_prefix)

    def _envelope_json_payload(
        self,
        data: dict,
        log_source_identifier: str,
        skip_timestamp_field: str,
        skip_log_source_identifier_field: str,
    ) -> str:
        """Serialize a JSON-mode record with a syslog-style envelope.

        Matches ``syslog``'s JSON-mode message format exactly, so the
        Log Source Identifier is available for both CEF (as the CEF
        envelope's hostname, via ``CEFGenerator``) and JSON (as this
        text prefix) ingestion modes, instead of only CEF. Both the
        timestamp and the Log Source Identifier are included by
        default; each is omitted only when its corresponding "Exclude"
        configuration flag is explicitly set to "yes".

        Args:
            data (dict): The record (raw or field-filtered) to
                serialize.
            log_source_identifier (str): Value of the configured Log
                Source Identifier field.
            skip_timestamp_field (str): "yes" to omit the timestamp
                prefix, else "no".
            skip_log_source_identifier_field (str): "yes" to omit the
                Log Source Identifier prefix, else "no".

        Returns:
            str: The JSON payload, optionally prefixed with
            "<timestamp>" and/or "<log_source_identifier>".
        """
        parts = []
        if skip_timestamp_field != "yes":
            parts.append(
                time.strftime("%b %d %H:%M:%S", time.localtime(time.time()))
            )
        if skip_log_source_identifier_field != "yes":
            parts.append(log_source_identifier)
        parts.append(json.dumps(data))
        return " ".join(parts)

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into target platform
        supported data formats.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            data_type (str): Datatype for logs. e.g. alerts,events,webtx, etc.
            subtype (str): Subtype of alerts/events e.g network,uba,etc.

        Returns:
            List: List of transformed logs.
        """
        if self.configuration.get("transformData", "cef") == "json":
            return self._transform_json(raw_data, data_type, subtype)
        return self._transform_cef(raw_data, data_type, subtype)

    def _get_kafka_mappings_or_raise(self, lookup_key, is_json):
        """Fetch delimiter/cef_version/taxonomy for a transform pass.

        Shared by both the JSON and CEF transform paths -- only the
        taxonomy lookup key ("json" vs the actual data_type) and the
        missing-taxonomy resolution wording differ between the two
        callers.

        Args:
            lookup_key (str): Key to fetch the taxonomy under -- "json"
                for JSON-mode transform, the actual data_type for
                CEF-mode transform.
            is_json (bool): Whether this call is for JSON-mode
                transform, used only to phrase the missing-taxonomy
                resolution text.

        Returns:
            tuple: (delimiter, cef_version, kafka_mappings) as
            returned by get_kafka_mappings().
        """
        try:
            return get_kafka_mappings(
                self.mappings, lookup_key, self.log_prefix
            )
        except KeyError as err:
            self.logger.error(
                message=(
                    "{}: Error occurred while fetching the {} mapping "
                    "file. Error: {}".format(
                        self.log_prefix, PLATFORM_NAME, err
                    )
                ),
                resolution=(
                    "Ensure that the configured attribute mapping "
                    "file contains a valid 'json' taxonomy."
                    if is_json
                    else (
                        "Ensure that the configured attribute mapping "
                        "file contains a valid taxonomy for this data "
                        "type."
                    )
                ),
                details=traceback.format_exc(),
            )
            raise
        except MappingValidationError as err:
            self.logger.error(
                message=(
                    "{}: Error occurred while validating the "
                    "attribute mapping. {}".format(self.log_prefix, err)
                ),
                resolution=(
                    "Ensure that a valid Kafka attribute mapping is "
                    "configured."
                ),
                details=traceback.format_exc(),
            )
            raise
        except Exception as err:
            self.logger.error(
                message=(
                    "{}: Error occurred while mapping data using the "
                    "configured JSON mapping. Error: {}".format(
                        self.log_prefix, err
                    )
                ),
                resolution=(
                    "Ensure that a valid Kafka attribute mapping is "
                    "configured."
                ),
                details=traceback.format_exc(),
            )
            raise

    def _get_subtype_mapping_for_transform(
        self, kafka_mappings, data_type, subtype, is_json
    ):
        """Fetch the subtype mapping for a transform pass.

        Shared by both the JSON and CEF transform paths -- only the
        taxonomy lookup path and the log message/resolution wording
        differ between the two callers. Re-raises on failure so the
        caller's transform() propagates the exception, matching
        syslog's convention of surfacing a missing/unrecognized
        subtype as a hard transform failure (visible as a CE batch
        ERROR) rather than silently skipping it.

        Args:
            kafka_mappings (dict): Full taxonomy dict as returned by
                _get_kafka_mappings_or_raise().
            data_type (str): Datatype being transformed.
            subtype (str): Subtype being transformed.
            is_json (bool): Whether this call is for JSON-mode
                transform, used to select the taxonomy lookup path
                and to phrase the log message/resolution text.

        Returns:
            The subtype mapping -- a field-selection list for
            JSON mode ("[]" means forward the whole raw record), or a
            {"header": ..., "extension": ...} dict for CEF mode.
        """
        try:
            if is_json:
                return self.get_subtype_mapping(
                    kafka_mappings["json"][data_type], subtype
                )
            return self.get_subtype_mapping(
                kafka_mappings[data_type], subtype
            )
        except Exception:
            if is_json:
                message = (
                    "{}: Error occurred while retrieving mappings for "
                    "datatype: {} (subtype: {}). Transformation will "
                    "be skipped.".format(
                        self.log_prefix, data_type, subtype
                    )
                )
                resolution = (
                    "Ensure that the configured attribute mapping "
                    "file contains a valid 'json' taxonomy entry for "
                    "this data type and subtype."
                )
            else:
                message = (
                    "{}: Error occurred while retrieving mappings for "
                    "subtype {}. Transformation of current batch will "
                    "be skipped.".format(self.log_prefix, subtype)
                )
                resolution = (
                    "Ensure that the configured attribute mapping "
                    "file contains a valid taxonomy entry for this "
                    "data type and subtype."
                )
            self.logger.error(
                message=message,
                resolution=resolution,
                details=traceback.format_exc(),
            )
            raise

    def _log_skipped_transform_records(self, skipped_logs, mapping_desc):
        """Log a debug summary of records dropped during transform().

        Args:
            skipped_logs (int): Number of records skipped.
            mapping_desc (str): "configured JSON mapping" or
                "configured mapping", matching the calling transform
                path.
        """
        if skipped_logs > 0:
            self.logger.debug(
                "{}: Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the {}. Therefore, the "
                "transformation and ingestion for those records were "
                "skipped.".format(self.log_prefix, skipped_logs, mapping_desc)
            )

    def _build_json_records(
        self,
        raw_data,
        subtype_mapping,
        log_source_identifier,
        skip_timestamp_field,
        skip_log_source_identifier_field,
    ):
        """Build the JSON-mode transformed record list.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            subtype_mapping (list): Field-selection list ("[]" means
                forward the whole raw record).
            log_source_identifier (str): Configured Log Source
                Identifier value.
            skip_timestamp_field (str): "yes"/"no" flag.
            skip_log_source_identifier_field (str): "yes"/"no" flag.

        Returns:
            tuple: (transformed_data, skipped_logs)
        """
        transformed_data = []
        skipped_logs = 0
        for data in raw_data:
            record = (
                data
                if not subtype_mapping
                else self.map_json_data(subtype_mapping, data)
            )
            if record:
                transformed_data.append(
                    self._envelope_json_payload(
                        record,
                        log_source_identifier,
                        skip_timestamp_field,
                        skip_log_source_identifier_field,
                    )
                )
            else:
                skipped_logs += 1
        return transformed_data, skipped_logs

    def _build_cef_record(
        self, data, subtype_mapping, cef_generator, data_type, subtype
    ):
        """Build a single CEF-formatted record.

        Args:
            data (dict): The raw record to transform.
            subtype_mapping (dict): The {"header": ..., "extension": ...}
                mapping for this data type/subtype.
            cef_generator (CEFGenerator): Generator used to render the
                final CEF string.
            data_type (str): Datatype being transformed.
            subtype (str): Subtype being transformed.

        Returns:
            tuple: (cef_string_or_None, counted_as_skipped). The
            second element preserves the pre-existing behavior where
            only the "no mapped fields" case increments the
            transform-level skipped-records counter; header/extension/
            CEF-generation failures are logged but not counted (as in
            the original implementation).
        """
        try:
            header, mapped_flag_header = self.get_headers(
                subtype_mapping["header"], data, data_type, subtype
            )
        except Exception as err:
            self.logger.error(
                message=(
                    "{}: [{}][{}] Error occurred while creating "
                    "the CEF header: {}. Transformation of "
                    "current record will be skipped.".format(
                        self.log_prefix, data_type, subtype, err
                    )
                ),
                resolution=(
                    "Ensure that the configured header mapping "
                    "for this data type and subtype is valid."
                ),
                details=traceback.format_exc(),
            )
            return None, False

        try:
            extension, mapped_flag_extension = self.get_extensions(
                subtype_mapping["extension"], data, data_type, subtype
            )
        except Exception as err:
            self.logger.error(
                message=(
                    "{}: [{}][{}] Error occurred while creating "
                    "the CEF extension: {}. Transformation of the "
                    "current record will be skipped.".format(
                        self.log_prefix, data_type, subtype, err
                    )
                ),
                resolution=(
                    "Ensure that the configured extension "
                    "mapping for this data type and subtype is "
                    "valid."
                ),
                details=traceback.format_exc(),
            )
            return None, False

        if not (mapped_flag_header or mapped_flag_extension):
            return None, True

        try:
            cef_generated_event = cef_generator.get_cef_event(
                data,
                header,
                extension,
                data_type,
                subtype,
                # Log Source Identifier is optional; CEF always
                # needs a hostname token, so fall back to the
                # default even if the field was left blank (not
                # just absent).
                self.configuration.get("log_source_identifier")
                or "netskopece",
            )
            return cef_generated_event, False
        except EmptyExtensionError:
            self.logger.error(
                message=(
                    "{}: [{}][{}] Error occurred during "
                    "transformation: got empty extension. "
                    "Transformation of current record will be "
                    "skipped.".format(
                        self.log_prefix, data_type, subtype
                    )
                ),
                resolution=(
                    "Ensure that at least one extension field is "
                    "mapped for this data type and subtype."
                ),
                details=traceback.format_exc(),
            )
            return None, False
        except Exception as err:
            self.logger.error(
                message=(
                    "{}: [{}][{}] Error occurred during "
                    "transformation. Transformation of current "
                    "record will be skipped. Error: {}".format(
                        self.log_prefix, data_type, subtype, err
                    )
                ),
                resolution=(
                    "Ensure that the record retrieved from "
                    "Netskope is well-formed and that the "
                    "configured mapping is valid."
                ),
                details=traceback.format_exc(),
            )
            return None, False

    def _build_cef_records(
        self, raw_data, subtype_mapping, cef_generator, data_type, subtype
    ):
        """Build the CEF-mode transformed record list.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            subtype_mapping (dict): The {"header": ..., "extension": ...}
                mapping for this data type/subtype.
            cef_generator (CEFGenerator): Generator used to render
                each CEF string.
            data_type (str): Datatype being transformed.
            subtype (str): Subtype being transformed.

        Returns:
            tuple: (transformed_data, skipped_logs)
        """
        transformed_data = []
        skipped_logs = 0
        for data in raw_data:
            if not data:
                # Drop the empty data.
                skipped_logs += 1
                continue

            cef_generated_event, counted_skip = self._build_cef_record(
                data, subtype_mapping, cef_generator, data_type, subtype
            )
            if cef_generated_event:
                transformed_data.append(cef_generated_event)
            elif counted_skip:
                skipped_logs += 1
        return transformed_data, skipped_logs

    def _transform_json(self, raw_data, data_type, subtype) -> List:
        """JSON-mode transform: full pass-through or field-filtered,
        enveloped with the syslog-style timestamp/Log Source
        Identifier prefix.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            data_type (str): Datatype for logs.
            subtype (str): Subtype of alerts/events.

        Returns:
            List: List of transformed logs.
        """
        log_source_identifier = self.configuration.get(
            "log_source_identifier", ""
        ).strip()
        skip_timestamp_field = self._get_skip_flag_value(
            self.configuration, "skip_timestamp_field"
        )
        skip_log_source_identifier_field = self._get_skip_flag_value(
            self.configuration, "skip_log_source_identifier_field"
        )

        _, _, kafka_mappings = self._get_kafka_mappings_or_raise(
            "json", is_json=True
        )
        subtype_mapping = self._get_subtype_mapping_for_transform(
            kafka_mappings, data_type, subtype, is_json=True
        )

        transformed_data, skipped_logs = self._build_json_records(
            raw_data,
            subtype_mapping,
            log_source_identifier,
            skip_timestamp_field,
            skip_log_source_identifier_field,
        )
        self._log_skipped_transform_records(
            skipped_logs, "configured JSON mapping"
        )
        return transformed_data

    def _transform_cef(self, raw_data, data_type, subtype) -> List:
        """CEF-mode transform: builds a CEF header+extension string
        per record using the configured taxonomy mapping.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            data_type (str): Datatype for logs.
            subtype (str): Subtype of alerts/events.

        Returns:
            List: List of transformed logs.
        """
        delimiter, cef_version, kafka_mappings = (
            self._get_kafka_mappings_or_raise(data_type, is_json=False)
        )
        cef_generator = CEFGenerator(
            self.mappings,
            delimiter,
            cef_version,
            self.logger,
            self.log_prefix,
        )
        # First retrieve the mapping of subtype being transformed
        subtype_mapping = self._get_subtype_mapping_for_transform(
            kafka_mappings, data_type, subtype, is_json=False
        )
        transformed_data, skipped_logs = self._build_cef_records(
            raw_data, subtype_mapping, cef_generator, data_type, subtype
        )
        self._log_skipped_transform_records(skipped_logs, "configured mapping")
        return transformed_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the Kafka Topic.

        Args:
            transformed_data (list): Transformed data list.
            data_type (str): Datatype for logs. e.g. alerts,events,webtx, etc.
            subtype (str): Subtype of alerts/events e.g network,uba,etc.

        Returns:
            PushResult: Push result object with message and status.
        """
        kafka_topic_name = self.configuration.get("kafka_topic", "").strip()
        skipped_logs = 0
        enqueued_futures = []
        try:
            (
                producer,
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
            ) = self._get_producer(self.configuration)

        except KafkaException as exp:
            # The specific failure (broker unreachable, auth failure,
            # invalid topic, etc.) was already logged with its own
            # precise message, resolution and traceback inside
            # _get_producer(). Log a generic entry here too (visible in
            # the log feed), but without a resolution so only the
            # specific entry above carries one.
            err_msg = (
                "Error occurred while creating the producer for the "
                "configured {} broker.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
            )
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while creating the producer for the "
                "configured {} broker.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=(
                    "Ensure that the Kafka Broker Address, Kafka Port, "
                    "Kafka Security Protocol and Kafka Topic Name are "
                    "correctly configured."
                ),
                details=str(traceback.format_exc()),
            )
            raise

        # Log the transformed data to given kafka server
        for data in transformed_data:
            try:
                if data:
                    enqueued_futures.append(
                        producer.send(
                            topic=kafka_topic_name,
                            value=data
                            if not isinstance(data, dict)
                            else json.dumps(data),
                        )
                    )
                else:
                    skipped_logs += 1
            except MessageSizeTooLargeError as error:
                err_msg = (
                    "Message too large error occurred while sending "
                    "logs to Kafka."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"pushing data to {PLATFORM_NAME}. {err_msg} "
                        f"Error: {error}"
                    ),
                    resolution=(
                        "Ensure that the individual record size does "
                        "not exceed the Kafka broker's configured "
                        "'message.max.bytes' limit."
                    ),
                    details=traceback.format_exc(),
                )
            except KafkaTimeoutError as error:
                err_msg = (
                    "Maximum timeout exceeded while sending logs"
                    " to {}.".format(PLATFORM_NAME)
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"pushing data to {PLATFORM_NAME}. {err_msg} "
                        f"Error: {error}"
                    ),
                    resolution=(
                        "Ensure that the configured Kafka Broker "
                        "Address is reachable and the cluster is not "
                        "overloaded."
                    ),
                    details=traceback.format_exc(),
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Error occurred while sending data to {} "
                        'topic "{}". Record will be skipped. '
                        "Error: {}".format(
                            self.log_prefix,
                            PLATFORM_NAME,
                            kafka_topic_name,
                            exp,
                        )
                    ),
                    resolution=(
                        "Ensure that the record being pushed is valid "
                        "and that the connection to the Kafka broker is "
                        "stable."
                    ),
                    details=traceback.format_exc(),
                )
        try:
            producer.flush(timeout=TIMEOUT)
            # flush() blocks until every enqueued future is done (either
            # acknowledged or failed), so counting here -- rather than
            # right after send() -- reflects actual delivery outcome
            # instead of just successful enqueuing.
            successful_log_push_counter = sum(
                1 for future in enqueued_futures if future.succeeded()
            )
            failed_push_counter = sum(
                1 for future in enqueued_futures if future.failed()
            )
            if failed_push_counter > 0:
                self.logger.error(
                    message=(
                        "{}: {} out of {} enqueued log(s) were not "
                        "acknowledged by the {} broker and were not "
                        "ingested.".format(
                            self.log_prefix,
                            failed_push_counter,
                            len(enqueued_futures),
                            PLATFORM_NAME,
                        )
                    ),
                    resolution=(
                        "Ensure that the configured Kafka Broker "
                        "Address is reachable, the Kafka Topic Name is "
                        "valid, and the cluster has enough capacity to "
                        "accept the ingested records."
                    ),
                )
            if skipped_logs > 0:
                self.logger.debug(
                    "{}: Received empty transformed data for {} log(s) hence "
                    "ingestion of those log(s) will be skipped.".format(
                        self.log_prefix,
                        skipped_logs,
                    )
                )
            log_msg = (
                "[{}] [{}] Successfully ingested {} log(s)"
                ' to "{}" topic.'.format(
                    data_type,
                    subtype,
                    successful_log_push_counter,
                    kafka_topic_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as exp:
            err_msg = (
                "Error occurred while transferring logs to {} "
                "server.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                resolution=(
                    "Ensure that the configured Kafka Broker Address is "
                    "reachable and that the connection was not "
                    "interrupted during flush."
                ),
                details=traceback.format_exc(),
            )
            raise KafkaException(exp)
        finally:
            producer.close(timeout=TIMEOUT)
            self._cleanup_ssl_tmp_files(
                kafka_ca_file, kafka_cert_file, kafka_key_file
            )

    def _create_tmp_file(
        self,
        kafka_ca_certificate: str,
        kafka_client_certificate: str,
        kafka_client_private_key: str,
    ):
        """Create tmp files.

        Args:
            kafka_ca_certificate (str): Kafka CA Certificate
            kafka_client_certificate (str): Kafka Client Certificate
            kafka_client_private_key (str): Kafka Client Private Key
        """
        tmp_ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        tmp_ca_file.write(kafka_ca_certificate.encode())
        tmp_ca_file.close()

        tmp_cert_file = tempfile.NamedTemporaryFile(
            delete=False, suffix=".pem"
        )
        tmp_cert_file.write(kafka_client_certificate.encode())
        tmp_cert_file.close()

        tmp_private_key_file = tempfile.NamedTemporaryFile(
            delete=False, suffix=".pem"
        )
        tmp_private_key_file.write(kafka_client_private_key.encode())
        tmp_private_key_file.close()

        return tmp_ca_file.name, tmp_cert_file.name, tmp_private_key_file.name

    def _get_common_producer_kwargs(self, kafka_broker_address: str) -> dict:
        """Build the KafkaProducer kwargs shared by PLAINTEXT and SSL.

        Args:
            kafka_broker_address (str): "<broker>:<port>" bootstrap
                address.

        Returns:
            dict: Common KafkaProducer keyword arguments.
        """
        return {
            "bootstrap_servers": kafka_broker_address,
            "value_serializer": lambda x: x.encode("utf-8"),
            "acks": ACKS,
            "partitioner": DefaultPartitioner(),
            "retries": RETRIES,
            "linger_ms": LINGER_MS,
            "client_id": self._get_user_agent(),
            "batch_size": BATCH_SIZE,
            "compression_type": COMPRESSION_TYPE,
            "request_timeout_ms": TIMEOUT_MS,
        }

    def _get_ssl_kwargs(
        self,
        kafka_ca_file,
        kafka_cert_file,
        kafka_key_file,
        kafka_ssl_password,
    ) -> dict:
        """Build the SSL-only kwargs shared by the producer and consumer.

        Args:
            kafka_ca_file (str): Path to the temporary CA certificate
                file.
            kafka_cert_file (str): Path to the temporary client
                certificate file.
            kafka_key_file (str): Path to the temporary client private
                key file.
            kafka_ssl_password (str): Password protecting the private
                key.

        Returns:
            dict: SSL-specific keyword arguments.
        """
        return {
            "ssl_cafile": kafka_ca_file,
            "ssl_certfile": kafka_cert_file,
            "ssl_keyfile": kafka_key_file,
            "ssl_password": kafka_ssl_password,
        }

    def _verify_topic_exists(self, consumer, kafka_topic: str) -> None:
        """Ensure the configured Kafka topic exists on the cluster.

        Args:
            consumer (KafkaConsumer): Consumer used to fetch cluster
                topics.
            kafka_topic (str): Configured Kafka topic name.

        Raises:
            KafkaException: If the topic does not exist on the cluster.
        """
        available_topics = consumer.topics()
        if kafka_topic not in available_topics:
            err_msg = (
                "The Kafka Topic Name provided in configuration "
                "parameter does not exist on configured Kafka cluster."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured Kafka Topic Name "
                    "already exists on the configured Kafka cluster."
                ),
            )
            raise KafkaException(err_msg)

    def _cleanup_ssl_tmp_files(
        self, kafka_ca_file, kafka_cert_file, kafka_key_file
    ) -> None:
        """Delete the temporary SSL cert/key files written to disk.

        Safe to call with any combination of None values (e.g. under
        PLAINTEXT, where no files were created).

        Args:
            kafka_ca_file (str or None): Path to the temp CA
                certificate file.
            kafka_cert_file (str or None): Path to the temp client
                certificate file.
            kafka_key_file (str or None): Path to the temp client
                private key file.
        """
        for path in (kafka_ca_file, kafka_cert_file, kafka_key_file):
            if path is not None:
                os.remove(path)

    def _build_kafka_client(
        self,
        kafka_security_protocol,
        kafka_broker_address,
        kafka_topic,
        ssl_kwargs,
    ):
        """Verify the configured topic exists and build the producer.

        Every kafka-python connection/auth/topic error raised while
        doing so is caught here, logged with a precise message and
        resolution, and re-raised as a KafkaException (or, for
        unexpected errors, a plain Exception) -- _get_producer() only
        needs to handle those two types.

        Args:
            kafka_security_protocol (str): "SSL" or "PLAINTEXT".
            kafka_broker_address (str): "<broker>:<port>" bootstrap
                address.
            kafka_topic (str): Configured Kafka topic name.
            ssl_kwargs (dict): SSL kwargs from _get_ssl_kwargs(), or
                {} for PLAINTEXT.

        Returns:
            KafkaProducer: The connected producer.
        """
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=kafka_broker_address,
                security_protocol=kafka_security_protocol,
                request_timeout_ms=TIMEOUT_MS,
                **ssl_kwargs,
            )
            self._verify_topic_exists(consumer, kafka_topic)

            producer_kwargs = self._get_common_producer_kwargs(
                kafka_broker_address
            )
            if kafka_security_protocol == "SSL":
                producer_kwargs.update(ssl_kwargs)
                producer_kwargs["security_protocol"] = (
                    kafka_security_protocol
                )

            return KafkaProducer(**producer_kwargs)
        except InvalidTopicError as error:
            err_msg = (
                "Invalid topic error raised from {} server. This "
                "error may caused when plugin attempts to access the"
                " invalid topic or if an attempt is made to write "
                "to an internal topic.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that a valid, non-internal Kafka Topic Name "
                    "is provided in the configuration parameters."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except TopicAuthorizationFailedError as error:
            err_msg = (
                "Configured authorization credentials does not have"
                " access to topic {}".format(kafka_topic)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured authentication "
                    "credentials have Write access to the configured "
                    "Kafka Topic Name."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except ClusterAuthorizationFailedError:
            err_msg = (
                "Unable to authenticate with the configured {} Security "
                "Protocol and authentication credentials.".format(
                    PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
                resolution=(
                    "Ensure that the configured Kafka Security Protocol "
                    "and authentication credentials are correct."
                ),
                details=traceback.format_exc(),
            )
            raise KafkaException(err_msg)
        except KafkaConnectionError as error:
            err_msg = (
                "Error occur while connecting with {} cluster. Verify"
                " the authentication credentials provided in "
                "configuration parameters.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured Kafka Broker Address, "
                    "Kafka Port and authentication credentials are "
                    "correct and that the cluster is reachable."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except NoBrokersAvailable as error:
            err_msg = (
                "{} Broker is unreachable or {} cluster might be down."
                " Verify {} Broker Address and {} Port"
                " provided in configuration parameters.".format(
                    PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                resolution=(
                    "Ensure that the configured Kafka Broker Address "
                    "and Kafka Port are correct and the cluster "
                    "is up and reachable from the CE host."
                ),
                details=traceback.format_exc(),
            )
            raise KafkaException(err_msg)
        except AuthenticationMethodNotSupported as error:
            err_msg = (
                "Kafka Cluster does not support the selected"
                " authentication method."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the selected Kafka Security Protocol "
                    "is supported by the configured Kafka cluster."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except AuthenticationFailedError as error:
            err_msg = (
                "Authentication failed. Verify authentication "
                "credentials provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the configured authentication "
                    "credentials are correct."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except SSLError as error:
            err_msg = (
                "Authentication failed. Verify Kafka CA Certificate, "
                "Kafka Client Certificate, Kafka Client Private Key and Kafka"
                " SSL Private Key Password provided in "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that valid Kafka CA Certificate, Kafka "
                    "Client Certificate, Kafka Client Private Key and "
                    "Kafka SSL Private Key Password are provided in the "
                    "configuration parameters."
                ),
                details=str(error),
            )
            raise KafkaException(err_msg)
        except KafkaException:
            raise
        except Exception as exp:
            err_msg = (
                "Unable to connect to configured {} broker. "
                "Error: {}".format(PLATFORM_NAME, exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: Error occurred while "
                f"connecting to {PLATFORM_NAME}. {err_msg}",
                resolution=(
                    "Ensure that the Kafka Broker Address, Kafka Port "
                    "and Kafka Security Protocol are correctly "
                    "configured."
                ),
                details=str(traceback.format_exc()),
            )
            raise Exception(err_msg)

    def _get_producer(self, configuration: dict):
        """Get Producer for Kafka.

        Builds a KafkaConsumer to verify the configured topic exists,
        then builds and returns the KafkaProducer used by validate()/
        push() (via _build_kafka_client()). If SSL is selected and
        that step fails for any reason, the temporary SSL cert/key
        files created below are deleted here before the failure
        propagates, so private-key material is never left on disk
        (see _cleanup_ssl_tmp_files()).

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            tuple: (producer, kafka_ca_file, kafka_cert_file,
            kafka_key_file). The three file paths are None when SSL is
            not the configured Kafka Security Protocol.
        """
        kafka_security_protocol = configuration.get("security_protocol")
        kafka_broker_address = "{}:{}".format(
            configuration.get("kafka_broker", "").strip(),
            configuration.get("kafka_port"),
        )
        kafka_topic = configuration.get("kafka_topic", "").strip()

        kafka_ca_file, kafka_cert_file, kafka_key_file = None, None, None
        ssl_kwargs = {}
        if kafka_security_protocol == "SSL":
            # The 4 SSL fields are dynamic (get_dynamic_fields()) and are
            # only present in configuration when SSL is selected.
            (
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
            ) = self._create_tmp_file(
                configuration.get("kafka_ca_certificate"),
                configuration.get("kafka_client_certificate"),
                configuration.get("kafka_client_private_key"),
            )
            ssl_kwargs = self._get_ssl_kwargs(
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
                configuration.get("kafka_ssl_password", ""),
            )

        try:
            producer = self._build_kafka_client(
                kafka_security_protocol,
                kafka_broker_address,
                kafka_topic,
                ssl_kwargs,
            )
            return producer, kafka_ca_file, kafka_cert_file, kafka_key_file
        except Exception:
            self._cleanup_ssl_tmp_files(
                kafka_ca_file, kafka_cert_file, kafka_key_file
            )
            raise

    def _get_config_params(
        self, configuration: dict, params_to_get: List[str] = None
    ):
        """Fetch one or more raw configuration values by key.

        Used by ``get_dynamic_fields()`` to read the in-progress
        configuration submitted so far.

        Args:
            configuration (dict): Configuration parameters.
            params_to_get (List[str]): Keys to fetch.

        Returns:
            The single value when only one key is requested, else a
            tuple of values in the same order as ``params_to_get``.
        """
        if not params_to_get:
            return configuration
        values = [configuration.get(param) for param in params_to_get]
        return values[0] if len(values) == 1 else tuple(values)

    def _get_skip_flag_value(self, configuration: dict, key: str) -> str:
        """Fetch and normalize a yes/no skip-flag from configuration.

        Args:
            configuration (dict): Configuration parameters.
            key (str): Configuration key of the flag to fetch.

        Returns:
            str: "yes" or "no" (defaults to "no" for a missing,
            differently-cased, or otherwise unrecognized value).
        """
        value = configuration.get(key, "no")
        if isinstance(value, str):
            value = value.strip().lower()
        return value if value in IDENTIFIER_ALLOWED_VALUES else "no"

    def _get_common_dynamic_fields(self) -> list:
        """Build the dynamic fields returned regardless of the
        selected Kafka Security Protocol.

        These are declared as dynamic (rather than static manifest
        fields) purely so the CE UI renders them, and any SSL-only
        fields prepended to them, immediately after the Kafka Security
        Protocol field instead of at the very end of the form —
        mirroring the ``databricks``/``aws_s3_events_alerts`` pattern
        of always-returned fields (e.g. their `region_field`/
        `bucket_field`) that render after the auth-method trigger.

        Returns:
            list: Kafka Topic Name, Log Source Identifier, Exclude
            Timestamp Field, and Exclude Log Source Identifier Field
            field definitions.
        """
        return [
            {
                "label": "Kafka Topic Name",
                "key": "kafka_topic",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Name of the Kafka topic to which the logs should "
                    "be sent. Note: the Kafka Topic Name should not "
                    "contain any whitespace and must already exist on "
                    "the configured Kafka cluster. This plugin does "
                    "not support creating topics on kafka."
                ),
            },
            {
                "label": "Log Source Identifier",
                "key": "log_source_identifier",
                "type": "text",
                "default": "netskopece",
                "mandatory": False,
                "description": (
                    "This value will be added as a prefix to all "
                    "ingested logs."
                ),
            },
            {
                "label": "Exclude Timestamp Field",
                "key": "skip_timestamp_field",
                "type": "choice",
                "choices": [
                    {"key": "Yes", "value": "yes"},
                    {"key": "No", "value": "no"},
                ],
                "default": "no",
                "mandatory": False,
                "description": (
                    "Select 'Yes' to ingest the data without the "
                    "timestamp prefix. This option is only applicable "
                    "to JSON-formatted data."
                ),
            },
            {
                "label": "Exclude Log Source Identifier Field",
                "key": "skip_log_source_identifier_field",
                "type": "choice",
                "choices": [
                    {"key": "Yes", "value": "yes"},
                    {"key": "No", "value": "no"},
                ],
                "default": "no",
                "mandatory": False,
                "description": (
                    "Select 'Yes' to ingest the data without the Log "
                    "Source Identifier field. This option is only "
                    "applicable to JSON-formatted data."
                ),
            },
        ]

    def _get_ssl_dynamic_fields(self) -> list:
        """Build the 4 SSL-only dynamic fields.

        Returns:
            list: Kafka CA Certificate, Kafka Client Certificate,
            Kafka Client Private Key, and Kafka SSL Private Key
            Password field definitions.
        """
        return [
            {
                "label": "Kafka CA Certificate",
                "key": "kafka_ca_certificate",
                "type": "textarea",
                "default": "",
                "mandatory": True,
                "description": (
                    "Kafka CA Certificate in PEM format, used to "
                    "verify the identity of the Kafka broker. "
                    "Required only when 'SSL' is selected as the "
                    "Kafka Security Protocol."
                ),
            },
            {
                "label": "Kafka Client Certificate",
                "key": "kafka_client_certificate",
                "type": "textarea",
                "default": "",
                "mandatory": True,
                "description": (
                    "Kafka Client Certificate in PEM format, used "
                    "by the plugin to authenticate itself to the "
                    "Kafka broker. Required only when 'SSL' is "
                    "selected as the Kafka Security Protocol."
                ),
            },
            {
                "label": "Kafka Client Private Key",
                "key": "kafka_client_private_key",
                "type": "textarea",
                "default": "",
                "mandatory": True,
                "description": (
                    "Kafka Client Private Key in PEM format, "
                    "paired with the Kafka Client Certificate. "
                    "Required only when 'SSL' is selected as the "
                    "Kafka Security Protocol."
                ),
            },
            {
                "label": "Kafka SSL Private Key Password",
                "key": "kafka_ssl_password",
                "type": "password",
                "default": "",
                "mandatory": False,
                "description": (
                    "Password for the Kafka Client Private "
                    "Key. Required only if the private key PEM "
                    "file was generated with a passphrase. "
                    "Required only when 'SSL' is selected as the "
                    "Kafka Security Protocol."
                ),
            },
        ]

    def get_dynamic_fields(self) -> list:
        """Return the configuration fields rendered after the Kafka
        Security Protocol field.

        Called by the CE configuration UI whenever ``security_protocol``
        changes (``has_api_call``/``payload_fields`` in manifest.json).
        Kafka Topic Name, Log Source Identifier, and the two "Exclude"
        flags are always included (regardless of protocol) purely to
        position them after Kafka Security Protocol; the 4 SSL fields
        are prepended only when 'SSL' is selected.

        Returns:
            list: Dynamic field definitions to render.
        """
        security_protocol = self._get_config_params(
            self.configuration, ["security_protocol"]
        )
        common_fields = self._get_common_dynamic_fields()
        if security_protocol and security_protocol == "SSL":
            return self._get_ssl_dynamic_fields() + common_fields
        return common_fields

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        is_required: bool = True,
        is_password: bool = False,
        allowed_values: list = None,
        no_whitespace: bool = False,
        range_validation: bool = False,
        range_values: tuple = None,
        required_field_message: str = None,
    ):
        """Validate a single configuration parameter.

        Centralizes the empty/type/range/allowed-value/whitespace
        checks shared by every field validated in ``validate()``, used
        via the walrus-operator short-circuit pattern:
        ``if result := self._validate_configuration_parameters(...):
        return result``.

        Args:
            field_name (str): Human-readable field name for messages.
            field_value: Raw value fetched from configuration.
            field_type (type): Expected Python type (str/int).
            is_required (bool): Whether the field must be non-empty.
            is_password (bool): True for password-type fields — skips
                ``.strip()`` so secret values are never mutated.
            allowed_values (list): Allowed values for choice fields.
            no_whitespace (bool): Reject values containing whitespace.
            range_validation (bool): Enable numeric range validation.
            range_values (tuple): (min, max) inclusive range.
            required_field_message (str): Custom message when the
                field is required but empty.

        Returns:
            ValidationResult on failure, None when validation passes.
        """
        if (
            field_type is str
            and isinstance(field_value, str)
            and not is_password
        ):
            field_value = field_value.strip()

        if field_type is int and isinstance(field_value, str):
            # Preserve the original validate_kafka_port() tolerance for
            # a numeric string (e.g. "9092") instead of rejecting it
            # outright on the type check below.
            try:
                field_value = int(field_value.strip())
            except (ValueError, TypeError):
                pass

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                required_field_message
                or f"{field_name} is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} is provided in the "
                    "configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid {field_name} provided in configuration "
                "parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value for {field_name} is "
                    "provided in the configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            range_validation
            and range_values
            and field_value is not None
            and not (range_values[0] <= field_value <= range_values[1])
        ):
            err_msg = (
                f"Invalid {field_name} provided in configuration "
                "parameters. Value should be an integer in range "
                f"{range_values[0]} to {range_values[1]}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} is an integer in range "
                    f"{range_values[0]} to {range_values[1]}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values and field_value not in allowed_values:
            err_msg = (
                f"Invalid {field_name} provided in configuration "
                f"parameters. Accepted value are {allowed_values}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} is one of "
                    f"{allowed_values}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            no_whitespace
            and isinstance(field_value, str)
            and bool(re.search(r"\s", field_value))
        ):
            err_msg = (
                f"Invalid {field_name} provided in configuration "
                "parameters. Value should be a string without any "
                "spaces."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} does not contain any "
                    "whitespace characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for "
            f"'{field_name}'."
        )
        return None

    def _validate_ssl_configuration_parameters(self, configuration: dict):
        """Validate the four SSL-only configuration parameters.

        Only invoked when ``security_protocol == "SSL"`` — these
        fields are entirely absent from ``configuration`` under
        PLAINTEXT since they are dynamic (get_dynamic_fields()).

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult on failure, None on success.
        """
        kafka_ca_certificate = configuration.get("kafka_ca_certificate")
        if result := self._validate_configuration_parameters(
            field_name="Kafka CA Certificate",
            field_value=kafka_ca_certificate,
            field_type=str,
            required_field_message=(
                "Kafka CA Certificate is a required configuration"
                " parameter if SSL is selected as Kafka Security Protocol."
            ),
        ):
            return result

        kafka_client_certificate = configuration.get(
            "kafka_client_certificate"
        )
        if result := self._validate_configuration_parameters(
            field_name="Kafka Client Certificate",
            field_value=kafka_client_certificate,
            field_type=str,
            required_field_message=(
                "Kafka Client Certificate is a required configuration"
                " parameter if SSL is selected as Kafka Security Protocol."
            ),
        ):
            return result

        kafka_client_private_key = configuration.get(
            "kafka_client_private_key"
        )
        if result := self._validate_configuration_parameters(
            field_name="Kafka Client Private Key",
            field_value=kafka_client_private_key,
            field_type=str,
            required_field_message=(
                "Kafka Client Private Key is a required configuration"
                " parameter if SSL is selected as Kafka Security Protocol."
            ),
        ):
            return result

        kafka_ssl_password = configuration.get("kafka_ssl_password", "")
        if result := self._validate_configuration_parameters(
            field_name="Kafka SSL Private Key Password",
            field_value=kafka_ssl_password,
            field_type=str,
            is_required=False,
            is_password=True,
        ):
            return result

        return None

    def _validate_kafka_mapping(self):
        """Validate the configured Kafka attribute mapping file.

        Returns:
            ValidationResult on failure, None on success.
        """
        kafka_validator = KafkaValidator(self.logger, self.log_prefix)
        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not (
            isinstance(mappings, dict)
            and kafka_validator.validate_kafka_map(mappings)
        ):
            err_msg = f"Invalid {PLATFORM_NAME} attribute mapping provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that a valid Kafka attribute mapping is "
                    "configured, including a valid 'kafka_map_version' "
                    "value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_connectivity(self, configuration: dict) -> ValidationResult:
        """Validate connectivity to the configured Kafka broker/topic.

        Opens a producer/consumer, checks ``bootstrap_connected()`` and
        topic existence, then closes the connection. No test message
        is produced to the topic.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Result of the live connectivity probe.
        """
        kafka_ca_file, kafka_cert_file, kafka_key_file = None, None, None
        try:
            (
                producer,
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
            ) = self._get_producer(configuration)
            if producer.bootstrap_connected():
                producer.close(timeout=TIMEOUT)
                self.logger.debug(
                    f"{self.log_prefix}: Validation completed "
                    "successfully."
                )
                return ValidationResult(
                    message="Validation successful.", success=True
                )
            else:
                err_msg = (
                    "Unable to connect to configured {} broker. Verify the"
                    " authentication credentials provided in "
                    "configuration parameters.".format(PLATFORM_NAME)
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the Kafka Broker Address, Kafka "
                        "Port and authentication credentials are "
                        "correct and that the cluster is reachable."
                    ),
                )
                return ValidationResult(message=err_msg, success=False)
        except KafkaException as exp:
            # The specific failure (broker unreachable, auth failure,
            # invalid topic, etc.) was already logged with its own
            # precise message, resolution and traceback inside
            # _get_producer(). Log a generic validation-error entry here
            # too (visible in the log feed), but without a resolution so
            # only the specific entry above carries one.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {exp}"
                ),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Validation error occurred while creating connection"
                " with configured {} broker. Refer logs for more "
                "details.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"Error occurred while validating connectivity. "
                    f"Error: {exp}"
                ),
                resolution=(
                    "Ensure that the Kafka Broker Address, Kafka Port "
                    "and Kafka Security Protocol are correctly "
                    "configured and that the cluster is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)
        finally:
            self._cleanup_ssl_tmp_files(
                kafka_ca_file, kafka_cert_file, kafka_key_file
            )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with validation flag and
            message.
        """
        kafka_broker = configuration.get("kafka_broker", "").strip()
        if result := self._validate_configuration_parameters(
            field_name=f"{PLATFORM_NAME} Broker Address",
            field_value=kafka_broker,
            field_type=str,
        ):
            return result

        kafka_port = configuration.get("kafka_port")
        if result := self._validate_configuration_parameters(
            field_name=f"{PLATFORM_NAME} Port",
            field_value=kafka_port,
            field_type=int,
            range_validation=True,
            range_values=(1, 65535),
        ):
            return result

        security_protocol = configuration.get("security_protocol")
        if result := self._validate_configuration_parameters(
            field_name="Kafka Security Protocol",
            field_value=security_protocol,
            field_type=str,
            allowed_values=KAFKA_SECURITY_PROTOCOLS,
        ):
            return result

        if security_protocol == "SSL":
            if result := self._validate_ssl_configuration_parameters(
                configuration
            ):
                return result

        kafka_topic = configuration.get("kafka_topic", "").strip()
        if result := self._validate_configuration_parameters(
            field_name=f"{PLATFORM_NAME} Topic",
            field_value=kafka_topic,
            field_type=str,
            no_whitespace=True,
        ):
            return result

        if result := self._validate_kafka_mapping():
            return result

        skip_timestamp_field = self._get_skip_flag_value(
            configuration, "skip_timestamp_field"
        )
        if result := self._validate_configuration_parameters(
            field_name="Exclude Timestamp Field",
            field_value=skip_timestamp_field,
            field_type=str,
            is_required=False,
            allowed_values=IDENTIFIER_ALLOWED_VALUES,
        ):
            return result

        skip_log_source_identifier_field = self._get_skip_flag_value(
            configuration, "skip_log_source_identifier_field"
        )
        if result := self._validate_configuration_parameters(
            field_name="Exclude Log Source Identifier Field",
            field_value=skip_log_source_identifier_field,
            field_type=str,
            is_required=False,
            allowed_values=IDENTIFIER_ALLOWED_VALUES,
        ):
            return result

        # Log Source Identifier is only optional when JSON format is
        # selected AND it is explicitly excluded below — CEF format
        # always requires it (the CEF envelope always needs a
        # hostname), matching syslog's require_log_source_identifier.
        transform_data_json = (
            configuration.get("transformData", "cef") == "json"
        )
        require_log_source_identifier = (
            not transform_data_json
            or skip_log_source_identifier_field == "no"
        )
        log_source_identifier = configuration.get(
            "log_source_identifier", ""
        ).strip()
        if result := self._validate_configuration_parameters(
            field_name="Log Source Identifier",
            field_value=log_source_identifier,
            field_type=str,
            is_required=require_log_source_identifier,
            required_field_message=(
                "Log Source Identifier is a required configuration "
                "parameter for the selected format."
            ),
        ):
            return result

        # Validate Server connection.
        return self._validate_connectivity(configuration)
