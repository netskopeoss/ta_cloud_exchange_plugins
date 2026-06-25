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

Microsoft Azure Log Analytics Plugin."""

import datetime
import re
import traceback
import json
from typing import Dict, List, Tuple, Union
from jsonpath import jsonpath

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult
)
from netskope.common.utils import AlertsHelper
from .utils.log_analytics_cef_generator import CEFGenerator
from .utils.log_analytics_validator import AzureLogAnalyticsValidator
from .utils.log_analytics_client import AzureLogAnalyticsClient
from .utils.log_analytics_helper import (
    validate_log_analytics_mappings,
    get_log_analytics_mappings,
    split_into_size
)
from .utils.log_analytics_exception import (
    FieldNotFoundError,
    MicrosoftAzureLogAnalyticsPluginException,
    MappingValidationError,
    EmptyExtensionError,
)
from .utils.log_analytics_constants import (
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    PUSH_DATA_ENDPOINT,
    VALIDATION_ERROR_MSG,
    INGESTION_MODE_SINGLE_TABLE,
    INGESTION_MODE_PER_DATA_TYPE,
    JSON_MAPPED_DATA_TYPES,
    COLUMN_NAME_INVALID_CHAR_RE,
    RESERVED_NAMES,
    SPECIAL_RENAMES,
    SINGLE_TABLE_DYNAMIC_FIELDS,
    PER_DATA_TYPE_DYNAMIC_FIELDS,
)


class AzureLogAnalyticsPlugin(PluginBase):
    """The Microsoft Azure LogAnalytics CLS plugin implementation class."""

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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.log_analytics_client = AzureLogAnalyticsClient(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            verify_ssl=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AzureLogAnalyticsPlugin.metadata
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

    def get_dynamic_fields(self):
        """Return configuration fields that depend on the selected
        Ingestion Mode.

        - single_table: a single custom_log_table_name text field
          (matches monitor behaviour: every record is pushed to this one
          table inside a RawData envelope).
        - per_data_type: a multi-choice data_types selector
          plus three table-name fields, one per supported data type.
          The table-name fields are presented as non-mandatory at the
          manifest layer; their conditional-mandatory check is enforced
          in :meth:`validate` based on which data types are selected.
        """
        ingestion_mode = self.configuration.get(
            "ingestion_mode", INGESTION_MODE_SINGLE_TABLE
        )
        if ingestion_mode == INGESTION_MODE_PER_DATA_TYPE:
            return PER_DATA_TYPE_DYNAMIC_FIELDS
        return SINGLE_TABLE_DYNAMIC_FIELDS

    def get_subtype_mapping(self, mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events) \
            case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which \
            the mapping is to be fetched
        :return: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Transform and ingests the given data chunks to \
            Microsoft Azure LogAnalytics.

        :param data_type: The type of data being pushed.
            Current possible values: alerts, events and webtx
        :param transformed_data: Transformed data to be ingested to
            Microsoft Azure LogAnalytics in chunks
        :param subtype: The subtype of data being pushed.
        """
        try:
            parsed_config = self.log_analytics_client.get_configuration_parameters(     # noqa
                self.configuration
            )

            is_per_type = parsed_config["ingestion_mode"] == INGESTION_MODE_PER_DATA_TYPE     # noqa
            if is_per_type and data_type not in parsed_config["data_types"]:
                log_msg = (
                    f"[{data_type}][{subtype}] Skipping push for data type "
                    f"'{data_type}' as it is not selected in "
                    "'Data Types to Ingest'."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return PushResult(success=True, message=log_msg)

            table_name = self.log_analytics_client.table_name_for(
                parsed_config, data_type
            )
            if not table_name:
                err_msg = (
                    f"[{data_type}][{subtype}] No Custom Log Table Name "
                    f"is provided for data type '{data_type}'."
                )
                self.logger.error(message=f"{self.log_prefix}: {err_msg}")
                raise MicrosoftAzureLogAnalyticsPluginException(err_msg)

            log_msg = self._ingest_chunks(
                chunks=split_into_size(transformed_data),
                parsed_config=parsed_config,
                table_name=table_name,
                data_type=data_type,
                subtype=subtype,
            )
            return PushResult(success=True, message=log_msg)
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting "
                    f"[{data_type}][{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err

    def _ingest_chunks(
        self,
        chunks: List,
        parsed_config: Dict,
        table_name: str,
        data_type: str,
        subtype: str,
    ) -> str:
        """Ingest each pre-sized chunk to the Azure DCR ingestion endpoint.

        Returns:
            str: Summary log message suitable for the PushResult.
        """
        auth_header, storage = self.log_analytics_client.get_or_refresh_auth_header(    # noqa
            parsed_config=parsed_config,
            storage=self.storage,
        )
        url_endpoint = PUSH_DATA_ENDPOINT.format(
            dce_uri=parsed_config["dce_uri"],
            dcr_immutable_id=parsed_config["dcr_immutable_id"],
            custom_log_table_name=table_name,
        )

        skipped_count = 0
        total_count = 0
        for page, chunk in enumerate(chunks, start=1):
            try:
                self.log_analytics_client.api_helper(
                    logger_msg=(
                        f"ingesting data to {PLUGIN_NAME} for chunk {page}"
                    ),
                    url=url_endpoint,
                    method="POST",
                    data=json.dumps(chunk),
                    headers=auth_header,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                )
                self.logger.info(
                    f"{self.log_prefix}: [{data_type}][{subtype}] "
                    f"Successfully ingested {len(chunk)} {data_type} "
                    f"for chunk {page} to {PLUGIN_NAME}."
                )
                total_count += len(chunk)
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] "
                        f"Error occurred while ingesting data. "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_count += len(chunk)

        log_msg = (
            f"[{data_type}][{subtype}] Successfully ingested "
            f"{total_count} {data_type} to {PLUGIN_NAME}."
        )
        if skipped_count > 0:
            log_msg += (
                f" Skipped {skipped_count} record(s) "
                "due to some unexpected error."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return log_msg

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
            except (Exception, FieldNotFoundError) as err:
                missing_fields.append(str(err))
        return extension, mapped_field_flag

    def get_headers(self, header_mappings, data, data_type):
        """To Create a dictionary of CEF headers from \
            given header mappings for given Netskope alert/event record.

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
            if not hasattr(self, "tenant"):
                helper = AlertsHelper()
                self.tenant = helper.get_tenant_cls(self.source)
            mapping_variables = {"$tenant_name": self.tenant.name}

        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                (
                    headers[cef_header], mapped_field,
                ) = self.get_field_value_from_data(
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

    def get_nested_field_value(self, data, field_path):
        """Extract value from nested dictionary using dot notation.

        Some Netskope records (e.g. clientstatus events) expose values
        only under nested keys like ``host_info.device_make``, while the
        configured mapping references the field as a single dotted
        string. This walks the dict one segment at a time and returns
        the leaf value when the full path resolves.

        Args:
            data: The data dictionary
            field_path: Dot-separated field path
                (e.g., 'host_info.device_make')

        Returns:
            tuple: (value, exists) where exists is True if field was found
        """
        try:
            current_data = data
            for part in field_path.split('.'):
                if isinstance(current_data, dict) and part in current_data:
                    current_data = current_data[part]
                else:
                    return None, False

            return current_data, True

        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting nested field value. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return None, False

    def get_field_value_from_data(
        self,
        extension_mapping,
        data,
        is_json_path=False
    ) -> Tuple[Union[str, int], bool]:
        """To Fetch the value of extension based on \
            "mapping" and "default" fields.

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
        if (
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
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:  # case #1 and case #4  # noqa
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
                else:
                    # Try nested field access using dot notation
                    nested_value, field_exists = self.get_nested_field_value(
                        data, extension_mapping["mapping_field"]
                    )

                    if field_exists:
                        if (
                            extension_mapping.get("transformation") == "Time Stamp"  # noqa
                            and nested_value
                        ):
                            try:
                                mapped_field = True
                                timestamp_value = int(nested_value)
                                return timestamp_value, mapped_field
                            except Exception:
                                pass

                        mapped_field = True
                        final_result = (
                            (nested_value, True)
                            if nested_value or isinstance(nested_value, int)
                            else ("null", False)
                        )
                        return final_result
                    elif "default_value" in extension_mapping:
                        # If mapped value is not found in response and
                        # default is mapped, map the default value (case #2)
                        return extension_mapping["default_value"], mapped_field
                    else:  # case #6
                        raise FieldNotFoundError(
                            extension_mapping["mapping_field"]
                        )
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
        data_keys = data.keys()
        for key in mappings:
            if key in data_keys:
                mapped_dict[key] = data[key]
            else:
                (
                    value,
                    field_exist
                ) = self.get_nested_field_value(data, key)
                if field_exist:
                    mapped_dict[key] = value
        return mapped_dict

    def _sanitize_column_name(self, name: str) -> str:
        """Transform a Netskope field name into an Azure-valid column name.

        Returns an empty string for names that cannot be salvaged
        (which the caller should drop from the payload).
        """
        if not isinstance(name, str) or not name:
            return ""
        sanitized = re.compile(COLUMN_NAME_INVALID_CHAR_RE).sub("_", name)
        if sanitized and sanitized[0].isdigit():
            sanitized = "_" + sanitized
        if sanitized in RESERVED_NAMES:
            sanitized += "_field"
        sanitized = SPECIAL_RENAMES.get(sanitized, sanitized)

        return sanitized

    def _flatten_nested_dicts(
        self,
        record: Dict,
        parent_path: str = "",
    ) -> Dict:
        """Recursively collapse nested dict values into dot-notated keys.

        Netskope often nests one level deep (e.g. the ``host_info``,
        ``user_info`` and ``epdlp`` blocks on clientstatus events),
        but the Azure Custom Log Tables in per_data_type mode expect
        each leaf as its own column (``host_info_os``,
        ``host_info_device_make``, ...). This walks the record and
        produces a flat dict whose keys use ``.`` as the path
        separator

        Args:
            record: the data which needs to be flattened
            parent_path: the parent key of each nested dict
        """
        flat: Dict = {}
        if not isinstance(record, dict):
            return flat
        for key, value in record.items():
            if not isinstance(key, str):
                continue
            full_key = f"{parent_path}.{key}" if parent_path else key
            if isinstance(value, dict):
                flat.update(self._flatten_nested_dicts(value, full_key))
            else:
                flat[full_key] = value
        return flat

    def _flatten_for_dcr(
        self,
        record: Dict,
        data_type: str,
        subtype: str,
        log_source_identifier: str,
    ) -> Dict:
        """Build a flat payload dict for the per-data-type DCR tables.

        Nested dicts are first collapsed into dotted keys (e.g.
        host_info.os); each key is then sanitised into a valid
        Azure column name (the dot becomes _ →
        host_info_os) before being merged with the
        columns the schemas always carry.
        """
        flat: Dict = {}
        if isinstance(record, dict):
            for raw_name, value in self._flatten_nested_dicts(record).items():
                column = self._sanitize_column_name(raw_name)
                if not column:
                    continue
                flat[column] = value
        flat["TimeGenerated"] = f"{datetime.datetime.now()}"
        flat["Application"] = log_source_identifier
        flat["DataType"] = data_type
        flat["SubType"] = subtype
        return flat

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into \
            target platform supported data formats.

        Dispatches to one of three pipelines based on the plugin's
        ``Ingestion Mode`` and SIEM Mapping format:
          - per_data_type: flatten each record into one row, one column
            per Netskope field.
          - single_table + JSON: wrap each record in a ``RawData``
            envelope, applying JSON field-filter mappings for alerts/events.
          - single_table + CEF: build a CEF string per record via the
            mappings and wrap in a ``RawData`` envelope.
        """
        log_source_identifier = self.configuration.get(
            "log_source_identifier", "Netskope CE"
        )
        ingestion_mode = self.configuration.get(
            "ingestion_mode", INGESTION_MODE_SINGLE_TABLE
        )

        if ingestion_mode == INGESTION_MODE_PER_DATA_TYPE:
            return self._transform_per_data_type(
                raw_data, data_type, subtype, log_source_identifier
            )

        if self.configuration.get("transformData", "json") == "json":
            return self._transform_json(
                raw_data, data_type, subtype, log_source_identifier
            )

        return self._transform_cef(
            raw_data, data_type, subtype, log_source_identifier
        )

    def _single_table_payload(
        self,
        payload,
        data_type: str,
        subtype: str,
        log_source_identifier: str,
    ) -> Dict:
        """Wrap a single record/CEF-string into the single_table envelope
        columns expected by the destination Custom Log Table."""
        return {
            "RawData": payload,
            "Application": log_source_identifier,
            "DataType": data_type,
            "SubType": subtype,
            "TimeGenerated": f"{datetime.datetime.now()}",
        }

    def _transform_per_data_type(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        log_source_identifier: str,
    ) -> List:
        """Per-data-type mode bypasses CEF generation entirely; each
        record becomes one row with every kept field as its own column.

        Alerts/events still honour the JSON taxonomy's per-subtype
        field-filter list; an empty list is a passthrough so every
        field is forwarded. Records whose filtered payload is empty
        are skipped to avoid pushing envelope-only rows.
        """
        subtype_mapping = (
            self._load_json_subtype_mapping(data_type, subtype)
            if data_type in JSON_MAPPED_DATA_TYPES
            else []
        )
        return self._map_and_transform(
            raw_data,
            subtype_mapping,
            lambda r: self._flatten_for_dcr(
                record=r,
                data_type=data_type,
                subtype=subtype,
                log_source_identifier=log_source_identifier,
            ),
            data_type,
            subtype,
        )

    def _load_log_analytics_mappings(self):
        """Resolve (delimiter, cef_version, log_analytics_mappings) from the
        plugin's mappings file. Raises with a logged error on failure;
        the caller is expected to propagate."""
        try:
            return get_log_analytics_mappings(self.mappings)
        except KeyError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: An error occurred while "
                    f"fetching the mappings. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise
        except MappingValidationError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: An error occurred while "
                    f"validating the mapping file. {err}"
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

    def _load_json_subtype_mapping(
        self, data_type: str, subtype: str
    ) -> List:
        """Load the JSON subtype mapping for *data_type/subtype*.

        Assumes ``data_type in JSON_MAPPED_DATA_TYPES``; callers are
        responsible for that guard.
        """
        _, _, log_analytics_mappings = self._load_log_analytics_mappings()
        try:
            return self.get_subtype_mapping(
                log_analytics_mappings["json"][data_type], subtype
            )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while retrieving "
                    f"JSON mappings for datatype: {data_type} "
                    f"(subtype: {subtype}). Transformation will be skipped."
                ),
                details=str(traceback.format_exc()),
            )
            raise

    def _map_and_transform(
        self,
        raw_data: List,
        subtype_mapping: List,
        transform_fn,
        data_type: str,
        subtype: str,
    ) -> List:
        """Apply *subtype_mapping* to each record then call *transform_fn*.

        Empty inputs and records that map to nothing are skipped and
        counted; the total is logged at DEBUG level.
        """
        result = []
        skip_count = 0
        for record in raw_data:
            if not record:
                skip_count += 1
                continue
            mapped = self.map_json_data(subtype_mapping, record)
            if not mapped:
                skip_count += 1
                continue
            result.append(transform_fn(mapped))
        if skip_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] "
                f"Skipped {skip_count} record(s) — either the payload "
                "was empty or no fields matched the configured "
                "JSON mapping."
            )
        return result

    def _transform_json(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        log_source_identifier: str,
    ) -> List:
        """JSON-format single-table transform.

        Alerts/events go through the JSON taxonomy's field-filter list
        (see ``JSON_MAPPED_DATA_TYPES``); every other data type
        (currently WebTx) is wrapped in the envelope as-is.
        """
        if data_type not in JSON_MAPPED_DATA_TYPES:
            return [
                self._single_table_payload(
                    data, data_type, subtype, log_source_identifier
                )
                for data in raw_data
            ]

        subtype_mapping = self._load_json_subtype_mapping(data_type, subtype)
        return self._map_and_transform(
            raw_data,
            subtype_mapping,
            lambda r: self._single_table_payload(
                r, data_type, subtype, log_source_identifier
            ),
            data_type,
            subtype,
        )

    def _transform_cef(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        log_source_identifier: str,
    ) -> List:
        """CEF-format single-table transform — build a CEF string per
        record and wrap it in the single_table envelope."""
        delimiter, cef_version, log_analytics_mappings = (
            self._load_log_analytics_mappings()
        )

        cef_generator = CEFGenerator(
            self.mappings,
            delimiter,
            cef_version,
            self.logger,
            self.log_prefix,
        )

        try:
            subtype_mapping = self.get_subtype_mapping(
                log_analytics_mappings[data_type], subtype
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
        skip_count = 0
        for data in raw_data:
            if not data:
                skip_count += 1
                continue
            try:
                header, mapped_flag_header = self.get_headers(
                    subtype_mapping["header"], data, data_type
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] "
                        f"Error occurred while creating CEF header: {err}. "
                        "Transformation of current record will be skipped."
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
                        f"{self.log_prefix}: [{data_type}][{subtype}] "
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
                    data, header, extension, data_type, subtype
                )
                if cef_generated_event:
                    transformed_data.append(
                        self._single_table_payload(
                            cef_generated_event,
                            data_type,
                            subtype,
                            log_source_identifier,
                        )
                    )
            except EmptyExtensionError:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Got"
                        " empty extension during transformation. "
                        "Transformation of current record will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_count += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] An "
                        f"error occurred during transformation. "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_count += 1

        if skip_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Plugin couldn't process {skip_count} "
                "records because they either had no data or contained "
                "invalid/missing fields according to the configured "
                "mapping. Therefore, the transformation and ingestion "
                "for those records were skipped."
            )
        return transformed_data

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the configuration "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is valid."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def _validate_connectivity(
        self,
        configuration: Dict,
        parsed_config: Dict,
    ) -> ValidationResult:
        """Hit each configured custom log table with an empty POST to
        confirm auth + DCR + table all line up.

        In ``single_table`` mode this is one POST. In ``per_data_type``
        mode every distinct, non-empty table name selected by the user
        is tested.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating credentials "
            f"for {PLUGIN_NAME} platform."
        )

        if (
            parsed_config["ingestion_mode"]
            == INGESTION_MODE_PER_DATA_TYPE
        ):
            tables_to_test = [
                (dt, parsed_config["tables"].get(dt, ""))
                for dt in parsed_config["data_types"]
                if parsed_config["tables"].get(dt)
            ]
        else:
            tables_to_test = [
                ("all", parsed_config["single_table_name"]),
            ]

        try:
            auth_header, storage = (
                self.log_analytics_client.get_or_refresh_auth_header(
                    parsed_config=parsed_config,
                    storage=self.storage,
                    is_validation=True,
                )
            )
            for label, table_name in tables_to_test:
                url_endpoint = PUSH_DATA_ENDPOINT.format(
                    dce_uri=parsed_config["dce_uri"],
                    dcr_immutable_id=parsed_config["dcr_immutable_id"],
                    custom_log_table_name=table_name,
                )
                self.log_analytics_client.api_helper(
                    logger_msg=(
                        f"validating credentials against table "
                        f"'{table_name}' ({label})"
                    ),
                    url=url_endpoint,
                    method="POST",
                    data=json.dumps([]),
                    headers=auth_header,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=configuration,
                    storage=storage,
                    is_validation=True,
                )

            logger_msg = (
                "Successfully validated "
                f"credentials for {PLUGIN_NAME} platform."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True, message=logger_msg,
            )
        except MicrosoftAzureLogAnalyticsPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate_mappings(self):
        """Validate the Microsoft Azure LogAnalytics mappings for
          all data type.

        Raises:
            MappingValidationError: When validation fails for \
                any of the configured data_type.
        """
        validation_err_msg = (
            f"{self.log_prefix}: Mapping validation error occurred."
        )
        err_msg = "Invalid attribute mapping provided."
        log_analytics_validator = AzureLogAnalyticsValidator(
            self.logger, self.log_prefix
        )

        def _validate_json_data(json_string):
            """Validate that the jsonData should not be empty."""
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")
            except Exception as e:
                raise ValueError(f"Error occurred while validating JSON: {e}.")
            return json_object

        try:
            mappings = _validate_json_data(self.mappings.get("jsonData"))
        except Exception as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )

        if (
            not isinstance(mappings, dict)
            or not log_analytics_validator.validate_log_analytics_map(mappings)
        ):
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        for data_type in mappings.get("taxonomy", {}).keys():
            try:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Validating the mappings for "
                        f"{PLUGIN_NAME} {data_type}."
                    )
                )
                validate_log_analytics_mappings(mappings, data_type)
            except MappingValidationError as mapping_validation_error:
                self.logger.error(
                    message=(
                        f"{validation_err_msg} {err_msg} Error: "
                        f"{mapping_validation_error}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        return ValidationResult(
            success=True,
            message="Mappings validation successful.",
        )

    def _ingestion_mode_validation(
        self, parsed_config: Dict, configuration: Dict
    ) -> Union[ValidationResult, None]:
        """Enforce the rules that depend on the chosen Ingestion Mode.

        - ingestion_mode itself must be one of the supported values.
        - single_table: custom_log_table_name is mandatory.
        - per_data_type: at least one data type must be selected and
          each selected data type must have a matching table name.
        - CEF format is rejected in per_data_type mode because it
          collapses every record into a single string and is therefore
          incompatible with one-column-per-field tables.
        """
        ingestion_mode = parsed_config["ingestion_mode"]
        if ingestion_mode not in (
            INGESTION_MODE_SINGLE_TABLE,
            INGESTION_MODE_PER_DATA_TYPE,
        ):
            err_msg = (
                "Invalid value provided for 'Ingestion Mode'. "
                "Allowed values: 'single_table', 'per_data_type'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    "Select either 'Single Table' or 'Per Data Type' "
                    "for the 'Ingestion Mode' field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if ingestion_mode == INGESTION_MODE_SINGLE_TABLE:
            return self._validate_parameters(
                field_name="Custom Log Table Name",
                field_value=parsed_config["single_table_name"],
                field_type=str,
            )

        # per_data_type
        data_types = parsed_config["data_types"]
        if not data_types:
            err_msg = (
                "'Data Types to Ingest' is required when 'Ingestion Mode' "
                "is set to 'Per Data Type'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    "Select at least one of Alerts, Events or WebTx."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        for dt in data_types:
            table_name = parsed_config["tables"].get(dt, "")
            if not table_name:
                pretty = dt.capitalize() if dt != "webtx" else "WebTx"
                err_msg = (
                    f"'{pretty} Custom Log Table Name' is required when "
                    f"'{pretty}' is selected under 'Data Types to Ingest'."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Provide the Custom Log Table Name for {pretty} "
                        "or remove it from 'Data Types to Ingest'."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        transform_data = configuration.get("transformData", "json")
        if transform_data == "cef":
            err_msg = (
                "CEF formatting cannot be used with 'Per Data Type' "
                "Ingestion Mode."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    "Switch the SIEM Mapping to JSON, or change "
                    "'Ingestion Mode' to 'Single Table' if you need CEF."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        parsed_config = self.log_analytics_client.get_configuration_parameters(
            configuration
        )

        for field_name, value in (
            ("Directory (tenant) ID", parsed_config["tenant_id"]),
            ("Application (client) ID", parsed_config["app_id"]),
            ("Client Secret", parsed_config["app_secret"]),
            ("DCE URI", parsed_config["dce_uri"]),
            ("DCR Immutable ID", parsed_config["dcr_immutable_id"]),
            ("Log Source Identifier", parsed_config["log_source_identifier"]),
        ):
            if validation_result := self._validate_parameters(
                field_name=field_name,
                field_value=value,
                field_type=str,
            ):
                return validation_result

        if mode_result := self._ingestion_mode_validation(
            parsed_config=parsed_config,
            configuration=configuration,
        ):
            return mode_result

        mappings_validation_result = self.validate_mappings()
        if not mappings_validation_result.success:
            return mappings_validation_result

        return self._validate_connectivity(
            configuration=configuration,
            parsed_config=parsed_config,
        )
