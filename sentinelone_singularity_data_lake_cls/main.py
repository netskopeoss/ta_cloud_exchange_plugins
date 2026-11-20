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

SentinelOne Singularity Data Lake CLS plugin.
"""

import copy
import json
import time
import traceback
from collections import deque
from typing import Any, Dict, List, NoReturn, Optional, Tuple

from jsonpath import jsonpath
from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.cef_generator import CEFGenerator
from .utils import constants as CONST
from .utils.exceptions import (
    EmptyExtensionError,
    FieldNotFoundError,
    MappingValidationError,
    SentinelOneSDLPayloadTooLargeError,
    SentinelOneSDLPluginException,
)
from .utils.hec_client import (
    build_event_body,
    build_event_payload,
    build_raw_params,
    build_raw_payload,
    send_events,
    send_raw,
)
from .utils.helper import SentinelOneSDLPluginHelper
from .utils.utilities import (
    build_numeric_field_map,
    coerce_numeric_fields,
    get_nested_value,
    is_soft_time_limit,
    namespace_reserved,
    resolve_event_time,
    resolve_event_type,
    serialize_item,
    split_into_size,
    validate_hec_base_url,
)
from .utils.validator import SentinelOneSDLValidator

# Returned by _get_subtype_entry() when the mapping has no entry.
_MISSING = object()


class SentinelOneSDLPlugin(PluginBase):
    """Sends Netskope Alerts, Events and WebTx to Singularity Data Lake.

    Uses the HTTP Event Collector (HEC) API. JSON goes to
    /services/collector/event and CEF goes to /services/collector/raw.
    """

    def __init__(self, name: Optional[str], *args, **kwargs):
        """Set up the plugin.

        Nothing here reads the configuration or calls the network. Cloud
        Exchange builds this object with no configuration for validate()
        and with no name for get_dynamic_fields().

        Args:
            name (Optional[str]): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.config_name = name
        self.sdl_helper = SentinelOneSDLPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.sdl_validator = SentinelOneSDLValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )
        self.alerts_helper = AlertsHelper()

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Read the plugin name and version from the manifest.

        Returns:
            Tuple[str, str]: Plugin name and version.
        """
        try:
            manifest_json = SentinelOneSDLPlugin.metadata
            plugin_name = manifest_json.get("name", CONST.PLUGIN_NAME)
            plugin_version = manifest_json.get("version", CONST.PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{CONST.MODULE_NAME} {CONST.PLUGIN_NAME}: Could not"
                    " read the plugin name and version. Using the"
                    " built-in values."
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    # ── Dynamic configuration ────────────────────────────────────────

    def get_dynamic_fields(self) -> List[Dict]:
        """Return a Log File Name field per selected data type.

        Logs to Ingest decides which fields exist; Log File Mode decides
        whether they are shown, through the "condition" each one
        carries. That split is deliberate:

        - Only one field may trigger this call for a given set of
          fields. Cloud Exchange tags what it gets back with the key of
          the field that triggered the fetch and later replaces only the
          fields carrying that tag, so a second trigger would leave a
          second copy of every field on screen.
        - The fields are therefore returned whatever the mode is, and
          Cloud Exchange hides them while Log File Mode is not Different
          Log File per Data Type. Were they withheld instead, switching
          to that mode would show no Log File Name field at all until
          Logs to Ingest was touched, because nothing would trigger a
          fetch.
        - Single mode's Log File Name is a static manifest field and is
          never returned here. A key that is both static and dynamic is
          drawn twice.

        Returns:
            List[Dict]: Field definitions to show.
        """
        configuration = self.configuration or {}
        selected = self._selected_log_types(configuration)
        return [
            copy.deepcopy(field)
            for field in CONST.PER_TYPE_SOURCE_DYNAMIC_FIELDS
            if CONST.PER_TYPE_SOURCE_DATA_TYPES.get(field["key"])
            in selected
        ]

    # ── Configuration helpers ────────────────────────────────────────

    @staticmethod
    def _get_text(configuration: Dict, key: str) -> Any:
        """Read a text value from the configuration.

        Strings are stripped. A missing value or None becomes "". Other
        types are returned as they are, so validation can reject them.
        Never use this for secrets.

        Args:
            configuration (Dict): Plugin configuration.
            key (str): Parameter key.

        Returns:
            Any: Clean value.
        """
        value = configuration.get(key)
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return value

    @staticmethod
    def _is_json_format(configuration: Dict) -> bool:
        """Check if the selected format is JSON.

        Cloud Exchange sends transformData as "json" or "cef" because the
        manifest has format_options. The bool form (True means CEF) is
        still read in case Cloud Exchange sends it.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            bool: True for JSON, False for CEF.
        """
        transform_data = configuration.get("transformData")
        if transform_data is None:
            return True
        if isinstance(transform_data, bool):
            return not transform_data
        return str(transform_data).strip().lower() != CONST.TRANSFORM_DATA_CEF

    @staticmethod
    def _selected_log_types(configuration: Dict) -> List[str]:
        """List the data types picked in "Logs to Ingest".

        validate() refuses a per data type configuration that selects
        nothing, so a saved configuration always has a value here.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            List[str]: Selected data types, lower case.
        """
        value = configuration.get(CONST.LOGS_TO_INGEST_KEY)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return [str(item).strip().lower() for item in value]

    def _is_data_type_skipped(
        self, configuration: Dict, data_type: str
    ) -> bool:
        """Check if this data type is switched off by the configuration.

        In "Different Log File per Data Type" mode only the data types
        picked in "Logs to Ingest" are sent. An empty Log File name is
        not a way of switching one off: the logs are still sent, just
        with no Log File name, which SDL accepts.

        Args:
            configuration (Dict): Plugin configuration.
            data_type (str): "alerts", "events" or "webtx".

        Returns:
            bool: True if nothing should be sent for this data type.
        """
        source_mode = (
            self._get_text(configuration, "source_mode")
            or CONST.SOURCE_MODE_SINGLE
        )
        if source_mode != CONST.SOURCE_MODE_PER_TYPE:
            return False
        return data_type not in self._selected_log_types(configuration)

    def _use_ingestion_time(self, configuration: Dict) -> bool:
        """Check if JSON logs should carry the ingestion time.

        Only JSON logs are affected. CEF goes to /raw, which takes one
        time for a whole request, so Singularity Data Lake stamps those
        logs when they arrive whatever this is set to.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            bool: True to use the Cloud Exchange ingestion time.
        """
        value = self._get_text(configuration, "time_mode")
        return str(value).lower() == CONST.TIME_MODE_INGESTION

    def _resolve_hec_base_url(self, configuration: Dict) -> str:
        """Find the HEC base URL to send logs to.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            str: Base URL with no trailing slash, or "" if not set.
        """
        base_url = self._get_text(configuration, "hec_base_url")
        if base_url == CONST.CUSTOM_HEC_BASE_URL:
            base_url = self._get_text(configuration, "custom_hec_base_url")
        if not isinstance(base_url, str):
            return ""
        return base_url.rstrip("/")

    def _resolve_log_file_name(
        self, configuration: Dict, data_type: str
    ) -> str:
        """Find the Log File name for a data type.

        Args:
            configuration (Dict): Plugin configuration.
            data_type (str): "alerts", "events" or "webtx".

        Returns:
            str: Log File name, or "" if it is not set in "Different Log
                File per Data Type" mode.
        """
        source_mode = (
            self._get_text(configuration, "source_mode")
            or CONST.SOURCE_MODE_SINGLE
        )
        if source_mode == CONST.SOURCE_MODE_PER_TYPE:
            key = CONST.PER_TYPE_SOURCE_KEYS.get(data_type)
            value = self._get_text(configuration, key) if key else ""
            return value if isinstance(value, str) else ""
        value = self._get_text(configuration, "source_name")
        if not isinstance(value, str) or not value:
            return CONST.DEFAULT_LOG_FILE_NAME
        return value

    def _get_send_settings(
        self,
        configuration: Dict,
        data_type: str,
        subtype: str,
        is_json: bool,
    ) -> Dict:
        """Read the Source, Log File Name and Parser for a data type.

        Args:
            configuration (Dict): Plugin configuration.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for log messages.
            is_json (bool): True for JSON logs, False for CEF logs. Picks
                the Parser used when the Parser field is empty.

        Returns:
            Dict: host, source and sourcetype values.

        Raises:
            SentinelOneSDLPluginException: If the Log File name for this
                data type is not set.
        """
        # May be empty: the Log File name is then left out of the
        # request and the log is stored with no Log File in SDL.
        source = self._resolve_log_file_name(configuration, data_type)
        host = self._get_text(configuration, "host")
        if not isinstance(host, str) or not host:
            host = CONST.CE_LOG_SOURCE_IDENTIFIER
        sourcetype = self._get_text(configuration, "sourcetype")
        if not isinstance(sourcetype, str) or not sourcetype:
            sourcetype = (
                CONST.DEFAULT_PARSER if is_json else CONST.DEFAULT_CEF_PARSER
            )
        elif not is_json and sourcetype.lower() in CONST.JSON_PARSER_NAMES:
            # A JSON parser cannot read CEF. This only happens when the
            # format was switched to JSON while a CEF push was retried.
            sourcetype = CONST.DEFAULT_CEF_PARSER
        return {"host": host, "source": source, "sourcetype": sourcetype}

    # ── Mapping helpers ──────────────────────────────────────────────

    def _parsed_mappings(self) -> Dict:
        """Return the mapping document in either shape Cloud Exchange uses.

        transform() gets the parsed document. validate() and
        validate_mappings() get the saved mapping record, which holds
        the document as a JSON string under "jsonData".

        Returns:
            Dict: Mapping document, or {} if there is none or it cannot
                be read.
        """
        mappings = self.mappings
        if not isinstance(mappings, dict):
            return {}
        if "taxonomy" in mappings:
            return mappings
        raw = mappings.get("jsonData")
        if isinstance(raw, dict):
            return raw
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError) as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not read the mapping file."
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Fix the mapping under Settings > Log Shipper >"
                    " Mapping, or reset it to the default mapping."
                ),
            )
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> Any:
        """Find the mapping of a subtype. Case is ignored.

        Args:
            mappings (Dict): Subtype to mapping, for one data type.
            subtype (str): Subtype, for example "dlp" or "page".

        Returns:
            Any: Mapping of the subtype.

        Raises:
            MappingValidationError: If the subtype is not in the mapping.
        """
        if isinstance(mappings, dict) and subtype:
            lowered = {str(key).lower(): val for key, val in mappings.items()}
            if str(subtype).lower() in lowered:
                return lowered[str(subtype).lower()]
        raise MappingValidationError(
            f"No mapping found for subtype '{subtype}'."
        )

    def map_json_data(self, mappings: List, data: Dict) -> Dict:
        """Keep only the fields listed in the mapping.

        An empty list keeps every field. Dot paths such as
        "host_info.hostname" are supported. Listed fields that are not in
        the record are left out.

        Args:
            mappings (List): Field names to keep.
            data (Dict): Netskope record.

        Returns:
            Dict: Filtered record.
        """
        if not mappings or not data:
            return data
        mapped_dict = {}
        for field in mappings:
            value, found = get_nested_value(data, field)
            if found:
                mapped_dict[field] = value
        return mapped_dict

    @staticmethod
    def _is_empty_value(value: Any) -> bool:
        """Check if a value is empty. 0 and False are not empty.

        Args:
            value (Any): Value to check.

        Returns:
            bool: True for None, "", [] and {}.
        """
        return value is None or (
            isinstance(value, (str, list, dict)) and len(value) == 0
        )

    def get_field_value_from_data(
        self,
        extension_mapping: Dict,
        data: Dict,
        is_json_path: bool = False,
    ) -> Tuple[Any, bool]:
        """Read the value of one CEF header or extension field.

        Uses "mapping_field" when the record has a value for it,
        otherwise "default_value".

        Args:
            extension_mapping (Dict): Field definition with mapping_field,
                default_value and transformation.
            data (Dict): Netskope record.
            is_json_path (bool): mapping_field is a JSON path.

        Returns:
            Tuple[Any, bool]: The value, and True if it came from the
                record (False if it is the default).

        Raises:
            FieldNotFoundError: If the record has no value and there is
                no default.
        """
        mapping_field = extension_mapping.get("mapping_field")
        if mapping_field:
            if is_json_path:
                matches = jsonpath(data, mapping_field)
                if matches:
                    return ",".join(map(str, matches)), True
            else:
                value, found = get_nested_value(data, mapping_field)
                if found and not self._is_empty_value(value):
                    if extension_mapping.get("transformation") == (
                        "Time Stamp"
                    ):
                        try:
                            return int(value), True
                        except (TypeError, ValueError):
                            pass
                    return value, True
        if "default_value" in extension_mapping:
            return extension_mapping["default_value"], False
        raise FieldNotFoundError(str(mapping_field))

    def get_headers(
        self, header_mappings: Dict, data: Dict, tenant_name: Optional[str]
    ) -> Tuple[Dict, bool]:
        """Build the CEF header values for one record.

        "$tenant_name" is replaced with the Netskope tenant name.

        Args:
            header_mappings (Dict): Header definitions.
            data (Dict): Netskope record.
            tenant_name (Optional[str]): Tenant name. None for WebTx.

        Returns:
            Tuple[Dict, bool]: Header values, and True if any value came
                from the record.
        """
        headers = {}
        mapped_flag = False
        for header, header_mapping in header_mappings.items():
            try:
                value, mapped = self.get_field_value_from_data(
                    header_mapping,
                    data,
                    is_json_path=bool(header_mapping.get("is_json_path")),
                )
            except FieldNotFoundError:
                continue
            if (
                isinstance(value, str)
                and value.strip().lower() == CONST.TENANT_NAME_VARIABLE
            ):
                value = tenant_name or CONST.TENANT_NAME_FALLBACK
            headers[header] = value
            mapped_flag = mapped_flag or mapped
        return headers, mapped_flag

    def get_extensions(
        self, extension_mappings: Dict, data: Dict
    ) -> Tuple[Dict, bool]:
        """Build the CEF extension values for one record.

        Args:
            extension_mappings (Dict): Extension definitions.
            data (Dict): Netskope record.

        Returns:
            Tuple[Dict, bool]: Extension values, and True if any value
                came from the record.
        """
        extensions = {}
        mapped_flag = False
        for name, extension_mapping in extension_mappings.items():
            try:
                value, mapped = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    is_json_path=bool(extension_mapping.get("is_json_path")),
                )
            except FieldNotFoundError:
                continue
            extensions[name] = value
            mapped_flag = mapped_flag or mapped
        return extensions, mapped_flag

    def get_tenant_name(self, source: str) -> Optional[str]:
        """Find the Netskope tenant name of a source configuration.

        Args:
            source (str): Source configuration name.

        Returns:
            Optional[str]: Tenant name, or None if it cannot be found.
        """
        if not source:
            return None
        try:
            return str(self.alerts_helper.get_tenant_cls(source).name)
        except Exception as err:
            if is_soft_time_limit(err):
                raise
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not find the tenant name for"
                    f" source '{source}'. Logs will be sent without it."
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Check that the source configuration still exists in"
                    " Cloud Exchange."
                ),
            )
            return None

    # ── Transform ────────────────────────────────────────────────────

    def transform(self, raw_data: List, data_type: str, subtype: str) -> List:
        """Turn Netskope records into HEC event bodies or CEF lines.

        JSON format: each record becomes an HEC /event body. CEF format:
        each record becomes a CEF line for /raw. A record that cannot be
        used is skipped and counted; it never stops the batch.

        Args:
            raw_data (List): Netskope records.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".

        Returns:
            List: HEC event bodies (JSON) or CEF lines (CEF).

        Raises:
            SentinelOneSDLPluginException: If the mapping or the
                configuration cannot be used.
        """
        if not raw_data:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] No logs to"
                " transform."
            )
            return []
        configuration = self.configuration or {}
        if self._is_data_type_skipped(configuration, data_type):
            self.logger.info(
                f"{self.log_prefix}: [{data_type}][{subtype}]"
                f" '{data_type}' is not selected in Logs to Ingest, so"
                f" it is not sent. Skipped {len(raw_data)} log(s)."
            )
            return []
        mappings = self._parsed_mappings()
        tenant_name = None
        if data_type != CONST.DATA_TYPE_WEBTX:
            tenant_name = self.get_tenant_name(self.source)
        if self._is_json_format(configuration):
            return self._transform_json(
                raw_data, data_type, subtype, mappings, tenant_name,
                configuration,
            )
        return self._transform_cef(
            raw_data, data_type, subtype, mappings, tenant_name
        )

    def _raise_mapping_error(
        self, data_type: str, subtype: str, message: str
    ) -> NoReturn:
        """Log a mapping problem and stop the transform.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            message (str): What is wrong with the mapping.

        Raises:
            SentinelOneSDLPluginException: Always.
        """
        err_msg = (
            f"[{data_type}][{subtype}] Could not use the mapping file."
            f" {message}"
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=(
                "Fix the mapping under Settings > Log Shipper > Mapping, or"
                " reset it to the default mapping."
            ),
        )
        raise SentinelOneSDLPluginException(err_msg)

    def _skip_unmapped_subtype(
        self, data_type: str, subtype: str, log_format: str, count: int
    ) -> List:
        """Skip logs whose subtype has no entry in the mapping.

        Cloud Exchange only sends a subtype when the JSON or the CEF part
        of the mapping has it. If only the other part has it, these logs
        are skipped with a warning. Like Cloud Exchange's own skip, the
        logs are not sent. Unlike it, Cloud Exchange marks the run as not
        successful, because transform() returns no logs.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            log_format (str): "JSON" or "CEF".
            count (int): Number of logs skipped.

        Returns:
            List: An empty list.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: [{data_type}][{subtype}] The mapping"
                f" has no {log_format} entry for this data type and"
                f" subtype. Skipped {count} log(s). They were not sent."
            ),
            resolution=(
                "Add the entry under Settings > Log Shipper > Mapping, or"
                " reset the mapping to the default."
            ),
        )
        return []

    def _get_subtype_entry(
        self, branch: Any, data_type: str, subtype: str, log_format: str
    ) -> Any:
        """Find the mapping entry of a subtype in one format branch.

        Args:
            branch (Any): Mapping of one data type in one format.
            data_type (str): Data type.
            subtype (str): Subtype.
            log_format (str): "JSON" or "CEF".

        Returns:
            Any: The subtype entry, or _MISSING if the data type or the
                subtype is not in the mapping.

        Raises:
            SentinelOneSDLPluginException: If the data type branch is not
                an object.
        """
        if branch is None:
            return _MISSING
        if not isinstance(branch, dict):
            self._raise_mapping_error(
                data_type,
                subtype,
                f"The {log_format} mapping of '{data_type}' must be an"
                " object.",
            )
        try:
            return self.get_subtype_mapping(branch, subtype)
        except MappingValidationError:
            return _MISSING

    @staticmethod
    def _get_taxonomy(mappings: Dict) -> Dict:
        """Return the "taxonomy" part of the mapping document.

        Args:
            mappings (Dict): Mapping document.

        Returns:
            Dict: Taxonomy, or {} if it is missing.
        """
        taxonomy = mappings.get("taxonomy") if mappings else None
        return taxonomy if isinstance(taxonomy, dict) else {}

    def _get_numeric_fields(
        self, taxonomy: Dict, data_type: str, subtype: str
    ) -> Dict:
        """List the fields of a subtype that should be sent as numbers.

        The types come from the CEF part of the mapping, which gives each
        Netskope field a "transformation" such as Integer.

        Args:
            taxonomy (Dict): Mapping taxonomy.
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            Dict: Field name to "Integer" or "Floating Point". Empty if
                the mapping has no CEF part for this subtype.
        """
        cef_branch = taxonomy.get(data_type)
        if not isinstance(cef_branch, dict):
            return {}
        try:
            return build_numeric_field_map(
                self.get_subtype_mapping(cef_branch, subtype)
            )
        except MappingValidationError:
            return {}

    def _transform_json(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        mappings: Dict,
        tenant_name: Optional[str],
        configuration: Dict,
    ) -> List[Dict]:
        """Build HEC /event bodies.

        Args:
            raw_data (List): Netskope records.
            data_type (str): Data type.
            subtype (str): Subtype.
            mappings (Dict): Mapping document.
            tenant_name (Optional[str]): Tenant name, None for WebTx.
            configuration (Dict): Plugin configuration.

        Returns:
            List[Dict]: HEC event bodies.
        """
        taxonomy = self._get_taxonomy(mappings)
        json_taxonomy = taxonomy.get("json")
        json_branch = (
            json_taxonomy.get(data_type)
            if isinstance(json_taxonomy, dict)
            else None
        )
        subtype_mapping = self._get_subtype_entry(
            json_branch, data_type, subtype, "JSON"
        )
        if subtype_mapping is _MISSING:
            return self._skip_unmapped_subtype(
                data_type, subtype, "JSON", len(raw_data)
            )
        if not isinstance(subtype_mapping, list):
            self._raise_mapping_error(
                data_type,
                subtype,
                f"The JSON mapping of subtype '{subtype}' must be a list"
                " of field names.",
            )
        numeric_fields = self._get_numeric_fields(
            taxonomy, data_type, subtype
        )
        settings = self._get_send_settings(
            configuration, data_type, subtype, is_json=True
        )
        use_ingestion_time = self._use_ingestion_time(configuration)

        counts = {"empty": 0, "no_fields": 0, "bad": 0, "time_fallback": 0}
        transformed = []
        for record in raw_data:
            if not record:
                counts["empty"] += 1
                continue
            try:
                body, used_fallback = self._build_json_body(
                    use_ingestion_time=use_ingestion_time,
                    record=record,
                    data_type=data_type,
                    subtype=subtype,
                    subtype_mapping=subtype_mapping,
                    numeric_fields=numeric_fields,
                    tenant_name=tenant_name,
                    settings=settings,
                )
            except MappingValidationError as err:
                counts["bad"] += 1
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped a"
                    f" log that could not be read. Error: {err}"
                )
                continue
            except Exception as err:
                if is_soft_time_limit(err):
                    raise
                counts["bad"] += 1
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}]"
                        " Skipped a log because of an unexpected error."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                continue
            if body is None:
                counts["no_fields"] += 1
                continue
            if used_fallback:
                counts["time_fallback"] += 1
            transformed.append(body)
        self._log_transform_summary(
            data_type, subtype, len(raw_data), len(transformed), counts
        )
        return transformed

    def _build_json_body(
        self,
        record: Any,
        data_type: str,
        subtype: str,
        subtype_mapping: List,
        numeric_fields: Dict,
        tenant_name: Optional[str],
        settings: Dict,
        use_ingestion_time: bool,
    ) -> Tuple[Optional[Dict], bool]:
        """Build one HEC /event body from a Netskope record.

        Args:
            record (Any): Netskope record.
            data_type (str): Data type.
            subtype (str): Subtype.
            subtype_mapping (List): Field names to keep.
            numeric_fields (Dict): Fields to send as numbers.
            tenant_name (Optional[str]): Tenant name, None for WebTx.
            settings (Dict): host, source and sourcetype values.
            use_ingestion_time (bool): True to put the Cloud Exchange
                ingestion time in the HEC envelope instead of the
                Netskope event time.

        Returns:
            Tuple[Optional[Dict], bool]: The body (None if no mapped field
                is in the record), and True if the current time was used
                because the record has no valid timestamp.

        Raises:
            MappingValidationError: If the record is not a JSON object or
                cannot be turned into JSON.
        """
        if not isinstance(record, dict):
            raise MappingValidationError(
                f"The log is a {type(record).__name__}, not a JSON object."
            )
        mapped = self.map_json_data(subtype_mapping, record)
        if not mapped:
            return None, False
        mapped = coerce_numeric_fields(mapped, numeric_fields)
        event = namespace_reserved(mapped)
        event[CONST.DATA_SOURCE_VENDOR_KEY] = CONST.DATA_SOURCE_VENDOR
        event[CONST.DATA_SOURCE_NAME_KEY] = CONST.DATA_SOURCE_NAME
        event[CONST.DATA_SOURCE_CATEGORY_KEY] = CONST.DATA_SOURCE_CATEGORY
        event[CONST.EVENT_TYPE_KEY] = resolve_event_type(
            record, data_type, subtype
        )
        if tenant_name:
            event[CONST.TENANT_NAME_KEY] = tenant_name

        # Read the time from the original record, not the mapped copy:
        # the mapping may leave the timestamp field out.
        ingestion_time = round(time.time(), 3)
        event_time = resolve_event_time(record, data_type)
        used_fallback = event_time is None
        if used_fallback:
            # Nothing usable in the record, so the two are the same.
            event_time = ingestion_time

        # Both go on every log, whichever one the envelope gets, so a
        # search does not depend on how this plugin is configured.
        event[CONST.NETSKOPE_EVENT_TIME_KEY] = event_time
        event[CONST.CE_INGESTION_TIME_KEY] = ingestion_time

        body = build_event_body(
            event=event,
            host=settings["host"],
            source=settings["source"],
            sourcetype=settings["sourcetype"],
            time_value=(
                ingestion_time if use_ingestion_time else event_time
            ),
        )
        try:
            serialize_item(body)
        except (TypeError, ValueError) as err:
            raise MappingValidationError(
                f"The log cannot be turned into JSON. Error: {err}"
            )
        return body, used_fallback

    def _transform_cef(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        mappings: Dict,
        tenant_name: Optional[str],
    ) -> List[str]:
        """Build CEF lines for HEC /raw.

        Args:
            raw_data (List): Netskope records.
            data_type (str): Data type.
            subtype (str): Subtype.
            mappings (Dict): Mapping document.
            tenant_name (Optional[str]): Tenant name, None for WebTx.

        Returns:
            List[str]: CEF lines.
        """
        taxonomy = self._get_taxonomy(mappings)
        subtype_mapping = self._get_subtype_entry(
            taxonomy.get(data_type), data_type, subtype, "CEF"
        )
        if subtype_mapping is _MISSING:
            return self._skip_unmapped_subtype(
                data_type, subtype, "CEF", len(raw_data)
            )
        if not isinstance(subtype_mapping, dict) or not all(
            isinstance(subtype_mapping.get(section), dict)
            and all(
                isinstance(definition, dict)
                for definition in subtype_mapping[section].values()
            )
            for section in ("header", "extension")
        ):
            self._raise_mapping_error(
                data_type,
                subtype,
                f"The CEF mapping of subtype '{subtype}' needs a 'header'"
                " and an 'extension' object, and each field in them must"
                " be an object.",
            )
        try:
            cef_generator = CEFGenerator(
                extension_mapping=subtype_mapping["extension"],
                delimiter=mappings.get("delimiter") or "|",
                cef_version=mappings.get("cef_version") or "0",
                logger=self.logger,
                log_prefix=self.log_prefix,
            )
        except MappingValidationError as err:
            self._raise_mapping_error(data_type, subtype, str(err))

        counts = {"empty": 0, "no_fields": 0, "bad": 0, "time_fallback": 0}
        transformed = []
        for record in raw_data:
            if not record:
                counts["empty"] += 1
                continue
            try:
                if not isinstance(record, dict):
                    raise MappingValidationError(
                        f"The log is a {type(record).__name__}, not a JSON"
                        " object."
                    )
                headers, header_mapped = self.get_headers(
                    subtype_mapping["header"], record, tenant_name
                )
                extensions, extension_mapped = self.get_extensions(
                    subtype_mapping["extension"], record
                )
                if not (header_mapped or extension_mapped):
                    counts["no_fields"] += 1
                    continue
                transformed.append(
                    cef_generator.get_cef_event(
                        record, headers, extensions, data_type, subtype
                    )
                )
            except EmptyExtensionError:
                counts["no_fields"] += 1
            except MappingValidationError as err:
                counts["bad"] += 1
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped a"
                    f" log that could not be read. Error: {err}"
                )
            except Exception as err:
                if is_soft_time_limit(err):
                    raise
                counts["bad"] += 1
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}]"
                        " Skipped a log because of an unexpected error."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
        self._log_transform_summary(
            data_type, subtype, len(raw_data), len(transformed), counts
        )
        return transformed

    def _log_transform_summary(
        self,
        data_type: str,
        subtype: str,
        received: int,
        transformed: int,
        counts: Dict,
    ) -> None:
        """Log how many logs were transformed and skipped.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            received (int): Logs received.
            transformed (int): Logs transformed.
            counts (Dict): Skip and fallback counters.
        """
        log_tag = f"{self.log_prefix}: [{data_type}][{subtype}]"
        self.logger.debug(
            f"{log_tag} Transformed {transformed} of {received} log(s)."
        )
        skipped = counts["empty"] + counts["no_fields"] + counts["bad"]
        if skipped:
            self.logger.info(
                f"{log_tag} Skipped {skipped} of {received} log(s):"
                f" {counts['empty']} empty, {counts['no_fields']} with no"
                f" mapped fields, {counts['bad']} that could not be read."
            )
        if counts["time_fallback"]:
            self.logger.info(
                f"{log_tag} {counts['time_fallback']} log(s) had no valid"
                " timestamp. The current time was used for them."
            )

    # ── Push ─────────────────────────────────────────────────────────

    @staticmethod
    def chunk_size() -> int:
        """Tell Cloud Exchange how many logs to hand over at a time.

        Only a hint. push() splits by size, not by count. Must stay a
        static method: PluginBase.chunk_size is static, and an instance
        method here would break calls made on the class.

        Returns:
            int: Logs per transform/push cycle.
        """
        return CONST.CHUNK_SIZE

    @staticmethod
    def _split_in_half(
        pending: deque, items: List, lines: List[str]
    ) -> None:
        """Put the two halves of a chunk back at the front of the queue.

        The order of logs is kept, so the logs handled so far are always
        the first logs of transformed_data.

        Args:
            pending (deque): Chunks still to send.
            items (List): Logs in the chunk.
            lines (List[str]): Serialized logs in the chunk.
        """
        middle = len(items) // 2
        pending.appendleft((items[middle:], lines[middle:]))
        pending.appendleft((items[:middle], lines[:middle]))

    def _detect_log_format(
        self, transformed_data: List, configuration: Dict, log_tag: str
    ) -> bool:
        """Work out the format of the logs from the logs themselves.

        The endpoint must match the data. If an admin changes the log
        format while Cloud Exchange is retrying a push, the logs were
        prepared in the old format, so they are sent in that format.

        Args:
            transformed_data (List): Output of transform().
            configuration (Dict): Plugin configuration.
            log_tag (str): "[data_type][subtype]" text for logs.

        Returns:
            bool: True for JSON (HEC event bodies), False for CEF lines.

        Raises:
            SentinelOneSDLPluginException: If the logs are a mix of shapes
                or of an unknown shape.
        """
        if all(isinstance(item, dict) for item in transformed_data):
            is_json = True
        elif all(isinstance(item, str) for item in transformed_data):
            is_json = False
        else:
            err_msg = (
                f"{log_tag} The logs to send are not all JSON objects or all"
                " CEF lines, so they cannot be sent."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Check that no other plugin changes the logs before"
                    " they reach this plugin."
                ),
            )
            raise SentinelOneSDLPluginException(err_msg)
        if is_json != self._is_json_format(configuration):
            log_format = "JSON" if is_json else "CEF"
            self.logger.info(
                f"{self.log_prefix}: {log_tag} The log format setting was"
                " changed after these logs were prepared. They are sent as"
                f" {log_format}, the format they were prepared in."
            )
        return is_json

    @staticmethod
    def _get_hec_rejection(response: Any) -> Optional[str]:
        """Read the reason when HEC answers 200 but did not accept the logs.

        A normal answer is {"text": "Success", "code": 0}.

        Args:
            response (Any): Parsed HEC response.

        Returns:
            Optional[str]: HEC's text when "code" is not 0, else None.
        """
        if isinstance(response, dict) and response.get("code") not in (
            None,
            0,
        ):
            return str(response.get("text") or "unknown error")
        return None

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Send transformed logs to Singularity Data Lake.

        Logs are packed into batches of at most 10 MB, gzipped, and sent
        one batch per request. A batch that is too big after gzip, or
        that HEC rejects with 413, is split in half and sent again. A
        single log that is still too big is left out and reported in
        failed_data.

        If a request fails, the logs already sent are removed from
        transformed_data and the error is raised. Cloud Exchange then
        retries with the same list, so sent logs are not sent twice.

        Args:
            transformed_data (List): Output of transform().
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype.

        Returns:
            PushResult: Result with a summary message.

        Raises:
            SentinelOneSDLPluginException: If a request fails.
        """
        log_tag = f"[{data_type}][{subtype}]"
        if not transformed_data:
            log_msg = f"{log_tag} No logs to send to {CONST.PLATFORM_NAME}."
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)

        configuration = self.configuration or {}
        base_url = self._resolve_hec_base_url(configuration)
        api_token = configuration.get("api_token")
        if not base_url or not api_token:
            err_msg = (
                f"{log_tag} The HEC Base URL or the Log Access Write Key is"
                " not set."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Edit the plugin configuration and set the HEC Base URL"
                    " and the Log Access Write Key."
                ),
            )
            raise SentinelOneSDLPluginException(err_msg)

        is_json = self._detect_log_format(
            transformed_data, configuration, log_tag
        )
        raw_params = None
        if not is_json:
            settings = self._get_send_settings(
                configuration, data_type, subtype, is_json=False
            )
            raw_params = build_raw_params(
                source=settings["source"],
                sourcetype=settings["sourcetype"],
                host=settings["host"],
                data_source_vendor=CONST.DATA_SOURCE_VENDOR,
                data_source_name=CONST.DATA_SOURCE_NAME,
                data_source_category=CONST.DATA_SOURCE_CATEGORY,
            )
        # self.proxy reads the Cloud Exchange settings each time, so it is
        # read once here.
        proxies = self.proxy

        total = len(transformed_data)
        processed = 0
        sent = 0
        batch = 0
        failed_data = []
        try:
            pending = deque(split_into_size(transformed_data))
            while pending:
                items, lines = pending.popleft()
                body = (
                    build_event_payload(lines)
                    if is_json
                    else build_raw_payload(lines)
                )
                if len(body) > CONST.MAX_COMPRESSED_PAYLOAD_SIZE_IN_BYTES:
                    if len(items) > 1:
                        self.logger.debug(
                            f"{self.log_prefix}: {log_tag} A batch of"
                            f" {len(items)} logs is too large to send in one"
                            " request. Splitting it into two smaller"
                            " batches."
                        )
                        self._split_in_half(pending, items, lines)
                        continue
                    self._skip_oversized_log(log_tag, items, failed_data)
                    processed += 1
                    continue

                logger_msg = (
                    f"sending {len(items)} {data_type} log(s) in batch"
                    f" {batch + 1}"
                )
                try:
                    if is_json:
                        response = send_events(
                            helper=self.sdl_helper,
                            base_url=base_url,
                            api_token=api_token,
                            body=body,
                            verify=self.ssl_validation,
                            proxies=proxies,
                            logger_msg=logger_msg,
                        )
                    else:
                        response = send_raw(
                            helper=self.sdl_helper,
                            base_url=base_url,
                            api_token=api_token,
                            body=body,
                            params=raw_params,
                            verify=self.ssl_validation,
                            proxies=proxies,
                            logger_msg=logger_msg,
                        )
                except SentinelOneSDLPayloadTooLargeError:
                    if len(items) > 1:
                        self.logger.info(
                            f"{self.log_prefix}: {log_tag} Batch"
                            f" {batch + 1} was too large for"
                            f" {CONST.PLATFORM_NAME}. Splitting it into"
                            " two smaller batches and"
                            " sending them again."
                        )
                        self._split_in_half(pending, items, lines)
                        continue
                    self._skip_oversized_log(log_tag, items, failed_data)
                    processed += 1
                    continue

                rejection = self._get_hec_rejection(response)
                if rejection:
                    err_msg = (
                        f"{log_tag} {CONST.PLATFORM_NAME} did not accept batch"
                        f" {batch + 1}. It said: '{rejection}'."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"API response: {response}",
                        resolution=(
                            "Check the HEC Base URL and the Log Access Write"
                            " Key."
                        ),
                    )
                    raise SentinelOneSDLPluginException(err_msg)

                batch += 1
                processed += len(items)
                sent += len(items)
                self.logger.info(
                    f"{self.log_prefix}: {log_tag} Sent {len(items)} log(s)"
                    f" in batch {batch}. Total sent: {sent} of {total}."
                )
        except SentinelOneSDLPluginException:
            del transformed_data[:processed]
            # Logs left out for being too large were counted in
            # "processed", so the trim above drops them too. Put them back
            # at the front: the push is retried, and only a PushResult can
            # report them in failed_data for Cloud Exchange to subtract.
            transformed_data[:0] = failed_data
            self._log_push_failure(log_tag, batch + 1, sent, total)
            raise
        except Exception as err:
            # Celery raises SoftTimeLimitExceeded once, wherever the
            # task happens to be. Cloud Exchange needs that exact type
            # to reschedule the run; wrapping it means the worker is
            # killed at the hard limit and the logs in flight are lost.
            if is_soft_time_limit(err):
                raise
            del transformed_data[:processed]
            transformed_data[:0] = failed_data
            self._log_push_failure(log_tag, batch + 1, sent, total, err)
            raise SentinelOneSDLPluginException(
                f"{log_tag} Could not send logs to {CONST.PLATFORM_NAME}."
                f" Error: {err}"
            ) from err

        log_msg = (
            f"{log_tag} Sent {sent} of {total} log(s) to"
            f" {CONST.PLATFORM_NAME}."
        )
        if failed_data:
            log_msg += (
                f" {len(failed_data)} log(s) were not sent because each one"
                " is larger than the size limit."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(
            success=True, message=log_msg, failed_data=failed_data
        )

    def _skip_oversized_log(
        self, log_tag: str, items: List, failed_data: List
    ) -> None:
        """Leave out one log that is too big to send on its own.

        Args:
            log_tag (str): "[data_type][subtype]" text for logs.
            items (List): A chunk with exactly one log.
            failed_data (List): Logs not sent. Updated in place.
        """
        failed_data.extend(items)
        self.logger.error(
            message=(
                f"{self.log_prefix}: {log_tag} One log is too large to send,"
                " even on its own. It was not sent."
            ),
            resolution=(
                "Check the source data for a log with a very large field."
                " Use the mapping to leave that field out if it is not"
                " needed."
            ),
        )

    def _log_push_failure(
        self,
        log_tag: str,
        batch: int,
        sent: int,
        total: int,
        err: Optional[Exception] = None,
    ) -> None:
        """Log that a push stopped part way.

        Args:
            log_tag (str): "[data_type][subtype]" text for logs.
            batch (int): Batch that failed.
            sent (int): Logs sent before the failure.
            total (int): Logs in this push.
            err (Exception): Unexpected error, if any.
        """
        message = (
            f"{self.log_prefix}: {log_tag} Could not send batch {batch}."
            f" {sent} of {total} log(s) were sent before this."
        )
        if err is not None:
            message += f" Error: {err}"
        self.logger.error(
            message=message,
            details=traceback.format_exc(),
            resolution=(
                "Check the error above. Cloud Exchange retries this push"
                " with the logs that were not sent."
            ),
        )

    # ── Validation ───────────────────────────────────────────────────

    def _validate_url(self, url: str) -> bool:
        """Check that a URL can be used as an HEC base URL.

        Args:
            url (str): URL with no trailing slash.

        Returns:
            bool: True if it is https, has a host, and has no path.
        """
        return validate_hec_base_url(url)

    def _validation_failed(
        self, message: str, resolution: str
    ) -> ValidationResult:
        """Log a validation failure and build the result.

        The message has no log prefix. Cloud Exchange adds its own.

        Args:
            message (str): What is wrong.
            resolution (str): What the user should do.

        Returns:
            ValidationResult: Failed result.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: {CONST.VALIDATION_ERROR_MESSAGE}"
                f" {message}"
            ),
            resolution=resolution,
        )
        return ValidationResult(success=False, message=message)

    def _validate_configuration_parameters(
        self,
        value: Any,
        validation_type: str,
        field_name: str,
        is_required: bool = True,
        valid_values: Optional[List] = None,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
    ) -> Optional[ValidationResult]:
        """Check one configuration value.

        Returns None when the value is fine, so it can be used with the
        walrus operator.

        Args:
            value (Any): Value to check. Text is already stripped.
                Passwords are never stripped.
            validation_type (str): "text", "password", "choice", "url",
                "log_file" or "number".
            field_name (str): Label shown to the user.
            is_required (bool): The value must be set.
            valid_values (List): Allowed values for "choice".
            min_val (int): Lowest value for "number".
            max_val (int): Highest value for "number".

        Returns:
            Optional[ValidationResult]: Failed result, or None if valid.
        """
        resolution = (
            f"Provide a valid value for '{field_name}' in the configuration"
            " parameters."
        )
        if value is None or value == "":
            if is_required:
                return self._validation_failed(
                    CONST.EMPTY_ERROR_MESSAGE.format(field_name), resolution
                )
            self.logger.debug(
                f"{self.log_prefix}: Validation successful for"
                f" '{field_name}'."
            )
            return None

        invalid_msg = CONST.INVALID_VALUE_ERROR_MESSAGE.format(field_name)
        if validation_type == "number":
            if isinstance(value, bool) or not isinstance(value, int):
                return self._validation_failed(invalid_msg, resolution)
            if (min_val is not None and value < min_val) or (
                max_val is not None and value > max_val
            ):
                return self._validation_failed(
                    f"{invalid_msg} It must be between {min_val} and"
                    f" {max_val}.",
                    f"Set '{field_name}' between {min_val} and {max_val}.",
                )
        elif not isinstance(value, str):
            return self._validation_failed(invalid_msg, resolution)

        if (
            validation_type == "choice"
            and valid_values
            and value not in valid_values
        ):
            allowed = ", ".join(str(item) for item in valid_values)
            return self._validation_failed(
                f"{invalid_msg} Allowed values are: {allowed}.",
                f"Select one of these values for '{field_name}': {allowed}.",
            )
        if validation_type == "url" and not self._validate_url(value):
            return self._validation_failed(
                f"{invalid_msg} Enter only the https base URL, for example"
                " https://ingest.us1.sentinelone.net.",
                "Enter an https URL with no path, query or trailing text.",
            )
        if (
            validation_type == "log_file"
            and value.lower() in CONST.BLOCKED_LOG_FILE_NAMES
        ):
            return self._validation_failed(
                f"{invalid_msg} '{value}' is reserved by"
                f" {CONST.PLATFORM_NAME}.",
                f"Use a different name for '{field_name}'.",
            )

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for '{field_name}'."
        )
        return None

    def _validate_mapping_document(
        self, cef_required: bool
    ) -> Optional[ValidationResult]:
        """Check the mapping file.

        Args:
            cef_required (bool): True when CEF format is selected.

        Returns:
            Optional[ValidationResult]: Failed result, or None if valid.
        """
        resolution = (
            "Fix the mapping under Settings > Log Shipper > Mapping, or"
            " reset it to the default SentinelOne Singularity Data Lake"
            " mapping."
        )
        mappings = self._parsed_mappings()
        if not mappings:
            return self._validation_failed(
                f"The {CONST.PLATFORM_NAME} mapping is empty or could not be"
                " read.",
                resolution,
            )
        if not self.sdl_validator.validate_mappings(
            mappings, cef_required=cef_required
        ):
            return self._validation_failed(
                f"Invalid {CONST.PLATFORM_NAME} mapping. Check logs for more"
                " details.",
                resolution,
            )
        self.logger.debug(
            f"{self.log_prefix}: Validation successful for the mapping."
        )
        return None

    def validate_mappings(self) -> ValidationResult:
        """Check the mapping file when an admin saves it.

        Cloud Exchange calls this with no configuration, so both the JSON
        and the CEF parts are checked if they are present.

        Returns:
            ValidationResult: Result of the check.
        """
        if result := self._validate_mapping_document(cef_required=False):
            return result
        return ValidationResult(
            success=True, message="Mapping validation successful."
        )

    def _validate_connectivity(
        self, base_url: str, api_token: str, host: str, sourcetype: str
    ) -> ValidationResult:
        """Send one test log to HEC /event to check the configuration.

        The test log has real content. HEC answers 200 even for an empty
        body that it then drops, so an empty test would prove nothing.

        Args:
            base_url (str): HEC base URL.
            api_token (str): Log Access Write Key.
            host (str): Source value.
            sourcetype (str): Parser name.

        Returns:
            ValidationResult: Result of the check.
        """
        body = build_event_body(
            event={
                "event_type": CONST.VALIDATION_EVENT_TYPE,
                "plugin_name": self.config_name or self.plugin_name,
                "plugin_version": self.plugin_version,
            },
            host=host or CONST.CE_LOG_SOURCE_IDENTIFIER,
            source=CONST.VALIDATION_LOG_FILE_NAME,
            sourcetype=sourcetype or CONST.DEFAULT_PARSER,
            time_value=round(time.time(), 3),
        )
        try:
            response = send_events(
                helper=self.sdl_helper,
                base_url=base_url,
                api_token=api_token,
                body=build_event_payload([serialize_item(body)]),
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="sending a test log to check the configuration",
                is_validation=True,
            )
        except SentinelOneSDLPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                f"Unexpected error while checking the connection to"
                f" {CONST.PLATFORM_NAME}. Check logs for more details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
                resolution="Check the configuration parameters and retry.",
            )
            return ValidationResult(success=False, message=err_msg)

        rejection = self._get_hec_rejection(response)
        if rejection:
            return self._validation_failed(
                f"{CONST.PLATFORM_NAME} did not accept the test log. It said:"
                f" '{rejection}'.",
                "Check the HEC Base URL and the Log Access Write Key.",
            )

        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration, the mapping, and the connection.

        Parameters are checked in manifest order. The connection check
        runs last. Only the configuration argument is used here, never
        self.configuration: Cloud Exchange builds the plugin without a
        configuration when it validates.

        Args:
            configuration (Dict): Configuration to check.

        Returns:
            ValidationResult: Result of the validation.
        """
        transform_data = configuration.get("transformData")
        if transform_data is None:
            transform_data = CONST.TRANSFORM_DATA_JSON
        if not isinstance(transform_data, bool) and (
            str(transform_data).strip().lower()
            not in CONST.ALLOWED_TRANSFORM_DATA
        ):
            return self._validation_failed(
                f"Log format '{transform_data}' is not supported. Select"
                " JSON or CEF.",
                "Select JSON or CEF as the log format.",
            )
        is_json = self._is_json_format(configuration)

        hec_base_url = self._get_text(configuration, "hec_base_url")
        if result := self._validate_configuration_parameters(
            hec_base_url,
            "choice",
            "HEC Base URL",
            valid_values=CONST.ALLOWED_HEC_BASE_URLS,
        ):
            return result

        custom_hec_base_url = self._get_text(
            configuration, "custom_hec_base_url"
        )
        if isinstance(custom_hec_base_url, str):
            custom_hec_base_url = custom_hec_base_url.rstrip("/")
        if result := self._validate_configuration_parameters(
            custom_hec_base_url,
            "url" if hec_base_url == CONST.CUSTOM_HEC_BASE_URL else "text",
            "Custom HEC Base URL",
            is_required=hec_base_url == CONST.CUSTOM_HEC_BASE_URL,
        ):
            return result

        api_token = configuration.get("api_token")
        if result := self._validate_configuration_parameters(
            api_token, "password", "Log Access Write Key"
        ):
            return result

        host = self._get_text(configuration, "host")
        if result := self._validate_configuration_parameters(
            host, "text", "Source", is_required=False
        ):
            return result

        sourcetype = self._get_text(configuration, "sourcetype")
        if result := self._validate_configuration_parameters(
            sourcetype, "text", "Parser", is_required=False
        ):
            return result
        if not is_json and sourcetype.lower() in CONST.JSON_PARSER_NAMES:
            return self._validation_failed(
                f"Parser '{sourcetype}' cannot read CEF logs.",
                "Enter the name of a CEF parser from User > Manage Logs >"
                " Parsers in Singularity Data Lake, or leave Parser empty to"
                f" use '{CONST.DEFAULT_CEF_PARSER}'.",
            )

        time_mode = self._get_text(configuration, "time_mode")
        if result := self._validate_configuration_parameters(
            time_mode,
            "choice",
            "Timestamp Field Value",
            valid_values=CONST.ALLOWED_TIME_MODES,
        ):
            return result

        source_mode = self._get_text(configuration, "source_mode")
        if result := self._validate_configuration_parameters(
            source_mode,
            "choice",
            "Log File Mode",
            valid_values=CONST.ALLOWED_SOURCE_MODES,
        ):
            return result

        if source_mode == CONST.SOURCE_MODE_PER_TYPE:
            selected = self._selected_log_types(configuration)
            unknown = [
                item
                for item in selected
                if item not in CONST.SUPPORTED_DATA_TYPES
            ]
            if unknown:
                return self._validation_failed(
                    CONST.INVALID_VALUE_ERROR_MESSAGE.format(
                        "Logs to Ingest"
                    ),
                    "Select Alerts, Events or WebTx in 'Logs to"
                    " Ingest'.",
                )
            if not selected:
                return self._validation_failed(
                    CONST.EMPTY_ERROR_MESSAGE.format("Logs to Ingest"),
                    "Select at least one data type in 'Logs to Ingest'."
                    " A data type left out is not sent.",
                )
            # Names are optional; an empty one sends no Log File name.
            log_file_fields = [
                (field["key"], field["label"], False)
                for field in CONST.PER_TYPE_SOURCE_DYNAMIC_FIELDS
                if CONST.PER_TYPE_SOURCE_DATA_TYPES.get(field["key"])
                in selected
                and self._get_text(configuration, field["key"])
            ]
        else:
            log_file_fields = [
                (CONST.SINGLE_SOURCE_KEY, CONST.SINGLE_SOURCE_LABEL, False)
            ]
        for key, label, is_required in log_file_fields:
            if result := self._validate_configuration_parameters(
                self._get_text(configuration, key),
                "log_file",
                label,
                is_required=is_required,
            ):
                return result

        if result := self._validate_mapping_document(cef_required=not is_json):
            return result

        if hec_base_url == CONST.CUSTOM_HEC_BASE_URL:
            base_url = custom_hec_base_url
        else:
            base_url = hec_base_url.rstrip("/")
        return self._validate_connectivity(
            base_url=base_url,
            api_token=api_token,
            host=host,
            sourcetype=sourcetype,
        )
