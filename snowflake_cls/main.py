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

Snowflake CLS Plugin.
"""

import json
import re
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.constants import (
    ALL_INGESTION_MODES,
    CHUNK_SIZE,
    COLUMN_MODE_COMBINED,
    COLUMN_MODE_SEPARATE_FIELDS,
    DATA_TYPE_LABELS,
    EMPTY_ERROR_MESSAGE,
    ENVELOPE_COLUMN_NAMES,
    EXTRA_FIELDS_COLUMN_NAME,
    FIELD_NAME_INVALID_CHAR_RE,
    GZIP_CONTENT_ENCODING,
    INGESTION_MODE_PER_DATA_TYPE,
    INGESTION_MODE_SINGLE_TABLE,
    INVALID_VALUE_ERROR_MESSAGE,
    ISO_TIMESTAMP_FORMAT,
    MANDATORY_COMBINED_COLUMN_TYPES,
    MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
    MODULE_NAME,
    OPTIONAL_COMBINED_COLUMN_TYPES,
    PER_DATA_TYPE_DYNAMIC_FIELDS,
    PER_DATA_TYPE_TABLE_FIELD,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RAW_DATA_COLUMN_NAME,
    SNOWFLAKE_IDENTIFIER_MAX_LENGTH,
    RAW_LINE_FIELD_NAME,
    SCHEMA_CACHE_STORAGE_KEY,
    SINGLE_TABLE_DYNAMIC_FIELDS,
    SNOWFLAKE_RESERVED_KEYWORDS,
    SOURCE_CONFIG_NAME_COLUMN,
    SUBTYPE_SOURCE_FIELD,
    SUPPORTED_DATA_TYPES,
    TIMESTAMP_FIELDS,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import (
    MappingValidationError,
    SnowflakeAuthenticationError,
    SnowflakeConfigurationError,
    SnowflakePluginException,
)
from .utils.helper import SnowflakePluginHelper
from .utils.schema_helper import SnowflakeSchemaHelper
from .utils.streaming_helper import (
    SnowflakeAuthProvider,
    SnowflakeStreamingClient,
)
from .utils.utilities import split_into_size, try_compress_whole_batch
from .utils.validator import SnowflakeValidator


class SnowflakePlugin(PluginBase):
    """Sends Netskope alerts, events and WebTx to a Snowflake table.

    Delivery goes over the Snowpipe Streaming REST API using an elastic
    channel, so no channel has to be opened or closed and no warehouse is
    needed. The plugin never creates or alters a table - every target
    table must already exist.
    """

    # Matches any character that cannot appear in an unquoted Snowflake
    # column name.
    NORMALIZE_RE = re.compile(FIELD_NAME_INVALID_CHAR_RE)

    def __init__(self, name, *args, **kwargs):
        """Set up the plugin.

        Nothing here touches the network. Cloud Exchange can build this
        object without ever calling validate() or push().

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.config_name = name

        self.snowflake_helper = SnowflakePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.auth_provider = SnowflakeAuthProvider(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )
        self.streaming_client = SnowflakeStreamingClient(
            logger=self.logger,
            log_prefix=self.log_prefix,
            helper=self.snowflake_helper,
            auth_provider=self.auth_provider,
        )
        self.schema_helper = SnowflakeSchemaHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            helper=self.snowflake_helper,
            auth_provider=self.auth_provider,
        )
        self.snowflake_validator = SnowflakeValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Read the plugin name and version from the manifest.

        Returns:
            Tuple[str, str]: Plugin name and version.
        """
        try:
            manifest_json = SnowflakePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            # The name and version are only used in log lines. Falling
            # back to the built-in values costs nothing and there is
            # nothing for the user to do, so no resolution is given.
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Could not read the"
                    f" plugin details. Using the built-in name and"
                    f" version. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    # ── Dynamic configuration ────────────────────────────────────────

    def get_dynamic_fields(self) -> List[Dict]:
        """Return the table-name fields for the chosen Ingestion Mode.

        Ingestion Mode is the plugin's only dynamic trigger. Cloud
        Exchange calls this when it changes, sending that field's value.

        Returns:
            List[Dict]: Field definitions for Cloud Exchange to render.
        """
        configuration = self.configuration or {}
        ingestion_mode = str(
            configuration.get("ingestion_mode") or ""
        ).strip()
        self.logger.debug(
            f"{self.log_prefix}: Returning table fields for Ingestion"
            f" Mode '{ingestion_mode}'."
        )
        if ingestion_mode == INGESTION_MODE_PER_DATA_TYPE:
            return list(PER_DATA_TYPE_DYNAMIC_FIELDS)
        return list(SINGLE_TABLE_DYNAMIC_FIELDS)

    # ── Configuration helpers ────────────────────────────────────────

    @staticmethod
    def _get_config_params(configuration: Dict) -> Dict:
        """Read the configuration into a tidy dict.

        Text fields are stripped. Secrets are not - whitespace matters
        inside a PEM block, and stripping a token can break it.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            Dict: The configuration values this plugin uses.
        """
        def text(key: str) -> str:
            value = configuration.get(key, "")
            return str(value).strip() if value is not None else ""

        return {
            "base_url": text("base_url"),
            "programmatic_access_token": (
                configuration.get("programmatic_access_token") or ""
            ),
            "database": text("database"),
            "schema": text("schema"),
            "ingestion_mode": text("ingestion_mode")
            or INGESTION_MODE_SINGLE_TABLE,
            "table_name": text("table_name"),
            "alerts_table_name": text("alerts_table_name"),
            "events_table_name": text("events_table_name"),
            "webtx_table_name": text("webtx_table_name"),
        }

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
        allowed_values: list = None,
        range_values: Tuple[int, int] = None,
        resolution: str = None,
    ) -> Optional[ValidationResult]:
        """Check one configuration field.

        Returns None when the field is fine, so the caller can use it
        with a walrus and carry on.

        Args:
            field_name (str): Label shown to the user.
            field_value: Value to check.
            field_type (type): Type the value should have.
            is_required (bool): Whether the field must be filled in.
            allowed_values (list): Values the field may hold.
            range_values (Tuple[int, int]): Lowest and highest allowed
                value, for number fields.
            resolution (str): Extra guidance put in the error log.

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        default_resolution = (
            f"Provide a valid value for '{field_name}' in the"
            " configuration parameters."
        )
        resolution = resolution or default_resolution

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = EMPTY_ERROR_MESSAGE.format(field_name)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if field_value not in (None, "") and not isinstance(
            field_value, field_type
        ):
            err_msg = INVALID_VALUE_ERROR_MESSAGE.format(field_name)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if range_values and isinstance(field_value, int):
            low, high = range_values
            if not low <= field_value <= high:
                err_msg = (
                    f"{INVALID_VALUE_ERROR_MESSAGE.format(field_name)}"
                    f" It should be between {low} and {high}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                        f" {err_msg}"
                    ),
                    resolution=(
                        f"Set '{field_name}' to a value between {low} and"
                        f" {high}."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        if allowed_values and field_value not in allowed_values:
            allowed = ", ".join(str(value) for value in allowed_values)
            err_msg = (
                f"{INVALID_VALUE_ERROR_MESSAGE.format(field_name)}"
                f" Allowed values are {allowed}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Set '{field_name}' to one of: {allowed}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for"
            f" '{field_name}'."
        )
        return None

    def _is_transform_data_json(self, configuration: Dict) -> bool:
        """Check whether Cloud Exchange is sending JSON, not CEF.

        Cloud Exchange sends the string "json" because the manifest
        declares format_options with JSON as the only choice. Without
        that key the core rewrites the value to a bool before the
        plugin sees it - True for CEF, False for JSON - so the bool
        form is still read here. It is not dead code for an old
        release: it is what any plugin without format_options gets,
        on every supported version.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            bool: True when the format is JSON.
        """
        transform_data = configuration.get("transformData", "json")
        if isinstance(transform_data, bool):
            return not transform_data
        return str(transform_data).strip().lower() == "json"

    # ── Mapping helpers ──────────────────────────────────────────────

    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> List:
        """Look up a subtype's field list, ignoring case.

        Args:
            mappings (Dict): Subtype to field-list mapping for one data
                type.
            subtype (str): Subtype to look up.

        Returns:
            List: Field names to keep. An empty list means keep them all.
        """
        if not mappings or not subtype:
            return []
        lowered = {str(k).lower(): v for k, v in mappings.items()}
        return lowered.get(str(subtype).lower(), [])

    @staticmethod
    def get_field_value_from_data(
        data: Dict, field: str
    ) -> Tuple[Any, bool]:
        """Read a field out of a record, following dot paths.

        Some Netskope records nest values, for example
        host_info.hostname. This walks the path one step at a time and
        never raises if a step is missing.

        Args:
            data (Dict): Record to read from.
            field (str): Field name, or a dot-separated path.

        Returns:
            Tuple[Any, bool]: The value and whether it was found.
        """
        if not isinstance(data, dict) or not field:
            return None, False
        if field in data:
            return data[field], True
        current = data
        for part in str(field).split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None, False
        return current, True

    def map_json_data(self, mappings: List, data: Dict) -> Dict:
        """Keep only the fields the mapping lists.

        An empty mapping list means keep everything, which is what the
        shipped mapping file does for every subtype. An admin who edits
        the mapping under Settings > Log Shipper gets that honoured here.

        Args:
            mappings (List): Field names to keep.
            data (Dict): Record to filter.

        Returns:
            Dict: The filtered record, or the record unchanged.
        """
        if not mappings or not data:
            return data

        mapped_dict = {}
        for field in mappings:
            value, found = self.get_field_value_from_data(data, field)
            if found:
                mapped_dict[field] = value
        return mapped_dict

    def _parsed_mappings(self) -> Dict:
        """Return the mapping document, whichever shape it arrives in.

        Cloud Exchange hands the mapping over differently depending on
        where the plugin is called from: validate() receives the saved
        profile, a dict holding the document as a JSON string under
        'jsonData', while transform() receives the document already
        parsed. Both shapes are accepted here so neither call site has
        to care.

        Returns:
            Dict: The mapping document, or an empty dict if there is
                none or it cannot be read.
        """
        mappings = self.mappings or {}
        if not isinstance(mappings, dict):
            return {}

        # Already the document itself - the shape transform() gets.
        if "taxonomy" in mappings:
            return mappings

        raw = mappings.get("jsonData")
        if not raw:
            return {}
        if isinstance(raw, dict):
            return raw
        try:
            parsed = json.loads(raw)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not read the mapping."
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Check the mapping under Settings > Log Shipper."
                ),
            )
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _get_json_mappings(self, data_type: str) -> Dict:
        """Read the subtype mapping for one data type.

        Args:
            data_type (str): "alerts", "events" or "webtx".

        Returns:
            Dict: Subtype to field-list mapping. Empty if unavailable,
                which means every field is sent.
        """
        return (
            self._parsed_mappings()
            .get("taxonomy", {})
            .get("json", {})
            .get(data_type, {})
        )

    # ── Field-name and record helpers ────────────────────────────────

    @classmethod
    def _normalize_field_name(cls, name: str) -> str:
        """Turn a record field name into a Snowflake column name.

        Every character that cannot appear in an unquoted Snowflake
        column name becomes an underscore, then the whole name is
        uppercased. So cs-method becomes CS_METHOD, and a customer can
        create a plain column named CS_METHOD without any quoting.

        If the result is a Snowflake reserved word, a trailing
        underscore is added: group becomes GROUP_.

        Args:
            name (str): Raw field name.

        Returns:
            str: Column name to match against the table.
        """
        normalized = cls.NORMALIZE_RE.sub("_", str(name)).upper()
        if normalized in SNOWFLAKE_RESERVED_KEYWORDS:
            normalized += "_"
        return normalized

    @classmethod
    def _flatten_record(cls, obj: Dict, prefix: str = "") -> Dict:
        """Flatten nested objects into dot-path keys.

        {"host_info": {"hostname": "x"}} becomes
        {"host_info.hostname": "x"}.

        Lists are left alone - a list stays a single value, even if it
        holds objects. An empty nested object adds no keys, because
        there is no value to attach a path to.

        Args:
            obj (Dict): Record to flatten.
            prefix (str): Path built so far, used when recursing.

        Returns:
            Dict: The flattened record.
        """
        flat = {}
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                flat.update(cls._flatten_record(value, path))
            else:
                flat[path] = value
        return flat

    @staticmethod
    def _strip_envelope_keys(obj: Dict) -> Dict:
        """Drop record fields that clash with a column the plugin fills.

        Only 'Separate Fields' needs this. There, a record field named
        subtype would normalize to the same column as the plugin's own
        SUBTYPE, and one would overwrite the other. Dropping the
        record's copy keeps the plugin's value, which is the one the
        column is named for.

        'Combined' does not use it: the record goes inside a VARIANT,
        where a field named subtype is nested one level below the
        SUBTYPE column and cannot collide with it.

        Call this after reading EVENT_TIME and SUBTYPE from the record,
        not before - one of the keys it drops is event_time.

        Args:
            obj (Dict): Record to clean up.

        Returns:
            Dict: A copy without the clashing keys.
        """
        return {
            k: v
            for k, v in obj.items()
            if str(k).upper() not in ENVELOPE_COLUMN_NAMES
        }

    def _extract_event_time(self, record: Dict) -> Optional[str]:
        """Read the event time out of a record.

        Checks the known timestamp fields in order and uses the first one
        holding a number. Returns None if none of them do, and the
        caller falls back to the current time.

        Args:
            record (Dict): Record to read from.

        Returns:
            Optional[str]: ISO 8601 UTC timestamp, or None.
        """
        for field in TIMESTAMP_FIELDS:
            value = record.get(field)
            if value in (None, "", False):
                continue
            try:
                return datetime.fromtimestamp(
                    float(value), tz=timezone.utc
                ).strftime(ISO_TIMESTAMP_FORMAT)
            except (TypeError, ValueError, OverflowError, OSError):
                continue
        return None

    def _resolve_subtype(
        self, record: Dict, data_type: str, subtype: str
    ) -> str:
        """Work out the subtype for a record.

        The record's own field wins when it has one, because the record
        is the better source for what it actually is. Alerts carry
        alert_type and events carry event_type. WebTx has no such field,
        so it always uses the subtype Cloud Exchange passed in.

        Args:
            record (Dict): Record to read from.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype Cloud Exchange passed in.

        Returns:
            str: The subtype to write.
        """
        field = SUBTYPE_SOURCE_FIELD.get(data_type)
        if field:
            value = record.get(field)
            if value:
                return str(value)
        return subtype

    def _get_source_configuration_name(self) -> str:
        """Read the name that fills the SOURCE_CONFIGURATION_NAME column.

        This is the Cloud Exchange **source configuration name** - the
        name of the plugin configuration that pulled these logs and
        handed them to this Log Shipper - read straight from
        `self.source`.

        For WebTx that is the Netskope Log Streaming plugin (AWS or
        Azure), which is both the tenant and the source. For Alerts and
        Events it is the CLS Netskope plugin configuration, which is
        distinct from the Netskope provider ("tenant") it reads from - so
        two CLS Netskope configurations reading one provider give two
        different values here, which the shared provider/tenant name
        could not.

        Best effort - returns an empty string rather than raising, since
        a missing name must never stop a push. The column is then left
        out of the row rather than written empty.

        Returns:
            str: Source configuration name, or an empty string.
        """
        try:
            return str(self.source or "")
        except Exception:
            return ""

    @staticmethod
    def _iso_now() -> str:
        """Return the current UTC time as an ISO 8601 string.

        Returns:
            str: Current time, for example 2026-10-01T12:00:00.000000Z.
        """
        return datetime.now(timezone.utc).strftime(ISO_TIMESTAMP_FORMAT)

    # ── Table and schema helpers ─────────────────────────────────────

    @staticmethod
    def _resolve_table_name(configuration: Dict, data_type: str) -> str:
        """Find the table a data type should be written to.

        In single_table mode every data type shares one table. In
        per_data_type mode each has its own.

        Args:
            configuration (Dict): Plugin configuration.
            data_type (str): "alerts", "events" or "webtx".

        Returns:
            str: Table name, or an empty string if none is configured.
        """
        ingestion_mode = str(
            configuration.get("ingestion_mode", INGESTION_MODE_SINGLE_TABLE)
        ).strip()
        if ingestion_mode == INGESTION_MODE_SINGLE_TABLE:
            return str(configuration.get("table_name", "")).strip()
        field = PER_DATA_TYPE_TABLE_FIELD.get(data_type)
        if not field:
            return ""
        return str(configuration.get(field, "")).strip()

    @staticmethod
    def _detect_column_mode(columns_upper) -> str:
        """Decide the Column Mode from the table's own columns.

        There is no Column Mode configuration field. The table's shape
        is the choice: a table with a RAW_DATA column is written in
        'Combined' mode, where the whole record goes into that one
        VARIANT column; any other table is written in 'Separate Fields'
        mode, where record fields fill the table's own columns.

        RAW_DATA is therefore a reserved column name for this plugin -
        its presence alone selects Combined mode, so a Separate Fields
        table must never have a column called RAW_DATA. This is called
        out in the plugin guide and TABLE_SETUP.md.

        The same cached column list that builds the rows is what the
        mode is read from, so the mode never disagrees with the columns
        and nothing extra is fetched to determine it.

        Args:
            columns_upper: Uppercased column names, as a set or as the
                keys of a {name: type} dict.

        Returns:
            str: COLUMN_MODE_COMBINED or COLUMN_MODE_SEPARATE_FIELDS.
        """
        if RAW_DATA_COLUMN_NAME in columns_upper:
            return COLUMN_MODE_COMBINED
        return COLUMN_MODE_SEPARATE_FIELDS

    def _introspected_columns(
        self, table_name: str
    ) -> Optional[Dict[str, str]]:
        """Read a table's cached column list.

        The list is written by validate() and reused until the user
        saves the configuration again.

        Args:
            table_name (str): Target table.

        Returns:
            Optional[Dict[str, str]]: Column name to data type, or None
                when nothing is cached for this table. None and an empty
                dict mean different things: None means validate() has
                not run here, which the caller must treat as an error
                rather than as a table with no columns.
        """
        if not self.storage:
            return None
        cache_key = self.schema_helper.cache_key(
            self.configuration, table_name
        )
        cache = self.storage.get(SCHEMA_CACHE_STORAGE_KEY) or {}
        return cache.get(cache_key)

    def _cache_introspected_columns(
        self, table_name: str, columns: Dict[str, str]
    ) -> None:
        """Add one table's column list to the cache in storage.

        Merges rather than replaces, so caching one table never drops
        another. validate() still replaces the whole cache, which is
        what makes a removed column stop being remembered.

        Args:
            table_name (str): Target table.
            columns (Dict[str, str]): Column name to data type.
        """
        if self.storage is None:
            return
        cache_key = self.schema_helper.cache_key(
            self.configuration, table_name
        )
        cache = self.storage.get(SCHEMA_CACHE_STORAGE_KEY) or {}
        cache[cache_key] = columns
        self.storage[SCHEMA_CACHE_STORAGE_KEY] = cache

    def _require_introspected_columns(
        self,
        table_name: str,
        data_type: str,
        subtype: str,
    ) -> Dict[str, str]:
        """Return a table's columns, reading them from Snowflake if the
        cache does not have them.

        validate() fills the cache when the configuration is saved, and
        storage persists across Cloud Exchange restarts, so the cache is
        normally present. As a safety net, if it is ever missing, read
        the columns now and cache them rather than failing the batch, so
        the plugin recovers on its own.

        If that read also fails, there is no way to carry on: the column
        list is what decides the Column Mode (RAW_DATA present or not)
        and, in 'Separate Fields' mode, which columns each record fills.
        Without it the plugin cannot know what shape of row to build, so
        it raises. A transform that raises is logged and the batch is
        dropped with no retry, so the fix is to save the plugin
        configuration again, which reads the columns back into storage.

        Args:
            table_name (str): Target table.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".

        Returns:
            Dict[str, str]: Column name to data type.

        Raises:
            SnowflakePluginException: If the columns cannot be read, or
                the table is not there.
        """
        columns = self._introspected_columns(table_name)
        if columns is not None:
            return columns

        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] The columns"
            f" of table '{table_name}' are not cached. Reading them"
            " from Snowflake now."
        )
        try:
            columns = self.schema_helper.introspect_columns(
                self.configuration,
                table_name=table_name,
                storage=self.storage,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=False,
            )
        except SnowflakePluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Could not read the columns of table '{table_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" {err_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Check network access to Snowflake, then save the"
                    " plugin configuration again."
                ),
            )
            raise SnowflakePluginException(err_msg)

        if not columns:
            err_msg = (
                f"Table '{table_name}' was not found, or the role behind"
                " these credentials cannot see it."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" {err_msg}"
                ),
                resolution=(
                    "Create the table in Snowflake and grant the role"
                    " INSERT on it, then save the plugin configuration"
                    " again."
                ),
            )
            raise SnowflakePluginException(err_msg)

        self._cache_introspected_columns(table_name, columns)
        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Read"
            f" {len(columns)} column(s) from table '{table_name}' and"
            " cached them."
        )
        return columns

    # ── Transform ────────────────────────────────────────────────────

    def transform(
        self, raw_data: List, data_type: str, subtype: str
    ) -> List[Dict]:
        """Turn raw Netskope records into rows for Snowflake.

        In per_data_type mode, a data type with no table name configured
        is not ingested, so the whole batch is skipped. Otherwise the
        target table's columns are read and the Column Mode is decided
        from them - a RAW_DATA column means Combined, anything else means
        Separate Fields - then rows are built in that shape.

        Args:
            raw_data (List): Records from Netskope.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".

        Returns:
            List[Dict]: Rows ready to push. May be empty.
        """
        if not raw_data:
            return []

        configuration = self.configuration or {}
        ingestion_mode = str(
            configuration.get("ingestion_mode", INGESTION_MODE_SINGLE_TABLE)
        ).strip()
        table_name = self._resolve_table_name(configuration, data_type)

        if (
            ingestion_mode == INGESTION_MODE_PER_DATA_TYPE
            and not table_name
        ):
            # No table name configured for this data type is how
            # 'Per Data Type' mode says "do not ingest this type".
            self.logger.info(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" Skipping these records because no table name is"
                    f" configured for '{data_type}'."
                )
            )
            return []

        columns_upper = {
            name.upper()
            for name in self._require_introspected_columns(
                table_name, data_type, subtype
            )
        }
        if (
            self._detect_column_mode(columns_upper)
            == COLUMN_MODE_SEPARATE_FIELDS
        ):
            return self._transform_separate_fields(
                raw_data, data_type, subtype, table_name, columns_upper
            )
        return self._transform_combined(
            raw_data, data_type, subtype, table_name, columns_upper
        )

    def _prepare_record(
        self, record: Any, subtype_mapping: List
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Get one record ready to be turned into a row.

        Returns both the original record and the filtered copy. The
        original is what event time and subtype are read from, so a
        narrowed mapping can never hide them.

        Args:
            record (Any): One record from Netskope.
            subtype_mapping (List): Field names to keep.

        Returns:
            Tuple[Optional[Dict], Optional[Dict]]: Original record and
                filtered record, or (None, None) if it cannot be used.
        """
        if isinstance(record, dict):
            raw_obj = record
        elif isinstance(record, str):
            # WebTx is expected to arrive as a dict. This branch is
            # insurance in case a raw line ever shows up instead.
            raw_obj = {RAW_LINE_FIELD_NAME: record}
        else:
            return None, None

        try:
            json.dumps(raw_obj, default=str)
        except (TypeError, ValueError) as exp:
            raise MappingValidationError(
                f"Record could not be serialized to JSON: {exp}"
            )

        filtered = self.map_json_data(subtype_mapping, raw_obj)
        if not isinstance(filtered, dict):
            return None, None
        return raw_obj, filtered

    def _transform_combined(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        table_name: str,
        columns_upper: set,
    ) -> List[Dict]:
        """Build envelope rows that hold the whole record in RAW_DATA.

        EVENT_TIME, DATA_TYPE, SUBTYPE and RAW_DATA are always written -
        validate() already checked the table has them. INGESTION_TIME and
        SOURCE_CONFIGURATION_NAME are written only when the table has
        those columns. A column the table does not have is left out of
        the row rather than written as null.

        Args:
            raw_data (List): Records from Netskope.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".
            table_name (str): Target table, resolved by the caller.
            columns_upper (set): Uppercased column names of the table,
                read once by the caller and shared with the mode check.

        Returns:
            List[Dict]: Rows ready to push.
        """
        has_ingestion_time = "INGESTION_TIME" in columns_upper
        has_source_config = SOURCE_CONFIG_NAME_COLUMN in columns_upper
        source_config_name = self._get_source_configuration_name()
        subtype_mapping = self.get_subtype_mapping(
            self._get_json_mappings(data_type), subtype
        )

        transformed = []
        skipped = 0

        for record in raw_data:
            try:
                raw_obj, filtered = self._prepare_record(
                    record, subtype_mapping
                )
            except MappingValidationError:
                skipped += 1
                continue
            if raw_obj is None:
                skipped += 1
                continue

            now_iso = self._iso_now()
            event_time = self._extract_event_time(raw_obj) or now_iso
            resolved_subtype = self._resolve_subtype(
                raw_obj, data_type, subtype
            )

            # RAW_DATA holds the record as it arrived. A field named
            # data_type or subtype sits inside the VARIANT, so it
            # cannot collide with the DATA_TYPE or SUBTYPE column
            # beside it - both values are kept, each where it belongs.
            row = {
                "EVENT_TIME": event_time,
                "DATA_TYPE": data_type,
                "SUBTYPE": resolved_subtype,
                RAW_DATA_COLUMN_NAME: filtered,
            }
            if has_ingestion_time:
                row["INGESTION_TIME"] = now_iso
            if has_source_config and source_config_name:
                # Leave the key out when the source configuration name
                # could not be read, rather than writing an empty string.
                row[SOURCE_CONFIG_NAME_COLUMN] = source_config_name
            transformed.append(row)

        if skipped:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                    f" {skipped} log(s) that could not be read."
                )
            )
        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Prepared"
            f" {len(transformed)} row(s) for table '{table_name}'."
        )
        return transformed

    def _transform_separate_fields(
        self,
        raw_data: List,
        data_type: str,
        subtype: str,
        table_name: str,
        columns_upper: set,
    ) -> List[Dict]:
        """Build rows that fill the table's own columns.

        Each record field is flattened, renamed to match Snowflake's
        column naming, and written to the column with that name. Fields
        with no matching column go into EXTRA_FIELDS when the table has
        that column, and are dropped otherwise.

        Dropped fields are not logged. At high volume that would fill
        the logging page for something that is normal in this mode.

        Args:
            raw_data (List): Records from Netskope.
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".
            table_name (str): Target table, resolved by the caller.
            columns_upper (set): Uppercased column names of the table,
                read once by the caller and shared with the mode check.

        Returns:
            List[Dict]: Rows ready to push.
        """
        has_extra_fields = (
            EXTRA_FIELDS_COLUMN_NAME.upper() in columns_upper
        )
        source_config_name = self._get_source_configuration_name()
        subtype_mapping = self.get_subtype_mapping(
            self._get_json_mappings(data_type), subtype
        )
        transformed = []
        skipped = 0
        unmatched = 0

        for record in raw_data:
            try:
                raw_obj, filtered = self._prepare_record(
                    record, subtype_mapping
                )
            except MappingValidationError:
                skipped += 1
                continue
            if raw_obj is None:
                skipped += 1
                continue

            now_iso = self._iso_now()
            flattened = self._flatten_record(filtered)
            # The record's own fields, kept apart from the plugin's
            # values below. EXTRA_FIELDS is built from these alone -
            # see where it is filled.
            record_fields = self._strip_envelope_keys(flattened)
            pseudo_record = dict(record_fields)
            pseudo_record.update(
                {
                    "INGESTION_TIME": now_iso,
                    "EVENT_TIME": self._extract_event_time(raw_obj)
                    or now_iso,
                    "DATA_TYPE": data_type,
                    "SUBTYPE": self._resolve_subtype(
                        raw_obj, data_type, subtype
                    ),
                }
            )
            if source_config_name:
                # Only offer SOURCE_CONFIGURATION_NAME when there is one,
                # so an empty value is never written to the column.
                pseudo_record[SOURCE_CONFIG_NAME_COLUMN] = source_config_name

            row = {}
            consumed_keys = set()
            for key, value in pseudo_record.items():
                normalized = self._normalize_field_name(key)
                if normalized == EXTRA_FIELDS_COLUMN_NAME.upper():
                    # A field really named extra_fields is never treated
                    # as a direct column match. It goes into the
                    # catch-all like anything else, so the column keeps
                    # one clear meaning.
                    continue
                if normalized not in columns_upper:
                    continue
                consumed_keys.add(key)
                if value not in (None, ""):
                    # Leave the key out when there is no value rather
                    # than sending an explicit null.
                    row[normalized] = value

            if has_extra_fields:
                # Built from the record's own fields only. EXTRA_FIELDS
                # answers one question - what did this record hold that
                # the table had nowhere to put - so the plugin's own
                # EVENT_TIME, DATA_TYPE, SUBTYPE, INGESTION_TIME and
                # SOURCE_CONFIGURATION_NAME stay out of it. A table
                # without those columns simply does not get those values,
                # which is what Combined mode does too.
                #
                # Keys here are the flattened dot paths, so a nested
                # field arrives as "host_info.os", not as a nested
                # object.
                extra_fields = {
                    k: v
                    for k, v in record_fields.items()
                    if k not in consumed_keys
                }
                if extra_fields:
                    row[EXTRA_FIELDS_COLUMN_NAME] = extra_fields

            if row:
                transformed.append(row)
            else:
                # Parsed fine, but no field matched a column. That is a
                # table-design question, not a bad record, so it is
                # counted and logged on its own.
                unmatched += 1

        if skipped:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                    f" {skipped} log(s) that could not be read."
                )
            )
        if unmatched and not transformed:
            # Nothing at all matched. That is a table-shape problem, not
            # sparse data, and push() would otherwise just say there was
            # nothing to send.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" Dropped all {unmatched} log(s). No field"
                    f" matched any column in '{table_name}', so nothing"
                    " will be sent."
                ),
                resolution=(
                    "Check that the table columns are named after the"
                    " fields you want stored, or add an EXTRA_FIELDS"
                    " VARIANT column to catch everything else. Save the"
                    " configuration again afterwards."
                ),
            )
        elif unmatched:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] Dropped"
                f" {unmatched} log(s) because no field matched a"
                f" column in '{table_name}'."
            )
        self.logger.debug(
            f"{self.log_prefix}: [{data_type}][{subtype}] Prepared"
            f" {len(transformed)} row(s) for table '{table_name}'."
        )
        return transformed

    # ── Push ─────────────────────────────────────────────────────────

    @staticmethod
    def chunk_size() -> int:
        """Tell Cloud Exchange how many records to hand over at a time.

        This is only a hint about the hand-over size. It has nothing to
        do with how push() batches: push() splits by payload size
        alone, never by row count, because size is the only limit
        Snowflake has.

        Static to match PluginBase. As an instance method it would
        override a staticmethod, and SnowflakePlugin.chunk_size() -
        called on the class rather than an object - would raise
        TypeError.

        Returns:
            int: Records per transform/push cycle.
        """
        return CHUNK_SIZE

    def push(
        self, transformed_data: List[Dict], data_type: str, subtype: str
    ) -> PushResult:
        """Send rows to Snowflake.

        When the whole batch fits in one gzipped request it is sent as a
        single call. Otherwise the rows are split into size-bounded
        batches and sent one after another.

        If a batch in the size-chunked path fails, the rows that already
        landed are removed from transformed_data in place before the
        error is raised. Cloud Exchange retries with the same
        transformed_data list, so trimming the already-sent rows means
        the retry re-sends only the un-sent remainder, not the batches
        that already succeeded. The failed batch is left in the list, so
        it can arrive twice, but the earlier successful batches are not
        duplicated. (The single gzip request sends nothing partial, so a
        failure there retries the whole request.)

        Raising is still required: Cloud Exchange retries a push only
        when it raises and ignores the returned success flag, so
        returning success would mark the un-sent rows as delivered and
        lose them.

        Args:
            transformed_data (List[Dict]): Rows from transform().
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".

        Returns:
            PushResult: Success, and a summary of what was sent.

        Raises:
            SnowflakePluginException: If any batch failed.
        """
        configuration = self.configuration or {}
        total = len(transformed_data)

        if not transformed_data:
            log_msg = (
                f"[{data_type}][{subtype}] No records to send to"
                f" {PLATFORM_NAME}."
            )
            self.logger.info(message=f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)

        table_name = self._resolve_table_name(configuration, data_type)
        if not table_name:
            err_msg = (
                f"[{data_type}][{subtype}] No table name is configured"
                f" for data type '{data_type}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Set the table name for this data type in the"
                    " configuration and save it again."
                ),
            )
            raise SnowflakePluginException(err_msg)

        successful = 0
        page = 0

        compressed_body = try_compress_whole_batch(
            transformed_data, max_bytes=MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES
        )
        if compressed_body is not None:
            # The whole batch fits gzipped in one request. Send it as
            # a single batch instead of going through split_into_size().
            page = 1
            self._send_batch(
                data_type=data_type,
                subtype=subtype,
                table_name=table_name,
                page=page,
                row_count=total,
                successful=successful,
                append_rows_kwargs={
                    "configuration": configuration,
                    "rows": transformed_data,
                    "table_name": table_name,
                    "body": compressed_body,
                    "content_encoding": GZIP_CONTENT_ENCODING,
                    "storage": self.storage,
                    "verify": self.ssl_validation,
                    "proxies": self.proxy,
                    "logger_msg": (
                        f"sending {total} '{data_type}/{subtype}'"
                        f" log(s) in batch {page} to table"
                        f" '{table_name}' (gzip compressed)"
                    ),
                },
            )
            successful = total
        else:
            # Does not fit gzipped in one request. Fall back to the
            # uncompressed, size-chunked path.
            try:
                for chunk, chunk_lines in split_into_size(
                    transformed_data,
                    max_bytes=MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
                ):
                    page += 1
                    self._send_batch(
                        data_type=data_type,
                        subtype=subtype,
                        table_name=table_name,
                        page=page,
                        row_count=len(chunk),
                        successful=successful,
                        append_rows_kwargs={
                            "configuration": configuration,
                            "rows": chunk,
                            "table_name": table_name,
                            "lines": chunk_lines,
                            "storage": self.storage,
                            "verify": self.ssl_validation,
                            "proxies": self.proxy,
                            "logger_msg": (
                                f"sending {len(chunk)}"
                                f" '{data_type}/{subtype}' log(s) in"
                                f" batch {page} to table '{table_name}'"
                            ),
                        },
                    )
                    successful += len(chunk)
            except Exception:
                # A batch failed partway through. Remove the rows that
                # already landed so Cloud Exchange's retry re-sends only
                # the un-sent remainder instead of every batch. Mutated
                # in place because Cloud Exchange retries with the same
                # transformed_data list object (the approach the Syslog
                # CLS plugin uses).
                del transformed_data[:successful]
                raise

        log_msg = (
            f"[{data_type}][{subtype}] Sent {successful} of {total}"
            f" log(s) to table '{table_name}' on {PLATFORM_NAME}."
        )
        self.logger.info(message=f"{self.log_prefix}: {log_msg}")
        return PushResult(success=True, message=log_msg)

    def _send_batch(
        self,
        data_type: str,
        subtype: str,
        table_name: str,
        page: int,
        row_count: int,
        successful: int,
        append_rows_kwargs: Dict,
    ) -> None:
        """Send one batch and apply push()'s stop-on-failure logging.

        Shared by both the single gzip-compressed batch and the
        uncompressed, size-chunked batches push() can send - only the
        kwargs passed to append_rows() differ between the two.

        Args:
            data_type (str): "alerts", "events" or "webtx".
            subtype (str): Subtype, for example "dlp" or "page".
            table_name (str): Target table.
            page (int): Which batch this is, for the log lines.
            row_count (int): Rows in this batch, for the log lines.
            successful (int): Rows already sent before this batch.
            append_rows_kwargs (Dict): Passed straight to
                self.streaming_client.append_rows().

        Raises:
            SnowflakePluginException: If the batch failed. The push
                stops there, same as every batch failure today.
        """
        try:
            self.streaming_client.append_rows(**append_rows_kwargs)
        except SnowflakePluginException:
            # Already logged where it was raised. Add which batch it
            # was, then stop the push.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" Could not send {row_count} log(s) in batch"
                    f" {page} to table '{table_name}'. {successful}"
                    " log(s) were sent before this. Stopping this"
                    " push."
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Check the error above. Cloud Exchange retries"
                    " this push with the records that have not been"
                    " sent yet."
                ),
            )
            raise
        except Exception as err:
            err_msg = (
                f"[{data_type}][{subtype}] Unexpected error while"
                f" sending {row_count} log(s) in batch {page} to"
                f" table '{table_name}'. {successful} log(s) were"
                " sent before this. Stopping this push."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
                resolution=(
                    "Check the logs for the full error. Cloud"
                    " Exchange retries this push with the records that"
                    " have not been sent yet."
                ),
            )
            raise SnowflakePluginException(err_msg) from err

        self.logger.info(
            message=(
                f"{self.log_prefix}: [{data_type}][{subtype}] Sent"
                f" {row_count} log(s) in batch {page} to table"
                f" '{table_name}'."
            )
        )

    # ── Validation ───────────────────────────────────────────────────

    def _validation_error(
        self, message: str, resolution: str = None
    ) -> ValidationResult:
        """Log a validation failure and build the result.

        The message has no log prefix - Cloud Exchange adds its own when
        it shows the message in the UI.

        Args:
            message (str): What is wrong.
            resolution (str): What the user should do about it.

        Returns:
            ValidationResult: A failed result.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {message}"
            ),
            resolution=resolution or "",
        )
        return ValidationResult(success=False, message=message)

    def validate_mappings(self) -> ValidationResult:
        """Check that the mapping file can be read and has the right shape.

        The shipped mapping keeps every field, so by default nothing is
        filtered out. The check still runs, because an admin can edit the
        mapping under Settings > Log Shipper.

        Returns:
            ValidationResult: Whether the mapping is usable.
        """
        parsed = self._parsed_mappings()
        if not parsed:
            return self._validation_error(
                "The Snowflake mapping is empty or could not be read.",
                resolution=(
                    "Open Settings > Log Shipper and restore the default"
                    " Snowflake mapping."
                ),
            )
        if not self.snowflake_validator.validate_mappings(parsed):
            return self._validation_error(
                "The Snowflake mapping does not have the expected"
                " structure.",
                resolution=(
                    "Open Settings > Log Shipper and restore the default"
                    " Snowflake mapping."
                ),
            )
        return ValidationResult(
            success=True, message="Mapping validation successful."
        )

    def _validate_token(self, params: Dict) -> Optional[ValidationResult]:
        """Check the Programmatic Access Token is present.

        The token is never stripped - whitespace could be part of it -
        and never logged.

        Args:
            params (Dict): Configuration read by _get_config_params().

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        if not params["programmatic_access_token"]:
            return self._validation_error(
                EMPTY_ERROR_MESSAGE.format("Programmatic Access Token"),
                resolution=(
                    "Generate a token in Snowflake and paste it into the"
                    " configuration. See TABLE_SETUP.md for the SQL."
                ),
            )
        self.logger.debug(
            f"{self.log_prefix}: Validation successful for"
            " 'Programmatic Access Token'."
        )
        return None

    def _validate_identifier(
        self, field_name: str, value: str
    ) -> Optional[ValidationResult]:
        """Check that a name can be used as a Snowflake object name.

        Case is not normalized or restricted here. The name is matched
        against Snowflake case-sensitively, quoted, everywhere it is
        used (SHOW COLUMNS and the Snowpipe Streaming URL alike) - so
        whatever case is typed here must be the exact case Snowflake
        stores the object under, whether that is upper case (an
        ordinary unquoted CREATE TABLE) or mixed/lower case (a quoted
        CREATE TABLE). A mismatch is reported as "not found" by
        validate(), not rejected here.

        Args:
            field_name (str): Label shown to the user.
            value (str): Name to check.

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        if not self.snowflake_validator.is_valid_identifier(value):
            name = str(value or "").strip()
            if len(name) > SNOWFLAKE_IDENTIFIER_MAX_LENGTH:
                return self._validation_error(
                    f"'{field_name}' is {len(name)} characters."
                    f" Snowflake allows at most"
                    f" {SNOWFLAKE_IDENTIFIER_MAX_LENGTH}.",
                    resolution=(
                        f"Shorten '{field_name}' to"
                        f" {SNOWFLAKE_IDENTIFIER_MAX_LENGTH} characters"
                        " or fewer."
                    ),
                )
            return self._validation_error(
                f"'{field_name}' is not a valid Snowflake name. Use"
                " letters, digits, underscore and dollar only,"
                " starting with a letter or underscore.",
                resolution=(
                    f"Correct '{field_name}' in the configuration"
                    " parameters."
                ),
            )
        self.logger.debug(
            f"{self.log_prefix}: Validation successful for"
            f" '{field_name}'."
        )
        return None

    def _validate_ingestion_mode(
        self, params: Dict
    ) -> Optional[ValidationResult]:
        """Check the table-name fields the chosen mode needs.

        single_table needs the one table name. per_data_type is driven
        by which of the three table-name fields are filled in: each one
        filled selects its data type, a blank one means that type is not
        ingested, and at least one must be filled. Every filled name is
        checked as a Snowflake identifier.

        Args:
            params (Dict): Configuration read by _get_config_params().

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        if params["ingestion_mode"] == INGESTION_MODE_SINGLE_TABLE:
            if result := self._validate_configuration_parameters(
                field_name="Table Name",
                field_value=params["table_name"],
                field_type=str,
                resolution=(
                    "Enter the name of a table that already exists in"
                    " Snowflake."
                ),
            ):
                return result
            return self._validate_identifier(
                "Table Name", params["table_name"]
            )

        # Per Data Type: ingestion is decided by which table-name fields
        # are filled in. A blank field means that data type is simply not
        # ingested, so at least one must be provided.
        provided = [
            (
                DATA_TYPE_LABELS.get(data_type, data_type),
                params[PER_DATA_TYPE_TABLE_FIELD[data_type]],
            )
            for data_type in SUPPORTED_DATA_TYPES
            if params[PER_DATA_TYPE_TABLE_FIELD[data_type]]
        ]
        if not provided:
            return self._validation_error(
                "At least one table name is required when 'Ingestion"
                " Mode' is set to 'Per Data Type'.",
                resolution=(
                    "Enter a table name for at least one of Alerts,"
                    " Events or WebTx. A data type left blank is not"
                    " ingested."
                ),
            )
        for label, table_name in provided:
            if result := self._validate_identifier(
                f"{label} Table Name", table_name
            ):
                return result
        return None

    def _tables_to_validate(self, params: Dict) -> List[Tuple[str, str]]:
        """List the tables this configuration writes to.

        Args:
            params (Dict): Configuration read by _get_config_params().

        Returns:
            List[Tuple[str, str]]: Label and table name for each table.
        """
        if params["ingestion_mode"] == INGESTION_MODE_SINGLE_TABLE:
            return [("all", params["table_name"])]
        return [
            (
                DATA_TYPE_LABELS.get(data_type, data_type),
                params[PER_DATA_TYPE_TABLE_FIELD[data_type]],
            )
            for data_type in SUPPORTED_DATA_TYPES
            if params[PER_DATA_TYPE_TABLE_FIELD[data_type]]
        ]

    def _check_combined_columns(
        self, table_name: str, columns_upper: Dict[str, str]
    ) -> Optional[ValidationResult]:
        """Check a combined-mode table has the right columns and types.

        Args:
            table_name (str): Target table.
            columns_upper (Dict[str, str]): Uppercased column name to
                Snowflake data type.

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        missing = sorted(
            set(MANDATORY_COMBINED_COLUMN_TYPES) - set(columns_upper)
        )
        if missing:
            return self._validation_error(
                f"Table '{table_name}' has a RAW_DATA column but is"
                f" missing required column(s) {', '.join(missing)}. A"
                " table with RAW_DATA is used in Combined mode, which"
                " needs EVENT_TIME, DATA_TYPE, SUBTYPE and RAW_DATA.",
                resolution=(
                    "Add the missing column(s) to the table in"
                    " Snowflake. To use the table in 'Separate Fields'"
                    " mode instead, remove its RAW_DATA column."
                ),
            )

        expected_types = {
            **MANDATORY_COMBINED_COLUMN_TYPES,
            **OPTIONAL_COMBINED_COLUMN_TYPES,
        }
        mismatches = [
            f"{column} (expected"
            f" {' or '.join(accepted)}, found"
            f" {columns_upper[column]})"
            for column, accepted in expected_types.items()
            if column in columns_upper
            and columns_upper[column] not in accepted
        ]
        if mismatches:
            return self._validation_error(
                f"Table '{table_name}' has column(s) with the wrong"
                f" type: {'; '.join(sorted(mismatches))}.",
                resolution=(
                    "Change the column type(s) in Snowflake to match,"
                    " then save this configuration again."
                ),
            )
        return None

    def _check_separate_fields_columns(
        self, table_name: str, columns_upper: Dict[str, str]
    ) -> Optional[ValidationResult]:
        """Check the table can actually hold record data.

        'Separate Fields' fills columns by matching record field names.
        Five columns are filled by the plugin itself. This mode is only
        chosen for a table without a RAW_DATA column (a table with one is
        read as 'Combined' instead), so if the only columns present are
        those five envelope columns, every record would be thrown away
        while rows kept landing - this fails instead.

        Args:
            table_name (str): Target table.
            columns_upper (Dict[str, str]): Uppercased column name to
                Snowflake data type.

        Returns:
            Optional[ValidationResult]: A failure, or None if it passed.
        """
        data_columns = set(columns_upper) - set(ENVELOPE_COLUMN_NAMES)
        if data_columns:
            return None

        return self._validation_error(
            f"Table '{table_name}' has no column the plugin can match a"
            " record field to. Every record would be dropped.",
            resolution=(
                "Add columns named after the fields you want stored, or"
                " an EXTRA_FIELDS VARIANT column to catch everything,"
                " or add a RAW_DATA VARIANT column to use Combined mode"
                " instead."
            ),
        )

    def _validate_connectivity(
        self, configuration: Dict, params: Dict
    ) -> ValidationResult:
        """Reach Snowflake and read every target table's columns.

        One SQL API call per table does three jobs: it proves the
        credentials work, it proves the table exists and the Role can
        see it, and it reads the column list the push path needs. A
        table that is missing or hidden comes back with zero rows.

        Args:
            configuration (Dict): Plugin configuration.
            params (Dict): Configuration read by _get_config_params().

        Returns:
            ValidationResult: Whether Snowflake is reachable and usable.
        """
        ingestion_mode = params["ingestion_mode"]
        introspected = {}

        try:
            self.streaming_client.resolve_hostname(
                configuration,
                storage=self.storage,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
            )

            for label, table_name in self._tables_to_validate(params):
                columns = self.schema_helper.introspect_columns(
                    configuration,
                    table_name=table_name,
                    storage=self.storage,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_validation=True,
                )
                if not columns:
                    return self._validation_error(
                        f"Table '{table_name}' was not found, or the"
                        " role behind these credentials cannot see it.",
                        resolution=(
                            "Create the table in Snowflake, check the"
                            " Database and Schema, and grant the role"
                            " INSERT on it."
                        ),
                    )

                columns_upper = {
                    name.upper(): dtype
                    for name, dtype in columns.items()
                }

                # The table's shape chooses the Column Mode: a RAW_DATA
                # column means Combined, anything else means Separate
                # Fields.
                column_mode = self._detect_column_mode(columns_upper)

                # Single Table shares one table across Alerts, Events and
                # WebTx, which rarely fits one Separate Fields layout, so
                # that pairing is not supported. A Single Table
                # configuration must point at a Combined (RAW_DATA) table.
                if (
                    ingestion_mode == INGESTION_MODE_SINGLE_TABLE
                    and column_mode == COLUMN_MODE_SEPARATE_FIELDS
                ):
                    return self._validation_error(
                        f"Table '{table_name}' has no RAW_DATA column, so"
                        " it would be used in 'Separate Fields' mode,"
                        " which is not supported with 'Single Table'"
                        " ingestion.",
                        resolution=(
                            "Add a RAW_DATA VARIANT column (and the other"
                            " Combined columns) to the table, or switch"
                            " to 'Per Data Type' ingestion so each data"
                            " type has its own table."
                        ),
                    )

                if column_mode == COLUMN_MODE_COMBINED:
                    if result := self._check_combined_columns(
                        table_name, columns_upper
                    ):
                        return result
                    has_ts = "INGESTION_TIME" in columns_upper
                    has_sc = SOURCE_CONFIG_NAME_COLUMN in columns_upper
                    extra_info = (
                        "mode: Combined,"
                        f" INGESTION_TIME: {'yes' if has_ts else 'no'},"
                        " SOURCE_CONFIGURATION_NAME:"
                        f" {'yes' if has_sc else 'no'}"
                    )
                else:
                    if result := self._check_separate_fields_columns(
                        table_name, columns_upper
                    ):
                        return result
                    has_extra = (
                        EXTRA_FIELDS_COLUMN_NAME in columns_upper
                    )
                    extra_info = (
                        "mode: Separate Fields, EXTRA_FIELDS catch-all:"
                        f" {'yes' if has_extra else 'no'}"
                    )

                cache_key = self.schema_helper.cache_key(
                    configuration, table_name
                )
                introspected[cache_key] = columns
                self.logger.debug(
                    f"{self.log_prefix}: Read {len(columns)} column(s)"
                    f" from table '{table_name}' ({label}) and saved"
                    f" them to storage. {extra_info}."
                )
        except SnowflakeAuthenticationError as err:
            return self._validation_error(
                str(err),
                resolution=(
                    "Check the Account URL and the credentials"
                    " in the configuration parameters, and the"
                    " privileges of the role behind them."
                ),
            )
        except (
            SnowflakeConfigurationError,
            SnowflakePluginException,
        ) as err:
            return self._validation_error(
                f"Could not reach Snowflake. {err}",
                resolution=(
                    "Check the configuration parameters and network"
                    " access from this Cloud Exchange node to Snowflake."
                ),
            )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" Unexpected error while reaching Snowflake. Error:"
                    f" {err}"
                ),
                details=traceback.format_exc(),
                resolution="Check logs for the full error.",
            )
            return ValidationResult(
                success=False,
                message=(
                    "Unexpected error while reaching Snowflake. Check"
                    " logs for more details."
                ),
            )

        # Replace the cache rather than merging into it, so a column the
        # user removed is forgotten instead of staying cached forever.
        if self.storage is not None:
            self.storage[SCHEMA_CACHE_STORAGE_KEY] = introspected

        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Check the whole configuration.

        Fields are checked in the order they appear in the manifest,
        and so on the form: Account URL, Programmatic Access Token,
        Database, Schema, Ingestion Mode. The format choice is checked
        first because the rest is pointless if the plugin is being asked
        for CEF. The mapping comes next, and Snowflake is contacted
        last, so a simple typo never costs a network round trip. The
        Column Mode is not a field - it is read from each target table's
        shape during the connectivity check.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            ValidationResult: Whether the configuration is usable.
        """
        params = self._get_config_params(configuration)

        # This plugin only sends JSON. Snowflake stores JSON natively in
        # a VARIANT column, so there is nothing CEF would add.
        if not self._is_transform_data_json(configuration):
            return self._validation_error(
                f"This plugin only sends JSON data to {PLATFORM_NAME}."
                " Select 'JSON' as the format to continue.",
                resolution=(
                    "Set the SIEM Mapping format to 'JSON' for this"
                    " plugin configuration."
                ),
            )

        if result := self._validate_configuration_parameters(
            field_name="Account URL",
            field_value=params["base_url"],
            field_type=str,
            resolution=(
                "Enter the Snowflake account URL, for example"
                " https://myorg-myaccount.snowflakecomputing.com."
            ),
        ):
            return result

        # Every request built from this value carries the customer's
        # token, so the host has to be a Snowflake one. Check it before
        # anything is sent.
        if not self.snowflake_validator.is_valid_base_url(
            params["base_url"]
        ):
            return self._validation_error(
                "'Account URL' is not a Snowflake account URL. It must"
                " be an https:// address ending in"
                " .snowflakecomputing.com, with no path, port or"
                " query.",
                resolution=(
                    "Enter the account URL as Snowflake shows it, for"
                    " example"
                    " https://myorg-myaccount.snowflakecomputing.com"
                    " or"
                    " https://xy12345.us-east-1.aws.snowflakecomputing.com."
                ),
            )
        self.logger.debug(
            f"{self.log_prefix}: Validation successful for"
            " 'Account URL'."
        )

        if result := self._validate_token(params):
            return result

        if result := self._validate_configuration_parameters(
            field_name="Database",
            field_value=params["database"],
            field_type=str,
            resolution="Enter the Snowflake database name.",
        ):
            return result
        if result := self._validate_identifier(
            "Database", params["database"]
        ):
            return result

        if result := self._validate_configuration_parameters(
            field_name="Schema",
            field_value=params["schema"],
            field_type=str,
            resolution="Enter the Snowflake schema name.",
        ):
            return result
        if result := self._validate_identifier("Schema", params["schema"]):
            return result

        if result := self._validate_configuration_parameters(
            field_name="Ingestion Mode",
            field_value=params["ingestion_mode"],
            field_type=str,
            allowed_values=list(ALL_INGESTION_MODES),
            resolution=(
                "Select either 'Single Table' or 'Per Data Type'."
            ),
        ):
            return result

        # Table names belong to Ingestion Mode, so they are checked with
        # it. There is no Column Mode field: the mode is read from each
        # table's shape during the connectivity check below, which is
        # also where 'Single Table' pointed at a Separate Fields table
        # (one with no RAW_DATA column) is rejected.
        if result := self._validate_ingestion_mode(params):
            return result

        mappings_result = self.validate_mappings()
        if not mappings_result.success:
            return mappings_result

        return self._validate_connectivity(configuration, params)
