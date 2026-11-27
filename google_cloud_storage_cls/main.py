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
Google Cloud Storage Plugin.
"""

import json
from tempfile import NamedTemporaryFile
import copy
from typing import Any, List, Optional

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.client import GCPStorageClient
from .utils.exceptions import GCPStorageException
from .utils.helper import (
    get_subtype_mapping,
    get_user_agent,
    log_and_raise,
    log_error,
    map_json_data,
    remove_local_file,
    serialize_records,
)
from .utils.validator import GCPStorageValidator


class GCPStoragePlugin(PluginBase):
    """The Google Cloud Storage plugin implementation class."""

    def __init__(self, name: Optional[str], *args: Any, **kwargs: Any) -> None:
        """Initialize the plugin.

        Args:
            name (Optional[str]): Configuration name.
            *args (Any): Positional arguments of PluginBase.
            **kwargs (Any): Keyword arguments of PluginBase.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get the plugin name and version from the manifest.

        Returns:
            tuple: (plugin name, plugin version).
        """
        try:
            manifest_json = GCPStoragePlugin.metadata
            return (
                manifest_json.get(CONST.MANIFEST_NAME_KEY, CONST.PLUGIN_NAME),
                manifest_json.get(
                    CONST.MANIFEST_VERSION_KEY, CONST.PLUGIN_VERSION
                ),
            )
        except Exception:
            log_error(
                self.logger,
                f"{CONST.MODULE_NAME} {CONST.PLUGIN_NAME}",
                "getting plugin details",
                "Ensure that the plugin manifest.json is valid.",
            )
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    def _get_client(self, configuration: dict) -> GCPStorageClient:
        """Create the Google Cloud Storage client.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            GCPStorageClient: The client.
        """
        return GCPStorageClient(
            configuration,
            self.logger,
            self.log_prefix,
            self.proxy,
            self.ssl_validation,
            get_user_agent(self.plugin_name, self.plugin_version),
        )

    def get_dynamic_fields(self) -> list:
        """Return the configuration fields that follow the Region Name.

        Returns:
            list: Custom Region (only when 'Custom Region' is selected as
                the Region Name) followed by the fields shown always.
        """
        configuration = getattr(self, "configuration", None) or {}
        fields = copy.deepcopy(CONST.COMMON_FIELDS)
        if configuration.get(CONST.LOCATION_KEY) == CONST.CUSTOM_LOCATION_VALUE:
            fields.insert(0, copy.deepcopy(CONST.CUSTOM_LOCATION_FIELD))
        return fields

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result (message without prefix).
        """
        validator = GCPStorageValidator(self.logger, self.log_prefix)
        if message := validator.validate_format(configuration):
            return ValidationResult(success=False, message=message)
        if (
            configuration.get("transformData", CONST.FORMAT_JSON)
            != CONST.FORMAT_JSON
        ):
            return ValidationResult(
                success=False, message=CONST.UNSUPPORTED_FORMAT_MESSAGE
            )
        if (result := self.validate_mappings()) and not result.success:
            return result
        try:
            self._get_client(configuration).verify_bucket()
        except GCPStorageException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception:
            message = log_error(
                self.logger,
                self.log_prefix,
                "verifying the Google Cloud Storage bucket",
                "Ensure that the Key File and the Bucket Name are valid. "
                "Check the logs for details.",
            )
            return ValidationResult(success=False, message=message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated configuration "
            "parameters."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _load_mappings(self) -> dict:
        """Return the parsed mapping, whichever way Core passes it.

        When the mapping is validated Core passes the mapping file as
        {"name": ..., "jsonData": "<json string>"}. While transforming it
        passes the already parsed content of "jsonData", i.e. the dict
        with the "taxonomy" key. Both are accepted here.

        Returns:
            dict: Parsed mapping.

        Raises:
            ValueError: When the mapping is not valid JSON.
            TypeError: When there is no mapping.
        """
        mappings = self.mappings
        if isinstance(mappings, dict) and CONST.MAPPING_JSON_DATA in mappings:
            return json.loads(mappings[CONST.MAPPING_JSON_DATA])
        if not isinstance(mappings, dict):
            raise TypeError("The mapping is missing or is not an object.")
        return mappings

    def validate_mappings(self) -> ValidationResult:
        """Validate the mapping file.

        Returns:
            ValidationResult: Validation result.
        """
        if not self.mappings:
            return ValidationResult(
                success=True,
                message=(
                    "No mapping file is attached to this configuration, "
                    "the records will be ingested as received."
                ),
            )
        message = resolution = None
        try:
            mappings = self._load_mappings()
            taxonomy = mappings.get(CONST.MAPPING_TAXONOMY)
            json_taxonomy = (
                taxonomy.get(CONST.MAPPING_JSON)
                if isinstance(taxonomy, dict)
                else None
            )
            if not isinstance(json_taxonomy, dict):
                message = CONST.MAPPING_MISSING_TAXONOMY_MESSAGE
            for data_type in CONST.SUPPORTED_DATA_TYPES:
                if message:
                    break
                subtypes = json_taxonomy.get(data_type)
                if not isinstance(subtypes, dict):
                    message = CONST.MAPPING_TYPE_INVALID_MESSAGE.format(
                        data_type=data_type
                    )
                    break
                for subtype, fields in subtypes.items():
                    if not isinstance(fields, list) or not all(
                        isinstance(field, str) for field in fields
                    ):
                        message = CONST.MAPPING_SUBTYPE_INVALID_MESSAGE.format(
                            data_type=data_type, subtype=subtype
                        )
                        break
            resolution = CONST.MAPPING_VALIDATION_RESOLUTION
        except (TypeError, ValueError, AttributeError):
            message = CONST.MAPPING_INVALID_JSON_MESSAGE
            resolution = CONST.MAPPING_INVALID_JSON_RESOLUTION
        if message:
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=message,
                resolution=resolution,
            )
            return ValidationResult(success=False, message=message)
        return ValidationResult(
            success=True, message=CONST.MAPPING_VALIDATION_SUCCESS
        )

    def transform(
        self,
        raw_data: List[Any],
        data_type: Optional[str],
        subtype: Optional[str],
    ) -> List[Any]:
        """Keep only the fields listed for the subtype in the mapping.

        An empty field list keeps the records unchanged. Records that are
        not parsed (dict), such as raw WebTx data, are left untouched. The
        records are serialized in ``push``, which owns the file.

        Args:
            raw_data (list): Parsed records (dict).
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            List[Any]: The records with the mapped fields.
        """
        if not self.mappings:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}] [{subtype}] No mapping "
                "is attached to this configuration, hence the record(s) "
                "will be ingested as received."
            )
            return raw_data
        try:
            fields = get_subtype_mapping(
                self._load_mappings()[CONST.MAPPING_TAXONOMY][
                    CONST.MAPPING_JSON
                ][data_type],
                subtype,
            )
        except (KeyError, TypeError, ValueError, AttributeError) as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"[{data_type}] [{subtype}] fetching the JSON mapping",
                "Ensure that the mapping file contains the JSON mapping "
                "for the data type and subtype.",
                err=err,
            )
        if not fields:
            return raw_data
        transformed, skipped = [], 0
        for record in raw_data:
            if not isinstance(record, dict):
                transformed.append(record)
                continue
            try:
                mapped = map_json_data(fields, record)
            except Exception:
                skipped += 1
                continue
            if mapped:
                transformed.append(mapped)
            else:
                skipped += 1
        if skipped:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}] [{subtype}] Skipped "
                f"{skipped} log(s) that were empty or had none of the "
                "mapped fields."
            )
        return transformed

    @staticmethod
    def _build_push_result(message: str, rejected: list) -> PushResult:
        """Build the push result, returning the logs that were not written.

        Cloud Exchange subtracts the returned logs from the ingested
        count, so that they are not reported as ingested.

        Args:
            message (str): Push result message.
            rejected (list): Empty and failed logs that were not written.

        Returns:
            PushResult: Push result.
        """
        kwargs = {"success": True, "message": message}
        if rejected and "failed_data" in getattr(
            PushResult, "model_fields", {}
        ):
            kwargs["failed_data"] = rejected
        return PushResult(**kwargs)

    def push(
        self,
        transformed_data: Optional[List[Any]],
        data_type: Optional[str],
        subtype: Optional[str],
    ) -> PushResult:
        """Upload the Netskope data to the bucket as one JSON Lines object.

        Args:
            transformed_data (list): Parsed records (dict).
            data_type (str): Data type, ``alerts``, ``events`` or ``webtx``.
            subtype (str): Subtype, e.g. ``v2`` or ``dlp``.

        Raises:
            GCPStorageException: When the upload fails, so that CE retries.

        Returns:
            PushResult: Push result.
        """
        tag = f"[{data_type or CONST.WEBTX_DATA_TYPE}]"
        if subtype:
            tag = f"{tag} [{subtype}]"
        if data_type not in CONST.SUPPORTED_DATA_TYPES:
            message = (
                f"{tag} Data type '{data_type}' is not supported, only "
                "Alerts, Events and WebTx data are supported. The log(s) "
                "were skipped."
            )
            self.logger.info(f"{self.log_prefix}: {message}")
            return PushResult(success=True, message=message)

        bucket = ""
        temp_path = None
        try:
            bucket = self.configuration.get(CONST.BUCKET_NAME_KEY).strip()
            compress = (
                self.configuration.get(
                    CONST.COMPRESSION_KEY, CONST.COMPRESSION_GZIP
                )
                != CONST.COMPRESSION_NONE
            )
            with NamedTemporaryFile(
                "wb",
                delete=False,
                suffix=CONST.OBJECT_EXTENSION_GZIP
                if compress
                else CONST.OBJECT_EXTENSION_JSON,
            ) as temp_file:
                temp_path = temp_file.name
                result = serialize_records(
                    transformed_data or [], temp_file, compress
                )
            if result.failed:
                log_error(
                    self.logger,
                    self.log_prefix,
                    f"serializing {result.failed} log(s); they were "
                    "skipped",
                    "Ensure that the source plugin sends valid "
                    "records.",
                    details=(
                        f"{tag} {result.failed} log(s) are not parsed "
                        "records or could not be converted to JSON."
                    ),
                )
            if result.skipped:
                self.logger.info(
                    f"{self.log_prefix}: {tag} Skipped {result.skipped} "
                    "empty log(s)."
                )
            if not result.written:
                message = (
                    f"{tag} No log(s) to ingest, {result.failed} log(s) "
                    "could not be serialized and were skipped."
                    if result.failed
                    else f"{tag} No log(s) to ingest."
                )
                self.logger.debug(f"{self.log_prefix}: {message}")
                return self._build_push_result(message, result.rejected)
            object_name = self._get_client(self.configuration).push(
                temp_path, data_type, subtype, compress
            )
            message = (
                f"{tag} Successfully ingested {result.written} log(s) to "
                f"Google Cloud Storage bucket '{bucket}'. "
                f"Object: '{object_name}'."
            )
            self.logger.info(f"{self.log_prefix}: {message}")
            return self._build_push_result(message, result.rejected)
        except GCPStorageException:
            raise
        except Exception as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"pushing logs to bucket '{bucket}'",
                "Ensure that the plugin configuration is valid. Check the "
                "logs for details.",
                err=err,
            )
        finally:
            remove_local_file(temp_path)
