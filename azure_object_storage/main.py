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

Microsoft Azure Cloud Storage plugin.
"""

import gzip
import json
import os
import re
import traceback
from tempfile import NamedTemporaryFile
from typing import List, Tuple

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.client import AzureCloudStorageClient
from .utils.constants import (
    BLOB_EXTENSION_JSON,
    BLOB_EXTENSION_JSON_GZIP,
    COMPRESSION_GZIP,
    COMPRESSION_KEY,
    COMPRESSION_NONE,
    MAPPING_JSON,
    MAPPING_JSON_DATA,
    MAPPING_TAXONOMY,
    MAPPING_VALIDATION_RESOLUTION,
    MAX_CONTAINER_NAME_LENGTH,
    MAX_OBJECT_PREFIX_LENGTH,
    MIN_CONTAINER_NAME_LENGTH,
    MODULE_NAME,
    NESTED_FIELD_SEPARATOR,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    REGEX_FOR_CONTAINER,
    SUPPORTED_DATA_TYPES,
    VALIDATION_ERROR_MSG,
)
from .utils.exceptions import AzureCloudStorageException


class AzurePlugin(PluginBase):
    """The Netskope CLS plugin implementation class."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the Microsoft Azure Cloud Storage plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from the manifest.

        Returns:
            tuple: Plugin name and version fetched from the manifest.
        """
        try:
            manifest_json = AzurePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the plugin manifest.json is present and "
                    "valid."
                ),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _log_skipped_log(self, exp, action_msg):
        """Log a single log that could not be added to an object.

        Args:
            exp (Exception): Error raised while handling the log.
            action_msg (str): What the plugin was doing.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while {action_msg}. "
                f"This log will be skipped. Error: {exp}"
            ),
            details=str(traceback.format_exc()),
            resolution=(
                "Ensure that the source plugin sends valid records."
            ),
        )

    def _discard_object_file(self, path):
        """Remove a temporary object file, ignoring any failure.

        Args:
            path (str): Path of the file to remove.
        """
        try:
            os.unlink(path)
        except OSError as exp:
            self.logger.debug(
                f"{self.log_prefix}: Could not remove the temporary "
                f"object file '{path}'. Error: {exp}"
            )

    def _record_skipped(self, stats, data):
        """Record a log that will not reach Azure.

        The log is kept so that it can be returned to CE Core through
        PushResult.failed_data, which Core subtracts from the ingested
        counters. Without it a skipped log is counted as ingested.

        Args:
            stats (dict): Counters updated in place.
            data: The log that was skipped.
        """
        stats["skipped"] += 1
        stats["failed"].append(data)

    def _build_push_result(self, log_msg, stats) -> PushResult:
        """Build the PushResult for a completed push cycle.

        Args:
            log_msg (str): Message to report back to CE Core.
            stats (dict): Counters collected during the push.

        Returns:
            PushResult: Result carrying the skipped log(s) when the
                running CE Core supports the failed_data field.
        """
        result_kwargs = {"success": True, "message": log_msg}
        if stats["failed"] and "failed_data" in getattr(
            PushResult, "model_fields", {}
        ):
            result_kwargs["failed_data"] = stats["failed"]
        return PushResult(**result_kwargs)

    def _build_json_object(self, transformed_data, stats, compress=True):
        """Write logs to a temporary JSON Lines file.

        The object is gzip-compressed by default to reduce the storage and
        transfer size of the logs.

        Args:
            transformed_data (List): Batch of logs to write.
            stats (dict): Counters updated in place.
            compress (bool): Whether to gzip-compress the object.

        Returns:
            str: Path of the object file, or None when no log could be
                written.
        """
        object_file = NamedTemporaryFile("wb", delete=False)
        gz_file = (
            gzip.GzipFile(fileobj=object_file, mode="wb")
            if compress
            else object_file
        )
        try:
            for data in transformed_data:
                if not data:
                    self._record_skipped(stats, data)
                    continue
                try:
                    gz_file.write(f"{json.dumps(data)}\n".encode("utf-8"))
                except Exception as exp:
                    self._log_skipped_log(
                        exp, "serializing a log to JSON"
                    )
                    self._record_skipped(stats, data)
                    continue
                stats["written"] += 1
            gz_file.close()
            object_file.close()
        except BaseException:
            # Best-effort cleanup so a close failure (e.g. disk full) does
            # not mask the original exception.
            try:
                gz_file.close()
            except Exception:
                pass
            try:
                object_file.close()
            except Exception:
                pass
            self._discard_object_file(object_file.name)
            raise
        if not stats["written"]:
            self._discard_object_file(object_file.name)
            return None
        return object_file.name

    def push(self, transformed_data: List, data_type, subtype) -> PushResult:
        """Ingest the given log(s) to Microsoft Azure Blob Storage.

        The whole batch is written as a single blob.

        Args:
            transformed_data (List): Logs to be ingested to Azure.
            data_type (str): The type of data being pushed.
            subtype (str): The subtype of data being pushed.

        Returns:
            PushResult: Push result containing message and status.

        Raises:
            AzureCloudStorageException: If the logs could not be ingested.
        """
        container_name = self.configuration.get("container_name", "").strip()
        total = len(transformed_data)
        stats = {"written": 0, "skipped": 0, "failed": []}
        object_count = 0
        try:
            self.logger.debug(
                f"{self.log_prefix}: Initializing the sharing of "
                f"{total} [{data_type}] [{subtype}] log(s) "
                f"to the {PLATFORM_NAME} container '{container_name}'."
            )
            azure_client = AzureCloudStorageClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.log_prefix,
                self.plugin_name,
                self.plugin_version,
            )
            compress = (
                self.configuration.get(COMPRESSION_KEY, COMPRESSION_GZIP)
                != COMPRESSION_NONE
            )
            object_path = self._build_json_object(
                transformed_data, stats, compress
            )

            if object_path:
                try:
                    azure_client.push(
                        object_path,
                        data_type,
                        subtype,
                        BLOB_EXTENSION_JSON_GZIP
                        if compress
                        else BLOB_EXTENSION_JSON,
                    )
                finally:
                    self._discard_object_file(object_path)
                object_count = 1

            log_msg = (
                f"[{data_type}] [{subtype}] Successfully ingested "
                f"{stats['written']} log(s) in {object_count} object(s) "
                f"to the {self.plugin_name} container '{container_name}'."
            )
            if stats["skipped"]:
                log_msg += (
                    " Received empty or unsupported data for "
                    f"{stats['skipped']} log(s) hence ingestion of those "
                    "log(s) was skipped."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return self._build_push_result(log_msg, stats)
        except AzureCloudStorageException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while ingesting [{data_type}] [{subtype}] "
                f"log(s) to the container '{container_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Azure Connection String and Container "
                    "Name are valid. Check the logs for details."
                ),
            )
            raise AzureCloudStorageException(err_msg)

    def _load_mappings(self):
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
        if isinstance(mappings, dict) and MAPPING_JSON_DATA in mappings:
            return json.loads(mappings[MAPPING_JSON_DATA])
        if not isinstance(mappings, dict):
            raise TypeError("The mapping is missing or is not an object.")
        return mappings

    @staticmethod
    def _get_subtype_mapping(mappings, subtype):
        """Return the field list of a subtype, ignoring the case.

        Args:
            mappings (dict): Mappings of a data type.
            subtype (str): Subtype.

        Returns:
            list: Field names of the subtype, None when the subtype has no
                mapping.
        """
        lowered = {str(key).lower(): value for key, value in mappings.items()}
        return lowered.get(str(subtype).lower())

    @staticmethod
    def _map_json_data(fields, record):
        """Keep only the listed fields of a record.

        A field is looked up as a top level key first, then as a dot
        separated path (e.g. 'host_info.hostname') into nested objects.
        The value is stored under the field name as written in the mapping.

        Args:
            fields (list): Field names to keep.
            record (dict): Record received from Netskope.

        Returns:
            dict: Record with the listed fields only.
        """
        mapped = {}
        for field in fields:
            if field in record:
                mapped[field] = record[field]
                continue
            current = record
            for part in field.split(NESTED_FIELD_SEPARATOR):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    break
            else:
                mapped[field] = current
        return mapped

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
                    "the logs will be ingested as received."
                ),
            )
        err_msg = None
        try:
            mappings = self._load_mappings()
            taxonomy = mappings.get(MAPPING_TAXONOMY)
            json_taxonomy = (
                taxonomy.get(MAPPING_JSON)
                if isinstance(taxonomy, dict)
                else None
            )
            if not isinstance(json_taxonomy, dict):
                err_msg = (
                    "Invalid mapping file. 'taxonomy.json' must be an "
                    "object."
                )
            for data_type in SUPPORTED_DATA_TYPES:
                if err_msg:
                    break
                subtypes = json_taxonomy.get(data_type)
                if not isinstance(subtypes, dict):
                    err_msg = (
                        f"Invalid mapping file. 'taxonomy.json.{data_type}' "
                        "must be an object of subtype and list of field "
                        "names."
                    )
                    break
                for subtype, fields in subtypes.items():
                    if not isinstance(fields, list) or not all(
                        isinstance(field, str) for field in fields
                    ):
                        err_msg = (
                            "Invalid mapping file. 'taxonomy.json."
                            f"{data_type}.{subtype}' must be a list of "
                            "field names (strings)."
                        )
                        break
            resolution = MAPPING_VALIDATION_RESOLUTION
        except (TypeError, ValueError, AttributeError):
            err_msg = (
                "Invalid mapping file. The mapping must be a valid JSON "
                "object."
            )
            resolution = "Ensure that the mapping file is a valid JSON object."
        if err_msg:
            return self._validation_error(err_msg, resolution=resolution)
        return ValidationResult(
            success=True, message="Mapping validation successful."
        )

    def transform(self, raw_data, data_type, subtype) -> List:
        """Keep only the fields listed for the subtype in the mapping.

        An empty field list keeps the logs unchanged. Logs that are not
        parsed (dict), such as raw WebTx data, are left untouched.

        Args:
            raw_data (List): Raw data retrieved from Netskope.
            data_type (str): Type of data to be transformed.
            subtype (str): The subtype of data being transformed.

        Returns:
            List: List of logs to be ingested.

        Raises:
            AzureCloudStorageException: When the mapping is unreadable or
                has no JSON mapping for the data type.
        """
        if not self.mappings:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}] [{subtype}] No mapping "
                "is attached to this configuration, hence the log(s) will "
                "be ingested as received."
            )
            return raw_data
        try:
            fields = self._get_subtype_mapping(
                self._load_mappings()[MAPPING_TAXONOMY][MAPPING_JSON][
                    data_type
                ],
                subtype,
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exp:
            err_msg = (
                f"[{data_type}] [{subtype}] Error occurred while fetching "
                "the JSON mapping of the data type."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the mapping file is valid and contains the "
                    "JSON mapping for the data type."
                ),
            )
            raise AzureCloudStorageException(err_msg)
        if fields is None:
            # Core skips the subtypes that are not in the mapping before it
            # calls transform(), so this only guards a mapping that lists
            # the subtype under another data type. Nothing is ingested for
            # it, the same as a subtype missing from the mapping.
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}] [{subtype}] Skipped "
                f"{len(raw_data)} log(s) as the subtype is not present in "
                "the mapping."
            )
            return []
        if not fields:
            return raw_data
        transformed, skipped = [], 0
        for record in raw_data:
            if not isinstance(record, dict):
                transformed.append(record)
                continue
            try:
                mapped = self._map_json_data(fields, record)
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

    def _validation_error(self, err_msg, resolution) -> ValidationResult:
        """Log a configuration problem and build a ValidationResult.

        Args:
            err_msg (str): Message shown to the user.
            resolution (str): What the user should do about it.

        Returns:
            ValidationResult: Unsuccessful validation result.
        """
        log_msg = f"{self.log_prefix}: {VALIDATION_ERROR_MSG} Error: {err_msg}"
        self.logger.error(message=log_msg, resolution=resolution)
        return ValidationResult(success=False, message=err_msg)

    def _is_transform_data_json(self, configuration: dict) -> bool:
        """Check whether Cloud Exchange is sending JSON, not CEF.

        Cloud Exchange sends the string "json" because the manifest
        declares format_options with JSON as the only choice. Without
        that key the core rewrites the value to a bool before the
        plugin sees it - True for CEF, False for JSON - so the bool
        form is still read here. It is what a configuration saved
        before this release carries.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            bool: True when the format is JSON.
        """
        transform_data = configuration.get("transformData", "json")
        if isinstance(transform_data, bool):
            return not transform_data
        return str(transform_data).strip().lower() == "json"

    def _validate_container_name(self, configuration: dict):
        """Validate the Container Name configuration parameter.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Unsuccessful result, or None when valid.
        """
        container_name = configuration.get("container_name")
        if not container_name:
            return self._validation_error(
                "Container Name is a required configuration parameter.",
                resolution="Ensure that the Container Name is provided.",
            )
        if not isinstance(container_name, str):
            return self._validation_error(
                "Invalid Container Name provided in the configuration "
                "parameters. Container Name should be a string.",
                resolution="Ensure that the Container Name is a string.",
            )
        container_name = container_name.strip()
        if (
            len(container_name) < MIN_CONTAINER_NAME_LENGTH
            or len(container_name) > MAX_CONTAINER_NAME_LENGTH
            or not re.match(REGEX_FOR_CONTAINER, container_name)
        ):
            return self._validation_error(
                "Invalid Container Name provided in the configuration "
                f"parameters. Container Name should be "
                f"{MIN_CONTAINER_NAME_LENGTH} to "
                f"{MAX_CONTAINER_NAME_LENGTH} characters long and may "
                "only contain lowercase letters, numbers and single "
                "dashes, and must start and end with a letter or number.",
                resolution=(
                    f"Ensure that the Container Name is "
                    f"{MIN_CONTAINER_NAME_LENGTH} to "
                    f"{MAX_CONTAINER_NAME_LENGTH} characters long, uses only "
                    "lowercase letters, numbers and single dashes, and "
                    "starts and ends with a letter or number."
                ),
            )
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result with status and message.
        """
        # This plugin writes the Netskope records as received. There is
        # nothing CEF would add to an object dropped in blob storage.
        if not self._is_transform_data_json(configuration):
            return self._validation_error(
                f"This plugin only sends raw Netskope logs to "
                f"{PLATFORM_NAME} Blob Storage. Select 'JSON' as the "
                "format to continue.",
                resolution=(
                    "Set the SIEM Mapping format to 'JSON' for this "
                    "plugin configuration."
                ),
            )

        azure_connection_string = configuration.get(
            "azure_connection_string"
        )
        if azure_connection_string is not None and not isinstance(
            azure_connection_string, str
        ):
            return self._validation_error(
                "Invalid Azure Connection String provided in the "
                "configuration parameters.",
                resolution=(
                    "Ensure that the Azure Connection String is a string."
                ),
            )
        if not azure_connection_string or not azure_connection_string.strip():
            return self._validation_error(
                "Azure Connection String is a required configuration "
                "parameter.",
                resolution=(
                    "Ensure that the Azure Connection String is provided."
                ),
            )

        mapping_result = self.validate_mappings()
        if not mapping_result.success:
            return mapping_result

        compression = configuration.get(COMPRESSION_KEY, COMPRESSION_GZIP)
        if compression not in (COMPRESSION_GZIP, COMPRESSION_NONE):
            return self._validation_error(
                "Invalid Compression provided in the configuration "
                "parameters.",
                resolution=(
                    "Ensure that the Compression is selected from the "
                    "available options."
                ),
            )

        container_result = self._validate_container_name(configuration)
        if container_result is not None:
            return container_result

        obj_prefix = configuration.get("obj_prefix")
        if obj_prefix is not None and not isinstance(obj_prefix, str):
            return self._validation_error(
                "Invalid Object Prefix provided in the configuration "
                "parameters. Object Prefix should be a string.",
                resolution="Ensure that the Object Prefix is a string.",
            )
        if not obj_prefix or not obj_prefix.strip():
            return self._validation_error(
                "Object Prefix is a required configuration parameter.",
                resolution=(
                    "Ensure that the Object Prefix is provided and is not "
                    "empty."
                ),
            )

        # The prefix is the top-level folder of the blob name. Azure can
        # normalize '.' and '..' path segments in the request URL and
        # advises against backslashes, and an empty folder name is not
        # wanted.
        prefix = obj_prefix.strip()
        folder = prefix.strip("/")
        if (
            len(prefix) > MAX_OBJECT_PREFIX_LENGTH
            or not folder
            or "\\" in prefix
            or re.search(r"[\x00-\x1f\x7f]", prefix)
            or any(part in ("", ".", "..") for part in folder.split("/"))
        ):
            return self._validation_error(
                "Invalid Object Prefix provided in the configuration "
                f"parameters. Object Prefix should be at most "
                f"{MAX_OBJECT_PREFIX_LENGTH} characters long and be a "
                "folder name that has no empty, '.' or '..' path segments, "
                "no backslashes and no control characters.",
                resolution=(
                    "Ensure that the Object Prefix is a folder name such "
                    "as 'netskope' or 'netskope/logs'."
                ),
            )

        try:
            azure_client = AzureCloudStorageClient(
                configuration,
                self.logger,
                self.proxy,
                self.log_prefix,
                self.plugin_name,
                self.plugin_version,
            )
            azure_client.validate_connectivity(
                configuration.get("container_name", "").strip()
            )
        except AzureCloudStorageException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters are valid. "
                    "Check the logs for details."
                ),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for "
            f"{self.plugin_name} plugin."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )
