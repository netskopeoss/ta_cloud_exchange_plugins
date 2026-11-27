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

Palo Alto Networks Cortex XDR CLS Plugin.
"""

import json
import traceback
from typing import Dict, List, Optional, Tuple, Union

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.exceptions import (
    CortexXDRPluginException,
    CortexXDRRequestRejectedException,
    MappingValidationError,
)
from .utils.helper import (
    CortexXDRPluginHelper,
    build_validation_record,
    get_cortex_xdr_mappings,
    get_nested_field_value,
    gzip_compress,
    is_json_format,
    is_soft_time_limit,
    serialize_record,
    split_into_size,
)
from .utils.validator import CortexXDRValidator


class CortexXDRPlugin(PluginBase):
    """Palo Alto Networks Cortex XDR CLS plugin: sends JSON data."""

    def __init__(self, name, *args, **kwargs):
        """Initialize.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.config_name = name
        self.log_prefix = self._build_log_prefix(CONST.PLUGIN_NAME)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = self._build_log_prefix(self.plugin_name)
        self.cortex_xdr_helper = CortexXDRPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _build_log_prefix(self, plugin_name: str) -> str:
        """Return the log prefix "CLS <plugin name> [<configuration>]".

        Args:
            plugin_name (str): Plugin name.

        Returns:
            str: Log prefix.
        """
        log_prefix = CONST.LOG_PREFIX_TEMPLATE.format(
            CONST.MODULE_NAME, plugin_name
        )
        if self.config_name:
            log_prefix += CONST.LOG_PREFIX_NAME_TEMPLATE.format(
                self.config_name
            )
        return log_prefix

    def _get_plugin_info(self) -> tuple:
        """Return the plugin name and version from the manifest metadata.

        Returns:
            tuple: (plugin name, plugin version).
        """
        try:
            metadata = CortexXDRPlugin.metadata
            return (
                metadata.get("name", CONST.PLUGIN_NAME),
                metadata.get("version", CONST.PLUGIN_VERSION),
            )
        except Exception:
            self._log_error(CONST.PLUGIN_INFO_MESSAGE)
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    def _log_error(
        self, message: str, resolution: str = None, details: str = None
    ):
        """Log an error with the log prefix and the current traceback.

        Args:
            message (str): Message, starting with "Error occurred while".
            resolution (str): Resolution, when the user can fix the cause.
            details (str): Details; defaults to the current traceback.
        """
        log_kwargs = {
            "message": CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix, message
            ),
            "details": (
                details
                if details is not None
                else str(traceback.format_exc())
            ),
        }
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------
    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> Optional[List]:
        """Return the field list of a subtype, case insensitively.

        Args:
            mappings (Dict): Subtype keyed mapping of a data type.
            subtype (str): Subtype.

        Returns:
            Optional[List]: Field list, or None when the subtype is not
                in the mapping.
        """
        if not isinstance(mappings, dict) or not subtype:
            return None
        lowered = {
            key.lower(): value
            for key, value in mappings.items()
            if isinstance(key, str)
        }
        return lowered.get(subtype.lower())

    def map_json_data(self, mappings: List, data: Dict) -> Dict:
        """Keep only the fields listed in the mapping.

        Args:
            mappings (List): Field names, dot notation allowed. An empty
                list keeps every field.
            data (Dict): Record.

        Returns:
            Dict: Mapped record; empty when no field matched.
        """
        if not mappings or not data:
            return data
        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]
                continue
            value, field_exist = get_nested_field_value(data, key)
            if field_exist:
                mapped_dict[key] = value
        return mapped_dict

    @staticmethod
    def _to_record(data) -> Optional[Dict]:
        """Return a record as a dict.

        Records are dicts. A record received as a JSON string is parsed.

        Args:
            data: Record.

        Returns:
            Optional[Dict]: The record, or None when it is empty or not a
                JSON object.
        """
        if isinstance(data, str) and data.strip():
            data = json.loads(data)
        return data if isinstance(data, dict) and data else None

    def _get_log_source_identifier(self) -> str:
        """Return the stripped Log Source Identifier.

        Returns:
            str: Log Source Identifier; empty when none is configured.
        """
        value = self.configuration.get(
            CONST.CONFIG_LOG_SOURCE_IDENTIFIER,
            CONST.DEFAULT_LOG_SOURCE_IDENTIFIER,
        )
        return str(value).strip() if value is not None else ""

    def transform(self, raw_data, data_type, subtype) -> List:
        """Filter the records with the JSON mapping.

        When a Log Source Identifier is configured, every record gets the
        "log_source_identifier" field with its value.

        Args:
            raw_data (list): Records.
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            list: Records to push.

        Raises:
            CortexXDRPluginException: When a format other than JSON is
                selected, the mapping can not be read or the subtype has no
                mapping.
        """
        if not raw_data:
            return []
        if not is_json_format(self.configuration):
            message = CONST.TRANSFORM_FORMAT_MESSAGE.format(
                data_type=data_type, subtype=subtype
            )
            self._log_error(
                message, CONST.FORMAT_NOT_SUPPORTED_RESOLUTION, details=""
            )
            raise CortexXDRPluginException(message)
        try:
            taxonomy = get_cortex_xdr_mappings(self.mappings)
        except MappingValidationError as err:
            message = CONST.TRANSFORM_MAPPING_MESSAGE.format(
                data_type=data_type, subtype=subtype
            )
            self._log_error(message, CONST.TRANSFORM_MAPPING_RESOLUTION)
            raise CortexXDRPluginException(message) from err

        fields = self.get_subtype_mapping(taxonomy.get(data_type), subtype)
        if fields is None:
            message = CONST.TRANSFORM_MAPPING_MESSAGE.format(
                data_type=data_type, subtype=subtype
            )
            self._log_error(
                message,
                CONST.TRANSFORM_SUBTYPE_MAPPING_RESOLUTION.format(
                    data_type=data_type, subtype=subtype
                ),
                details="",
            )
            raise CortexXDRPluginException(message)
        log_source_identifier = self._get_log_source_identifier()

        transformed_data, skipped, error_logged = [], 0, False
        for data in raw_data:
            try:
                record = self._to_record(data)
                mapped_data = (
                    self.map_json_data(fields, record) if record else None
                )
                if not mapped_data:
                    skipped += 1
                    continue
                mapped_data = dict(mapped_data)
                if log_source_identifier:
                    mapped_data[CONST.LOG_SOURCE_IDENTIFIER_FIELD] = (
                        log_source_identifier
                    )
                transformed_data.append(mapped_data)
            except Exception:
                skipped += 1
                if not error_logged:
                    # One error log per batch, not one per record.
                    error_logged = True
                    self._log_error(
                        CONST.TRANSFORM_RECORD_MESSAGE.format(
                            data_type=data_type, subtype=subtype
                        ),
                        CONST.TRANSFORM_RECORD_RESOLUTION,
                    )
        if skipped:
            self.logger.info(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.TRANSFORM_SKIPPED_MESSAGE.format(
                        data_type=data_type, subtype=subtype, count=skipped
                    ),
                )
            )
        return transformed_data

    # ------------------------------------------------------------------
    # Push
    # ------------------------------------------------------------------
    @staticmethod
    def _build_headers(api_key: str, compression: str) -> Dict:
        """Return the headers of an HTTP Log Collector request.

        Args:
            api_key (str): API Key, sent as is.
            compression (str): Compression.

        Returns:
            Dict: Headers.
        """
        headers = {
            CONST.HEADER_AUTHORIZATION: api_key,
            CONST.HEADER_CONTENT_TYPE: CONST.CONTENT_TYPE_JSON,
        }
        if compression == CONST.COMPRESSION_GZIP:
            headers[CONST.HEADER_CONTENT_ENCODING] = (
                CONST.CONTENT_ENCODING_GZIP
            )
        return headers

    @staticmethod
    def _build_payload(records: List[str], compression: str):
        """Return the body of an HTTP Log Collector request.

        Args:
            records (List[str]): JSON lines.
            compression (str): Compression.

        Returns:
            str or bytes: Newline delimited JSON, gzipped when selected.
        """
        payload = CONST.RECORD_SEPARATOR.join(records)
        if compression == CONST.COMPRESSION_GZIP:
            return gzip_compress(payload)
        return payload

    def _log_skipped_records(self, split_result, data_type, subtype):
        """Log the records that can not be sent.

        Args:
            split_result (SplitResult): Result of split_into_size().
            data_type (str): Data type.
            subtype (str): Subtype.
        """
        if split_result.oversized:
            self._log_error(
                CONST.PUSH_OVERSIZED_MESSAGE.format(
                    count=len(split_result.oversized),
                    data_type=data_type,
                    subtype=subtype,
                ),
                CONST.PUSH_OVERSIZED_RESOLUTION,
                details="",
            )
        if split_result.failed:
            self._log_error(
                CONST.PUSH_SERIALIZE_MESSAGE.format(
                    count=len(split_result.failed),
                    data_type=data_type,
                    subtype=subtype,
                ),
                CONST.TRANSFORM_RECORD_RESOLUTION,
                details="",
            )

    def _log_ingested(self, data_type, subtype, count, skipped=0) -> str:
        """Log and return the success message of a push.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            count (int): Records ingested.
            skipped (int): Records that could not be ingested.

        Returns:
            str: Message.
        """
        log_msg = CONST.PUSH_SUCCESS_MESSAGE.format(
            data_type=data_type,
            subtype=subtype,
            count=count,
            platform=self.plugin_name,
        )
        if skipped:
            log_msg += CONST.PUSH_SKIPPED_MESSAGE.format(count=skipped)
        self.logger.info(
            CONST.LOG_MESSAGE_TEMPLATE.format(self.log_prefix, log_msg)
        )
        return log_msg

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Send the records to the Cortex XDR HTTP Log Collector.

        The records are sent in requests of about 1 MB. A request whose
        content Cortex XDR rejects is skipped, its records are reported in
        failed_data and the other requests are still sent. When a request
        fails for another reason, the records already sent are removed
        from ``transformed_data`` and the error is raised, so Cloud
        Exchange retries only the remaining records.

        Args:
            transformed_data (list): Records from transform().
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            PushResult: Result of the push.

        Raises:
            CortexXDRPluginException: When the data can not be sent.
        """
        self.logger.debug(
            CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix,
                CONST.PUSH_START_MESSAGE.format(
                    count=len(transformed_data or []),
                    data_type=data_type,
                    subtype=subtype,
                    platform=self.plugin_name,
                ),
            )
        )
        split_result = split_into_size(transformed_data or [])
        self._log_skipped_records(split_result, data_type, subtype)
        if not split_result.chunks:
            log_msg = CONST.PUSH_NO_DATA_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                platform=self.plugin_name,
            )
            self.logger.info(
                CONST.LOG_MESSAGE_TEMPLATE.format(self.log_prefix, log_msg)
            )
            return PushResult(
                success=True,
                message=log_msg,
                failed_data=split_result.not_sent,
            )

        api_url, api_key, compression = self._get_config_params(
            self.configuration,
            [
                CONST.CONFIG_HTTP_LOG_COLLECTOR_URL,
                CONST.CONFIG_API_KEY,
                CONST.CONFIG_COMPRESSION,
            ],
        )
        headers = self._build_headers(api_key, compression)
        total, rejected = 0, []
        for batch, chunk in enumerate(split_result.chunks, start=1):
            try:
                self.cortex_xdr_helper.api_helper(
                    logger_msg=CONST.PUSH_BATCH_LOGGER_MESSAGE.format(
                        count=len(chunk.records),
                        data_type=data_type,
                        subtype=subtype,
                        batch=batch,
                    ),
                    url=api_url,
                    method=CONST.HTTP_METHOD_POST,
                    data=self._build_payload(chunk.records, compression),
                    headers=dict(headers),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
            except CortexXDRRequestRejectedException:
                # Cortex XDR refused the content of this request; it was
                # logged by the helper. The other batches are still sent
                # and its records are reported in failed_data.
                rejected.extend(transformed_data[i] for i in chunk.indexes)
                self._log_error(
                    CONST.PUSH_REJECTED_MESSAGE.format(
                        count=len(chunk.records),
                        data_type=data_type,
                        subtype=subtype,
                        batch=batch,
                    ),
                    CONST.REJECTED_RESPONSE_RESOLUTION,
                    details="",
                )
                continue
            except Exception as err:
                self._keep_unsent_records(
                    transformed_data, split_result, chunk, rejected
                )
                if is_soft_time_limit(err):
                    raise
                self._raise_push_error(
                    err, transformed_data, data_type, subtype, total
                )
            total += len(chunk.records)
            self.logger.info(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.PUSH_BATCH_MESSAGE.format(
                        data_type=data_type,
                        subtype=subtype,
                        count=len(chunk.records),
                        batch=batch,
                        platform=self.plugin_name,
                        total=total,
                    ),
                )
            )
        if rejected and not total:
            # Every batch was rejected, which points to the configuration
            # (Log Format or Compression), so Cloud Exchange retries.
            message = CONST.PUSH_ALL_REJECTED_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                platform=self.plugin_name,
            )
            self._log_error(
                message, CONST.REJECTED_RESPONSE_RESOLUTION, details=""
            )
            raise CortexXDRPluginException(message)
        # Cloud Exchange subtracts the failed records from the ingested
        # count. The oversized, unserializable and rejected records are
        # not retried.
        failed_data = split_result.not_sent + rejected
        return PushResult(
            success=True,
            message=self._log_ingested(
                data_type, subtype, total, len(failed_data)
            ),
            failed_data=failed_data,
        )

    @staticmethod
    def _keep_unsent_records(transformed_data, split_result, chunk, rejected):
        """Remove the sent records before the push is retried.

        The records before ``chunk`` were sent, except the skipped and
        rejected ones; those are put back so that the retried push
        reports them in failed_data.

        Args:
            transformed_data (list): Records of the push, changed in
                place.
            split_result (SplitResult): Result of split_into_size().
            chunk (Chunk): Request that failed.
            rejected (list): Records of the rejected requests.
        """
        skipped = [
            transformed_data[index]
            for index in split_result.skipped_indexes
            if index < chunk.start
        ]
        del transformed_data[: chunk.start]
        transformed_data[:0] = skipped + rejected

    def _raise_push_error(
        self, err, transformed_data, data_type, subtype, total
    ):
        """Log a failed push and raise it, so Cloud Exchange retries it.

        Args:
            err (Exception): Error of the failed request.
            transformed_data (list): Records left to send.
            data_type (str): Data type.
            subtype (str): Subtype.
            total (int): Records sent before the failure.

        Raises:
            CortexXDRPluginException: Always.
        """
        if total:
            self._log_ingested(data_type, subtype, total)
        if isinstance(err, CortexXDRPluginException):
            # The helper already logged the cause with its resolution.
            message = CONST.PUSH_FAILED_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                platform=self.plugin_name,
                count=len(transformed_data),
            )
            details = str(err)
        else:
            message = CONST.PUSH_UNEXPECTED_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                platform=self.plugin_name,
            )
            details = None
        self._log_error(
            message, CONST.PUSH_UNEXPECTED_RESOLUTION, details=details
        )
        raise CortexXDRPluginException(message) from err

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
        allowed_values: list = None,
        validation_err_msg: str = CONST.VALIDATION_ERROR_MESSAGE,
        range_validation: bool = False,
        range_values: Tuple[int, int] = None,
        required_field_message: str = None,
        is_url: bool = False,
    ) -> Union[ValidationResult, None]:
        """Validate a configuration field.

        Args:
            field_name: Name of the field to validate
            field_value: Value of the field to validate
            field_type: Expected type of the field
            is_required: Whether the field is required
            allowed_values: List of allowed values for the field
            validation_err_msg: Base validation error message
            range_validation: Whether to validate range for numeric fields
            range_values: Tuple of (min, max) values for range validation
            required_field_message: Custom error message when field is
                required but empty. Defaults to generic message.
            is_url: Whether the value must be an HTTP or HTTPS URL

        Returns:
            ValidationResult on failure, None on success
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
                else CONST.REQUIRED_FIELD_MESSAGE.format(field=field_name)
            )
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix, validation_err_msg, err_msg
                ),
                resolution=CONST.REQUIRED_FIELD_RESOLUTION.format(
                    field=field_name
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Type check. A boolean is not accepted as a number.
        if field_value and (
            not isinstance(field_value, field_type)
            or (field_type is int and isinstance(field_value, bool))
        ):
            err_msg = CONST.INVALID_FIELD_MESSAGE.format(field=field_name)
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix, validation_err_msg, err_msg
                ),
                resolution=CONST.INVALID_FIELD_RESOLUTION.format(
                    field=field_name
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Range validation for numeric fields
        if range_validation and range_values:
            if not (range_values[0] <= field_value <= range_values[1]):
                err_msg = CONST.RANGE_FIELD_MESSAGE.format(
                    field=field_name,
                    minimum=range_values[0],
                    maximum=range_values[1],
                )
                self.logger.error(
                    message=CONST.VALIDATION_LOG_TEMPLATE.format(
                        self.log_prefix, validation_err_msg, err_msg
                    ),
                    resolution=CONST.RANGE_FIELD_RESOLUTION.format(
                        field=field_name,
                        minimum=range_values[0],
                        maximum=range_values[1],
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        # Allowed values check
        if (
            allowed_values
            and field_type is str
            and field_value not in allowed_values
        ):
            values = CONST.ALLOWED_VALUES_SEPARATOR.join(allowed_values)
            err_msg = CONST.ALLOWED_VALUES_MESSAGE.format(
                field=field_name, values=values
            )
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix, validation_err_msg, err_msg
                ),
                resolution=CONST.ALLOWED_VALUES_RESOLUTION.format(
                    field=field_name, values=values
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # URL format check
        if is_url and not CortexXDRValidator.validate_url(field_value):
            err_msg = CONST.INVALID_FIELD_MESSAGE.format(field=field_name)
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix, validation_err_msg, err_msg
                ),
                resolution=CONST.INVALID_URL_RESOLUTION.format(
                    field=field_name
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix,
                CONST.FIELD_VALIDATION_SUCCESS.format(field=field_name),
            )
        )
        return None

    def _get_config_params(
        self, configurations: dict, params_to_get: List[str] = None
    ):
        """Get the required configuration parameters.

        Text and choice values are stripped. The API Key is kept as
        provided.

        Args:
            configurations (dict): Plugin configuration.
            params_to_get (list): Keys to return; all when not given.

        Returns:
            The value when one key is requested, otherwise a tuple of
            values in the order of the keys.
        """

        def _strip(value):
            """Strip a string value; other values are kept."""
            return value.strip() if isinstance(value, str) else value

        api_url = _strip(
            configurations.get(CONST.CONFIG_HTTP_LOG_COLLECTOR_URL, "")
        )
        if isinstance(api_url, str):
            api_url = api_url.rstrip("/")
        all_params = {
            CONST.CONFIG_HTTP_LOG_COLLECTOR_URL: api_url,
            CONST.CONFIG_API_KEY: configurations.get(CONST.CONFIG_API_KEY),
            CONST.CONFIG_COMPRESSION: _strip(
                configurations.get(CONST.CONFIG_COMPRESSION, "")
            ),
            CONST.CONFIG_LOG_SOURCE_IDENTIFIER: _strip(
                configurations.get(CONST.CONFIG_LOG_SOURCE_IDENTIFIER, "")
            ),
            CONST.CONFIG_TRANSFORM_DATA: is_json_format(configurations),
        }

        if not params_to_get:
            return tuple(all_params.values())

        result = [all_params.get(param) for param in params_to_get]
        return result[0] if len(result) == 1 else tuple(result)

    def validate_mappings(self) -> ValidationResult:
        """Validate the mapping file.

        Returns:
            ValidationResult: Result of the validation.
        """
        validator = CortexXDRValidator(self.logger, self.log_prefix)
        mappings = (self.mappings or {}).get(CONST.MAPPING_JSON_DATA)
        try:
            mappings = json.loads(mappings)
            if not mappings or not isinstance(mappings, dict):
                raise ValueError(CONST.MAPPING_INVALID_JSON_MESSAGE)
        except (TypeError, ValueError):
            self._log_error(
                CONST.MAPPING_INVALID_JSON_MESSAGE,
                CONST.MAPPING_INVALID_JSON_RESOLUTION,
            )
            return ValidationResult(
                success=False, message=CONST.MAPPING_INVALID_JSON_MESSAGE
            )
        if not validator.validate_mappings(mappings):
            return ValidationResult(
                success=False,
                message=CONST.MAPPING_INVALID_MESSAGE.format(
                    error=validator.error
                ),
            )
        return ValidationResult(
            success=True, message=CONST.MAPPING_VALIDATION_SUCCESS
        )

    def validate_auth(
        self,
        api_url: str,
        api_key: str,
        compression: str,
        log_source_identifier: str,
    ) -> Union[ValidationResult, None]:
        """Send one record to verify the URL, API Key and Compression.

        Cortex XDR has no endpoint to check the credentials, so a
        validation record is ingested.

        Args:
            api_url (str): HTTP Log Collector URL.
            api_key (str): API Key.
            compression (str): Compression.
            log_source_identifier (str): Log Source Identifier.

        Returns:
            ValidationResult on failure, None on success
        """
        record = build_validation_record(log_source_identifier)
        try:
            self.cortex_xdr_helper.api_helper(
                logger_msg=CONST.VALIDATION_LOGGER_MESSAGE,
                url=api_url,
                method=CONST.HTTP_METHOD_POST,
                data=self._build_payload(
                    [serialize_record(record)], compression
                ),
                headers=self._build_headers(api_key, compression),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
            )
        except CortexXDRPluginException as err:
            # Already logged by the helper, with its resolution.
            return ValidationResult(success=False, message=str(err))
        except Exception:
            err_msg = CONST.UNEXPECTED_ERROR_MESSAGE.format(
                logger_msg=CONST.VALIDATION_LOGGER_MESSAGE
            )
            self._log_error(err_msg, CONST.UNEXPECTED_ERROR_RESOLUTION)
            return ValidationResult(success=False, message=err_msg)
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters.

        Validation order: the format (JSON only), HTTP Log Collector URL,
        API Key, Compression, Log Source Identifier, the mapping, and
        last the authentication parameters, by sending one validation
        record.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Result of the validation, with the message
                to show when it fails.
        """
        validation_err_msg = CONST.VALIDATION_ERROR_MESSAGE

        # Get all configuration parameters
        (
            api_url,
            api_key,
            compression,
            log_source_identifier,
            transform_data_json,
        ) = self._get_config_params(configuration)

        # Validate the format; the plugin supports JSON only
        if not transform_data_json:
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix,
                    validation_err_msg,
                    CONST.FORMAT_NOT_SUPPORTED_MESSAGE,
                ),
                resolution=CONST.FORMAT_NOT_SUPPORTED_RESOLUTION,
            )
            return ValidationResult(
                success=False, message=CONST.FORMAT_NOT_SUPPORTED_MESSAGE
            )

        # Validate HTTP Log Collector URL
        if api_url_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_HTTP_LOG_COLLECTOR_URL,
            field_value=api_url,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
            is_url=True,
        ):
            return api_url_result

        # Validate API Key
        if api_key_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_API_KEY,
            field_value=api_key,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return api_key_result

        # Validate Compression
        if compression_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_COMPRESSION,
            field_value=compression,
            field_type=str,
            is_required=True,
            allowed_values=CONST.COMPRESSION_VALUES,
            validation_err_msg=validation_err_msg,
        ):
            return compression_result

        # Validate Log Source Identifier
        if log_source := self._validate_configuration_parameters(
            field_name=CONST.LABEL_LOG_SOURCE_IDENTIFIER,
            field_value=log_source_identifier,
            field_type=str,
            is_required=False,
            validation_err_msg=validation_err_msg,
        ):
            return log_source

        # Validate Mappings
        mappings_validation_result = self.validate_mappings()
        if not mappings_validation_result.success:
            return mappings_validation_result

        # Validate the authentication parameters
        if auth_result := self.validate_auth(
            api_url, api_key, compression, log_source_identifier
        ):
            return auth_result

        self.logger.debug(
            CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix, CONST.VALIDATION_COMPLETED
            )
        )
        return ValidationResult(
            success=True, message=CONST.VALIDATION_SUCCESS
        )
