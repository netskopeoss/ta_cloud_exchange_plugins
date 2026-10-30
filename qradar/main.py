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

QRadar Plugin."""

import json
import traceback
from typing import List, Tuple, Union

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.cef_generator import CEFGenerator
from .utils.client import QRadarSyslogClient
from .utils.exceptions import (
    MappingValidationError,
    QRadarPluginError,
    QRadarSendError,
)
from .utils.helper import (
    build_syslog_header,
    get_exclude_flag_value,
    get_extensions,
    get_headers,
    get_qradar_mappings,
    get_subtype_mapping,
    map_json_data,
    transformation_compatibility_check,
    uses_tenant_name,
    validate_qradar_mappings,
)
from .utils.validator import QRadarValidator


class QRadarPlugin(PluginBase):
    """QRadar CLS plugin: ingests data into QRadar over Syslog."""

    def __init__(self, name, *args, **kwargs):
        """Initialize.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.config_name = name
        self._tenant_name = None
        self.log_prefix = self._build_log_prefix(CONST.PLATFORM_NAME)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = self._build_log_prefix(self.plugin_name)

    def _build_log_prefix(self, plugin_name):
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
            metadata = QRadarPlugin.metadata
            return (
                metadata.get("name", CONST.PLATFORM_NAME),
                metadata.get("version", CONST.PLUGIN_VERSION),
            )
        except Exception:
            self._log_error(CONST.PLUGIN_INFO_MESSAGE)
        return CONST.PLATFORM_NAME, CONST.PLUGIN_VERSION

    def _log_error(self, message, resolution=None, details=None):
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
    def _get_tenant_name(self):
        """Return the tenant name of the source, cached per instance.

        Returns:
            str: Tenant name.
        """
        if self._tenant_name is None:
            self._tenant_name = (
                AlertsHelper().get_tenant_cls(self.source).name
            )
        return self._tenant_name

    def _resolve_tenant_name(self, data_type, subtype):
        """Resolve the tenant name once before a batch is transformed.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.

        Raises:
            QRadarPluginError: When the tenant can not be found.
        """
        try:
            self._get_tenant_name()
        except Exception as err:
            message = CONST.TENANT_NAME_MESSAGE.format(
                data_type=data_type, subtype=subtype
            )
            self._log_error(message, CONST.TENANT_NAME_RESOLUTION)
            raise QRadarPluginError(message) from err

    def _get_subtype_mapping_or_raise(
        self, mappings, data_type, subtype, data_format
    ):
        """Return the mapping of a subtype, logging when it is missing.

        Args:
            mappings (dict): Taxonomy of the format.
            data_type (str): Data type.
            subtype (str): Subtype.
            data_format (str): "JSON" or "CEF", for the log message.

        Returns:
            Mapping of the subtype.

        Raises:
            QRadarPluginError: When the mapping is missing.
        """
        try:
            return get_subtype_mapping(mappings[data_type], subtype)
        except (KeyError, MappingValidationError) as err:
            message = CONST.TRANSFORM_MAPPING_MESSAGE.format(
                format=data_format, data_type=data_type, subtype=subtype
            )
            self._log_error(
                message,
                CONST.TRANSFORM_MAPPING_RESOLUTION.format(
                    format=data_format, data_type=data_type, subtype=subtype
                ),
            )
            raise QRadarPluginError(message) from err

    def _log_record_error(self, logged, kind, message, resolution=None):
        """Log a per-record error once per batch.

        Args:
            logged (set): Kinds of errors already logged in the batch.
            kind (str): Kind of error.
            message (str): Message, starting with "Error occurred while".
            resolution (str): Resolution, when the user can fix the cause.
        """
        if kind in logged:
            return
        logged.add(kind)
        self._log_error(message, resolution)

    def _get_log_source_identifier(self):
        """Return the stripped Log Source Identifier.

        Returns:
            str: Log Source Identifier.
        """
        value = self.configuration.get(
            CONST.CONFIG_LOG_SOURCE_IDENTIFIER,
            CONST.DEFAULT_LOG_SOURCE_IDENTIFIER,
        )
        return str(value).strip() if value is not None else ""

    def _log_skipped(self, count, data_type, subtype, data_format):
        """Log the number of records that were not transformed.

        The count is logged at info level for JSON and at debug level for
        CEF.

        Args:
            count (int): Skipped records.
            data_type (str): Data type.
            subtype (str): Subtype.
            data_format (str): "JSON" or "CEF".
        """
        if count > 0:
            log = (
                self.logger.info
                if data_format == CONST.FORMAT_JSON.upper()
                else self.logger.debug
            )
            log(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.TRANSFORM_SKIPPED_MESSAGE.format(
                        data_type=data_type,
                        subtype=subtype,
                        count=count,
                        format=data_format,
                    ),
                )
            )

    def _transform_json(self, raw_data, data_type, subtype, taxonomy):
        """Transform records to JSON lines with the Syslog header.

        Args:
            raw_data (list): Records.
            data_type (str): Data type.
            subtype (str): Subtype.
            taxonomy (dict): Mapping taxonomy.

        Returns:
            list: Transformed records.
        """
        fields = self._get_subtype_mapping_or_raise(
            taxonomy.get(CONST.MAPPING_JSON, {}),
            data_type,
            subtype,
            CONST.FORMAT_JSON.upper(),
        )
        log_source_identifier = self._get_log_source_identifier()
        exclude_timestamp = (
            get_exclude_flag_value(
                self.configuration, CONST.CONFIG_EXCLUDE_TIMESTAMP
            )
            == CONST.YES
        )
        exclude_identifier = (
            get_exclude_flag_value(
                self.configuration, CONST.CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER
            )
            == CONST.YES
        )
        transformed_data, skipped, logged = [], 0, set()
        for data in raw_data:
            try:
                mapped_data = map_json_data(fields, data)
                if not mapped_data:
                    skipped += 1
                    continue
                transformed_data.append(
                    build_syslog_header(
                        log_source_identifier,
                        exclude_timestamp,
                        exclude_identifier,
                    )
                    + json.dumps(mapped_data)
                )
            except Exception:
                skipped += 1
                self._log_record_error(
                    logged,
                    CONST.FORMAT_JSON,
                    CONST.TRANSFORM_JSON_RECORD_MESSAGE.format(
                        data_type=data_type, subtype=subtype
                    ),
                )
        self._log_skipped(
            skipped, data_type, subtype, CONST.FORMAT_JSON.upper()
        )
        return transformed_data

    def _transform_cef_record(
        self, data, subtype_mapping, data_type, subtype, cef_generator, logged
    ):
        """Transform one record to a CEF event.

        Args:
            data (dict): Record.
            subtype_mapping (dict): CEF mapping of the subtype.
            data_type (str): Data type.
            subtype (str): Subtype.
            cef_generator (CEFGenerator): Generator.
            logged (set): Kinds of errors already logged in the batch.

        Returns:
            str: CEF event, or None when the record is skipped.
        """
        try:
            header, mapped_header = get_headers(
                subtype_mapping[CONST.MAPPING_HEADER],
                data,
                data_type,
                self._tenant_name,
            )
        except Exception:
            self._log_record_error(
                logged,
                CONST.MAPPING_HEADER,
                CONST.TRANSFORM_HEADER_MESSAGE.format(
                    data_type=data_type, subtype=subtype
                ),
                CONST.TRANSFORM_HEADER_RESOLUTION,
            )
            return None
        try:
            extension, mapped_extension = get_extensions(
                subtype_mapping[CONST.MAPPING_EXTENSION], data
            )
        except Exception:
            self._log_record_error(
                logged,
                CONST.MAPPING_EXTENSION,
                CONST.TRANSFORM_EXTENSION_MESSAGE.format(
                    data_type=data_type, subtype=subtype
                ),
                CONST.TRANSFORM_EXTENSION_RESOLUTION,
            )
            return None
        if not (mapped_header or mapped_extension):
            return None
        try:
            return cef_generator.get_cef_event(
                data,
                header,
                extension,
                data_type,
                subtype,
                self._get_log_source_identifier(),
            )
        except Exception:
            self._log_record_error(
                logged,
                CONST.FORMAT_CEF,
                CONST.TRANSFORM_CEF_EVENT_MESSAGE.format(
                    data_type=data_type, subtype=subtype
                ),
            )
        return None

    def _transform_cef(self, raw_data, data_type, subtype, mappings):
        """Transform records to CEF events.

        Args:
            raw_data (list): Records.
            data_type (str): Data type.
            subtype (str): Subtype.
            mappings (dict): Parsed mapping file.

        Returns:
            list: CEF events.
        """
        delimiter, cef_version, taxonomy = get_qradar_mappings(mappings)
        subtype_mapping = self._get_subtype_mapping_or_raise(
            taxonomy, data_type, subtype, CONST.FORMAT_CEF.upper()
        )
        if data_type != CONST.WEBTX and uses_tenant_name(
            subtype_mapping.get(CONST.MAPPING_HEADER, {})
        ):
            self._resolve_tenant_name(data_type, subtype)
        cef_generator = CEFGenerator(
            mappings, delimiter, cef_version, self.logger, self.log_prefix
        )
        transformed_data, skipped, logged = [], 0, set()
        for data in raw_data:
            if not data:
                skipped += 1
                continue
            cef_event = self._transform_cef_record(
                data,
                subtype_mapping,
                data_type,
                subtype,
                cef_generator,
                logged,
            )
            if cef_event:
                transformed_data.append(cef_event)
            else:
                skipped += 1
        self._log_skipped(
            skipped, data_type, subtype, CONST.FORMAT_CEF.upper()
        )
        return transformed_data

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform Netskope data to CEF or JSON Syslog messages.

        Args:
            raw_data (list): Records.
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            list: Transformed records.

        Raises:
            QRadarPluginError: When the mapping of the subtype is missing.
        """
        if not raw_data:
            return []
        mappings = self.mappings or {}
        if transformation_compatibility_check(self.configuration):
            _, _, taxonomy = get_qradar_mappings(mappings)
            return self._transform_json(raw_data, data_type, subtype, taxonomy)
        return self._transform_cef(raw_data, data_type, subtype, mappings)

    # ------------------------------------------------------------------
    # Push
    # ------------------------------------------------------------------
    def log_success_msg(self, data_type, subtype, sent, empty):
        """Log and return the success message of a push.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            sent (int): Records sent.
            empty (int): Empty records skipped.

        Returns:
            str: Message, empty when nothing was sent.
        """
        log_msg = ""
        if sent > 0:
            log_msg = CONST.PUSH_SUCCESS_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                count=sent,
                platform=self.plugin_name,
            )
            if empty:
                log_msg += CONST.PUSH_SKIPPED_MESSAGE.format(count=empty)
            self.logger.info(
                CONST.LOG_MESSAGE_TEMPLATE.format(self.log_prefix, log_msg)
            )
        return log_msg

    def _log_oversized(self, oversized):
        """Log the records skipped because they do not fit in UDP.

        Args:
            oversized (int): Number of records.
        """
        if oversized:
            self._log_error(
                CONST.PUSH_OVERSIZED_MESSAGE.format(count=oversized),
                CONST.PUSH_OVERSIZED_RESOLUTION,
                details="",
            )

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Send the transformed records to QRadar.

        On a send failure the records already handled are removed from
        ``transformed_data`` and the error is raised, so Cloud Exchange
        retries only the remaining records.

        Args:
            transformed_data (list): Records from transform().
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            PushResult: Result of the push.

        Raises:
            QRadarPluginError: When the data can not be sent.
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
        if not transformed_data:
            log_msg = CONST.PUSH_NO_DATA_MESSAGE.format(
                data_type=data_type,
                subtype=subtype,
                platform=self.plugin_name,
            )
            self.logger.info(
                CONST.LOG_MESSAGE_TEMPLATE.format(self.log_prefix, log_msg)
            )
            return PushResult(success=True, message=log_msg)
        client = QRadarSyslogClient(
            self.configuration,
            self.logger,
            self.log_prefix,
            transformation_compatibility_check(self.configuration),
        )
        try:
            client.connect()
            sent, empty, oversized_records = client.send(transformed_data)
        except QRadarSendError as err:
            self.log_success_msg(data_type, subtype, err.sent, 0)
            self._log_oversized(err.oversized)
            del transformed_data[: err.processed]
            message = CONST.PUSH_FAILED_MESSAGE.format(
                count=len(transformed_data)
            )
            self._log_error(message, CONST.PUSH_FAILED_RESOLUTION)
            raise QRadarPluginError(message) from err
        except QRadarPluginError:
            raise
        except Exception as err:
            message = CONST.PUSH_UNEXPECTED_MESSAGE.format(
                data_type=data_type, subtype=subtype
            )
            self._log_error(message)
            raise QRadarPluginError(message) from err
        finally:
            client.close()
        self._log_oversized(len(oversized_records))
        # Cloud Exchange subtracts the failed records from the ingested
        # count, so the records that were not sent are not counted as
        # ingested. They are not retried, as they can never fit in UDP.
        return PushResult(
            success=True,
            message=self.log_success_msg(data_type, subtype, sent, empty),
            failed_data=oversized_records,
        )

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
        allow_whitespace: bool = True,
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
            allow_whitespace: Whether whitespace is allowed in the value

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
            return ValidationResult(
                success=False,
                message=err_msg,
            )

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
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

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
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Whitespace check, for values written into the Syslog header
        if (
            not allow_whitespace
            and isinstance(field_value, str)
            and any(character.isspace() for character in field_value)
        ):
            err_msg = CONST.WHITESPACE_FIELD_MESSAGE.format(field=field_name)
            self.logger.error(
                message=CONST.VALIDATION_LOG_TEMPLATE.format(
                    self.log_prefix, validation_err_msg, err_msg
                ),
                resolution=CONST.WHITESPACE_FIELD_RESOLUTION.format(
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

        Text and choice values are stripped. The certificate is kept as
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

        all_params = {
            CONST.CONFIG_SERVER: _strip(
                configurations.get(CONST.CONFIG_SERVER, "")
            ),
            CONST.CONFIG_PROTOCOL: _strip(
                configurations.get(CONST.CONFIG_PROTOCOL, "")
            ),
            CONST.CONFIG_PORT: configurations.get(CONST.CONFIG_PORT),
            CONST.CONFIG_CERTIFICATE: configurations.get(
                CONST.CONFIG_CERTIFICATE, ""
            ),
            CONST.CONFIG_LOG_SOURCE_IDENTIFIER: _strip(
                configurations.get(CONST.CONFIG_LOG_SOURCE_IDENTIFIER, "")
            ),
            CONST.CONFIG_EXCLUDE_TIMESTAMP: get_exclude_flag_value(
                configurations, CONST.CONFIG_EXCLUDE_TIMESTAMP
            ),
            CONST.CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER: (
                get_exclude_flag_value(
                    configurations, CONST.CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER
                )
            ),
            CONST.CONFIG_EXCLUDE_PRIORITY: get_exclude_flag_value(
                configurations, CONST.CONFIG_EXCLUDE_PRIORITY
            ),
            CONST.CONFIG_TRANSFORM_DATA: (
                transformation_compatibility_check(configurations)
            ),
        }

        if not params_to_get:
            return tuple(all_params.values())

        result = [all_params.get(param) for param in params_to_get]
        return result[0] if len(result) == 1 else tuple(result)

    def validate_mappings(self) -> ValidationResult:
        """Validate the QRadar mapping file.

        Returns:
            ValidationResult: Result of the validation.
        """
        validator = QRadarValidator(self.logger, self.log_prefix)
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
        if not validator.validate_qradar_map(mappings):
            return ValidationResult(
                success=False,
                message=CONST.MAPPING_INVALID_MESSAGE.format(
                    error=validator.error
                ).strip(),
            )
        for data_type in mappings[CONST.MAPPING_TAXONOMY]:
            self.logger.debug(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.MAPPING_VALIDATING.format(data_type=data_type),
                )
            )
            try:
                validate_qradar_mappings(mappings, data_type)
            except Exception as err:
                # MappingValidationError, or an unexpected structure that
                # the schema did not reject.
                message = CONST.MAPPING_TYPE_INVALID_MESSAGE.format(
                    data_type=data_type, error=err
                )
                self._log_error(
                    message,
                    CONST.MAPPING_TYPE_RESOLUTION.format(data_type=data_type),
                )
                return ValidationResult(success=False, message=message)
        return ValidationResult(
            success=True, message=CONST.MAPPING_VALIDATION_SUCCESS
        )

    def validate_server_connectivity(
        self, configuration: dict
    ) -> Union[ValidationResult, None]:
        """Test whether the configured QRadar server is reachable.

        TCP and TLS open and close a connection; UDP only resolves the
        QRadar Server, as nothing can be checked without sending data.

        Args:
            configuration (dict): Plugin configuration.

        Returns:
            ValidationResult on failure, None on success
        """
        try:
            QRadarSyslogClient(
                configuration,
                self.logger,
                self.log_prefix,
                transformation_compatibility_check(configuration),
            ).validate_connectivity()
        except QRadarPluginError as err:
            # Already logged by the client, with its resolution.
            return ValidationResult(success=False, message=str(err))
        except Exception:
            err_msg = CONST.CONNECTIVITY_UNEXPECTED_MESSAGE
            self._log_error(err_msg, CONST.CONNECTION_ERROR_RESOLUTION)
            return ValidationResult(success=False, message=err_msg)
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        validation_err_msg = CONST.VALIDATION_ERROR_MESSAGE

        # Get all configuration parameters
        (
            qradar_server,
            qradar_protocol,
            qradar_port,
            qradar_certificate,
            log_source_identifier,
            exclude_timestamp_field,
            exclude_log_source_identifier_field,
            exclude_priority_field,
            transform_data_json,
        ) = self._get_config_params(configuration)

        # Validate QRadar Server
        if server_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_SERVER,
            field_value=qradar_server,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return server_result

        # Validate QRadar Protocol
        if protocol_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_PROTOCOL,
            field_value=qradar_protocol,
            field_type=str,
            is_required=True,
            allowed_values=CONST.QRADAR_PROTOCOLS,
            validation_err_msg=validation_err_msg,
        ):
            return protocol_result

        # Validate QRadar Port
        if port_result := self._validate_configuration_parameters(
            field_name=CONST.LABEL_PORT,
            field_value=qradar_port,
            field_type=int,
            is_required=True,
            range_validation=True,
            range_values=CONST.QRADAR_PORT_RANGE,
            validation_err_msg=validation_err_msg,
        ):
            return port_result

        # Validate QRadar Certificate for TLS
        if qradar_protocol == CONST.PROTOCOL_TLS:
            if certificate_result := self._validate_configuration_parameters(
                field_name=CONST.LABEL_CERTIFICATE,
                field_value=qradar_certificate,
                field_type=str,
                is_required=True,
                validation_err_msg=validation_err_msg,
            ):
                return certificate_result

        # Validate Exclude Timestamp Field
        if timestamp_field := self._validate_configuration_parameters(
            field_name=CONST.LABEL_EXCLUDE_TIMESTAMP,
            field_value=exclude_timestamp_field,
            field_type=str,
            is_required=False,
            allowed_values=CONST.EXCLUDE_ALLOWED_VALUES,
            validation_err_msg=validation_err_msg,
        ):
            return timestamp_field

        # Validate Exclude Log Source Identifier Field
        if log_source_identifier_field := self._validate_configuration_parameters(  # noqa E501
            field_name=CONST.LABEL_EXCLUDE_LOG_SOURCE_IDENTIFIER,
            field_value=exclude_log_source_identifier_field,
            field_type=str,
            is_required=False,
            allowed_values=CONST.EXCLUDE_ALLOWED_VALUES,
            validation_err_msg=validation_err_msg,
        ):
            return log_source_identifier_field

        # Validate Exclude Priority Field
        if priority_field := self._validate_configuration_parameters(
            field_name=CONST.LABEL_EXCLUDE_PRIORITY,
            field_value=exclude_priority_field,
            field_type=str,
            is_required=False,
            allowed_values=CONST.EXCLUDE_ALLOWED_VALUES,
            validation_err_msg=validation_err_msg,
        ):
            return priority_field

        # Determine if Log Source Identifier is required based on format
        require_log_source_identifier = (
            not transform_data_json
            or exclude_log_source_identifier_field == CONST.NO
        )

        # Validate Log Source Identifier
        if log_source := self._validate_configuration_parameters(
            field_name=CONST.LABEL_LOG_SOURCE_IDENTIFIER,
            field_value=log_source_identifier,
            field_type=str,
            is_required=require_log_source_identifier,
            validation_err_msg=validation_err_msg,
            required_field_message=(
                CONST.REQUIRED_FIELD_FOR_FORMAT_MESSAGE.format(
                    field=CONST.LABEL_LOG_SOURCE_IDENTIFIER
                )
            ),
            allow_whitespace=False,
        ):
            return log_source

        # Validate Mappings
        mappings_validation_result = self.validate_mappings()

        if not mappings_validation_result.success:
            return mappings_validation_result

        # Validate Server Connectivity
        if connectivity_result := self.validate_server_connectivity(
            configuration
        ):
            return connectivity_result

        self.logger.debug(
            CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix, CONST.VALIDATION_COMPLETED
            )
        )
        return ValidationResult(
            success=True, message=CONST.VALIDATION_SUCCESS
        )

    def get_dynamic_fields(self) -> list:
        """Return dynamic configuration fields for the selected protocol.

        Cloud Exchange shows these fields after the manifest fields, so
        every field after QRadar Protocol is returned here. The QRadar
        Certificate is only used by TLS, so it is shown first, right after
        QRadar Protocol, only when TLS is selected.

        Returns:
            list: List of dynamic field definitions.
        """
        qradar_protocol = self._get_config_params(
            self.configuration, [CONST.CONFIG_PROTOCOL]
        )
        yes_no_choices = [
            {"key": "Yes", "value": CONST.YES},
            {"key": "No", "value": CONST.NO},
        ]
        common_fields = [
            {
                "label": CONST.LABEL_PORT,
                "key": CONST.CONFIG_PORT,
                "type": "number",
                "default": "",
                "mandatory": True,
                "description": CONST.PORT_DESCRIPTION,
            },
            {
                "label": CONST.LABEL_LOG_SOURCE_IDENTIFIER,
                "key": CONST.CONFIG_LOG_SOURCE_IDENTIFIER,
                "type": "text",
                "default": CONST.DEFAULT_LOG_SOURCE_IDENTIFIER,
                "mandatory": False,
                "description": CONST.LOG_SOURCE_IDENTIFIER_DESCRIPTION,
            },
            {
                "label": CONST.LABEL_EXCLUDE_TIMESTAMP,
                "key": CONST.CONFIG_EXCLUDE_TIMESTAMP,
                "type": "choice",
                "choices": yes_no_choices,
                "default": CONST.NO,
                "mandatory": False,
                "description": CONST.EXCLUDE_TIMESTAMP_DESCRIPTION,
            },
            {
                "label": CONST.LABEL_EXCLUDE_LOG_SOURCE_IDENTIFIER,
                "key": CONST.CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER,
                "type": "choice",
                "choices": yes_no_choices,
                "default": CONST.NO,
                "mandatory": False,
                "description": (
                    CONST.EXCLUDE_LOG_SOURCE_IDENTIFIER_DESCRIPTION
                ),
            },
            {
                "label": CONST.LABEL_EXCLUDE_PRIORITY,
                "key": CONST.CONFIG_EXCLUDE_PRIORITY,
                "type": "choice",
                "choices": yes_no_choices,
                "default": CONST.NO,
                "mandatory": False,
                "description": CONST.EXCLUDE_PRIORITY_DESCRIPTION,
            },
        ]

        if qradar_protocol == CONST.PROTOCOL_TLS:
            return [
                {
                    "label": CONST.LABEL_CERTIFICATE,
                    "key": CONST.CONFIG_CERTIFICATE,
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": CONST.CERTIFICATE_DESCRIPTION,
                },
            ] + common_fields
        return common_fields

    def chunk_size(self):
        """Return the number of records ingested per thread.

        Returns:
            int: Chunk size.
        """
        return CONST.CHUNK_SIZE
