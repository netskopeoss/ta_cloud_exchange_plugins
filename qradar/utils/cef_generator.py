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

QRadar Plugin CEF generator."""

import collections
import datetime
import time
import traceback

from netskope.integrations.cls.utils.converter import type_converter
from netskope.integrations.cls.utils.sanitizer import (
    escaper,
    get_sanitizers,
    str_sanitizer,
)

from . import constants as CONST
from .exceptions import QRadarPluginError


def iso_datetime_sanitizer():
    """Return a sanitizer that writes a datetime as ISO 8601 UTC.

    QRadar keeps this format for the "Time Stamp" transformation instead
    of the epoch seconds written by the Cloud Exchange sanitizer.

    Returns:
        callable: Sanitizer taking (value, field name).
    """

    def sanitize(value, debug_name):
        """Return the ISO 8601 UTC text of a datetime."""
        if not isinstance(value, datetime.datetime):
            raise ValueError(
                CONST.DATETIME_EXPECTED_ERROR.format(
                    field=debug_name, value_type=type(value)
                )
            )
        epoch = int(value.timestamp())
        return datetime.datetime.fromtimestamp(
            epoch, datetime.timezone.utc
        ).isoformat(CONST.ISO_SEPARATOR, CONST.ISO_TIMESPEC)

    return sanitize


class CEFGenerator:
    """Build CEF events from the mapped header and extension values."""

    def __init__(self, mapping, delimiter, cef_version, logger, log_prefix):
        """Initialize.

        Args:
            mapping (dict): Parsed mapping file.
            delimiter (str): CEF delimiter.
            cef_version (str): CEF version.
            logger: Cloud Exchange logger.
            log_prefix (str): Prefix of every log message.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.mapping = mapping
        self.delimiter = delimiter
        self.cef_version = cef_version
        self._prefix_field_str_sanitizer = str_sanitizer(
            CONST.CEF_PREFIX_FIELD_REGEX, escape_chars=delimiter
        )
        self._severity_sanitizer = str_sanitizer(CONST.CEF_SEVERITY_REGEX)
        self._equals_escaper = escaper(CONST.CEF_EQUALS_CHARACTER)
        self.extension = collections.namedtuple(
            CONST.EXTENSION_TUPLE_NAME,
            (CONST.EXTENSION_KEY_NAME, CONST.EXTENSION_SANITIZER),
        )
        self.extension_converter = collections.namedtuple(
            CONST.EXTENSION_CONVERTER_TUPLE_NAME,
            (CONST.EXTENSION_KEY_NAME, CONST.EXTENSION_CONVERTER),
        )
        sanitizers = get_sanitizers()
        sanitizers[CONST.TRANSFORMATION_TIMESTAMP] = iso_datetime_sanitizer()
        self.valid_extensions = self._build_field_map(
            sanitizers, self.extension, CONST.EXTENSION_SANITIZER
        )
        self.extension_converters = self._build_field_map(
            type_converter(),
            self.extension_converter,
            CONST.EXTENSION_CONVERTER,
        )

    @staticmethod
    def field_key(data_type, subtype, section, field):
        """Return the key of a field, unique per type and subtype.

        Args:
            data_type (str): Data type.
            subtype (str): Subtype.
            section (str): "header" or "extension".
            field (str): CEF field name.

        Returns:
            str: Field key.
        """
        return CONST.CEF_FIELD_KEY_TEMPLATE.format(
            data_type.lower(), subtype.lower(), section, field
        )

    def _build_field_map(self, functions, entry_type, function_name):
        """Map every mapped field to its converter or sanitizer.

        Args:
            functions (dict): Transformation name to function.
            entry_type: Named tuple type of the entries.
            function_name (str): Name of the function attribute.

        Returns:
            dict: Field key to named tuple.

        Raises:
            QRadarPluginError: When a transformation is not supported.
        """
        field_map = {}
        try:
            taxonomy = self.mapping[CONST.MAPPING_TAXONOMY]
            for data_type, data_mapping in taxonomy.items():
                if data_type == CONST.MAPPING_JSON:
                    continue
                for subtype, subtype_mapping in data_mapping.items():
                    for section, fields in subtype_mapping.items():
                        for field, field_mapping in fields.items():
                            transformation = field_mapping.get(
                                CONST.MAPPING_TRANSFORMATION,
                                CONST.TRANSFORMATION_STRING,
                            )
                            field_map[
                                self.field_key(
                                    data_type, subtype, section, field
                                )
                            ] = entry_type(
                                **{
                                    CONST.EXTENSION_KEY_NAME: field,
                                    function_name: functions[transformation],
                                }
                            )
        except Exception as err:
            self.logger.error(
                message=CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix, CONST.TRANSFORMATION_PARSE_MESSAGE
                ),
                details=str(traceback.format_exc()),
                resolution=CONST.TRANSFORMATION_PARSE_RESOLUTION,
            )
            raise QRadarPluginError(
                CONST.TRANSFORMATION_PARSE_MESSAGE
            ) from err
        return field_map

    def get_header_value(self, header, headers):
        """Return the sanitized value of a CEF header.

        Args:
            header (str): Header name.
            headers (dict): Header values.

        Returns:
            str: Sanitized value.
        """
        if header == CONST.CEF_HEADER_SEVERITY:
            return self._severity_sanitizer(headers[header], header)
        return self._prefix_field_str_sanitizer(headers[header], header)

    def log_invalid_header(self, headers, data_type, subtype):
        """Log the configured headers that are not CEF headers.

        Args:
            headers (dict): Header values.
            data_type (str): Data type.
            subtype (str): Subtype.
        """
        for configured_header in headers:
            if configured_header not in CONST.CEF_HEADERS:
                self.logger.debug(
                    CONST.LOG_MESSAGE_TEMPLATE.format(
                        self.log_prefix,
                        CONST.INVALID_HEADER_MESSAGE.format(
                            data_type=data_type,
                            subtype=subtype,
                            header=configured_header,
                        ),
                    )
                )

    @staticmethod
    def webtx_timestamp(raw_data):
        """Return the receipt time of a WebTx record.

        Args:
            raw_data (dict): WebTx record.

        Returns:
            str: "<date>T<time>Z", or None when date or time is missing.
        """
        date = raw_data.get(CONST.WEBTX_DATE_FIELD)
        time_value = raw_data.get(CONST.WEBTX_TIME_FIELD)
        if date and time_value:
            return CONST.WEBTX_TIMESTAMP_TEMPLATE.format(date, time_value)
        return None

    def _extension_strings(self, extensions, data_type, subtype):
        """Convert and sanitize the extension values.

        Args:
            extensions (dict): Extension field to raw value.
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            dict: Extension field to CEF value.
        """
        extension_strs = {}
        for name, value in extensions.items():
            field_key = self.field_key(
                data_type, subtype, CONST.MAPPING_EXTENSION, name
            )
            if (
                field_key not in self.extension_converters
                or field_key not in self.valid_extensions
            ):
                self.logger.debug(
                    CONST.LOG_MESSAGE_TEMPLATE.format(
                        self.log_prefix,
                        CONST.EXTENSION_FIELD_NOT_FOUND_MESSAGE.format(
                            data_type=data_type, subtype=subtype, field=name
                        ),
                    )
                )
                continue
            try:
                value = self.extension_converters[field_key].converter(
                    value, name
                )
                sanitized_value = self.valid_extensions[field_key].sanitizer(
                    value, name
                )
                if isinstance(sanitized_value, str):
                    sanitized_value = self._equals_escaper(sanitized_value)
                extension_strs[self.valid_extensions[field_key].key_name] = (
                    sanitized_value
                )
            except Exception as err:
                self.logger.debug(
                    message=CONST.LOG_MESSAGE_TEMPLATE.format(
                        self.log_prefix,
                        CONST.EXTENSION_FIELD_ERROR_MESSAGE.format(
                            data_type=data_type,
                            subtype=subtype,
                            field=name,
                            error=err,
                        ),
                    ),
                    details=str(traceback.format_exc()),
                )
        return extension_strs

    def get_cef_event(
        self,
        raw_data,
        headers,
        extensions,
        data_type,
        subtype,
        log_source_identifier,
    ):
        """Build a CEF event.

        Args:
            raw_data (dict): Record being transformed.
            headers (dict): CEF header values.
            extensions (dict): CEF extension values.
            data_type (str): Data type.
            subtype (str): Subtype.
            log_source_identifier (str): Hostname of the Syslog header.

        Returns:
            str: CEF event.
        """
        extension_strs = self._extension_strings(
            extensions, data_type, subtype
        )
        self.log_invalid_header(headers, data_type, subtype)

        cef_components = [
            CONST.CEF_PREFIX_TEMPLATE.format(
                time.strftime(
                    CONST.SYSLOG_TIMESTAMP_FORMAT,
                    time.localtime(time.time()),
                ),
                log_source_identifier,
                self.cef_version,
            )
        ]
        severity_map = (
            CONST.AUDIT_SEVERITY_MAP
            if subtype.lower() == CONST.AUDIT_SUBTYPE
            else CONST.SEVERITY_MAP
        )
        # Always write all six header columns, as an empty value when a
        # header is missing or invalid. Dropping a column would shift the
        # following ones, and QRadar would read the wrong fields.
        for header in CONST.CEF_HEADERS:
            header_value = ""
            if header not in headers:
                cef_components.append(header_value)
                continue
            try:
                if header == CONST.CEF_HEADER_SEVERITY:
                    headers[header] = severity_map.get(
                        str(headers[header]).lower(), CONST.SEVERITY_UNKNOWN
                    )
                header_value = self.get_header_value(header, headers)
            except Exception as err:
                self.logger.debug(
                    message=CONST.LOG_MESSAGE_TEMPLATE.format(
                        self.log_prefix,
                        CONST.HEADER_FIELD_ERROR_MESSAGE.format(
                            data_type=data_type,
                            subtype=subtype,
                            field=header,
                            error=err,
                        ),
                    ),
                    details=str(traceback.format_exc()),
                )
            cef_components.append(header_value)

        if data_type == CONST.WEBTX:
            receipt_time = self.webtx_timestamp(raw_data)
            if receipt_time:
                extension_strs[CONST.CEF_RECEIPT_TIME] = receipt_time

        cef_components.append(
            CONST.CEF_EXTENSION_SEPARATOR.join(
                sorted(
                    CONST.CEF_EXTENSION_TEMPLATE.format(key, value)
                    for key, value in extension_strs.items()
                )
            )
        )
        return self.delimiter.join(cef_components)
