"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin CEF generator.
"""

import collections
import traceback

from netskope.integrations.cls.utils.sanitizer import *  # noqa: F401,F403
from netskope.integrations.cls.utils.converter import *  # noqa: F401,F403

from .constants import (
    AUDIT_SEVERITY_MAP,
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
)
from .exceptions import AWSCloudWatchPluginError


class CEFGenerator(object):
    """Build CEF lines from the mapped headers and extensions."""

    def __init__(self, mapping, delimiter, cef_version, logger, log_prefix):
        """Initialize CEFGenerator.

        Args:
            mapping (dict): Parsed mapping file.
            delimiter (str): CEF field delimiter.
            cef_version (str): CEF version string.
            logger: Logger object.
            log_prefix (str): Log prefix string.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.cef_version = cef_version
        self.mapping = mapping
        self.extension = collections.namedtuple(
            "Extension", ("key_name", "sanitizer")
        )
        self.extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )
        self._prefix_field_str_sanitizer = str_sanitizer(
            "[^\r\n]*", escape_chars=delimiter
        )
        self._prefix_field_float_sanitizer = float_sanitizer()
        self._equals_escaper = escaper("=")
        self._severity_sanitizer = str_sanitizer(
            "Unknown|Low|Medium|High|Info|Very-High"
        )
        self.valid_extensions = self._valid_extensions()
        self.extension_converters = self._type_converter()
        self.delimiter = delimiter

    def _type_converter(self) -> dict:
        """Build the value converter for every mapped CEF field.

        Returns:
            dict: Field key to converter.

        Raises:
            AWSCloudWatchPluginError: When the mapping cannot be read.
        """
        converters = type_converter()

        try:
            field_converters = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
                if data_type == "json":
                    continue
                for subtype, subtype_mapping in data_mapping.items():
                    for key, value in subtype_mapping.items():
                        for field, field_mapping in value.items():
                            field_converter_key = (
                                f"{data_type.lower()}_{subtype.lower()}"
                                f"_{key}_{field}"
                            )
                            field_converters[field_converter_key] = (
                                self.extension_converter(
                                    key_name=field,
                                    converter=converters[
                                        field_mapping.get(
                                            "transformation", "String"
                                        )
                                    ],
                                )
                            )
            return field_converters
        except Exception as err:
            error_msg = "Error occurred while reading the CEF field types."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)

    def _valid_extensions(self) -> dict:
        """Build the value sanitizer for every mapped CEF field.

        Returns:
            dict: Field key to sanitizer.

        Raises:
            AWSCloudWatchPluginError: When the mapping cannot be read.
        """
        sanitizers = get_sanitizers()

        try:
            field_sanitizers = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
                if data_type == "json":
                    continue
                for subtype, subtype_mapping in data_mapping.items():
                    for key, value in subtype_mapping.items():
                        for field, field_mapping in value.items():
                            field_key = (
                                f"{data_type.lower()}_{subtype.lower()}"
                                f"_{key}_{field}"
                            )
                            field_sanitizers[field_key] = self.extension(
                                key_name=field,
                                sanitizer=sanitizers[
                                    field_mapping.get(
                                        "transformation", "String"
                                    )
                                ],
                            )
            return field_sanitizers
        except Exception as err:
            error_msg = (
                "Error occurred while reading the CEF field sanitizers."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AWSCloudWatchPluginError(error_msg)

    def get_header_value(self, header, headers):
        """Return the clean value of one CEF header.

        Args:
            header (str): Header name.
            headers (dict): All mapped headers.

        Returns:
            str: Clean header value.
        """
        if header == "Severity":
            return self._severity_sanitizer(headers[header], header)
        return self._prefix_field_str_sanitizer(headers[header], header)

    def log_invalid_header(
        self, possible_headers, headers, data_type, subtype
    ):
        """Log every header in the mapping that CEF does not support.

        Args:
            possible_headers (list): Headers CEF supports.
            headers (dict): Headers read from the mapping file.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                self.logger.warn(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Found an"
                    " unsupported header in the mapping file:"
                    f" {configured_header}. This header will be skipped."
                )

    def webtx_timestamp(self, raw_data):
        """Build the webtx event time from the date and time fields.

        Args:
            raw_data (dict): Raw webtx record.

        Returns:
            str: Event time, or None when the fields are missing.
        """
        date = raw_data.get("date", None)
        record_time = raw_data.get("time", None)
        if date and record_time:
            return f"{date}T{record_time}Z"
        return None

    def get_cef_event(
        self,
        raw_data,
        headers,
        extensions,
        data_type,
        subtype,
    ):
        """Build one CEF line from the mapped headers and extensions.

        Args:
            raw_data (dict): Raw record from Netskope.
            headers (dict): Mapped CEF headers.
            extensions (dict): Mapped CEF extensions.
            data_type (str): Data type being transformed.
            subtype (str): Subtype being transformed.

        Returns:
            str: CEF line.
        """
        extension_strs = {}
        for name, value in extensions.items():
            field_key = (
                f"{data_type.lower()}_{subtype.lower()}_extension_{name}"
            )
            try:
                value = self.extension_converters[field_key].converter(
                    value, name
                )
            except KeyError:
                self.logger.warn(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f' not find the field "{name}" in the valid'
                        " extensions list. This field will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
            except Exception as err:
                self.logger.warn(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f' not build the CEF value for the field "{name}".'
                        f" This field will be skipped. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue

            try:
                sanitized_value = self.valid_extensions[field_key].sanitizer(
                    value, name
                )
                if isinstance(sanitized_value, str):
                    sanitized_value = self._equals_escaper(sanitized_value)

                extension_strs[self.valid_extensions[field_key].key_name] = (
                    sanitized_value
                )
            except KeyError:
                self.logger.warn(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f' not find the field "{name}" in the valid'
                        " extensions list. This field will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
            except Exception as err:
                self.logger.warn(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f' not clean the CEF value for the field "{name}".'
                        f" This field will be skipped. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )

        possible_headers = [
            "Device Vendor",
            "Device Product",
            "Device Version",
            "Device Event Class ID",
            "Name",
            "Severity",
        ]

        self.log_invalid_header(possible_headers, headers, data_type, subtype)

        # The CloudWatch Logs API is the transport, not syslog, so the CEF
        # line carries no syslog header (priority, timestamp or host). It
        # starts at the CEF version. CloudWatch stamps each event with its
        # own @timestamp at ingestion.
        cef_components = ["CEF:{}".format(self.cef_version)]

        for header in possible_headers:
            if header in headers:
                try:
                    if header == "Severity":
                        if subtype in ["audit"]:
                            headers[header] = AUDIT_SEVERITY_MAP.get(
                                str(headers[header]).lower(),
                                SEVERITY_UNKNOWN,
                            )
                        else:
                            headers[header] = SEVERITY_MAP.get(
                                str(headers[header]).lower(),
                                SEVERITY_UNKNOWN,
                            )

                    cef_components.append(
                        self.get_header_value(header, headers)
                    )
                except Exception as err:
                    self.logger.warn(
                        f"{self.log_prefix}: [{data_type}][{subtype}] Could"
                        f' not build the CEF value for the header "{header}".'
                        f" This header will be skipped. Error: {err}"
                    )

        if data_type == "webtx":
            date = self.webtx_timestamp(raw_data)
            if date:
                extension_strs["rt"] = date

        extensions_str = " ".join(
            sorted("{}={}".format(k, v) for k, v in extension_strs.items())
        )

        cef_components.append(extensions_str)

        return self.delimiter.join(cef_components)
