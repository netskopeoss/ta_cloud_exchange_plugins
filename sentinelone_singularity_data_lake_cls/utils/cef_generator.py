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

SentinelOne Singularity Data Lake CEF generator.

Builds plain CEF lines for the HEC /raw endpoint:

    CEF:0|Device Vendor|Device Product|Device Version|Event Class ID|
    Name|Severity|key=value key=value ...

No syslog prefix (date and host) is added: HEC /raw takes the CEF line
as it is.
"""

import traceback
from typing import Any, Callable, Dict, Tuple

from netskope.integrations.cls.utils.converter import type_converter
from netskope.integrations.cls.utils.sanitizer import (
    escaper,
    get_sanitizers,
    str_sanitizer,
)

from .constants import (
    AUDIT_SEVERITY_MAP,
    CEF_HEADERS,
    DATA_TYPE_WEBTX,
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
    WEBTX_DATE_FIELD,
    WEBTX_TIME_FIELD,
)
from .exceptions import EmptyExtensionError, MappingValidationError
from .utilities import is_soft_time_limit


class CEFGenerator:
    """Turns header and extension values into one CEF line."""

    def __init__(
        self,
        extension_mapping: Dict,
        delimiter: str,
        cef_version: str,
        logger: Any,
        log_prefix: str,
    ):
        """Prepare the converter and sanitizer of each extension field.

        Only the extension mapping of the subtype being transformed is
        read, so a problem in another part of a custom mapping cannot
        stop this subtype.

        Args:
            extension_mapping (Dict): CEF extension mapping of one
                subtype.
            delimiter (str): CEF delimiter, "|".
            cef_version (str): CEF version, "0".
            logger (Any): Cloud Exchange logger.
            log_prefix (str): Prefix put in front of every log message.

        Raises:
            MappingValidationError: If a field definition is not an
                object or has an unknown "transformation" value.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.extension_mapping = extension_mapping
        self.delimiter = delimiter
        self.cef_version = cef_version
        self._header_sanitizer = str_sanitizer(
            "[^\r\n]*", escape_chars=delimiter
        )
        self._severity_sanitizer = str_sanitizer(
            "Unknown|Low|Medium|High|Info|Very-High"
        )
        self._equals_escaper = escaper("=")
        self.field_handlers = self._build_field_handlers()

    def _build_field_handlers(self) -> Dict[str, Tuple[Callable, Callable]]:
        """Pick a converter and sanitizer for every extension field.

        Returns:
            Dict[str, Tuple[Callable, Callable]]: (converter, sanitizer)
                per extension field name.

        Raises:
            MappingValidationError: If a field definition is not an
                object or its "transformation" is unknown.
        """
        converters = type_converter()
        sanitizers = get_sanitizers()
        handlers = {}
        for field, field_mapping in self.extension_mapping.items():
            if not isinstance(field_mapping, dict):
                raise MappingValidationError(
                    f"CEF field '{field}' must be an object."
                )
            transformation = field_mapping.get("transformation", "String")
            if (
                transformation not in converters
                or transformation not in sanitizers
            ):
                raise MappingValidationError(
                    f"CEF field '{field}' has an unknown transformation"
                    f" '{transformation}'."
                )
            handlers[field] = (
                converters[transformation],
                sanitizers[transformation],
            )
        return handlers

    def _get_header_value(
        self, header: str, headers: Dict, subtype: str
    ) -> str:
        """Read and clean one header value.

        Missing or invalid headers become an empty string, so the line
        always has all seven CEF header slots.

        Args:
            header (str): Header name.
            headers (Dict): Header values for this record.
            subtype (str): Subtype, used for the severity map.

        Returns:
            str: Clean header value.
        """
        if header not in headers:
            return ""
        value = headers[header]
        try:
            if header == "Severity":
                severity_map = (
                    AUDIT_SEVERITY_MAP
                    if str(subtype).lower() == "audit"
                    else SEVERITY_MAP
                )
                value = severity_map.get(
                    str(value).lower(), SEVERITY_UNKNOWN
                )
                return self._severity_sanitizer(value, header)
            return self._header_sanitizer(str(value), header)
        except Exception as err:
            if is_soft_time_limit(err):
                raise
            self.logger.debug(
                f"{self.log_prefix}: CEF header '{header}' has a bad value"
                f" and was left empty. Error: {err}"
            )
            return ""

    @staticmethod
    def _webtx_receipt_time(raw_data: Dict) -> str:
        """Build the CEF "rt" value from WebTx date and time.

        Args:
            raw_data (Dict): WebTx record.

        Returns:
            str: "<date>T<time>Z", or an empty string.
        """
        date_value = raw_data.get(WEBTX_DATE_FIELD)
        time_value = raw_data.get(WEBTX_TIME_FIELD)
        if date_value and time_value:
            return f"{date_value}T{time_value}Z"
        return ""

    def get_cef_event(
        self,
        raw_data: Dict,
        headers: Dict,
        extensions: Dict,
        data_type: str,
        subtype: str,
    ) -> str:
        """Build one CEF line.

        Args:
            raw_data (Dict): Original Netskope record.
            headers (Dict): Header values for this record.
            extensions (Dict): Extension values for this record.
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            str: CEF line with no raw line breaks.

        Raises:
            EmptyExtensionError: If no extension value could be used.
        """
        extension_values = {}
        for name, value in extensions.items():
            handler = self.field_handlers.get(name)
            if not handler:
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] CEF field"
                    f" '{name}' is not in the mapping. It was skipped."
                )
                continue
            converter, sanitizer = handler
            try:
                clean = sanitizer(converter(value, name), name)
                if isinstance(clean, str):
                    clean = self._equals_escaper(clean)
                extension_values[name] = clean
            except Exception as err:
                if is_soft_time_limit(err):
                    raise
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] CEF"
                        f" field '{name}' has a bad value. It was skipped."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )

        if data_type == DATA_TYPE_WEBTX:
            receipt_time = self._webtx_receipt_time(raw_data)
            if receipt_time:
                extension_values["rt"] = self._equals_escaper(receipt_time)

        if not extension_values:
            raise EmptyExtensionError(
                "No CEF extension value could be built for this record."
            )

        for header in headers:
            if header not in CEF_HEADERS:
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Unknown"
                    f" CEF header '{header}' in the mapping. It was"
                    " skipped."
                )

        components = [f"CEF:{self.cef_version}"]
        components.extend(
            self._get_header_value(header, headers, subtype)
            for header in CEF_HEADERS
        )
        components.append(
            " ".join(
                sorted(f"{k}={v}" for k, v in extension_values.items())
            )
        )
        line = self.delimiter.join(components)
        # /raw uses one line per event. A raw line break inside a value
        # would split one event into two, so turn it into text.
        return line.replace("\r", "\\r").replace("\n", "\\n")
