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

CLS Elastic plugin's ECS Generator class.
"""

import collections
import datetime
import traceback

from .elastic_constants import (
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
    BOOLEAN_FIELDS,
)
from .elastic_exceptions import ECSTypeError
from netskope.integrations.cls.utils.sanitizer import *
from netskope.integrations.cls.utils.converter import *


class ECSGenerator(object):
    """ECS Generator class."""

    def __init__(self, mapping, ecs_version, logger, log_prefix):
        """Init method."""
        self.logger = logger
        self.log_prefix = log_prefix
        self.ecs_version = ecs_version  # Version of ECS being used
        self.mapping = mapping  # Mapping file content
        self.extension = collections.namedtuple(
            "Extension", ("key_name", "sanitizer")
        )
        self.extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )
        self._prefix_field_str_sanitizer = str_sanitizer("[^\r\n]*")
        self._prefix_field_float_sanitizer = float_sanitizer()
        self._equals_escaper = escaper("=")
        self._severity_sanitizer = str_sanitizer(
            "Unknown|Low|Medium|High|Very-High"
        )
        self.valid_extensions = self._valid_extensions()
        self.extension_converters = self._type_converter()

    def datetime_sanitizer(self):
        """Wrap function for ensuring the given value is a valid date time instance.

        Raises:
            ECSTypeError in case of value other than datetime

        Returns:
            Function to sanitize the given datetime value
        """

        def sanitize(t, debug_name):
            if not isinstance(t, datetime.datetime):
                raise ECSTypeError(
                    f"{self.log_prefix}: {debug_name}- Expected"
                    f" datetime, got {type(t)}"
                )
            else:
                return t.strftime(r"%Y-%m-%dT%H:%M:%S.000Z")

        return sanitize

    def datetime_converter(self):
        """Wrap function for converting given value to datetime object.

        Raises:
            ECSTypeError in case when value is not datetime compatible

        Returns:
            Function to convert type of given value to datetime
        """

        def convert(val, debug_name):
            try:
                return datetime.datetime.fromtimestamp(val)
            except Exception as err:
                raise ECSTypeError(
                    f"{self.log_prefix}: {debug_name} - Error "
                    f"occurred while converting to datetime: {err}"
                )

        return convert

    def _type_converter(self):
        """To Parse the ECS extension CSV string and creates the dict for data type converters.

        Returns:
            Dict object having details of all the available ECS fields and its type converters
        """
        converters = type_converter()

        converters["DateTime"] = self.datetime_converter()
        converters["Time Stamp"] = self.datetime_converter()

        # Parse the transformation mapping and create key-converter dict
        try:
            field_converters = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
                if data_type == "json":
                    continue
                for subtype, subtype_mapping in data_mapping.items():
                    for key, value in subtype_mapping.items():
                        for field, field_mapping in value.items():
                            field_converters[field] = self.extension_converter(
                                key_name=field,
                                converter=converters[
                                    field_mapping.get(
                                        "transformation", "String"
                                    )
                                ],
                            )
            return field_converters
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while parsing "
                    f"ECS transformation field. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise

    def _valid_extensions(self):
        """To Parse the given extension CSV string and creates the dict for each provided values with its sanitizers.

        Returns:
            Dict object having details of all the available ECS fields and its sanitizers
        """
        sanitizers = get_sanitizers()

        sanitizers["DateTime"] = self.datetime_sanitizer()
        sanitizers["Time Stamp"] = self.datetime_sanitizer()

        # Parse the transformation mapping and create key-sanitizer dict
        try:
            field_sanitizers = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
                if data_type == "json":
                    continue
                for subtype, subtype_mapping in data_mapping.items():
                    for key, value in subtype_mapping.items():
                        for field, field_mapping in value.items():
                            field_sanitizers[field] = self.extension(
                                key_name=field,
                                sanitizer=sanitizers[
                                    field_mapping.get(
                                        "transformation", "String"
                                    )
                                ],
                            )
            return field_sanitizers
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while parsing"
                    f" ECS transformation field. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise

    def get_header_value(self, header, headers):
        """To Fetch sanitized value of header from given configured headers dict.

        Args:
            header: The header for which sanitized value is to be fetched
            headers: Configured headers

        Returns:
            Sanitized value
        """
        if header == "security_result.severity":
            return self._severity_sanitizer(headers[header], header)
        return self._prefix_field_str_sanitizer(headers[header], header)

    def log_invalid_header(
        self, possible_headers, headers, data_type, subtype
    ):
        """Issues log in case of invalid header found in mappings.

        Args:
            possible_headers: Possible ECS headers
            headers: Configured headers
            data_type: Data type for which ECS event is being generated
            subtype: Subtype of data type for which ECS event is being
            generated
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                self.logger.error(
                    f"{self.log_prefix}: [{data_type}][{subtype}] -"
                    " Found invalid header configured in elastic"
                    f' mapping file: "{configured_header}". Header '
                    "field will be ignored."
                )

    def get_json_structure(self, ecs_field_data, ecs_field, value):
        """Get JSON structure from ecs field."""
        levels = ecs_field.split(".")
        if len(levels) == 1:
            ecs_field_data[ecs_field] = value
            return ecs_field_data

        data = ecs_field_data.get(levels[0], {})
        ecs_field_data[levels[0]] = self.get_json_structure(
            data, ".".join(levels[1:]), value
        )
        return ecs_field_data

    def json_converter(self, header_pairs, extension_pairs):
        """Convert JSON."""
        ecs_data = {}
        for key, value in header_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                ecs_data[levels[0]] = value
            else:
                data = ecs_data.get(levels[0], {})
                ecs_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        for key, value in extension_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                ecs_data[levels[0]] = value
            else:
                data = ecs_data.get(levels[0], {})
                ecs_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        return ecs_data

    def get_ecs_event(self, headers, extensions, data_type, subtype):
        """To Produce a ECS compliant message from the arguments.

        Args:
            data_type: type of data being transformed (alert/event)
            subtype: subtype of data being transformed
            headers: Headers of ECS event
            extensions (dict): key-value pairs for event metadata.
        """
        extension_pairs = {}
        for name, value in extensions.items():
            # First convert the incoming value from Netskope to appropriate
            # data type
            try:
                value = self.extension_converters[name].converter(value, name)
            except KeyError:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] - An "
                        f"error occurred while generating ECS data for field:"
                        f' "{name}". Could not find the field in the  '
                        '"valid_extensions". Field will be ignored'
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] - An "
                        "error occurred while generating ECS data for field: "
                        f'"{name}". Error: {err}. Field will be ignored.'
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
            # Validate and sanitize (if required) the incoming value from
            # Netskope before mapping it ECS
            try:
                current = self.valid_extensions[name].key_name
                extension_pairs[current] = self.valid_extensions[
                    name
                ].sanitizer(value, name)

                if (current in BOOLEAN_FIELDS) and (
                    extension_pairs[current]
                    not in ["Yes", "No", True, False, "", "True", "False"]
                ):
                    extension_pairs[current] = ""
            except KeyError:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] - An "
                        f"error occurred while generating ECS data for field: "
                        f'"{name}". Could not find the field in the '
                        '"valid_extensions". Field will be ignored.'
                    ),
                    details=str(traceback.format_exc()),
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: [{data_type}][{subtype}] - An "
                        f"error occurred while generating ECS data for field: "
                        f'"{name}". Error: {err}. Field will be ignored.'
                    ),
                    details=str(traceback.format_exc()),
                )

        possible_headers = [
            "metadata.event_timestamp",
            "metadata.product_name",
            "metadata.product_version",
            "metadata.product_event_type",
            "metadata.event_type",
            "security_result.severity",
        ]

        self.log_invalid_header(possible_headers, headers, data_type, subtype)

        # Append the ECS version
        header_pairs = {}

        # Append other headers if available
        for header in possible_headers:
            if header in headers:
                try:
                    if header == "security_result.severity":
                        headers[header] = SEVERITY_MAP.get(
                            str(headers[header]).lower(), SEVERITY_UNKNOWN
                        )
                    header_pairs[header] = self.get_header_value(
                        header, headers
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] - An"
                            f" error occurred while generating ECS data for"
                            f' header field: "{header}". Error: {err}. '
                            "Field will be ignored."
                        ),
                        details=str(traceback.format_exc()),
                    )

        ecs_data = self.json_converter(header_pairs, extension_pairs)
        return ecs_data
