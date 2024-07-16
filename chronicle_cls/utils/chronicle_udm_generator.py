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
"""

"""CLS Google Chronicle Plugin UDM Generator."""


import collections
import traceback

from .chronicle_parser import UDMParser

from .chronicle_constants import (
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
)
from netskope.integrations.cls.utils.sanitizer import *
from netskope.integrations.cls.utils.converter import *


class UDMGenerator(object):
    """UDM Generator class."""

    def __init__(self, mapping, udm_version, logger, log_prefix):
        """Init method."""
        self.logger = logger
        self.log_prefix = log_prefix
        self.udm_version = udm_version  # Version of UDM being used
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
            "UNKNOWN_SEVERITY|Low|Medium|High|Very-High"
        )
        self.valid_extensions = self._valid_extensions()
        self.extension_converters = self._type_converter()

    def _type_converter(self):
        """To Parse the UDM extension CSV string and creates the dict for data type converters.

        Returns:
            Dict object having details of all the available UDM fields and its type converters
        """
        converters = type_converter()

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
            err_msg = (
                "Error occurred while parsing CEF transformation field. "
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc())
            )
            raise

    def _valid_extensions(self):
        """To Parse the given extension CSV string and creates the dict for each provided values with its sanitizers.

        Returns:
            Dict object having details of all the available UDM fields and its sanitizers
        """
        sanitizers = get_sanitizers()

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
            err_msg = (
                "Error occurred while parsing CEF transformation field. "
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc())
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
            possible_headers: Possible UDM headers
            headers: Configured headers
            data_type: Data type for which UDM event is being generated
            subtype: Subtype of data type for which UDM event is being generated
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                err_msg = (
                    f'[{data_type}][{subtype}]: Found invalid header '
                    'configured in chronicle mapping file: '
                    f'"{configured_header}". Header field will be ignored.'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc())
                )

    def get_json_structure(self, udm_field_data, udm_field, value):
        """Get Json structure from udm field."""
        levels = udm_field.split(".")
        if len(levels) == 1:
            udm_field_data[udm_field] = value
            return udm_field_data

        data = udm_field_data.get(levels[0], {})
        udm_field_data[levels[0]] = self.get_json_structure(
            data, ".".join(levels[1:]), value
        )
        return udm_field_data

    def json_converter(self, all_pairs):
        """JSON Converter."""
        udm_data = {}
        for key, value in all_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                udm_data[levels[0]] = value
            else:
                data = udm_data.get(levels[0], {})
                udm_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        return udm_data

    def get_udm_event(self, data, headers, extensions, data_type, subtype):
        """To Produce a UDM compliant message from the arguments.

        Args:
            data: Raw json data from netskope
            data_type: type of data being transformed (alert/event)
            subtype: subtype of data being transformed
            headers: Headers of UDM event
            extensions (dict): key-value pairs for event metadata.
        """
        extension_pairs = {}
        for name, value in extensions.items():
            # First convert the incoming value from Netskope to appropriate data type
            try:
                value = self.extension_converters[name].converter(value, name)
            except KeyError:
                err_msg = (
                    f'[{data_type}][{subtype}]: An error occurred while '
                    f'generating UDM data for field: "{name}". Could not '
                    'find the field in the "valid_extensions". '
                    'Field will be ignored.'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc())
                )
                continue
            except Exception as err:
                err_msg = (
                    f'[{data_type}][{subtype}]: An error occurred while '
                    f'generating UDM data for field: "{name}". '
                    f'Error: {str(err)}. Field will be ignored'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc())
                )
                continue

            # Validate and sanitise (if required) the incoming value from Netskope before mapping it UDM
            try:
                extension_pairs[
                    self.valid_extensions[name].key_name
                ] = self.valid_extensions[name].sanitizer(value, name)
            except KeyError:
                err_msg = (
                    f'[{data_type}][{subtype}]: An error occurred while '
                    f'generating UDM data for field: "{name}". Could not '
                    'find the field in the "valid_extensions". '
                    'Field will be ignored'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc())
                )
            except Exception as err:
                err_msg = (
                    f'[{data_type}][{subtype}]: An error occurred while '
                    f'generating UDM data for field: "{name}". '
                    f'Error: {str(err)}. Field will be ignored.'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc())
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

        # Append the UDM version
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
                    err_msg = (
                        f'[{data_type}][{subtype}]: An error occurred while'
                        f'generating UDM data for header field: "{header}". '
                        f'Error: {str(err)}. Field will be ignored'
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(traceback.format_exc())
                    )

        all_pairs = {**header_pairs, **extension_pairs}

        try:
            udm_generator = UDMParser(
                data, self.logger, self.log_prefix, all_pairs, data_type, subtype
            )
            all_pairs = udm_generator.parse_data()
        except Exception as err:
            err_msg = (
                f'[{data_type}][{subtype}]: An error occurred while '
                f'generating UDM data for header field: "{header}". '
                f'Error: {str(err)}. Fields will be ignored'
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc())
            )

        udm_data = self.json_converter(all_pairs)
        return udm_data
