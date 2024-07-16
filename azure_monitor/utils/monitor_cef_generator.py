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

Azure Monitor Plugin."""

import datetime
import collections
import traceback
from netskope.integrations.cls.utils.sanitizer import *
from netskope.integrations.cls.utils.converter import *
from .monitor_exceptions import CEFTypeError


class CEFGenerator(object):
    """CEF Generator class."""

    def __init__(self, mapping, delimiter, cef_version, logger, log_prefix):
        """Init method."""
        self.logger = logger
        self.log_prefix = log_prefix
        self.cef_version = cef_version  # Version of CEF being used
        self.mapping = mapping  # Mapping file content
        self.extension = collections.namedtuple("Extension", ("key_name", "sanitizer"))
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

    def timestamp_object_converter(self):
        """Wrap function for converting given value to datetime object.

        Raises:
            ECSTypeError in case when value is not datetime compatible

        Returns:
            Function to convert type of given value to datetime
        """

        def convert(val, debug_name):
            try:
                if isinstance(val, str):
                    return datetime.datetime.strptime(val, "%Y-%m-%dT%H:%M:%S+00:00")
                if isinstance(val, int):
                    return datetime.datetime.fromtimestamp(val)
            except Exception as err:
                raise CEFTypeError(
                    "{}: Error occurred while converting to "
                    "Json Object: {}".format(debug_name, err)
                )

        return convert

    def _type_converter(self):
        """To Parse the CEF transformation mapping and creates the dict for data type converters.

        Returns:
            Dict object having details of all the available CEF fields and its type converters
        """
        converters = type_converter()
        converters["Time Stamp"] = self.timestamp_object_converter()

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
                                    field_mapping.get("transformation", "String")
                                ],
                            )
            return field_converters
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while parsing CEF "
                    f"transformation field. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise

    def _valid_extensions(self):
        """To Parse the given transformation mapping and creates the dict for each provided values with its sanitizers.

        Returns:
            Dict object having details of all the available CEF fields and its sanitizers
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
                                    field_mapping.get("transformation", "String")
                                ],
                            )
            return field_sanitizers
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while parsing CEF "
                    f"transformation field. Error: {err}"
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
        if header == "Severity":
            return self._severity_sanitizer(headers[header], header)
        return self._prefix_field_str_sanitizer(headers[header], header)

    def webtx_timestamp(self, raw_data):
        date = raw_data.get("date", None)
        time = raw_data.get("time", None)
        if date and time:
            return f"{date}T{time}Z"
        return None

    def get_cef_event(
        self,
        raw_data,
        headers,
        extensions,
        data_type,
        subtype,
    ):
        """To Produce a CEF compliant message from the arguments.

        Args:
            data_type: type of data being transformed (alert/event)
            subtype: subtype of data being transformed
            headers: Headers of CEF event
            extensions (dict): key-value pairs for event metadata.
        """
        extension_strs = {}
        for name, value in extensions.items():
            # First convert the incoming value from Netskope to appropriate data type
            try:
                value = self.extension_converters[name].converter(value, name)
            except KeyError:
                self.logger.error(
                    message=(
                        '{}: [{}][{}]: An error occurred while generating CEF data for field: "{}". Could not '
                        'find the field in the "valid_extensions". Field will be ignored'.format(
                            self.log_prefix, data_type, subtype, name
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        '{}: [{}][{}]: An error occurred while generating CEF data for field: "{}". Error: {}. '
                        "Field will be ignored".format(
                            self.log_prefix, data_type, subtype, name, str(err)
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                continue

            # Validate and sanitise (if required) the incoming value from Netskope before mapping it CEF
            try:
                sanitized_value = self.valid_extensions[name].sanitizer(value, name)
                if isinstance(sanitized_value, str):
                    sanitized_value = self._equals_escaper(sanitized_value)

                extension_strs[self.valid_extensions[name].key_name] = sanitized_value
            except KeyError:
                self.logger.error(
                    message=(
                        '{}: [{}][{}]: An error occurred while generating CEF data for field: "{}". Could not '
                        'find the field in the "valid_extensions". Field will be ignored'.format(
                            self.log_prefix, data_type, subtype, name
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        '{}: [{}][{}]: An error occurred while generating CEF data for field: "{}". Error: {}. '
                        "Field will be ignored".format(
                            self.log_prefix, data_type, subtype, name, str(err)
                        )
                    ),
                    details=str(traceback.format_exc()),
                )

        if data_type == "webtx":
            date = self.webtx_timestamp(raw_data)
            if date:
                extension_strs["rt"] = date

        extensions_str = " ".join(
            sorted("{}={}".format(k, v) for k, v in extension_strs.items())
        )

        return extensions_str
