"""CEF Generator class."""


import collections
from .cloudtrail_exceptions import CEFTypeError

from netskope.integrations.cls.utils.sanitizer import (
    str_sanitizer,
    float_sanitizer,
    get_sanitizers,
    escaper,
)
from netskope.integrations.cls.utils.converter import type_converter


class CEFGenerator(object):
    """CEF Generator class."""

    def __init__(self, mapping, logger):
        """Init method."""
        self.logger = logger
        self.mapping = mapping
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

    def json_object_sanitizer(self):
        """Wrap function for ensuring the given value is a valid date time instance.

        Raises:
            CEFTypeError in case of value other than datetime

        Returns:
            Function to sanitize the given datetime value
        """

        def sanitize(t, debug_name):
            if not isinstance(t, dict):
                raise CEFTypeError(
                    "{}: Expected Json object, "
                    "got {}".format(debug_name, type(t))
                )
            else:
                return {"details": t}

        return sanitize

    def json_object_converter(self):
        """Wrap function for converting given value to datetime object.

        Raises:
            ECSTypeError in case when value is not datetime compatible

        Returns:
            Function to convert type of given value to datetime
        """

        def convert(val, debug_name):
            try:
                return {"details": val}
            except Exception as err:
                raise CEFTypeError(
                    "{}: Error occurred while converting to "
                    "Json Object: {}".format(
                        debug_name, err
                    )
                )

        return convert

    def _type_converter(self):
        """To Parse the CEF extension CSV string.

        Returns:
            Dict object having details of all the available
            CEF fields and its type converters
        """
        converters = type_converter()

        converters["JSON object"] = self.json_object_converter()

        # Parse the transformation mapping and create key-converter dict
        try:
            field_converters = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
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
                "Error occurred while parsing CEF transformation field. "
                "Error: {}".format(
                    str(err)
                )
            )
            raise

    def _valid_extensions(self):
        """To Parse the given extension CSV string.

        Returns:
            Dict object having details of all the available ECS fields
            and its sanitizers
        """
        sanitizers = get_sanitizers()

        sanitizers["JSON object"] = self.json_object_sanitizer()

        # Parse the transformation mapping and create key-sanitizer dict
        try:
            field_sanitizers = {}
            mapping = self.mapping["taxonomy"]

            for data_type, data_mapping in mapping.items():
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
                "Error occurred while parsing CEF transformation field. "
                "Error: {}".format(str(err))
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
            possible_headers: Possible CEF headers
            headers: Configured headers
            data_type: Data type for which CEF event is being generated
            subtype: Subtype of data type for which CEF event is being
            generated
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                self.logger.error(
                    "[{}][{}]: Found invalid header configured in "
                    'elastic mapping file: "{}". Header '
                    "field will be ignored.".format(
                        data_type, subtype, configured_header
                    )
                )

    def get_json_structure(self, cef_field_data, cef_field, value):
        """Get JSON structure from cef field."""
        levels = cef_field.split(".")
        if len(levels) == 1:
            cef_field_data[cef_field] = value
            return cef_field_data

        data = cef_field_data.get(levels[0], {})
        cef_field_data[levels[0]] = self.get_json_structure(
            data, ".".join(levels[1:]), value
        )
        return cef_field_data

    def json_converter(self, extension_pairs):

        """Convert JSON."""
        cef_data = {}

        for key, value in extension_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                cef_data[levels[0]] = value
            else:
                data = cef_data.get(levels[0], {})
                cef_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        return cef_data

    def get_cef_event(self, extensions, data_type, subtype):
        """To Produce a CEF compliant message from the arguments.

        Args:
            data_type: type of data being transformed (alert/event)
            subtype: subtype of data being transformed
            headers: Headers of CEF event
            extensions (dict): key-value pairs for event metadata.
        """
        extension_pairs = {}
        for name, value in extensions.items():
            try:
                value = self.extension_converters[name].converter(value, name)
            except KeyError:
                self.logger.error(
                    "[{}][{}]: An error occurred while generating "
                    'CEF data for field: "{}". Could not '
                    'find the field in the "valid_extensions". '
                    "Field will be ignored".format(data_type, subtype, name)
                )
                continue
            except Exception as err:
                self.logger.error(
                    "[{}][{}]: An error occurred while generating "
                    'CEF data for field: "{}". Error: {}. '
                    "Field will be ignored".format(
                        data_type, subtype, name, str(err)
                    )
                )
                continue

            try:
                extension_pairs[
                    self.valid_extensions[name].key_name
                ] = self.valid_extensions[name].sanitizer(value, name)
            except KeyError:
                self.logger.error(
                    "[{}][{}]: An error occurred while generating CEF data "
                    'for field: "{}". Could not '
                    'find the field in the "valid_extensions". '
                    "Field will be ignored".format(data_type, subtype, name)
                )
            except Exception as err:
                self.logger.error(
                    "[{}][{}]: An error occurred while generating ECS data "
                    'for field: "{}". Error: {}. '
                    "Field will be ignored".format(
                        data_type, subtype, name, str(err)
                    )
                )

        cef_data = self.json_converter(extension_pairs)

        return cef_data
