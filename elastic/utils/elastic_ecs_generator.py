"""ECS Generator class."""
import io
import collections
import csv
import datetime
import datetime as dt
import re

from .elastic_constants import (
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
)
from .elastic_exceptions import (
    ECSValueError,
    ECSTypeError,
)


class ECSGenerator(object):
    """ECS Generator class."""

    def __init__(self, extensions, ecs_version, logger):
        """Init method."""
        self.logger = logger
        self.ecs_version = ecs_version  # Version of ECS being used
        self.extensions = extensions  # CSV string having information of all the available ECS fields
        self.extension = collections.namedtuple(
            "Extension", ("key_name", "sanitizer")
        )
        self.extension_converter = collections.namedtuple(
            "Extension", ("key_name", "converter")
        )
        self._prefix_field_str_sanitizer = self.str_sanitizer("[^\r\n]*")
        self._prefix_field_float_sanitizer = self.float_sanitizer()
        self._equals_escaper = self.escaper("=")
        self._severity_sanitizer = self.str_sanitizer(
            "Unknown|Low|Medium|High|Very-High"
        )
        self.valid_extensions = self._valid_extensions()
        self.extension_converters = self._type_converter()

    def escaper(self, special_chars):
        """Escapes the given special characters.

        Args:
            special_chars: The special characters to be escaped

        Returns:
            Escaped special characters
        """
        strip_escaped_re = re.compile(r"\\([{}\\])".format(special_chars))
        do_escape_re = re.compile(r"([{}\\])".format(special_chars))

        def escape(s):
            stripped = strip_escaped_re.sub(r"\1", s)
            return do_escape_re.sub(r"\\\1", stripped)

        return escape

    def ensure_in_range(self, debug_name, min, max, num):
        """To Check whether the given value is in given range or not.

        Args:
            debug_name: The human readable name of the value being verified
            min: Min value of threshold
            max: Max value of threshold
            num: The value to be verified

        Raises:
            ECSValueError in case of value is not in given threshold

        Returns:
            Escaped special characters
        """
        if max is None:
            if min is not None and num < min:
                raise ECSValueError(
                    "{}: {} less than {}".format(debug_name, num, min)
                )
        elif min is None:
            if max is not None and num > max:
                raise ECSValueError(
                    "{}: {} greater than {}".format(debug_name, num, max)
                )
        elif not min <= num <= max:
            raise ECSValueError(
                "{}: {} out of range {}-{}".format(debug_name, num, min, max)
            )

    def int_sanitizer(self, max=None, min=None):
        """Wrap function for ensuring the given value is integer and in given range.

        Args:
            min: Min value of threshold
            max: Max value of threshold

        Raises:
            ECSTypeError in case of value other than integer

        Returns:
            Function to sanitize the given integer value
        """

        def sanitize(n, debug_name):
            if not isinstance(n, int):
                raise ECSTypeError(
                    "{}: Expected int, got {}".format(debug_name, type(n))
                )
            self.ensure_in_range(debug_name, min, max, n)
            return n

        return sanitize

    def float_sanitizer(self):
        """Wrap function for ensuring the given value is float.

        Raises:
            ECSTypeError in case of value other than float

        Returns:
            Function to sanitize the given float value
        """

        def sanitize(n, debug_name):
            if not isinstance(n, float):
                raise ECSTypeError(
                    "{}: Expected float, got {}".format(debug_name, type(n))
                )
            else:
                return n

        return sanitize

    def str_sanitizer(
        self, regex_str=".*", escape_chars="", min_len=0, max_len=None
    ):
        """Wrap function for ensuring the given value is string and has specific properties.

        Args:
            regex_str: The regex to be matched in given string
            escape_chars: The characters to be escaped in given string
            min_len: The min possible length of given string
            max_len: The max possible length of given string

        Raises:
            ECSTypeError in case of value other than string

        Returns:
            Function to sanitize the given string
        """
        regex = re.compile("^{}$".format(regex_str), re.DOTALL)
        escape = self.escaper(escape_chars)

        def sanitize(s, debug_name):
            if not isinstance(s, str):
                raise ECSTypeError(
                    "{}: Expected str, got {}".format(debug_name, type(s))
                )
            if not regex.match(s):
                raise ECSTypeError(
                    "{}: {!r} did not match regex {!r}".format(
                        debug_name, s, regex_str
                    )
                )

            s = s.encode("unicode_escape").decode("utf-8")
            escaped = escape(s)
            if max_len is None and not min_len:
                return escaped

            byte_len = len(escaped)
            if (max_len is None) and (byte_len < min_len):
                raise ECSTypeError(
                    "{}: String shorter than {} bytes".format(
                        debug_name, min_len
                    )
                )

            if (max_len is not None) and not min_len <= byte_len <= max_len:
                raise ECSTypeError(
                    "{}: String length out of range {}-{}".format(
                        debug_name, min_len, max_len
                    )
                )
            return escaped

        return sanitize

    def datetime_sanitizer(self):
        """Wrap function for ensuring the given value is a valid date time instance.

        Raises:
            ECSTypeError in case of value other than datetime

        Returns:
            Function to sanitize the given datetime value
        """

        def sanitize(t, debug_name):
            if not isinstance(t, dt.datetime):
                raise ECSTypeError(
                    "{}: Expected datetime, got {}".format(debug_name, type(t))
                )
            else:
                return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        return sanitize

    def string_converter(self):
        """Wrap function for converting given value to string.

        Raises:
            ECSTypeError in case when value is not string compatible

        Returns:
            Function to convert type of given value to string
        """

        def convert(val, debug_name):
            try:
                return str(val)
            except Exception:
                raise ECSTypeError(
                    "{}: Error occurred while converting to string".format(
                        debug_name
                    )
                )

        return convert

    def int_converter(self):
        """Wrap function for converting given value to integer.

        Raises:
            ECSTypeError in case when value is not integer compatible

        Returns:
            Function to convert type of given value to integer
        """

        def convert(val, debug_name):
            try:
                return int(val)
            except Exception:
                raise ECSTypeError(
                    "{}: Error occurred while converting to integer".format(
                        debug_name
                    )
                )

        return convert

    def float_converter(self):
        """Wrap function for converting given value to floating point.

        Raises:
            ECSTypeError in case when value is not float compatible

        Returns:
            Function to convert type of given value to float
        """

        def convert(val, debug_name):
            try:
                return float(val)
            except Exception:
                raise ECSTypeError(
                    "{}: Error occurred while converting to float".format(
                        debug_name
                    )
                )

        return convert

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
                    "{}: Error occurred while converting to datetime: {}".format(
                        debug_name, err
                    )
                )

        return convert

    def _type_converter(self):
        """To Parse the ECS extension CSV string and creates the dict for data type converters.

        Returns:
            Dict object having details of all the available ECS fields and its type converters
        """
        converters = {
            "String": self.string_converter(),
            "DateTime": self.datetime_converter(),
            "Time Stamp": self.datetime_converter(),
            "Integer": self.int_converter(),
            "Floating Point": self.float_converter(),
            "IPv4 Address": self.string_converter(),
            "IPv6 address": self.string_converter(),
            "MAC Address": self.string_converter(),
            "IP Address": self.string_converter(),
        }

        # Parse the CSV and create key-converter dict
        try:
            return {
                record["ECS Key Name"]: self.extension_converter(
                    key_name=record["ECS Key Name"],
                    converter=converters[record["Data Type"]],
                )
                for record in csv.DictReader(
                    io.StringIO(self.extensions), strict=True
                )
            }
        except Exception as err:
            self.logger.error(
                "Error occurred while parsing ECS validation CSV. Error: {}".format(
                    str(err)
                )
            )
            raise

    def _valid_extensions(self):
        """To Parse the given extension CSV string and creates the dict for each provided values with its sanitizers.

        Returns:
            Dict object having details of all the available ECS fields and its sanitizers
        """
        # Initialize the sanitizers for different data types
        # ipv4_addr_re = r"\.".join([r"\d{1,3}"] * 4)
        ipv4_addr_re = (
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]"
            r"[0-9]|25[0-5])$"
        )
        ipv4_addr = self.str_sanitizer(ipv4_addr_re)
        ipv6_addr_re = r"\:".join(
            ["[0-9a-fA-F]{1,4}"] * 8
        )  # only complete ipv6 address accepted
        ipv6_addr = self.str_sanitizer(ipv6_addr_re)
        ip_addr = self.str_sanitizer(
            r"(" + ipv6_addr_re + r"|" + ipv4_addr_re + r")"
        )
        mac_addr = self.str_sanitizer(r"\:".join(["[0-9a-fA-F]{2}"] * 6))
        str_lens = [31, 40, 63, 100, 128, 200, 255, 1023, 2048, 4000, 8000]
        sanitizers = {
            "IPv4 Address": {"": ipv4_addr},
            "IPv6 address": {"": ipv6_addr},
            "IP Address": {"": ip_addr},
            "MAC Address": {"": mac_addr},
            "DateTime": {"": self.datetime_sanitizer()},
            "Time Stamp": {"": self.datetime_sanitizer()},
            "Floating Point": {"": self.float_sanitizer()},
            "Integer": {
                "": self.int_sanitizer(),
                "65535": self.int_sanitizer(min=0, max=65535),
            },
            "String": dict(
                [("", self.str_sanitizer())]
                + [
                    (str(str_len), self.str_sanitizer(max_len=str_len))
                    for str_len in str_lens
                ]
            ),
        }

        # Parse the CSV and create key-sanitizer dict
        try:
            return {
                record["ECS Key Name"]: self.extension(
                    key_name=record["ECS Key Name"],
                    sanitizer=sanitizers[record["Data Type"]][
                        record["Length"]
                    ],
                )
                for record in csv.DictReader(
                    io.StringIO(self.extensions), strict=True
                )
            }
        except Exception as err:
            self.logger.error(
                "Error occurred while parsing ECS validation CSV. Error: {}".format(
                    str(err)
                )
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
            subtype: Subtype of data type for which ECS event is being generated
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                self.logger.error(
                    '[{}][{}]: Found invalid header configured in syslog mapping file: "{}". Header '
                    "field will be ignored.".format(
                        data_type, subtype, configured_header
                    )
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
            # First convert the incoming value from Netskope to appropriate data type
            try:
                value = self.extension_converters[name].converter(value, name)
            except KeyError:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating ECS data for field: "{}". Could not '
                    'find the field in the "valid_extensions". Field will be ignored'.format(
                        data_type, subtype, name
                    )
                )
                continue
            except Exception as err:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating ECS data for field: "{}". Error: {}. '
                    "Field will be ignored".format(
                        data_type, subtype, name, str(err)
                    )
                )
                continue

            # Validate and sanitise (if required) the incoming value from Netskope before mapping it ECS
            try:
                extension_pairs[
                    self.valid_extensions[name].key_name
                ] = self.valid_extensions[name].sanitizer(value, name)
            except KeyError:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating ECS data for field: "{}". Could not '
                    'find the field in the "valid_extensions". Field will be ignored'.format(
                        data_type, subtype, name
                    )
                )
            except Exception as err:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating ECS data for field: "{}". Error: {}. '
                    "Field will be ignored".format(
                        data_type, subtype, name, str(err)
                    )
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
                        '[{}][{}]: An error occurred while generating ECS data for header field: "{}". Error: {}. '
                        "Field will be ignored".format(
                            data_type, subtype, header, str(err)
                        )
                    )

        ecs_data = self.json_converter(header_pairs, extension_pairs)
        return ecs_data
