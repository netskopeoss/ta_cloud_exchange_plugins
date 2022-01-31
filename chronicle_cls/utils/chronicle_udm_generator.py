"""Syslog Plugin."""
import io
import collections
import csv
import datetime
import datetime as dt
import re

from .chronicle_constants import (
    SEVERITY_MAP,
    SEVERITY_UNKNOWN,
)
from .chronicle_exceptions import (
    UDMValueError,
    UDMTypeError,
)


class UDMGenerator(object):
    """UDM Generator class."""

    def __init__(self, extensions, udm_version, logger):
        """Init method."""
        self.logger = logger
        self.udm_version = udm_version  # Version of UDM being used
        self.extensions = extensions  # CSV string having information of
        # all the available UDM fields
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
            "UNKNOWN_SEVERITY|Low|Medium|High|Very-High"
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
            UDMValueError in case of value is not in given threshold

        Returns:
            Escaped special characters
        """
        if max is None:
            if min is not None and num < min:
                raise UDMValueError(
                    "{}: {} less than {}".format(debug_name, num, min)
                )
        elif min is None:
            if max is not None and num > max:
                raise UDMValueError(
                    "{}: {} greater than {}".format(debug_name, num, max)
                )
        elif not min <= num <= max:
            raise UDMValueError(
                "{}: {} out of range {}-{}".format(debug_name, num, min, max)
            )

    def int_sanitizer(self, max=None, min=None):
        """Wrap function for ensuring given value is integer & in given range.

        Args:
            min: Min value of threshold
            max: Max value of threshold

        Raises:
            UDMTypeError in case of value other than integer

        Returns:
            Function to sanitize the given integer value
        """

        def sanitize(n, debug_name):
            if not isinstance(n, int):
                raise UDMTypeError(
                    "{}: Expected int, got {}".format(debug_name, type(n))
                )
            self.ensure_in_range(debug_name, min, max, n)
            return n

        return sanitize

    def float_sanitizer(self):
        """Wrap function for ensuring the given value is float.

        Raises:
            UDMTypeError in case of value other than float

        Returns:
            Function to sanitize the given float value
        """

        def sanitize(n, debug_name):
            if not isinstance(n, float):
                raise UDMTypeError(
                    "{}: Expected float, got {}".format(debug_name, type(n))
                )
            else:
                return n

        return sanitize

    def str_sanitizer(
        self, regex_str=".*", escape_chars="", min_len=0, max_len=None
    ):
        """Wrap func to check given value is string & has specific properties.

        Args:
            regex_str: The regex to be matched in given string
            escape_chars: The characters to be escaped in given string
            min_len: The min possible length of given string
            max_len: The max possible length of given string

        Raises:
            UDMTypeError in case of value other than string

        Returns:
            Function to sanitize the given string
        """
        regex = re.compile("^{}$".format(regex_str), re.DOTALL)
        escape = self.escaper(escape_chars)

        def sanitize(s, debug_name):
            if not isinstance(s, str):
                raise UDMTypeError(
                    "{}: Expected str, got {}".format(debug_name, type(s))
                )
            if not regex.match(s):
                raise UDMTypeError(
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
                raise UDMTypeError(
                    "{}: String shorter than {} bytes".format(
                        debug_name, min_len
                    )
                )

            if (max_len is not None) and not min_len <= byte_len <= max_len:
                raise UDMTypeError(
                    "{}: String length out of range {}-{}".format(
                        debug_name, min_len, max_len
                    )
                )
            return escaped

        return sanitize

    def datetime_sanitizer(self):
        """Wrap function to check given value is a valid date time instance.

        Raises:
            UDMTypeError in case of value other than datetime

        Returns:
            Function to sanitize the given datetime value
        """

        def sanitize(t, debug_name):
            if not isinstance(t, dt.datetime):
                raise UDMTypeError(
                    "{}: Expected datetime, got {}".format(debug_name, type(t))
                )
            else:
                return str(t.timestamp()).split(".")[0]

        return sanitize

    def string_converter(self):
        """Wrap function for converting given value to string.

        Raises:
            UDMTypeError in case when value is not string compatible

        Returns:
            Function to convert type of given value to string
        """

        def convert(val, debug_name):
            try:
                return str(val)
            except Exception:
                raise UDMTypeError(
                    "{}: Error occurred while converting to string".format(
                        debug_name
                    )
                )

        return convert

    def int_converter(self):
        """Wrap function for converting given value to integer.

        Raises:
            UDMTypeError in case when value is not integer compatible

        Returns:
            Function to convert type of given value to integer
        """

        def convert(val, debug_name):
            try:
                return int(val)
            except Exception:
                raise UDMTypeError(
                    "{}: Error occurred while converting to integer".format(
                        debug_name
                    )
                )

        return convert

    def float_converter(self):
        """Wrap function for converting given value to floating point.

        Raises:
            UDMTypeError in case when value is not float compatible

        Returns:
            Function to convert type of given value to float
        """

        def convert(val, debug_name):
            try:
                return float(val)
            except Exception:
                raise UDMTypeError(
                    "{}: Error occurred while converting to float".format(
                        debug_name
                    )
                )

        return convert

    def datetime_converter(self):
        """Wrap function for converting given value to datetime object.

        Raises:
            UDMTypeError in case when value is not datetime compatible

        Returns:
            Function to convert type of given value to datetime
        """

        def convert(val, debug_name):
            try:
                return datetime.datetime.fromtimestamp(val)
            except Exception as err:
                raise UDMTypeError(
                    f"{debug_name}: Error occurred while converting to "
                    f"datetime: {err}."
                )

        return convert

    def _type_converter(self):
        """To Parse the UDM extension CSV string and creates the dict for data type converters.

        Returns:
            Dict object having details of all the available UDM fields and its type converters
        """
        converters = {
            "String": self.string_converter(),
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
                record["UDM Key Name"]: self.extension_converter(
                    key_name=record["UDM Key Name"],
                    converter=converters[record["Data Type"]],
                )
                for record in csv.DictReader(
                    io.StringIO(self.extensions), strict=True
                )
            }
        except Exception as err:
            self.logger.error(
                "Error occurred while parsing UDM validation CSV. Error: {}".format(
                    str(err)
                )
            )
            raise

    def _valid_extensions(self):
        """To Parse the given extension CSV string and creates the dict for each provided values with its sanitizers.

        Returns:
            Dict object having details of all the available UDM fields and its sanitizers
        """
        # Initialize the sanitizers for different data types
        # ipv4_addr_re = r"\.".join([r"\d{1,3}"] * 4)
        ipv4_addr_re = (
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]"
            r"[0-9]|25[0-5])$"
        )
        ipv4_addr = self.str_sanitizer(ipv4_addr_re)
        IPV4SEG = r"(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
        IPV4ADDR = r"(?:(?:" + IPV4SEG + r"\.){3,3}" + IPV4SEG + r")"
        IPV6SEG = r"(?:(?:[0-9a-fA-F]){1,4})"
        IPV6GROUPS = (
            r"(?:" + IPV6SEG + r":){7,7}" + IPV6SEG,
            r"(?:" + IPV6SEG + r":){1,7}:",
            r"(?:" + IPV6SEG + r":){1,6}:" + IPV6SEG,
            r"(?:" + IPV6SEG + r":){1,5}(?::" + IPV6SEG + r"){1,2}",
            r"(?:" + IPV6SEG + r":){1,4}(?::" + IPV6SEG + r"){1,3}",
            r"(?:" + IPV6SEG + r":){1,3}(?::" + IPV6SEG + r"){1,4}",
            r"(?:" + IPV6SEG + r":){1,2}(?::" + IPV6SEG + r"){1,5}",
            IPV6SEG + r":(?:(?::" + IPV6SEG + r"){1,6})",
            r":(?:(?::" + IPV6SEG + r"){1,7}|:)",
            r"fe80:(?::" + IPV6SEG + r"){0,4}%[0-9a-zA-Z]{1,}",
            r"::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]" + IPV4ADDR,
            r"(?:" + IPV6SEG + r":){1,6}:?[^\s:]" + IPV4ADDR,
        )

        ipv6_addr_re = "|".join(["(?:{})".format(g) for g in IPV6GROUPS[::-1]])
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
                record["UDM Key Name"]: self.extension(
                    key_name=record["UDM Key Name"],
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
                "Error occurred while parsing UDM validation CSV. Error: {}".format(
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
            possible_headers: Possible UDM headers
            headers: Configured headers
            data_type: Data type for which UDM event is being generated
            subtype: Subtype of data type for which UDM event is being generated
        """
        for configured_header in list(headers.keys()):
            if configured_header not in possible_headers:
                self.logger.error(
                    '[{}][{}]: Found invalid header configured in syslog mapping file: "{}". Header '
                    "field will be ignored.".format(
                        data_type, subtype, configured_header
                    )
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

    def json_converter(self, header_pairs, extension_pairs):
        """JSON Converter."""
        udm_data = {}
        for key, value in header_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                udm_data[levels[0]] = value
            else:
                data = udm_data.get(levels[0], {})
                udm_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        for key, value in extension_pairs.items():
            levels = key.split(".")
            if len(levels) == 1:
                udm_data[levels[0]] = value
            else:
                data = udm_data.get(levels[0], {})
                udm_data[levels[0]] = self.get_json_structure(
                    data, ".".join(levels[1:]), value
                )

        return udm_data

    def get_udm_event(self, headers, extensions, data_type, subtype):
        """To Produce a UDM compliant message from the arguments.

        Args:
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
                self.logger.error(
                    '[{}][{}]: An error occurred while generating UDM data for field: "{}". Could not '
                    'find the field in the "valid_extensions". Field will be ignored.'.format(
                        data_type, subtype, name
                    )
                )
                continue
            except Exception as err:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating UDM data for field: "{}". Error: {}. '
                    "Field will be ignored".format(
                        data_type, subtype, name, str(err)
                    )
                )
                continue

            # Validate and sanitise (if required) the incoming value from Netskope before mapping it UDM
            try:
                extension_pairs[
                    self.valid_extensions[name].key_name
                ] = self.valid_extensions[name].sanitizer(value, name)
            except KeyError:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating UDM data for field: "{}". Could not '
                    'find the field in the "valid_extensions". Field will be ignored'.format(
                        data_type, subtype, name
                    )
                )
            except Exception as err:
                self.logger.error(
                    '[{}][{}]: An error occurred while generating UDM data for field: "{}". Error: {}. '
                    "Field will be ignored.".format(
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
                    self.logger.error(
                        '[{}][{}]: An error occurred while generating UDM data for header field: "{}". Error: {}. '
                        "Field will be ignored".format(
                            data_type, subtype, header, str(err)
                        )
                    )

        udm_data = self.json_converter(header_pairs, extension_pairs)
        return udm_data
