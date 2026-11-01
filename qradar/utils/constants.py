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

QRadar Plugin constants."""

# Plugin details.
PLATFORM_NAME = "QRadar"
MODULE_NAME = "CLS"
PLUGIN_VERSION = "4.0.0"

# Configuration keys.
CONFIG_SERVER = "qradar_server"
CONFIG_PROTOCOL = "qradar_protocol"
CONFIG_PORT = "qradar_port"
CONFIG_CERTIFICATE = "qradar_certificate"
CONFIG_LOG_SOURCE_IDENTIFIER = "log_source_identifier"
CONFIG_EXCLUDE_TIMESTAMP = "exclude_timestamp_field"
CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER = "exclude_log_source_identifier_field"
CONFIG_EXCLUDE_PRIORITY = "exclude_priority_field"
CONFIG_TRANSFORM_DATA = "transformData"

# Configuration labels, used in the validation messages.
LABEL_SERVER = "QRadar Server"
LABEL_PROTOCOL = "QRadar Protocol"
LABEL_PORT = "QRadar Port"
LABEL_CERTIFICATE = "QRadar Certificate"
LABEL_LOG_SOURCE_IDENTIFIER = "Log Source Identifier"
LABEL_EXCLUDE_TIMESTAMP = "Exclude Timestamp Field"
LABEL_EXCLUDE_LOG_SOURCE_IDENTIFIER = "Exclude Log Source Identifier Field"
LABEL_EXCLUDE_PRIORITY = "Exclude Priority Field"

# Configuration values.
FORMAT_CEF = "cef"
FORMAT_JSON = "json"
DEFAULT_FORMAT = FORMAT_CEF
PROTOCOL_TLS = "TLS"
PROTOCOL_UDP = "UDP"
PROTOCOL_TCP = "TCP"
QRADAR_PROTOCOLS = [PROTOCOL_TLS, PROTOCOL_UDP, PROTOCOL_TCP]
QRADAR_PORT_RANGE = (1, 65535)
YES = "yes"
NO = "no"
EXCLUDE_ALLOWED_VALUES = [YES, NO]
DEFAULT_LOG_SOURCE_IDENTIFIER = "netskopece"

# Descriptions of the configuration fields built by get_dynamic_fields().
CERTIFICATE_DESCRIPTION = "Certificate is required only for TLS protocol."
PORT_DESCRIPTION = "Port of the QRadar server. Valid range is 1 to 65535."
LOG_SOURCE_IDENTIFIER_DESCRIPTION = (
    "This will be added as prefix to all the logs."
)
JSON_ONLY_DESCRIPTION = (
    " This option is only applicable to JSON-formatted data."
)
EXCLUDE_TIMESTAMP_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the timestamp field."
    + JSON_ONLY_DESCRIPTION
)
EXCLUDE_LOG_SOURCE_IDENTIFIER_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the Log Source Identifier "
    "field." + JSON_ONLY_DESCRIPTION
)
EXCLUDE_PRIORITY_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the priority"
    " field." + JSON_ONLY_DESCRIPTION
)

# Data types and subtypes.
WEBTX = "webtx"
AUDIT_SUBTYPE = "audit"

# Transport.
CHUNK_SIZE = 2000
SOCKET_TIMEOUT = 30
MAX_SEND_RETRIES = 3
RETRY_INTERVAL = 5
TLS_CLOSE_TIMEOUT = 2
TLS_READ_BUFFER_SIZE = 4096
UDP_MAX_PAYLOAD_SIZE = 65507
SYSLOG_LOGGER_NAME = "QRADAR_SYSLOG_LOGGER_{}"
SYSLOG_FACILITY = 1  # "user" facility
SYSLOG_PRIORITY_TEMPLATE = "<{}>"
SYSLOG_TIMESTAMP_FORMAT = "%b %d %H:%M:%S"
SYSLOG_HEADER_SEPARATOR = " "
LINE_TERMINATOR = "\n"
SYSLOG_NUL_TERMINATOR = "\000"
TCP_MESSAGE_FORMAT = "%(message)s" + LINE_TERMINATOR
ENCODING = "utf-8"

# Mapping file keys and values.
MAPPING_JSON_DATA = "jsonData"
MAPPING_TAXONOMY = "taxonomy"
MAPPING_DELIMITER = "delimiter"
MAPPING_CEF_VERSION = "cef_version"
MAPPING_JSON = "json"
MAPPING_HEADER = "header"
MAPPING_EXTENSION = "extension"
MAPPING_FIELD = "mapping_field"
MAPPING_DEFAULT_VALUE = "default_value"
MAPPING_TRANSFORMATION = "transformation"
MAPPING_IS_JSON_PATH = "is_json_path"
MAPPING_DELIMITER_VALUE = "|"
TRANSFORMATION_STRING = "String"
TRANSFORMATION_TIMESTAMP = "Time Stamp"
TENANT_NAME_VARIABLE = "$tenant_name"
NESTED_FIELD_SEPARATOR = "."
JSON_PATH_VALUE_SEPARATOR = ","
NULL_VALUE = "null"
CEF_FIELD_KEY_TEMPLATE = "{}_{}_{}_{}"
CEF_PREFIX_TEMPLATE = "{} {} CEF:{}"
CEF_EXTENSION_TEMPLATE = "{}={}"
CEF_EXTENSION_SEPARATOR = " "
CEF_EQUALS_CHARACTER = "="
CEF_PREFIX_FIELD_REGEX = "[^\r\n]*"
CEF_SEVERITY_REGEX = "Unknown|Low|Medium|High|Info|Very-High"
CEF_RECEIPT_TIME = "rt"
EXTENSION_TUPLE_NAME = "Extension"
EXTENSION_CONVERTER_TUPLE_NAME = "ExtensionConverter"
EXTENSION_KEY_NAME = "key_name"
EXTENSION_SANITIZER = "sanitizer"
EXTENSION_CONVERTER = "converter"
WEBTX_DATE_FIELD = "date"
WEBTX_TIME_FIELD = "time"
WEBTX_TIMESTAMP_TEMPLATE = "{}T{}Z"
ISO_TIMESPEC = "seconds"
ISO_SEPARATOR = "T"
CEF_HEADER_DEVICE_VENDOR = "Device Vendor"
CEF_HEADER_DEVICE_PRODUCT = "Device Product"
CEF_HEADER_DEVICE_VERSION = "Device Version"
CEF_HEADER_EVENT_CLASS_ID = "Device Event Class ID"
CEF_HEADER_NAME = "Name"
CEF_HEADER_SEVERITY = "Severity"
CEF_HEADERS = [
    CEF_HEADER_DEVICE_VENDOR,
    CEF_HEADER_DEVICE_PRODUCT,
    CEF_HEADER_DEVICE_VERSION,
    CEF_HEADER_EVENT_CLASS_ID,
    CEF_HEADER_NAME,
    CEF_HEADER_SEVERITY,
]

# Severity values.
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_VERY_HIGH = "Very-High"
SEVERITY_UNKNOWN = "Unknown"
SEVERITY_INFO = "Info"

SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_VERY_HIGH,
    "critical": SEVERITY_VERY_HIGH,
    "0": SEVERITY_LOW,
    "1": SEVERITY_LOW,
    "2": SEVERITY_LOW,
    "3": SEVERITY_LOW,
    "4": SEVERITY_MEDIUM,
    "5": SEVERITY_MEDIUM,
    "6": SEVERITY_MEDIUM,
    "7": SEVERITY_HIGH,
    "8": SEVERITY_HIGH,
    "9": SEVERITY_VERY_HIGH,
    "10": SEVERITY_VERY_HIGH,
}

AUDIT_SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_HIGH,
    "critical": SEVERITY_HIGH,
    "0": SEVERITY_UNKNOWN,
    "1": SEVERITY_HIGH,
    "2": SEVERITY_MEDIUM,
    "3": SEVERITY_UNKNOWN,
    "4": SEVERITY_LOW,
    "5": SEVERITY_UNKNOWN,
    "6": SEVERITY_INFO,
    "7": SEVERITY_UNKNOWN,
    "8": SEVERITY_UNKNOWN,
    "9": SEVERITY_UNKNOWN,
    "10": SEVERITY_UNKNOWN,
}

# Mapping schema.
MAPPING_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_DELIMITER: {
            "type": "string",
            "minLength": 1,
            "enum": [MAPPING_DELIMITER_VALUE],
        },
        MAPPING_CEF_VERSION: {"type": "string", "minLength": 1},
        MAPPING_TAXONOMY: {
            "type": "object",
            "properties": {
                "alerts": {"type": "object"},
                "events": {"type": "object"},
            },
            "anyOf": [
                {"required": ["alerts"]},
                {"required": ["events"]},
            ],
        },
    },
    "required": [MAPPING_DELIMITER, MAPPING_TAXONOMY, MAPPING_CEF_VERSION],
}
TAXONOMY_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_HEADER: {"type": "object", "minProperties": 0},
        MAPPING_EXTENSION: {"type": "object", "minProperties": 0},
    },
    "required": [MAPPING_HEADER, MAPPING_EXTENSION],
}
JSON_TAXONOMY_SCHEMA = {
    "type": "object",
    "patternProperties": {
        ".*": {
            "type": "object",
            "patternProperties": {".*": {"type": "array"}},
        },
    },
}
EXTENSION_SCHEMA = {"type": "object", "minProperties": 0}
# Both "mapping_field" and "default_value" empty is not allowed, so a
# field needs one of them, or both.
MAPPING_FIELD_ONE_OF = [
    {
        "oneOf": [
            {"required": [MAPPING_FIELD]},
            {"required": [MAPPING_DEFAULT_VALUE]},
        ]
    },
    {
        "allOf": [
            {"required": [MAPPING_FIELD]},
            {"required": [MAPPING_DEFAULT_VALUE]},
        ]
    },
]
HEADER_FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_DEFAULT_VALUE: {"type": "string"},
        MAPPING_FIELD: {"type": "string"},
        MAPPING_TRANSFORMATION: {"type": "string"},
    },
    "minProperties": 0,
    "maxProperties": 3,
    "oneOf": MAPPING_FIELD_ONE_OF,
}
HEADER_SCHEMA = {
    "type": "object",
    "properties": {header: HEADER_FIELD_SCHEMA for header in CEF_HEADERS},
}
EXTENSION_FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_FIELD: {"type": "string"},
        MAPPING_DEFAULT_VALUE: {"type": "string"},
        MAPPING_TRANSFORMATION: {"type": "string"},
        MAPPING_IS_JSON_PATH: {"type": "boolean"},
    },
    "minProperties": 0,
    "maxProperties": 4,
    "oneOf": MAPPING_FIELD_ONE_OF,
}

# Log messages. Error messages start with "Error occurred while" and
# resolutions with "Ensure that the".
VALIDATION_ERROR_MESSAGE = (
    "Error occurred while validating configuration parameters."
)
REQUIRED_FIELD_MESSAGE = "{field} is a required configuration parameter."
REQUIRED_FIELD_FOR_FORMAT_MESSAGE = (
    "{field} is a required configuration parameter, for the selected "
    "format."
)
REQUIRED_FIELD_RESOLUTION = (
    "Ensure that the {field} is provided in the configuration parameters."
)
INVALID_FIELD_MESSAGE = (
    "Invalid value provided for the configuration parameter '{field}'."
)
INVALID_FIELD_RESOLUTION = (
    "Ensure that the {field} provided in the configuration parameters is "
    "valid."
)
RANGE_FIELD_MESSAGE = (
    "Invalid value provided for the configuration parameter '{field}'. "
    "It should be in range {minimum} to {maximum}."
)
RANGE_FIELD_RESOLUTION = (
    "Ensure that the {field} is in range {minimum} to {maximum}."
)
ALLOWED_VALUES_MESSAGE = (
    "Invalid value provided for the configuration parameter '{field}'. "
    "Allowed values are {values}."
)
ALLOWED_VALUES_RESOLUTION = "Ensure that the {field} is one of {values}."
ALLOWED_VALUES_SEPARATOR = ", "
WHITESPACE_FIELD_MESSAGE = "{field} should not contain whitespace."
WHITESPACE_FIELD_RESOLUTION = (
    "Ensure that the {field} does not contain whitespace."
)
FIELD_VALIDATION_SUCCESS = "Validation successful for '{field}'."
VALIDATION_COMPLETED = "Validation completed successfully."
VALIDATION_SUCCESS = "Validation successful."
CONNECTIVITY_UNEXPECTED_MESSAGE = (
    "Error occurred while establishing connection with the QRadar server. "
    "Make sure you have provided correct QRadar Server, QRadar Port and "
    "QRadar Certificate (if required)."
)

MAPPING_INVALID_JSON_MESSAGE = (
    "Error occurred while validating mappings. Invalid JSON provided."
)
MAPPING_INVALID_JSON_RESOLUTION = (
    "Ensure that the mapping is a valid, non-empty JSON."
)
MAPPING_INVALID_MESSAGE = (
    "Error occurred while validating mappings. {error}"
)
MAPPING_TYPE_INVALID_MESSAGE = (
    "Error occurred while validating mappings for {data_type}. {error}"
)
MAPPING_RESOLUTION = (
    "Ensure that the mapping follows the QRadar mapping schema."
)
MAPPING_TYPE_RESOLUTION = (
    "Ensure that the mapping for {data_type} follows the QRadar mapping "
    "schema."
)
MAPPING_SCHEMA_ERROR = "Validating JSON schema failed: {error}"
MAPPING_SUBTYPE_SCHEMA_ERROR = (
    'Validating JSON schema for type "{data_type}" and subtype '
    '"{subtype}" failed: {error}'
)
MAPPING_HEADER_ERROR = (
    'Validating the QRadar header for type "{subtype}" failed: {error}'
)
MAPPING_EXTENSION_ERROR = (
    'Validating the QRadar extension for type "{subtype}" failed: {error}'
)
MAPPING_EXTENSION_FIELD_ERROR = (
    'Validating the QRadar extension field "{field}" for type "{subtype}" '
    "failed: {error}"
)
MAPPING_FIELD_TYPE_ERROR = "The field mapping must be an object"
MAPPING_TRANSFORMATION_ERROR = (
    'Unsupported transformation "{transformation}"'
)
MAPPING_NOT_OBJECT_ERROR = "The mapping must be a JSON object"
MAPPING_BOTH_EMPTY_ERROR = 'Both "mapping" and "default" can not be empty'
MAPPING_FIELD_EMPTY_ERROR = (
    '"mapping" field can not be empty as no "default" is provided'
)
MAPPING_DEFAULT_EMPTY_ERROR = (
    '"default" field can not be empty as no "mapping" is provided'
)
MAPPING_VALIDATING = "Validating the mappings for {data_type}."
MAPPING_VALIDATION_SUCCESS = "Mappings validation successful."

CONNECTION_TIMEOUT_MESSAGE = (
    "Error occurred while connecting to the QRadar server. "
    "Connection timed out."
)
CONNECTION_TIMEOUT_RESOLUTION = (
    "Ensure that the QRadar Server and QRadar Port are reachable from "
    "Cloud Exchange."
)
CONNECTION_REFUSED_MESSAGE = (
    "Error occurred while connecting to the QRadar server. "
    "Connection refused."
)
CONNECTION_REFUSED_RESOLUTION = (
    "Ensure that the QRadar Server is listening on the QRadar Port with "
    "the selected QRadar Protocol."
)
CONNECTION_RESOLVE_MESSAGE = (
    "Error occurred while resolving the QRadar Server '{server}'."
)
CONNECTION_RESOLVE_RESOLUTION = (
    "Ensure that the QRadar Server is a valid IP address or FQDN that "
    "Cloud Exchange can resolve."
)
CERTIFICATE_LOAD_MESSAGE = (
    "Error occurred while loading the QRadar Certificate."
)
CERTIFICATE_LOAD_RESOLUTION = (
    "Ensure that the QRadar Certificate is the complete PEM encoded "
    "certificate, including the BEGIN and END lines."
)
CERTIFICATE_VERIFY_MESSAGE = (
    "Error occurred while verifying the QRadar server certificate."
)
CERTIFICATE_VERIFY_RESOLUTION = (
    "Ensure that the QRadar Certificate is the certificate of the QRadar "
    "server or of the CA that signed it, and that it has not expired."
)
CONNECTION_ERROR_MESSAGE = (
    "Error occurred while connecting to the QRadar server. {cause}"
)
CONNECTION_ERROR_RESOLUTION = (
    "Ensure that the QRadar Server, QRadar Protocol and QRadar Port are "
    "correct."
)
CERTIFICATE_LOAD_CAUSE = "Unable to load the QRadar Certificate. {error}"

TRANSFORM_MAPPING_MESSAGE = (
    "Error occurred while fetching the {format} mapping for "
    "[{data_type}][{subtype}]."
)
TRANSFORM_MAPPING_RESOLUTION = (
    "Ensure that the mapping file contains the {format} mapping for "
    "{data_type} {subtype}."
)
SUBTYPE_MAPPING_NOT_FOUND = "No mapping found for subtype '{subtype}'."
TENANT_NAME_MESSAGE = (
    "Error occurred while fetching the tenant name for "
    "[{data_type}][{subtype}]."
)
TENANT_NAME_RESOLUTION = (
    "Ensure that the Netskope tenant used as the source is available in "
    "Cloud Exchange."
)
TRANSFORM_HEADER_MESSAGE = (
    "Error occurred while creating the CEF header for "
    "[{data_type}][{subtype}]. The record will be skipped."
)
TRANSFORM_HEADER_RESOLUTION = (
    "Ensure that the CEF header mappings in the mapping file are valid."
)
TRANSFORM_EXTENSION_MESSAGE = (
    "Error occurred while creating the CEF extension for "
    "[{data_type}][{subtype}]. The record will be skipped."
)
TRANSFORM_EXTENSION_RESOLUTION = (
    "Ensure that the CEF extension mappings in the mapping file are valid."
)
TRANSFORM_CEF_EVENT_MESSAGE = (
    "Error occurred while generating the CEF event for "
    "[{data_type}][{subtype}]. The record will be skipped."
)
TRANSFORM_JSON_RECORD_MESSAGE = (
    "Error occurred while transforming a [{data_type}][{subtype}] record "
    "to JSON. The record will be skipped."
)
TRANSFORMATION_PARSE_MESSAGE = (
    "Error occurred while parsing the CEF transformation of the mapping "
    "file."
)
TRANSFORMATION_PARSE_RESOLUTION = (
    "Ensure that the mapping file uses a supported transformation for "
    "every field."
)
TRANSFORM_SKIPPED_MESSAGE = (
    "[{data_type}][{subtype}] Plugin couldn't process {count} record(s) "
    "because they either had no data or contained invalid/missing fields "
    "according to the configured {format} mapping. Therefore, the "
    "transformation and ingestion for those records were skipped."
)
INVALID_HEADER_MESSAGE = (
    "[{data_type}][{subtype}] Found invalid header configured in the QRadar "
    'mapping file: "{header}". The header field will be ignored.'
)
EXTENSION_FIELD_NOT_FOUND_MESSAGE = (
    "[{data_type}][{subtype}] Could not find the field "
    '"{field}" in the valid extensions. The field will be ignored.'
)
EXTENSION_FIELD_ERROR_MESSAGE = (
    "[{data_type}][{subtype}] Could not generate the CEF value of the "
    'field "{field}". The field will be ignored. Error: {error}'
)
HEADER_FIELD_ERROR_MESSAGE = (
    "[{data_type}][{subtype}] Could not generate the CEF value of the "
    'header field "{field}". The field will be ignored. Error: {error}'
)
DATETIME_EXPECTED_ERROR = "{field}: Expected datetime, got {value_type}"

PUSH_START_MESSAGE = (
    "Initializing the sharing of {count} [{data_type}][{subtype}] log(s) "
    "to the {platform} server."
)
PUSH_SUCCESS_MESSAGE = (
    "[{data_type}][{subtype}] Successfully ingested {count} log(s) to the "
    "{platform} server."
)
PUSH_SKIPPED_MESSAGE = (
    " Received empty transformed data for {count} log(s) hence ingestion "
    "of those log(s) will be skipped."
)
PUSH_NO_DATA_MESSAGE = (
    "[{data_type}][{subtype}] No data to ingest to the {platform} server."
)
PUSH_FAILED_MESSAGE = (
    "Error occurred while ingesting data to the QRadar server. {count} "
    "log(s) failed to be ingested."
)
PUSH_FAILED_RESOLUTION = (
    "Ensure that the QRadar server is reachable and accepting data on the "
    "QRadar Port."
)
PUSH_UNEXPECTED_MESSAGE = (
    "Error occurred while ingesting [{data_type}][{subtype}] data to the "
    "QRadar server."
)
PUSH_OVERSIZED_MESSAGE = (
    "Error occurred while ingesting {count} log(s) larger than the UDP "
    "limit. They were skipped."
)
PUSH_OVERSIZED_RESOLUTION = (
    "Ensure that the TCP or TLS QRadar Protocol is selected to ingest "
    "large records."
)
SEND_RETRY_MESSAGE = (
    "Sending a log to the {platform} server failed. Reconnecting and "
    "retrying in {interval} second(s), attempt {attempt} of {maximum}. "
    "Error: {error}"
)
PEER_CLOSED_MESSAGE = (
    "The {platform} server closed the connection. Reconnecting before "
    "sending the next log."
)
CLEANUP_FAILED_MESSAGE = (
    "Error occurred while closing the connection with the {platform} "
    "server. Error: {error}"
)
PLUGIN_INFO_MESSAGE = "Error occurred while getting the plugin details."
LOG_PREFIX_TEMPLATE = "{} {}"
LOG_PREFIX_NAME_TEMPLATE = " [{}]"
LOG_MESSAGE_TEMPLATE = "{}: {}"
VALIDATION_LOG_TEMPLATE = "{}: {} {}"
