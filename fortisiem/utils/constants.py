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

FortiSIEM Plugin constants."""

# Plugin details.
PLATFORM_NAME = "FortiSIEM"
MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.1.0"

# Configuration keys.
CONFIG_SERVER = "fortisiem_server"
CONFIG_PROTOCOL = "fortisiem_protocol"
CONFIG_PORT = "fortisiem_port"
CONFIG_CERTIFICATE = "fortisiem_certificate"
CONFIG_LOG_SOURCE_IDENTIFIER = "log_source_identifier"
CONFIG_EXCLUDE_TIMESTAMP = "exclude_timestamp_field"
CONFIG_EXCLUDE_LOG_SOURCE_IDENTIFIER = "exclude_log_source_identifier_field"
CONFIG_EXCLUDE_PRIORITY = "exclude_priority_field"
CONFIG_TRANSFORM_DATA = "transformData"

# Configuration labels, used in the validation messages.
LABEL_SERVER = "FortiSIEM Server"
LABEL_PROTOCOL = "FortiSIEM Protocol"
LABEL_PORT = "FortiSIEM Port"
LABEL_CERTIFICATE = "FortiSIEM Certificate"
LABEL_LOG_SOURCE_IDENTIFIER = "Log Source Identifier"
LABEL_EXCLUDE_TIMESTAMP = "Exclude Timestamp Field"
LABEL_EXCLUDE_LOG_SOURCE_IDENTIFIER = "Exclude Log Source Identifier Field"
LABEL_EXCLUDE_PRIORITY = "Exclude Priority Field"
LABEL_FORMAT = "Format"

# Configuration values.
FORMAT_CEF = "cef"
FORMAT_JSON = "json"
DEFAULT_FORMAT = FORMAT_JSON
PROTOCOL_TLS = "TLS"
PROTOCOL_UDP = "UDP"
PROTOCOL_TCP = "TCP"
FORTISIEM_PROTOCOLS = [PROTOCOL_TLS, PROTOCOL_UDP, PROTOCOL_TCP]
FORTISIEM_PORT_RANGE = (1, 65535)
FORTISIEM_FORMATS = [FORMAT_JSON]
YES = "yes"
NO = "no"
EXCLUDE_ALLOWED_VALUES = [YES, NO]
DEFAULT_LOG_SOURCE_IDENTIFIER = "netskopece"

# Descriptions of the configuration fields built by get_dynamic_fields().
CERTIFICATE_DESCRIPTION = "Certificate is required only for TLS protocol."
PORT_DESCRIPTION = "Port of the FortiSIEM server. Valid range is 1 to 65535."
LOG_SOURCE_IDENTIFIER_DESCRIPTION = (
    "This will be added as prefix to all the logs."
)
EXCLUDE_TIMESTAMP_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the timestamp field."
)
EXCLUDE_LOG_SOURCE_IDENTIFIER_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the Log Source Identifier "
    "field."
)
EXCLUDE_PRIORITY_DESCRIPTION = (
    "Select 'Yes' to ingest the data without the priority field."
)

# Transport.
CHUNK_SIZE = 2000
SOCKET_TIMEOUT = 30
MAX_SEND_RETRIES = 3
RETRY_INTERVAL = 5
TLS_CLOSE_TIMEOUT = 2
TLS_READ_BUFFER_SIZE = 4096
UDP_MAX_PAYLOAD_SIZE = 65507
SYSLOG_LOGGER_NAME = "FORTISIEM_SYSLOG_LOGGER_{}"
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
MAPPING_JSON = "json"
NESTED_FIELD_SEPARATOR = "."

# Mapping schema.
MAPPING_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_TAXONOMY: {
            "type": "object",
            "properties": {MAPPING_JSON: {"type": "object"}},
            "required": [MAPPING_JSON],
        },
    },
    "required": [MAPPING_TAXONOMY],
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
    "Error occurred while establishing connection with the FortiSIEM "
    "server. Make sure you have provided correct FortiSIEM Server, "
    "FortiSIEM Port and FortiSIEM Certificate (if required)."
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
MAPPING_RESOLUTION = (
    "Ensure that the mapping follows the FortiSIEM mapping schema."
)
MAPPING_SCHEMA_ERROR = "Validating JSON schema failed: {error}"
MAPPING_JSON_SCHEMA_ERROR = (
    'Validating JSON schema of the "json" taxonomy failed: {error}'
)
MAPPING_NOT_OBJECT_ERROR = "The mapping must be a JSON object"
MAPPING_VALIDATION_SUCCESS = "Mappings validation successful."
JSON_MAPPING_MISSING_MESSAGE = (
    "Error occurred while validating mappings. The mapping file has no "
    "JSON taxonomy for the selected format."
)
JSON_MAPPING_MISSING_RESOLUTION = (
    "Ensure that the mapping file contains the JSON taxonomy for the "
    "selected format."
)

CONNECTION_TIMEOUT_MESSAGE = (
    "Error occurred while connecting to the FortiSIEM server. "
    "Connection timed out."
)
CONNECTION_TIMEOUT_RESOLUTION = (
    "Ensure that the FortiSIEM Server and FortiSIEM Port are reachable "
    "from Cloud Exchange."
)
CONNECTION_REFUSED_MESSAGE = (
    "Error occurred while connecting to the FortiSIEM server. "
    "Connection refused."
)
CONNECTION_REFUSED_RESOLUTION = (
    "Ensure that the FortiSIEM Server is listening on the FortiSIEM Port "
    "with the selected FortiSIEM Protocol."
)
CONNECTION_RESOLVE_MESSAGE = (
    "Error occurred while resolving the FortiSIEM Server '{server}'."
)
CONNECTION_RESOLVE_RESOLUTION = (
    "Ensure that the FortiSIEM Server is a valid IP address or FQDN that "
    "Cloud Exchange can resolve."
)
CERTIFICATE_LOAD_MESSAGE = (
    "Error occurred while loading the FortiSIEM Certificate."
)
CERTIFICATE_LOAD_RESOLUTION = (
    "Ensure that the FortiSIEM Certificate is the complete PEM encoded "
    "certificate, including the BEGIN and END lines."
)
CERTIFICATE_VERIFY_MESSAGE = (
    "Error occurred while verifying the FortiSIEM server certificate."
)
CERTIFICATE_VERIFY_RESOLUTION = (
    "Ensure that the FortiSIEM Certificate is the certificate of the "
    "FortiSIEM server or of the CA that signed it, and that it has not "
    "expired."
)
CONNECTION_ERROR_MESSAGE = (
    "Error occurred while connecting to the FortiSIEM server. {cause}"
)
CONNECTION_ERROR_RESOLUTION = (
    "Ensure that the FortiSIEM Server, FortiSIEM Protocol and FortiSIEM "
    "Port are correct."
)
CERTIFICATE_LOAD_CAUSE = "Unable to load the FortiSIEM Certificate. {error}"

FORMAT_NOT_SUPPORTED_MESSAGE = (
    "Error occurred while transforming [{data_type}][{subtype}] data. "
    "FortiSIEM supports only the JSON format."
)
FORMAT_NOT_SUPPORTED_RESOLUTION = (
    "Ensure that the JSON format is selected for the configuration."
)
TRANSFORM_MAPPING_MESSAGE = (
    "Error occurred while fetching the {format} mapping for "
    "[{data_type}][{subtype}]."
)
TRANSFORM_MAPPING_RESOLUTION = (
    "Ensure that the mapping file contains the {format} mapping for "
    "{data_type} {subtype}."
)
SUBTYPE_MAPPING_NOT_FOUND = "No mapping found for subtype '{subtype}'."
TRANSFORM_JSON_RECORD_MESSAGE = (
    "Error occurred while transforming a [{data_type}][{subtype}] record "
    "to JSON. The record will be skipped."
)
TRANSFORM_SKIPPED_MESSAGE = (
    "[{data_type}][{subtype}] Plugin couldn't process {count} record(s) "
    "because they either had no data or contained invalid/missing fields "
    "according to the configured {format} mapping. Therefore, the "
    "transformation and ingestion for those records were skipped."
)

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
    "Error occurred while ingesting data to the FortiSIEM server. {count} "
    "log(s) failed to be ingested."
)
PUSH_FAILED_RESOLUTION = (
    "Ensure that the FortiSIEM server is reachable and accepting data on "
    "the FortiSIEM Port."
)
PUSH_UNEXPECTED_MESSAGE = (
    "Error occurred while ingesting [{data_type}][{subtype}] data to the "
    "FortiSIEM server."
)
PUSH_OVERSIZED_MESSAGE = (
    "Error occurred while ingesting {count} log(s) larger than the UDP "
    "limit. They were skipped."
)
PUSH_OVERSIZED_RESOLUTION = (
    "Ensure that the TCP or TLS FortiSIEM Protocol is selected to ingest "
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
