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

Palo Alto Networks Cortex XDR Plugin constants.
"""

# Plugin details.
PLATFORM_NAME = "Palo Alto Networks Cortex XDR"
PLUGIN_NAME = "Palo Alto Networks Cortex XDR"
MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.0.0"

# Configuration keys.
CONFIG_HTTP_LOG_COLLECTOR_URL = "http_log_collector_url"
CONFIG_API_KEY = "api_key"
CONFIG_COMPRESSION = "compression"
CONFIG_LOG_SOURCE_IDENTIFIER = "log_source_identifier"
CONFIG_TRANSFORM_DATA = "transformData"

# Configuration labels, used in the validation messages.
LABEL_HTTP_LOG_COLLECTOR_URL = "HTTP Log Collector URL"
LABEL_API_KEY = "API Key"
LABEL_COMPRESSION = "Compression"
LABEL_LOG_SOURCE_IDENTIFIER = "Log Source Identifier"

# Configuration values.
FORMAT_JSON = "json"
COMPRESSION_UNCOMPRESSED = "uncompressed"
COMPRESSION_GZIP = "gzip"
COMPRESSION_VALUES = [COMPRESSION_UNCOMPRESSED, COMPRESSION_GZIP]
DEFAULT_LOG_SOURCE_IDENTIFIER = "netskopece"
LOG_SOURCE_IDENTIFIER_FIELD = "log_source_identifier"
URL_SCHEMES = ("https",)

# Mapping file keys.
MAPPING_JSON_DATA = "jsonData"
MAPPING_TAXONOMY = "taxonomy"
MAPPING_JSON = "json"
NESTED_FIELD_SEPARATOR = "."
MAPPING_SCHEMA = {
    "type": "object",
    "properties": {
        MAPPING_TAXONOMY: {
            "type": "object",
            "properties": {
                MAPPING_JSON: {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "object",
                            "patternProperties": {
                                ".*": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                }
                            },
                        }
                    },
                }
            },
            "required": [MAPPING_JSON],
        }
    },
    "required": [MAPPING_TAXONOMY],
}

# HTTP Log Collector request. Cortex XDR accepts newline delimited JSON
# records, up to 10 MiB per request (1 MiB recommended) and 5 MB per
# record. Chunk size is kept 1 KiB (1024 bytes) under the 10 MiB hard
# limit as a safety buffer.
HTTP_METHOD_POST = "POST"
HEADER_AUTHORIZATION = "Authorization"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_CONTENT_ENCODING = "Content-Encoding"
HEADER_USER_AGENT = "User-Agent"
HEADER_RETRY_AFTER = "Retry-After"
CONTENT_TYPE_JSON = "application/json"
CONTENT_ENCODING_GZIP = "gzip"
RECORD_SEPARATOR = "\n"
ENCODING = "utf-8"
MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES = (10 * 1024 * 1024) - 1024
MAX_RECORD_SIZE_IN_BYTES = 5 * 1000 * 1000
RESPONSE_ERROR_KEY = "error"
RESPONSE_SUCCESS_VALUES = ("false", False)
VALIDATION_RECORD = {
    "message": (
        "Validation call from Netskope Cloud Exchange Palo Alto Networks "
        "Cortex XDR plugin."
    ),
}
VALIDATION_TIMESTAMP_FIELD = "timestamp"

# HTTP status codes.
HTTP_SUCCESS_CODES = (200, 201, 202)
HTTP_NO_CONTENT = 204
HTTP_TOO_MANY_REQUESTS = 429
# Codes for which Cortex XDR rejects the content of one request. The
# other requests of the push are still sent.
HTTP_REJECTED_CODES = (400, 413)

# Retry. range(MAX_RETRY_COUNT): 4 means 1 first call + 3 retries, so at
# most 3 waits of up to MAX_WAIT_TIME before giving up. Cortex XDR
# returns 500 when the format or compression of the request does not
# match the collector, which a retry can not fix, so only 429 and the
# other 5xx codes are retried.
MAX_RETRY_COUNT = 4
DEFAULT_WAIT_TIME = 60
MAX_WAIT_TIME = 120
SERVER_ERROR_RANGE = (500, 600)
# Celery stops a long task with SoftTimeLimitExceeded. It must reach
# Cloud Exchange unchanged so that the task is rescheduled.
SOFT_TIME_LIMIT_ERROR_NAME = "SoftTimeLimitExceeded"

# User agent.
DEFAULT_USER_AGENT = "netskope-ce"
USER_AGENT_TEMPLATE = "{ce_agent}-{module}-{plugin}-{version}"

# Log templates.
LOG_PREFIX_TEMPLATE = "{} {}"
LOG_PREFIX_NAME_TEMPLATE = " [{}]"
LOG_MESSAGE_TEMPLATE = "{}: {}"
VALIDATION_LOG_TEMPLATE = "{}: {} {}"
PLUGIN_INFO_MESSAGE = "Error occurred while getting the plugin details."

# Validation messages. Error messages start with "Error occurred while"
# and resolutions with "Ensure that the".
VALIDATION_ERROR_MESSAGE = (
    "Error occurred while validating configuration parameters."
)
REQUIRED_FIELD_MESSAGE = "{field} is a required configuration parameter."
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
INVALID_URL_RESOLUTION = (
    "Ensure that the {field} is the complete HTTPS POST URL of the Cortex "
    "XDR HTTP Log Collector, for example "
    "https://api-<tenant external URL>/logs/v1/event."
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
FORMAT_NOT_SUPPORTED_MESSAGE = (
    "This plugin only supports sharing JSON data to Palo Alto Networks "
    "Cortex XDR. Please select 'JSON' as the format to continue."
)
FORMAT_NOT_SUPPORTED_RESOLUTION = (
    "Ensure that the 'JSON' format is selected in the plugin "
    "configuration."
)
FIELD_VALIDATION_SUCCESS = "Validation successful for '{field}'."
VALIDATION_COMPLETED = "Validation completed successfully."
VALIDATION_SUCCESS = "Validation successful."

# Mapping validation messages.
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
    "Ensure that the mapping contains 'taxonomy' > 'json' and that every "
    "subtype maps to a list of field names."
)
MAPPING_VALIDATION_SUCCESS = "Mappings validation successful."

# Transform messages.
TRANSFORM_MAPPING_MESSAGE = (
    "Error occurred while fetching the JSON mapping for "
    "[{data_type}][{subtype}]."
)
TRANSFORM_MAPPING_RESOLUTION = (
    "Ensure that the mapping file contains 'taxonomy' > 'json' with valid "
    "JSON."
)
TRANSFORM_FORMAT_MESSAGE = (
    "Error occurred while transforming [{data_type}][{subtype}] data. This "
    "plugin only supports sharing JSON data to Palo Alto Networks Cortex XDR."
)
TRANSFORM_RECORD_MESSAGE = (
    "Error occurred while transforming a [{data_type}][{subtype}] record. "
    "The record will be skipped."
)
TRANSFORM_RECORD_RESOLUTION = (
    "Ensure that the records received from the source are valid JSON "
    "objects."
)
TRANSFORM_SUBTYPE_MAPPING_RESOLUTION = (
    "Ensure that the mapping file contains the JSON mapping for "
    "{data_type} {subtype}."
)
TRANSFORM_SKIPPED_MESSAGE = (
    "[{data_type}][{subtype}] Plugin couldn't process {count} record(s) "
    "because they either had no data or contained invalid/missing fields "
    "according to the configured JSON mapping. Therefore, the "
    "transformation and ingestion for those records were skipped."
)

# Push messages.
PUSH_START_MESSAGE = (
    "Initializing the sharing of {count} [{data_type}][{subtype}] log(s) "
    "to {platform}."
)
PUSH_NO_DATA_MESSAGE = (
    "[{data_type}][{subtype}] No data to ingest to {platform}."
)
PUSH_BATCH_MESSAGE = (
    "[{data_type}][{subtype}] Successfully ingested {count} log(s) in batch "
    "{batch} to {platform}. Total log(s) ingested: {total}."
)
PUSH_SUCCESS_MESSAGE = (
    "[{data_type}][{subtype}] Successfully ingested {count} log(s) to "
    "{platform}."
)
PUSH_SKIPPED_MESSAGE = " Skipped {count} log(s) that could not be ingested."
PUSH_REJECTED_MESSAGE = (
    "Error occurred while ingesting {count} [{data_type}][{subtype}] "
    "log(s) in batch {batch}. Palo Alto Networks Cortex XDR rejected them "
    "and they were skipped; the other batches are still sent."
)
PUSH_ALL_REJECTED_MESSAGE = (
    "Error occurred while ingesting [{data_type}][{subtype}] data to "
    "{platform}. Every batch was rejected."
)
PUSH_BATCH_LOGGER_MESSAGE = (
    "ingesting {count} [{data_type}][{subtype}] log(s) in batch {batch}"
)
PUSH_FAILED_MESSAGE = (
    "Error occurred while ingesting [{data_type}][{subtype}] data to "
    "{platform}. {count} log(s) failed to be ingested."
)
PUSH_UNEXPECTED_MESSAGE = (
    "Error occurred while ingesting [{data_type}][{subtype}] data to "
    "{platform}."
)
PUSH_UNEXPECTED_RESOLUTION = (
    "Ensure that the plugin configuration is valid and check the logs for "
    "more details."
)
PUSH_OVERSIZED_MESSAGE = (
    "Error occurred while ingesting {count} [{data_type}][{subtype}] "
    "log(s). They are larger than the 5 MB per log limit of Palo Alto "
    "Networks Cortex XDR and were skipped."
)
PUSH_OVERSIZED_RESOLUTION = (
    "Ensure that the JSON mapping removes the large fields of these logs."
)
PUSH_SERIALIZE_MESSAGE = (
    "Error occurred while converting {count} [{data_type}][{subtype}] "
    "log(s) to JSON. They were skipped."
)

# API messages.
API_REQUEST_MESSAGE = "API request for {logger_msg}. Endpoint: {method} {url}"
API_RESPONSE_MESSAGE = (
    "Received API response for {logger_msg}. Status code: {status_code}."
)
VALIDATION_LOGGER_MESSAGE = "validating the authentication parameters"
API_ERROR_MESSAGE = "Error occurred while {logger_msg}. {error}"
API_RESPONSE_DETAILS = "API response: {response}"
API_ERROR_CAUSE_TEMPLATE = "{} {}"
RETRY_MESSAGE = (
    "Received status code {status_code} while {logger_msg}. Retrying "
    "after {wait_time} second(s). {remaining} retries remaining."
)
RETRY_EXCEEDED_MESSAGE = (
    "Error occurred while {logger_msg}. Received status code {status_code} "
    "and the maximum retries were exceeded."
)
RETRY_EXCEEDED_RESOLUTION = (
    "Ensure that the requests sent to Palo Alto Networks Cortex XDR are "
    "within its limit of 400 requests per second, and try again later."
)
RETRY_AFTER_EXCEEDED_MESSAGE = (
    "Error occurred while {logger_msg}. The 'Retry-After' value received "
    "from Palo Alto Networks Cortex XDR is greater than {maximum} seconds."
)
INVALID_RESPONSE_MESSAGE = (
    "Error occurred while {logger_msg}. Invalid JSON response received "
    "from Palo Alto Networks Cortex XDR."
)
INVALID_RESPONSE_RESOLUTION = (
    "Ensure that the HTTP Log Collector URL is the HTTP POST URL of the "
    "Cortex XDR HTTP Log Collector."
)
REJECTED_RESPONSE_MESSAGE = (
    "Error occurred while {logger_msg}. Palo Alto Networks Cortex XDR "
    "rejected the request. Error: {error}"
)
REJECTED_RESPONSE_RESOLUTION = (
    "Ensure that the Log Format of the Cortex XDR HTTP Log Collector is "
    "JSON and that its Compression matches the Compression configuration "
    "parameter."
)
COMPRESSION_MISMATCH_RESOLUTION = (
    "Ensure that the Compression configuration parameter matches the "
    "Compression of the Cortex XDR HTTP Log Collector: select 'Gzip' for a "
    "gzip collector and 'Uncompressed' for an uncompressed collector."
)
# Resolutions picked from the error text returned by Cortex XDR, in
# order; the first keyword found in the error wins. A gzipped body sent
# to an uncompressed collector can also be reported as invalid JSON, so
# the JSON resolution mentions the Compression too.
RESPONSE_ERROR_RESOLUTIONS = (
    ("gzip", COMPRESSION_MISMATCH_RESOLUTION),
    ("compress", COMPRESSION_MISMATCH_RESOLUTION),
    ("json", REJECTED_RESPONSE_RESOLUTION),
)
READ_TIMEOUT_MESSAGE = "Error occurred while {logger_msg}. Read timed out."
READ_TIMEOUT_RESOLUTION = (
    "Ensure that the HTTP Log Collector URL is reachable from Cloud "
    "Exchange and that Palo Alto Networks Cortex XDR is responding."
)
PROXY_ERROR_MESSAGE = (
    "Error occurred while {logger_msg}. Unable to connect through the proxy."
)
PROXY_ERROR_RESOLUTION = (
    "Ensure that the proxy configured in Cloud Exchange is reachable and "
    "allows connections to the HTTP Log Collector URL."
)
SSL_ERROR_MESSAGE = (
    "Error occurred while {logger_msg}. SSL certificate verification failed."
)
SSL_ERROR_RESOLUTION = (
    "Ensure that the SSL certificate of the HTTP Log Collector URL is valid "
    "and trusted by Cloud Exchange."
)
CONNECTION_ERROR_MESSAGE = (
    "Error occurred while {logger_msg}. Unable to establish connection with "
    "Palo Alto Networks Cortex XDR."
)
CONNECTION_ERROR_RESOLUTION = (
    "Ensure that the HTTP Log Collector URL is correct and reachable from "
    "Cloud Exchange, directly or through the configured proxy."
)
HTTP_ERROR_MESSAGE = (
    "Error occurred while {logger_msg}. HTTP error occurred."
)
UNEXPECTED_ERROR_MESSAGE = (
    "Error occurred while {logger_msg}. Unexpected error occurred."
)
UNEXPECTED_ERROR_RESOLUTION = (
    "Ensure that the plugin configuration is valid and check the logs for "
    "more details."
)

# HTTP status code messages, as documented for the HTTP Log Collector.
STATUS_CODE_ERRORS = {
    400: (
        "Received status code 400, Bad Request.",
        "Ensure that the Log Format of the Cortex XDR HTTP Log Collector is "
        "JSON and its Compression matches the Compression "
        "configuration parameter.",
    ),
    401: (
        "Received status code 401, Unauthorized.",
        "Ensure that the API Key is correct and the Cortex XDR HTTP Log "
        "Collector is not deleted or disabled.",
    ),
    403: (
        "Received status code 403, Forbidden.",
        "Ensure that the API Key belongs to the Cortex XDR HTTP Log "
        "Collector of the HTTP Log Collector URL.",
    ),
    404: (
        "Received status code 404, Not Found.",
        "Ensure that the HTTP Log Collector URL is the HTTP POST URL of the "
        "Cortex XDR HTTP Log Collector.",
    ),
    413: (
        "Received status code 413, Payload Too Large.",
        "Ensure that the requests sent to Palo Alto Networks Cortex XDR are "
        "smaller than its 10 MB limit.",
    ),
    500: (
        "Received status code 500. Palo Alto Networks Cortex XDR could not "
        "process the request.",
        "Ensure that the Log Format of the Cortex XDR HTTP Log Collector is "
        "JSON and that its Compression matches the Compression "
        "configuration parameter.",
    ),
}
CLIENT_ERROR_MESSAGE = "Received status code {status_code}, HTTP client error."
SERVER_ERROR_MESSAGE = "Received status code {status_code}, HTTP server error."
STATUS_CODE_RESOLUTION = (
    "Ensure that the HTTP Log Collector URL, API Key and Compression "
    "provided in the configuration parameters are correct."
)
