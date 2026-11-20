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

SentinelOne Singularity Data Lake CLS plugin constants.
"""

# ── Plugin identity ──────────────────────────────────────────────────
PLATFORM_NAME = "SentinelOne Singularity Data Lake"
PLUGIN_NAME = PLATFORM_NAME
MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.0.0"

# ── HEC endpoints ────────────────────────────────────────────────────
# Ingestion hosts that have a published HEC endpoint. NA4 and ME1 have
# none, so customers there use the Custom URL option. These are the
# "ingest.*" hosts, not the "xdr.*" console hosts.
HEC_BASE_URLS = {
    "us1": "https://ingest.us1.sentinelone.net",
    "ca1": "https://ingest.ca1.sentinelone.net",
    "eu1": "https://ingest.eu1.sentinelone.net",
    "ap1": "https://ingest.ap1.sentinelone.net",
    "aps1": "https://ingest.aps1.sentinelone.net",
    "apse2": "https://ingest.apse2.sentinelone.net",
}
CUSTOM_HEC_BASE_URL = "custom"
ALLOWED_HEC_BASE_URLS = list(HEC_BASE_URLS.values()) + [CUSTOM_HEC_BASE_URL]
HEC_EVENT_PATH = "/services/collector/event"
HEC_RAW_PATH = "/services/collector/raw"

# ── Size limits ──────────────────────────────────────────────────────
# Records are packed into chunks of at most this many bytes before
# compression (UTF-8 length of the serialized records).
MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES = 10 * 1024 * 1024  # 10 MB
# HEC really limits the compressed request body to about 10 MB and
# answers 413 above it. A gzipped chunk bigger than this is split in
# half before it is sent. The margin leaves room for request overhead.
MAX_COMPRESSED_PAYLOAD_SIZE_IN_BYTES = int(9.5 * 1024 * 1024)  # 9.5 MB
GZIP_COMPRESSION_LEVEL = 6

# Records Cloud Exchange hands to transform()/push() at a time. Only a
# hint: push() splits by size, not by count.
CHUNK_SIZE = 2000

# ── Retry ────────────────────────────────────────────────────────────
# range(MAX_RETRIES): 4 means 1 first call + 3 retries, so at most 3
# flat sleeps of RETRY_SLEEP_TIME (180 s of waiting) before giving up.
MAX_RETRIES = 4
# Waited when the response carries no usable Retry-After. Flat, not
# backed off: Cloud Exchange sends a few requests per cycle against a
# 1000 request/second limit, so there is no congestion to relieve.
RETRY_SLEEP_TIME = 60
# A Retry-After above this is not waited out. See
# SentinelOneSDLPluginHelper._get_retry_wait_time().
MAX_WAIT_TIME = 120

# ── Metadata added to every log ──────────────────────────────────────
# dataSource.vendor must never be "SentinelOne" - that value is
# reserved for SentinelOne's own connectors.
DATA_SOURCE_VENDOR = "Netskope"
DATA_SOURCE_NAME = "Netskope Cloud Exchange"
DATA_SOURCE_CATEGORY = "security"  # needed for the XDR view

DATA_SOURCE_VENDOR_KEY = "dataSource.vendor"
DATA_SOURCE_NAME_KEY = "dataSource.name"
DATA_SOURCE_CATEGORY_KEY = "dataSource.category"
EVENT_TYPE_KEY = "event.type"
# Both times are added to every JSON log, whatever JSON Log Time is set
# to, so a query does not have to know how the plugin is configured.
NETSKOPE_EVENT_TIME_KEY = "netskope_event_time"
CE_INGESTION_TIME_KEY = "netskope_ce_ingestion_time"
TENANT_NAME_KEY = "netskope_tenant_name"

# Default "Source" value. Lands in serverHost, shown under the Sources
# tab in Singularity Data Lake.
CE_LOG_SOURCE_IDENTIFIER = "Netskope Cloud Exchange"
# Default "Log File Name" value. Lands in logfile, shown under the
# Log Files tab.
DEFAULT_LOG_FILE_NAME = "Netskope Logs"
# Parser used when the Parser field is empty, per log format.
DEFAULT_PARSER = "json"
DEFAULT_CEF_PARSER = "cef"
# JSON parsers. They cannot read CEF text, so they are refused in CEF mode.
JSON_PARSER_NAMES = frozenset({"json", "_json"})
# A log file named "scalyr" is hidden from DV PQ results.
BLOCKED_LOG_FILE_NAMES = frozenset({"scalyr"})
# Log file used by the connectivity test in validate().
VALIDATION_LOG_FILE_NAME = "netskope-ce-validation"
VALIDATION_EVENT_TYPE = "Cloud Exchange plugin connectivity test"

# ── Reserved field names ─────────────────────────────────────────────
# Netskope fields whose bare name collides with a Singularity Data Lake
# attribute. Checked against all 822 Netskope schema fields:
# - severity: renamed to _severity by SDL, and it means something else
#   (log level) in SDL.
# - site: not dropped, but SDL uses site.id for tenant scope.
# - time: overwrites the real SDL time attribute.
# - timestamp: renamed to timestamp_ by SDL.
# Each one is sent as netskope_<field> instead (JSON mode only).
NETSKOPE_FIELD_PREFIX = "netskope_"
RESERVED_FIELDS = frozenset({"severity", "site", "time", "timestamp"})

# ── Event time and type ──────────────────────────────────────────────
# Fields tried, in order, for the event time. Epoch seconds.
TIMESTAMP_FIELDS = ("timestamp", "x-cs-timestamp")
WEBTX_DATE_FIELD = "date"
WEBTX_TIME_FIELD = "time"
SUBTYPE_SOURCE_FIELD = {"alerts": "alert_type", "events": "event_type"}
WEBTX_EVENT_TYPE = "webtx"

# CEF mapping "transformation" values that mean "this Netskope field is
# a number". In JSON mode, string values of these fields are sent as
# JSON numbers.
INTEGER_TRANSFORMATION = "Integer"
FLOAT_TRANSFORMATION = "Floating Point"
NUMERIC_TRANSFORMATIONS = frozenset(
    {INTEGER_TRANSFORMATION, FLOAT_TRANSFORMATION}
)
# Largest integer a 64-bit float holds exactly (2^53 - 1). Bigger
# integers are sent as strings so no digit is lost.
MAX_SAFE_JSON_INTEGER = 2**53 - 1
MAX_SAFE_INTEGER_DIGITS = len(str(MAX_SAFE_JSON_INTEGER))  # 16

# ── Data types and modes ─────────────────────────────────────────────
DATA_TYPE_ALERTS = "alerts"
DATA_TYPE_EVENTS = "events"
DATA_TYPE_WEBTX = "webtx"
SUPPORTED_DATA_TYPES = (DATA_TYPE_ALERTS, DATA_TYPE_EVENTS, DATA_TYPE_WEBTX)

# Values of Cloud Exchange's transformData (manifest format_options).
TRANSFORM_DATA_JSON = "json"
TRANSFORM_DATA_CEF = "cef"
ALLOWED_TRANSFORM_DATA = (TRANSFORM_DATA_JSON, TRANSFORM_DATA_CEF)

# Which time goes into the HEC envelope "time" of a JSON log. CEF is not
# affected: /raw takes one time per request, so SDL stamps it on arrival.
TIME_MODE_EVENT = "event"
TIME_MODE_INGESTION = "ingestion"
ALLOWED_TIME_MODES = [TIME_MODE_EVENT, TIME_MODE_INGESTION]

SOURCE_MODE_KEY = "source_mode"
SOURCE_MODE_SINGLE = "single"
SOURCE_MODE_PER_TYPE = "per_type"
ALLOWED_SOURCE_MODES = [SOURCE_MODE_SINGLE, SOURCE_MODE_PER_TYPE]

# Configuration keys mirror the HEC API fields their values become
# (host -> "host"/serverHost, sourcetype -> "sourcetype", source_name ->
# "source"), while the manifest labels match what the SentinelOne console
# calls them (Source, Parser, Log File Name). The mismatch is deliberate.
# Log File Name config key per data type (Different Log File per Data
# Type mode).
LOGS_TO_INGEST_KEY = "logs_to_ingest"

PER_TYPE_SOURCE_KEYS = {
    DATA_TYPE_ALERTS: "alert_source_name",
    DATA_TYPE_EVENTS: "event_source_name",
    DATA_TYPE_WEBTX: "webtx_source_name",
}

# Field key -> data type, for picking the dynamic fields to show.
PER_TYPE_SOURCE_DATA_TYPES = {
    key: data_type for data_type, key in PER_TYPE_SOURCE_KEYS.items()
}

# ── Dynamic configuration fields (Log File Mode) ─────────────────────
# Single mode's Log File Name is a static manifest field rendered on a
# condition, not a dynamic one. Cloud Exchange tags every dynamic field
# with the field that triggered the fetch and only replaces fields
# carrying that same tag, so a key that is both static and dynamic, or
# dynamic under two triggers, is drawn twice.
SINGLE_SOURCE_KEY = "source_name"
SINGLE_SOURCE_LABEL = "Log File Name"

# Returned by get_dynamic_fields(). Each carries the same condition as
# the field that triggers the fetch, so Cloud Exchange hides them again
# when Log File Mode leaves per_type.
PER_TYPE_SOURCE_CONDITION = {
    "key": SOURCE_MODE_KEY,
    "values": [SOURCE_MODE_PER_TYPE],
}
PER_TYPE_SOURCE_DYNAMIC_FIELDS = [
    {
        "label": "Alert Log File Name",
        "key": "alert_source_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Log File name for Netskope Alerts. Shown under the Log Files"
            " tab in Singularity Data Lake Event Search. Leave it"
            " empty to send Alerts with no Log File name."
        ),
        "condition": PER_TYPE_SOURCE_CONDITION,
    },
    {
        "label": "Event Log File Name",
        "key": "event_source_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Log File name for Netskope Events. Shown under the Log Files"
            " tab in Singularity Data Lake Event Search. Leave it"
            " empty to send Events with no Log File name."
        ),
        "condition": PER_TYPE_SOURCE_CONDITION,
    },
    {
        "label": "WebTx Log File Name",
        "key": "webtx_source_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Log File name for Netskope WebTx. Shown under the Log Files"
            " tab in Singularity Data Lake Event Search. Leave it"
            " empty to send WebTx with no Log File name."
        ),
        "condition": PER_TYPE_SOURCE_CONDITION,
    },
]

# ── CEF ──────────────────────────────────────────────────────────────
CEF_HEADERS = (
    "Device Vendor",
    "Device Product",
    "Device Version",
    "Device Event Class ID",
    "Name",
    "Severity",
)
TENANT_NAME_VARIABLE = "$tenant_name"
TENANT_NAME_FALLBACK = "Netskope"

SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_VERY_HIGH = "Very-High"
SEVERITY_UNKNOWN = "Unknown"
SEVERITY_INFO = "Info"

# Used for the CEF Severity header only. JSON mode sends Netskope's own
# severity value unchanged as netskope_severity.
SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_VERY_HIGH,
    "critical": SEVERITY_VERY_HIGH,
    "info": SEVERITY_INFO,
    "unknown": SEVERITY_UNKNOWN,
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
    "info": SEVERITY_INFO,
    "unknown": SEVERITY_UNKNOWN,
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

# ── HTTP status names used in messages ───────────────────────────────
HTTP_STATUS_REASONS = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    413: "Request too large",
    429: "Too many requests",
}

# Celery's soft time limit error. Matched by name so celery is not
# imported. It must never be swallowed by a per-log error handler.
SOFT_TIME_LIMIT_ERROR_NAME = "SoftTimeLimitExceeded"

# ── Messages ─────────────────────────────────────────────────────────
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = "'{}' is a required configuration parameter."
INVALID_VALUE_ERROR_MESSAGE = (
    "Invalid value provided for '{}' in the configuration parameters."
)
