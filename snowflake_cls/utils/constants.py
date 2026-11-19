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

Snowflake CLS Plugin constants.
"""

# ── Plugin identity ──────────────────────────────────────────────────────
PLATFORM_NAME = "Snowflake"
MODULE_NAME = "CLS"
PLUGIN_NAME = "Snowflake"
PLUGIN_VERSION = "1.0.0"

# ── Retry / backoff ──────────────────────────────────────────────────────
# Total attempts per API call, not the retry count: api_helper() loops
# range(MAX_RETRY_COUNT), so 4 means 1 initial call + 3 retries.
MAX_RETRY_COUNT = 4
DEFAULT_WAIT_TIME = 60
MAX_WAIT_TIME = 300
HTTP_BACKOFF_FACTOR = 2
DEFAULT_REQUEST_TIMEOUT = 60

# ── Chunking ─────────────────────────────────────────────────────────────
# Snowflake rejects any request body over 4,194,304 bytes with HTTP 413 and
# REQUEST_BODY_TOO_LARGE. Confirmed against a live tenant on 2026-10-01.
SNOWFLAKE_MAX_REQUEST_BYTES = 4194304
# We stop filling a chunk 1 KiB under that. split_into_size() measures the
# exact NDJSON line it will send for each row, so the running total is the
# real body size - it over-counts by one byte, the trailing newline that
# never goes out. 1 KiB is headroom, not an estimate allowance.
MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES = SNOWFLAKE_MAX_REQUEST_BYTES - 1024
# Rows Core hands to push() in one call, returned by chunk_size().
#
# It does not bound the rows per request. A request is bounded by
# MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES above and nothing else - Snowflake limits a
# request by size, not by row count, so push() batches on size alone and
# there is no batch-size setting.
#
# Cloud Exchange 6.1.0 and 7.0.0 never call chunk_size(), so this value
# currently changes nothing. It is kept so the plugin states its preference
# if the core starts reading it again.
CHUNK_SIZE = 2000

# push() tries gzipping the whole batch as one request before falling back
# to split_into_size(). Level 6 is zlib's default: a good ratio for JSON
# without the CPU cost of the higher levels.
GZIP_COMPRESSION_LEVEL = 6
GZIP_CONTENT_ENCODING = "gzip"

# ── Endpoints ────────────────────────────────────────────────────────────
# Every Snowflake account is reached at <account>.snowflakecomputing.com.
# The customer gives the whole URL, and it is checked against this suffix
# before any request carries their token to it.
SNOWFLAKE_HOST_SUFFIX = ".snowflakecomputing.com"
STREAMING_HOSTNAME_ENDPOINT = "{base_url}/v2/streaming/hostname"
STREAMING_ROWS_ENDPOINT = (
    "https://{streaming_host}/v2/streaming/data/databases/{database}"
    "/schemas/{schema}/tables/{table}/rows"
)
SQL_API_ENDPOINT = "{base_url}/api/v2/statements"
SQL_API_STATUS_ENDPOINT = "{base_url}/api/v2/statements/{statement_handle}"

NDJSON_CONTENT_TYPE = "application/x-ndjson"
JSON_CONTENT_TYPE = "application/json"

# ── Authentication ───────────────────────────────────────────────────────
# A Programmatic Access Token is the only authentication this plugin
# supports. Key-pair JWT was dropped: it needs an RSA key pair, a
# PKCS#8 conversion, an ALTER USER to register the public key and a
# fingerprint check, and any missed step fails in a way that is hard to
# read. A PAT is one SQL statement with the same result every time.
TOKEN_TYPE_HEADER = "X-Snowflake-Authorization-Token-Type"
TOKEN_TYPE_PAT = "PROGRAMMATIC_ACCESS_TOKEN"

# ── self.storage keys ────────────────────────────────────────────────────
SCHEMA_CACHE_STORAGE_KEY = "snowflake_schema_cache"
STREAMING_HOST_STORAGE_KEY = "snowflake_streaming_host"

# ── Ingestion mode (table scope) ─────────────────────────────────────────
INGESTION_MODE_SINGLE_TABLE = "single_table"
INGESTION_MODE_PER_DATA_TYPE = "per_data_type"
ALL_INGESTION_MODES = (
    INGESTION_MODE_SINGLE_TABLE,
    INGESTION_MODE_PER_DATA_TYPE,
)

# ── Column mode (row shape) ──────────────────────────────────────────────
# Not a configuration field. The mode is read from a table's own columns at
# validate() and transform() time - a RAW_DATA column means Combined,
# anything else means Separate Fields (see _detect_column_mode in main.py).
# These are the two internal values that decision returns.
COLUMN_MODE_COMBINED = "combined"
COLUMN_MODE_SEPARATE_FIELDS = "separate_fields"

# ── Data types ───────────────────────────────────────────────────────────
DATA_TYPE_ALERTS = "alerts"
DATA_TYPE_EVENTS = "events"
DATA_TYPE_WEBTX = "webtx"
SUPPORTED_DATA_TYPES = (
    DATA_TYPE_ALERTS,
    DATA_TYPE_EVENTS,
    DATA_TYPE_WEBTX,
)

# data_type -> the configuration key holding its table name in
# per_data_type mode.
PER_DATA_TYPE_TABLE_FIELD = {
    DATA_TYPE_ALERTS: "alerts_table_name",
    DATA_TYPE_EVENTS: "events_table_name",
    DATA_TYPE_WEBTX: "webtx_table_name",
}

# Label shown to the user for each data type.
DATA_TYPE_LABELS = {
    DATA_TYPE_ALERTS: "Alerts",
    DATA_TYPE_EVENTS: "Events",
    DATA_TYPE_WEBTX: "WebTx",
}

# ── Column names and types ───────────────────────────────────────────────
# The column the plugin fills with the Cloud Exchange source configuration
# name - the name of the plugin configuration that pulled these logs and
# handed them to this Log Shipper. Its own constant because several places
# reference it by name.
SOURCE_CONFIG_NAME_COLUMN = "SOURCE_CONFIGURATION_NAME"

# The 5 values the plugin builds for every record. A record field with one
# of these names is dropped, so the plugin's value is used instead of the
# record's own.
ENVELOPE_COLUMN_NAMES = frozenset(
    {
        "INGESTION_TIME",
        "EVENT_TIME",
        "DATA_TYPE",
        "SUBTYPE",
        SOURCE_CONFIG_NAME_COLUMN,
    }
)

# Any of these takes the UTC ISO-8601 string the plugin writes.
TIMESTAMP_COLUMN_TYPES = ("TIMESTAMP_NTZ", "TIMESTAMP_LTZ", "TIMESTAMP_TZ")

# A structured OBJECT reports as "OBJECT" from SHOW COLUMNS, so _read_type()
# gives it this name instead to keep the two apart.
STRUCTURED_OBJECT_TYPE = "STRUCTURED OBJECT"

# combined mode: these 4 columns must exist on the table. Each maps to the
# types the plugin's own values actually load into - not one preferred type.
#
# EVENT_TIME is written as a UTC ISO-8601 string ending in Z, which carries
# its own offset, so all three TIMESTAMP flavours take it. LTZ is often the
# better choice for a customer whose analysts share one timezone.
#
# RAW_DATA takes VARIANT or an unstructured OBJECT. A *structured* object -
# OBJECT(a VARCHAR, b NUMBER) - is not accepted: SHOW COLUMNS reports it as
# plain "OBJECT" too, but a live test showed the append returns HTTP 200 and
# the row is then dropped. _read_type() reports it as STRUCTURED OBJECT so
# it fails this check instead of failing silently later.
MANDATORY_COMBINED_COLUMN_TYPES = {
    "EVENT_TIME": TIMESTAMP_COLUMN_TYPES,
    "DATA_TYPE": ("TEXT",),
    "SUBTYPE": ("TEXT",),
    "RAW_DATA": ("VARIANT", "OBJECT"),
}

# combined mode: these 2 are optional. If the table has them we fill them;
# if not, we leave the key out of the row.
OPTIONAL_COMBINED_COLUMN_TYPES = {
    "INGESTION_TIME": TIMESTAMP_COLUMN_TYPES,
    SOURCE_CONFIG_NAME_COLUMN: ("TEXT",),
}

RAW_DATA_COLUMN_NAME = "RAW_DATA"
RAW_LINE_FIELD_NAME = "raw_line"

# separate_fields mode: a table may have this VARIANT column to collect
# every field that did not match a named column.
EXTRA_FIELDS_COLUMN_NAME = "EXTRA_FIELDS"

# ── Record field handling ────────────────────────────────────────────────
# Checked in this order. First one with a numeric value wins.
#
# Confirmed against the 822-field Netskope catalogue: 'timestamp' is the
# only top-level time field on every alert and event subtype, and
# 'x-cs-timestamp' is the only one on WebTx ('transaction'). 'alert_time',
# 'event_time' and 'ts' are not real field names on any subtype - they
# never matched anything and are not listed here.
# ('x-c-local-timestamp' also exists, but that is the client's local
# clock, not the event time.)
TIMESTAMP_FIELDS = (
    "timestamp",
    "x-cs-timestamp",
)

# The record's own field that tells us the subtype. webtx has no such
# field, so it always falls back to the subtype argument.
SUBTYPE_SOURCE_FIELD = {
    DATA_TYPE_ALERTS: "alert_type",
    DATA_TYPE_EVENTS: "event_type",
}

ISO_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Any character outside this set is replaced with "_" before we match a
# field name against a column name.
FIELD_NAME_INVALID_CHAR_RE = r"[^A-Za-z0-9_$]"

# Database / schema / table names may be given in any case - matched
# against Snowflake case-sensitively, quoted, everywhere the plugin uses
# them (SHOW COLUMNS and the Snowpipe Streaming rows URL alike).
#
# Snowflake itself stores an unquoted name in upper case (a table created
# as 'netskope_logs' is stored as 'NETSKOPE_LOGS'), but a table created
# quoted keeps whatever case it was given. Since every call this plugin
# makes quotes the name, the case typed here must be the exact case
# Snowflake stores the object under - which for an ordinary, unquoted
# CREATE TABLE is upper case, and for a quoted one is whatever was quoted.
# A mismatch is reported as "not found" at validate() time rather than
# rejected here, because this regex cannot know which case is correct for
# a name it has never looked up.
#
# Confirmed live (2026-10-07): the Snowpipe Streaming REST API resolves
# %22-quoted database/schema/table path segments case-sensitively, the
# same as a quoted SQL identifier - an unquoted segment 404s against a
# quoted-mixed-case object regardless of case, a %22-quoted one with the
# exact stored case succeeds.
SNOWFLAKE_IDENTIFIER_RE = r"^[A-Za-z_][A-Za-z0-9_$]*$"

# Snowflake's own cap, quoted or unquoted. Checked live: 255 is accepted,
# 256 fails with "Object name '...' is too long".
SNOWFLAKE_IDENTIFIER_MAX_LENGTH = 255

# The account part of the host, in front of SNOWFLAKE_HOST_SUFFIX. Covers
# both the orgname-accountname form and the legacy locator.region.cloud
# form. The whole URL carries the customer's bearer credential, so the host
# is pinned to Snowflake's domain and this is what may sit in front of it.
SNOWFLAKE_ACCOUNT_LABEL_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"

# Snowflake's reserved keywords (reserved + limited-use lists, fetched from
# docs.snowflake.com on 2026-10-01). A column can never be named exactly
# one of these without quoting, so a field name that normalizes to one gets
# a trailing "_": group -> GROUP -> GROUP_.
SNOWFLAKE_RESERVED_KEYWORDS = frozenset(
    {
        "ACCOUNT", "ALL", "ALTER", "AND", "ANY", "AS", "BETWEEN", "BY",
        "CASE", "CAST", "CHECK", "COLUMN", "CONNECT", "CONNECTION",
        "CONSTRAINT", "CREATE", "CROSS", "CURRENT", "CURRENT_DATE",
        "CURRENT_TIME", "CURRENT_TIMESTAMP", "CURRENT_USER", "DATABASE",
        "DELETE", "DISTINCT", "DROP", "ELSE", "EXISTS", "FALSE",
        "FOLLOWING", "FOR", "FROM", "FULL", "GRANT", "GROUP", "GSCLUSTER",
        "HAVING", "ILIKE", "IN", "INCREMENT", "INNER", "INSERT",
        "INTERSECT", "INTO", "IS", "ISSUE", "JOIN", "LATERAL", "LEFT",
        "LIKE", "LOCALTIME", "LOCALTIMESTAMP", "MINUS", "NATURAL", "NOT",
        "NULL", "OF", "ON", "OR", "ORDER", "ORGANIZATION", "QUALIFY",
        "REGEXP", "REVOKE", "RIGHT", "RLIKE", "ROW", "ROWS", "SAMPLE",
        "SCHEMA", "SELECT", "SET", "SOME", "START", "TABLE",
        "TABLESAMPLE", "THEN", "TO", "TRIGGER", "TRUE", "TRY_CAST",
        "UNION", "UNIQUE", "UPDATE", "USING", "VALUES", "VIEW", "WHEN",
        "WHENEVER", "WHERE", "WINDOW", "WITH",
    }
)

# ── Schema introspection ─────────────────────────────────────────────────
# Reads column names and types without needing a warehouse.
#
# SHOW COLUMNS is a metadata command, so Snowflake runs it with no
# compute. A SELECT against INFORMATION_SCHEMA.COLUMNS looks equivalent
# but is an ordinary query: it fails with HTTP 422 "You must specify the
# warehouse to use" for any user without a default warehouse. Confirmed
# against a live tenant on 2026-10-04.
#
# It also reports types in the form this plugin already expects - TEXT,
# VARIANT, TIMESTAMP_NTZ - while DESCRIBE TABLE reports
# VARCHAR(16777216) and TIMESTAMP_NTZ(9), which would need parsing.
SCHEMA_INTROSPECTION_QUERY = (
    'SHOW COLUMNS IN TABLE "{database}"."{schema}"."{table}"'
)

# Snowflake answers SHOW COLUMNS for a table that is not there with this
# SQL compilation error rather than an empty result.
OBJECT_DOES_NOT_EXIST_CODE = "002003"

# Where the pieces we want sit in a SHOW COLUMNS row. Looked up by name
# from the response metadata when possible; these are the fallback.
SHOW_COLUMNS_NAME_INDEX = 2
SHOW_COLUMNS_TYPE_INDEX = 3
SQL_API_TIMEOUT_SECONDS = 30
# How many times we poll a 202 before giving up.
SQL_API_MAX_POLL_ATTEMPTS = 10
SQL_API_POLL_WAIT_SECONDS = 2

# ── Messages ─────────────────────────────────────────────────────────────
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = "'{}' is a required configuration parameter."
INVALID_VALUE_ERROR_MESSAGE = (
    "Invalid value provided for the configuration parameter '{}'."
)

AUTH_ERROR_MESSAGE = (
    "Authentication or authorization failed. Verify the Account"
    " Identifier and the credentials, and that the role behind them"
    " has INSERT on the target table."
)
TABLE_NOT_FOUND_ERROR_MESSAGE = (
    "The configured Database, Schema, or Table Name was not found. This"
    " plugin does not create tables - create it in Snowflake first, then"
    " re-save this configuration."
)
BAD_REQUEST_ERROR_MESSAGE = (
    "Snowflake rejected the request - check Database, Schema and Table"
    " Name for typos or invalid characters."
)
RATE_LIMIT_ERROR_MESSAGE = (
    "Snowflake rate-limited this request. This is retried automatically."
    " If it keeps happening, ask Snowflake support about your"
    " account's streaming ingest quota."
)
# validate() does not retry, so it must not promise a retry either.
RATE_LIMIT_VALIDATION_MESSAGE = (
    "Snowflake rate-limited this request. Try saving the configuration"
    " again in a few minutes. If it keeps happening, ask Snowflake"
    " support about your account's streaming ingest quota."
)
SERVER_ERROR_MESSAGE = (
    "Snowflake returned a server error. This is retried automatically"
    " with backoff."
)
# validate() does not retry, so it must not promise a retry either.
SERVER_ERROR_VALIDATION_MESSAGE = (
    "Snowflake returned a server error. Try saving the configuration"
    " again in a few minutes."
)
PAYLOAD_TOO_LARGE_ERROR_MESSAGE = (
    "Snowflake rejected the request because the body is larger than"
    f" {SNOWFLAKE_MAX_REQUEST_BYTES} bytes. The plugin already splits"
    " batches under that limit, so a single record must be over it on"
    " its own."
)

# ── Dynamic configuration fields ─────────────────────────────────────────
# Returned by get_dynamic_fields(), which Cloud Exchange calls when
# 'ingestion_mode' changes. These must NOT appear in the manifest
# configuration array.
#
# Ingestion Mode is the plugin's only dynamic trigger. Cloud Exchange
# renders each trigger independently, so one call only ever answers for
# one field.

# Shown when 'ingestion_mode' is 'single_table'. One table takes every
# data type.
SINGLE_TABLE_DYNAMIC_FIELDS = [
    {
        "label": "Table Name",
        "key": "table_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "Table that receives Alerts, Events and WebTx. It must be a"
            " Combined-mode table - one with a RAW_DATA VARIANT column -"
            " because 'Single Table' does not support Separate Fields."
            " The name provided must exactly match what is present on"
            " Snowflake."
        ),
    },
]

# Shown when 'ingestion_mode' is 'per_data_type'. Each data type goes to
# its own table. Ingestion is driven by which of these three table names
# are filled in: a name selects its data type, a blank one means that
# type is not ingested. The fields are optional individually because any
# one may be left blank - validate() requires at least one, which the
# manifest cannot express.
PER_DATA_TYPE_DYNAMIC_FIELDS = [
    {
        "label": "Alerts Table Name",
        "key": "alerts_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Table that receives Alerts. Fill this in to ingest Alerts;"
            " leave it blank to skip them. Case-sensitive - must exactly"
            " match the name Snowflake stores the table under. It must"
            " already exist."
        ),
    },
    {
        "label": "Events Table Name",
        "key": "events_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Table that receives Events. Fill this in to ingest Events;"
            " leave it blank to skip them. Case-sensitive - must exactly"
            " match the name Snowflake stores the table under. It must"
            " already exist."
        ),
    },
    {
        "label": "WebTx Table Name",
        "key": "webtx_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Table that receives WebTx. Fill this in to ingest WebTx;"
            " leave it blank to skip it. Case-sensitive - must exactly"
            " match the name Snowflake stores the table under. It must"
            " already exist."
        ),
    },
]
