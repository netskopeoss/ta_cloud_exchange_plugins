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

Provides constants for Microsoft Azure Log Analytics plugin."""


GENERATE_TOKEN_BASE_URL = (
   "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
)
API_SCOPE = "https://monitor.azure.com/.default"
GRANT_TYPE = "client_credentials"
PUSH_DATA_ENDPOINT = (
   "{dce_uri}/dataCollectionRules/{dcr_immutable_id}/streams/"
   "Custom-{custom_log_table_name}?api-version=2023-01-01"
)

MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
MAX_WAIT_TIME = 120
MODULE_NAME = "CLS"
PLUGIN_NAME = "Microsoft Azure Log Analytics"
PLUGIN_VERSION = "1.0.0"

# Ingestion mode values (must match manifest.json choice values)
INGESTION_MODE_SINGLE_TABLE = "single_table"
INGESTION_MODE_PER_DATA_TYPE = "per_data_type"

# Supported data types (must match manifest 'types' and multichoice values)
DATA_TYPE_ALERTS = "alerts"
DATA_TYPE_EVENTS = "events"
DATA_TYPE_WEBTX = "webtx"
SUPPORTED_DATA_TYPES = (DATA_TYPE_ALERTS, DATA_TYPE_EVENTS, DATA_TYPE_WEBTX)

# Map data_type -> configuration key holding its table name in per_data_type mode
PER_DATA_TYPE_TABLE_KEY = {
    DATA_TYPE_ALERTS: "alerts_table_name",
    DATA_TYPE_EVENTS: "events_table_name",
    DATA_TYPE_WEBTX:  "webtx_table_name",
}

RETRY_ERROR_MSG = (
   "Received exit code {status_code}, {error_reason} "
   "while {logger_msg}. Retrying after {wait_time} "
   "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
   "Received exit code {status_code}, API rate limit "
   "exceeded while {logger_msg}. Max retries for rate "
   "limit handler exceeded hence returning status "
   "code {status_code}."
)
VALIDATION_ERROR_MSG = "Validation error occurred. "
JSON_MAPPED_DATA_TYPES = ["alerts", "events", "webtx"]

# this is to make sure the values are inline with whats expected on azure
COLUMN_NAME_INVALID_CHAR_RE = r"[^A-Za-z0-9_]"
RESERVED_NAMES = [
   "type",
   "title",
   "subtype",
   "date",
   "time",
   "TimeGenerated",
   "Application",
   "DataType",
   "SubType",
]
SPECIAL_RENAMES = {
   "_id": "id",
   "Title": "TitleField",
   "Type": "TypeField",
}

SINGLE_TABLE_DYNAMIC_FIELDS = [
    {
        "label": "Custom Log Table Name",
        "key": "custom_log_table_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "Custom Log Table name for ingesting all data. "
            "Every record (Alerts, Events and WebTx) is pushed "
            "into this table inside a 'RawData' column. "
            "The table must already exist in the Log Analytics "
            "Workspace."
        ),
    },
]

PER_DATA_TYPE_DYNAMIC_FIELDS = [
    {
        "label": "Data Types to Ingest",
        "key": "data_types",
        "type": "multichoice",
        "choices": [
            {"key": "Alerts", "value": DATA_TYPE_ALERTS},
            {"key": "Events", "value": DATA_TYPE_EVENTS},
            {"key": "WebTx",  "value": DATA_TYPE_WEBTX},
        ],
        "default": [
            DATA_TYPE_ALERTS, DATA_TYPE_EVENTS, DATA_TYPE_WEBTX,
        ],
        "mandatory": True,
        "description": (
            "Select which Netskope data types should be "
            "ingested. A separate custom log table is used "
            "for each selected type — provide the matching "
            "table name(s) below."
        ),
    },
    {
        "label": "Alerts Custom Log Table Name",
        "key": "alerts_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Custom Log Table name that will receive Alerts. "
            "Required only when 'Alerts' is selected above. "
            "The table must already exist in the Log Analytics "
            "Workspace."
        ),
    },
    {
        "label": "Events Custom Log Table Name",
        "key": "events_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Custom Log Table name that will receive Events. "
            "Required only when 'Events' is selected above. "
            "The table must already exist in the Log Analytics "
            "Workspace."
        ),
    },
    {
        "label": "WebTx Custom Log Table Name",
        "key": "webtx_table_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Custom Log Table name that will receive WebTx "
            "transactions. Required only when 'WebTx' is "
            "selected above. The table must already exist "
            "in the Log Analytics Workspace."
        ),
    },
]
