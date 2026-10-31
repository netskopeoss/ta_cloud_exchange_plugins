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
   "https://{login_host}/{tenant_id}/oauth2/v2.0/token"
)
# Microsoft Entra ID authority host and Azure Monitor token scope per
# national cloud. The token must be requested from the same cloud the
# app registration lives in, otherwise Entra ID rejects it with
# AADSTS900382 (Confidential Client is not supported in Cross Cloud request).
AZURE_CLOUD_PUBLIC = "public"
AZURE_CLOUD_US_GOVERNMENT = "us_government"
AZURE_CLOUD_CHINA = "china"
# Any other Azure cloud: the Entra ID authority host and the token scope
# are provided by the user ('Custom Authority Host' and 'Custom Token Scope'
# configuration parameters).
AZURE_CLOUD_CUSTOM = "custom"
AZURE_CLOUD_LABELS = {
    AZURE_CLOUD_PUBLIC: "Azure Public (Commercial)",
    AZURE_CLOUD_US_GOVERNMENT: "Azure US Government",
    AZURE_CLOUD_CHINA: "Azure China (21Vianet)",
    AZURE_CLOUD_CUSTOM: "Custom Cloud",
}
AZURE_CLOUD_ENVIRONMENTS = {
    AZURE_CLOUD_PUBLIC: {
        "login_host": "login.microsoftonline.com",
        "dce_domain": "ingest.monitor.azure.com",
        "scope": "https://monitor.azure.com/.default",
    },
    AZURE_CLOUD_US_GOVERNMENT: {
        "login_host": "login.microsoftonline.us",
        "dce_domain": "ingest.monitor.azure.us",
        "scope": "https://monitor.azure.us/.default",
    },
    AZURE_CLOUD_CHINA: {
        "login_host": "login.chinacloudapi.cn",
        "dce_domain": "ingest.monitor.azure.cn",
        "scope": "https://monitor.azure.cn/.default",
    },
}
GRANT_TYPE = "client_credentials"
PUSH_DATA_ENDPOINT = (
   "{dce_uri}/dataCollectionRules/{dcr_immutable_id}/streams/"
   "Custom-{custom_log_table_name}?api-version=2023-01-01"
)
# Logs Ingestion API accepts at most 1 MB per call. Chunks are sized with a
# fast estimate against this limit; a chunk whose actual JSON body is larger
# (e.g. non-ASCII data) is re-split by its exact size before it is sent.
MAX_CHUNK_SIZE_BYTES = 1024 * 1024
TOKEN_SCOPE_SUFFIX = "/.default"
HOSTNAME_LABEL_RE = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"

# Microsoft Entra ID error codes (AADSTS) returned by the token endpoint
AADSTS_CODE_RE = r"AADSTS(\d+)"
AADSTS_CROSS_CLOUD_CODES = ("900382", "900432")
AADSTS_TENANT_NOT_FOUND_CODE = "90002"
AADSTS_INVALID_TENANT_CODES = ("900023",)
AADSTS_INVALID_APP_CODE = "700016"
AADSTS_INVALID_SECRET_CODE = "7000215"

MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
MAX_WAIT_TIME = 120
MODULE_NAME = "CLS"
PLUGIN_NAME = "Microsoft Azure Log Analytics"
PLUGIN_VERSION = "1.1.0"

# Ingestion mode values (must match manifest.json choice values)
INGESTION_MODE_SINGLE_TABLE = "single_table"
INGESTION_MODE_PER_DATA_TYPE = "per_data_type"

# Supported data types (must match manifest 'types')
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

# Configuration keys of the parameters that are mandatory only for the
# 'Custom Cloud' option (must match manifest.json)
CONFIG_CUSTOM_AUTHORITY_HOST = "custom_authority_host"
CONFIG_CUSTOM_TOKEN_SCOPE = "custom_token_scope"

# Configuration key of the 'Data Types to Ingest' multichoice (per_data_type
# mode). It is the only field that triggers get_dynamic_fields().
CONFIG_DATA_TYPES = "data_types"

# Table name fields returned by get_dynamic_fields() for the data types
# selected in 'Data Types to Ingest'. The condition hides them again when
# 'Ingestion Mode' is switched back to 'Single Table'.
PER_DATA_TYPE_TABLE_FIELDS = {
    data_type: {
        "label": f"{label} Custom Log Table Name",
        "key": PER_DATA_TYPE_TABLE_KEY[data_type],
        "type": "text",
        "default": "",
        "mandatory": True,
        "condition": {
            "key": "ingestion_mode",
            "values": [INGESTION_MODE_PER_DATA_TYPE],
        },
        "description": (
            f"Custom Log Table name that will receive {label}. The table "
            "must already exist in the Log Analytics Workspace."
        ),
    }
    for data_type, label in (
        (DATA_TYPE_ALERTS, "Alerts"),
        (DATA_TYPE_EVENTS, "Events"),
        (DATA_TYPE_WEBTX, "WebTx"),
    )
}
