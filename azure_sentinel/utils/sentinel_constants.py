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
"""

"""Provides constants for Azure Sentinel plugin."""


HTTP_METHOD = "POST"
CONTENT_TYPE = "application/json"
RESOURCE = "/api/logs"
API_BASE_URL = "https://{}.ods.opinsights.azure.com{}?api-version=2016-04-01"
MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
ATTRIBUTE_DTYPE_MAP = {
    "dlp_incident_id": "string",
    "app_session_id": "string",
    "transaction_id": "string",
    "md5": "string",
    "request_id": "string",
    "browser_session_id": "string",
    "page_id": "string",
    "dlp_parent_id": "string",
    "timestamp": "datetime",
    "_insertion_epoch_timestamp": "datetime",
    "bin_timestamp": "datetime",
    "last_timestamp": "datetime",
    "page_starttime": "datetime",
    "page_endtime": "datetime",
    "breach_date": "datetime",
    "suppression_end_time": "datetime",
    "suppression_start_time": "datetime",
    "conn_starttime": "datetime",
    "conn_endtime": "datetime",
    "malsite_first_seen": "datetime",
    "malsite_last_seen": "datetime",
    "scan_time": "datetime",
    "modified_date": "datetime",
    "created_date": "datetime",
}
MODULE_NAME = "CLS"
PLUGIN_NAME = "Microsoft Azure Sentinel"
PLUGIN_VERSION = "3.0.2"
VALIDATION_ALPHANUM_PATTERN = r"^[a-zA-Z0-9_]+$"
VALIDATION_DIGITS_PATTERN = r"^[\d_]+$"
MAX_API_CALL = 3
DEFAULT_WAIT = 30
TARGET_SIZE_MB = 25
BATCH_SIZE = 10000
TARGET_SIZE_BYTES = TARGET_SIZE_MB * 1024 * 1024
