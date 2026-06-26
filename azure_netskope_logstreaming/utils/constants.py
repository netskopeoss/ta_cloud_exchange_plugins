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

Azure Netskope LogStreaming constants.
"""

MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.0.1"
PLATFORM_NAME = "Microsoft Azure"
PLUGIN_NAME = "Azure Netskope LogStreaming"
VALIDATION_ERROR_MSG = "Validation error occurred. "
# Last CE version that does NOT support resolution= in logger.error().
# Versions strictly above this get the resolution field; 5.1.2 and below do not.
MAXIMUM_CORE_VERSION = "5.1.2"
MAINTENANCE_PULL = "maintenance pulling"
HISTORICAL_PULL = "Historical pulling"
TYPE_EVENT = "events"
TYPE_ALERT = "alerts"
TYPE_WEBTX = "webtx"

# Retry and timeout settings (used in client.py retry logic)
MAX_RETRIES = 4
READ_TIMEOUT = 300
DEFAULT_WAIT_TIME = 30
VALIDATION_READTIMEOUT = 60

RESULT = "result"
BATCH_SIZE = 10000
BACK_PRESSURE_WAIT_TIME = 300

# Azure Queue receive settings
MESSAGES_PER_PAGE = 20
# Visibility timeout in seconds: blobs must be fully processed within this window
# before the message reappears in the queue for reprocessing.
VISIBILITY_TIMEOUT = 3000

STRING_FIELDS = [
    "dlp_incident_id",
    "connection_id",
    "app_session_id",
    "dlp_parent_id",
    "browser_session_id",
]

# Maps record_type or alert_type field values from Netskope Log Streaming CSV
# data to normalized subtype keys used for bifurcation into ALERTS / EVENTS /
# WEBTX.
#
# Two patterns exist in the wild:
#   1. record_type is a descriptive value ("alert_type_dlp", "page", etc.)
#      → handled by the first branch in _bifurcate_data()
#   2. record_type == "alert" and alert_type holds the alert subtype
#      → handled by the second branch in _bifurcate_data()
#
# All values are lowercase (with underscores for multi-word) so they match the
# ALERTS and EVENTS lists without case-sensitive lookup errors.
NLS_EVENT_MAPPINGS = {
    # --- record_type-keyed entries (old Netskope Log Streaming format) ---
    "alert_type_c2": "ctep",
    "alert_type_compromised_credential": "Compromised Credential",
    "alert_type_content": "content",
    "alert_type_ctep": "ctep",
    "alert_type_device": "device",
    "alert_type_dlp": "dlp",
    "alert_type_ips": "ctep",
    "alert_type_malsite": "Malsite",
    "alert_type_malware": "malware",
    "alert_type_policy": "policy",
    "alert_type_quarantine": "Quarantine",
    "alert_type_remediation": "Remediation",
    "alert_type_security_assessment": "Security Assessment",
    "alert_type_uba": "uba",
    "alert_type_watchlist": "Watchlist",
    "application": "application",
    "audit": "audit",
    "clientstatus": "clientstatus",
    "endpoint": "endpoint",
    "incident": "incident",
    "infrastructure": "infrastructure",
    "network": "network",
    "page": "page",
    "policy": "policy",
    "malsite": "Malsite",
    "DLP": "dlp",
    "uba": "uba",
    "watchlist": "Watchlist",
    "Security Assessment": "Security Assessment",
    "Compromised Credential": "Compromised Credential",
    "Malware": "malware",
    "ips": "ctep",
    "quarantine": "Quarantine",
    "Remediation": "Remediation",
    "ctep": "ctep",
    "c2": "ctep",
    "Device": "device",
    "Content": "content",
}

ALERTS = [
    "compromised credential",
    "policy",
    "malsite",
    "malware",
    "dlp",
    "security assessment",
    "watchlist",
    "quarantine",
    "remediation",
    "uba",
    "ctep",
    "ips",
    "c2",
    "device",
    "content",
]

EVENTS = [
    "page",
    "application",
    "audit",
    "infrastructure",
    "network",
    "incident",
    "endpoint",
    "clientstatus",
]

WEBTX = ["v2"]

CONNECTION_STRING_REQUIRED_COMPONENTS = [
    "DefaultEndpointsProtocol=",
    "AccountName=",
    "AccountKey=",
    "EndpointSuffix=",
]
