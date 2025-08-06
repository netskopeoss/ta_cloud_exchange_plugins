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

# from netskope_api.iterator.const import Const

MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "Microsoft Azure"
PLUGIN_NAME = "Azure Netskope LogStreaming"
MAINTENANCE_PULL = "maintenance pulling"
HISTORICAL_PULL = "Historical pulling"
TYPE_EVENT = "events"
TYPE_ALERT = "alerts"
TYPE_WEBTX = "webtx"
MAX_RETRIES = 3
READ_TIMEOUT = 300
DEFAULT_WAIT_TIME = 30
VALIDATION_READTIMEOUT = 60
RESULT = "result"
QUEUE_SIZE = 10
BATCH_SIZE = 10000
BACK_PRESSURE_WAIT_TIME = 300

STRING_FIELDS = [
    "dlp_incident_id",
    "connection_id",
    "app_session_id",
    "dlp_parent_id",
    "browser_session_id",
]

NLS_EVENT_MAPPINGS = {
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
    "epdlp": "epdlp",
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
    "anomaly",
    "compromisedcredential",
    "policy",
    "malsite",
    "malware",
    "dlp",
    "securityassessment",
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
