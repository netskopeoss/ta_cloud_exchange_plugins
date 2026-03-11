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

AWS Netskope LogStreaming Provider constants.
"""


MODULE_NAME = "CLS"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "AWS Netskope LogStreaming"
MAINTENANCE_PULL = "maintenance_pulling"
HISTORICAL_PULL = "historical_pulling"
INITIAL_SUB_TYPE = "device"
TYPE_EVENT = "events"
TYPE_ALERT = "alerts"
TYPE_WEBTX = "webtx"
RESULT = "result"
MAX_RETRIES = 3
READ_TIMEOUT = 300
DEFAULT_WAIT_TIME = 30
VALIDATION_READTIMEOUT = 60
QUEUE_SIZE = 10
BATCH_SIZE = 10000
BACK_PRESSURE_WAIT_TIME = 300
SUCCESS_FALSE = {"success": False}
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"

AUTHENTICATION_METHODS = [
    "aws_iam_roles_anywhere",
    "deployed_on_aws",
]

STRING_FIELDS = [
    "dlp_incident_id",
    "connection_id",
    "app_session_id",
    "dlp_parent_id",
    "browser_session_id",
]

NLS_ALERTS_MAPPINGS = {
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
    "Compromised Credential": "Compromised Credential",
    "policy": "policy",
    "malsite": "Malsite",
    "Malware": "malware",
    "DLP": "dlp",
    "Security Assessment": "Security Assessment",
    "watchlist": "Watchlist",
    "quarantine": "Quarantine",
    "Remediation": "Remediation",
    "uba": "uba",
    "ctep": "ctep",
    "ips": "ctep",
    "c2": "ctep",
    "Device": "device",
    "Content": "content",
}

NLS_EVENTS_MAPPINGS = {
    "page": "page",
    "application": "application",
    "audit": "audit",
    "infrastructure": "infrastructure",
    "network": "network",
    "clientstatus": "clientstatus",
    "incident": "incident",
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
    "clientstatus",
]

WEBTX = ["v2"]

REGIONS = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "eu-south-2",
    "eu-central-2",
    "me-central-1",
    "ca-west-1",
    "ap-southeast-4",
    "il-central-1",
    "ap-southeast-7",
    "ca-west-1",
    "ap-southeast-5",
    "mx-central-1"
]
