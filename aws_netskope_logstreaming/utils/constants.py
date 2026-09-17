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
PLUGIN_VERSION = "1.1.0"
PLATFORM_NAME = "AWS Netskope LogStreaming"
MAINTENANCE_PULL = "maintenance_pulling"
HISTORICAL_PULL = "historical_pulling"
INITIAL_SUB_TYPE = "device"
DATA_FORMAT_JSON = "json"
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

VALIDATION_ERROR_MESSAGE = "Validation error occurred."

# Temporary credentials are refreshed this many minutes before their actual
# expiry so a pull cycle never uses credentials that expire mid-request.
CREDENTIALS_REFRESH_BUFFER_MINUTES = 3

# Authentication methods supported by the plugin.
DEPLOYED_ON_AWS = "deployed_on_aws"
AWS_IAM_ROLES_ANYWHERE = "aws_iam_roles_anywhere"

AUTHENTICATION_METHODS = [
    AWS_IAM_ROLES_ANYWHERE,
    DEPLOYED_ON_AWS,
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
    "endpoint": "endpoint",
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
    "endpoint",
]

WEBTX = ["v2"]

# AWS regions offered in the "AWS Region Name" dropdown. This is the single
# source of truth for the region list - REGIONS below is derived from it so the
# dropdown and the validation allow-list can never drift apart.
REGION_CHOICES = [
    {"key": "US East (N. Virginia) [us-east-1]", "value": "us-east-1"},
    {"key": "US East (Ohio) [us-east-2]", "value": "us-east-2"},
    {"key": "US West (N. California) [us-west-1]", "value": "us-west-1"},
    {"key": "US West (Oregon) [us-west-2]", "value": "us-west-2"},
    {"key": "Africa (Cape Town) [af-south-1]", "value": "af-south-1"},
    {"key": "Asia Pacific (Hong Kong) [ap-east-1]", "value": "ap-east-1"},
    {"key": "Asia Pacific (Mumbai) [ap-south-1]", "value": "ap-south-1"},
    {
        "key": "Asia Pacific (Tokyo) [ap-northeast-1]",
        "value": "ap-northeast-1",
    },
    {
        "key": "Asia Pacific (Seoul) [ap-northeast-2]",
        "value": "ap-northeast-2",
    },
    {
        "key": "Asia Pacific (Osaka) [ap-northeast-3]",
        "value": "ap-northeast-3",
    },
    {
        "key": "Asia Pacific (Singapore) [ap-southeast-1]",
        "value": "ap-southeast-1",
    },
    {
        "key": "Asia Pacific (Sydney) [ap-southeast-2]",
        "value": "ap-southeast-2",
    },
    {
        "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
        "value": "ap-southeast-3",
    },
    {
        "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
        "value": "ap-southeast-4",
    },
    {
        "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
        "value": "ap-southeast-5",
    },
    {
        "key": "Asia Pacific (Thailand) [ap-southeast-7]",
        "value": "ap-southeast-7",
    },
    {"key": "Asia Pacific (Hyderabad) [ap-south-2]", "value": "ap-south-2"},
    {"key": "Canada (Central) [ca-central-1]", "value": "ca-central-1"},
    {"key": "Canada (Calgary) [ca-west-1]", "value": "ca-west-1"},
    {"key": "China (Beijing) [cn-north-1]", "value": "cn-north-1"},
    {"key": "China (Ningxia) [cn-northwest-1]", "value": "cn-northwest-1"},
    {"key": "Europe (Frankfurt) [eu-central-1]", "value": "eu-central-1"},
    {"key": "Europe (Zurich) [eu-central-2]", "value": "eu-central-2"},
    {"key": "Europe (Ireland) [eu-west-1]", "value": "eu-west-1"},
    {"key": "Europe (London) [eu-west-2]", "value": "eu-west-2"},
    {"key": "Europe (Paris) [eu-west-3]", "value": "eu-west-3"},
    {"key": "Europe (Milan) [eu-south-1]", "value": "eu-south-1"},
    {"key": "Europe (Spain) [eu-south-2]", "value": "eu-south-2"},
    {"key": "Europe (Stockholm) [eu-north-1]", "value": "eu-north-1"},
    {"key": "Israel (Tel Aviv) [il-central-1]", "value": "il-central-1"},
    {"key": "Mexico (Central) [mx-central-1]", "value": "mx-central-1"},
    {"key": "Middle East (Bahrain) [me-south-1]", "value": "me-south-1"},
    {"key": "Middle East (UAE) [me-central-1]", "value": "me-central-1"},
    {"key": "South America (São Paulo) [sa-east-1]", "value": "sa-east-1"},
]

REGIONS = [region.get("value") for region in REGION_CHOICES]
