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

CTE Cynet plugin constants.
"""

from netskope.integrations.cte.models import (
    IndicatorType,
    SeverityType,
)


# Plugin Information
PLATFORM_NAME = "Cynet"
MODULE_NAME = "CTE"
PLUGIN_NAME = "Cynet"
PLUGIN_VERSION = "1.0.0"

# Maximum Number of Reties for 4xx or 5xx or 6xx API Status Code.
MAX_API_CALLS = 3

DEFAULT_WAIT_TIME = 300
DEFAULT_BATCH_SIZE = 100
MAX_WAIT_TIME = 300

# Cynet Last Seen request parameter datetime format.
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"

# Cynet to Netskope datetime format of string representation.
NETSKOPE_DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"

# Threat Types Supported by Cynet
# THREAT_TYPES = ["sha256", "md5", "domain", "ipv4", "ipv6"]
THREAT_TYPES = {
    "0": "sha256",
    "1": "domain",
    "2": "ip",
    "3": "url",
    # "4": "USER",
    # "5": "HOST",
    # "6": "System",
}

# Netskope Supports only SHA256, MD5, URL (Domain, IP, URL) type
# MD5 is not supported by cynet.
THREAT_TYPES_TO_INTERNAL_TYPE = {
    "0": IndicatorType.SHA256,
    "1": IndicatorType.URL,
    "2": IndicatorType.URL,
    "3": IndicatorType.URL,
}

# Value Field Mapping based on the alert type.
CYNET_ALERT_VALUE = {
    "0": "Sha256",
    "1": "AlertDomain",
    "2": "AlertIp",
    "3": "AlertUrl",
}

# Severity Types Supported by Cynet
SEVERITY_TYPES = {
    1: "Information",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    99: "Unknown",
}

NETSKOPE_SEVERITY_TYPES = {
    1: SeverityType.UNKNOWN,
    2: SeverityType.LOW,
    3: SeverityType.MEDIUM,
    4: SeverityType.HIGH,
    5: SeverityType.CRITICAL,
    99: SeverityType.UNKNOWN,
}

CYNET_THREAT_STATUS = {
    "0": "Open",
    "1": "Pending",
    "2": "Ignored",
    "3": "Closed",
}

CYNET_URLS = {
    "AUTHENTICATION": "{base_url}/api/account_token",
    "GET_ALERTS_COUNT": "{base_url}/api/alerts/count",
    "GET_ALERTS_STATUS": "{base_url}/api/alerts/bulkByDateChanged",
    "GET_ALERTS_PAGINATION": "{base_url}/api/alerts/bulk",
    "GET_LATEST_ALERTS": "{base_url}/api/alerts",
    "REMEDIATION_KILL": "{base_url}/api/file/remediation/kill",
    "REMEDIATION_QUARANTINE": "{base_url}/api/file/remediation/path/quarantine",  # noqa
    "REMEDIATION_UNQUARANTINE": "{base_url}/api/file/remediation/unquarantine",
    "REMEDIATION_DELETE": "{base_url}/api/file/remediation/delete",
    "REMEDIATION_VERIFY": "{base_url}/api/file/remediation/verify",
}

CYNET_CONFIG_PARAMS = {"base_url", "user_name", "password", "client_id"}

GET_ACTION_LABEL = {
    "delete_file": "Delete File",
    "quarantine": "Quarantine",
    "unquarantine": "Unquarantine",
    "verify_file": "Verify File",
    "kill_process": "Kill Process",
}

GET_URLS_FROM_LABEL = {
    "delete_file": "REMEDIATION_DELETE",
    "quarantine": "REMEDIATION_QUARANTINE",
    "unquarantine": "REMEDIATION_UNQUARANTINE",
    "verify_file": "REMEDIATION_VERIFY",
    "kill_process": "REMEDIATION_KILL",
}

INTEGER_THRESHOLD = 4611686018427387904
