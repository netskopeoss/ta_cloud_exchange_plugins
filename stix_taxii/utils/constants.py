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

Constants for STIX/TAXII plugin."""

from netskope.integrations.cte.models import IndicatorType
from netskope.integrations.cte.models.indicator import SeverityType

# user agent format
MODULE_NAME = "CTE"
PLUGIN_VERSION = "3.2.0"
PLATFORM_NAME = "STIX/TAXII"
USER_AGENT_FORMAT = "{}-{}-{}-v{}"
USER_AGENT_KEY = "User-Agent"
DEFAULT_USER_AGENT = "netskope-ce"
STIX_VERSION_1 = "1"
STIX_VERSION_20 = "2.0"
STIX_VERSION_21 = "2.1"
SERVICE_TYPE = "COLLECTION_MANAGEMENT"
RETRACTION = "Retraction"
IN_EXECUTION_MAX_RETRIES = 3
IN_EXECUTION_SLEEP_TIME = 60 # Sleep time in seconds
DATE_CONVERSION_STRING = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%S%fZ"

# Display format for validity times in comments
VALIDITY_DISPLAY_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

CONFIDENCE_TO_REPUTATION_MAPPINGS = {
    "High": 10,
    "Medium": 6,
    "Low": 3,
    "None": 1,
    "Unknown": 5,
}

LIKELY_IMPACT_TO_SEVERITY = {
    "High": SeverityType.CRITICAL,
    "Medium": SeverityType.HIGH,
    "Low": SeverityType.MEDIUM,
    "None": SeverityType.LOW,
    "Unknown": SeverityType.UNKNOWN,
}

IPV4_REGEX = r"ipv4-addr:value = '((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})'" # noqa
IPV6_REGEX = r"ipv6-addr:value = '((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|::(?:ffff(?::0{1,4})?::)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d))'" # noqa

OBSERVABLE_REGEXES = [
    {
        "regex": (
            r"file:hashes\.(?:'SHA-256'|\"SHA-256\")\s*="
            r"\s*('[a-z0-9]*'|\"[a-z0-9]*\")"
        ),
        "type": IndicatorType.SHA256,
    },
    {
        "regex": (
            r"file:hashes\.(?:MD5|'MD5'|\"MD5\")\s*="
            r"\s*('[a-z0-9]*'|\"[a-z0-9]*\")"
        ),
        "type": IndicatorType.MD5,
    },
    {
        "regex": r"url:value\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')", # noqa
        "type": IndicatorType.URL,
    },
    {
        "regex": r"domain-name:value\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')", # noqa
        "type": getattr(
            IndicatorType, "DOMAIN", IndicatorType.URL
        ),
    },
    {
        "regex": IPV4_REGEX,
        "type": getattr(
            IndicatorType, "IPV4", IndicatorType.URL
        ),
    },
    {
        "regex": IPV6_REGEX,
        "type": getattr(
            IndicatorType, "IPV6", IndicatorType.URL
        ),
    },
]

# Error resolution messages
PROXY_ERROR_RESOLUTION = (
    "Ensure the proxy server address, port, username, and "
    "password are correctly configured and the proxy server is "
    "accessible from the network."
)

CONNECTION_ERROR_RESOLUTION = (
    "Ensure the Discovery URL/API Root URL is correct, "
    "accessible from your network, and the TAXII server is "
    "running and reachable."
)

# Configuration field constants
DISCOVERY_URL_V1 = {
    "label": "Discovery URL",
    "key": "discovery_url",
    "type": "text",
    "default": "",
    "mandatory": True,
    "description": (
        "Discovery/Feed URL of TAXII server for version 1.x. "
        "Contact your STIX/TAXII support to get the appropriate URL."
    )
}

DISCOVERY_URL_V2 = {
    "label": "API Root URL",
    "key": "discovery_url",
    "type": "text",
    "default": "",
    "mandatory": True,
    "description": (
        "API Root URL of TAXII server for version 2.x. "
        "Contact your STIX/TAXII support to get the appropriate URL."
    )
}

USERNAME_CONFIG = {
    "label": "Username",
    "key": "username",
    "type": "text",
    "mandatory": False,
    "description": "Username required for authentication if any."
}

PASSWORD_CONFIG = {
    "label": "Password",
    "key": "password",
    "type": "password",
    "mandatory": False,
    "description": "Password required for authentication if any."
}

COLLECTION_NAMES_CONFIG = {
    "label": "Collection Names",
    "key": "collection_names",
    "type": "text",
    "default": "",
    "mandatory": False,
    "description": (
        "Comma separated collection names from which data needs to be "
        "fetched. Leave empty to fetch data from all of the collections."
    )
}

PAGINATION_METHOD_CONFIG_V2 = {
    "label": "Pagination Method",
    "key": "pagination_method",
    "description": (
        "Pagination Method to use while pulling the indicators. "
        "Contact your STIX/TAXII support to choose the appropriate option."
    ),
    "type": "choice",
    "choices": [
        {"key": "Next", "value": "next"},
        {"key": "X-TAXII-Date-Added-Last", "value": "last_added_date"}
    ],
    "mandatory": True,
    "default": "next"
}

INITIAL_RANGE_CONFIG = {
    "label": "Initial Range (in days)",
    "key": "days",
    "type": "number",
    "mandatory": True,
    "default": 7,
    "description": "Number of days to pull the data for the initial run. Must be an integer in range 1 to 365."
}

LOOK_BACK_CONFIG = {
    "label": "Look Back (in minutes)",
    "key": "delay",
    "type": "number",
    "mandatory": False,
    "description": (
        "Number of minutes to backdate the start time for pulling the data. "
        "Valid value is anything between 1 to 1440."
    )
}

TYPE_V1 = {
    "label": "Type of Threat data to pull",
    "key": "type",
    "type": "multichoice",
    "choices": [
        {"key": "SHA-256", "value": "sha256"},
        {"key": "MD5", "value": "md5"},
        {"key": "URL", "value": "url"},
        {"key": "Domain", "value": "domain"}
    ],
    "default": ["sha256", "md5", "url", "domain"],
    "mandatory": False,
    "description": "Type of Threat data to pull. Keep empty to fetch indicators of all types."
}

TYPE_V2 = {
    "label": "Type of Threat data to pull",
    "key": "type",
    "type": "multichoice",
    "choices": [
        {"key": "SHA-256", "value": "sha256"},
        {"key": "MD5", "value": "md5"},
        {"key": "URL", "value": "url"},
        {"key": "IPv4", "value": "ipv4"},
        {"key": "IPv6", "value": "ipv6"},
        {"key": "Domain", "value": "domain"}
    ],
    "default": ["sha256", "md5", "url", "ipv4", "ipv6", "domain"],
    "mandatory": False,
    "description": (
        "Type of Threat data to pull. "
        "IPv4/IPv6 is supported for STIX/TAXII version 2.x. "
        "Keep empty to fetch indicators of all types."
    )
}

SEVERITY_V1 = {
    "label": "Severity",
    "key": "severity",
    "type": "multichoice",
    "choices": [
        {"key": "Unknown", "value": "unknown"},
        {"key": "Low", "value": "low"},
        {"key": "Medium", "value": "medium"},
        {"key": "High", "value": "high"},
        {"key": "Critical", "value": "critical"}
    ],
    "default": ["critical", "high", "medium", "low", "unknown"],
    "mandatory": False,
    "description": (
        "Only indicators with matching severity will be fetched. "
        "Keep empty to fetch indicators of all severity."
    )
}

SEVERITY_V2 = {
    "label": "Severity",
    "key": "severity",
    "type": "multichoice",
    "choices": [
        {"key": "Unknown", "value": "unknown"},
    ],
    "default": ["unknown"],
    "mandatory": False,
    "description": (
        "Only indicators with matching severity will be fetched. "
        "For STIX/TAXII version 2.x, Unknown should be selected because "
        "for all the indicators fetched from these versions would have "
        "Unknown severity. "
        "Keep empty to fetch indicators of all severity."
    )
}

REPUTATION_CONFIG = {
    "label": "Reputation",
    "key": "reputation",
    "type": "number",
    "mandatory": True,
    "default": 5,
    "description": (
        "Only indicators with reputation equal to or greater than "
        "this will be stored. Must be an integer in range 1 to 10."
    )
}

BATCH_SIZE_CONFIG_V20 = {
    "label": "Batch Size",
    "key": "batch_size",
    "type": "number",
    "mandatory": True,
    "default": 1000,
    "description": "Number of indicators to fetch per bundle. Must be an integer in range 2 to 1000."
}

BATCH_SIZE_CONFIG_V21 = {
    "label": "Batch Size",
    "key": "batch_size",
    "type": "number",
    "mandatory": True,
    "default": 1000,
    "description": "Number of indicators to fetch per bundle. Must be an integer in range 1 to 1000."
}

RETRACTION_INTERVAL_CONFIG = {
    "label": "Retraction Interval (in days)",
    "key": "retraction_interval",
    "type": "number",
    "mandatory": False,
    "description": (
        "Number of days to look back for retraction checks. "
        "Leave empty to disable retraction. Must be an integer in range 1 to 365."
    )
}
