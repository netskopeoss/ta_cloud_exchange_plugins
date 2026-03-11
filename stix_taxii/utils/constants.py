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
USER_AGENT_FORMAT = "{}-{}-{}-v{}"
USER_AGENT_KEY = "User-Agent"
DEFAULT_USER_AGENT = "netskope-ce"
STIX_VERSION_1 = "1"
STIX_VERSION_20 = "2.0"
STIX_VERSION_21 = "2.1"
SERVICE_TYPE = "COLLECTION_MANAGEMENT"

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
DATE_CONVERSION_STRING = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%S%fZ"
# page size
LIMIT = 1000

# page
BUNDLE_LIMIT = 100

MODULE_NAME = "CTE"
PLUGIN_VERSION = "3.1.0"
PLATFORM_NAME = "STIX/TAXII"
