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

CTE CrowdStrike plugin constants.
"""

from netskope.integrations.cte.models import IndicatorType, SeverityType

BASE_URLS = [
    "https://api.crowdstrike.com",
    "https://api.us-2.crowdstrike.com",
    "https://api.laggar.gcw.crowdstrike.com",
    "https://api.eu-1.crowdstrike.com",
]
PAGE_SIZE = 9999
MODULE_NAME = "CTE"
PLUGIN_NAME = "CrowdStrike"
PLATFORM_NAME = "CrowdStrike"
PLUGIN_VERSION = "2.3.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
DEFAULT_BATCH_SIZE = 200
MAX_WAIT_TIME = 300
MAX_LIMIT_FOR_HOSTS = 100
MAX_RETRY_AFTER_IN_MIN = 5
ISOLATE_REMEDIATE_BATCH_SIZE = 5000
IOC_MANAGEMENT_INDICATORS_LIMIT = 1000000
MAX_INDICATOR_THRESHOLD = 100000
DATE_FORMAT = r"%Y-%m-%dT%H:%M:%S.%f%zZ"
ENDPOINT_DETECTION_DETAILS_BATCH_SIZE = 1000
ENDPOINT_DETECTION = "CrowdStrike Endpoint Detections"
IOC_MANAGEMENT = "CrowdStrike Custom IOC Management"
IOC_MANAGEMENT_PULL_PAGE_LIMIT = 2000
DEFAULT_NETSKOPE_TAG = "netskope-ce"
THREAT_TYPES = ["sha256", "md5", "domain", "ipv4", "ipv6"]
THREAT_MAPPING = {
    "sha256": ["hash_sha256", "sha256"],
    "md5": ["hash_md5", "md5"],
    "domain": ["domain"],
    "ipv4": ["ipv4"],
    "ipv6": ["ipv6"],
}
PREFIX_IOC_SOURCE_TAG = "Netskope - Cloud Threat Exchange"
NON_CROWDSTRIKE_DISCOVERED = "non-CrowdStrike-discovered"
INTEGER_THRESHOLD = 4611686018427387904
RETRACTION = "Retraction"
IOC_SOURCE_PAGES = ["endpoint_detections", "ioc_management"]
IOC_MANAGEMENT_SEVERITY_MAPPING = {
    "": SeverityType.UNKNOWN,
    "informational": SeverityType.UNKNOWN,
    "low": SeverityType.LOW,
    "medium": SeverityType.MEDIUM,
    "high": SeverityType.HIGH,
    "critical": SeverityType.CRITICAL,
}
CROWDSTRIKE_TO_INTERNAL_TYPE = {
    "hash_md5": IndicatorType.MD5,
    "hash_sha256": IndicatorType.SHA256,
    "domain": getattr(IndicatorType, "DOMAIN", IndicatorType.URL),
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "ipv4": getattr(IndicatorType, "IPV4", IndicatorType.URL),
    "ipv6": getattr(IndicatorType, "IPV6", IndicatorType.URL),
}
INTERNAL_TYPES_TO_CROWDSTRIKE = {
    IndicatorType.MD5: "md5",
    IndicatorType.SHA256: "sha256",
    IndicatorType.URL: "domain",
}

# Bifurcated IndicatorType
BIFURCATE_INDICATOR_TYPES = {
    "url",
    "domain",
    "hostname",
    "ipv4",
    "ipv6",
    "fqdn",
}

CASE_INSENSITIVE_IOC_TYPES = ["md5", "sha256", "ipv6"]

API_ENDPOINTS = {
    "pull_ioc_management": "{}/iocs/combined/indicator/v1",
    "endpoint_detections": "{}/alerts/combined/alerts/v1",
    "devices": "{}/indicators/queries/devices/v1",
    "devices_actions": "{}/devices/entities/devices-actions/v2",
    "update_ioc_management": "{}/iocs/entities/indicators/v1",
}