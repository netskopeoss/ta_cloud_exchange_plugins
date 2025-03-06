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

CTE Anomali Threatstream plugin constants.
"""

from netskope.integrations.cte.models import SeverityType

SEVERITY_MAPPING = {
    "very-high": SeverityType.CRITICAL,
    "high": SeverityType.HIGH,
    "medium": SeverityType.MEDIUM,
    "low": SeverityType.LOW,
    "unknown": SeverityType.UNKNOWN,
    "": SeverityType.UNKNOWN,
}

ANOMALI_SEVERITY_MAPPING = {
    SeverityType.CRITICAL: "very-high",
    SeverityType.HIGH: "high",
    SeverityType.MEDIUM: "medium",
    SeverityType.LOW: "low",
    SeverityType.UNKNOWN: "",
}

INDICATOR_TYPES = ["md5", "sha256", "domain", "url", "ip", "ipv6"]
ANOMALI_SEVERITY = ["very-high", "high", "medium", "low"]
ANOMALI_STATUS = ["active", "inactive", "falsepos"]
MODULE_NAME = "CTE"
PLUGIN_NAME = "Anomali Threatstream XDR"
PLATFORM_NAME = "Anomali Threatstream XDR"
PLUGIN_VERSION = "1.3.0"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
RETRY_SLEEP_TIME = 50
MAX_PAGE_SIZE = 1000
PAGE_LIMIT = 100
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%S.%f%Z"
TARGET_SIZE_MB = 10
BYTES_TO_MB = 1024.0**2
DEFAULT_REPUTATION = 5
# Maximum number of Initial Range in Days.
INTEGER_THRESHOLD = 4611686018427387904

# Tag Name
TAG_NAME = "netskope-ce"
PREFIX_IOC_SOURCE = "Netskope CE"
SEPARATOR = "|"

# Retraction Constant
RETRACTION = "Retraction"
