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

CTE Carbon Black plugin constants.
"""

from netskope.integrations.cte.models import SeverityType

MODULE_NAME = "CTE"
PLUGIN_NAME = "Carbon Black"
PLATFORM_NAME = "Carbon Black"
PLUGIN_VERSION = "1.1.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 30
MAX_PULL_PAGE_SIZE = 2000
DATE_FORMAT_FOR_IOCS = "%Y-%m-%dT%H:%M:%S.%f%Z"

CARBONBLACK_TO_INTERNAL_TYPE = {
    0: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.LOW,
    4: SeverityType.MEDIUM,
    5: SeverityType.MEDIUM,
    6: SeverityType.MEDIUM,
    7: SeverityType.HIGH,
    8: SeverityType.HIGH,
    9: SeverityType.HIGH,
    10: SeverityType.CRITICAL,
}

FETCH_ALERS_API_ENDPOINT = "{}/api/alerts/v7/orgs/{}/alerts/_search"
FEEDS_API_ENDPOINT = "{}/threathunter/feedmgr/v2/orgs/{}/feeds"

REPUTATION = [
    "ADAPTIVE_WHITE_LIST",
    "COMPANY_BLACK_LIST",
    "COMMON_WHITE_LIST",
    "KNOWN_MALWARE",
    "NOT_LISTED",
    "PUP",
    "SUSPECT_MALWARE",
    "TRUSTED_WHITE_LIST",
]
VALIDATION_MSG = "Verify the API ID, Organization Key, and API Secret provided in the configuration parameters."
