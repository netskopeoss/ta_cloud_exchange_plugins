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
"""

"""Cybereason Plugin implementation to push and pull the data from Cybereason Platform."""

from netskope.integrations.cte.models import (
    IndicatorType,
)

CYBEREASON_TO_INTERNAL_TYPE = {
    "hash_md5": IndicatorType.MD5,
    "hash_sha256": IndicatorType.SHA256,
    "domain": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "ipv4": IndicatorType.URL,
}

INTERNAL_TYPES_TO_CYBEREASON = {
    "IndicatorType.MD5": "md5",
    "IndicatorType.SHA256": "sha256",
    "IndicatorType.URL": "domain",
}

MODULE_NAME = "CTE"
PLUGIN_NAME = "Cybereason"
PLUGIN_VERSION = "1.1.0"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
PLATFORM_NAME = "Cybereason"
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"
INDICATOR_TYPES = [
    "domain",
    "hash_md5",
    "hash_sha256",
    "sha256",
    "md5",
    "ipv4",
]
IOC_DESCRIPTION = "(Created from Netskope CTE)"
