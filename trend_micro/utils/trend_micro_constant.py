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

Trend Vision One Plugin to push and pull the data from Trend Vision One Platform.
"""

from netskope.integrations.cte.models import (
    IndicatorType,
    SeverityType,
)


TREND_MICRO_INDICATOR_TYPES = {
    "0": "fileSha256",
    "1": "domain",
    "2": "ip",
    "3": "url",
}


TRENDMICRO_TO_INTERNAL_TYPE = {
    "url": IndicatorType.URL,
    "domain": IndicatorType.URL,
    "ip": IndicatorType.URL,
    "fileSha256": IndicatorType.SHA256,
}

INTERNAL_TYPES_TO_TRENDMICRO = {
    IndicatorType.SHA256: "fileSha256",
    IndicatorType.URL: "domain",
}

TRENDMICRO_TO_INTERNAL_SEVERITY = {
    "high": SeverityType.HIGH,
    "medium": SeverityType.MEDIUM,
    "low": SeverityType.LOW,
}

INTERNAL_SEVERITY_TO_TRENDMICRO = {
    SeverityType.UNKNOWN: "",
    SeverityType.LOW: "low",
    SeverityType.MEDIUM: "medium",
    SeverityType.HIGH: "high",
    SeverityType.CRITICAL: "high",
}

TRENDMICRO_BASE_URLS = [
    "https://api.au.xdr.trendmicro.com",
    "https://api.eu.xdr.trendmicro.com",
    "https://api.in.xdr.trendmicro.com",
    "https://api.xdr.trendmicro.co.jp",
    "https://api.sg.xdr.trendmicro.com",
    "https://api.xdr.trendmicro.com",
]

INDICATOR_TYPES = ["domain", "fileSha256", "ip", "url"]
TRENDMICRO_SEVERITY = ["high", "medium", "low"]
MODULE_NAME = "CTE"
PLUGIN_NAME = "Trend Vision One"
PLUGIN_VERSION = "1.0.2"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
PLATFORM_NAME = "Trend Vision One"
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"
IOC_DESCRIPTION = "(Created from Netskope CTE)"
