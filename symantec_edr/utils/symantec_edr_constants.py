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

CTE Symantec EDR plugin constants.
"""

from netskope.integrations.cte.models import SeverityType, IndicatorType

MODULE_NAME = "CTE"
PLUGIN_NAME = "Symantec EDR"
PLATFORM_NAME = "Symantec EDR"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 30
MAX_PULL_PAGE_SIZE = 1000
DATE_FORMAT_FOR_IOCS = "%Y-%m-%dT%H:%M:%S.%f%Z"

DISPOSITION_TO_SEVERITY_MAPPING = {
    1: SeverityType.UNKNOWN,
    0: SeverityType.LOW,
    2: SeverityType.HIGH,
    3: SeverityType.CRITICAL,
}
FILE_HEALTH_TO_SEVERITY_MAPPING = {
    2: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    3: SeverityType.HIGH,
    4: SeverityType.CRITICAL,
    6: SeverityType.MEDIUM,
}

SYMANTEC_EDR_TO_INDICATOR_TYPE_MAPPING = {
    "external_domain_latest": IndicatorType.URL,
    "file_latest": IndicatorType.SHA256,
    "endpoint_latest": IndicatorType.URL,
}

VALIDATION_MSG = "Verify the Server URL, Client ID, and Client Secret provided in the configuration parameters."
