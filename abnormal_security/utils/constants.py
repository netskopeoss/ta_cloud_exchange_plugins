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

"""Abnormal Security Plugin constants."""

from netskope.integrations.cte.models import IndicatorType

MODULE_NAME = "CTE"
PLUGIN_NAME = "Abnormal Security"
PLATFORM_NAME = "Abnormal Security"
PLUGIN_VERSION = "1.1.0"
API_RESPONSE_LIMIT = 100
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
MAX_API_CALLS = 4
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RETRACTION = "Retraction"
ABNORMAL_SITES = {
    "Production Server (api.abnormalplatform.com/v1)": "https://api."
    "abnormalplatform.com/v1",
    "EU Production Server (eu.rest.abnormalsecurity.com/v1)": "https://eu."
    "rest.abnormalsecurity.com/v1",
    "FedRAMP GovCloud (rest.abnormalsecurity.us)": "https://rest."
    "abnormalsecurity.us",
}
INDICATOR_TYPES = {
    "SHA256": "sha256",
    "MD5": "md5",
    "URL": "url",
    "DOMAIN": "domain",
    "IPV4": "ipv4",
    "IPV6": "ipv6",
}
INDICATOR_TYPE_LIST = list(INDICATOR_TYPES.values())
CONFIGURATION_BOOLEAN_VALUES = {"Yes": "yes", "No": "no"}
# The maximum CE version that does not support partial action failure
MAXIMUM_CE_VERSION = "5.1.2"

ABNORMAL_SECURITY_TO_INTERNAL_TYPE = {
    "domain": (
        IndicatorType.DOMAIN
        if hasattr(IndicatorType, "DOMAIN")
        else IndicatorType.URL
    ),
    "ipv4": (
        IndicatorType.IPV4
        if hasattr(IndicatorType, "IPV4")
        else IndicatorType.URL
    ),
    "ipv6": (
        IndicatorType.IPV6
        if hasattr(IndicatorType, "IPV6")
        else IndicatorType.URL
    ),
    "url": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
}
