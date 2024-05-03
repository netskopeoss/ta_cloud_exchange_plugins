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

CTE Trellix plugin constants.
"""

from netskope.integrations.cte.models import (
    IndicatorType,
)


# Plugin Information
PLATFORM_NAME = "Trellix"
MODULE_NAME = "CTE"
PLUGIN_NAME = "Trellix"
PLUGIN_VERSION = "1.0.0"

# Maximum Number of Reties for 4xx or 5xx or 6xx API Status Code.
MAX_API_CALLS = 4

DEFAULT_WAIT_TIME = 60
DEFAULT_BATCH_SIZE = 1000
MAX_WAIT_TIME = 300

# Maximum nos of Pages to pull in a single run cycle.
MAX_PAGE_COUNT = 100

# Trellix Last Seen request parameter datetime format.
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%S.%fZ"

# Trellix to Netskope datetime format of string representation.
NETSKOPE_DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%S.%fZ"

# Threat Types Supported by Trellix
# Threat having 'imphash' type will be skipped.
# Netskope Supports only SHA256, MD5, URL (Domain, IP, URL) type
THREAT_TYPES_TO_INTERNAL_TYPES = {
    "md5": IndicatorType.MD5,
    "sha256": IndicatorType.SHA256,
    "domain": IndicatorType.URL,
    "url": IndicatorType.URL,
    "ip": IndicatorType.URL,
}

TRELLIX_GRANT_TYPE = "client_credentials"
TRELLIX_API_SCOPES = ["ins.user | ins.suser | ins.ms. | soc.act.tg"]
TRELLIX_AUDIENCE = "iam_client"

TRELLIX_URLS = {
    "AUTHORIZATION": "https://iam.mcafee-cloud.com/iam/v1.4/token",
    "GET_IOCS": "{base_url}/insights/v2/iocs",
}


TRELLIX_CONFIG_PARAMS = {"base_url", "client_id", "client_secret", "api_key"}

INTEGER_THRESHOLD = 4611686018427387904
