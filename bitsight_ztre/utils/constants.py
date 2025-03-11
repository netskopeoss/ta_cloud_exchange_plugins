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

CRE Bitsight plugin constants.
"""

PLATFORM_NAME = "Bitsight"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
PAGE_LIMIT = 1000
COMPANIES_LIMIT = 10000
INTEGER_THRESHOLD = 4611686018427387904
MAX_TIERS = 5

ENTITY_NAME = "Companies"
BASE_URL = "https://api.bitsighttech.com"
API_ENDPOINTS = {
    "portfolio": f"{BASE_URL}/ratings/v2/portfolio",
    "companies": BASE_URL + "/v1/tiers/{tier_guid}/companies",
    "get_teirs": BASE_URL + "/ratings/v1/tiers",
    "get_company_details": BASE_URL + "/ratings/v1/companies/{company_guid}",
    "create_tier": BASE_URL + "/ratings/v1/tiers",
}
NETSKOPE_NORMALIZED_SCORE = "Netskope Normalized Score"
COMPANY_FIELD_MAPPING = {
    "Company GUID": {"key": "guid"},
    "Security Rating": {"key": "rating", "transformation": "integer"},
    "Company Name": {
        "key": "name",
    },
    "Rating Type": {"key": "type"},
    "Primary Domain": {"key": "primary_domain"},
    "Tier GUID": {"key": "tier"},
    "Tier Name": {"key": "tier_name"},
    "Confidence": {
        "key": "details.confidence",
    },
}
