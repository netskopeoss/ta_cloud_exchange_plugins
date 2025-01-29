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

CRE Mimecast Plugin constants.
"""

PLATFORM_NAME = "Mimecast"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "2.0.0"
DEFAULT_RETRY_AFTER_TIME = 60000
MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES = 2036
MAX_PAGE_SIZE = 100
ADD_TO_GROUP_BATCH_SIZE = 10
MAX_API_CALLS = 4
MIMECAST_SCORE_MAPPING = {"A": 800, "B": 600, "C": 400, "D": 200, "F": 1}
NETSKOPE_RISK_CATEGORY_MAPPING = {
    "A": "Low",
    "B": "Medium",
    "C": "High",
    "D": "Critical",
    "F": "Critical",
}

EMAIL_ADDRESS_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Field mapping
USER_FIELD_MAPPING = {
    "User Email": {"key": "emailAddress"},
    "User Name": {"key": "name"},
    "User Risk": {"key": "risk"},
}

# All the Endpoints
BASE_URL = "https://api.services.mimecast.com"
GET_BEARER_TOKEN_ENDPOINT = "oauth/token"
FIND_GROUPS_ENDPOINT = "api/directory/find-groups"
CREATE_GROUP_ENDPOINT = "api/directory/create-group"
ADD_GROUP_MEMBER_ENDPOINT = "api/directory/add-group-member"
REMOVE_GROUP_MEMBER_ENDPOINT = "api/directory/remove-group-member"
GET_ACCOUNT_DETAILS_ENDPOINT = "api/account/get-account"
GET_SAFE_SCORE_DETAILS_ENDPOINT = (
    "api/awareness-training/company/get-safe-score-details"
)
