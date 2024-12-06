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

CRE CyberArk plugin constants.
"""

MODULE_NAME = "CRE"
PLUGIN_NAME = "CyberArk"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "CyberArk"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
PAGE_SIZE = 10000
BATCH_SIZE = 100
USERS_FIELD_MAPPING = {
    "User ID": {"key": "Row.ID"},
    "Display Name": {"key": "Row.DisplayName"},
    "Username": {"key": "Row.Username"},
    "Login Name": {"key": "Row.LoginName"},
    "Email": {"key": "Row.Email"},
    "Status": {"key": "Row.Status"},
    "Status Enum (Localized Status)": {"key": "Row.StatusEnum"},
    "Risk Level": {"key": "Row.RiskLevel"},
    "Risk Level Localized": {"key": "Row.RiskLevelLocalized"},
    "Risk Level Rank": {"key": "Row.RiskLevelRank"},
}
USERS_ENTITY = "Users"
NORMALIZATION_MAPPING = {
    "Unknown": None,
    "Normal": 875,
    "Low": 625,
    "Medium": 375,
    "High": 125
}
