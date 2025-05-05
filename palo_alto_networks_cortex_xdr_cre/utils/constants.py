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

CRE Palo Alto Networks Cortex XDR plugin constants.
"""

MODULE_NAME = "CRE"
PLATFORM_NAME = "Palo Alto Networks Cortex XDR"
PLUGIN_VERSION = "1.0.0"
PAGE_SIZE = 100
ACTION_BATCH_SIZE = 1000
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
STANDARD = "standard"
ADVANCED = "advanced"
ONE = 1
VALIDATE_API = "/api_keys/validate/"
FETCH_USERS_API = "/public_api/v1/get_risky_users"
FETCH_HOSTS_API = "/public_api/v1/get_risky_hosts"
FETCH_ENDPOINTS_API = "/public_api/v1/endpoints/get_endpoint"
ENDPOINT_FIELD_MAPPING = {
    "Endpoint ID": {"key": "endpoint_id"},
    "Endpoint Name": {"key": "endpoint_name"},
    "IPv4 Address": {"key": "ip"},
    "IPv6 Address": {"key": "ipv6"},
    "Public IP Address": {"key": "public_ip"},
    "Users": {"key": "users"},
    "Domain": {"key": "domain"},
    "MAC Address": {"key": "mac_address"},
    "Isolation Status": {"key": "is_isolated"},
    "Operational Status": {"key": "operational_status"},
    "Scan Status": {"key": "scan_status"},
    "Group Name": {"key": "group_name"},
    "Endpoint Type": {"key": "endpoint_type"},
    "Endpoint Status": {"key": "endpoint_status"},
    "Operating System Type": {"key": "os_type"},
    "Operating System Name": {"key": "operating_system"},
    "Operating System Version": {"key": "os_version"},
    "Server Tags": {"key": "tags.server_tags"},
    "Endpoint Tags": {"key": "tags.endpoint_tags"},
    "Risk Level": {"key": "risk_level"},
    "Risk Score": {"key": "score"},
    "Normalized Risk Score": {"key": "norm_risk_score"},
}
USER_FIELD_MAPPING = {
    "User ID": {"key": "id"},
    "Email": {"key": "email"},
    "Risk Level": {"key": "risk_level"},
    "Risk Score": {"key": "score"},
    "Normalized Risk Score": {"key": "norm_risk_score"},
}
USERS = "Users"
ENDPOINTS = "Endpoints"
ISOLATE = "isolate"
UNISOLATE = "un-isolate"
RUNSCAN = "run-scan"
CANCELSCAN = "cancel-scan"
CONFIGURATION = "configuration"
ACTION = "action"
