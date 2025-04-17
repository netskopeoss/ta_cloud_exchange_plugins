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

CRE Tanium Plugin constants.
"""

MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "HPE Aruba Networking Central"
PAGE_SIZE = 1000
DEFAULT_WAIT_TIME = 60
MAX_RETRIES = 4
ONE = 1
RATE_LIMIT_PER_SECOND = 7
ACTION_BATCH_SIZE = 100
WIRED_CLIENT_FIELD_MAPPING = {
    "MAC Address": {"key": "macaddr"},
    "Client Type": {"key": "client_type", "default": "WIRED"},
    "IPv4": {"key": "ip_address"},
    "Username": {"key": "username"},
    "VLAN": {"key": "vlan"},
    "Hostname": {"key": "hostname"},
    "Associated Device MAC Address": {"key": "associated_device_name"},
    "Associated Device Serial Number": {"key": "associated_device"},
    "Name": {"key": "name"},
    "Group Name": {"key": "group_name"},
    "Swarm ID": {"key": "swarm_id", "default": ""},
}
WIRELESS_CLIENT_FIELD_MAPPING = {
    "MAC Address": {"key": "macaddr"},
    "Client Type": {"key": "client_type", "default": "WIRELESS"},
    "IPv4": {"key": "ip_address"},
    "Username": {"key": "username"},
    "VLAN": {"key": "vlan"},
    "Hostname": {"key": "hostname"},
    "Authentication Type": {"key": "authentication_type"},
    "Encryption Method": {"key": "encryption_method"},
    "Associated Device MAC Address": {"key": "associated_device_name"},
    "Associated Device Serial Number": {"key": "associated_device"},
    "Name": {"key": "name"},
    "Connection Standard": {"key": "connection"},
    "Operating System Type": {"key": "os_type"},
    "Group Name": {"key": "group_name"},
    "Swarm ID": {"key": "swarm_id", "default": ""},
}
WIRED_CLIENTS_API_URL = "{base_url}/monitoring/v1/clients/wired"
WIRELESS_CLIENTS_API_URL = "{base_url}/monitoring/v1/clients/wireless"
BLACKLIST_API_URL = "{base_url}/configuration/v1/swarm/{swarm_id}/blacklisting"
DISCONNECT_CLIENT_API_URL = (
    "{base_url}/device_management/v1/device/{device_serial}/action/disconnect_user"
)
SUCCESS = "success"
UNAUTHORIZED = "unauthorized"
FAILED = "failed"
