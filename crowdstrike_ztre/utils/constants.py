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

CRE CrowdStrike Constants module.
"""

PAGE_SIZE = 5000
BATCH_SIZE = 1000
HOST_FETCH_BATCH_SIZE = 5000
MAC_PUT_DIR = r"/Library/Application Support/Netskope/STAgent"
WINDOWS_PUT_DIR = r"C:\Program Files (x86)\Netskope\STAgent"  # noqa
PLUGIN_NAME = "CrowdStrike"
PLATFORM_NAME = "CrowdStrike"
PLUGIN_VERSION = "1.1.0"
MODULE_NAME = "CRE"
MAX_API_CALLS = 3
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER_IN_MIN = 5
CROWDSTRIKE_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
COMMAND_TIMEOUT = 60
COMMAND_WAIT = 6
SCORE_NORMALIZE_MULTIPLIER = 10
SCRIPT_PERMISSION_TYPE = "public"
HOST_MANAGEMENT_PAGE = "Host management page"
ZERO_TRUST_ASSESSMENT_PAGE = "Zero trust assessment page"
SCORE_TO_FILE_MAPPING = {
    "1_25": "crwd_zta_1_25.txt",
    "26_50": "crwd_zta_26_50.txt",
    "51_75": "crwd_zta_51_75.txt",
    "76_100": "crwd_zta_76_100.txt",
}
WINDOWS_REMOVE_FILE_SCRIPT_NAME = "Windows Score File Removal Script"
MAC_REMOVE_FILE_SCRIPT_NAME = "Mac Score File Removal Script"
BASE_URLS = [
    "https://api.crowdstrike.com",
    "https://api.us-2.crowdstrike.com",
    "https://api.laggar.gcw.crowdstrike.com",
    "https://api.eu-1.crowdstrike.com",
]
HOST_ID = "Host ID"
SERIAL_NUMBER = "System Serial Number"
OVERALL_ASSESSMENT_SCORE = "Overall Assessment Score"
NETSKOPE_NORMALIZED_SCORE = "Netskope Normalized Score"
MAXIMUM_CE_VERSION = "5.1.2"

AGEENT_ENTITY_MAPPING = {
    "Host ID": {"key": "aid"},
    "System Serial Number": {"key": "system_serial_number"},
    "Overall Assessment Score": {"key": "assessment.overall"},
}

HOST_ENTITY_MAPPING = {
    "Host ID": {"key": "device_id"},
    "System Serial Number": {"key": "serial_number"},
    "Tags": {"key": "tags"},
    "CID": {"key": "cid"},
    "Agent Version": {"key": "agent_version"},
    "BIOS Manufacturer": {"key": "bios_manufacturer"},
    "BIOS Version": {"key": "bios_version"},
    "Build Number": {"key": "build_number"},
    "External IP": {"key": "external_ip"},
    "Mac Address": {"key": "mac_address"},
    "Hostname": {"key": "hostname"},
    "First Seen": {"key": "first_seen"},
    "Last Login User": {"key": "last_login_user"},
    "Last Login User SID": {"key": "last_login_user_sid"},
    "Last Seen": {"key": "last_seen"},
    "Local IP": {"key": "local_ip"},
    "OS Version": {"key": "os_version"},
    "OS Build": {"key": "os_build"},
    "Platform ID": {"key": "platform_id"},
    "Platform Name": {"key": "platform_name"},
    "RTR State": {"key": "rtr_state"},
    "Groups": {"key": "groups"},
    "Product Type": {"key": "product_type"},
    "Product Type Description": {"key": "product_type_desc"},
    "Provision Status": {"key": "provision_status"},
    "Status": {"key": "status"},
    "System Manufacturer": {"key": "system_manufacturer"},
    "System Product Name": {"key": "system_product_name"},
    "Modified Timestamp": {"key": "modified_timestamp"},
    "Kernel Version": {"key": "kernel_version"},
    "OS Product Name": {"key": "os_product_name"},
    "Chassis Type": {"key": "chassis_type"},
    "Chassis Type Description": {"key": "chassis_type_desc"},
    "Connection IP": {"key": "connection_ip"},
    "Default Gateway IP": {"key": "default_gateway_ip"},
    "Connection Mac Address": {"key": "connection_mac_address"},
    "Filesystem Containment Status": {"key": "filesystem_containment_status"},
}
