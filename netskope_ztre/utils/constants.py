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

Netskope CRE plugin Constants."""

MAX_RETRY_COUNT = 4
DEFAULT_WAIT_TIME = 60
DEVICE_BULK_TAG_INTER_BATCH_SLEEP = 12
PAGE_SIZE = 100
MAX_HOSTS_PER_PRIVATE_APP = 500
USERS_BATCH_SIZE = 512
APPLICATIONS_BATCH_SIZE = 100
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"
)
REGEX_EMAIL = r"[^@]+@[^@]+\.[^@]+"
REGEX_TAG = r"^[a-zA-Z0-9- ]*$"
MODULE_NAME = "CRE"
PLUGIN = "Netskope Risk Exchange"
PLUGIN_VERSION = "1.7.0"
URLS = {
    "V2_PRIVATE_APP": "/api/v2/steering/apps/private",
    "V2_PRIVATE_APP_PATCH": "/api/v2/steering/apps/private/{}",
    "V2_PUBLISHER": "/api/v2/infrastructure/publishers",
    "V2_CCI_TAG_CREATE": "/api/v2/services/cci/tags",
    "V2_CCI_TAG_UPDATE": "/api/v2/services/cci/tags/{}",
    "V2_DEVICE_GET_TAGS": "/api/v2/devices/device/tags/gettags",
    "V2_DEVICE_TAG": "/api/v2/devices/device/tags",
    "V2_DEVICE_BULK_ADD_TAGS": "/api/v2/devices/device/tags/bulkadd",
    "V2_DEVICE_BULK_REMOVE_TAGS": "/api/v2/devices/device/tags/bulkremove",
    "V2_DEVICE_BULK_REPLACE_TAGS": "/api/v2/devices/device/tags/bulkreplace",
    "V1_APP_INSTANCE": "/api/v1/app_instances",
    "V2_SCIM_GROUPS": "/api/v2/scim/Groups",
    "V2_SCIM_USERS": "/api/v2/scim/Users",
    "V2_UCI_RESET": "/api/v2/incidents/users/uci/reset",
    "V2_CCI_APP": "/api/v2/services/cci/app",
    "V2_CCI_DOMAINS": "/api/v2/services/cci/domain",
    "V2_CCI_TAGS": "/api/v2/services/cci/tags",
    "V2_UCI_IMPACT": "/api/v2/incidents/user/uciimpact",
    "V2_GET_UCI": "/api/v2/incidents/uba/getuci",
    "V2_REVERT_UCI_IMPACT": "/api/v2/incidents/anomalies/{}/allow"
}
ERROR_TAG_EXISTS = (
    "Tag provided is already present. Hence use PATCH method to add "
    "existing tag to the list of apps/ids"
)
ERROR_APP_DOES_NOT_EXIST = "No records matched"
SUCCESS = "Success"
TAG_NOT_FOUND = "Tag provided is not present"
TAG_EXISTS = "Tag provided is already present"
# Bulk actions batch size
ADD_REMOVE_USER_BATCH_SIZE = 5000
APP_INSTANCE_BATCH_SIZE = 500
TAG_APP_BATCH_SIZE = 100
TAG_APP_TAG_LENGTH = 75
TAG_DEVICE_TAG_LENGTH = 80
TAG_DEVICE_BATCH_SIZE = 1000
MAX_TAGS_PER_DEVICE = 5
TAG_CACHE_PAGE_SIZE = 10
DEVICE_FIELD_MAPPING = {
    "Device ID": {"key": "device_id"},
    "Hostname": {"key": "host_info.hostname"},
    "Netskope Device UID": {"key": "host_info.nsdeviceuid"},
    "Mac Addresses": {"key": "host_info.mac_addresses"},
    "Device Serial Number": {"key": "host_info.serial_number"},
    "Operating System": {"key": "host_info.os"},
    "Operating System Version": {"key": "host_info.os_version"},
    "Device Make": {"key": "host_info.device_make"},
    "Device Model": {"key": "host_info.device_model"},
    "Last Updated Timestamp": {"key": "host_info.last_update_timestamp"},
    "Management ID": {"key": "host_info.managementID"},
    "Steering Config": {"key": "host_info.steering_config"},
    "Region": {"key": "region"},
    "User Name": {"key": "user_info.username"},
    "User Key": {"key": "user_info.userkey"},
    "Device Classification Status": {
        "key": "user_info.device_classification_status"
    },
    "Last Connected from Private IP": {
        "key": "last_connected_from_private_ip"
    },
    "Last Connected from Public IP": {
        "key": "last_connected_from_public_ip"
    },
}
USER_FIELD_MAPPING = {
    "email": {"key": "userkey"},
    "ubaScore": {"key": "uba_score"},
    "policyName": {"key": "policy"},
    "cci": {"key": "cci"},
    "ccl": {"key": "ccl"},
    "deviceClassification": {"key": "device_classification"},
    "policyAction": {"key": "policy_actions"},
    "severity": {"key": "severity"},
    "destinationIP": {"key": "dstip"},
    "sourceRegion": {"key": "src_region"},
    "sourceIP": {"key": "srcip"},
    "userIP": {"key": "userip"},
    "policyID": {"key": "policy_id"}
}

TAG_ACTION_LABEL_MAP = {
    "append": "Add",
    "remove": "Remove"
}
