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

CRE Omnissa Workspace One UEM Plugin constants module.
"""

DEFAULT_SLEEP_TIME = 60
MAX_RETRIES = 4
PAGE_SIZE = 500
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "Omnissa Workspace One UEM"
# The maximum CE version that does not support partial action failure
MAXIMUM_CE_VERSION = "5.1.2"

CONFIGURATION = "configuration"
ACTION = "action"

YES = "yes"
NO = "no"
CONFIGURATION_BOOLEAN_VALUES = [YES, NO]

OAUTH_URLS = [
    "https://uat.uemauth.workspaceone.com",
    "https://na.uemauth.workspaceone.com",
    "https://emea.uemauth.workspaceone.com",
    "https://apac.uemauth.workspaceone.com"
]
VALIDATE_CONNECTIVITY_ENDPOINT = "{base_url}/api/system/info"
GENERATE_ACCESS_TOKEN_ENDPOINT = "{base_url}/connect/token"
PULL_DEVICES_ENDPOINT = "{base_url}/api/mdm/devices/search"
PULL_DEVICE_TAGS_ENDPOINT = "{base_url}/api/mdm/devices/{device_uuid}/tags"
PULL_DEVICE_NETWORK_ENDPOINT = "{base_url}/api/mdm/devices/{device_id}/network"
FETCH_TAGS_ENDPOINT = "{base_url}/api/system/groups/{organization_id}/tags"
CREATE_TAG_ENDPOINT = "{base_url}/api/mdm/tags/addtag"
TAG_DEVICE_ENDPOINT = "{base_url}/api/mdm/tags/{tag_id}/adddevices"
UNTAG_DEVICE_ENDPOINT = "{base_url}/api/mdm/tags/{tag_id}/removedevices"
GET = "GET"
POST = "POST"
ACTION_BATCH_SIZE = 500
TAG_CHARACTER_LENGTH_LIMIT = 50
ONE = 1
TWO = 2

RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason}"
    " while {logger_msg}. Retrying after {wait_time} "
    "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit "
    "exceeded while {logger_msg}. Max retries for rate"
    " limit handler exceeded hence returning status"
    " code {status_code}."
)
EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are '{allowed_values}'"
TAG_ALREADY_ATTACHED_MESSAGE = "tag is already associated with the device"
TAG_NOT_ATTACHED_MESSAGE = "tag is not associated with the device"

DEVICE_ENTITY_MAPPING = {
    "Device UUID": {"key": "Uuid"},
    "Device ID": {"key": "Id.Value"},
    "Organization ID": {"key": "LocationGroupId.Id.Value"},
    "Mac Address": {"key": "MacAddress"},
    "IP Address": {"key": "IpAddresses"},
    "Device Serial Number": {"key": "SerialNumber"},
    "IMEI": {"key": "Imei"},
    "Asset Number": {"key": "AssetNumber"},
    "Hostname": {"key": "HostName"},
    "Local Hostname": {"key": "LocalHostName"},
    "User Name": {"key": "UserName"},
    "User Email Address": {"key": "UserEmailAddress"},
    "Compliance Status": {"key": "ComplianceStatus"},
    "Compromised Status": {"key": "CompromisedStatus"},
    "Enrollment Status": {"key": "EnrollmentStatus"},
    "UDID": {"key": "Udid"},
    "Eas ID": {"key": "EasId"},
    "Device Friendly Name": {"key": "DeviceFriendlyName"},
    "Device Reported Name": {"key": "DeviceReportedName"},
    "Organization Name": {"key": "LocationGroupName"},
    "Platform": {"key": "Platform"},
    "Model": {"key": "Model"},
    "Operating System": {"key": "OperatingSystem"},
    "Last Seen": {"key": "LastSeen"},
    "OS Build Version": {"key": "OSBuildVersion"},
}
CUSTOM_SEPARATOR = "@)*!"
