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

CRE Microsoft Intune Plugin constants module
"""

DEFAULT_SLEEP_TIME = 60
MAX_RETRIES = 4
PAGE_SIZE = 500
ACTION_BATCH_SIZE = 20
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "Microsoft Intune"
# The maximum CE version that does not support partial action failure
MAXIMUM_CE_VERSION = "5.1.2"

CONFIGURATION = "configuration"
ACTION = "action"

OAUTH_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
OAUTH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"
BATCHED_API_ENDPOINT = f"{GRAPH_API_BASE_URL}/$batch"
PULL_DEVICES_API_ENDPOINT = (
    f"{GRAPH_API_BASE_URL}/deviceManagement/managedDevices"
)
GET_DEVICE_HEALTH_SCORE_API_ENDPOINT = (
    f"{GRAPH_API_BASE_URL}/deviceManagement/userExperienceAnalytics"
    "DeviceScores"
)
REBOOT_DEVICE_API_ENDPOINT = (
    "/deviceManagement/managedDevices/{device_id}/rebootNow"
)
SYNC_DEVICE_API_ENDPOINT = (
    "/deviceManagement/managedDevices/{device_id}/syncDevice"
)
RUN_WINDOWS_DEFENDER_SCAN_API_ENDPOINT = (
    "/deviceManagement/managedDevices/{device_id}/windowsDefenderScan"
)
UPDATE_WINDOWS_DEFENDER_SIGNATURES_API_ENDPOINT = (
    "/deviceManagement/managedDevices/{device_id}"
    "/windowsDefenderUpdateSignatures"
)

ACTION_API_ENDPOINT_MAPPING = {
    "reboot": REBOOT_DEVICE_API_ENDPOINT,
    "sync": SYNC_DEVICE_API_ENDPOINT,
    "run": RUN_WINDOWS_DEFENDER_SCAN_API_ENDPOINT,
    "update": UPDATE_WINDOWS_DEFENDER_SIGNATURES_API_ENDPOINT,
}

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

DEVICE_ENTITY_MAPPING = {
    "Device ID": {"key": "id"},
    "Azure AD Device ID": {"key": "azureADDeviceId"},
    "Serial Number": {"key": "serialNumber"},
    "Ethernet MAC Address": {
        "key": "ethernetMacAddress",
        "transformation": "_format_mac_address",
    },
    "Wifi MAC Address": {
        "key": "wiFiMacAddress",
        "transformation": "_format_mac_address",
    },
    "IMEI": {"key": "imei"},
    "Compliance State": {"key": "complianceState"},
    "User Email": {"key": "emailAddress"},
    "User Principal Name": {"key": "userPrincipalName"},
    "User Display name": {"key": "userDisplayName"},
    "User ID": {"key": "userId"},
    "MEID": {"key": "meid"},
    "UDID": {"key": "udid"},
    "EAS Device ID": {"key": "easDeviceId"},
    "Managed Device Name": {"key": "managedDeviceName"},
    "Device Name": {"key": "deviceName"},
    "Model": {"key": "model"},
    "Manufacturer": {"key": "manufacturer"},
    "OS": {"key": "operatingSystem"},
    "OS Version": {"key": "osVersion"},
    "Jail Broken": {"key": "jailBroken"},
    "Management State": {"key": "managementState"},
    "Device Registration State": {"key": "deviceRegistrationState"},
    "Device Enrollment State": {"key": "deviceEnrollmentType"},
}

DEVICE_HEALTH_SCORE_MAPPING = {
    "Device ID": {"key": "id"},
    "Endpoint Analytics Score": {
        "key": "endpointAnalyticsScore",
        "transformation": "_truncate_decimal",
    },
    "Startup Performance Score": {
        "key": "startupPerformanceScore",
        "transformation": "_truncate_decimal",
    },
    "App Reliability Score": {
        "key": "appReliabilityScore",
        "transformation": "_truncate_decimal",
    },
    "Work From Anywhere Score": {
        "key": "workFromAnywhereScore",
        "transformation": "_truncate_decimal",
    },
    "Battery Health Score": {
        "key": "batteryHealthScore",
        "transformation": "_truncate_decimal",
    },
    "Health Status": {"key": "healthStatus"},
}

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
CUSTOM_SEPARATOR = "+^"
