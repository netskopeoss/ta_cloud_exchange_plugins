"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CRE Kolide plugin constants module.
"""

# ---------------------------------------------------------------------------
# Plugin identity
# ---------------------------------------------------------------------------
PLATFORM_NAME = "Kolide"
MODULE_NAME = "CRE"
PLUGIN_NAME = "Kolide"
PLUGIN_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# API base & versioning
# ---------------------------------------------------------------------------
BASE_URL = "https://api.kolide.com"
# BASE_URL = "http://10.50.8.224:8765"
KOLIDE_API_VERSION = "2026-04-07"
KOLIDE_API_VERSION_HEADER = "x-kolide-api-version"

# ---------------------------------------------------------------------------
# Retry / pagination
# ---------------------------------------------------------------------------
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER = 300
PAGE_SIZE = 100

# ---------------------------------------------------------------------------
# Entity names
# ---------------------------------------------------------------------------
USERS_ENTITY = "Users"
DEVICES_ENTITY = "Devices"

# ---------------------------------------------------------------------------
# API Endpoints (format strings; substitute {base_url} before use)
# ---------------------------------------------------------------------------
WHOAMI_ENDPOINT = "{base_url}/whoami"
PEOPLE_ENDPOINT = "{base_url}/people"
DEVICES_ENDPOINT = "{base_url}/devices"
DEPROVISIONED_PEOPLE_ENDPOINT = "{base_url}/deprovisioned_people"
ISSUES_ENDPOINT = "{base_url}/issues"
DEVICE_GROUPS_ENDPOINT = "{base_url}/device_groups"
DEVICE_GROUP_MEMBERSHIPS_ENDPOINT = (
    "{base_url}/device_groups/{group_id}/memberships"
)
DEVICE_GROUP_MEMBERSHIP_ENDPOINT = (
    "{base_url}/device_groups/{group_id}/memberships/{device_id}"
)
# ---------------------------------------------------------------------------
# Field mappings
# Each entry: {"key": "<api_field_or_dot_notation>", "default": None}
# Keys must match EntityField names used in get_entities().
# ---------------------------------------------------------------------------

USER_FIELD_MAPPING = {
    "User ID": {"key": "id", "default": None},
    "Name": {"key": "name", "default": None},
    "Email": {"key": "email", "default": None},
    "Created At": {
        "key": "created_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    "Last Authenticated At": {
        "key": "last_authenticated_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    "Has Registered Device": {
        "key": "has_registered_device",
        "default": None,
    },
    "Usernames": {"key": "usernames", "default": None},
}

DEVICE_FIELD_MAPPING = {
    "Device ID": {"key": "id", "default": None},
    "Name": {"key": "name", "default": None},
    "Device Serial Number": {"key": "serial", "default": None},
    "Hardware UUID": {"key": "hardware_uuid", "default": None},
    "Hardware Model": {"key": "hardware_model", "default": None},
    "Operating System": {"key": "operating_system", "default": None},
    "Device Type": {"key": "device_type", "default": None},
    "Form Factor": {"key": "form_factor", "default": None},
    "Registered At": {
        "key": "registered_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    "Last Authenticated At": {
        "key": "last_authenticated_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    "Last Seen At": {
        "key": "last_seen_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    "Auth State": {"key": "auth_state", "default": None},
    "Will Block At": {
        "key": "will_block_at",
        "default": None,
        "transformation": "_parse_datetime",
    },
    # Dot-notation keys are resolved by walking nested dicts at runtime.
    "User ID": {
        "key": "registered_owner_info.identifier",
        "default": None,
    },
    "Authentication Mode": {
        "key": "auth_configuration.authentication_mode",
        "default": None,
    },
}

# ---------------------------------------------------------------------------
# Group membership batching
# ---------------------------------------------------------------------------
DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE = 100

# ---------------------------------------------------------------------------
# Action values
# ---------------------------------------------------------------------------
ACTION_MANAGE_GROUP = "manage_group"
ACTION_NO_ACTION = "generate"

SUPPORTED_ACTIONS = [
    ACTION_MANAGE_GROUP,
    ACTION_NO_ACTION,
]

# Choices for the Action Type parameter within ACTION_MANAGE_GROUP
GROUP_ACTION_TYPE_ADD = "add"
GROUP_ACTION_TYPE_REMOVE = "remove"

# Separator used to pack "<group name><CUSTOM_SEPARATOR><group id>" into a
# single Device Group Name dropdown value, so the group id is available at
# execution time via rpartition without an extra group-lookup API call.
# Kolide has no group-create API, so groups are never created on the fly and
# the id can always be carried in the dropdown value. Chosen to be extremely
# unlikely to occur in a real device group name.
CUSTOM_SEPARATOR = ")#%(^"

# ---------------------------------------------------------------------------
# SSF (Shared Signals Framework) stream
# ---------------------------------------------------------------------------
SSF_STREAMS_ENDPOINT = "{base_url}/ssf_streams"
SSF_STREAM_EVENTS_ENDPOINT = (
    "{base_url}/ssf_streams/{stream_id}/events"
)
SSF_STREAM_BY_ID_ENDPOINT = "{base_url}/ssf_streams/{stream_id}"
SSF_STREAM_NAME = "Netskope CE Kolide Plugin"
SSF_CAEP_COMPLIANCE_EVENT = (
    "https://schemas.openid.net/secevent/caep/event-type/"
    "device-compliance-change"
)
# Keys used in plugin storage to persist the SSF stream credentials.
SSF_STORAGE_STREAM_ID = "ssf_stream_id"
SSF_STORAGE_POLL_TOKEN = "ssf_poll_bearer_token"
KOLIDE_SSF_POLL_TOKEN_HEADER = "X-Kolide-Poll-Bearer-Token"

# ---------------------------------------------------------------------------
# Datetime
# ---------------------------------------------------------------------------
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# ---------------------------------------------------------------------------
# Parameter types (used in validation error messages)
# ---------------------------------------------------------------------------
CONFIGURATION = "configuration"
ACTION = "action"

# ---------------------------------------------------------------------------
# Validation error message templates
# ---------------------------------------------------------------------------
EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are '{allowed_values}'"

# ---------------------------------------------------------------------------
# Error message templates
# ---------------------------------------------------------------------------
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}. "
    "Max retries exceeded."
)
RETRY_ERROR_MSG = (
    "Received exit code {status_code} ({error_reason}) while "
    "{logger_msg}. Retrying after {wait_time} second(s). "
    "{retry_remaining} retries remaining."
)
