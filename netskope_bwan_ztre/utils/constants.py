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

CRE Netskope Borderless WAN plugin constants.
"""

MODULE_NAME = "CRE"
PLATFORM_NAME = "Netskope Borderless WAN"
PLUGIN_VERSION = "1.0.0"

# Retry handling: 1 initial attempt + 3 retries.
MAX_API_CALLS = 4
# Wait time in seconds for HTTP 5xx and fallback for HTTP 429 when the
# Retry-After header is missing or not numeric.
DEFAULT_WAIT_TIME = 60
# If Retry-After is greater than this value (in seconds), the plugin
# raises immediately without waiting.
MAX_RETRY_AFTER_IN_SECS = 300

# Cursor-based pagination page sizes.
PAGE_SIZE = 100
VALIDATION_PAGE_SIZE = 1
# Safety cap on the number of pages fetched for one list operation.
MAX_PAGES = 10000

# API endpoints. Base URL comes from the Netskope Borderless WAN
# Tenant.
ADDRESS_GROUPS_ENDPOINT = "{base_url}/v2/address-groups"
ADDRESS_OBJECTS_ENDPOINT = (
    "{base_url}/v2/address-groups/{address_group_id}/address-objects"
)
ADDRESS_OBJECT_ENDPOINT = (
    "{base_url}/v2/address-groups/{address_group_id}/address-objects/"
    "{address_object_id}"
)

ADDRESS_OBJECT_TYPE = "ipv4"

# Action values / labels
ADD_TO_ADDRESS_GROUP = "add_to_address_group"
REMOVE_FROM_ADDRESS_GROUP = "remove_from_address_group"
ADD_TO_ADDRESS_GROUP_LABEL = "Add to Address Group"
REMOVE_FROM_ADDRESS_GROUP_LABEL = "Remove from Address Group"
NO_ACTION = "generate"
NO_ACTION_LABEL = "No Action"
SUPPORTED_ACTIONS = [
    ADD_TO_ADDRESS_GROUP,
    REMOVE_FROM_ADDRESS_GROUP,
    NO_ACTION,
]
# Actions that change Address Group membership and hence can be reverted.
REVERTIBLE_ACTIONS = [ADD_TO_ADDRESS_GROUP, REMOVE_FROM_ADDRESS_GROUP]

# Action parameter keys
ADDRESS_GROUP_PARAM = "address_group"
IP_ADDRESS_PARAM = "ip_address"
NEW_ADDRESS_GROUP_NAME_PARAM = "new_address_group_name"
DESCRIPTION_PARAM = "description"
# Optional configuration parameter. When provided, it is the only token
# used (the Auth Token of the Netskope Borderless WAN Tenant is not used);
# else the Auth Token of the Tenant is used.
API_TOKEN_PARAM = "api_token"

CREATE_NEW_ADDRESS_GROUP_VALUE = "create_new_address_group"
CREATE_NEW_ADDRESS_GROUP_LABEL = "Create New Address Group"

# Action parameter labels used in the action form and in messages.
IP_PARAM_LABEL = "IPs"
NEW_ADDRESS_GROUP_NAME_LABEL = "New Address Group Name"

# Grouping keys of the records of one batch: a new Address Group (by
# name) or an existing Address Group (by ID).
BUCKET_CREATE = "create"
BUCKET_EXISTING = "id"

# Reasons for looking up an Address Group by name after a create request.
RECOVERY_CREATED = "created"
RECOVERY_CREATED_AFTER_RETRY = "created_after_retry"
RECOVERY_ALREADY_EXISTS = "already_exists"

# Validation messages. The Base URL (and the Auth Token, unless the
# optional 'API Token' configuration parameter is provided) come from the
# Netskope Borderless WAN Tenant selected in Basic Information.
VALIDATION_SUCCESS_MSG = "Validation successful."
TENANT_CONTEXT = f"the {PLATFORM_NAME} Tenant configuration"
CONFIG_CONTEXT = "configuration parameters"
ACTION_CONTEXT = "action parameters"

# Outcome keys used while executing actions.
OUTCOME_ADDED = "added"
OUTCOME_ALREADY_EXISTS = "already_exists"
OUTCOME_REMOVED = "removed"
OUTCOME_NOT_FOUND = "not_found"
OUTCOME_FAILED = "failed"
OUTCOME_LIMIT_EXCEEDED = "limit_exceeded"
# The IP already exists as an Address Object on the tenant (outside the
# target Address Group), hence it cannot be created again.
OUTCOME_EXISTS_ON_TENANT = "exists_on_tenant"
# Summary details key: IPs that were added or removed for records that
# are nevertheless marked as failed (another IP of the record failed).
# Logged only so that an admin can clean them up manually, since CE does
# not offer revert for failed action logs.
APPLIED_IPS_OF_FAILED_RECORDS = "applied_ips_of_failed_records"

# Maximum number of Address Objects (IPs) one Address Group can hold.
MAX_ADDRESS_OBJECTS_PER_GROUP = 1000

# Resolutions. A resolution is provided only for errors that the user
# can fix (credentials, permissions, configuration, input values). API
# side failures (HTTP 429, HTTP 5xx, timeouts, pagination anomalies and
# unexpected errors) are logged without a resolution.
RESOLUTION_401 = (
    f"Ensure that the Auth Token configured in the {PLATFORM_NAME} "
    "Tenant is valid and has not expired."
)
RESOLUTION_403_VALIDATION = (
    "Ensure that the Auth Token has the required permissions for Address "
    "Groups. Refer to the plugin guide for the required permissions."
)
RESOLUTION_403 = (
    "Ensure that the Auth Token has the required permissions for Address "
    "Groups and Address Objects. Refer to the plugin guide for the "
    "required permissions."
)
RESOLUTION_CONFIG_TOKEN_401 = (
    "Ensure that the 'API Token' provided in the configuration parameters "
    "is valid and has not expired."
)
RESOLUTION_CONFIG_TOKEN_PERMISSION = (
    "Ensure that the 'API Token' provided in the configuration parameters "
    "has all the required permissions for Address Groups and Address "
    "Objects. Refer to the plugin guide for the required permissions."
)
RESOLUTION_404 = (
    "Ensure that the selected Address Group exists on "
    f"{PLATFORM_NAME}."
)
RESOLUTION_GENERIC = (
    "Ensure that the Base URL and Auth Token are correct and the request "
    "parameters are valid."
)
# Single resolution for every Base URL related error.
RESOLUTION_BASE_URL = (
    f"Ensure that the Base URL is correct and the {PLATFORM_NAME} server "
    "is reachable from CE."
)
RESOLUTION_PROXY = "Ensure that the proxy configuration in CE is correct."
RESOLUTION_HTTP = (
    f"Ensure that the Base URL and Auth Token configured in the "
    f"{PLATFORM_NAME} Tenant are correct."
)
RESOLUTION_FETCH_ADDRESS_GROUPS = (
    "Ensure that the Auth Token has the required permissions for Address "
    f"Groups and the {PLATFORM_NAME} platform is reachable."
)
RESOLUTION_CREATE_ADDRESS_GROUP = (
    "Ensure that the Auth Token has the required permissions for Address "
    "Groups and the Address Group name is valid."
)
RESOLUTION_ADD_IP = (
    "Ensure that the IP is a valid IPv4 address or IPv4 CIDR range and "
    "the Auth Token has the required permissions for Address Objects."
)
RESOLUTION_FETCH_ADDRESS_OBJECTS = (
    f"Ensure that the selected Address Group exists on {PLATFORM_NAME} "
    "and the Auth Token has the required permissions for Address "
    "Objects."
)
RESOLUTION_REMOVE_IP = (
    "Ensure that the Address Object still exists in the Address Group "
    "and the Auth Token has the required permissions for Address "
    "Objects."
)
RESOLUTION_INVALID_IP = (
    "Ensure that the 'IPs' field is mapped to a Source field containing "
    "IPv4 addresses or IPv4 CIDR ranges, or contains static "
    "comma-separated IPv4 addresses or IPv4 CIDR ranges."
)
RESOLUTION_NO_IP = (
    "Ensure that at least one IPv4 address or IPv4 CIDR range is provided "
    "in 'IPs'."
)
RESOLUTION_UNSUPPORTED_ACTION = (
    f"Ensure that a supported action ('{ADD_TO_ADDRESS_GROUP_LABEL}', "
    f"'{REMOVE_FROM_ADDRESS_GROUP_LABEL}' or '{NO_ACTION_LABEL}') is "
    "selected."
)
RESOLUTION_NEW_ADDRESS_GROUP = (
    "Ensure that the 'New Address Group Name' is provided when "
    f"'{CREATE_NEW_ADDRESS_GROUP_LABEL}' is selected."
)
RESOLUTION_ADDRESS_GROUP_NOT_FOUND = (
    f"Ensure that the selected Address Group exists on {PLATFORM_NAME}, "
    "or reconfigure the action with an existing Address Group."
)
RESOLUTION_REVERT_ADDRESS_GROUP_NOT_FOUND = (
    "Ensure that the Address Group created for this action still exists "
    f"on {PLATFORM_NAME}, or manually remove the IP(s) from the "
    "appropriate Address Group."
)
RESOLUTION_ADDRESS_GROUP_LIMIT = (
    "Ensure that the Address Group has fewer than "
    f"{MAX_ADDRESS_OBJECTS_PER_GROUP} IP(s), or use a different Address "
    "Group (or 'Create New Address Group') for the remaining IP(s)."
)
RESOLUTION_EXISTS_ON_TENANT = (
    "Ensure that the existing Address Object for the IP(s) is added to "
    f"the Address Group from the {PLATFORM_NAME} console, or remove the "
    "existing Address Object and retry."
)
RESOLUTION_TENANT = (
    f"Ensure that a {PLATFORM_NAME} Tenant is configured from "
    "Settings > Netskope Tenants and selected in the plugin "
    "configuration."
)
RESOLUTION_NO_ADDRESS_GROUPS = (
    f"Ensure that at least one Address Group exists on {PLATFORM_NAME} "
    "before configuring this action."
)
