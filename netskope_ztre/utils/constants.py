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
# Private app host IPv4 CIDR blocks wider than /8 (prefix < 8) are rejected;
# 0.0.0.0/0 is wider than /8 and is therefore rejected by the same check.
PRIVATE_APP_MIN_CIDR_PREFIX = 8
# A single hostname label: 1-63 chars of letters/digits/hyphen/underscore,
# not starting or ending with a hyphen. Used to validate private app
# host/domain labels.
REGEX_HOSTNAME_LABEL = r"^(?!-)[a-zA-Z0-9_-]{1,63}(?<!-)$"
USERS_BATCH_SIZE = 512
APPLICATIONS_BATCH_SIZE = 100
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"
)
REGEX_EMAIL = r"[^@]+@[^@]+\.[^@]+"
REGEX_TAG = r"^[a-zA-Z0-9- ]*$"
# Anchored with ``\Z`` (not ``$``): in Python ``$`` also matches just
# before a trailing newline, so a value like "example.com\n" would
# otherwise be accepted as a valid domain. ``\Z`` matches only the very
# end of the string.
REGEX_FOR_DOMAIN = (
    r"^(?!.{254})(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})\Z"
)
MODULE_NAME = "CRE"
PLUGIN = "Netskope Risk Exchange"
PLUGIN_VERSION = "1.8.0"
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
    "V2_REVERT_UCI_IMPACT": "/api/v2/incidents/anomalies/{}/allow",
    "V2_DESTINATION_PROFILE": "/api/v2/profiles/destinations",
    "V2_DESTINATION_PROFILE_BY_ID": "/api/v2/profiles/destinations/{}",
    "V2_DESTINATION_PROFILE_VALUES": (
        "/api/v2/profiles/destinations/{}/values"
    ),
    "V2_DESTINATION_PROFILE_DEPLOY": "/api/v2/profiles/destinations/deploy",
    "V2_DNS_PROFILE": "/api/v2/profiles/dns",
    "V2_DNS_PROFILE_BY_ID": "/api/v2/profiles/dns/{}",
    "V2_DNS_DOMAIN_CATEGORIES": "/api/v2/profiles/dns/domaincategories",
    "V2_DNS_RECORD_TYPES": "/api/v2/profiles/dns/recordtypes",
    "V2_DEVICE_CLASSIFICATION_TAGS": "/api/v2/deviceclassification/tags",
    "V2_DEVICE_CLASSIFICATION_RULES": "/api/v2/deviceclassification/rules",
    "V2_DEVICE_CLASSIFICATION_RULE_BY_ID": (
        "/api/v2/deviceclassification/rules/{}"
    ),
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
PRIVATE_APP_TAG_MAX_LENGTH = 30
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

# ---------------------------------------------------------------------------
# Add to Destination Profile action constants
# ---------------------------------------------------------------------------
# Capacity limits enforced by Netskope for destination profiles.
DESTINATION_PROFILE_EXACT_TOTAL_LIMIT = 300000
DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT = 100000
DESTINATION_PROFILE_REGEX_TOTAL_LIMIT = 1000
# Destination profile by-id PATCH request body byte budget with a safety
# buffer. The by-id PATCH carries the match type/description and the full
# value list, and a body larger than this is rejected, so a value set
# that does not fit is split across a first by-id PATCH and one or more
# appends on the values endpoint. NOTE: this size budget applies ONLY to
# the by-id PATCH (and the create POST). The values-endpoint append is
# bounded by a value COUNT, not by payload size (see
# DESTINATION_PROFILE_VALUES_PER_APPEND).
# IMPORTANT: the real enforced limit is 9 MB, not the documented 10 MB --
# a 10 MB body is rejected by the API. Do NOT raise this to 10 * 1024 *
# 1024.
DESTINATION_PROFILE_PAYLOAD_LIMIT = 9 * 1024 * 1024
DESTINATION_PROFILE_PAYLOAD_SAFETY_BUFFER = 1024
# The destination profile values endpoint (PATCH with op "append")
# accepts at most this many values per call, so overflow values are
# appended in batches of this size.
DESTINATION_PROFILE_VALUES_PER_APPEND = 10
# Destination profile name/description length limits.
MAX_DESTINATION_PROFILE_NAME_LENGTH = 100
MAX_DESTINATION_PROFILE_DESC_LENGTH = 200
# Characters not allowed in a destination profile name.
DESTINATION_PROFILE_NAME_FORBIDDEN_CHARS = ['"', ";"]
# Allowed match types for a destination profile.
MATCH_TYPE_OPTIONS = {
    "insensitive": "Case Insensitive",
    "sensitive": "Case Sensitive",
    "regex": "Regex",
}
# Substring returned by the API when a profile has undeployed changes.
PENDING_CHANGES_DETECTED = (
    "non-interactive operation on pending profile is not allowed"
)

# ---------------------------------------------------------------------------
# Add to DNS Profile action constants
# ---------------------------------------------------------------------------
# DNS profile name/description length limits.
MAX_DNS_PROFILE_NAME_LENGTH = 255
MAX_DNS_PROFILE_DESC_LENGTH = 255
# Characters not allowed in a DNS profile name or description.
DNS_PROFILE_FORBIDDEN_CHARS = ["(", ")", '"']
# DNS profile payload byte budget (16 MiB) with a safety buffer.
DNS_PROFILE_PAYLOAD_LIMIT = 16 * 1024 * 1024
DNS_PROFILE_PAYLOAD_SAFETY_BUFFER = 1024
# Allowed action types when adding domains to a DNS profile.
DNS_PROFILE_ACTION_TYPE_OPTIONS = {
    "add_to_allow_list": "Add to Domain Allowlist",
    "add_to_block_list": "Add to Domain Blocklist",
}
# Allowed values for the "Block all except Allow list" choice.
BLOCK_ALL_EXCEPT_ALLOW_LIST_OPTIONS = {
    "True": "Yes",
    "False": "No",
}
# Separator used to pack DNS profile name and id into a choice value
# (DNS profile names cannot contain these characters).
CUSTOM_SEPARATOR = "()"
# Page size used when paginating DNS profile listings/categories.
DNS_PROFILE_PAGE_SIZE = 150

# ---------------------------------------------------------------------------
# Add to Service Profile action constants
# ---------------------------------------------------------------------------
# API endpoint paths (URL is built as f"{tenant}{path}").
V2_SERVICE_PROFILE = "/api/v2/profiles/serviceobjects"
V2_SERVICE_PROFILE_BY_ID = "/api/v2/profiles/serviceobjects/{}"
# Allowed operations when adding data to a profile (append keeps the
# existing data and adds to it, replace overwrites it with the new
# data). Shared by the destination, DNS and service profile actions.
OPERATION_OPTIONS = {
    "replace": "Replace",
    "append": "Append",
}
# Alias retained for the service profile action.
SERVICE_PROFILE_OPERATION_OPTIONS = OPERATION_OPTIONS
# Service profile name/description length limits.
MAX_SERVICE_PROFILE_NAME_LENGTH = 255
MAX_SERVICE_PROFILE_DESC_LENGTH = 512
# Only CUSTOM service profiles are editable (PREDEFINED are read-only).
SERVICE_PROFILE_TYPE_CUSTOM = "CUSTOM"
# Page size used when paginating service profile listings.
SERVICE_PROFILE_PAGE_SIZE = 150

# ---------------------------------------------------------------------------
# Create Device Classification action constants
# ---------------------------------------------------------------------------
# Page size used when paginating device classification tag/rule listings.
DEVICE_CLASSIFICATION_PAGE_SIZE = 1000
# Name length limit for a device classification and its rule.
MAX_DEVICE_CLASSIFICATION_NAME_LENGTH = 80
# Separator used to pack "name<sep>id" in the device classification rule
# dropdown. A dedicated separator (not the shared CUSTOM_SEPARATOR "()") is
# used because device classification and rule names are allowed to contain
# "()", so it cannot serve as a delimiter here.
CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION = "@#!<>"
# Default description used when creating a device classification.
DEVICE_CLASSIFICATION_DEFAULT_DESCRIPTION = "Created from Netskope CE."
# Maximum number of device tags allowed in a single condition group of a
# device classification rule. When a rule references more device tags than
# this, the tags are split across multiple groups joined by the selected
# logical operator.
DEVICE_CLASSIFICATION_TAGS_PER_GROUP = 5
# Maximum number of device tags an action may apply to a rule (the rule total).
# Tags beyond this count (by position, after de-duplication) are ignored: they
# are not validated, not resolved, and not sent. For an Append, the new tags
# only fill the rule up to this total; a rule already holding this many tags
# skips the append entirely.
MAX_DEVICE_CLASSIFICATION_TAGS = 5
# Allowed operating systems for a device classification rule (the key is
# the value sent to the API, the value is the display label).
DEVICE_CLASSIFICATION_OS_OPTIONS = {
    "windows": "Windows",
    "winserver": "Windows Server",
    "mac": "macOS",
    "android": "Android",
    "ios": "iOS",
    "chromeos": "ChromeOS",
    "linux": "Linux",
}
# Allowed logical operators for combining device tags in a rule. The key is
# the value stored on the action; it is mapped to the API's "$and"/"$or"
# condition operator at build time (stored without the "$" so it is not
# mistaken for a Source field reference during validation).
DEVICE_CLASSIFICATION_OPERATOR_OPTIONS = {
    "and": "All",
    "or": "Any",
}

# ---------------------------------------------------------------------------
# Action parameter templates
# ---------------------------------------------------------------------------
# Static field definitions for the actions added in this release. They are
# deep-copied in ``get_action_params`` and the fields whose ``choices`` (and
# in some cases ``default``) depend on live API responses are populated
# there by parameter ``key``:
#   - destination_profile -> "destination_profile_name"
#   - dns_profile         -> "dns_profile_name", "dns_security_categories",
#                            "dns_record_types"
#   - service_profile     -> "service_profile_name"
#   - device_classification -> "device_classification",
#                              "device_classification_rule"
DESTINATION_PROFILE_ACTION_PARAMS = [
    {
        "label": "Operation",
        "key": "operation",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in OPERATION_OPTIONS.items()
        ],
        "default": "append",
        "mandatory": True,
        "description": (
            "Select whether to append the values to the existing values or"
            " replace the current values with new values on the profile."
            " Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Destination Profile",
        "key": "destination_profile_name",
        "type": "choice",
        "choices": [],
        "default": "",
        "mandatory": True,
        "description": (
            "Select an existing destination profile from the Static "
            "field dropdown or select 'Create new profile'."
        ),
    },
    {
        "label": "Create New Profile",
        "key": "new_profile_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Name of the destination profile to create. Provide the "
            "name in the Static field only if 'Create new profile' is "
            "selected in Destination Profile. The profile name should "
            f"not exceed {MAX_DESTINATION_PROFILE_NAME_LENGTH} "
            "characters and it cannot contain '\"' (Double Quotes) or"
            " ';' (Semicolon)."
        ),
    },
    {
        "label": "Profile Description",
        "key": "new_profile_description",
        "type": "text",
        "default": "Created from Netskope CE.",
        "mandatory": False,
        "description": (
            "Description for the destination profile. It will add or replace"
            " the current description with provided. The description should"
            " not exceed {MAX_DESTINATION_PROFILE_DESC_LENGTH} characters."
        ),
    },
    {
        "label": "Match Type",
        "key": "profile_match_type",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in MATCH_TYPE_OPTIONS.items()
        ],
        "default": "insensitive",
        "mandatory": False,
        "description": (
            "Match type for the destination profile. Select from the "
            "Static field dropdown only. It will add or replace the current"
            " match type with the provided value."
        ),
    },
    {
        "label": "Apply Pending Changes",
        "key": "apply_pending_changes",
        "type": "choice",
        "choices": [
            {"key": "Yes", "value": "Yes"},
            {"key": "No", "value": "No"},
        ],
        "default": "No",
        "mandatory": True,
        "description": (
            "Select 'Yes' to deploy pending changes and retry when the "
            "destination profile has undeployed changes. Select from "
            "the Static field dropdown only."
        ),
    },
    {
        "label": "Network Targets",
        "key": "destination_values",
        "type": "text",
        "default": "",
        "placeholder": "i.e. 10.0.0.1, example.com",
        "mandatory": True,
        "description": (
            "Select a Source field for the destination values or "
            "provide Static comma-separated values, IPs, or URLs to "
            "add to the profile."
        ),
    },
    {
        "label": "Tenant Exact-Match Value Limit",
        "key": "exact_match_total_limit",
        "type": "number",
        "default": DESTINATION_PROFILE_EXACT_TOTAL_LIMIT,
        "mandatory": False,
        "description": (
            "Maximum number of exact-match (Case Insensitive / Case "
            "Sensitive) values allowed tenant-wide, used as the capacity "
            "ceiling when adding values to a profile. Provide a positive "
            "integer in the Static field only. The default tenant limit is"
            f" {DESTINATION_PROFILE_EXACT_TOTAL_LIMIT}. If you have increased"
            " limit enter that value here. Leave empty to use the "
            f"default of {DESTINATION_PROFILE_EXACT_TOTAL_LIMIT}."
        ),
    },
]

DNS_PROFILE_ACTION_PARAMS = [
    {
        "label": "Operation",
        "key": "operation",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in OPERATION_OPTIONS.items()
        ],
        "default": "append",
        "mandatory": True,
        "description": (
            "Select whether to append the values to the existing values or"
            " replace the current values with new values on the profile."
            " Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Action Type",
        "key": "dns_profile_action_type",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in DNS_PROFILE_ACTION_TYPE_OPTIONS.items()
        ],
        "default": "add_to_allow_list",
        "mandatory": True,
        "description": (
            "Whether to add the domains to the allow list or the block "
            "list of the DNS profile. Select from the Static field "
            "dropdown only."
        ),
    },
    {
        "label": "DNS Profile",
        "key": "dns_profile_name",
        "type": "choice",
        "choices": [],
        "default": "",
        "mandatory": True,
        "description": (
            "Select an existing DNS profile from the Static field "
            "dropdown or select 'Create new DNS Profile'."
        ),
    },
    {
        "label": "Create New DNS Profile",
        "key": "new_profile_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Name of the DNS profile to create. Provide the name in "
            "the Static field only if 'Create new DNS Profile' is "
            "selected in DNS Profile. The profile name should not exceed "
            f"{MAX_DNS_PROFILE_NAME_LENGTH} characters and it cannot contain"
            " '(', ')' or '\"'."
        ),
    },
    {
        "label": "Profile Description",
        "key": "new_profile_description",
        "type": "text",
        "default": "Created from Netskope CE.",
        "mandatory": False,
        "description": (
            "Description for the DNS profile to be created. Used only "
            "when 'Create new DNS Profile' is selected in DNS Profile. "
            f"The description should not exceed {MAX_DNS_PROFILE_DESC_LENGTH}"
            " characters"
        ),
    },
    {
        "label": "Categories",
        "key": "dns_security_categories",
        "type": "multichoice",
        "choices": [],
        "default": [],
        "mandatory": False,
        "description": (
            "Select the security categories to apply on the DNS profile"
            " from the Static field dropdown only. The same category cannot"
            " be selected with both 'Block' and 'Sinkhole' actions."
            " Selecting any 'Sinkhole' variant requires a value in the"
            " 'Sinkhole IP' parameter."
        ),
    },
    {
        "label": "Sinkhole IP",
        "key": "sinkhole_ip",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Sinkhole IP address for the DNS profile. Required only "
            "when a '(Sinkhole)' category is selected in Categories. "
            "Provide in the Static field only."
        ),
    },
    {
        "label": "Record Types",
        "key": "dns_record_types",
        "type": "multichoice",
        "choices": [],
        "default": [],
        "mandatory": True,
        "description": (
            "Select the DNS record types from the Static field dropdown."
            " The 'All Record Types' value cannot be selected together with"
            " any other Record Type value."
        ),
    },
    {
        "label": "Block all except Allow list",
        "key": "block_all_except_allow_list",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in BLOCK_ALL_EXCEPT_ALLOW_LIST_OPTIONS.items()
        ],
        "default": "False",
        "mandatory": True,
        "description": (
            "Select 'Yes' to block all domains except those on the "
            "allow list. Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Domain Names",
        "key": "domain_names",
        "type": "text",
        "default": "",
        "placeholder": "i.e. example.com, test.org",
        "mandatory": True,
        "description": (
            "Select a Source field for the domain names or provide "
            "Static comma-separated domains or FQDNs to add to the DNS "
            "profile."
        ),
    },
]

SERVICE_PROFILE_ACTION_PARAMS = [
    {
        "label": "Operation",
        "key": "operation",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in SERVICE_PROFILE_OPERATION_OPTIONS.items()
        ],
        "default": "append",
        "mandatory": True,
        "description": (
            "Select whether to append the values to the existing values or"
            " replace the current values with new values on the profile."
            " Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Service Profile",
        "key": "service_profile_name",
        "type": "choice",
        "choices": [],
        "default": "",
        "mandatory": True,
        "description": (
            "Select an existing custom service profile from the Static "
            "field dropdown or select 'Create new service profile'. "
            "Only custom (editable) profiles are listed."
        ),
    },
    {
        "label": "Service Profile Name",
        "key": "new_profile_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Name of the service profile to create. Provide the name "
            "in the Static field only if 'Create new service profile' "
            "is selected in Service Profile. The profile name should "
            f"not exceed {MAX_SERVICE_PROFILE_NAME_LENGTH} characters."
        ),
    },
    {
        "label": "Description",
        "key": "new_profile_description",
        "type": "text",
        "default": "Created from Netskope CE.",
        "mandatory": False,
        "description": (
            "Description for the service profile to be created. Used "
            "only when 'Create new service profile' is selected in "
            "Service Profile. The description should not exceed "
            f"{MAX_SERVICE_PROFILE_DESC_LENGTH} characters."
        ),
    },
    {
        "label": "TCP Ports",
        "key": "tcp_ports",
        "type": "text",
        "default": "",
        "placeholder": "i.e. 443, 8080-8090",
        "mandatory": False,
        "description": (
            "Select a Source field for the TCP ports or provide Static "
            "comma-separated ports or port ranges (e.g. 9000-9500)."
        ),
    },
    {
        "label": "UDP Ports",
        "key": "udp_ports",
        "type": "text",
        "default": "",
        "placeholder": "i.e. 53, 8080-8090",
        "mandatory": False,
        "description": (
            "Select a Source field for the UDP ports or provide Static "
            "comma-separated ports or port ranges (e.g. 9000-9500)."
        ),
    },
    {
        "label": "TCP/UDP Ports",
        "key": "tcp_udp_ports",
        "type": "text",
        "default": "",
        "placeholder": "i.e. 443, 8080-8090",
        "mandatory": False,
        "description": (
            "Select a Source field for the TCP_UDP ports or provide "
            "Static comma-separated ports or port ranges "
            "(e.g. 9000-9500)."
        ),
    },
    {
        "label": "ICMP",
        "key": "icmp",
        "type": "choice",
        "choices": [
            {"key": "No", "value": False},
            {"key": "Yes", "value": True},
        ],
        "default": False,
        "mandatory": False,
        "description": (
            "Select 'Yes' to enable the ICMP protocol on the service "
            "profile. Select from the Static field dropdown only."
        ),
    },
]

DEVICE_CLASSIFICATION_ACTION_PARAMS = [
    {
        "label": "Operation",
        "key": "operation",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in OPERATION_OPTIONS.items()
        ],
        "default": "append",
        "mandatory": True,
        "description": (
            "Select whether to append the values to the existing values or"
            " replace the current values with new values on the rule."
            " Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Device Classification",
        "key": "device_classification",
        "type": "choice",
        "choices": [],
        "default": "",
        "mandatory": True,
        "description": (
            "Select an existing device classification from the Static "
            "field dropdown to use as the rule's classification, or "
            "select 'Create new Device Classification'."
        ),
    },
    {
        "label": "Device Classification Name",
        "key": "new_classification_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Name of the device classification to create. Provide the "
            "name in the Static field only if 'Create new Device "
            "Classification' is selected in Device Classification. The "
            "name should not exceed "
            f"{MAX_DEVICE_CLASSIFICATION_NAME_LENGTH} characters."
        ),
    },
    {
        "label": "Device Classification Rule",
        "key": "device_classification_rule",
        "type": "choice",
        "choices": [],
        "default": "",
        "mandatory": True,
        "description": (
            "Select an existing device classification rule to update "
            "from the Static field dropdown, or select 'Create new "
            "Device Classification Rule'."
        ),
    },
    {
        "label": "Device Classification Rule Name",
        "key": "new_rule_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Name of the device classification rule to create. Provide "
            "the name in the Static field only if 'Create new Device "
            "Classification Rule' is selected in Device Classification "
            "Rule. The rule name should not exceed "
            f"{MAX_DEVICE_CLASSIFICATION_NAME_LENGTH} characters."
        ),
    },
    {
        "label": "Operating System",
        "key": "os",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in DEVICE_CLASSIFICATION_OS_OPTIONS.items()
        ],
        "default": "windows",
        "mandatory": True,
        "description": (
            "Target operating system for the device classification "
            "rule. Select from the Static field dropdown only."
        ),
    },
    {
        "label": "Match Type",
        "key": "logical_operator",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in DEVICE_CLASSIFICATION_OPERATOR_OPTIONS.items()
        ],
        "default": "and",
        "mandatory": True,
        "description": (
            "Select the Match Type (Logical Operator) to be applied on the"
            "tags in the Device Classification Rule. Select from the Static"
            " field dropdown only."
        ),
    },
    {
        "label": "Group Match Type",
        "key": "group_operator",
        "type": "choice",
        "choices": [
            {"key": value, "value": key}
            for key, value in DEVICE_CLASSIFICATION_OPERATOR_OPTIONS.items()
        ],
        "default": "and",
        "mandatory": True,
        "description": (
            "Select how the top-level condition groups are combined in"
            " the Device Classification Rule. 'All' requires every"
            " group to match; 'Any' requires at least one group to"
            " match. Takes effect when more than"
            f" {DEVICE_CLASSIFICATION_TAGS_PER_GROUP} tags are provided"
            " (creating multiple tag groups) or when the existing rule"
            " already contains multiple condition groups. Select from"
            " the Static field dropdown only."
        ),
    },
    {
        "label": "Tags",
        "key": "classification_tags",
        "type": "text",
        "default": "",
        "placeholder": "i.e. tag1, tag2",
        "mandatory": True,
        "description": (
            "Select a Source field for the device tags or provide "
            "Static comma-separated device tag names to use in the "
            "rule conditions. If more than "
            f"{DEVICE_CLASSIFICATION_TAGS_PER_GROUP} tags are provided,"
            " they are split into groups of "
            f"{DEVICE_CLASSIFICATION_TAGS_PER_GROUP} and each group"
            " becomes a separate condition block in the rule. For an"
            " Append, new tags are unioned with the existing ones and"
            " the result is re-grouped. Each tag must already exist on"
            " the Netskope Tenant."
        ),
    },
]
