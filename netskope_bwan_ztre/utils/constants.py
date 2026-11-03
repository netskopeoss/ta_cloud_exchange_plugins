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

from datetime import timedelta

MODULE_NAME = "CRE"
PLATFORM_NAME = "Netskope Borderless WAN"
PLUGIN_VERSION = "2.0.0"

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
# Actions shipped in 1.0.0 that change Address Group membership. Their
# behaviour, parameters and endpoints are unchanged in 2.0.0.
ADDRESS_GROUP_ACTIONS = [ADD_TO_ADDRESS_GROUP, REMOVE_FROM_ADDRESS_GROUP]

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

# ---------------------------------------------------------------------- #
# Entities (2.0.0)
# ---------------------------------------------------------------------- #
CLIENTS_ENTITY = "Clients"
GATEWAYS_ENTITY = "Gateways"
# Custom CRE entity subtypes used by the netskope CRE flow. These MUST match the
# values yielded by the netskope_bwan_tenant provider's pull(), so that
# common.pull fans each batch out to fetch_records with the right sub_type.
CRE_ENTITY_CLIENT_SUBTYPE = "cre_entity_client"
CRE_ENTITY_GATEWAY_SUBTYPE = "cre_entity_gateway"
ENTITY_SUBTYPE = {
    CLIENTS_ENTITY: CRE_ENTITY_CLIENT_SUBTYPE,
    GATEWAYS_ENTITY: CRE_ENTITY_GATEWAY_SUBTYPE,
}
# Per-entity high water marks kept on the tenant (provider) storage. These
# MUST match the keys the netskope_bwan_tenant provider writes. The cleanup
# method clears them on delete so a re-configure performs a full pull.
CRE_ENTITY_CHECKPOINT_KEYS = [
    "cre_entity_client_checkpoint",
    "cre_entity_gateway_checkpoint",
]
# Cache of the users, kept on the tenant (provider) storage so that every
# batch of either entity and every pull cycle share one copy. It maps the
# user ID that a Client or a Gateway configuration carries to the email
# and the name of that user. A user ID the platform does not resolve is
# held with an empty value: user IDs are immutable, hence a record
# assigned to a deleted user never resolves again, and recording the ID
# stops the user list from being read again on every batch that carries
# it.
USER_CACHE_KEY = "cre_bwan_user_map"
# When the cache expires. Stored beside the cache as a datetime, set to
# the moment the listing was read plus USER_CACHE_TTL. The listing is read
# again once the expiry has passed, so an email changed on the platform
# reaches Cloud Exchange within a day instead of never.
USER_CACHE_TTL_KEY = "cre_bwan_user_map_ttl"
USER_CACHE_TTL = timedelta(days=1)
USER_ID_PATH = "device_config_raw.dcfg_general.dcfg_user"
USER_EMAIL_KEY = "email"
SUPPORTED_ENTITIES = [CLIENTS_ENTITY, GATEWAYS_ENTITY]

# Entity endpoints.
CLIENTS_ENDPOINT = "{base_url}/v2/clients"
GATEWAYS_ENDPOINT = "{base_url}/v2/gateways"
CUSTOM_APPS_ENDPOINT = "{base_url}/v2/custom-apps"
CUSTOM_APP_ENDPOINT = "{base_url}/v2/custom-apps/{custom_app_id}"
APP_CATEGORIES_ENDPOINT = "{base_url}/v2/app-categories"
USERS_ENDPOINT = "{base_url}/v2/users"

# Unique identifier field of each entity.
CLIENT_ID_FIELD = "Client ID"
GATEWAY_ID_FIELD = "Gateway ID"
# Fields of both entities that are resolved from the user list endpoint
# rather than read from the Client or Gateway record.
USER_EMAIL_FIELD = "User Email"
# Formats accepted when a DATETIME entity field is parsed into a datetime
# object. Netskope Borderless WAN returns an ISO 8601 UTC timestamp, with
# the fractional second present on some objects and absent on others,
# hence both spellings are tried before the value is dropped.
DATETIME_PARSE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
]
# Declared type of an entity field, used to coerce the extracted value
# before it is handed to Cloud Exchange. Cloud Exchange raises a ValueError
# for a non-bool value in a BOOLEAN field, and that error aborts the whole
# batch and every remaining mapped entity, hence a value that cannot be
# coerced is dropped instead of being passed through.
FIELD_TYPE_BOOLEAN = "boolean"
FIELD_TYPE_NUMBER = "number"
FIELD_TYPE_IPV4 = "ipv4"

# Field mappings. The key is the dot separated path in the API record.
# Values extracted from 'device_config_raw' are allow listed leaves; the
# blob itself is never stored in Cloud Exchange, since it also carries
# plaintext Gateway passwords.
CLIENTS_FIELD_MAPPING = {
    CLIENT_ID_FIELD: {"key": "id", "required": True},
    "Name": {"key": "name"},
    USER_EMAIL_FIELD: {
        "key": USER_ID_PATH,
        "transformation": "user_email",
    },
    "Created At": {"key": "created_at", "transformation": "datetime"},
    "Modified At": {"key": "modified_at", "transformation": "datetime"},
    "Template ID": {"key": "template_id"},
    "Labels": {"key": "labels", "transformation": "labels"},
    "Overlay IPv4 Address": {
        "key": "device_config_raw.dcfg_overlay.ovlay_ipv4",
        "type": FIELD_TYPE_IPV4,
    },
    "Serial Number": {
        "key": "device_config_raw.dcfg_serial", "required": True
    },
    "City": {
        "key": "device_config_raw.dcfg_general.dcfg_location.dloc_city"
    },
    "Country": {
        "key": "device_config_raw.dcfg_general.dcfg_location.dloc_country"
    },
    "IOT Security": {
        "key": "device_config_raw.dcfg_iotsecurity.dcfg_iotsec_enabled",
        "type": FIELD_TYPE_BOOLEAN,
    },
}
GATEWAYS_FIELD_MAPPING = {
    GATEWAY_ID_FIELD: {"key": "id", "required": True},
    "Name": {"key": "name"},
    USER_EMAIL_FIELD: {
        "key": USER_ID_PATH,
        "transformation": "user_email",
    },
    "Created At": {"key": "created_at", "transformation": "datetime"},
    "Modified At": {"key": "modified_at", "transformation": "datetime"},
    "Labels": {"key": "labels", "transformation": "labels"},
    # Read-only. The tag names are pulled across every 'dcfg_tags' group,
    # which needs no knowledge of the 'inftag_name' namespace. A write
    # (tag) action is intentionally NOT offered, because writing a tag
    # requires that undocumented namespace and we cannot determine it for
    # an arbitrary tenant (see get_actions() in main.py for the full
    # rationale).
    "Tags": {
        "key": "device_config_raw.dcfg_tags",
        "transformation": "gateway_tags",
    },
    "Overlay ID": {"key": "overlay_id", "type": FIELD_TYPE_NUMBER},
    "Is Activated": {
        "key": "is_activated", "type": FIELD_TYPE_BOOLEAN
    },
    "Managed": {"key": "managed", "type": FIELD_TYPE_BOOLEAN},
    "Config Updates Enabled": {
        "key": "config_updates_enabled", "type": FIELD_TYPE_BOOLEAN
    },
    "Overlay IPv4 Address": {
        "key": "device_config_raw.dcfg_overlay.ovlay_ipv4",
        "type": FIELD_TYPE_IPV4,
    },
    "Role": {"key": "device_config_raw.dcfg_role"},
    "Hardware Model": {"key": "device_config_raw.dcfg_hardware.hw_model"},
    "Model Display Name": {
        "key": "device_config_raw.dcfg_hardware.hw_model_display_name"
    },
    "Software Version": {
        "key": "device_config_raw.dcfg_general.dcfg_sw_version"
    },
    "Serial Number": {
        "key": "device_config_raw.dcfg_serial", "required": True
    },
    "City": {
        "key": "device_config_raw.dcfg_general.dcfg_location.dloc_city"
    },
    "Country": {
        "key": "device_config_raw.dcfg_general.dcfg_location.dloc_country"
    },
    "IOT Security": {
        "key": "device_config_raw.dcfg_iotsecurity.dcfg_iotsec_enabled",
        "type": FIELD_TYPE_BOOLEAN,
    },
}
ENTITY_FIELD_MAPPINGS = {
    CLIENTS_ENTITY: CLIENTS_FIELD_MAPPING,
    GATEWAYS_ENTITY: GATEWAYS_FIELD_MAPPING,
}

# ---------------------------------------------------------------------- #
# Actions added in 2.0.0
# ---------------------------------------------------------------------- #
ADD_TO_CUSTOM_APP = "add_to_custom_app"
ADD_TO_CUSTOM_APP_LABEL = "Add to Custom App"

# Action parameter keys.
CUSTOM_APP_NAME_PARAM = "custom_app_name"
NEW_CUSTOM_APP_NAME_PARAM = "name"
CATEGORY_PARAM = "category"
HOST_PARAM = "host"
MAX_HOSTS_PARAM = "max_hosts"
SKIP_EXCESS_HOSTS_PARAM = "skip_excess_hosts"
PROTOCOL_PARAM = "protocol"
TCP_PORTS_PARAM = "tcp_ports"
UDP_PORTS_PARAM = "udp_ports"
WEB_ACCESS_PARAM = "web_access"

# Action parameter labels used in the action form and in messages.
CUSTOM_APP_NAME_LABEL = "Custom App Name"
NEW_CUSTOM_APP_NAME_LABEL = "Create New Custom App"
CATEGORY_LABEL = "Category"
HOST_PARAM_LABEL = "Host"
MAX_HOSTS_LABEL = "Maximum Hosts Per Custom App"
SKIP_EXCESS_HOSTS_LABEL = "Skip Excess Hosts"
PROTOCOL_LABEL = "Protocol"
TCP_PORTS_LABEL = "TCP Ports"
UDP_PORTS_LABEL = "UDP Ports"
WEB_ACCESS_LABEL = "Web Access"

# ---------------------------------------------------------------------- #
# Add to Custom App
# ---------------------------------------------------------------------- #
CREATE_NEW_CUSTOM_APP_VALUE = "create"
CREATE_NEW_CUSTOM_APP_LABEL = "Create new custom app"

# The BWAN Tenant UI rejects a Custom App name shorter than 6 characters,
# so the same floor is enforced here to keep behaviour in sync.
MIN_CUSTOM_APP_NAME_LENGTH = 6

# The four members of the CustomAppDefinitionsProtocol enum. The enum is
# fixed in the API contract, hence the list is hard coded and no API call
# is made to populate the dropdown.
PROTOCOL_TCP = "tcp"
PROTOCOL_UDP = "udp"
PROTOCOL_ICMP = "icmp"
PROTOCOL_IPV4 = "ipv4"
PROTOCOL_CHOICES = [
    {"key": "ICMP", "value": PROTOCOL_ICMP},
    {"key": "TCP", "value": PROTOCOL_TCP},
    {"key": "UDP", "value": PROTOCOL_UDP},
    {"key": "IPv4", "value": PROTOCOL_IPV4},
]
PROTOCOL_VALUES = [
    PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_IPV4
]
# Every protocol is selected by default, so a host is matched whatever
# protocol it is reached over unless the operator narrows the selection.
DEFAULT_PROTOCOLS = list(PROTOCOL_VALUES)
# Only TCP and UDP take ports; the port parameter of every other
# protocol is ignored and 'port_range' is omitted from its definition.
PROTOCOL_PORT_PARAMS = {
    PROTOCOL_TCP: TCP_PORTS_PARAM,
    PROTOCOL_UDP: UDP_PORTS_PARAM,
}
PROTOCOL_PORT_LABELS = {
    PROTOCOL_TCP: TCP_PORTS_LABEL,
    PROTOCOL_UDP: UDP_PORTS_LABEL,
}

# Host slots one Custom Application may hold. A slot is one host inside
# one traffic definition, hence a host costs one slot per selected
# protocol. No upper bound is imposed: the capacity of a Custom
# Application depends on the tenant's own configuration, so the ceiling
# is left to Netskope Borderless WAN rather than hard coded here.
DEFAULT_MAX_HOSTS = 1000
MIN_MAX_HOSTS = 1

# Maximum length of a host value. The BWAN Tenant UI caps a host at 100
# characters, well under the RFC 1035 domain name limit of 253.
MAX_HOST_LENGTH = 100
# The BWAN Tenant UI rejects an underscore anywhere in a label, so '_' is
# excluded here even though it is a valid hostname character elsewhere.
REGEX_HOSTNAME_LABEL = r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$"

MIN_PORT = 1
MAX_PORT = 65535

# Absent from 'GET /v2/app-categories' but valid on write, hence added to
# the dropdown from the API specification. See DESIGN_NOTES.md, "The two
# categories missing from 'GET /v2/app-categories'".
SPEC_ONLY_CATEGORIES = [
    {"id": "3", "name": "Audio/Video"},
    {"id": "32", "name": "Custom"},
]
DEFAULT_CATEGORY_NAME = "Standard"

# Netskope Borderless WAN error codes carried in the response body. The
# two HTTP 500 responses have opposite meanings; see DESIGN_NOTES.md,
# "The two meanings of HTTP 500".
ERROR_CODE_UNAVAILABLE = "connect_err_unavailable"
ERROR_CODE_INTERNAL = "connect_err_internal"
# Deleting a Custom Application that a policy references is refused with
# this status; see DESIGN_NOTES.md, "Deleting a Custom Application a
# policy references".
STATUS_PRECONDITION_FAILED = 412

# Outcome key of the Add to Custom App action.
OUTCOME_PLACED = "placed"

# Grouping keys of the records of one batch.
BUCKET_CUSTOM_APP = "custom_app"

# ---------------------------------------------------------------------- #
# Resolutions for the 2.0.0 surfaces
# ---------------------------------------------------------------------- #
RESOLUTION_ENTITY = (
    f"Ensure that the entity is either '{CLIENTS_ENTITY}' or "
    f"'{GATEWAYS_ENTITY}'."
)
RESOLUTION_FETCH_CUSTOM_APPS = (
    "Ensure that the Auth Token has the required permissions for Custom "
    f"Applications and the {PLATFORM_NAME} platform is reachable."
)
RESOLUTION_FETCH_CATEGORIES = (
    "Ensure that the Auth Token has the required permissions for Custom "
    "Applications."
)
RESOLUTION_FETCH_USERS = (
    "Ensure that the Auth Token has the required permissions to read the "
    f"users of {PLATFORM_NAME}. Until it does, the records are stored "
    f"without the '{USER_EMAIL_FIELD}' field."
)
# Resolutions for a permission failure on an entity's list endpoint,
# used when the connectivity check probes it. Without these, any 403
# raised during validation reports the Address Groups resolution.
RESOLUTION_ACCESS_CLIENTS = (
    "Ensure that the Auth Token has read permission for Clients on "
    f"{PLATFORM_NAME}. Refer to the plugin guide for the required "
    "permissions."
)
RESOLUTION_ACCESS_GATEWAYS = (
    "Ensure that the Auth Token has read permission for Gateways on "
    f"{PLATFORM_NAME}. Refer to the plugin guide for the required "
    "permissions."
)
ENTITY_ACCESS_RESOLUTIONS = {
    CLIENTS_ENTITY: RESOLUTION_ACCESS_CLIENTS,
    GATEWAYS_ENTITY: RESOLUTION_ACCESS_GATEWAYS,
}
RESOLUTION_CUSTOM_APP_NOT_FOUND = (
    f"Ensure that the Custom Application exists on {PLATFORM_NAME}, or "
    "select another Custom Application in the action."
)
RESOLUTION_NO_HOST = (
    f"Ensure that at least one valid host is provided in "
    f"'{HOST_PARAM_LABEL}'."
)
RESOLUTION_INVALID_HOST = (
    f"Ensure that '{HOST_PARAM_LABEL}' contains IPv4 addresses, IPv4 CIDR "
    "ranges, fully-qualified hostnames or domain names."
)
RESOLUTION_INVALID_PORTS = (
    "Ensure that the ports are comma separated numbers or ranges between "
    f"{MIN_PORT} and {MAX_PORT}, for example '443, 8080-8090'."
)
RESOLUTION_MAX_HOSTS = (
    f"Ensure that '{MAX_HOSTS_LABEL}' is an integer of at least "
    f"{MIN_MAX_HOSTS}."
)
RESOLUTION_RECORD_TOO_LARGE = (
    f"Ensure that '{MAX_HOSTS_LABEL}' is at least as large as the number "
    "of host slots one record needs, or reduce the number of protocols "
    "selected."
)
RESOLUTION_NEW_CUSTOM_APP = (
    f"Ensure that '{NEW_CUSTOM_APP_NAME_LABEL}' is provided when "
    f"'{CREATE_NEW_CUSTOM_APP_LABEL}' is selected in "
    f"'{CUSTOM_APP_NAME_LABEL}'."
)
RESOLUTION_CUSTOM_APP_NAME_LENGTH = (
    f"Ensure that '{NEW_CUSTOM_APP_NAME_LABEL}' is at least "
    f"{MIN_CUSTOM_APP_NAME_LENGTH} characters long."
)
RESOLUTION_NO_CUSTOM_APPS = (
    f"Ensure that at least one Custom Application exists on "
    f"{PLATFORM_NAME}, or select "
    f"'{CREATE_NEW_CUSTOM_APP_LABEL}' in the action."
)
RESOLUTION_NO_PROTOCOL = (
    f"Ensure that at least one protocol is selected in "
    f"'{PROTOCOL_LABEL}'."
)
RESOLUTION_WEB_ACCESS = (
    f"Ensure that either 'Yes' or 'No' is selected in '{WEB_ACCESS_LABEL}'."
)
RESOLUTION_SKIP_EXCESS_HOSTS = (
    "Ensure that either 'Yes' or 'No' is selected in "
    f"'{SKIP_EXCESS_HOSTS_LABEL}'."
)
RESOLUTION_UPDATE_CUSTOM_APP = (
    "Ensure that the Auth Token has the required permissions for Custom "
    f"Applications on {PLATFORM_NAME}."
)
RESOLUTION_CUSTOM_APP_IN_POLICY = (
    "Remove the Custom Application from the policies that reference it "
    f"on {PLATFORM_NAME} before it can be deleted."
)


# Every action the plugin exposes. Declared here because the 2.0.0
# action values are defined above.
SUPPORTED_ACTIONS = [
    ADD_TO_ADDRESS_GROUP,
    REMOVE_FROM_ADDRESS_GROUP,
    ADD_TO_CUSTOM_APP,
    NO_ACTION,
]
# Action labels used in messages and in the action form.
ACTION_LABELS = {
    ADD_TO_ADDRESS_GROUP: ADD_TO_ADDRESS_GROUP_LABEL,
    REMOVE_FROM_ADDRESS_GROUP: REMOVE_FROM_ADDRESS_GROUP_LABEL,
    ADD_TO_CUSTOM_APP: ADD_TO_CUSTOM_APP_LABEL,
    NO_ACTION: NO_ACTION_LABEL,
}
# List endpoint of each entity. The configuration check reads one record
# from the endpoint of every entity the configuration pulls, so that a
# token lacking access to one of them is rejected while it is saved.
ENTITY_LIST_ENDPOINTS = {
    CLIENTS_ENTITY: CLIENTS_ENDPOINT,
    GATEWAYS_ENTITY: GATEWAYS_ENDPOINT,
}

RESOLUTION_UNSUPPORTED_ACTION = (
    "Ensure that a supported action is selected. The supported actions "
    f"are '{ADD_TO_CUSTOM_APP_LABEL}', "
    f"'{ADD_TO_ADDRESS_GROUP_LABEL}', "
    f"'{REMOVE_FROM_ADDRESS_GROUP_LABEL}' and '{NO_ACTION_LABEL}'."
)
