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

CRE Orca Security plugin constants module.
"""

# ---------------------------------------------------------------------------
# Plugin identity
# ---------------------------------------------------------------------------
MODULE_NAME = "CRE"
PLATFORM_NAME = "Orca Security"
PLUGIN_NAME = "Orca Security"
PLUGIN_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Retry / pagination / batching
# ---------------------------------------------------------------------------
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER = 300
PAGE_SIZE = 1000
# Hard ceiling on a single HTTP request so a hung Orca endpoint can never
# stall a whole pull/update cycle indefinitely.
DEFAULT_REQUEST_TIMEOUT = 300
# Emit a progress log line every N assets in the per-asset enrichment loops
# (linked entity counts / open ports / custom tags), which are O(N) API calls
# and can run for a long time on a large tenant.
PROGRESS_LOG_INTERVAL = 100

# ---------------------------------------------------------------------------
# Entity names
# ---------------------------------------------------------------------------
DEVICES = "Workloads"
USERS = "Users"
SUPPORTED_ENTITIES = [DEVICES, USERS]

# Singular labels used in log messages, e.g. "Workload record(s)".
ENTITY_LABEL_SINGULAR = {
    DEVICES: "Workload",
    USERS: "User",
}

# ---------------------------------------------------------------------------
# Configuration parameter keys and their UI labels. Referenced instead of
# inline string literals so a key rename can never silently disable a toggle.
# ---------------------------------------------------------------------------
CONFIG_BASE_URL = "base_url"
CONFIG_CUSTOM_BASE_URL = "custom_base_url"
CONFIG_API_TOKEN = "api_token"
CONFIG_DEVICE_MODELS = "device_models"
CONFIG_USER_MODELS = "user_models"
CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS = "fetch_additional_device_details"
CONFIG_FETCH_CUSTOM_TAGS = "fetch_custom_tags"

CONFIG_FIELD_LABELS = {
    CONFIG_BASE_URL: "Base URL",
    CONFIG_CUSTOM_BASE_URL: "Custom Base URL",
    CONFIG_API_TOKEN: "API Token",
    CONFIG_DEVICE_MODELS: "Workload Types",
    CONFIG_USER_MODELS: "User Types",
    CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS: "Fetch Additional Workload Details",
    CONFIG_FETCH_CUSTOM_TAGS: "Fetch Custom Tags",
}

# ---------------------------------------------------------------------------
# Base URL - a fixed set of known regional tenant URLs, plus a "Custom"
# option backed by a separate free-text field (CONFIG_CUSTOM_BASE_URL). Kept
# as a single list (not one constant per region) to match the DEVICE_MODELS/
# USER_MODELS convention below.
# ---------------------------------------------------------------------------
BASE_URL_CUSTOM_VALUE = "custom"
BASE_URL_CHOICE_VALUES = [
    "https://app.orcasecurity.io",
    "https://app.in.orcasecurity.io",
    "https://app.eu.orcasecurity.io",
    "https://app.au.orcasecurity.io",
    "https://app.sa.orcasecurity.io",
    "https://app.id.orcasecurity.io",
    "https://app.gov.orcasecurity.io",
    BASE_URL_CUSTOM_VALUE,
]

# ---------------------------------------------------------------------------
# 'Fetch Additional Workload Details' multichoice values.
# ---------------------------------------------------------------------------
DEVICE_DETAIL_COUNTS = "device_count_details"
DEVICE_DETAIL_PORTS = "device_ports_details"
DEVICE_DETAIL_VALUES = [DEVICE_DETAIL_COUNTS, DEVICE_DETAIL_PORTS]

# Toggle parameters and their allowed values.
TOGGLE_CONFIG_KEYS = [
    CONFIG_FETCH_CUSTOM_TAGS,
]
TOGGLE_YES = "yes"
TOGGLE_NO = "no"
TOGGLE_VALUES = [TOGGLE_YES, TOGGLE_NO]

# ---------------------------------------------------------------------------
# Entity fields that must be present in the entity mappings for the plugin to
# be able to identify (and act on) a record.
# ---------------------------------------------------------------------------
FIELD_ENTITY_UNIQUE_ID = "Entity Unique ID"
FIELD_ENTITY_ID = "Entity ID"
FIELD_HOSTNAME = "Hostname"
FIELD_EMAIL = "Email"
FIELD_DISPLAY_NAME = "Display Name"
FIELD_TYPE = "Type"
FIELD_EXPOSURE = "Exposure"
FIELD_TAGS = "Tags"
FIELD_MODEL_TAGS = "Model Tags"
FIELD_CUSTOM_TAGS = "Custom Tags"
FIELD_PORTS = "Ports"
FIELD_PORT_SERVICES = "Port Services"
FIELD_PORT_PROTOCOLS = "Port Protocols"
FIELD_NORMALIZED_SCORE = "Netskope Normalized Score"

REQUIRED_ENTITY_FIELDS = {
    DEVICES: [FIELD_ENTITY_UNIQUE_ID, FIELD_ENTITY_ID, FIELD_HOSTNAME],
    USERS: [FIELD_ENTITY_UNIQUE_ID, FIELD_ENTITY_ID, FIELD_EMAIL],
}

# Value of the Workload 'Exposure' field that gates the open-ports enrichment.
EXPOSURE_PUBLIC_FACING = "public_facing"

# ---------------------------------------------------------------------------
# API Endpoints (relative paths; {base_url} is prefixed at call time)
# ---------------------------------------------------------------------------
BASE_URL_ENDPOINT = "/api/serving-layer/query"
LINKED_ENTITIES_COUNT_ENDPOINT = "/api/serving-layer/linked_entities_count"
SCAN_ENDPOINT = "/api/scan/asset/{asset_unique_id}"
MANUAL_TAGS_ENDPOINT = "/api/manual_tags/{asset_id}"

# ---------------------------------------------------------------------------
# Query models
# ---------------------------------------------------------------------------
DEVICE_MODELS = [
    "AwsEc2Instance",
    "AzureComputeVm",
    "AzureContainerInstance",
    "GcpVmInstance",
    "OciComputeVmInstance",
]
USER_MODELS = [
    "AwsUser",
    "AzureUser",
    "AzureServicePrincipal",
    "GcpUser",
    "GcpIamServiceAccount",
    "OciUser",
    "K8sServiceAccount",
]

# ---------------------------------------------------------------------------
# Dynamic configuration fields returned by get_dynamic_fields().
#
# manifest.json declares only 'Base URL' as a static field; the CE UI
# renders get_dynamic_fields() output as a follow-on block placed after
# every static manifest field, so if the remaining fields (API Token,
# Workload Types, etc.) stayed in manifest.json, 'Custom Base URL' would
# always land after all of them instead of right below 'Base URL'.
# Keeping only 'Base URL' static and returning everything else here - as
# two ordered variants, one with 'Custom Base URL' prepended - makes it
# appear directly under 'Base URL' when 'Custom' is selected.
# ---------------------------------------------------------------------------
CUSTOM_BASE_URL_FIELD = {
    "label": "Custom Base URL",
    "key": CONFIG_CUSTOM_BASE_URL,
    "type": "text",
    "mandatory": True,
    "default": "",
    "placeholder": "https://app.example.orcasecurity.io",
    "description": (
        "Base URL of your Orca Security tenant. Shown only when"
        " 'Custom' is selected for 'Base URL'."
    ),
}

DYNAMIC_FIELDS_DEFAULT = [
    {
        "label": "API Token",
        "key": CONFIG_API_TOKEN,
        "type": "password",
        "default": "",
        "mandatory": True,
        "description": (
            "API Token for authenticating with the Orca platform."
            " Navigate to 'Settings > Users & Permissions > API Tokens'"
            " to generate the API Token."
        ),
    },
    {
        "label": "Workload Types",
        "key": CONFIG_DEVICE_MODELS,
        "type": "multichoice",
        "default": DEVICE_MODELS,
        "mandatory": False,
        "choices": [
            {"key": "AWS EC2 Instance", "value": "AwsEc2Instance"},
            {
                "key": "Azure Compute VM Instance",
                "value": "AzureComputeVm",
            },
            {
                "key": "Azure Container Instance",
                "value": "AzureContainerInstance",
            },
            {"key": "GCP Compute VM Instance", "value": "GcpVmInstance"},
            {
                "key": "OCI Compute VM Instance",
                "value": "OciComputeVmInstance",
            },
        ],
        "description": (
            "Select Workload Types to pull the Workloads entity records."
            " Leave empty to pull all Workloads entity records."
        ),
    },
    {
        "label": "User Types",
        "key": CONFIG_USER_MODELS,
        "type": "multichoice",
        "default": USER_MODELS,
        "mandatory": False,
        "choices": [
            {"key": "GCP User", "value": "GcpUser"},
            {"key": "AWS IAM User", "value": "AwsUser"},
            {"key": "OCI User", "value": "OciUser"},
            {"key": "Azure User", "value": "AzureUser"},
            {
                "key": "Azure Service Principal",
                "value": "AzureServicePrincipal",
            },
            {
                "key": "GCP IAM Service Account",
                "value": "GcpIamServiceAccount",
            },
            {"key": "K8s Service Account", "value": "K8sServiceAccount"},
        ],
        "description": (
            "Select User Types to pull the Users entity records. Leave"
            " empty to pull all Users entity records."
        ),
    },
    {
        "label": "Fetch Additional Workload Details",
        "key": CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS,
        "type": "multichoice",
        "default": [],
        "mandatory": False,
        "choices": [
            {
                "key": "Additional Workload Count Details",
                "value": DEVICE_DETAIL_COUNTS,
            },
            {
                "key": "Additional Workload Ports Details",
                "value": DEVICE_DETAIL_PORTS,
            },
        ],
        "description": (
            "Select which additional Workload details to fetch during the"
            " update cycle. When 'Additional Workload Count Details' is"
            " selected, an additional API call to"
            " '/serving-layer/linked_entities_count' is made once per"
            " Workload to fetch 'Alerts Count', 'Login Attempts Count' and"
            " 'Vulnerability Count'. When 'Additional Workload Ports"
            " Details' is selected, an additional API call to"
            " '/serving-layer/query' is made for public-facing workloads"
            " to fetch 'Ports', 'Port Services' and 'Port Protocols'."
        ),
    },
    {
        "label": "Fetch Custom Tags",
        "key": CONFIG_FETCH_CUSTOM_TAGS,
        "type": "choice",
        "mandatory": False,
        "default": TOGGLE_NO,
        "choices": [
            {"key": "Yes", "value": TOGGLE_YES},
            {"key": "No", "value": TOGGLE_NO},
        ],
        "description": (
            "When set to 'Yes', an additional API call to"
            " '/manual_tags/{asset_id}' is made once per asset to fetch"
            " 'Custom Tags' on both Workloads and Users."
        ),
    },
]

# Same fields as DYNAMIC_FIELDS_DEFAULT, with 'Custom Base URL' prepended
# so it renders directly under 'Base URL' when 'Custom' is selected.
DYNAMIC_FIELDS_CUSTOM_BASE_URL = [
    CUSTOM_BASE_URL_FIELD,
] + DYNAMIC_FIELDS_DEFAULT

# Model queried for the "Workload Ports Details" option of the Fetch
# Additional Workload Details multichoice.
LOCAL_PORT_MODEL = "LocalPort"
# A LocalPort record is tied to its workload through a nested `with` clause
# that walks Compute -> base -> id, matched against the workload's Entity ID
# (a uuid). Multiple workload ids are queried together in a single combined
# call (see LOCAL_PORT_BATCH_SIZE). No `select` clause is sent, so every
# returned LocalPort item carries its parent workload as a nested `Compute`
# object (including `Compute.id`), which is what attributes each returned
# port back to the workload it belongs to.
LOCAL_PORT_PARENT_KEYS = ["Compute", "base"]
LOCAL_PORT_DEVICE_ID_KEY = "id"
LOCAL_PORT_DEVICE_ID_TYPE = "uuid"
# Maximum number of workload ids batched into a single LocalPort query's
# `values` filter, to bound request payload size.
LOCAL_PORT_BATCH_SIZE = 1000

# ---------------------------------------------------------------------------
# Cloud provider derivation (Workloads, Users) - Type/type model-name prefix.
# ---------------------------------------------------------------------------
CLOUD_PROVIDER_PREFIX_MAP = {
    "Aws": "AWS",
    "Azure": "Azure",
    "Gcp": "GCP",
    "Oci": "OCI",
    "K8s": "Kubernetes",
}

# ---------------------------------------------------------------------------
# linked_entities_count relation_key -> Workload enrichment field name.
# Matched by EXACT relation_key, never summed by related_model (Alerts
# appears under two relation_keys from two graph directions and summing
# would double-count).
# ---------------------------------------------------------------------------
RELATION_KEY_FIELD_MAP = {
    "Alerts": "Alerts Count",
    "LoginAttempts": "Login Attempts Count",
    "VulnerabilityV2s": "Vulnerability Count",
}

# ---------------------------------------------------------------------------
# Score Mapping
# Netskope Normalized Score = round((10 - OrcaScore) * 100), computed only
# when OrcaScore is present and within [0.0, 10.0]. When OrcaScore is absent,
# not numeric, or outside that range, the field is left empty - there is no
# fallback to Risk Level or any other field.
# ---------------------------------------------------------------------------
MIN_ORCA_SCORE = 0.0
MAX_ORCA_SCORE = 10.0

# ---------------------------------------------------------------------------
# Field mappings
# Each entry is either:
#   {"key": "<dotted.path>", "default": None, "transformation": "<method>"}
# or, for fallback-chain fields:
#   {"keys": ["<path1>", "<path2>", ...], "default": None}
# Keys must match EntityField names used in get_entities().
# ---------------------------------------------------------------------------

DEVICE_FIELD_MAPPING = {
    "Entity ID": {"key": "id", "default": None},
    "Asset Name": {"key": "Name", "default": None},
    "Type": {"key": "Type", "default": None},
    "Cloud Provider": {
        "key": "Type",
        "default": None,
        "transformation": "_cloud_provider_from_type",
    },
    "Category": {"key": "Category", "default": None},
    "Risk Level": {"key": "RiskLevel", "default": None},
    "Risk Score": {"key": "OrcaScore", "default": None},
    "State": {"key": "State", "default": None},
    "Exposure": {"key": "Exposure", "default": None},
    "Is Internet Facing": {"key": "IsInternetFacing", "default": None},
    "Is Crown Jewel": {"key": "IsCrownJewel", "default": None},
    "Crown Jewel Score": {
        "key": "DetectedCrownJewelScore",
        "default": None,
    },
    "Crown Jewel Reason": {
        "key": "DetectedCrownJewelReason",
        "default": None,
    },
    "Public IP": {
        "key": "PublicIps",
        "default": None,
        "transformation": "_first_item",
    },
    "Private IP": {
        "key": "PrivateIps",
        "default": None,
        "transformation": "_first_item",
    },
    "Public DNS": {"key": "PublicDnss", "default": None},
    "Private DNS": {"key": "PrivateDnss", "default": None},
    "MAC Addresses": {"key": "MacAddresses", "default": None},
    "Region": {"key": "Region", "default": None},
    "Availability Zones": {"key": "AvailabilityZones", "default": None},
    "Matched CVEs": {"key": "MatchedCVEs", "default": None},
    "Max CVSS Score": {"key": "MaxCVSSScore", "default": None},
}
# "Entity Unique ID" and "Hostname" are resolved separately (skip-on-missing
# and fallback-chain logic respectively) rather than through this mapping.
DEVICE_HOSTNAME_FALLBACK_KEYS = ["Hostname", "Name", "name"]

USER_FIELD_MAPPING = {
    "Entity ID": {"key": "id", "default": None},
    "Email": {"key": "Email", "default": None},
    "Type": {"key": "Type", "default": None},
    "Cloud Provider": {
        "key": "Type",
        "default": None,
        "transformation": "_cloud_provider_from_type",
    },
    "Category": {"key": "Category", "default": None},
    "Risk Level": {"key": "RiskLevel", "default": None},
    "Risk Score": {"key": "OrcaScore", "default": None},
    "State": {"key": "State", "default": None},
}
USER_DISPLAY_NAME_FALLBACK_KEYS = ["DisplayName", "Name", "name"]

# ---------------------------------------------------------------------------
# Action values
# ---------------------------------------------------------------------------
ACTION_SCAN_DATA_NOW = "scan_data_now"
ACTION_ADD_REMOVE_TAG = "add_remove_tag"
ACTION_NO_ACTION = "generate"
SUPPORTED_ACTIONS = [
    ACTION_SCAN_DATA_NOW,
    ACTION_ADD_REMOVE_TAG,
    ACTION_NO_ACTION,
]

# Human-readable labels for the supported actions, used in log messages so an
# operator sees the same wording as the action dropdown in the UI.
ACTION_LABELS = {
    ACTION_SCAN_DATA_NOW: "Scan Data Now",
    ACTION_ADD_REMOVE_TAG: "Add/Remove Custom Tag",
    ACTION_NO_ACTION: "No Action",
}

# 'Add/Remove Custom Tag' action — Tag Action choice values.
TAG_ACTION_ADD = "add"
TAG_ACTION_REMOVE = "remove"
TAG_ACTIONS = [TAG_ACTION_ADD, TAG_ACTION_REMOVE]

# ---------------------------------------------------------------------------
# Action parameter keys
# ---------------------------------------------------------------------------
PARAM_ASSET_UNIQUE_ID = "asset_unique_id"
PARAM_ASSET_ID = "asset_id"
PARAM_TAG_ACTION = "tag_action"
PARAM_TAG_KEY = "tag_key"
PARAM_TAG_VALUE = "tag_value"

ACTION_PARAM_LABELS = {
    PARAM_ASSET_UNIQUE_ID: "Asset Unique ID",
    PARAM_ASSET_ID: FIELD_ENTITY_ID,
    PARAM_TAG_ACTION: "Tag Action",
    PARAM_TAG_KEY: "Tag Key",
    PARAM_TAG_VALUE: "Tag Value",
}

# ---------------------------------------------------------------------------
# Parameter types (used in validation error messages)
# ---------------------------------------------------------------------------
CONFIGURATION = "configuration"
ACTION = "action"

# ---------------------------------------------------------------------------
# Validation error message templates
# ---------------------------------------------------------------------------
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = (
    "'{field_name}' is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter"
    " '{field_name}'."
)
INVALID_VALUE_ERROR_MESSAGE = (
    "Invalid value(s) {invalid_values} provided for the {parameter_type}"
    " parameter '{field_name}'. Allowed values are {allowed_values}."
)

# ---------------------------------------------------------------------------
# Error message templates (verbatim per TDD status-code table)
# ---------------------------------------------------------------------------
ERROR_MESSAGE_MAP = {
    400: "Received exit code 400, Bad Request. Verify the query payload.",
    401: (
        "Received exit code 401, Unauthorized. Verify the API Token"
        " provided."
    ),
    403: (
        "Received exit code 403, Forbidden. Verify the API Token has read"
        " access to the Orca serving layer."
    ),
    404: (
        "Received exit code 404, Resource not found. Verify the Base URL"
        " provided."
    ),
}
RESOLUTION_MESSAGE_MAP = {
    400: "Verify the query payload sent to the Orca serving layer.",
    401: "Verify the API Token provided in the configuration parameters.",
    403: (
        "Ensure the API Token has read access to the Orca serving layer"
        " (and write access to the scan/manual-tags endpoints if using"
        " 'Scan Data Now' or 'Add/Remove Custom Tag')."
    ),
    404: "Verify the Base URL provided in the configuration parameters.",
}
# Scan Data Now (POST /scan/asset/{asset_unique_id}) 404 more likely means
# the asset no longer exists on the Orca tenant rather than a bad Base URL.
SCAN_NOT_FOUND_RESOLUTION_MESSAGE = (
    "Verify the Asset Unique ID exists on the Orca Security tenant; it may"
    " have been deleted or is no longer discoverable."
)
# Add/Remove Custom Tag (POST|DELETE /manual_tags/{asset_id}) 404 more likely means
# the asset no longer exists on the Orca tenant rather than a bad Base URL.
TAG_NOT_FOUND_RESOLUTION_MESSAGE = (
    "Verify the Entity ID exists on the Orca Security tenant; it may have"
    " been deleted or is no longer discoverable."
)
CLIENT_ERROR_MSG = "Received exit code {status_code}, HTTP Client Error."
SERVER_ERROR_MSG = "Received exit code {status_code}, HTTP Server Error."
GENERIC_ERROR_MSG = "Received exit code {status_code}, HTTP Error."
CLIENT_ERROR_RESOLUTION_MESSAGE = (
    "Verify the configuration and action parameters provided."
)
SERVER_ERROR_RESOLUTION_MESSAGE = (
    f"Please check if the {PLATFORM_NAME} API server is reachable and retry"
    " after some time."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}. Max retries"
    " exceeded."
)
RETRY_ERROR_MSG = (
    "Received exit code {status_code} ({error_reason}) while {logger_msg}."
    " Retrying after {wait_time} second(s). {retry_remaining} retries"
    " remaining."
)
