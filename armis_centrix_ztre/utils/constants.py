"""CRE Armis Centrix plugin constants.

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
"""

# ----------------------------------------------------------------------
# Plugin identity
# ----------------------------------------------------------------------
PLATFORM_NAME = "Armis Centrix"
PLUGIN_NAME = "Armis Centrix"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
LOG_PREFIX_FORMAT = "{module} {plugin}"
LOG_PREFIX_NAME_FORMAT = "{prefix} [{name}]"
METADATA_NAME_KEY = "name"
METADATA_VERSION_KEY = "version"

# ----------------------------------------------------------------------
# Configuration parameters
# ----------------------------------------------------------------------
CONFIG_API_BASE_URL = "api_base_url"
CONFIG_TENANT_URL = "tenant_url"
CONFIG_CLIENT_ID = "client_id"
CONFIG_CLIENT_SECRET = "client_secret"
CONFIG_VENDOR_ID = "vendor_id"
CONFIG_SCOPES = "scopes"
CONFIG_CUSTOM_PERMISSIONS = "custom_permissions"
CONFIG_PULL_CUSTOM_PROPERTIES = "pull_custom_properties"
CONFIG_CUSTOM_PROPERTIES = "custom_properties"
CONFIG_LABELS = {
    CONFIG_API_BASE_URL: "API Base URL",
    CONFIG_TENANT_URL: "Tenant URL",
    CONFIG_CLIENT_ID: "Client ID",
    CONFIG_CLIENT_SECRET: "Client Secret",
    CONFIG_VENDOR_ID: "Vendor ID",
    CONFIG_SCOPES: "Scopes",
    CONFIG_CUSTOM_PERMISSIONS: "Custom Permissions",
    CONFIG_PULL_CUSTOM_PROPERTIES: "Pull Custom Properties",
    CONFIG_CUSTOM_PROPERTIES: "Custom Properties",
}
CREDENTIAL_KEYS = (
    CONFIG_API_BASE_URL,
    CONFIG_TENANT_URL,
    CONFIG_CLIENT_ID,
    CONFIG_CLIENT_SECRET,
    CONFIG_VENDOR_ID,
    CONFIG_SCOPES,
)
PULL_CUSTOM_PROPERTIES_YES = "yes"
PULL_CUSTOM_PROPERTIES_NO = "no"
PULL_CUSTOM_PROPERTIES_VALUES = (
    PULL_CUSTOM_PROPERTIES_YES,
    PULL_CUSTOM_PROPERTIES_NO,
)
DEFAULT_API_BASE_URL = "https://api.armis.com"
URL_SCHEMES = ("http", "https")
URL_PATH_SEPARATOR = "/"
PARAMETER_TYPE_CONFIGURATION = "configuration"
PARAMETER_TYPE_ACTION = "action"
MAPPED_ENTITIES_ATTRIBUTE = "mappedEntities"
MAPPING_ENTITY_KEY = "entity"
MAPPING_FIELDS_KEY = "fields"
MAPPING_SOURCE_KEY = "source"
QUOTED_VALUE_FORMAT = "'{value}'"

# Keys of a configuration or action parameter field definition.
FIELD_LABEL_KEY = "label"
FIELD_KEY_KEY = "key"
FIELD_TYPE_KEY = "type"
FIELD_CHOICES_KEY = "choices"
FIELD_DEFAULT_KEY = "default"
FIELD_MANDATORY_KEY = "mandatory"
FIELD_DESCRIPTION_KEY = "description"
FIELD_PLACEHOLDER_KEY = "placeholder"
FIELD_HAS_API_CALL_KEY = "has_api_call"
FIELD_PAYLOAD_FIELDS_KEY = "payload_fields"
CHOICE_KEY = "key"
CHOICE_VALUE = "value"

# Field returned by get_dynamic_fields() when Pull Custom Properties is
# 'Yes'. It is not declared in manifest.json.
CUSTOM_PROPERTIES_FIELD = {
    FIELD_LABEL_KEY: CONFIG_LABELS[CONFIG_CUSTOM_PROPERTIES],
    FIELD_KEY_KEY: CONFIG_CUSTOM_PROPERTIES,
    FIELD_TYPE_KEY: "multichoice",
    FIELD_CHOICES_KEY: [],
    FIELD_DEFAULT_KEY: [],
    FIELD_MANDATORY_KEY: False,
    FIELD_DESCRIPTION_KEY: (
        "Armis Centrix custom properties to pull with the devices. Each "
        "selected custom property is added to the 'Devices' entity as 'Custom "
        "- <custom property name>'."
    ),
}

# Field returned by get_dynamic_fields() for the Scopes trigger, after
# Custom Permissions. It is not declared in manifest.json because Cloud
# Exchange renders the dynamic fields after the manifest fields, which
# would put Custom Permissions below it. It is itself a trigger: its
# payload holds CONFIG_PULL_CUSTOM_PROPERTIES, which tells the two
# triggers apart and ends the chain.
PULL_CUSTOM_PROPERTIES_FIELD = {
    FIELD_LABEL_KEY: CONFIG_LABELS[CONFIG_PULL_CUSTOM_PROPERTIES],
    FIELD_KEY_KEY: CONFIG_PULL_CUSTOM_PROPERTIES,
    FIELD_TYPE_KEY: "choice",
    FIELD_CHOICES_KEY: [
        {CHOICE_KEY: "Yes", CHOICE_VALUE: PULL_CUSTOM_PROPERTIES_YES},
        {CHOICE_KEY: "No", CHOICE_VALUE: PULL_CUSTOM_PROPERTIES_NO},
    ],
    FIELD_DEFAULT_KEY: PULL_CUSTOM_PROPERTIES_NO,
    FIELD_MANDATORY_KEY: True,
    FIELD_HAS_API_CALL_KEY: True,
    FIELD_PAYLOAD_FIELDS_KEY: [
        CONFIG_PULL_CUSTOM_PROPERTIES,
        CONFIG_API_BASE_URL,
        CONFIG_TENANT_URL,
        CONFIG_CLIENT_ID,
        CONFIG_CLIENT_SECRET,
        CONFIG_VENDOR_ID,
        CONFIG_SCOPES,
        CONFIG_CUSTOM_PERMISSIONS,
    ],
    FIELD_DESCRIPTION_KEY: (
        "Select 'Yes' to pull Armis Centrix custom properties with the "
        "devices. Provide the credentials above first, as the custom "
        "properties are fetched from the Armis Centrix platform."
    ),
}

# Field returned by get_dynamic_fields() when 'Custom Permissions' is
# selected in Scopes. It is not declared in manifest.json.
CUSTOM_PERMISSIONS_FIELD = {
    FIELD_LABEL_KEY: CONFIG_LABELS[CONFIG_CUSTOM_PERMISSIONS],
    FIELD_KEY_KEY: CONFIG_CUSTOM_PERMISSIONS,
    FIELD_PLACEHOLDER_KEY: "e.g. PERMISSION.DEVICE.READ, FULL_VISIBILITY",
    FIELD_TYPE_KEY: "text",
    FIELD_DEFAULT_KEY: "",
    FIELD_MANDATORY_KEY: True,
    FIELD_DESCRIPTION_KEY: (
        "Comma-separated Armis Centrix permissions to request in addition to "
        "the selected Scopes. Provide the full permission names, for example "
        "PERMISSION.DEVICE.READ. Refer to https://dev.armis.com/reference for "
        "the available permissions."
    ),
}

# ----------------------------------------------------------------------
# API endpoints
# ----------------------------------------------------------------------
TOKEN_ENDPOINT = "/v3/oauth/token"
SEARCH_ASSETS_ENDPOINT = "/v3/assets/_search"
CUSTOM_PROPERTIES_ENDPOINT = "/v3/settings/device-custom-properties"
BULK_ASSETS_ENDPOINT = "/v3/assets/_bulk"
URL_FORMAT = "{base_url}{endpoint}"
METHOD_GET = "GET"
METHOD_POST = "POST"

# ----------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
SCOPE_DEVICE_READ = "PERMISSION.DEVICE.READ"
SCOPE_PII_DEVICE = "PERMISSION.PII.DEVICE"
SCOPE_FULL_VISIBILITY = "FULL_VISIBILITY"
SCOPE_CUSTOM_PROPERTIES_READ = "PERMISSION.SETTINGS.CUSTOM_PROPERTIES.READ"
SCOPE_CUSTOM_PROPERTIES_MANAGE = (
    "PERMISSION.SETTINGS.CUSTOM_PROPERTIES.MANAGE"
)
SCOPE_DEVICE_MANAGE_EDIT = "PERMISSION.DEVICE.MANAGE.EDIT"
# Options of the Scopes multichoice. Each option except Custom
# Permissions stands for a group of Armis permissions; the token is
# requested with the permissions of the selected options plus the
# Custom Permissions. Keep in sync with the Scopes choices in
# manifest.json.
SCOPE_DEVICE_PULL = "device_pull"
SCOPE_CUSTOM_PROPERTIES_PULL = "custom_properties_pull"
SCOPE_CUSTOM_ACTIONS = "custom_actions"
# Value of the Scopes option that shows the Custom Permissions field.
SCOPE_CUSTOM = "custom"
SCOPE_GROUPS = {
    # POST /v3/assets/_search: the device pull, and the read of the
    # current values before Remove Custom Property Value.
    SCOPE_DEVICE_PULL: (
        SCOPE_DEVICE_READ,
        SCOPE_PII_DEVICE,
        SCOPE_FULL_VISIBILITY,
    ),
    # GET /v3/settings/device-custom-properties: Custom Properties
    # dropdowns, entity field types and the checks of both actions.
    SCOPE_CUSTOM_PROPERTIES_PULL: (SCOPE_CUSTOM_PROPERTIES_READ,),
    # POST /v3/assets/_bulk and POST /v3/settings/device-custom-properties.
    SCOPE_CUSTOM_ACTIONS: (
        SCOPE_DEVICE_MANAGE_EDIT,
        SCOPE_CUSTOM_PROPERTIES_MANAGE,
    ),
}
SCOPE_LABELS = {
    SCOPE_DEVICE_PULL: "Device Pull",
    SCOPE_CUSTOM_PROPERTIES_PULL: "Custom Properties Pull",
    SCOPE_CUSTOM_ACTIONS: "Custom Actions",
    SCOPE_CUSTOM: "Custom Permissions",
}
SCOPE_CHOICES = [
    {CHOICE_KEY: SCOPE_LABELS[value], CHOICE_VALUE: value}
    for value in (
        SCOPE_DEVICE_PULL,
        SCOPE_CUSTOM_PROPERTIES_PULL,
        SCOPE_CUSTOM_ACTIONS,
        SCOPE_CUSTOM,
    )
]
SCOPE_VALUES = tuple(choice[CHOICE_VALUE] for choice in SCOPE_CHOICES)
SCOPES_SEPARATOR = ","
SCOPE_PATTERN = r"^[A-Za-z0-9_.]+$"
JWT_SCOPE_CLAIM = "scope"
JWT_SEGMENT_SEPARATOR = "."
JWT_MIN_SEGMENTS = 2
BASE64_PADDING = "="
BASE64_BLOCK_SIZE = 4
TEXT_ENCODING = "utf-8"
DEFAULT_TOKEN_EXPIRES_IN = 900
TOKEN_REFRESH_MARGIN = 120
STORAGE_ACCESS_TOKEN = "access_token"
STORAGE_TOKEN_EXPIRY = "token_expiry"
STORAGE_CREDENTIALS_HASH = "credentials_hash"
HASH_SEPARATOR = "|"
TOKEN_AUDIENCE_KEY = "audience"
TOKEN_GRANT_TYPE_KEY = "grant_type"
TOKEN_CLIENT_ID_KEY = "client_id"
TOKEN_CLIENT_SECRET_KEY = "client_secret"
TOKEN_VENDOR_ID_KEY = "vendor_id"
TOKEN_SCOPES_KEY = "scopes"
ACCESS_TOKEN_KEY = "access_token"
EXPIRES_IN_KEY = "expires_in"

# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
HEADER_AUTHORIZATION = "Authorization"
HEADER_ACCEPT = "Accept"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_USER_AGENT = "User-Agent"
HEADER_RETRY_AFTER = "Retry-After"
MIME_JSON = "application/json"
BEARER_FORMAT = "Bearer {token}"
DEFAULT_CE_USER_AGENT = "netskope-ce"
USER_AGENT_FORMAT = "{ce_agent}-{module}-{plugin}-{version}"
USER_AGENT_SPACE = " "
USER_AGENT_SPACE_REPLACEMENT = "-"
# Attempts in total for a request answered with 429 or 5xx, or failing
# with a connection error or a timeout.
MAX_API_CALLS = 4
# Wait before the first retry when no numeric Retry-After header is
# returned; doubled on each further retry (60, 120, 240 seconds).
DEFAULT_WAIT_TIME = 60
BACKOFF_FACTOR = 2
MAX_WAIT_TIME = 300
CONNECT_TIMEOUT = 30
READ_TIMEOUT = 120
REQUEST_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
TOO_MANY_REQUESTS_STATUS = 429
SERVER_ERROR_STATUS_CODES = range(500, 600)
RETRY_STATUS_CODES = frozenset(
    [TOO_MANY_REQUESTS_STATUS] + list(SERVER_ERROR_STATUS_CODES)
)
SUCCESS_STATUS_CODES = (200, 201, 202, 207)
NO_CONTENT_STATUS = 204
BAD_REQUEST_STATUS = 400
UNAUTHORIZED_STATUS = 401
FORBIDDEN_STATUS = 403
NOT_FOUND_STATUS = 404
CREATED_STATUS = 201
MAX_RESPONSE_TEXT_LENGTH = 500
# Keys of an error response body that hold the API message, in the order
# they are looked up, and the longest API message put in a log message.
API_MESSAGE_KEYS = ("detail", "message", "error_description", "error", "title")
MAX_API_MESSAGE_LENGTH = 300
JWT_REDACTION_PATTERN = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
BEARER_REDACTION_PATTERN = r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"
ACCESS_TOKEN_REDACTION_PATTERN = r'("access_token"\s*:\s*")[^"]*(")'
ACCESS_TOKEN_REDACTION_REPLACEMENT = r"\1[REDACTED]\2"
REDACTED = "[REDACTED]"

# ----------------------------------------------------------------------
# Pull
# ----------------------------------------------------------------------
ENTITY_DEVICES = "Devices"
ENTITY_DEVICES_LABEL = "Devices"
ASSET_TYPE_DEVICE = "DEVICE"
PAGE_SIZE = 1000
FIRST_PAGE_AFTER = 0
FILTER_CRITERIA_VISIBILITY = "VISIBILITY"
VISIBILITY_FULL = "FULL"
FILTER_OPERATOR_EQUALS = "EQUALS"
ASSET_ID_SOURCE = "ASSET_ID"
CUSTOM_FIELD_PREFIX = "custom."
CUSTOM_ENTITY_FIELD_PREFIX = "Custom - "

# Request body keys.
BODY_ASSET_TYPE = "asset_type"
BODY_FIELDS = "fields"
BODY_FILTER = "filter"
BODY_OPERATOR = "operator"
BODY_FILTER_CRITERIA = "filter_criteria"
BODY_VISIBILITY = "visibility"
BODY_LIMIT = "limit"
BODY_AFTER = "after"
BODY_ASSET_ID_SOURCE = "asset_id_source"
BODY_ITEMS = "items"
BODY_ASSET_ID = "asset_id"
BODY_OPERATION = "operation"
BODY_KEY = "key"
BODY_VALUE = "value"

# Response keys.
ITEMS_KEY = "items"
FIELDS_KEY = "fields"
NEXT_KEY = "next"
STATUS_KEY = "status"
ERROR_KEY = "error"
SITE_NAME_KEY = "name"

# Fields of the _search API.
API_DEVICE_ID = "device_id"
API_DISPLAY = "display"
API_NAMES = "names"
API_BRAND = "brand"
API_MODEL = "model"
API_CATEGORY = "category"
API_TYPE = "type"
API_OS_NAME = "os_name"
API_OS_VERSION = "os_version"
API_IPV4_ADDRESSES = "ipv4_addresses"
API_IPV6_ADDRESSES = "ipv6_addresses"
API_MAC_ADDRESSES = "mac_addresses"
API_SERIAL_NUMBERS = "serial_numbers"
API_TAGS = "tags"
API_RISK_LEVEL = "risk_level"
API_SITE = "site"
API_FIRST_SEEN = "first_seen"
API_LAST_SEEN = "last_seen"
API_VISIBILITY = "visibility"
STANDARD_SEARCH_FIELDS = (
    API_DEVICE_ID,
    API_DISPLAY,
    API_NAMES,
    API_BRAND,
    API_MODEL,
    API_CATEGORY,
    API_TYPE,
    API_OS_NAME,
    API_OS_VERSION,
    API_IPV4_ADDRESSES,
    API_IPV6_ADDRESSES,
    API_MAC_ADDRESSES,
    API_SERIAL_NUMBERS,
    API_TAGS,
    API_RISK_LEVEL,
    API_SITE,
    API_FIRST_SEEN,
    API_LAST_SEEN,
    API_VISIBILITY,
)

# Entity field names.
FIELD_DEVICE_ID = "Device ID"
FIELD_HOSTNAME = "Hostname"
FIELD_NAMES = "Names"
FIELD_BRAND = "Brand"
FIELD_MODEL = "Model"
FIELD_CATEGORY = "Category"
FIELD_TYPE = "Type"
FIELD_OPERATING_SYSTEM = "Operating System"
FIELD_OPERATING_SYSTEM_VERSION = "Operating System Version"
FIELD_IPV4_ADDRESSES = "IPv4 Addresses"
FIELD_IPV6_ADDRESSES = "IPv6 Addresses"
FIELD_MAC_ADDRESSES = "MAC Addresses"
FIELD_SERIAL_NUMBER = "Serial Number"
FIELD_TAGS = "Tags"
FIELD_RISK_LEVEL = "Risk Level"
FIELD_SITE = "Site"
FIELD_FIRST_SEEN = "First Seen"
FIELD_LAST_SEEN = "Last Seen"
FIELD_VISIBILITY = "Visibility"
REQUIRED_ENTITY_FIELDS = (
    FIELD_DEVICE_ID,
    FIELD_HOSTNAME,
    FIELD_SERIAL_NUMBER,
)

# Values of EntityFieldType used by the plugin.
FIELD_TYPE_STRING = "string"
FIELD_TYPE_NUMBER = "number"
FIELD_TYPE_LIST = "list"
FIELD_TYPE_DATETIME = "datetime"
FIELD_TYPE_BOOLEAN = "boolean"

# Transformations applied to the _search fields.
TRANSFORM_DEVICE_ID = "to_device_id"
TRANSFORM_STRING = "to_string"
TRANSFORM_LIST = "to_list"
TRANSFORM_NUMBER = "to_number"
TRANSFORM_SITE = "to_site"
TRANSFORM_DATETIME = "to_datetime"
TRANSFORM_SERIAL_NUMBER = "serial_number_fan_out"

MAPPING_API_KEY = "api_key"
MAPPING_TRANSFORMATION = "transformation"
MAPPING_TYPE = "type"
MAPPING_DESCRIPTION = "description"

# Entity field -> _search field, transformation, field type and
# description, in the order shown in the entity.
DEVICE_FIELD_MAPPING = {
    FIELD_DEVICE_ID: {
        MAPPING_API_KEY: API_DEVICE_ID,
        MAPPING_TRANSFORMATION: TRANSFORM_DEVICE_ID,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: (
            "Armis Centrix device ID. Used as the Device ID of the 'Set "
            "Custom Property Value' action."
        ),
    },
    FIELD_HOSTNAME: {
        MAPPING_API_KEY: API_DISPLAY,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Display name of the device in Armis Centrix.",
    },
    FIELD_NAMES: {
        MAPPING_API_KEY: API_NAMES,
        MAPPING_TRANSFORMATION: TRANSFORM_LIST,
        MAPPING_TYPE: FIELD_TYPE_LIST,
        MAPPING_DESCRIPTION: "Names known for the device in Armis Centrix.",
    },
    FIELD_BRAND: {
        MAPPING_API_KEY: API_BRAND,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Brand of the device.",
    },
    FIELD_MODEL: {
        MAPPING_API_KEY: API_MODEL,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Model of the device.",
    },
    FIELD_CATEGORY: {
        MAPPING_API_KEY: API_CATEGORY,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Armis Centrix category of the device.",
    },
    FIELD_TYPE: {
        MAPPING_API_KEY: API_TYPE,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Armis Centrix type of the device.",
    },
    FIELD_OPERATING_SYSTEM: {
        MAPPING_API_KEY: API_OS_NAME,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Operating system of the device.",
    },
    FIELD_OPERATING_SYSTEM_VERSION: {
        MAPPING_API_KEY: API_OS_VERSION,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Operating system version of the device.",
    },
    FIELD_IPV4_ADDRESSES: {
        MAPPING_API_KEY: API_IPV4_ADDRESSES,
        MAPPING_TRANSFORMATION: TRANSFORM_LIST,
        MAPPING_TYPE: FIELD_TYPE_LIST,
        MAPPING_DESCRIPTION: "IPv4 addresses of the device.",
    },
    FIELD_IPV6_ADDRESSES: {
        MAPPING_API_KEY: API_IPV6_ADDRESSES,
        MAPPING_TRANSFORMATION: TRANSFORM_LIST,
        MAPPING_TYPE: FIELD_TYPE_LIST,
        MAPPING_DESCRIPTION: "IPv6 addresses of the device.",
    },
    FIELD_MAC_ADDRESSES: {
        MAPPING_API_KEY: API_MAC_ADDRESSES,
        MAPPING_TRANSFORMATION: TRANSFORM_LIST,
        MAPPING_TYPE: FIELD_TYPE_LIST,
        MAPPING_DESCRIPTION: "MAC addresses of the device.",
    },
    FIELD_SERIAL_NUMBER: {
        MAPPING_API_KEY: API_SERIAL_NUMBERS,
        MAPPING_TRANSFORMATION: TRANSFORM_SERIAL_NUMBER,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: (
            "Serial number of the device. A device with several serial "
            "numbers is pulled as one record per serial number."
        ),
    },
    FIELD_TAGS: {
        MAPPING_API_KEY: API_TAGS,
        MAPPING_TRANSFORMATION: TRANSFORM_LIST,
        MAPPING_TYPE: FIELD_TYPE_LIST,
        MAPPING_DESCRIPTION: "Armis Centrix tags of the device (read-only).",
    },
    FIELD_RISK_LEVEL: {
        MAPPING_API_KEY: API_RISK_LEVEL,
        MAPPING_TRANSFORMATION: TRANSFORM_NUMBER,
        MAPPING_TYPE: FIELD_TYPE_NUMBER,
        MAPPING_DESCRIPTION: (
            "Armis Centrix risk level of the device, from 0 to 100, as "
            "returned by Armis Centrix."
        ),
    },
    FIELD_SITE: {
        MAPPING_API_KEY: API_SITE,
        MAPPING_TRANSFORMATION: TRANSFORM_SITE,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Name of the Armis Centrix site of the device.",
    },
    FIELD_FIRST_SEEN: {
        MAPPING_API_KEY: API_FIRST_SEEN,
        MAPPING_TRANSFORMATION: TRANSFORM_DATETIME,
        MAPPING_TYPE: FIELD_TYPE_DATETIME,
        MAPPING_DESCRIPTION: "Time the device was first seen, in UTC.",
    },
    FIELD_LAST_SEEN: {
        MAPPING_API_KEY: API_LAST_SEEN,
        MAPPING_TRANSFORMATION: TRANSFORM_DATETIME,
        MAPPING_TYPE: FIELD_TYPE_DATETIME,
        MAPPING_DESCRIPTION: "Time the device was last seen, in UTC.",
    },
    FIELD_VISIBILITY: {
        MAPPING_API_KEY: API_VISIBILITY,
        MAPPING_TRANSFORMATION: TRANSFORM_STRING,
        MAPPING_TYPE: FIELD_TYPE_STRING,
        MAPPING_DESCRIPTION: "Armis Centrix visibility of the device.",
    },
}

# ----------------------------------------------------------------------
# Custom properties
# ----------------------------------------------------------------------
PROPERTY_NAME_KEY = "name"
PROPERTY_DESCRIPTION_KEY = "description"
PROPERTY_TYPE_KEY = "type"
PROPERTY_ALLOWED_VALUES_KEY = "allowed_values"
PROPERTY_TYPE_STRING = "string"
PROPERTY_TYPE_INTEGER = "integer"
PROPERTY_TYPE_BOOLEAN = "boolean"
PROPERTY_TYPE_ENUM = "enum"
PROPERTY_TYPE_EXTERNAL_LINK = "externalLink"
PROPERTY_TYPE_TIMESTAMP = "timestamp"
PROPERTY_TYPES = (
    PROPERTY_TYPE_STRING,
    PROPERTY_TYPE_INTEGER,
    PROPERTY_TYPE_BOOLEAN,
    PROPERTY_TYPE_ENUM,
    PROPERTY_TYPE_EXTERNAL_LINK,
    PROPERTY_TYPE_TIMESTAMP,
)
# Types offered when creating a custom property. External Link and
# Timestamp properties created in Armis can still be set.
NEW_PROPERTY_TYPES = (
    PROPERTY_TYPE_STRING,
    PROPERTY_TYPE_INTEGER,
    PROPERTY_TYPE_BOOLEAN,
    PROPERTY_TYPE_ENUM,
)
PROPERTY_TYPE_CHOICES = [
    {CHOICE_KEY: "String", CHOICE_VALUE: PROPERTY_TYPE_STRING},
    {CHOICE_KEY: "Integer", CHOICE_VALUE: PROPERTY_TYPE_INTEGER},
    {CHOICE_KEY: "Boolean", CHOICE_VALUE: PROPERTY_TYPE_BOOLEAN},
    {CHOICE_KEY: "Enum", CHOICE_VALUE: PROPERTY_TYPE_ENUM},
]
# Armis custom property type -> EntityFieldType value.
CUSTOM_PROPERTY_FIELD_TYPES = {
    PROPERTY_TYPE_STRING: FIELD_TYPE_STRING,
    PROPERTY_TYPE_ENUM: FIELD_TYPE_STRING,
    PROPERTY_TYPE_EXTERNAL_LINK: FIELD_TYPE_STRING,
    PROPERTY_TYPE_INTEGER: FIELD_TYPE_NUMBER,
    PROPERTY_TYPE_BOOLEAN: FIELD_TYPE_BOOLEAN,
    PROPERTY_TYPE_TIMESTAMP: FIELD_TYPE_DATETIME,
}
CUSTOM_FIELD_DESCRIPTION = (
    "Value of the Armis Centrix custom property '{name}' of the device."
)
PROPERTY_NAME_PATTERN = r"^[\w_]*$"
PROPERTY_NAME_MAX_LENGTH = 40
PROPERTY_DESCRIPTION_MAX_LENGTH = 250

# ----------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------
ACTION_NO_ACTION = "generate"
ACTION_SET_CUSTOM_PROPERTY = "set_custom_property"
ACTION_REMOVE_CUSTOM_PROPERTY = "remove_custom_property"
ACTION_LABELS = {
    ACTION_NO_ACTION: "No action",
    ACTION_SET_CUSTOM_PROPERTY: "Set Custom Property Value",
    ACTION_REMOVE_CUSTOM_PROPERTY: "Remove Custom Property Value",
}
# Order of the actions in the UI; No action is listed last.
SUPPORTED_ACTIONS = (
    ACTION_SET_CUSTOM_PROPERTY,
    ACTION_REMOVE_CUSTOM_PROPERTY,
    ACTION_NO_ACTION,
)
CUSTOM_PROPERTY_ACTIONS = (
    ACTION_SET_CUSTOM_PROPERTY,
    ACTION_REMOVE_CUSTOM_PROPERTY,
)
# Scopes each custom property action needs: the custom property list
# and the write permissions.
ACTION_REQUIRED_SCOPES = {
    ACTION_SET_CUSTOM_PROPERTY: (
        SCOPE_CUSTOM_ACTIONS,
        SCOPE_CUSTOM_PROPERTIES_PULL,
    ),
    ACTION_REMOVE_CUSTOM_PROPERTY: (
        SCOPE_CUSTOM_ACTIONS,
        SCOPE_CUSTOM_PROPERTIES_PULL,
    ),
}
ACTION_PARAMS_KEY = "params"
ACTION_ID_KEY = "id"
SINGLE_ACTION_ID = "single"
PARAM_DEVICE_ID = "device_id"
# Set Custom Property Value takes one custom property; Remove Custom
# Property Value takes several.
PARAM_CUSTOM_PROPERTY = "custom_property"
PARAM_CUSTOM_PROPERTIES = "custom_properties"
PARAM_VALUE = "value"
PARAM_NEW_PROPERTY_NAME = "new_property_name"
PARAM_NEW_PROPERTY_DESCRIPTION = "new_property_description"
PARAM_NEW_PROPERTY_TYPE = "new_property_type"
PARAM_NEW_PROPERTY_ALLOWED_VALUES = "new_property_allowed_values"
PARAM_LABELS = {
    PARAM_DEVICE_ID: "Device ID",
    PARAM_CUSTOM_PROPERTY: "Custom Property",
    PARAM_CUSTOM_PROPERTIES: "Custom Properties",
    PARAM_VALUE: "Value",
    PARAM_NEW_PROPERTY_NAME: "New Property Name",
    PARAM_NEW_PROPERTY_DESCRIPTION: "Description",
    PARAM_NEW_PROPERTY_TYPE: "Type",
    PARAM_NEW_PROPERTY_ALLOWED_VALUES: "Allowed Values",
}
CREATE_PROPERTY_VALUE = "create"
CREATE_PROPERTY_LABEL = "Create new custom property"
CREATE_BUCKET_FORMAT = "create:{name}"
DEVICE_ID_PARAM = {
    FIELD_LABEL_KEY: PARAM_LABELS[PARAM_DEVICE_ID],
    FIELD_KEY_KEY: PARAM_DEVICE_ID,
    FIELD_PLACEHOLDER_KEY: "e.g. 123",
    FIELD_TYPE_KEY: "text",
    FIELD_DEFAULT_KEY: "",
    FIELD_MANDATORY_KEY: True,
    FIELD_DESCRIPTION_KEY: (
        "Armis Centrix device ID (a whole number) of the device to update. "
        "Select the 'Device ID' field of the 'Devices' entity from the Source "
        "Field dropdown."
    ),
}
# Cloud Exchange renders the action parameters in list order and cannot
# show a parameter only when another one has a given value, so the
# create parameters are always listed and Value comes last.
SET_CUSTOM_PROPERTY_PARAMS = [
    DEVICE_ID_PARAM,
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_CUSTOM_PROPERTY],
        FIELD_KEY_KEY: PARAM_CUSTOM_PROPERTY,
        FIELD_TYPE_KEY: "choice",
        FIELD_CHOICES_KEY: [],
        FIELD_DEFAULT_KEY: CREATE_PROPERTY_VALUE,
        FIELD_MANDATORY_KEY: True,
        FIELD_DESCRIPTION_KEY: (
            "Armis Centrix custom property to set on the device. Select "
            "'Create new custom property' to create a custom property first. "
            "Select the value from the Static Field dropdown only. To set "
            "different custom properties, configure one action per custom "
            "property."
        ),
    },
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_NEW_PROPERTY_NAME],
        FIELD_KEY_KEY: PARAM_NEW_PROPERTY_NAME,
        FIELD_PLACEHOLDER_KEY: "e.g. Netskope_Risk_Level",
        FIELD_TYPE_KEY: "text",
        FIELD_DEFAULT_KEY: "",
        FIELD_MANDATORY_KEY: False,
        FIELD_DESCRIPTION_KEY: (
            "Name of the custom property to create. Required only when "
            "'Create new custom property' is selected in Custom Property. "
            "Up to 40 letters, digits and underscores. Static Field only."
        ),
    },
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_NEW_PROPERTY_DESCRIPTION],
        FIELD_KEY_KEY: PARAM_NEW_PROPERTY_DESCRIPTION,
        FIELD_PLACEHOLDER_KEY: "e.g. Risk level shared by Netskope",
        FIELD_TYPE_KEY: "text",
        FIELD_DEFAULT_KEY: "",
        FIELD_MANDATORY_KEY: False,
        FIELD_DESCRIPTION_KEY: (
            "Description of the custom property to create, up to 250 "
            "characters. Used only when 'Create new custom property' is "
            "selected in Custom Property. Static Field only."
        ),
    },
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_NEW_PROPERTY_TYPE],
        FIELD_KEY_KEY: PARAM_NEW_PROPERTY_TYPE,
        FIELD_TYPE_KEY: "choice",
        FIELD_CHOICES_KEY: PROPERTY_TYPE_CHOICES,
        FIELD_DEFAULT_KEY: PROPERTY_TYPE_STRING,
        FIELD_MANDATORY_KEY: False,
        FIELD_DESCRIPTION_KEY: (
            "Type of the custom property to create. Used only when 'Create "
            "new custom property' is selected in Custom Property. Static "
            "Field only."
        ),
    },
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_NEW_PROPERTY_ALLOWED_VALUES],
        FIELD_KEY_KEY: PARAM_NEW_PROPERTY_ALLOWED_VALUES,
        FIELD_PLACEHOLDER_KEY: "e.g. low, medium, high, critical",
        FIELD_TYPE_KEY: "text",
        FIELD_DEFAULT_KEY: "",
        FIELD_MANDATORY_KEY: False,
        FIELD_DESCRIPTION_KEY: (
            "Comma-separated allowed values of the custom property to "
            "create. Required only when 'Create new custom property' is "
            "selected and the Type is 'Enum'. Static Field only."
        ),
    },
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_VALUE],
        FIELD_KEY_KEY: PARAM_VALUE,
        FIELD_PLACEHOLDER_KEY: "e.g. high",
        FIELD_TYPE_KEY: "text",
        FIELD_DEFAULT_KEY: "",
        FIELD_MANDATORY_KEY: True,
        FIELD_DESCRIPTION_KEY: (
            "Value to set on the selected custom property, or on the new "
            "custom property. It must match the type of the custom property: "
            "any text for String, a whole number for Integer, 'true' or "
            "'false' for Boolean, one of the allowed values for Enum, an http "
            "or https URL for External Link and an ISO 8601 date-time (e.g. "
            "2026-01-31T10:00:00Z) for Timestamp. Provide a Static value or "
            "select a field from the Source Field dropdown."
        ),
    },
]
REMOVE_CUSTOM_PROPERTY_PARAMS = [
    DEVICE_ID_PARAM,
    {
        FIELD_LABEL_KEY: PARAM_LABELS[PARAM_CUSTOM_PROPERTIES],
        FIELD_KEY_KEY: PARAM_CUSTOM_PROPERTIES,
        FIELD_TYPE_KEY: "multichoice",
        FIELD_CHOICES_KEY: [],
        FIELD_DEFAULT_KEY: [],
        FIELD_MANDATORY_KEY: False,
        FIELD_DESCRIPTION_KEY: (
            "Armis Centrix custom properties whose values are removed from "
            "the device. Select the values from the Static Field dropdown "
            "only."
        ),
    },
]
BULK_BATCH_SIZE = 1000
BULK_OPERATION_SET = "SET"
BULK_OPERATION_UNSET = "UNSET"
BULK_ITEM_SUCCESS_STATUSES = (200, 202)
BOOLEAN_TRUE = "true"
BOOLEAN_FALSE = "false"
INTEGER_PATTERN = r"^[+-]?\d+$"
SOURCE_FIELD_MARKER = "$"
LIST_VALUE_SEPARATOR = ", "
ALLOWED_VALUES_SEPARATOR = ","
UTC_SUFFIX = "Z"
UTC_OFFSET = "+00:00"
DETAILS_SUCCEEDED_KEY = "succeeded"
DETAILS_FAILED_KEY = "failed"
DETAILS_DEVICE_ID_KEY = "device_id"
DETAILS_PROPERTY_KEY = "custom_property"
DETAILS_STATUS_KEY = "status"
DETAILS_ERROR_KEY = "error"
DETAILS_ERRORS_KEY = "errors"
VERB_SET = "set"
VERB_CLEARED = "cleared"

# ----------------------------------------------------------------------
# Logger messages (the part after "log_prefix: ")
# ----------------------------------------------------------------------
LOGGER_MSG_TOKEN = "generating the access token"
LOGGER_MSG_LIST_PROPERTIES = "fetching custom properties"
LOGGER_MSG_CREATE_PROPERTY = "creating the custom property '{name}'"
LOGGER_MSG_SEARCH_PAGE = "pulling devices from page {page}"
LOGGER_MSG_BULK_SET = (
    "setting {count} custom property value(s) in batch {batch}"
)
LOGGER_MSG_BULK_UNSET = (
    "clearing {count} custom property value(s) in batch {batch}"
)
LOGGER_MSG_PULL = "pulling devices"
LOGGER_MSG_VALIDATE = "validating configuration parameters"
LOGGER_MSG_VALIDATE_ACTION = "validating the action"
LOGGER_MSG_EXECUTE = "executing the action '{label}'"
LOGGER_MSG_DYNAMIC_FIELDS = "loading the custom properties"

# Error catalogue: E-VAL.
ERR_VAL_01 = (
    "Error occurred while validating configuration parameters. API Base "
    "URL is a required configuration parameter."
)
RES_VAL_01 = "Ensure that a valid API Base URL is provided."
ERR_VAL_02 = (
    "Error occurred while validating configuration parameters. Invalid API "
    "Base URL provided."
)
RES_VAL_02 = (
    "Ensure that the API Base URL is a text value, for example "
    "https://api.armis.com."
)
ERR_VAL_03 = (
    "Error occurred while validating configuration parameters. Invalid "
    "Tenant URL provided."
)
RES_VAL_03 = (
    "Ensure that the Tenant URL is the URL of your Armis Centrix tenant, for "
    "example https://acme.armis.com/."
)
ERR_VAL_04 = (
    "Error occurred while validating configuration parameters. {field} is "
    "a required configuration parameter."
)
RES_VAL_04 = "Ensure that a valid {field} is provided."
ERR_VAL_05 = (
    "Error occurred while validating configuration parameters. Invalid "
    "value provided for {field}."
)
RES_VAL_05 = "Ensure that the {field} is a non-empty string value."
ERR_VAL_06 = (
    "Error occurred while validating configuration parameters. Invalid "
    "Scopes provided."
)
RES_VAL_06 = (
    "Ensure that at least one scope is selected from the available "
    "options."
)
ERR_VAL_07 = (
    "Error occurred while validating configuration parameters. Invalid "
    "Custom Properties provided."
)
RES_VAL_07 = (
    "Ensure that the Custom Properties are selected from the available "
    "options."
)
ERR_VAL_08 = (
    "Error occurred while validating configuration parameters. The access "
    "token does not include the required scope(s): {scopes}."
)
RES_VAL_08 = (
    "Ensure that the Armis Centrix user who generated the Secret API key has "
    "these permissions."
)
ERR_VAL_09 = (
    "Error occurred while validating configuration parameters. Required "
    "field(s) {fields} are not mapped for the 'Devices' entity."
)
RES_VAL_09 = (
    "Ensure that the required fields are mapped in the entity mapping."
)
ERR_VAL_10 = (
    "Error occurred while validating configuration parameters. Invalid "
    "value provided for Pull Custom Properties."
)
RES_VAL_10 = (
    "Ensure that 'Yes' or 'No' is selected for Pull Custom Properties."
)
ERR_VAL_11 = (
    "Error occurred while validating configuration parameters. Invalid "
    "Custom Permissions provided."
)
RES_VAL_11 = (
    "Ensure that the Custom Permissions are comma-separated full "
    "permission names, for example PERMISSION.DEVICE.READ."
)
ERR_VAL_12 = (
    "Error occurred while validating configuration parameters. The "
    "'Custom Properties Pull' scope is required to pull custom "
    "properties."
)
RES_VAL_12 = (
    "Ensure that 'Custom Properties Pull' is selected in Scopes, or "
    "select 'No' for Pull Custom Properties."
)
ERR_VAL_13 = (
    "Error occurred while validating configuration parameters. The "
    "'Custom Properties Pull' scope must be selected with the 'Device "
    "Pull' or 'Custom Actions' scope."
)
RES_VAL_13 = (
    "Ensure that 'Device Pull' or 'Custom Actions' is also selected in "
    "Scopes."
)
ERR_VAL_14 = (
    "Error occurred while validating configuration parameters. The "
    "'Custom Actions' scope requires the 'Custom Properties Pull' scope."
)
RES_VAL_14 = (
    "Ensure that 'Custom Properties Pull' is also selected in Scopes."
)
ERR_VAL_15 = (
    "Error occurred while validating configuration parameters. The "
    "'Device Pull' scope is required to pull the devices of the mapped "
    "'Devices' entity."
)
RES_VAL_15 = (
    "Ensure that 'Device Pull' is selected in Scopes, or remove the "
    "entity mapping."
)

# Error catalogue: E-AUTH.
ERR_AUTH_01 = (
    "Error occurred while generating the access token. Invalid "
    "credentials provided."
)
RES_AUTH_01 = (
    "Ensure that the Tenant URL, Client ID (the email address of the Armis "
    "Centrix user), Client Secret and Vendor ID are correct."
)
ERR_AUTH_02 = (
    "Error occurred while generating the access token. Access is "
    "forbidden."
)
RES_AUTH_02 = (
    "Ensure that the Armis Centrix user can generate API tokens and that the "
    "Vendor ID is registered for this tenant."
)
ERR_AUTH_03 = (
    "Error occurred while generating the access token. Invalid response "
    "received from Armis Centrix."
)
RES_AUTH_03 = (
    "Ensure that the API Base URL points to the Armis Centrix API and that "
    "the Armis Centrix service is available."
)
ERR_AUTH_04 = (
    "Error occurred while generating the access token. Unable to connect "
    "to Armis Centrix. Error: {error}"
)
RES_AUTH_04 = (
    "Ensure that the API Base URL is correct and the Cloud Exchange host "
    "can reach it directly or through the configured proxy."
)
ERR_AUTH_05 = (
    "Error occurred while {logger_msg}. The access token was rejected "
    "after it was renewed."
)
RES_AUTH_05 = (
    "Ensure that the credentials are valid and the Armis Centrix user has the "
    "required permissions."
)
ERR_AUTH_06 = (
    "Error occurred while generating the access token. The Armis Centrix "
    "token endpoint was not found (404)."
)
RES_AUTH_06 = "Ensure that the API Base URL is https://api.armis.com."
# Token endpoint status -> (message, resolution).
TOKEN_ERRORS = {
    BAD_REQUEST_STATUS: (ERR_AUTH_01, RES_AUTH_01),
    UNAUTHORIZED_STATUS: (ERR_AUTH_01, RES_AUTH_01),
    FORBIDDEN_STATUS: (ERR_AUTH_02, RES_AUTH_02),
    NOT_FOUND_STATUS: (ERR_AUTH_06, RES_AUTH_06),
}

# Error catalogue: E-API.
ERR_API_01 = (
    "Error occurred while {logger_msg}. Rate limit reached and the "
    "request was retried {retries} times."
)
RES_API_01 = (
    "Ensure that fewer than 200 requests per 5 minutes are made with "
    "these credentials, then try again."
)
ERR_API_02 = (
    "Error occurred while {logger_msg}. Armis Centrix returned a server error "
    "({status_code})."
)
RES_API_02 = (
    "Ensure that the Armis Centrix service is available, then try again."
)
ERR_API_03 = (
    "Error occurred while {logger_msg}. Unexpected response "
    "({status_code}): {text}."
)
RES_API_03 = "Ensure that the plugin configuration is valid."
ERR_API_04 = (
    "Error occurred while {logger_msg}. Invalid JSON response received."
)
RES_API_04 = "Ensure that the API Base URL points to the Armis Centrix API."
# Error responses of the data calls. The whole Armis response body goes in
# the log details; its API message is added to the message by the helper.
ERR_API_05 = (
    "Error occurred while {logger_msg}. Armis Centrix rejected the request as "
    "invalid (400)."
)
RES_API_05 = (
    "Ensure that the configuration and action parameters are valid; the "
    "Armis Centrix response is in the log details."
)
ERR_API_06 = (
    "Error occurred while {logger_msg}. Access is forbidden (403)."
)
RES_API_06 = (
    "Ensure that the Armis Centrix user has the required permissions and that "
    "the needed scopes are selected: 'Device Pull' to pull devices, "
    "'Custom Properties Pull' for the custom properties and 'Custom "
    "Actions' for the actions."
)
ERR_API_07 = (
    "Error occurred while {logger_msg}. The Armis Centrix API endpoint was "
    "not found (404)."
)
RES_API_07 = "Ensure that the API Base URL is https://api.armis.com."
ERR_API_08 = (
    "Error occurred while {logger_msg}. Armis Centrix returned status "
    "{status_code}."
)
# Added to the message of an error response when its body has an API message.
MSG_API_MESSAGE = " {text}"
# Data call status -> (message, resolution); other statuses use
# ERR_API_08 with RES_API_03.
API_ERRORS = {
    BAD_REQUEST_STATUS: (ERR_API_05, RES_API_05),
    FORBIDDEN_STATUS: (ERR_API_06, RES_API_06),
    NOT_FOUND_STATUS: (ERR_API_07, RES_API_07),
}

# Error catalogue: E-PUL.
ERR_PUL_01 = "Error occurred while pulling devices."
RES_PUL_01 = (
    "Ensure that the 'Device Pull' scope is selected and granted, and "
    "that the credentials are valid."
)
ERR_PUL_02 = "Error occurred while fetching custom properties."
RES_PUL_02 = (
    "Ensure that the 'Custom Properties Pull' scope is selected and "
    "granted."
)
ERR_PUL_03 = (
    "Error occurred while pulling custom property '{name}'. It no longer "
    "exists in Armis Centrix; it was skipped."
)
RES_PUL_03 = (
    "Ensure that the Custom Properties selection only contains properties "
    "that exist, and update the configuration."
)
ERR_PUL_04 = (
    "Error occurred while processing {count} device(s). They were skipped "
    "because the device ID is missing."
)
RES_PUL_04 = "Ensure that the Armis Centrix devices have a device ID."
ERR_PUL_05 = (
    "Error occurred while pulling records. Entity '{entity}' is not "
    "supported; only 'Devices' is supported."
)
RES_PUL_05 = "Ensure that only the 'Devices' entity is mapped."
ERR_PUL_06 = (
    "Error occurred while pulling devices. Armis Centrix returned an unusable "
    "paging cursor '{next}' after cursor '{after}', hence the pull was "
    "stopped."
)
RES_PUL_06 = (
    "Ensure that the Armis Centrix API is available and returns a valid "
    "'next' cursor, then run the pull again."
)

# Error catalogue: E-ACT.
ERR_ACT_01 = (
    "Error occurred while executing the action. Invalid Device ID "
    "'{value}'."
)
RES_ACT_01 = "Ensure that the Device ID is a whole number."
ERR_ACT_02 = (
    "Error occurred while executing the action. Custom property '{name}' "
    "was not found."
)
RES_ACT_02 = (
    "Ensure that the custom property exists in Armis Centrix, or select "
    "Create new custom property."
)
ERR_ACT_03 = (
    "Error occurred while executing the action. Value '{value}' is not "
    "valid for the {type} custom property '{name}'."
)
RES_ACT_03 = "Ensure that the value matches the type of the custom property."
ERR_ACT_04 = (
    "Error occurred while executing the action. Value '{value}' is not "
    "one of the allowed values of '{name}'."
)
RES_ACT_04 = "Ensure that the value is one of: {allowed_values}."
ERR_ACT_05 = (
    "Error occurred while validating the action. Invalid New Property "
    "Name provided."
)
RES_ACT_05 = (
    "Ensure that the name has at most 40 characters and contains only "
    "letters, digits and underscores."
)
ERR_ACT_06 = (
    "Error occurred while validating the action. Invalid Description "
    "provided."
)
RES_ACT_06 = "Ensure that the description has at most 250 characters."
ERR_ACT_07 = (
    "Error occurred while validating the action. Allowed Values are "
    "required for the enum type."
)
RES_ACT_07 = (
    "Ensure that at least one allowed value is provided, separated by "
    "commas."
)
ERR_ACT_08 = (
    "Error occurred while updating custom property values in batch "
    "{batch}. Armis Centrix rejected {count} value(s); the devices, custom "
    "properties and Armis Centrix errors are in the log details."
)
RES_ACT_08 = (
    "Ensure that the devices exist and the values are valid for the "
    "custom properties."
)
ERR_ACT_09 = (
    "Error occurred while updating {count} custom property value(s) in "
    "Armis Centrix."
)
RES_ACT_09 = (
    "Ensure that the 'Custom Actions' scope is selected and granted, and "
    "that the credentials are valid."
)
ERR_ACT_10 = (
    "Error occurred while creating the custom property '{name}'."
)
RES_ACT_10 = (
    "Ensure that the 'Custom Actions' scope is selected and granted, and "
    "that the property settings are valid."
)
ERR_ACT_12 = (
    "Error occurred while executing the action. The access token does not "
    "include the scope {scope}."
)
RES_ACT_12 = (
    "Ensure that the 'Custom Actions' scope is selected in Scopes and "
    "that the Armis Centrix user has its permissions."
)
ERR_ACT_13 = (
    "Error occurred while validating the action. Unsupported action "
    "'{action}' provided."
)
RES_ACT_13 = (
    "Ensure that 'Set Custom Property Value', 'Remove Custom Property "
    "Value' or 'No action' is selected."
)
ERR_ACT_14 = (
    "Error occurred while validating the action. {field} contains a Source "
    "Field value."
)
RES_ACT_14 = "Ensure that {field} is provided from the Static Field only."
ERR_ACT_15 = (
    "Error occurred while validating the action. Invalid Type provided for "
    "the new custom property."
)
RES_ACT_15 = (
    "Ensure that the Type is one of: string, integer, boolean, enum."
)
ERR_ACT_16 = (
    "Error occurred while updating {count} custom property value(s) in "
    "Armis Centrix. The response did not contain one result per value."
)
RES_ACT_16 = (
    "Ensure that the Armis Centrix API returns one result per requested value."
)
ERR_ACT_20 = (
    "Error occurred while executing the action. {count} action(s) have an "
    "invalid Device ID or Value, hence they were not sent to Armis Centrix."
)
RES_ACT_20 = (
    "Ensure that the Device ID is a whole number and that the Value "
    "matches the type of the custom property."
)
ERR_ACT_21 = (
    "Error occurred while validating the action. The scope(s) {scopes} "
    "are required for the action '{label}'."
)
RES_ACT_21 = (
    "Ensure that {scopes} are selected in the Scopes configuration "
    "parameter."
)
ERR_ACT_22 = (
    "Error occurred while reverting the action '{label}'. Reverting is not "
    "supported, hence {count} record(s) were not sent to Armis Centrix."
)
RES_ACT_22 = (
    "Use the 'Set Custom Property Value' or 'Remove Custom Property Value' "
    "action to change the custom property value instead of reverting."
)
# Raised by execute_action() when its single action failed; the cause
# is logged before.
ERR_SINGLE_ACTION = (
    "Error occurred while {logger_msg}."
)

# Error catalogue: E-GEN.
ERR_GEN_01 = "Error occurred while getting plugin details."
RES_GEN_01 = "Ensure that the plugin manifest.json is valid."
ERR_GEN_02 = (
    "Error occurred while {logger_msg}. Unexpected error: {error}"
)
RES_GEN_02 = (
    "Ensure that the plugin configuration is valid and that Armis Centrix is "
    "reachable, then try again."
)

# Info and debug messages.
VALIDATION_SUCCESS_MESSAGE = (
    "Validation successful for CRE Armis Centrix plugin."
)
ACTION_VALIDATION_SUCCESS_MESSAGE = "Validation successful."
DEBUG_ACTION_VALIDATED = (
    "Successfully validated the action configuration for '{label}'."
)
DEBUG_API_REQUEST = "API request for {logger_msg}. Endpoint: {method} {url}"
DEBUG_API_RESPONSE = (
    "Received API response for {logger_msg}. Status code={status_code}."
)
DEBUG_TOKEN_REUSED = "Reusing the cached access token."
DEBUG_TOKEN_GENERATED = (
    "Generated a new access token valid for {expires_in} second(s)."
)
DEBUG_PROPERTIES_CACHED = (
    "Cached {count} custom property(ies) fetched from Armis Centrix."
)
MSG_RETRY = (
    "Received {reason} while {logger_msg}. Retrying after {wait} "
    "second(s). {remaining} retry(ies) remaining."
)
RETRY_REASON_STATUS = "status code {status_code}"
RETRY_REASON_ERROR = "a {error} error"
MSG_TOKEN_REJECTED = (
    "Received status code 401 while {logger_msg}. Renewing the access "
    "token and repeating the request."
)
MSG_SCOPE_CHECK_SKIPPED = (
    "The granted scopes could not be read from the access token, hence "
    "the scope check was skipped."
)
MSG_CREDENTIALS_MISSING = (
    "The Armis Centrix credentials are not complete, hence the custom "
    "properties were not fetched."
)
MSG_SOURCE_FIELD = (
    "'{field}' contains a Source Field, hence it will be validated while "
    "executing the action."
)
MSG_PULL_START = "Pulling devices from Armis Centrix."
MSG_PAGE_FETCHED = (
    "Successfully fetched {count} device(s) in page {page}. Total "
    "device(s) fetched: {total}."
)
MSG_PULL_COMPLETE = (
    "Successfully pulled {records} record(s) for {devices} device(s) from "
    "Armis Centrix."
)
MSG_GENERATE = (
    "Successfully performed action '{label}' on {count} record(s). No "
    "processing is done by the plugin for this action."
)
MSG_NO_ACTIONS = "No actions to perform."
MSG_ACTION_START = "Executing action '{label}' on {count} record(s)."
MSG_ACTION_SUMMARY = (
    "Successfully performed action '{label}' on {success} record(s) out "
    "of {total}."
)
MSG_ACTION_SUMMARY_FAILED = " Failed for {count} record(s)."
MSG_BULK_CHUNK = (
    "Successfully {verb} {count} custom property value(s) in batch "
    "{batch}."
)
MSG_BULK_CHUNK_FAILED = " Failed for {count} value(s)."
MSG_PROPERTY_CREATED = (
    "Successfully created the custom property '{name}' of type '{type}' "
    "in Armis Centrix."
)
MSG_PROPERTY_EXISTS = (
    "The custom property '{name}' already exists in Armis Centrix, hence it "
    "was not created again."
)
