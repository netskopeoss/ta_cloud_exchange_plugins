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

CRE ServiceNow Plugin constants.
"""
MODULE_NAME = "CRE"
PLATFORM_NAME = "ServiceNow"
PLUGIN_VERSION = "2.0.0"
DEFAULT_WAIT_TIME = 60
# Upper bound (in seconds) on a single rate-limit/server-error backoff,
# so a large 'Retry-After' header cannot stall the plugin.
MAX_WAIT = 60
MAX_API_CALLS = 4
# Per-request timeout (in seconds) passed to requests.request, so a
# hung ServiceNow call cannot block the plugin indefinitely.
DEFAULT_API_TIMEOUT = 300
# How many values are packed into one "<field>IN<v1,v2,...>" filter when
# resolving user emails / user names to sys_ids. Kept well below the
# enrichment chunk size because this filter travels in a plain GET URL
# (not a Batch API body) and the value list is repeated once per
# queried column.
RESOLVE_IN_CHUNK_SIZE = 50
LIMIT = 10000

# Number of sub-requests bundled into one Batch API call by the action
# executors (Group / Role / Delegation / Tag / Share).
SERVICENOW_BATCH_SIZE = 100

# update_records enrichment-sweep sizing. Related rows (user roles,
# groups and delegation; device / application tags) are fetched with a
# "<key>IN<sys_id,...>" filter instead of sweeping the whole table into
# memory: ENRICHMENT_IN_CHUNK_SIZE sys_ids per IN filter, and
# ENRICHMENT_BATCH_SIZE such GET sub-requests per Batch API call.
# ENRICHMENT_SUBREQUEST_LIMIT caps the rows returned per sub-request; a
# sub-request whose result hits the cap is re-fetched with ordinary
# offset pagination, since a batch sub-request cannot paginate itself.
ENRICHMENT_IN_CHUNK_SIZE = 100
ENRICHMENT_BATCH_SIZE = 100
ENRICHMENT_SUBREQUEST_LIMIT = 10000
# Seed used as the outer batch_request_id on every batch call. Each
# call appends its own <entity>-<operation> tag and chunk index, e.g.
# "netskope-ce-group-add-check-1", so ServiceNow-side logs show what
# each batch call was actually doing.
BATCH_REQUEST_ID = "netskope-ce"

# Separator used to pack "<name><CUSTOM_SEPARATOR><sys_id>" into action
# dropdown values, so the sys_id is available at execution time via
# rpartition without an extra lookup API call. Chosen to be extremely
# unlikely to occur in a real group name (matches kolide_ztre).
CUSTOM_SEPARATOR = ")#%(^"
# Sentinel Group dropdown value (Add/Remove User from Group action) that
# means "create a new group" instead of selecting an existing one. It
# never contains CUSTOM_SEPARATOR, so it can't collide with a packed
# "name()sys_id" value.
CREATE_NEW_GROUP = "create_new_group"
# ServiceNow sys_user_group.name column max length.
GROUP_NAME_MAX_LENGTH = 80
# Pre-filled Tag Key on the Manage Device/Application Tags action, so
# tags this plugin writes are identifiable on the configuration item.
DEFAULT_TAG_KEY = "NetskopeCE"
# ServiceNow cmdb_key_value.key column max length.
TAG_KEY_MAX_LENGTH = 254
# Labels for the third outcome in the tag action's stats payload. The
# same bucket means "nothing to do" in both directions, but reads
# differently: an add skipped a tag the item already had, a remove
# found no such tag to delete.
TAG_STATS_ALREADY_EXISTS = "Already Exists"
TAG_STATS_DOES_NOT_EXIST = "Does Not Exist"
# discovery_source stamped on apps created by the new Share action.
# Rows carrying it are dropped while the Applications pull is processed,
# so Cloud Exchange never re-pulls what it pushed (echo prevention).
# Filtered on our side because the server-side
# "discovery_source!=NetskopeCloudExchange" sysparm_query does not
# reliably exclude them.
NETSKOPE_DISCOVERY_SOURCE = "NetskopeCloudExchange"
DISCOVERY_SOURCE_FIELD = "discovery_source"

# sys_id format: 32 lowercase hex characters.
SYS_ID_REGEX = r"^[0-9a-f]{32}$"

# Table API root path (joined as f"{instance_url}{TABLE_API}/...").
TABLE_API = "/api/now/table"

# All endpoint paths are path-only; the full URL is built as
# f"{instance_url}{URLS['KEY']}". Batch sub-request urls are also path-only.
URLS = {
    # entity pulls
    "DEVICES": f"{TABLE_API}/cmdb_ci_computer",
    "USERS": f"{TABLE_API}/sys_user",
    "APPLICATIONS": f"{TABLE_API}/cmdb_ci_business_app",
    # enrichment pulls
    "USER_HAS_ROLE": f"{TABLE_API}/sys_user_has_role",
    "USER_GRMEMBER": f"{TABLE_API}/sys_user_grmember",
    "USER_DELEGATE": f"{TABLE_API}/sys_user_delegate",
    "KEY_VALUE": f"{TABLE_API}/cmdb_key_value",
    # action targets / lookups
    "USER_GROUP": f"{TABLE_API}/sys_user_group",
    "USER_ROLE": f"{TABLE_API}/sys_user_role",
    "SYS_USER": f"{TABLE_API}/sys_user",
    "COMPANY": f"{TABLE_API}/core_company",
    # bulk action transport
    "BATCH": "/api/now/v1/batch",
}

# Tables the plugin reads or writes, checked at configuration time by a
# single Batch API call that asks each table for its first row's sys_id.
# One sub-request per table means a missing table permission is named
# during validation instead of surfacing later as a failed pull or
# action. SYS_USER is omitted as a duplicate of USERS (same table), and
# BATCH is the transport itself, exercised by the outer call.
VALIDATION_TABLE_KEYS = [
    "USERS",
    "DEVICES",
    "APPLICATIONS",
    "USER_HAS_ROLE",
    "USER_GRMEMBER",
    "USER_DELEGATE",
    "KEY_VALUE",
    "USER_GROUP",
    "USER_ROLE",
    "COMPANY",
]

# Entity names.
USERS_ENTITY = "Users"
DEVICES_ENTITY = "Devices"
APPLICATIONS_ENTITY = "Applications"
SUPPORTED_ENTITIES = [USERS_ENTITY, DEVICES_ENTITY, APPLICATIONS_ENTITY]
# How a counted entity is named in every pull-cycle log line. The entity
# names above are plural because that is what the framework passes
# around, but "637 Users record(s)" reads wrong next to "637 User
# record(s)" for the same 637 things - so anything that logs a count
# takes its noun from here instead of from the entity name.
ENTITY_RECORD_LABELS = {
    USERS_ENTITY: "User record(s)",
    DEVICES_ENTITY: "Device record(s)",
    APPLICATIONS_ENTITY: "Application record(s)",
}

# Pull Additional Details (multichoice config) values. The config key is
# still "pull_options", so the constant names below follow the key rather
# than the display label.
PULL_INACTIVE_USERS = "pull_inactive_users"
PULL_USER_ROLES = "pull_user_roles"
PULL_USER_GROUPS = "pull_user_groups"
PULL_USER_DELEGATION = "pull_user_delegation"
PULL_DEVICE_TAGS = "pull_device_tags"
PULL_APPLICATION_TAGS = "pull_application_tags"
PULL_OPTIONS_VALUES = [
    PULL_INACTIVE_USERS,
    PULL_USER_ROLES,
    PULL_USER_GROUPS,
    PULL_USER_DELEGATION,
    PULL_DEVICE_TAGS,
    PULL_APPLICATION_TAGS,
]
# Human-readable labels for the Pull Additional Details values, used in
# "skipped" logs. Kept identical to the choice keys in manifest.json so a
# log line names the option exactly as the UI does - _log_skipped_pull
# lower-cases the label straight into its sentence, so a label must not
# carry a "Pull " prefix.
PULL_OPTION_LABELS = {
    PULL_INACTIVE_USERS: "Inactive Users",
    PULL_USER_ROLES: "User Roles",
    PULL_USER_GROUPS: "User Groups",
    PULL_USER_DELEGATION: "User Delegation",
    PULL_DEVICE_TAGS: "Device Tags",
    PULL_APPLICATION_TAGS: "Application Tags",
}

# Action values.
ACTION_NO_ACTION = "generate"
ACTION_USER_GROUP = "user_group"
ACTION_USER_ROLE = "user_role"
ACTION_USER_DELEGATION = "user_delegation"
ACTION_TAG_DEVICE = "device_tag"
ACTION_TAG_APPLICATION = "application_tag"
ACTION_SHARE_APPLICATION_DATA = "share_app_data"
SUPPORTED_ACTIONS = [
    ACTION_NO_ACTION,
    ACTION_USER_GROUP,
    ACTION_USER_ROLE,
    ACTION_USER_DELEGATION,
    ACTION_TAG_DEVICE,
    ACTION_TAG_APPLICATION,
    ACTION_SHARE_APPLICATION_DATA,
]

# Share Application Data — "Select Table" dropdown (combined action: the
# Core Company path matches the legacy "Share application data"
# behavior, the CMDB CI Business App path matches the newer CMDB CI
# Business App share behavior).
# Rows one Core Company share lookup sub-request may return before the
# executor resumes offset-paging for the rest. A batch sub-request cannot
# paginate itself, so the cap is generous and a truncated sub-request is
# followed up rather than silently accepted.
COMPANY_LOOKUP_SUBREQUEST_LIMIT = 10000

SHARE_TABLE_CORE_COMPANY = "core_company"
SHARE_TABLE_BUSINESS_APP = "cmdb_ci_business_app"
SHARE_TABLE_OPTIONS = [
    {"key": "Core Company", "value": SHARE_TABLE_CORE_COMPANY},
    {"key": "CMDB CI Business App", "value": SHARE_TABLE_BUSINESS_APP},
]

# Add / Remove action type.
ACTION_TYPE_ADD = "add"
ACTION_TYPE_REMOVE = "remove"

# Action-type choices, worded per action so the CE UI reads naturally.
USER_GROUP_ACTION_TYPE_OPTIONS = [
    {"key": "Add to Group", "value": ACTION_TYPE_ADD},
    {"key": "Remove from Group", "value": ACTION_TYPE_REMOVE},
]
USER_ROLE_ACTION_TYPE_OPTIONS = [
    {"key": "Add Role to User", "value": ACTION_TYPE_ADD},
    {"key": "Remove Role from User", "value": ACTION_TYPE_REMOVE},
]
TAG_ACTION_TYPE_OPTIONS = [
    {"key": "Tag", "value": ACTION_TYPE_ADD},
    {"key": "Untag", "value": ACTION_TYPE_REMOVE},
]

# Delegation settings multichoice (Update User Delegation action).
# Selected values are sent to the API as "true"; unselected as "false".
# Selecting nothing means "no settings are delegated", which the action
# carries out by deleting the delegation record.
DELEGATION_APPROVALS = "approvals"
DELEGATION_ASSIGNMENTS = "assignments"
DELEGATION_NOTIFICATIONS = "notifications"
DELEGATION_INVITATIONS = "invitations"
DELEGATION_SETTINGS_VALUES = [
    DELEGATION_APPROVALS,
    DELEGATION_ASSIGNMENTS,
    DELEGATION_NOTIFICATIONS,
    DELEGATION_INVITATIONS,
]
DELEGATION_SETTINGS_OPTIONS = [
    {"key": "Approvals", "value": DELEGATION_APPROVALS},
    {"key": "Assignments", "value": DELEGATION_ASSIGNMENTS},
    {"key": "Notifications", "value": DELEGATION_NOTIFICATIONS},
    {"key": "Invitations", "value": DELEGATION_INVITATIONS},
]

# Whether an existing delegation's end time is extended by Delegation
# Duration when Update User Delegation updates it. Checked only on that
# update path - creating a delegation always sets both times from
# Delegation Duration regardless of this choice, and the start time is
# never touched even when the end time is extended.
DELEGATION_EXTEND_DURATION_YES = "yes"
DELEGATION_EXTEND_DURATION_NO = "no"
DELEGATION_EXTEND_DURATION_OPTIONS = [
    {"key": "Yes", "value": DELEGATION_EXTEND_DURATION_YES},
    {"key": "No", "value": DELEGATION_EXTEND_DURATION_NO},
]

# The three ways Update User Delegation can mutate a delegation. Each
# value doubles as the sub-request's op tag, the key it is counted under
# in the action stats, and the word used for it in the log line.
DELEGATION_OP_CREATED = "created"
DELEGATION_OP_UPDATED = "updated"
DELEGATION_OP_REMOVED = "removed"
DELEGATION_OPS = (
    DELEGATION_OP_CREATED,
    DELEGATION_OP_UPDATED,
    DELEGATION_OP_REMOVED,
)
# Fields read back per delegation so the desired settings can be
# compared against what ServiceNow currently holds.
DELEGATION_LOOKUP_FIELDS = ",".join(
    ["sys_id"] + DELEGATION_SETTINGS_VALUES
)

# Operator options used by Share Application Data's Core Company path.
OPERATOR_OPTIONS = [
    {"key": "AND", "value": "and"},
    {"key": "OR", "value": "or"},
]

# Datetime formats used to parse ServiceNow date / date-time strings.
DATETIME_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]
# Format used for the delegation starts/ends fields and shared summary block.
DELEGATION_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
# Hard upper bound on Delegation Duration: 200 years, in days. Also
# guards the arithmetic - "now + timedelta(days=N)" raises OverflowError
# well before datetime's year-9999 ceiling, and OverflowError is not one
# of the errors the duration parse catches, so an absurd value would
# otherwise escape and fail every action in the bulk request.
DELEGATION_MAX_DURATION_DAYS = 200 * 365

# Parameter-type labels used in validation error messages.
CONFIGURATION = "configuration"
ACTION = "action"

# Validation error message templates.
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = (
    "'{field_name}' is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter "
    "'{field_name}'."
)
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."
INVALID_URL_ERROR_MESSAGE = (
    " Provide a valid URL, for example "
    "'https://instance.service-now.com'."
)
EMPTY_CSV_ERROR_MESSAGE = (
    " Comma-separated values must not contain an empty value."
)
DELEGATION_DURATION_ERROR_MESSAGE = (
    " Value should be a positive whole number of days, up to "
    "{max_days} (200 years)."
)
STATIC_FIELD_ERROR_MESSAGE = (
    "{field_name} contains the Source Field. Please select {field_name} "
    "from the Static Field dropdown only."
)

# Field mappings. Each entry:
#   key       - the sysparm_fields token (flat / dot-walked) to read.
#   type      - one of: string, integer, boolean, datetime.
#   use       - "value" (raw) or "display" (label) under
#               sysparm_display_value=all.
#   fallback  - optional secondary key used when the primary is empty.
# The CE field name (dict key) matches the EntityField name in
# get_entities. Enrichment (LIST / delegation) fields are NOT here - they
# are populated by the update_records fetches.

USER_FIELD_MAPPING = {
    "User ID": {"key": "sys_id", "type": "string", "use": "value"},
    "Email": {"key": "email", "type": "string", "use": "value"},
    "User Name": {"key": "user_name", "type": "string", "use": "value"},
    "Name": {"key": "name", "type": "string", "use": "value"},
    "Failed login attempts": {
        "key": "failed_attempts", "type": "integer", "use": "value"
    },
    "Password needs reset": {
        "key": "password_needs_reset", "type": "boolean", "use": "value"
    },
    "Is Active": {"key": "active", "type": "boolean", "use": "value"},
    "Last login time": {
        "key": "last_login_time", "type": "datetime", "use": "value"
    },
    "VIP": {"key": "vip", "type": "boolean", "use": "value"},
    "Business impact": {
        "key": "business_criticality", "type": "integer", "use": "value"
    },
    "Internal Integration User": {
        "key": "internal_integration_user",
        "type": "boolean",
        "use": "value",
    },
    "Web service access only": {
        "key": "web_service_access_only", "type": "boolean", "use": "value"
    },
    "Identity type": {
        "key": "identity_type", "type": "string", "use": "value"
    },
    "Federated ID": {
        "key": "federated_id", "type": "string", "use": "value"
    },
    "Manager": {"key": "manager.email", "type": "string", "use": "value"},
    "Company": {"key": "company.name", "type": "string", "use": "value"},
    "Department": {
        "key": "department.name", "type": "string", "use": "value"
    },
    "Source": {"key": "source", "type": "string", "use": "value"},
}

DEVICE_FIELD_MAPPING = {
    "Device ID": {"key": "sys_id", "type": "string", "use": "value"},
    "Device Name": {"key": "name", "type": "string", "use": "value"},
    "Serial Number": {
        "key": "serial_number", "type": "string", "use": "value"
    },
    "IP Address": {"key": "ip_address", "type": "string", "use": "value"},
    "MAC Address": {"key": "mac_address", "type": "string", "use": "value"},
    "FQDN": {"key": "fqdn", "type": "string", "use": "value"},
    "DNS Domain": {"key": "dns_domain", "type": "string", "use": "value"},
    "Life Cycle Stage": {
        "key": "life_cycle_stage", "type": "string", "use": "display"
    },
    "Life Cycle Stage Status": {
        "key": "life_cycle_stage_status",
        "type": "string",
        "use": "display",
    },
    "Attested": {"key": "attested", "type": "boolean", "use": "value"},
    "Attestation Status": {
        "key": "attestation_status", "type": "string", "use": "value"
    },
    "Attestation Score": {
        "key": "attestation_score", "type": "integer", "use": "value"
    },
    "Requires verification": {
        "key": "unverified", "type": "boolean", "use": "value"
    },
    "Is Virtual": {"key": "virtual", "type": "boolean", "use": "value"},
    "Fault Count": {
        "key": "fault_count", "type": "integer", "use": "value"
    },
    "Environment": {
        "key": "environment", "type": "string", "use": "value"
    },
    "Discovery Source": {
        "key": "discovery_source", "type": "string", "use": "value"
    },
    "Device Asset Tag": {
        "key": "asset_tag", "type": "string", "use": "value"
    },
    "Assigned To": {
        "key": "assigned_to.email", "type": "string", "use": "value"
    },
    "Managed By": {
        "key": "managed_by", "type": "string", "use": "display"
    },
    "Most Frequent Login User": {
        "key": "most_frequent_user", "type": "string", "use": "display"
    },
    "Owned By": {"key": "owned_by", "type": "string", "use": "display"},
}

APPLICATION_FIELD_MAPPING = {
    "Application ID": {"key": "sys_id", "type": "string", "use": "value"},
    "Application Name": {"key": "name", "type": "string", "use": "value"},
    "Asset Tag": {"key": "asset_tag", "type": "string", "use": "value"},
    "IP Address": {"key": "ip_address", "type": "string", "use": "value"},
    "Description": {
        "key": "short_description", "type": "string", "use": "value"
    },
    "Comments": {"key": "comments", "type": "string", "use": "value"},
    "Application URL": {"key": "url", "type": "string", "use": "value"},
    "Vendor": {"key": "vendor.name", "type": "string", "use": "value"},
    "Manufacturer": {
        "key": "manufacturer.name", "type": "string", "use": "value"
    },
    "Category": {"key": "category", "type": "string", "use": "value"},
    "Subcategory": {
        "key": "subcategory", "type": "string", "use": "value"
    },
    "Business Criticality": {
        "key": "business_criticality", "type": "string", "use": "display"
    },
    "Data Classification": {
        "key": "data_classification", "type": "string", "use": "display"
    },
    "Operational Status": {
        "key": "operational_status", "type": "string", "use": "display"
    },
    "Install Status": {
        "key": "install_status", "type": "string", "use": "display"
    },
    "Life Cycle Stage": {
        "key": "life_cycle_stage.name", "type": "string", "use": "value"
    },
    "Life Cycle Stage Status": {
        "key": "life_cycle_stage_status.name",
        "type": "string",
        "use": "value",
    },
    "Product Support Status": {
        "key": "product_support_status",
        "type": "string",
        "use": "display",
    },
    "Certified": {"key": "certified", "type": "boolean", "use": "value"},
    "Attested": {"key": "attested", "type": "boolean", "use": "value"},
    "Attestation Status": {
        "key": "attestation_status", "type": "string", "use": "value"
    },
    "Attestation Score": {
        "key": "attestation_score", "type": "integer", "use": "value"
    },
    "Environment": {
        "key": "environment", "type": "string", "use": "value"
    },
    "Application Type": {
        "key": "application_type", "type": "string", "use": "display"
    },
    "Next Assessment Date": {
        "key": "next_assessment_date", "type": "datetime", "use": "value"
    },
    "Active": {"key": "active", "type": "boolean", "use": "value"},
    "Owned By": {
        "key": "owned_by.email",
        "type": "string",
        "use": "value",
        "fallback": "owned_by.name",
    },
    "Managed By": {
        "key": "managed_by.email",
        "type": "string",
        "use": "value",
        "fallback": "managed_by.name",
    },
    "IT Application Owner": {
        "key": "it_application_owner.email",
        "type": "string",
        "use": "value",
        "fallback": "it_application_owner.name",
    },
    "Application Portfolio Manager": {
        "key": "application_manager.email",
        "type": "string",
        "use": "value",
        "fallback": "application_manager.name",
    },
    "Support Group": {
        "key": "support_group.name", "type": "string", "use": "value"
    },
    "Company": {"key": "company.name", "type": "string", "use": "value"},
    "User Base": {"key": "user_base", "type": "string", "use": "display"},
    "Active User Count": {
        "key": "active_user_count", "type": "integer", "use": "value"
    },
    "Discovery Source": {
        "key": "discovery_source", "type": "string", "use": "value"
    },
    "Last Updated": {
        "key": "sys_updated_on", "type": "datetime", "use": "value"
    },
}
