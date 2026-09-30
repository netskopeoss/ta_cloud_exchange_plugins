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

CRE KnowBe4 Plugin constants.
"""

PLATFORM_NAME = "KnowBe4"
MODULE_NAME = "CRE"
PLUGIN_NAME = "KnowBe4"
PLUGIN_VERSION = "2.0.0"

# API call retry behaviour.
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER = 300

# Page sizes. The KnowBe4 GraphQL API accepts a minimum of 25 and a
# maximum that is typically 1000 items per page.
PAGE_SIZE = 100
PIQ_PAGE_SIZE = 100
SECURITY_COACH_PAGE_SIZE = 100

# KnowBe4 caps a single query at 150 complexity points. One aliased
# enrollments block costs 7 points, so 21 blocks is the measured
# ceiling. 10 keeps deliberate headroom below that ceiling.
ENRICHMENT_BATCH_SIZE = 10
# Default user IDs sent to one bulk action mutation ('Group Action
# Batch Size' configuration parameter). KnowBe4 declares no array
# size limit on userAddToGroups/userDeleteMemberships, but the call
# gets slower as the batch grows and hits a gateway timeout (a slow
# 504, not a clean rejection) confirmed against a live tenant around
# 100 users; 95 was the largest batch confirmed to complete.
ACTION_BATCH_SIZE = 50
MIN_ACTION_BATCH_SIZE = 1
MAX_ACTION_BATCH_SIZE = 100
# Page size used by the connectivity check in validate().
AUTH_CHECK_PAGE_SIZE = 1

# Region base URLs, without the '/graphql' path - every KnowBe4
# product (KSAT, PasswordIQ, SecurityCoach) is served by the same host
# for a given region. get_config_params() appends '/graphql' to
# whichever one is selected.
REGION_ENDPOINTS = [
    "https://training.knowbe4.com",
    "https://eu.knowbe4.com",
    "https://ca.knowbe4.com",
    "https://uk.knowbe4.com",
    "https://de.knowbe4.com",
]
# Sentinel 'Base URL' value selecting a user-supplied endpoint via the
# 'Custom Region URL' parameter, instead of one of the fixed
# REGION_ENDPOINTS - future-proofs the plugin against KnowBe4 adding a
# new deployment region without a code change.
REGION_CUSTOM_VALUE = "custom"
ALLOWED_REGION_VALUES = REGION_ENDPOINTS + [REGION_CUSTOM_VALUE]

# Entities.
USERS_ENTITY = "Users"
SUPPORTED_ENTITIES = [USERS_ENTITY]

# Configuration parameter keys. Each key matches its label (lower
# snake_case), per the best-practices page - except CONFIG_REGION,
# see the comment below.
#
# CONFIG_REGION is deliberately NOT "base_url", even though its label
# is "Base URL": the 1.0.0 manifest also used the key "base_url", for
# a REST endpoint (e.g. 'https://us.api.knowbe4.com') incompatible
# with 2.0.0's GraphQL endpoint (e.g. 'https://training.knowbe4.com').
# Reusing that key would make CE treat the 2.0.0 field as the same
# parameter on upgrade and carry the old, incompatible value over -
# the field would then not show up for re-selection in the UI (CE
# thinks nothing changed), and saving the upgraded configuration
# would fail against the new API with the stale host. A new key name
# forces CE to treat 'Base URL' as a new, unset field on upgrade, so
# the admin must pick a valid 2.0.0 value.
CONFIG_REGION = "region_base_url"
CONFIG_CUSTOM_REGION_URL = "custom_region_url"
CONFIG_KSAT_TOKEN = "ksat_api_token"
CONFIG_PULL_ARCHIVED_USERS = "pull_archived_users"
CONFIG_PULL_ADDITIONAL_DETAILS = "pull_additional_details"
CONFIG_PASSWORDIQ_TOKEN = "passwordiq_api_token"
CONFIG_SECURITYCOACH_TOKEN = "securitycoach_api_token"
CONFIG_ACTION_BATCH_SIZE = "group_action_batch_size"

CONFIG_FIELD_LABELS = {
    CONFIG_REGION: "Base URL",
    CONFIG_CUSTOM_REGION_URL: "Custom Region URL",
    CONFIG_KSAT_TOKEN: "KSAT API Token",
    CONFIG_PULL_ARCHIVED_USERS: "Pull Archived Users",
    CONFIG_PULL_ADDITIONAL_DETAILS: "Pull Additional Details",
    CONFIG_PASSWORDIQ_TOKEN: "PasswordIQ API Token",
    CONFIG_SECURITYCOACH_TOKEN: "SecurityCoach API Token",
    CONFIG_ACTION_BATCH_SIZE: "Group Action Batch Size",
}

# Values of the 'Pull Additional Details' multichoice parameter.
# 'custom_fields' uses the KSAT token already required for the base
# pull, so it has no dynamic token field of its own.
DETAIL_PASSWORDIQ = "passwordiq"
DETAIL_SECURITYCOACH = "securitycoach"
DETAIL_CUSTOM_FIELDS = "custom_fields"
ADDITIONAL_DETAIL_VALUES = [
    DETAIL_PASSWORDIQ,
    DETAIL_SECURITYCOACH,
    DETAIL_CUSTOM_FIELDS,
]

# Product names used in log messages.
PRODUCT_KSAT = "KSAT"
PRODUCT_PASSWORDIQ = "PasswordIQ"
PRODUCT_SECURITYCOACH = "SecurityCoach"

# Yes/No choice parameters.
TOGGLE_YES = "Yes"
TOGGLE_NO = "No"
TOGGLE_VALUES = [TOGGLE_YES, TOGGLE_NO]

# UserStatusFilters values used by the base user pull.
USER_STATUS_ACTIVE = "ACTIVE"
USER_STATUS_ALL = "ALL"

# 'User Status' entity field values, derived from the raw 'archived'
# boolean.
FIELD_USER_STATUS_ACTIVE = "Active"
FIELD_USER_STATUS_ARCHIVED = "Archived"

# Parameter type labels used in validation messages.
CONFIGURATION = "configuration"
ACTION = "action"

# Entity field names that the plugin code refers to directly.
FIELD_EMAIL = "User Email"
FIELD_USER_ID = "User ID"
FIELD_GROUPS = "Groups"
FIELD_USER_STATUS = "User Status"
FIELD_RISK_SCORE = "User Current Risk Score"
FIELD_NORMALIZED_SCORE = "Netskope Normalized Score"
FIELD_PAST_DUE_COUNT = "Past Due Training Count"
FIELD_PAST_DUE_NAMES = "Past Due Training Names"
FIELD_PIQ_DETECTIONS = "PasswordIQ Detections"
FIELD_AWARENESS_SCORE = "Awareness Score"
FIELD_ANTI_PHISHING_SCORE = "Anti Phishing Score"
FIELD_PHISHING_REPORT_SCORE = "Phishing Report Score"
FIELD_TRAINING_SCORE = "Training Score"

# Base user pull field mapping. Keys are entity field names, values
# describe where to read them from in the GraphQL User node.
USER_FIELD_MAPPING = {
    FIELD_EMAIL: {"key": "email"},
    FIELD_USER_ID: {"key": "id", "transformation": "string"},
    "First Name": {"key": "firstName"},
    "Last Name": {"key": "lastName"},
    "Display Name": {"key": "displayName"},
    "Employee Number": {"key": "employeeNumber"},
    "Job Title": {"key": "jobTitle"},
    "Department": {"key": "department"},
    "Manager Email": {"key": "managerEmail"},
    FIELD_USER_STATUS: {
        "key": "archived",
        "transformation": "_format_user_status",
    },
    FIELD_GROUPS: {
        "key": "groups",
        "transformation": "_extract_group_names",
    },
    FIELD_RISK_SCORE: {"key": "riskScore"},
    "Phish Prone Percentage": {"key": "currentPpp"},
}

# Custom field API names, as returned by the KnowBe4 API: 4 text
# fields and 2 date fields. Pulled, and added to the base user query,
# only when 'Custom Fields' is selected in 'Pull Additional Details'.
CUSTOM_TEXT_FIELDS = [
    "customField1",
    "customField2",
    "customField3",
    "customField4",
]
CUSTOM_DATE_FIELDS = ["customDate1", "customDate2"]

# Entity field names (Title Case) for the custom fields, mapped to
# their real API key.
CUSTOM_TEXT_FIELD_ENTITY_NAMES = [
    "Custom Field 1",
    "Custom Field 2",
    "Custom Field 3",
    "Custom Field 4",
]
CUSTOM_DATE_FIELD_ENTITY_NAMES = ["Custom Date 1", "Custom Date 2"]
CUSTOM_FIELDS_MAPPING = {
    **{
        entity_name: {"key": api_key}
        for entity_name, api_key in zip(
            CUSTOM_TEXT_FIELD_ENTITY_NAMES, CUSTOM_TEXT_FIELDS
        )
    },
    **{
        entity_name: {"key": api_key, "transformation": "parse_datetime"}
        for entity_name, api_key in zip(
            CUSTOM_DATE_FIELD_ENTITY_NAMES, CUSTOM_DATE_FIELDS
        )
    },
}

# SecurityCoach sub-score field mapping, keyed by entity field name.
SECURITY_COACH_FIELD_MAPPING = {
    FIELD_AWARENESS_SCORE: "awarenessScore",
    FIELD_ANTI_PHISHING_SCORE: "antiPhishingScore",
    FIELD_PHISHING_REPORT_SCORE: "phishingReportScore",
    FIELD_TRAINING_SCORE: "trainingScore",
}

# KnowBe4 SmartRisk score bounds, used by the normalization formula.
MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 100
MIN_NORMALIZED_SCORE = 0
MAX_NORMALIZED_SCORE = 1000


# PasswordIQ / Active Directory violation detection types.
PIQ_DETECTION_WEAK = "AD_PW_WEAK"
PIQ_DETECTION_SHARED = "AD_PW_SHARED"
PIQ_DETECTION_EMPTY = "AD_PW_EMPTY"
PIQ_DETECTION_CLEAR_TEXT = "AD_PW_CLEAR_TEXT"
PIQ_DETECTION_NOT_REQD = "AD_PW_NOT_REQD"
PIQ_DETECTION_NEVER_EXPIRES = "AD_PW_NEVER_EXPIRES"
PIQ_DETECTION_LM_HASH = "AD_USER_USES_LM_HASH"
PIQ_DETECTION_AES_ENCRYPTION_NOT_SET = "AD_USER_AES_ENCRYPTION_NOT_SET"
PIQ_DETECTION_DES_ONLY_ENCRYPTION = "AD_USER_DES_ONLY_ENCRYPTION"
PIQ_DETECTION_HAS_PREAUTHENTICATION = "AD_USER_HAS_PREAUTHENTICATION"
PIQ_DETECTION_FOUND_IN_BREACH = "AD_PW_FOUND_IN_BREACH"
PIQ_DETECTIONS = [
    PIQ_DETECTION_WEAK,
    PIQ_DETECTION_SHARED,
    PIQ_DETECTION_EMPTY,
    PIQ_DETECTION_CLEAR_TEXT,
    PIQ_DETECTION_NOT_REQD,
    PIQ_DETECTION_NEVER_EXPIRES,
    PIQ_DETECTION_LM_HASH,
    PIQ_DETECTION_AES_ENCRYPTION_NOT_SET,
    PIQ_DETECTION_DES_ONLY_ENCRYPTION,
    PIQ_DETECTION_HAS_PREAUTHENTICATION,
    PIQ_DETECTION_FOUND_IN_BREACH,
]
# Human-readable labels for the PasswordIQ Detections field, adapted from the
# field descriptions KnowBe4's own PasswordIQ GraphQL schema documents
# for each detection type (see docs/graphql/passwordiq_schema.graphql,
# type PasswordIqDetectionCounts).
PIQ_DETECTION_LABELS = {
    PIQ_DETECTION_WEAK: "Weak password",
    PIQ_DETECTION_SHARED: "Shared password",
    PIQ_DETECTION_EMPTY: "Empty password",
    PIQ_DETECTION_CLEAR_TEXT: "Password stored in clear text",
    PIQ_DETECTION_NOT_REQD: "No password required",
    PIQ_DETECTION_NEVER_EXPIRES: "Password never expires",
    PIQ_DETECTION_LM_HASH: "Uses LM hash for storing password",
    PIQ_DETECTION_AES_ENCRYPTION_NOT_SET: "AES encryption not set",
    PIQ_DETECTION_DES_ONLY_ENCRYPTION: "Only DES encryption",
    PIQ_DETECTION_HAS_PREAUTHENTICATION: "Preauthentication enabled",
    PIQ_DETECTION_FOUND_IN_BREACH: "Password found in a data breach",
}
PIQ_USER_TYPE = "KMSAT"

# Group and training campaign filters for the action dropdowns.
GROUP_STATUS_ACTIVE = "ACTIVE"
# CONSOLE groups are the only manually manageable type. ADI_MANAGED
# groups are directory synced and SMART groups are criteria based, so
# membership on either cannot be set through the action mutations.
GROUP_TYPE_CONSOLE = "CONSOLE"
TRAINING_CAMPAIGN_STATUSES = ["CREATED", "ENROLLING", "IN_PROGRESS"]

# Actions. Group membership is two separate actions — one per
# direction — rather than a single action with a direction dropdown,
# since removal can never offer the 'create new group' option that
# addition does.
ACTION_ADD_TO_GROUP = "add_to_group"
ACTION_REMOVE_FROM_GROUP = "remove_from_group"
ACTION_ENROLL_TRAINING = "enroll_training"
ACTION_UPDATE_FIELD = "update_field"
ACTION_NO_ACTION = "generate"

SUPPORTED_ACTIONS = [
    ACTION_ADD_TO_GROUP,
    ACTION_REMOVE_FROM_GROUP,
    ACTION_ENROLL_TRAINING,
    ACTION_UPDATE_FIELD,
    ACTION_NO_ACTION,
]

ACTION_LABELS = {
    ACTION_ADD_TO_GROUP: "Add User to Group",
    ACTION_REMOVE_FROM_GROUP: "Remove User from Group",
    ACTION_ENROLL_TRAINING: "Enroll in Training",
    ACTION_UPDATE_FIELD: "Update Custom Field",
    ACTION_NO_ACTION: "No Action",
}

# Actions that can be reverted. Enroll in Training and Update Custom
# Field have no designed inverse and are rejected when a revert is
# requested. Reverting 'Add User to Group' removes the user from the
# group, and reverting 'Remove User from Group' adds the user back to
# it — the plugin flips the direction at execution time rather than
# CE changing the action value itself.
REVERTIBLE_ACTIONS = [ACTION_ADD_TO_GROUP, ACTION_REMOVE_FROM_GROUP]

# Action parameter keys.
PARAM_USER_ID = "user_id"
PARAM_GROUP_ID = "group_id"
PARAM_NEW_GROUP_NAME = "new_group_name"
PARAM_TRAINING_CAMPAIGN_ID = "training_campaign_id"
PARAM_CUSTOM_FIELD_SLOT = "custom_field_slot"
PARAM_CUSTOM_FIELD_VALUE = "custom_field_value"

ACTION_PARAM_LABELS = {
    PARAM_USER_ID: "User ID",
    PARAM_GROUP_ID: "Group",
    PARAM_NEW_GROUP_NAME: "New Group Name",
    PARAM_TRAINING_CAMPAIGN_ID: "Training Campaign",
    PARAM_CUSTOM_FIELD_SLOT: "Custom Field",
    PARAM_CUSTOM_FIELD_VALUE: "Value",
}

# Value of the 'Group' dropdown that creates a new group instead of
# selecting an existing one. Offered only by 'Add User to Group'; a
# newly created group has no members yet, so 'Remove User from Group'
# only ever lists existing groups.
CREATE_NEW_GROUP_VALUE = "create"
CREATE_NEW_GROUP_LABEL = "Create new group"
# KnowBe4's own limit on a group name, confirmed against a live
# tenant: groupCreate rejects a 129-character name with a 'too_long'
# error and accepts 128. No special characters are rejected.
MAX_GROUP_NAME_LENGTH = 128

# Separator packed between a group's ID and name in every other
# 'Group' dropdown choice value, so the name is available for log
# messages during execute_actions without an extra API call to look
# it up. Chosen to be vanishingly unlikely to appear in a real group
# name.
GROUP_VALUE_SEPARATOR = "^#*@$"

# Custom field slots offered by the Update Custom Field action. Only
# the 4 text fields are supported; the 2 date fields have no designed
# write path.
CUSTOM_FIELD_SLOTS = CUSTOM_TEXT_FIELDS
# KnowBe4's own limit on a custom field value, confirmed against a
# live tenant: userEdit rejects a 256-character value with a
# 'too_long' error and accepts 255. No special characters are
# rejected or sanitized.
MAX_CUSTOM_FIELD_VALUE_LENGTH = 255

# Validation and error message templates.
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = (
    "Empty value provided for the '{field_name}' {parameter_type}"
    " parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the '{field_name}' {parameter_type}"
    " parameter."
)
INVALID_VALUE_ERROR_MESSAGE = (
    "Invalid value(s) {invalid_values} provided for the '{field_name}'"
    " {parameter_type} parameter. Allowed values are {allowed_values}."
)
LENGTH_ERROR_MESSAGE = (
    "The '{field_name}' {parameter_type} parameter is longer than"
    " {max_length} characters."
)
RANGE_ERROR_MESSAGE = (
    "Invalid value provided for the '{field_name}' {parameter_type}"
    " parameter. Valid value range is {min_value} to {max_value}."
)
# Shared verbatim with hpe_mist_access_assurance_ztre and
# servicenow_ztre's STATIC_FIELD_ERROR_MESSAGE.
STATIC_FIELD_ERROR_MESSAGE = (
    "{field_name} contains the Source Field. Please select {field_name}"
    " from the Static Field dropdown only."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}. Maximum retries reached while"
    " {logger_msg}."
)
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason} while"
    " {logger_msg}. Retrying after {wait_time} second(s)."
    " {retry_remaining} retries remaining."
)
GRAPHQL_ERROR_MSG = "Error occurred while {logger_msg}."

ERROR_MESSAGE_MAP = {
    400: "Received exit code 400, Bad Request.",
    401: "Received exit code 401, Unauthorized.",
    403: "Received exit code 403, Forbidden.",
    404: "Received exit code 404, Resource not found.",
}
CLIENT_ERROR_MSG = "Received exit code {status_code}, HTTP client error."
SERVER_ERROR_MSG = "Received exit code {status_code}, HTTP server error."
GENERIC_ERROR_MSG = "Received exit code {status_code}, HTTP error."

TOKEN_RESOLUTION_MESSAGE = (
    "Verify the API token(s) and the Region provided in the"
    " configuration parameters."
)
REGION_RESOLUTION_MESSAGE = (
    "Verify the Region provided in the configuration parameters."
)
SERVER_ERROR_RESOLUTION_MESSAGE = (
    "Verify that the KnowBe4 server is reachable and try again later."
)
CLIENT_ERROR_RESOLUTION_MESSAGE = (
    "Verify the configuration parameters provided."
)

RESOLUTION_MESSAGE_MAP = {
    400: CLIENT_ERROR_RESOLUTION_MESSAGE,
    401: TOKEN_RESOLUTION_MESSAGE,
    403: TOKEN_RESOLUTION_MESSAGE,
    404: REGION_RESOLUTION_MESSAGE,
}

# GraphQL documents.
AUTH_CHECK_QUERY = """
query AuthCheck($per: Int, $page: Int) {
  users(per: $per, page: $page) {
    nodes { id }
    pagination { totalCount }
  }
}
"""

USERS_QUERY = """
query Users($per: Int, $page: Int, $status: UserStatusFilters) {
  users(per: $per, page: $page, status: $status) {
    nodes {
      id email firstName lastName displayName employeeNumber jobTitle
      department managerEmail archived riskScore currentPpp
      groups { id name }
    }
    pagination { page pages per totalCount }
  }
}
"""

# Used instead of USERS_QUERY when 'Custom Fields' is selected in
# 'Pull Additional Details'.
USERS_QUERY_WITH_CUSTOM_FIELDS = """
query Users($per: Int, $page: Int, $status: UserStatusFilters) {
  users(per: $per, page: $page, status: $status) {
    nodes {
      id email firstName lastName displayName employeeNumber jobTitle
      department managerEmail archived riskScore currentPpp
      customField1 customField2 customField3 customField4
      customDate1 customDate2
      groups { id name }
    }
    pagination { page pages per totalCount }
  }
}
"""

# One aliased block per user, built at call time by the helper.
ENROLLMENTS_ALIAS_BLOCK = """
  u{index}: enrollments(userId: {user_id}, per: {per}, page: {page}) {{
    nodes {{
      status pastDue
      trainingCampaign {{ name }}
      enrollmentItem {{
        ... on PurchasedCourse {{ title }}
        ... on Policy {{ title }}
        ... on KnowledgeRefresher {{ title }}
      }}
    }}
    pagination {{ totalCount pages }}
  }}
"""

PASSWORDIQ_QUERY = """
query PiqUserStates(
  $detection: [DetectionTypes!]
  $userType: PiqUserTypes
  $pagination: PiqPaginationAttributes!
) {
  passwordIqUserStates(
    detection: $detection, userType: $userType, pagination: $pagination
  ) {
    users {
      id kmsatId
      events { detectionType { name } detected resolved }
    }
    pagination { page pages per totalCount }
  }
}
"""

SECURITY_COACH_QUERY = """
query CoachUsers($search: String!, $draw: Int!, $start: Int!,
                 $length: Int!) {
  securityCoachListMappedUsers(
    search: $search, draw: $draw, start: $start, length: $length
  ) {
    recordsTotal
    data {
      id email awarenessScore antiPhishingScore phishingReportScore
      trainingScore
    }
  }
}
"""

GROUPS_QUERY = """
query Groups($per: Int, $page: Int, $status: GroupStatuses,
             $type: GroupTypes) {
  groups(per: $per, page: $page, status: $status, type: $type) {
    nodes { id name }
    pagination { page pages totalCount }
  }
}
"""

TRAINING_CAMPAIGNS_QUERY = """
query TrainingCampaigns($per: Int, $page: Int,
                        $statuses: [TrainingCampaignStatuses!]) {
  trainingCampaigns(per: $per, page: $page, statuses: $statuses) {
    nodes { id name }
    pagination { page pages totalCount }
  }
}
"""

GROUP_CREATE_MUTATION = """
mutation CreateGroup($attributes: GroupAttributes!) {
  groupCreate(attributes: $attributes) {
    errors { field reason }
    node { id name }
  }
}
"""

ADD_TO_GROUPS_MUTATION = """
mutation AddToGroups($userIds: [Int!]!, $groupIds: [Int!]!) {
  userAddToGroups(userIds: $userIds, groupIds: $groupIds) {
    errors { field reason }
    node { id email }
  }
}
"""

REMOVE_FROM_GROUP_MUTATION = """
mutation RemoveFromGroup($userIds: [Int!]!, $groupId: Int!) {
  userDeleteMemberships(userIds: $userIds, groupId: $groupId) {
    errors { field reason }
    node { id email }
  }
}
"""

ENROLL_USER_MUTATION = """
mutation EnrollUser($trainingCampaignId: Int!, $userId: Int!) {
  trainingCampaignAddUser(
    trainingCampaignId: $trainingCampaignId, userId: $userId
  ) {
    errors { field reason }
    node
  }
}
"""

USER_EDIT_MUTATION = """
mutation EditUser($userId: Int!, $attributes: UserAttributes!) {
  userEdit(userId: $userId, attributes: $attributes) {
    errors { field reason }
    node { id email }
  }
}
"""

# Mutation field names in the GraphQL response body, used by
# _run_bulk_mutation() to dispatch between the two mutations it runs
# on behalf of the group actions. Enroll and Update Custom Field have
# no dispatch need - each is a dedicated method for exactly one
# mutation - so they read their response key as a literal instead.
MUTATION_RESPONSE_KEYS = {
    ACTION_ADD_TO_GROUP: "userAddToGroups",
    ACTION_REMOVE_FROM_GROUP: "userDeleteMemberships",
}
