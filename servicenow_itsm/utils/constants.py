"""
BSD 3-Clause License.

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

ServiceNow ITSM Plugin constants.
"""

MODULE_NAME = "CTO"
PLATFORM_NAME = "ServiceNow"
PLUGIN_VERSION = "2.3.0"

# API request handling
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
MAX_RETRY_AFTER = 300  # Maximum honoured 'Retry-After' value in seconds
LIMIT = 1000  # Page size for paginated dictionary/group lookups
BATCH_SIZE = 50  # Number of tickets fetched per batch during sync
MAX_RESPONSE_DETAILS_LENGTH = 2000  # Max response body length logged

# Destination tables
SECURITY_INCIDENT_TABLE = "sn_si_incident"
INCIDENT_TABLE = "incident"
GRC_ISSUE_TABLE = "sn_grc_issue"
CUSTOM_TABLE = "custom_table"
VALID_TABLES = [
    SECURITY_INCIDENT_TABLE,
    INCIDENT_TABLE,
    GRC_ISSUE_TABLE,
    CUSTOM_TABLE,
]

# Default field names used by the standard ServiceNow tables
DEFAULT_STATUS_FIELD = "state"
DEFAULT_SEVERITY_FIELD = "severity"
DEFAULT_ASSIGNEE_FIELD = "assigned_to"
DEFAULT_ASSIGNMENT_GROUP_FIELD = "assignment_group"
DEFAULT_UPDATE_FIELD = "work_notes"
IMPACT_FIELD = "impact"  # Severity source field for the GRC Issue table

# API endpoints
TABLE_ENDPOINT = "/api/now/table/{table}"
SYS_USER_ENDPOINT = "/api/now/table/sys_user"
SYS_DICTIONARY_ENDPOINT = "/api/now/table/sys_dictionary"
SYS_USER_GROUP_ENDPOINT = "/api/now/table/sys_user_group"

# Fields fetched when resolving a user's manager from the sys_user table
MANAGER_LOOKUP_FIELDS = "name,email,manager.name,manager.email,manager.sys_id"

# Persistent storage key for the sys_id -> email assignee cache.
USER_EMAIL_CACHE_KEY = "user_emails"

MAIN_ATTRS = [
    "id",
    "alertName",
    "alertType",
    "eventType",
    "app",
    "appCategory",
    "user",
    "type",
    "fileType",
    "timestamp",
]

# Virtual mapping field that assigns a ticket to the alert user's manager.
# It is not a real ServiceNow column; the plugin intercepts it at ticket
# creation/update time and injects the resolved manager sys_id.
MANAGER_ASSIGNEE_FIELD = "assigned_to_manager"
MANAGER_ASSIGNEE_LABEL = "Assigned to Manager"

# Configuration parameter keys for the custom table, mapped to their labels.
CUSTOM_TABLE_CONFIG_FIELDS = {
    "custom_table_name": "Custom Table Name",
    "custom_status": "Custom Status",
    "custom_severity": "Custom Severity",
    "custom_assignee": "Custom Assignee",
    "custom_group": "Custom Group",
    "custom_update": "Custom Update",
}
