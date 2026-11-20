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

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

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

Asana CTO plugin constants.
"""

PLATFORM_NAME = "Asana"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "1.0.0"

# Retry / rate limit
MAX_RETRIES = 4  # Total attempts, including the first request.
DEFAULT_WAIT_TIME = 60  # Seconds, used when Retry-After is missing.
MAX_WAIT_TIME = 300  # Seconds; a longer Retry-After aborts the call.

# Pagination
PAGE_LIMIT = 100  # Asana accepts 1 to 100.
MAX_PAGES = 100  # Page guard: 100 pages x 100 objects.
# Parts of the 400 message Asana returns for an expired or invalid cursor.
EXPIRED_CURSOR_MESSAGES = (
    "server timed out with your request",
    "pagination token",
)

# Maximum length of an API response in the details of a log
MAX_DETAILS_LENGTH = 2000

# Batch API
BATCH_SIZE = 10  # Maximum number of actions per POST /batch request.

# Comments (stories)
COMMENT_MAX_BYTES = 65400
TRUNCATION_SUFFIX = "... [truncated by Cloud Exchange]"

# Endpoints (relative to the API Base URL)
USERS_ME_ENDPOINT = "/users/me"
WORKSPACES_ENDPOINT = "/workspaces"
WORKSPACE_PROJECTS_ENDPOINT = "/workspaces/{workspace_gid}/projects"
WORKSPACE_CUSTOM_FIELDS_ENDPOINT = "/workspaces/{workspace_gid}/custom_fields"
PROJECT_CUSTOM_FIELD_SETTINGS_ENDPOINT = (
    "/projects/{project_gid}/custom_field_settings"
)
TASKS_ENDPOINT = "/tasks"
TASK_ENDPOINT = "/tasks/{task_gid}"
TASK_STORIES_ENDPOINT = "/tasks/{task_gid}/stories"
BATCH_ENDPOINT = "/batch"

# opt_fields
USERS_ME_OPT_FIELDS = "gid,name,email"
WORKSPACES_OPT_FIELDS = "gid,name"
PROJECTS_OPT_FIELDS = "gid,name"
CUSTOM_FIELD_ATTRIBUTES = [
    "gid",
    "name",
    "resource_subtype",
    "representation_type",
    "is_formula_field",
    "enum_options.gid",
    "enum_options.name",
    "enum_options.enabled",
]
WORKSPACE_CUSTOM_FIELDS_OPT_FIELDS = ",".join(CUSTOM_FIELD_ATTRIBUTES)
PROJECT_CUSTOM_FIELD_SETTINGS_OPT_FIELDS = ",".join(
    f"custom_field.{attribute}" for attribute in CUSTOM_FIELD_ATTRIBUTES
)
TASK_WRITE_OPT_FIELDS = [
    "gid",
    "name",
    "permalink_url",
    "completed",
    "completed_at",
    "assignee.gid",
    "assignee.email",
    "memberships.section.name",
    "memberships.project.gid",
    "custom_fields.gid",
    "custom_fields.name",
    "custom_fields.display_value",
    "custom_fields.enum_value.name",
]
TASK_READ_OPT_FIELDS = [
    "gid",
    "name",
    "completed",
    "completed_at",
    "modified_at",
    "permalink_url",
    "assignee.gid",
    "assignee.email",
    "memberships.project.gid",
    "memberships.section.gid",
    "memberships.section.name",
    "custom_fields.gid",
    "custom_fields.name",
    "custom_fields.display_value",
    "custom_fields.enum_value.name",
]
STORY_OPT_FIELDS = [
    "gid",
    "created_at",
    "created_by.name",
    "resource_subtype",
    "text",
]

# Queue mapping fields
NAME_FIELD = "name"
NOTES_FIELD = "notes"
ASSIGNEE_FIELD = "assignee"
COMMENT_FIELD = "text"
CUSTOM_FIELD_PREFIX = "custom_field:"
WRITABLE_CUSTOM_FIELD_TYPES = {"text", "number", "enum", "multi_enum", "date"}
DATE_FORMAT = "%Y-%m-%d"

# Configuration Parameters with the exact name of the Asana custom fields
# that hold the status and severity. An empty name is not synced.
STATUS_FIELD_KEY = "status_field"
SEVERITY_FIELD_KEY = "severity_field"

# HTTP status code messages
ERROR_REASONS = {
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Resource not found",
    429: "Too Many Requests",
    451: "Unavailable For Legal Reasons",
}

# Explanations added to Asana error messages, keyed by the field name that
# Asana puts before the colon ("assignee: Not a recognized ID: ...").
ASANA_ERROR_HINTS = {
    "assignee": (
        "The Assignee must be the email of a user who is a member of the"
        " Asana workspace."
    ),
    "enum_value": (
        "An enum custom field received a value that is not one of its"
        " options."
    ),
    "multi_enum_values": (
        "A multi-enum custom field received a value that is not one of its"
        " options."
    ),
    "number_value": "A number custom field received a value that is not a"
    " number.",
    "date_value": "A date custom field received a value that is not a date"
    " in the format YYYY-MM-DD.",
    "text_value": "A text custom field received a value that is too long or"
    " not text.",
    "custom_fields": (
        "A custom field in the queue mapping is not a field of the project"
        " or cannot be written."
    ),
    "name": "The Name of the task is missing or too long.",
    "notes": "The Notes of the task are too long or not valid.",
    "projects": (
        "The project selected as the queue does not exist or the user of"
        " the Token cannot add tasks to it."
    ),
    "text": "The comment text is too long or not valid.",
}

# Validation messages (returned in ValidationResult, no log prefix)
VALIDATION_SUCCESS_MESSAGE = (
    "Successfully validated the authentication parameters."
)
VALIDATION_ERROR_MESSAGES = {
    401: (
        "Received exit code 401, Unauthorized. Verify that the Personal"
        " Access Token is valid and has not been revoked."
    ),
    403: (
        "Received exit code 403, Forbidden. The user of the Token does not"
        " have permission to access Asana."
    ),
    404: (
        "Received exit code 404, Resource not found. Verify the API Base URL"
        " provided in the configuration parameters."
    ),
    429: "Received exit code 429, Too Many Requests. Try again later.",
}
VALIDATION_SERVER_ERROR_MESSAGE = (
    "Received exit code {status_code}, HTTP server error occurred."
    " Try again later."
)
VALIDATION_INVALID_RESPONSE_MESSAGE = (
    "Invalid response received from Asana. Verify the API Base URL."
)
# Status codes that stop sync_states, because every following batch would
# fail the same way (token, plan, legal or rate limit errors).
FATAL_STATUS_CODES = (401, 402, 403, 429, 451)
VALIDATION_PROXY_MESSAGE = (
    "Proxy error occurred. Verify the proxy configuration provided in the"
    " Cloud Exchange settings."
)
VALIDATION_TIMEOUT_MESSAGE = (
    "Read timeout error occurred while connecting to Asana. Verify the API"
    " Base URL provided in the configuration parameters and that Asana is"
    " reachable."
)
VALIDATION_CONNECTION_MESSAGE = (
    "Unable to establish connection with Asana. Verify the API Base URL"
    " provided in the configuration parameters."
)

# Resolutions for errors the user can fix
RESOLUTIONS = {
    400: (
        "Ensure that the configuration parameters and the values mapped in"
        " the queue mapping are valid for Asana."
    ),
    401: (
        "Ensure that the Token provided in the configuration is valid and"
        " has not been revoked."
    ),
    402: (
        "Ensure that the Asana workspace has a plan that supports the"
        " requested feature."
    ),
    403: (
        "Ensure that the user of the Token has access to the Asana"
        " workspace, the project and its tasks."
    ),
    404: (
        "Ensure that the API Base URL, the Workspace and the selected"
        " project exist on Asana."
    ),
    451: (
        "Ensure that the network policy of your organization allows access"
        " to Asana."
    ),
}
CONNECTION_RESOLUTION = (
    "Ensure that the API Base URL provided in the configuration is correct"
    " and Asana is reachable from Cloud Exchange."
)
PROXY_RESOLUTION = (
    "Ensure that the proxy configuration of Cloud Exchange is correct."
)
