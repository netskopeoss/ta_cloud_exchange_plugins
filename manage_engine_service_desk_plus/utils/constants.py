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

CTO Manage Engine Service Desk Plus Plugin constants.
"""

MODULE_NAME = "CTO"
PLATFORM_NAME = "Service Desk Plus"
PLUGIN_VERSION = "1.1.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
LIMIT = 50
CLOUD_API_AND_AUTH_URLS = {
    "https://sdpondemand.manageengine.com": "https://accounts.zoho.com/oauth/v2/token",
    "https://sdpondemand.manageengine.eu": "https://accounts.zoho.eu/oauth/v2/token",
    "https://sdpondemand.manageengine.in": "https://accounts.zoho.in/oauth/v2/token",
    "https://servicedeskplus.cn": "	https://accounts.zoho.com.cn/oauth/v2/token",
    "https://servicedeskplus.net.au": "https://accounts.zoho.com.au/oauth/v2/token",
    "https://servicedeskplus.jp": "https://accounts.zoho.jp/oauth/v2/token",
    "https://servicedeskplus.ca": "https://accounts.zohocloud.ca/oauth/v2/token",
    "https://servicedeskplus.uk": "https://accounts.zoho.uk/oauth/v2/token",
    "https://servicedeskplus.sa": "https://accounts.zoho.sa/oauth/v2/token",
}
CLOUD = "cloud"
ON_PREMISE = "onpremise"
PORTAL_FILTER_CLOUD = "/app/{portal_url}"
PORTAL_FILTER_ON_PREMISE = {"PORTALID": None}
GET_ALL_PORTALS_ENDPOINT = "{base_url}/api/v3/portals"
GET_ALL_PROJECTS_ENDPOINT = "{base_url}{portal_filter_cloud}/api/v3/projects"
GET_TASKS_ENDPOINT = "{base_url}{portal_filter_cloud}/api/v3/tasks"
CREATE_PROJECT_TASK = (
    "{base_url}{portal_filter_cloud}/api/v3/projects/{project_id}/tasks"
)
UPDATE_TASK_ENDPOINT = (
    "{base_url}{portal_filter_cloud}/api/v3/projects/{project_id}/tasks/{task_id}"
)
ADD_TASK_COMMENTS_ENDPOINT = "{base_url}{portal_filter_cloud}/api/v3/projects/{project_id}/tasks/{task_id}/comments"
USERS_ENDPOINT_URL = "{base_url}{portal_filter_cloud}/api/v3/users"
TASK_UI_LINK_CLOUD = "{base_url}{portal_filter_cloud}/ui/tasks/{task_id}/details"
TASK_UI_LINK_ON_PREMISE = (
    "{base_url}/ui/tasks?mode=detail&from=showAllTasks&taskId={task_id}"
)
DEFAULT_PAGE_LIMIT = 1000
FETCH_TASK_PAGE_LIMIT = 100
API_RATE_LIMIT_ERROR_MESSAGE_ON_PREMISE = "URL blocked as maximum access limit for the page is exceeded. Please try after sometime."
INPUT_DATA_FOR_GET = {
    "list_info": {
        "row_count": None,
        "start_index": 1,
        "page": 1,
        "sort_field": "created_time",
        "sort_order": "desc",
    }
}
SEARCH_CRITERIA = {
    "field": None,
    "condition": "is",
    "values": [],
}
AVAILABLE_FIELDS = {
    "title": {
        "queue_field_label": "Title",
        "task_field": {"cloud": "title", "onpremise": "title"},
    },
    "description": {
        "queue_field_label": "Description",
        "task_field": {"cloud": "description", "onpremise": "description"},
    },
    "owner": {
        "queue_field_label": "Owner",
        "task_field": {"cloud": "owner.id", "onpremise": "owner.id"},
    },
    "status": {
        "queue_field_label": "Status",
        "task_field": {"cloud": "status.name", "onpremise": "status.name"},
    },
    "priority": {
        "queue_field_label": "Priority",
        "task_field": {"cloud": "priority.name", "onpremise": "priority.name"},
    },
    "task_type": {
        "queue_field_label": "Task Type",
        "task_field": {"cloud": "task_type.name", "onpremise": "type.name"},
    },
    "comment": {
        "queue_field_label": "Comment",
        "task_field": {"cloud": "comment", "onpremise": "comment"},
    },
    "estimated_effort_days": {
        "queue_field_label": "Estimated Effort Days",
        "task_field": {
            "cloud": "estimated_effort_days",
            "onpremise": "estimated_effort.days",
        },
    },
    "estimated_effort_hours": {
        "queue_field_label": "Estimated Effort Hours",
        "task_field": {
            "cloud": "estimated_effort_hours",
            "onpremise": "estimated_effort.hours",
        },
    },
    "estimated_effort_minutes": {
        "queue_field_label": "Estimated Effort Minutes",
        "task_field": {
            "cloud": "estimated_effort_minutes",
            "onpremise": "estimated_effort.minutes",
        },
    },
    "percentage_completion": {
        "queue_field_label": "Percentage Completion",
        "task_field": {
            "cloud": "percentage_completion",
            "onpremise": "percentage_completion",
        },
    },
    "scheduled_start_time": {
        "queue_field_label": "Scheduled Start Time",
        "task_field": {
            "cloud": "scheduled_start_time.value",
            "onpremise": "scheduled_start_time.value",
        },
    },
    "scheduled_end_time": {
        "queue_field_label": "Scheduled End Time",
        "task_field": {
            "cloud": "scheduled_end_time.value",
            "onpremise": "scheduled_end_time.value",
        },
    },
    "actual_start_time": {
        "queue_field_label": "Actual Start Time",
        "task_field": {
            "cloud": "actual_start_time.value",
            "onpremise": "actual_start_time.value",
        },
    },
    "actual_end_time": {
        "queue_field_label": "Actual End Time",
        "task_field": {
            "cloud": "actual_end_time",
            "onpremise": "actual_end_time.value",
        },
    },
    "email_before": {
        "queue_field_label": "Email Before",
        "task_field": {"cloud": "email_before", "onpremise": "email_before"},
    },
    "additional_cost": {
        "queue_field_label": "Additional Cost",
        "task_field": {
            "cloud": "additional_cost",
            "onpremise": "additional_cost",
        },
    },
}
