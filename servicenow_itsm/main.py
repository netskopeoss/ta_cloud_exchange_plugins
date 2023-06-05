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
"""

"""ServiceNow ITSM plugin."""


from typing import List, Dict
import requests
import os
import json
import time
import traceback
import re
from netskope.common.utils import add_user_agent
from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    TaskStatus,
    Alert,
)


STATE_MAPPINGS = {
    "1": TaskStatus.NEW,
    "2": TaskStatus.IN_PROGRESS,
    "3": TaskStatus.ON_HOLD,
    "7": TaskStatus.CLOSED,
}
MAX_RETRY_COUNT = 4
LIMIT = 1000
PLATFORM_NAME = "ServiceNow"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "1.1.0"
MAIN_ALERT_ATTRS = [
    "id",
    "alertName",
    "alertType",
    "app",
    "appCategory",
    "user",
    "type",
    "timestamp",
]


class ServiceNowException(Exception):
    """ServiceNowException exception class."""

    pass


class ServiceNowPlugin(PluginBase):
    """ServiceNow CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize ServiceNow plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details. Error: {}".format(exp)
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _add_user_agent(self, header=None) -> Dict:
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        header = add_user_agent(header)
        header.update(
            {
                "User-Agent": f"{header.get('User-Agent', 'netskope-ce')}-cto-servicenow-v{self.plugin_version}",
            }
        )
        return header
    
    def substitute_vars(self, message, alert):
        """Replace variables in a string with values from alert."""

        def get_value(match):
            """Resolve variable name."""
            if match.group(1) in MAIN_ALERT_ATTRS:
                return getattr(alert, match.group(1), "value_unavailable")
            else:
                return alert.rawAlert.get(match.group(1), "value_unavailable")

        var_regex = r"(?<!\\)\$([a-zA-Z0-9_]+)"
        return re.sub(
            var_regex,
            lambda match: str(get_value(match)),
            message,
        )

    def map_values(self, alert, mappings):
        """Generate a mapped dictionary based on the given alert and field mappings."""
        result = {}
        for mapping in mappings:
            if mapping.extracted_field not in [None, "custom_message"]:
                if mapping.extracted_field in MAIN_ALERT_ATTRS:
                    result[mapping.destination_field] = getattr(
                        alert, mapping.extracted_field, None
                    )
                else:
                    result[mapping.destination_field] = alert.rawAlert.get(
                        mapping.extracted_field, None
                    )
            else:
                result[mapping.destination_field] = self.substitute_vars(
                    mapping.custom_message, alert
                )
            if result[mapping.destination_field] is None:
                result.pop(mapping.destination_field)
        return result

    def create_task(self, alert, mappings, queue):
        """Create an incident on ServiceNow."""

        if self.configuration.get('params', {}).get('default_mappings', 'no') == "yes":
            mappings_default = self.get_default_mappings(self.configuration)
            mappings_list = mappings_default.get("mappings", [])
            mappings = self.map_values(alert, mappings_list)
        values = (
            mappings
            if queue.value == "no_queue"
            else {**mappings, "assignment_group": queue.value}
        )
        headers = {
            "Content-Type": "application/json",
        }
        if "sys_id" in values:
            values.pop("sys_id")  # special field; do not allow overriding
        for key, value in list(mappings.items()):
            if type(value) is not str:
                mappings[key] = str(value)

        response = self._api_helper(
            lambda: requests.post(
                f"{self.configuration.get('auth', {}).get('url','').strip().strip('/')}/api/now/table/{self.configuration.get('params',{}).get('table','')}",
                json=values,
                auth=(
                    self.configuration.get("auth", {})
                    .get("username", "")
                    .strip(),
                    self.configuration.get("auth", {}).get("password", ""),
                ),
                proxies=self.proxy,
                headers=self._add_user_agent(headers),
            ),
            "creating an incident on {} platform".format(PLATFORM_NAME),
        )

        result = response.get("result", {})
        return Task(
            id=result.get("sys_id"),
            status=STATE_MAPPINGS.get(result.get("state"), TaskStatus.OTHER),
            link=(
                f"{self.configuration.get('auth',{}).get('url','').strip('/')}/"
                f"{self.configuration.get('params',{}).get('table','')}.do?sys_id={result.get('sys_id')}"
            ),
        )

    def sync_states(self, tasks: List[Task]):
        """Sync all task states."""
        sys_ids = [task.id for task in tasks]
        skip, size = 0, 50
        data = {}

        while True:
            ids = sys_ids[skip : skip + size]  # noqa
            if not ids:
                break
            response = self._api_helper(
                lambda: requests.get(
                    (
                        f"{self.configuration.get('auth',{}).get('url','').strip().strip('/')}/api/now/table/task"
                    ),
                    params={
                        "sysparm_fields": "sys_id,state",
                        "sysparm_query": (f"sys_idIN{','.join(ids)}"),
                    },
                    auth=(
                        self.configuration.get("auth", {})
                        .get("username", "")
                        .strip(),
                        self.configuration.get("auth", {}).get("password", ""),
                    ),
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                ),
                "syncing state of tasks",
            )
            results = response.get("result", {})

            for result in results:
                data[result.get("sys_id")] = result.get("state")
            skip += size

        for task in tasks:
            if data.get(task.id):
                task.status = STATE_MAPPINGS.get(
                    data.get(task.id), TaskStatus.OTHER
                )
            else:
                task.status = TaskStatus.DELETED
        return tasks

    def update_task(self, task: Task, alert: Alert, mappings, queue):
        """Update existing task."""
        headers = {
            "Content-Type": "application/json",
        }
        if mappings.get("work_notes", None):
            data = mappings.get("work_notes")
        else:
            data = f"New alert received at {str(alert.timestamp)}."
        response = self._api_helper(
            lambda: requests.patch(
                (
                    f"{self.configuration.get('auth',{}).get('url','').strip().strip('/')}/api/now/table/"
                    f"{self.configuration.get('params',{}).get('table','')}/{task.id}"
                ),
                json={"work_notes": data},
                auth=(
                    self.configuration.get("auth", {})
                    .get("username", "")
                    .strip(),
                    self.configuration.get("auth", {}).get("password", ""),
                ),
                proxies=self.proxy,
                headers=self._add_user_agent(headers),
            ),
            "updating existing task",
            False,
        )
        if response.status_code in [200, 201]:
            return task
        elif response.status_code == 404:
            self.logger.info(
                "{}: Incident with sys_id {} no longer exists on {} platform.".format(
                    self.log_prefix, task.id, PLATFORM_NAME
                )
            )
            return task
        else:
            err_msg = f"Received exit code {response.status_code}, HTTP Error."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise requests.HTTPError(
                "{}: Could not update the existing incident on {} with sys_id {}.".format(
                    self.log_prefix, PLATFORM_NAME, task.id
                )
            )

    def _validate_auth(self, configuration) -> ValidationResult:
        """Validate authentication step."""
        params = configuration.get("auth", {})
        try:
            response = self._api_helper(
                lambda: requests.get(
                    f"{params.get('url','').strip().strip('/')}/api/now/table/incident",
                    params={"sysparm_limit": 1},
                    auth=(
                        params.get("username", "").strip(),
                        params.get("password", ""),
                    ),
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                ),
                "validating configuration parameters",
            )
            if isinstance(response, dict):
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            response.raise_for_status()
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except Exception as ex:
            self.logger.error(
                f"{self.log_prefix}: Could not validate authentication credentials. Error: {ex}",
                details=traceback.format_exc(),
            )
        return ValidationResult(
            success=False,
            message="Error occurred while validating account credentials. Check logs.",
        )

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters."""
        params = configuration.get("params", {})
        if "table" not in params or params.get("table", "") not in [
            "sn_si_incident",
            "incident",
        ]:
            return ValidationResult(
                success=False,
                message="Invalid selection for Destination Table, Valid selections are 'Security Incidents' or 'Incidents'",
            )
        if "default_mappings" not in params or params[
            "default_mappings"
        ] not in ["yes", "no"]:
            return ValidationResult(
                success=False,
                message="Invalid selection for Use Default Mappings, Valid selections are 'Yes' or 'No'",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(self, name, configuration):
        """Validate a given step."""
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""

        if (
            self.configuration.get("params", {}).get("default_mappings", "no")
            == "yes"
        ):
            return []
        query = (
            "name=sn_si_incident^ORname=task^internal_type!=collection"
            if configuration.get("params", {}).get("table", "")
            == "sn_si_incident"
            else "name=incident^ORname=task^internal_type!=collection"
        )
        offset = 0
        fields = []
        while True:
            response = self._api_helper(
                lambda: requests.get(
                    f"{configuration.get('auth',{}).get('url','').strip().strip('/')}/api/now/table/sys_dictionary",
                    params={
                        "sysparm_query": query,
                        "sysparm_fields": "column_label,element",
                        "sysparm_offset": offset,
                        "sysparm_limit": LIMIT,
                    },
                    auth=(
                        self.configuration.get("auth", {})
                        .get("username", "")
                        .strip(),
                        self.configuration.get("auth", {}).get("password", ""),
                    ),
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                ),
                "fetching list of all the available fields",
            )
            offset += LIMIT

            fields.extend(response.get("result", []))

            if len(response.get("result", [])) < LIMIT:
                break

        if fields:
            return list(
                map(
                    lambda item: MappingField(
                        label=item.get("column_label"),
                        value=item.get("element"),
                    )
                    if item.get("element") not in ["work_notes"]
                    else MappingField(
                        label=item.get("column_label"),
                        value=item.get("element"),
                        updateAble=True,
                    ),
                    fields,
                )
            )
        else:
            raise ServiceNowException(
                f"{self.log_prefix}: Could not fetch fields from {PLATFORM_NAME}."
            )

    def get_default_mappings_list(self):
        """Get default mappings."""
        return [
            {
                "extracted_field": "custom_message",
                "destination_field": "short_description",
                "custom_message": "Netskope $appCategory alert: $alertName"
            },
            {
                "extracted_field": "custom_message",
                "destination_field": "description",
                "custom_message": (
                    "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                    "Alert Type: $alertType\nApp Category: $appCategory\nUser: $user"
                ),
            }
        ]

    def get_default_mappings(self, configuration):
        """Get default mappings."""
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="short_description",
                    custom_message="Netskope $appCategory alert: $alertName",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                        "Alert Type: $alertType\nApp Category: $appCategory\nUser: $user"
                    ),
                ),
            ],
            "dedup": [],
        }

    def get_queues(self):
        """Get list of ServiceNow groups as queues."""
        no_queue_list = [Queue(label="No Queue", value="no_queue")]
        offset = 0
        queue = []
        while True:
            response = self._api_helper(
                lambda: requests.get(
                    f"{self.configuration.get('auth',{}).get('url','').strip().strip('/')}/api/now/table/sys_user_group",
                    params={
                        "sysparm_fields": "name,sys_id",
                        "sysparm_limit": LIMIT,
                        "sysparm_offset": offset,
                    },
                    auth=(
                        self.configuration.get("auth", {})
                        .get("username", "")
                        .strip(),
                        self.configuration.get("auth", {}).get("password", ""),
                    ),
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                ),
                "fetching list of {} groups as queues".format(PLATFORM_NAME),
            )
            offset += LIMIT
            queue.extend(response.get("result", []))

            if len(response.get("result", [])) < LIMIT:
                break
        if queue:
            queue_list = list(
                map(
                    lambda item: Queue(
                        label=item.get("name"),
                        value=item.get("sys_id"),
                    ),
                    queue,
                )
            )
            queue_list = no_queue_list + queue_list
            return queue_list
        else:
            raise ServiceNowException(
                "{}: Could not fetch Queues from {} platform.".format(
                    self.log_prefix, PLATFORM_NAME
                )
            )

    def parse_response(self, response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received. "
                "Error: {}".format(err)
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ServiceNowException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise ServiceNowException(err_msg)

    def handle_errors(self, response, request, logger_msg):
        """Handle API Status code errors.

        Args:
            response (Requests response object): Response object of requests.
        """
        for attempt in range(MAX_RETRY_COUNT):
            resp_json = self.parse_response(response)

            if response.status_code in [200, 201]:
                return resp_json
            elif response.status_code == 401:
                err_msg = (
                    "Received exit code {} while {}. Verify"
                    " Username or Password provided in "
                    "configuration parameters.".format(
                        response.status_code, logger_msg
                    )
                )
                resp_err_msg = resp_json.get(
                    "error",
                    {"message": "No error details found in response."},
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(resp_err_msg),
                )
                raise ServiceNowException(err_msg)

            elif response.status_code == 403:
                err_msg = (
                    "Received exit code {}, while {}. This error may"
                    " occur if configured user does not have access"
                    " to perform this operation.".format(
                        response.status_code, logger_msg
                    )
                )
                resp_err_msg = resp_json.get(
                    "error",
                    {"message": "No error details found in response."},
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resp_err_msg),
                )
                raise ServiceNowException(err_msg)

            elif response.status_code == 429 and attempt < MAX_RETRY_COUNT:
                if attempt == MAX_RETRY_COUNT - 1:
                    err_msg = (
                        "Received exit code {}, maximum retry"
                        " limit exceeded for {}".format(
                            response.status_code, logger_msg
                        )
                    )

                    resp_err_msg = resp_json.get(
                        "error",
                        {"message": "No error details found in response."},
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(resp_err_msg),
                    )
                    raise ServiceNowException(err_msg)

                err_msg = (
                    "Received exit code {}, Too Many Requests"
                    " error while {}. Retry count {}.".format(
                        response.status_code, logger_msg, attempt + 1
                    )
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
                time.sleep(int(response.headers.get("Retry-After", 120)))

                response = self._api_helper(request, logger_msg, False)
            elif response.status_code >= 400 and response.status_code < 500:
                err_msg = "Received exit code {} while {}.".format(
                    response.status_code, logger_msg
                )
                resp_err_msg = resp_json.get(
                    "error",
                    {"message": "No error details found in response."},
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(resp_err_msg),
                )
                raise ServiceNowException(err_msg)
            elif (
                response.status_code >= 500
                and response.status_code < 600
                and attempt < MAX_RETRY_COUNT
            ):
                if attempt == MAX_RETRY_COUNT - 1:
                    err_msg = (
                        "Received exit code {}, maximum retry"
                        " limit exceeded for {}".format(
                            response.status_code, logger_msg
                        )
                    )

                    resp_err_msg = resp_json.get(
                        "error",
                        {"message": "No error details found in response."},
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(resp_err_msg),
                    )
                    raise ServiceNowException(
                        "Received exit code {}, HTTP server error "
                        "while {}.".format(response.status_code, logger_msg)
                    )
                err_msg = (
                    "Received exit code {}, HTTP server error "
                    "while {}. Retry count {}.".format(
                        response.status_code, logger_msg, attempt + 1
                    )
                )
                self.logger.warn(f"{self.log_prefix}: {err_msg}")
                time.sleep(60)

                response = self._api_helper(request, logger_msg, False)
            else:
                err_msg = "Received exit code {}, HTTP error while {}.".format(
                    response.status_code, logger_msg
                )
                api_err_msg = resp_json.get(
                    "error",
                    {"message": "No error details found in response."},
                )
                self.logger.error(
                    message="{}: {}".format(self.log_prefix, err_msg),
                    details=str(api_err_msg),
                )
                raise ServiceNowException(err_msg)

    def _api_helper(self, request, logger_msg, is_handle_error_required=True):
        """Helper function for api call."""

        try:
            response = request()
        except requests.exceptions.ProxyError as error:
            err_msg = (
                "ProxyError occurred while {}. Verify proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}. Proxy server or {}"
                " is not reachable. Error: {}".format(
                    PLATFORM_NAME, logger_msg, PLATFORM_NAME, error
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise ServiceNowException(err_msg)
        except requests.exceptions.RequestException as exp:
            err_msg = (
                "Error occurred while requesting"
                " to {} server for {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise ServiceNowException(err_msg)
        except Exception as exp:
            err_msg = (
                "Exception occurred while making API call to"
                " {} server while {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise ServiceNowException(err_msg)
        return (
            self.handle_errors(
                response=response, request=request, logger_msg=logger_msg
            )
            if is_handle_error_required
            else response
        )
