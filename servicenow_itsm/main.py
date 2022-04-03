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


from typing import List
import requests

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


class ServiceNowPlugin(PluginBase):
    """ServiceNow plugin implementation."""

    def create_task(self, alert, mappings, queue):
        """Create an incident on ServiceNow."""
        values = {**mappings, "assignment_group": queue.value}
        if "sys_id" in values:
            values.pop("sys_id")  # special field; do not allow overriding
        for key, value in list(mappings.items()):
            if type(value) is not str:
                mappings[key] = str(value)
        response = requests.post(
            f"{self.configuration['auth']['url'].strip('/')}/api/now/table/{self.configuration['params']['table']}",
            json=values,
            auth=(
                self.configuration["auth"]["username"].strip(),
                self.configuration["auth"]["password"],
            ),
            proxies=self.proxy,
            headers=add_user_agent(),
        )
        response.raise_for_status()
        if response.status_code == 201:
            result = response.json().get("result")
            return Task(
                id=result.get("sys_id"),
                status=STATE_MAPPINGS.get(
                    result.get("state"), TaskStatus.OTHER
                ),
                link=(
                    f"{self.configuration['auth']['url'].strip('/')}/"
                    f"{self.configuration['params']['table']}.do?sys_id={result.get('sys_id')}"
                ),
            )
        else:
            raise requests.HTTPError(
                "ServiceNow ITSM: Could not create the incident."
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
            response = requests.get(
                (
                    f"{self.configuration['auth']['url'].strip('/')}/api/now/table/task"
                ),
                params={
                    "sysparm_fields": "sys_id,state",
                    "sysparm_query": (f"sys_idIN{','.join(ids)}"),
                },
                auth=(
                    self.configuration["auth"]["username"].strip(),
                    self.configuration["auth"]["password"],
                ),
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            response.raise_for_status()
            results = response.json().get("result", {})
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
        if mappings.get("work_notes", None):
            data = mappings["work_notes"]
        else:
            data = f"New alert received at {str(alert.timestamp)}."
        response = requests.patch(
            (
                f"{self.configuration['auth']['url'].strip('/')}/api/now/table/"
                f"{self.configuration['params']['table']}/{task.id}"
            ),
            json={"work_notes": data},
            auth=(
                self.configuration["auth"]["username"].strip(),
                self.configuration["auth"]["password"],
            ),
            proxies=self.proxy,
            headers=add_user_agent(),
        )
        if response.status_code == 200:
            return task
        elif response.status_code == 404:
            self.logger.info(
                f"ServiceNow ITSM: Incident with sys_id {task.id} no longer exists on ServiceNow."
            )
            return task
        else:
            raise requests.HTTPError(
                f"Could not update the existing incident on ServiceNow with sys_id {task.id}."
            )

    def _validate_auth(self, configuration) -> ValidationResult:
        """Validate authentication step."""
        params = configuration["auth"]
        try:
            response = requests.get(
                f"{params['url'].strip('/')}/api/now/table/incident",
                params={"sysparm_limit": 1},
                auth=(params["username"].strip(), params["password"]),
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            response.raise_for_status()
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except Exception as ex:
            self.logger.error(
                "ServiceNow ITSM: Could not validate authentication credentials."
            )
            self.logger.error(repr(ex))
        return ValidationResult(
            success=False,
            message="Error occurred while validating account credentials.",
        )

    def validate_step(self, name, configuration):
        """Validate a given step."""
        if name == "auth":
            return self._validate_auth(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""
        if configuration["params"]["table"] == "sn_si_incident":
            query = "name=sn_si_incident^ORname=task^internal_type!=collection"
        else:
            query = "name=incident^ORname=task^internal_type!=collection"
        response = requests.get(
            f"{configuration['auth']['url'].strip('/')}/api/now/table/sys_dictionary",
            params={
                "sysparm_query": query,
                "sysparm_fields": "column_label,element",
            },
            auth=(
                configuration["auth"]["username"].strip(),
                configuration["auth"]["password"],
            ),
            proxies=self.proxy,
            headers=add_user_agent(),
        )
        response.raise_for_status()
        if response.status_code == 200:
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
                    response.json().get("result"),
                )
            )
        else:
            raise requests.HTTPError(
                "ServiceNow ITSM: Could not fetch fields from ServiceNow."
            )

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
        response = requests.get(
            f"{self.configuration['auth']['url'].strip('/')}/api/now/table/sys_user_group",
            params={"sysparm_fields": "name,sys_id"},
            auth=(
                self.configuration["auth"]["username"].strip(),
                self.configuration["auth"]["password"],
            ),
            proxies=self.proxy,
            headers=add_user_agent(),
        )
        response.raise_for_status()
        if response.status_code == 200:
            return list(
                map(
                    lambda item: Queue(
                        label=item.get("name"),
                        value=item.get("sys_id"),
                    ),
                    response.json().get("result"),
                )
            )
        else:
            raise requests.HTTPError(
                "ServiceNow ITSM: Could not fetch fields from ServiceNow."
            )
