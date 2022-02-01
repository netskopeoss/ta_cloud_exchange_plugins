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
        response = requests.patch(
            (
                f"{self.configuration['auth']['url'].strip('/')}/api/now/table/"
                f"{self.configuration['params']['table']}/{task.id}"
            ),
            json={
                "work_notes": f"New alert received at {str(alert.timestamp)}."
            },
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
        return [
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
        ]

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
