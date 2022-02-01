"""Microsoft Teams ITSM plugin."""
import requests
import uuid
from netskope.common.utils import add_user_agent
from urllib.parse import urlparse


from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    Task,
    TaskStatus,
    Queue,
    FieldMapping,
    Alert,
)
from typing import List, Dict


class MicrosoftPlugin(PluginBase):
    """Microsoft plugin implementation."""

    def get_default_mappings(self, configuration: dict) -> List[FieldMapping]:
        """Get default mappings."""
        return [
            FieldMapping(
                extracted_field="custom_message",
                destination_field="message",
                custom_message=(
                    "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                    "Alert Type: $alertType\nApp Category: $appCategory\nUser: $user"
                ),
            ),
        ]

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the mappable fields."""
        return [MappingField(label="Message", value="message")]

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        return [Queue(label="Notification", value="notification")]

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing issue."""
        return task

    def create_task(self, alert, mappings, queue):
        """Create an Task."""
        if "message" not in mappings:
            raise ValueError("Microsoft Teams: Could not create the task.")
        values = {"text": mappings["message"]}
        try:
            response = requests.post(
                f"{self.configuration['params']['url'].strip()}",
                json=values,
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            response.raise_for_status()
            if response.status_code == 200 and response.text == "1":
                return Task(
                    id=uuid.uuid4().hex, status=TaskStatus.NOTIFICATION
                )
            else:
                raise requests.HTTPError(
                    f"Could not create the task. Status code: {response.status_code}, Response: {response.text}"
                )
        except Exception as e:
            self.logger.error(
                f"Microsoft Teams: Error while sending data to Microsoft Teams: {e}"
            )
            raise

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters."""
        params = configuration["params"]
        if (
            "url" not in params
            or len(params["url"]) == 0
            or not self._validate_url(params["url"])
        ):
            return ValidationResult(
                success=False,
                message="Invalid Webhook URL provided.",
            )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        if name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )
