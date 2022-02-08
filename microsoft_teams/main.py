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
