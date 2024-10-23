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

CTO Microsoft Teams Plugin.
"""

import traceback
import uuid
from copy import deepcopy
from typing import Dict, List
from urllib.parse import urlparse

from netskope.integrations.itsm.models import (
    Alert,
    FieldMapping,
    Queue,
    Task,
    TaskStatus
)
from netskope.integrations.itsm.plugin_base import (
    MappingField,
    PluginBase,
    ValidationResult
)

from .utils.microsoft_teams_constants import (
    MESSAGE_CONTENT,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION
)
from .utils.microsoft_teams_helper import (
    MicrosoftTeamsPluginException,
    MicrosoftTeamsPluginHelper
)


class MicrosoftTeamsPlugin(PluginBase):
    """Microsoft Teams plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.microsoft_teams_helper = MicrosoftTeamsPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MicrosoftTeamsPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            Dict[str, List[FieldMapping]]: Dictionary containing default
            mapping.
        """
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="message",
                    custom_message=(
                        'Alert ID: "$id"\nApp: "$app"\nAlert Name: "$alertName"\n'
                        'Alert Type: "$alertType"\nApp Category: "$appCategory"\nUser: "$user"'
                    ),
                ),
            ],
            "dedup": [],
        }

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the available fields for message notification.

        Args:
            configuration (Dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        return [MappingField(label="Message", value="message")]

    def get_queues(self) -> List[Queue]:
        """Get Queue for Microsoft Teams Queue configuration."""
        return [Queue(label="Notification", value="notification")]

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all tasks states.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        # This plugin has message notification only.
        # Returning tasks as it is.
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing issue.

        Args:
            task (Task): Existing task/ticket created in Tickets page.
            alert (Alert): Alert received from tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        # This plugin has message notification only.
        # Returning tasks as it is.
        return task

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Send message notification to Microsoft Teams platform.

        Args:
            alert (Alert): Alert received from tenant.
            mappings (Dict): Dictionary containing mapped fields.
            queue (Queue): Queue selected in Queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        if "message" not in mappings:
            err_msg = (
                "No message found in Queue Configuration."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} A Custom "
                "Message should be passed against 'Message' "
                "field while configuring the queue."
            )
            raise MicrosoftTeamsPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Sending a message for Alert ID {alert.id}"
            f" to {PLATFORM_NAME}."
        )
        workflow_url = (
            self.configuration.get("params", "").get("workflow_url", "").strip().strip("/")
        )
        message_content = deepcopy(MESSAGE_CONTENT)
        message_content["attachments"][0]["content"]["body"] = [
            {
                "type": "TextBlock",
                "text": f"Message from Netskope CE {MODULE_NAME} {PLATFORM_NAME} plugin",
                "wrap": True,
                "style": "heading",
                "size": "medium",
                "weight": "bolder",
                "isSubtle": True
            },
            {
                "type": "TextBlock",
                "text": mappings["message"],
                "wrap": True
            }
        ]
        try:
            _ = self.microsoft_teams_helper.api_helper(
                url=workflow_url,
                method="POST",
                json=message_content,
                proxies=self.proxy,
                logger_msg=f"sending message for Alert ID {alert.id}",
            )
            task = Task(
                id=uuid.uuid4().hex, status=TaskStatus.NOTIFICATION
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully sent a message "
                f"for Alert ID {alert.id} to {PLATFORM_NAME}."
            )
            return task
        except MicrosoftTeamsPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while sending message "
                f"for Alert ID {alert.id}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftTeamsPluginException(err_msg)

    def _validate_params(self, configuration):
        """Validate plugin configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        params = configuration.get("params", {})
        # Validate workflow URL
        workflow_url = params.get("workflow_url", "").strip().strip("/")
        if not workflow_url:
            err_msg = "Workflow URL is required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            isinstance(workflow_url, str) and self._validate_url(workflow_url)
        ):
            err_msg = "Invalid Workflow URL provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme and parsed.netloc

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step.

        Args:
            name (str): Configuration step name.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        if name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )
