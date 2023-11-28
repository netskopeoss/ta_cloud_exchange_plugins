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

"""Webhook CTO plugin."""


from typing import List, Dict
import requests
import os
import json
import time
import traceback
import uuid
from urllib.parse import urlparse

from .utils.webhook_helper import (
    WebhookException,
    WebhookPluginHelper
)
from .utils.webhook_constants import (
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MODULE_NAME
)
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


class WebhookPlugin(PluginBase):
    """Webhook CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Webhook plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
            
        self.webhook_helper = WebhookPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

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

    def create_task(self, alert, mappings, queue):
        """Send notification to the webhook."""

        webhook_url = self.configuration.get("params", {}).get("webhook_url", "").strip()
        json_object_str = mappings.get("json_object", "")
        self.logger.debug(
            f"{self.log_prefix} JSON object value: {json_object_str}"
        )
        if not json_object_str:
            self.logger.error(
                f"{self.log_prefix}: No payload found, hence nothing will be sent to the Webhook."
                " A valid JSON value should be passed against 'JSON Object' field while configuring the queue."
            )
            raise WebhookException("No payload found.")
        
        try:
            json_object = json.loads(json_object_str)
            if not isinstance(json_object, dict):
                self.logger.error(
                    f"{self.log_prefix}: Invalid payload found, hence nothing will be sent to the webhook."
                    " A valid JSON dictionary value should be passed against 'JSON Object' field while configuring the queue."
                )
                raise WebhookException("Invalid payload found.")
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Invalid payload found, hence nothing will be sent to the webhook."
                f" A valid JSON value should be passed against 'JSON Object' field while configuring the queue. Error: {e}",
                details=traceback.format_exc()
            )
            raise WebhookException("Invalid payload found.")
        
        resp_json = self.webhook_helper.api_helper(
            url=webhook_url,
            method="POST",
            is_handle_error_required=True,
            logger_msg=(
                "sending data to the Webhook"
            ),
            json=json_object,
            proxies=self.proxy
        )
        
        if resp_json.get("success"):
            return Task(id=uuid.uuid4().hex, status=TaskStatus.NOTIFICATION)
        
        self.logger.error(f"{self.log_prefix}: Error occurred while sending data to the webhook.")
        raise WebhookException("Error occurred while sending data to the webhook.")

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Return the task as it is."""
        return task
    
    def validate_url(self, url):
        """Validate the url"""
        
        if not url:
            message = "Webhook URL is a required parameter."
            return False, message
        parsed_url = urlparse(url)
        message = "Validated Webhook URL successfully."
        if not (parsed_url.scheme and parsed_url.netloc):
            message = "Invalid Webhook URL provided."
            return False, message
        return True, message

    def validate_step(self, name, configuration):
        """Validate a given step."""
        if name != "params":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        webhook_url = configuration.get("params", {}).get("webhook_url", "").strip()
        result, message = self.validate_url(webhook_url)
        if not result:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {message}"
            )
            return ValidationResult(
                success=False,
                message=message
            )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""

        fields = [
            MappingField(
                label="JSON Object", value="json_object"
            )
        ]
        return fields

    def get_default_mappings(self, configuration):
        """Get default mappings."""
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="json_object",
                    custom_message="",
                )
            ],
            "dedup": [],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of queues."""
        return [Queue(label="Notification", value="notification")]