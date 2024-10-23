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

Azure Service Bus CTO plugin.

"""

import json
import traceback
import uuid


from typing import List, Dict, Tuple

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    Alert,
    TaskStatus,
)
from .utils.constants import (
    PLATFORM_NAME,
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
)

from .lib.azure.servicebus import ServiceBusClient, ServiceBusMessage
from .lib.azure.servicebus.exceptions import (
    ServiceBusError,
    ServiceBusConnectionError,
    ServiceBusAuthenticationError,
)
from .lib.azure.servicebus.management import ServiceBusAdministrationClient
from netskope.common.utils import add_user_agent


class AzureServiceBusPluginException(Exception):
    """Azure Service Bus plugin exception."""

    pass


class AzureServiceBusPlugin(PluginBase):
    """Azure Service Bus plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Azure Service Bus plugin initializer
        Args:
           name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = AzureServiceBusPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )

        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_user_agent(self) -> str:
        """Get User-Agent string.

        Args:
            None
        Returns:
            str: User-Agent string.
        """
        headers = add_user_agent()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        return "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """
        Validate a given configuration step.

        args:
            name: name of the configuration step.
            configuration (dict): Plugin configuration parameters.
        """
        if name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_params(self, configuration):
        """Validate the Plugin parameters."""

        params = configuration.get("params", {})
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        namespace_conn_str = params.get("namespace_conn_str")

        if not namespace_conn_str:
            err_msg = (
                "Namespace connection string is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(namespace_conn_str, str):
            err_msg = (
                "Invalid Namespace connection string provided "
                "in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(namespace_conn_str)

    def list_queues(self, servicebus_mgmt_client):
        """Get list of all the queues in the Azure Service Bus namespace."""
        try:
            queue_list = []
            for queue_properties in servicebus_mgmt_client.list_queues():
                queue_list.append(queue_properties.name)

            return queue_list
        except (
            ServiceBusConnectionError,
            ServiceBusAuthenticationError,
        ) as err:
            err_msg = (
                "An error occurred while establishing connection "
                f"with {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureServiceBusPluginException(str(err_msg))

        except Exception as err:
            err_msg = (
                "An error occurred while establishing connection "
                f"with {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureServiceBusPluginException(str(err_msg))

    def validate_auth_params(self, connection_string):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cto.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            with ServiceBusAdministrationClient.from_connection_string(
                connection_string, user_agent=self._get_user_agent()
            ) as servicebus_mgmt_client:
                self.list_queues(servicebus_mgmt_client)

            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except AzureServiceBusPluginException as err:
            err_msg = "Unable to validate Namespace Connection String."
            if "Failed to establish a new connection" in str(err):
                err_msg = (
                    "Unable to establish a new connection. Verify "
                    "the Namespace Connection String"
                    " provided in configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
        except Exception as err:
            err_msg = "Unable to validate Namespace Connection String."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""

        fields = [
            MappingField(
                label="Message",
                value="message",
            ),
        ]
        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="message",
                    custom_message=(
                        "Alert ID: $id , "
                        "App: $app , "
                        "Alert Name: $alertName , "
                        "Alert Type: $alertType , "
                        "App Category: $appCategory , "
                        "User: $user"
                    ),
                )
            ],
            "dedup": [],
        }

    def get_fields(self, name: str, configuration: dict):
        """Get configuration fields."""
        fields = []
        return fields

    def run(self, payload, queue_name, alert_id):
        """
        Creating a message on Azure Service Bus queue.
        args:
            payload (dict): Alert payload.
            queue_name (str): Queue name on Azure Service Bus.
        """
        try:
            error_log_msg = (
                f"while sending message having Alert ID {alert_id} to Queue "
                f"{queue_name} on {PLATFORM_NAME}."
            )
            params = self.configuration.get("params", {})
            connection_string = params.get("namespace_conn_str")
            string_payload = json.dumps(payload)

            servicebus_client = ServiceBusClient.from_connection_string(
                conn_str=connection_string,
                logging_enable=True,
                user_agent=self._get_user_agent(),
                http_proxy=self.proxy,
            )
            with servicebus_client:
                sender = servicebus_client.get_queue_sender(
                    queue_name=queue_name
                )
                with sender:
                    message = ServiceBusMessage(str(string_payload))
                    sender.send_messages(message)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully sent message with "
                        f"Alert ID {alert_id} to {queue_name} "
                        f"Queue on {PLATFORM_NAME}."
                    )
        except ServiceBusAuthenticationError as err:
            err_msg = (
                f"An authentication error occurred {error_log_msg} "
                f"Verify that the Queue {queue_name} "
                f"is available on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )

            raise AzureServiceBusPluginException(str(err_msg))
        except ServiceBusConnectionError as err:
            err_msg = f"Connection error occurred {error_log_msg}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )

            raise AzureServiceBusPluginException(str(err_msg))
        except ServiceBusError as err:
            err_msg = f"Service Buserror occurred {error_log_msg}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )

            raise AzureServiceBusPluginException(str(err_msg))
        except Exception as err:
            err_msg = f"Unexpected error occurred {error_log_msg}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )

            raise AzureServiceBusPluginException(str(err_msg))

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """
        Creating a message a message and enqueueing it to azure
        service bus queue.

        Args:
            alert (Alert): Alert received from tenant.
            mappings (Dict): Dictionary containing mapped fields.
            queue (Queue): Queue selected in Queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        try:
            queue_name = queue.value.strip()
            self.logger.info(
                f"{self.log_prefix}: Creating a message for Alert ID"
                f" {alert.id} on {PLATFORM_NAME}."
            )
            payload = {
                "message": mappings.get("message", ""),
            }
            self.run(payload, queue_name, alert.id)

            ticket_id = str(uuid.uuid4())
            return Task(
                id=f"{ticket_id}",
                status=TaskStatus.NEW,
            )
        except AzureServiceBusPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Failed to create a message for Alert ID"
                f" {alert.id} on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureServiceBusPluginException(err_msg)

    def update_task(self, task: Task, alert: Alert, mappings, queue):
        """Return the task as it is."""
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Returns the list of task"""
        return tasks

    def get_queues(self) -> List[Queue]:
        """Return a list of Queue objects."""

        try:
            params = self.configuration.get("params", {})
            connection_string = params.get("namespace_conn_str")
            list_of_queues = []
            message_queues = []
            with ServiceBusAdministrationClient.from_connection_string(
                connection_string
            ) as servicebus_mgmt_client:
                list_of_queues = self.list_queues(servicebus_mgmt_client)

            for queue_name in list_of_queues:
                message_queues.append(
                    Queue(label=queue_name, value=queue_name)
                )

            return message_queues
        except AzureServiceBusPluginException:
            raise
        except Exception as err:
            self.logger.error(
                message=f"{self.log_prefix}: Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureServiceBusPluginException(str(err))
