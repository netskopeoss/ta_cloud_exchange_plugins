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

Halo ITSM Plugin.
"""

import traceback
import json
from typing import List, Dict
from .utils.halo_exceptions import (
    HaloITSMPluginException,
)
from .utils.halo_api_helper import (
    HaloPluginHelper,
)
from .utils.halo_constants import (
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    BASE_URL,
    STATE_MAPPINGS
)

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


class HaloITSMPlugin(PluginBase):
    """HaloITSMPlugin Plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize HaloITSMPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.halo_api_helper = HaloPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = HaloITSMPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth(self, configuration):
        """Validate the Plugin authentication parameters."""
        auth_params = configuration.get("auth", {})

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        tenantname = auth_params.get("tenantname", "").strip()
        if not tenantname:
            err_msg = "Tenant Name is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(tenantname, str):
            err_msg = "Invalid Tenant Name provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        auth_method = auth_params.get("auth_method")
        if not auth_method:
            err_msg = "Authentication Method is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif auth_method not in ['password', 'client_credentials']:
            err_msg = "Invalid value for Authentication Method parameter. Available values are 'Username and Password' and 'Client ID and Secret (Services)'."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_id = auth_params.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return ValidationResult(success=True, message="Validation successful.")

    def _validate_params(self, configuration):
        """Validate the Plugin parameters."""
        params = configuration.get("params", {})
        auth_method = configuration.get("auth", {}).get("auth_method")
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        if auth_method == 'client_credentials':
            client_secret = params.get("client_secret")
            if not client_secret:
                err_msg = "Client Secret is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(client_secret, str):
                err_msg = "Invalid Client Secret provided in configuration parameters."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        elif auth_method == 'password':
            username = params.get("username", "").strip()
            if not username:
                err_msg = "Username is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(username, str):
                err_msg = "Invalid Username provided in configuration parameters."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            password = params.get("password", "")
            if not password:
                err_msg = "Password is a required configuration parameter."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(password, str):
                err_msg = "Invalid Password provided in configuration parameters."
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        return self.validate_auth_params(configuration, validation_err_msg)

    def get_headers(self, configuration):
        """
        Get the headers for the given configuration.

        Parameters:
            configuration (type): Description of the parameter.

        Returns:
            type: Description of the return value.
        """
        token = self.generate_token(configuration, False)
        return self.halo_api_helper._add_user_agent({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def generate_token(self, configuration, is_from_validation):
        """
        Generates a token for authentication.

        Parameters:
            is_from_validation (bool): A flag indicating whether the request is from a validation process.

        Returns:
            str: The generated token.
        """

        headers = self.halo_api_helper._add_user_agent(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
        )

        auth_params = configuration.get("auth", {})
        auth_method = auth_params.get("auth_method")
        params = configuration.get("params", {})
        auth_body = {
            "client_id": auth_params.get("client_id").strip(),
            "grant_type": auth_method,
            "scope": "all",
        }
        if auth_method == 'client_credentials':
            auth_body["client_secret"] = params.get("client_secret")

        elif auth_method == 'password':
            auth_body["username"] = params.get("username").strip()
            auth_body["password"] = params.get("password")

        try:
            response = self.halo_api_helper.api_helper(
                logger_msg="generating a token",
                method="POST",
                url=f"{BASE_URL.format(auth_params.get('tenantname').strip())}/auth/token",
                headers=headers,
                data=auth_body,
                is_validation=is_from_validation,
            )
            if response and response.get("access_token"):
                return response.get("access_token")
            else:
                raise HaloITSMPluginException(
                    "No response received. Token generation failed.")

        except HaloITSMPluginException as err:
            raise err
        except Exception as e:
            raise e

    def validate_auth_params(self, configuration, validation_err_msg):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cto.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            self.generate_token(configuration, is_from_validation=True)
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except HaloITSMPluginException as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Unexpected error occurred. Check logs for more details.",
            )

    def get_fields(self, name: str, configuration: dict):
        """Get configuration fields."""
        fields = []
        if name == "params":
            auth_method = configuration.get("auth", {}).get("auth_method")
            if auth_method == "client_credentials":
                fields.append(
                    {
                        "label": "Client Secret",
                        "key": "client_secret",
                        "type": "password",
                        "default": "",
                        "mandatory": True,
                        "description": "The Client Secret associated with the HaloITSM platform Application."
                    }
                )
            else:
                fields = [
                    {
                        "label": "Username",
                        "key": "username",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": "The Username associated with the HaloITSM account."
                    },
                    {
                        "label": "Password",
                        "key": "password",
                        "type": "password",
                        "default": "",
                        "mandatory": True,
                        "description": "The Password associated with the HaloITSM account."
                    }
                ]
        return fields

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""

        fields = [
            MappingField(
                label="Summary", value="summary",
            ),
            MappingField(
                label="Details", value="details",
            ),
            MappingField(
                label="Category", value="category_1",
            ),
            MappingField(
                label="Impact (CFimpact)", value="CFImpact",
            ),
            MappingField(
                label="Urgency (CFurgency)", value="CFUrgency",
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
                    destination_field="summary",
                    custom_message="Netskope $appCategory alert: $alertName",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="details",
                    custom_message=(
                        "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                        "Alert Type: $alertType\nApp Category: $appCategory\n"
                        "User: $user"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="category_1",
                    custom_message="",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="CFImpact",
                    custom_message="",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="CFUrgency",
                    custom_message="",
                ),
            ],
            "dedup": [],
        }

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an ticket on Halo ITSM platform."""
        try:
            auth_params = self.configuration.get("auth")
            url = f"{BASE_URL.format(auth_params.get('tenantname').strip())}/api/tickets"
            payload = {
                "tickettype_id": 1,
                "summary": mappings.get("summary", ""),
                "details": mappings.get("details", ""),
                "category_1": mappings.get("category_1", ""),
                "customfields": [{
                    "name": "CFUrgency",
                    "value": mappings.get("CFUrgency", ""),
                }, {
                    "name": "CFImpact",
                    "value": mappings.get("CFImpact", ""),
                }]
            }

            if queue and queue.value != "default":
                payload["team"] = queue.value

            response = self.halo_api_helper.api_helper(
                logger_msg=f"creating a Ticket for the Alert ID: {alert.id}",
                url=url,
                method="POST",
                headers=self.get_headers(self.configuration),
                data=json.dumps([payload]),
            )
            ticket_id = response.get('id', "")

            return Task(
                id=f"{ticket_id}",
                status=TaskStatus.NEW,
                link=f"{BASE_URL.format(auth_params.get('tenantname').strip())}/tickets?id={ticket_id}&showmenu=true",
            )

        except (HaloITSMPluginException, Exception) as err:
            self.logger.error(
                message=f"Failed to create a Ticket. Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise err

    def update_task(self, task: Task, alert: Alert, mappings, queue):
        """Return the task as it is."""
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        total_count = 0
        skip_count = 0
        auth_params = self.configuration.get("auth")
        url = f"{BASE_URL.format(auth_params.get('tenantname').strip())}/api/tickets"
        headers = self.get_headers(self.configuration)
        for task in tasks:
            try:
                response = self.halo_api_helper.api_helper(
                    logger_msg=f"syncing state for tasks with ID: {task.id}",
                    url=f"{url}/{task.id}",
                    method="GET",
                    headers=headers,
                )
                if response:
                    task.status = STATE_MAPPINGS.get(
                        response.get("status_id"), TaskStatus.OTHER)
                else:
                    task.status = TaskStatus.DELETED
                total_count += 1
            except (HaloITSMPluginException, Exception) as err:
                self.logger.error(
                    message=f"{self.log_prefix}: Error occurred while syncing a Task. Error: {err}",
                    details=str(traceback.format_exc()),
                )
                skip_count += 1
                continue

        self.logger.info(
            f"{self.log_prefix}: Successfully synced {total_count}, skipped {skip_count} ticket(s) from {PLATFORM_NAME}. "
        )
        return tasks

    def get_queues(self) -> List[Queue]:
        """
        Return a list of Queue objects.
        """
        no_queue_list = [Queue(label="Default Team", value="default")]
        try:
            response = self.halo_api_helper.api_helper(
                logger_msg="fetching list of teams as queues",
                url=f"{BASE_URL.format(self.configuration.get('auth',{}).get('tenantname').strip())}/api/Team",
                method="GET",
                headers=self.get_headers(self.configuration),
            )

            if response and len(response):
                queue_list = list(
                    map(
                        lambda item: Queue(
                            label=item.get("name"),
                            value=item.get("name"),
                        ),
                        response
                    )
                )
                queue_list = no_queue_list + queue_list
                return queue_list
            else:
                return no_queue_list

        except (HaloITSMPluginException, Exception):
            self.logger.info(
                f"{self.log_prefix}: Not able to retrieve 'Teams' as 'Queues' from {PLATFORM_NAME}. This could be either due to insufficient permissions or when selected the 'Client ID and Secret (Services)' Authentication method in the configuration and logged in as a 'Client', accessing the teams API requires an 'Agent' login."
            )
            return no_queue_list
