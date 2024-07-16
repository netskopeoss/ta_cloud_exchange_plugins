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

CTO Ivanti plugin package.
"""

import traceback
from typing import List, Dict, Tuple
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


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

from .utils.helper import IvantiPluginException, IvantiPluginHelper
from .utils.constants import (
    PLATFORM_NAME,
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    BATCH_SIZE,
)

STATUS_MAPPING = {
    "Logged": TaskStatus.NEW,
    "Active": TaskStatus.IN_PROGRESS,
    "Waiting for Customer": TaskStatus.ON_HOLD,
    "Waiting for Resolution": TaskStatus.ON_HOLD,
    "Waiting for 3rd Party": TaskStatus.ON_HOLD,
    "Resolved": TaskStatus.OTHER,
    "Closed": TaskStatus.CLOSED,
    "Cancelled": TaskStatus.OTHER,
}


class IvantiPlugin(PluginBase):
    """Ivanti plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Cynet plugin initializer
        Args:
           name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.ivanti_helper = IvantiPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = IvantiPlugin.metadata
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

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an incidents on Ivanti platform.

        Args:
            alert (Alert): Alert received from tenant.
            mappings (Dict): Dictionary containing mapped fields.
            queue (Queue): Queue selected in Queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        auth_params = self.ivanti_helper.get_auth_params(self.configuration)
        tenant_url = auth_params.get("tenant")
        endpoint = f"{tenant_url}/api/odata/businessobject/incidents"
        self.logger.info(
            f"{self.log_prefix}: Creating an incident for Alert ID {alert.id}"
            f" on {PLATFORM_NAME}."
        )
        token = self.ivanti_helper.get_auth_token(auth_params)
        headers = self.ivanti_helper.get_authorization_header(
            auth_method=auth_params.get("auth_method"),
            headers=self.ivanti_helper.get_headers(),
            tenant_url=tenant_url,
            token=token,
        )

        try:
            payload = mappings
            payload["ProfileLink"] = auth_params.get("employee_rec_id")
            resp_json = self.ivanti_helper.api_helper(
                url=endpoint,
                method="POST",
                headers=headers,
                json=payload,
                logger_msg=f"creating incident for Alert ID {alert.id}",
            )
            task = Task(
                id=f"{resp_json.get('IncidentNumber')}|{resp_json.get('RecId')}",  # noqa
                status=(
                    STATUS_MAPPING.get(resp_json.get("Status"), TaskStatus.NEW)
                    if resp_json.get("Status")
                    else TaskStatus.NEW
                ),
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully created an incident "
                f"with ID {resp_json.get('IncidentNumber')} "
                f"for Alert ID {alert.id} on {PLATFORM_NAME}."
            )
            return task
        except IvantiPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while creating incident "
                f"for Alert ID {alert.id}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync States.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(tasks)}"
            f" tickets with {PLATFORM_NAME} incidents."
        )
        auth_params = self.ivanti_helper.get_auth_params(self.configuration)
        tenant_url = auth_params.get("tenant")
        endpoint = f"{tenant_url}/api/odata/businessobject/incidents"
        token = self.ivanti_helper.get_auth_token(auth_params)
        headers = self.ivanti_helper.get_authorization_header(
            auth_method=auth_params.get("auth_method"),
            headers=self.ivanti_helper.get_headers(),
            tenant_url=tenant_url,
            token=token,
        )
        # Create a dictionary for future use.
        task_ids = {str(task.id).split("|")[0]: task for task in tasks}
        task_id_values = list(task_ids.values())
        self.logger.info(
            f"{self.log_prefix}: {len(tasks)} ticket(s) will"
            f" be synced in the batch of {BATCH_SIZE} with {PLATFORM_NAME}."
        )
        page_count = 1
        success_count = 0
        failed_count = 0
        for id in range(0, len(list(task_ids.keys())), BATCH_SIZE):
            page_success_count = 0
            incident_ids = task_id_values[id : id + BATCH_SIZE]  # noqa
            filter = " or ".join(
                [
                    f"IncidentNumber eq {str(id.id).split('|')[0]}"
                    for id in incident_ids
                ]
            )
            try:
                log_msg = (
                    "getting incidents for page "
                    f"{page_count} from {PLATFORM_NAME}"
                )
                resp_json = self.ivanti_helper.api_helper(
                    method="GET",
                    url=endpoint,
                    headers=headers,
                    params={"$filter": filter, "$top": BATCH_SIZE},
                    logger_msg=log_msg,
                )

                for value in resp_json.get("value", []):
                    incident_id = str(value.get("IncidentNumber"))
                    task_ids[incident_id].status = (
                        STATUS_MAPPING.get(value.get("Status"), TaskStatus.NEW)
                        if value.get("Status")
                        else TaskStatus.NEW
                    )
                    success_count += 1
                    page_success_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully synced "
                    f"{page_success_count} ticket(s) in page {page_count}."
                    f" Total ticket(s) synced: {success_count}"
                )
                page_count += 1
            except (IvantiPluginException, Exception) as exp:
                err_msg = (
                    "Error occurred while getting incidents"
                    f" from {PLATFORM_NAME}"
                )
                failed_count += 1
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                    details=str(traceback.format_exc()),
                )
        skip_count = len(tasks) - success_count - failed_count

        log_msg = f"Successfully synced {success_count} ticket(s)"
        if skip_count > 0 or failed_count > 0:
            log_msg = (
                log_msg
                + " and "
                + (
                    f"unable to sync status for {len(tasks)-success_count}"
                    f" ticket(s) with {PLATFORM_NAME} from which "
                    f"{failed_count} ticket(s) were failed and "
                    f"{len(tasks)-success_count-failed_count} ticket(s) were"
                    f" not found on {PLATFORM_NAME}."
                )
            )
        else:
            log_msg = log_msg + f" with {PLATFORM_NAME}."
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing Ivanti issue.

        Args:
            task (Task): Existing task/ticket created in Tickets page.
            alert (Alert): Alert received from tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        try:
            ticket_id, ticket_rec_id = list(str(task.id).split("|"))
        except Exception as exp:
            err_msg = (
                "Unable to find the Incident ID and Record ID"
                f" from the ticket having ID {task.id}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)
        auth_params = self.ivanti_helper.get_auth_params(self.configuration)
        tenant_url = auth_params.get("tenant")
        endpoint = f"{tenant_url}/api/odata/businessobject/incidents('{ticket_rec_id}')"  # noqa
        token = self.ivanti_helper.get_auth_token(auth_params)
        headers = self.ivanti_helper.get_authorization_header(
            auth_method=auth_params.get("auth_method"),
            headers=self.ivanti_helper.get_headers(),
            tenant_url=tenant_url,
            token=token,
        )

        payload = mappings
        try:
            log_msg = f"updating incident having ID {ticket_id}"
            self.ivanti_helper.api_helper(
                method="PATCH",
                url=endpoint,
                headers=headers,
                json=payload,
                logger_msg=log_msg,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated incident having"
                f" ID {ticket_id} on {PLATFORM_NAME}."
            )
            return task
        except IvantiPluginException:
            raise
        except Exception as exp:
            err_msg = f"Error occurred while {log_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)

    def _validate_auth_params(self, configuration: Dict) -> ValidationResult:
        """Validate auth parameters with Ivanti server.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation Result containing status and message.
        """
        try:
            auth_params = self.ivanti_helper.get_auth_params(configuration)
            employee_rec_id = auth_params.get("employee_rec_id")
            tenant_url = auth_params.get("tenant")
            endpoint = f"{tenant_url}/api/odata/businessobject/employees('{employee_rec_id}')"  # noqa
            headers = self.ivanti_helper.get_authorization_header(
                auth_params.get("auth_method"),
                self.ivanti_helper.get_auth_token(auth_params, True),
                tenant_url,
                self.ivanti_helper.get_headers(),
            )
            log_msg = (
                f"connectivity and Employee Record ID with {PLATFORM_NAME}"
            )
            self.ivanti_helper.api_helper(
                method="GET",
                url=endpoint,
                headers=headers,
                logger_msg=f"validating {log_msg}",
                is_handle_error_required=True,
                is_validation=True,
                regenerate_auth_token=False,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully validated {log_msg}."
            )
            return ValidationResult(
                success=True, message=f"Successfully validated {log_msg}"
            )
        except IvantiPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error ocurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} while validating "
                    f"connectivity with Ivanti. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def _validate_auth(self, configuration: Dict) -> ValidationResult:
        """Validate the authentication step."

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        auth_params = configuration.get("auth", {})

        # Validate Ivanti Tenant URL.
        tenant_url = auth_params.get("tenant_url", "").strip().strip("/")
        if not tenant_url:
            err_msg = "Tenant URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            isinstance(tenant_url, str) and self._validate_url(tenant_url)
        ):
            err_msg = (
                "Invalid Tenant URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate authentication method.
        auth_method = auth_params.get("authentication_method")
        if not auth_method:
            err_msg = (
                "Authentication method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif auth_method not in ["basic_auth", "api_key_auth"]:
            err_msg = (
                "Invalid Authentication Method provided in "
                "the configuration parameters. Allowed values are"
                " Basic Authentication and API Key Authentication."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Employee Record ID
        employee_rec_id = auth_params.get("employee_rec_id", "").strip()
        if not employee_rec_id:
            err_msg = (
                "Employee Record ID is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(employee_rec_id, str)):
            err_msg = (
                "Invalid Employee Record ID provided in the"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(
            success=True,
            message="Successfully validated Authentication parameters.",
        )

    def _validate_params(self, configuration: Dict) -> ValidationResult:
        """Validate plugin configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        # Validate authentication method.
        auth_method = configuration.get("auth", {}).get(
            "authentication_method"
        )
        params = configuration.get("params")
        if auth_method == "basic_auth":
            # Validate username.
            username = params.get("username", "").strip()
            if not username:
                err_msg = "Username is a required configuration parameter."
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(username, str)):
                err_msg = (
                    "Invalid Username provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate password.
            password = params.get("password")
            if not password:
                err_msg = "Password is a required configuration parameter."
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(password, str)):
                err_msg = (
                    "Invalid Password provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Ivanti User Role.
            user_role = params.get("user_role", "").strip()
            if not user_role:
                err_msg = (
                    "Ivanti User Role is a required configuration parameter."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(user_role, str)):
                err_msg = (
                    "Invalid Ivanti User Role provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        else:
            # Validate API key.
            api_key = params.get("api_key")
            if not api_key:
                err_msg = "API key is a required configuration parameter."
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(api_key, str)):
                err_msg = (
                    "Invalid API key provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Validate connectivity and Employee Record ID with Ivanti server.
        return self._validate_auth_params(configuration)

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step.

        Args:
            name (str): Configuration name.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _extract_property_names(self, xml_content: str) -> List[str]:
        """Extract property names for mapping from XML API Response.

        Args:
            xml_content (str): XML response API Response.

        Returns:
            List[str]: List of property names.
        """
        try:
            property_names = []
            root = ET.fromstring(xml_content)
            # Initialize the XML parser
            incident_entity = root.find(
                ".//{http://docs.oasis-open.org/odata/ns/edm}EntityType[@Name='incident']"  # noqa
            )
            if incident_entity is not None:
                # Find all Property elements within the incident_entity
                properties = incident_entity.findall(
                    "{http://docs.oasis-open.org/odata/ns/edm}Property"
                )
                # Extract the Name attribute of each Property element
                property_names = [
                    prop.attrib.get("Name")
                    for prop in properties
                    if prop.attrib.get("Name")
                    and all(
                        substring not in str(prop.attrib.get("Name")).lower()
                        for substring in ["valid", "recid"]
                    )
                ]
            return property_names

        except Exception as exp:
            err_msg = (
                "Error occurred while extracting fields from API Response."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)

    def get_fields(self, name: str, configuration: dict):
        """Get configuration fields."""
        fields = []
        if name == "params":
            auth_method = configuration.get("auth", {}).get(
                "authentication_method"
            )
            if auth_method == "basic_auth":
                fields.extend(
                    [
                        {
                            "label": "Username",
                            "key": "username",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": "Username for the Ivanti platform.",
                        },
                        {
                            "label": "Password",
                            "key": "password",
                            "type": "password",
                            "default": "",
                            "mandatory": True,
                            "description": "Password for the Ivanti platform.",
                        },
                        {
                            "label": "Ivanti User Role",
                            "key": "user_role",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "description": (
                                "Internal Role name"
                                " assigned to Ivanti User."
                            ),
                        },
                    ]
                )
            else:
                fields = [
                    {
                        "label": "API Key",
                        "key": "api_key",
                        "type": "password",
                        "default": "",
                        "mandatory": False,
                        "description": (
                            "API Key for Ivanti platform. API Key can be found"
                            " on Settings > Security Controls > API Keys page."
                        ),
                    },
                ]
        return fields

    def get_available_fields(self, configuration: Dict) -> List[MappingField]:
        """Get list of all the available fields for issues/tickets.

        Args:
            configuration (Dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        auth_params = self.ivanti_helper.get_auth_params(configuration)
        tenant_url = auth_params.get("tenant")
        endpoint = f"{tenant_url}/api/odata/incidents/$metadata"
        auth_method = auth_params.get("auth_method")
        token = self.ivanti_helper.get_auth_token(auth_params)
        headers = self.ivanti_helper.get_authorization_header(
            auth_method=auth_method,
            headers={},
            tenant_url=tenant_url,
            token=token,
        )
        try:
            response = self.ivanti_helper.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                logger_msg=f"getting incident fields from {PLATFORM_NAME}",
                is_handle_error_required=False,
            )
            if response.status_code == 200:
                resp_xml = response.text
                fields = self._extract_property_names(resp_xml)
                return list(
                    map(
                        lambda item: (
                            MappingField(
                                label=item, value=item, updateAble=False
                            )
                            if item not in ["NewNotes"]
                            else MappingField(
                                label=item,
                                value=item,
                                updateAble=True,
                            )
                        ),
                        fields,
                    )
                )

            else:
                err_msg = (
                    "Error occurred while getting incident"
                    f" fields from {PLATFORM_NAME}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise IvantiPluginException(err_msg)

        except IvantiPluginException:
            raise
        except Exception as error:
            error_message = "Unexpected error occurred"
            err_msg = (
                f"{error_message} while getting mapping "
                f"fields from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}"
            )
            raise IvantiPluginException(err_msg)

    def get_default_mappings(
        self, configuration: Dict
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
                    destination_field="Subject",
                    custom_message="Netskope $appCategory alert: $alertName",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Symptom",
                    custom_message=(
                        "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                        "Alert Type: $alertType\nApp Category: $appCategory\n"
                        "User: $user"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Status",
                    custom_message="Logged",
                ),
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="NewNotes",
                    custom_message=(
                        "Received new alert with Alert ID: $id and "
                        "Alert Name: $alertName in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_queues(self) -> List[Queue]:
        """Get Queue for Ivanti Queue configuration."""
        return [
            Queue(
                label="Create Incidents",
                value="create_incidents",
            )
        ]
