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

CTO Manage Engine Service Desk Plus plugin.
"""

import traceback
from copy import deepcopy
from typing import Callable, Dict, List, Literal, Tuple, Union
from urllib.parse import urlparse

from netskope.integrations.itsm.models import (
    Alert,
    Event,
    FieldMapping,
    Queue,
    Task,
    TaskStatus,
    UpdatedTaskValues,
    CustomFieldsSectionWithMappings,
    CustomFieldMapping
)
from netskope.integrations.itsm.plugin_base import (
    MappingField,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ADD_TASK_COMMENTS_ENDPOINT,
    AVAILABLE_FIELDS,
    CREATE_PROJECT_TASK,
    CLOUD,
    DEFAULT_PAGE_LIMIT,
    FETCH_TASK_PAGE_LIMIT,
    GET_ALL_PORTALS_ENDPOINT,
    GET_ALL_PROJECTS_ENDPOINT,
    INPUT_DATA_FOR_GET,
    MODULE_NAME,
    ON_PREMISE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PORTAL_FILTER_CLOUD,
    GET_TASKS_ENDPOINT,
    SEARCH_CRITERIA,
    TASK_UI_LINK_CLOUD,
    TASK_UI_LINK_ON_PREMISE,
    USERS_ENDPOINT_URL,
    UPDATE_TASK_ENDPOINT,
)
from .utils.helper import (
    ServiceDeskPluginException,
    ServiceDeskPluginHelper,
    api_ssl_wrapper
)


class ServiceDeskPlugin(PluginBase):
    """Service Desk CTO plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Service Desk Plus plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.servicedesk_helper = ServiceDeskPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ServiceDeskPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _update_task_details(self, task: Task, task_data: dict):
        """Update task fields with data fetched from Service Desk Plus.

        Args:
            task (Task): CE task.
            task_data (dict): Task fetched from Service Desk Plus.
        """
        if task.updatedValues:
            task.updatedValues.oldAssignee = task.dataItem.rawData.get(
                "assignee", None
            )
            task.updatedValues.status = task_data.get(
                "status", TaskStatus.OTHER
            )
        else:
            # Status and Severity are managed from core
            task.updatedValues = UpdatedTaskValues(
                assignee=None,
                oldAssignee=task.dataItem.rawData.get("assignee", None),
            )

        if task_data.get("owner"):
            task.updatedValues.assignee = task_data["owner"]

        task.status = task_data.get("status", TaskStatus.OTHER)
        return task

    def _assign_task_to_owner(
        self, mappings: Dict, create_task_json: Dict, task_json_field: str
    ):
        """Add owner details in task json if owner exists in Service Desk Plus.

        Args:
            mappings (Dict): Mappings containing owner.
            create_task_json (Dict): JSON to be created in Service Desk Plus.
            task_json_field (str): Field in JSON to be created.
        """
        owner_email = mappings.get("owner", "")
        user_data = self._is_user_present_in_storage(
            owner_email
        )
        if not user_data:
            self.logger.info(
                f"{self.log_prefix}: Skipped assigning task to user"
                f" {owner_email}. As user was not found on {PLATFORM_NAME}"
                " platform."
            )
        else:
            self._create_json(
                create_task_json,
                task_json_field,
                user_data.get("id"),
            )

    def _create_json(self, data_dict: Dict, key: str, value) -> Dict:
        """
        Create nested JSON based on the given key and value.

        Args:
            data_dict (Dict): JSON data to be created.
            key (str): Key in the JSON data.
            value: Value for the key in the JSON data.

        Returns:
            Dict: Updated JSON data.
        """
        key_parts = key.split('.')

        if len(key_parts) > 1:
            current_dict = data_dict
            for part in key_parts[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]
            current_dict[key_parts[-1]] = value
        else:
            data_dict[key] = value

    def _create_task_json(self, mappings: Dict):
        """
        Create task JSON based on given mappings.

        Args:
            mappings (Dict): Field mappings.

        Returns:
            Dict: JSON data for creating task.
        """
        create_task_json = {}
        deployment_type = self.configuration.get(
            "sdp_deployment_type"
        ).get("deployment_type")
        for mapping_field, field_value in mappings.items():
            create_task_field = AVAILABLE_FIELDS.get(mapping_field)
            if mapping_field == "owner":
                self._assign_task_to_owner(
                    mappings=mappings,
                    create_task_json=create_task_json,
                    task_json_field=create_task_field["task_field"][
                        deployment_type
                    ]
                )
            else:
                self._create_json(
                    create_task_json,
                    create_task_field["task_field"][deployment_type],
                    field_value,
                )

        return {"task": create_task_json}

    def create_task(self, alert, mappings: Dict, queue: Queue) -> Task:
        """Create a task on Service Desk Plus platform.

        Args:
            alert (Alert/Event): Alert/Event object.
            mappings (Dict): Field mappings.
            queue (Queue): Queue object.

        Returns:
            Task: Task object.
        """
        if not mappings:
            err_msg = "No mappings found in Queue Configuration."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Queue mapping "
                f"is required to create a task on {PLATFORM_NAME}."
            )
            raise ServiceDeskPluginException(err_msg)
        if "title" not in mappings:
            err_msg = (
                f"Title field is required to create a task on {PLATFORM_NAME}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            raise ServiceDeskPluginException(err_msg)

        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"

        logger_message = (
            f"a task for {event_type} ID '{alert.id}' on {PLATFORM_NAME}"
            " platform"
        )
        self.logger.info(f"{self.log_prefix}: Creating {logger_message}.")

        project_id = queue.value
        comment_while_create = None
        task_json = self._create_task_json(mappings=mappings)
        if task_json.get("task", {}).get("comment"):
            comment_while_create = task_json.get("task", {}).pop("comment")
        task_id, status, ui_link, owner = self._create_project_task(
            project_id=project_id,
            project_name=queue.label,
            task_details=task_json,
            deployment_type=self.servicedesk_helper.get_deployment_type(
                configuration=self.configuration
            )
        )
        if comment_while_create:
            success = self._add_comment_in_task(
                project_id=project_id,
                task_id=task_id,
                comment=comment_while_create,
                deployment_type=self.servicedesk_helper.get_deployment_type(
                    configuration=self.configuration
                )
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully added comment for"
                    f" newly created task {task_id}."
                )
        temp_status = status if status else TaskStatus.OTHER
        task = Task(
            id=task_id,
            status=temp_status,
            link=ui_link,
            dataItem=alert
        )
        task = self._update_task_details(
            task=task,
            task_data={
                "status": status, "owner": owner
            }
        )
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync States.

        Args:
            tasks (List[Task]): Task list received from Core.

        Returns:
            List[Task]: Task List with updated status.
        """
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(tasks)} "
            f"task(s) with {PLATFORM_NAME}."
        )
        task_ids = [task.id for task in tasks]
        fetched_tasks = self._fetch_tasks(
            task_id_list=task_ids,
            deployment_type=self.servicedesk_helper.get_deployment_type(
                configuration=self.configuration
            ),
        )

        for task in tasks:
            if fetched_tasks.get(task.id, ""):
                task = self._update_task_details(
                    task, fetched_tasks.get(task.id)
                )
            else:
                if (
                    task.updatedValues.status
                    and task.updatedValues.status != TaskStatus.DELETED
                ):
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        task.updatedValues.status,
                        TaskStatus.DELETED,
                    )
                else:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        TaskStatus.DELETED,
                        TaskStatus.DELETED,
                    )
                task.status = TaskStatus.DELETED
        self.logger.info(
            f"{self.log_prefix}: Successfully synced "
            f"{len(tasks)} task(s) with the {PLATFORM_NAME}."
        )
        return tasks

    def update_task(
        self,
        task: Task,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
        upsert_task=False,
    ) -> Task:
        """Add a comment in existing Service Desk Task.

        Args:
            task (Task): Existing task/ticket created in Tickets page.
            alert (Union[Alert, Event]): Alert or Event received from tenant.
            mappings (Dict): Dictionary of the mapped fields.
            queue (Queue): Selected queue configuration.

        Returns:
            Task: Task containing ticket ID and status.
        """
        event_type = "Alert"
        if "eventType" in alert.model_dump():
            event_type = "Event"

        if mappings.get("comment", None):
            comment_data = mappings.pop("comment")
        else:
            comment_data = (
                f"New {event_type.lower()} with ID '{alert.id}' received "
                f"at {str(alert.timestamp)}."
            )
        project_id = queue.value
        deployment_type = self.servicedesk_helper.get_deployment_type(
            configuration=self.configuration
        )
        if upsert_task:
            try:
                task_json = self._create_task_json(mappings=mappings)
                self._update_project_task(
                    project_id=project_id,
                    task_id=task.id,
                    task_details=task_json,
                    deployment_type=deployment_type
                )
            except ServiceDeskPluginException:
                raise
            except Exception as exp:
                err_msg = f"Error occurred while updating task {task.id}."
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                )
                raise ServiceDeskPluginException(err_msg)

        try:
            success = self._add_comment_in_task(
                project_id=project_id,
                task_id=task.id,
                comment=comment_data,
                deployment_type=deployment_type
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully added comment in"
                    f" task {task.id}"
                )
                return task
            else:
                if task.updatedValues.status and (
                    task.updatedValues.status != TaskStatus.DELETED
                ):
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        task.updatedValues.status, TaskStatus.DELETED
                    )
                else:
                    task.updatedValues.oldStatus, task.updatedValues.status = (
                        TaskStatus.DELETED, TaskStatus.DELETED
                    )
                task.status = TaskStatus.DELETED
                self.logger.info(
                    f"{self.log_prefix}: Task with ID '{task.id}' "
                    f"no longer exists on {PLATFORM_NAME} platform."
                )
                return task
        except ServiceDeskPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while adding comment in task"
                f" {task.id}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

    def _get_storage(self) -> Dict:
        """
        Returns the storage dictionary.

        If the storage is not initialized, it will be initialized to an
        empty dictionary.

        Returns:
            Dict: The storage dictionary.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def _get_api_url(
        self,
        base_url: str,
        endpoint: str,
        deployment_type: Literal["cloud", "onpremise"],
        **kwargs,
    ) -> str:
        """
        Construct the API URL for a given endpoint and instance type.

        Args:
            base_url (str): The base URL of the API
            endpoint (str): The endpoint to construct the URL for
            deployment_type (str): The deployment type, either "cloud" or
                "onpremise"
            **kwargs: Additional keyword arguments to pass to the endpoint
                format string. The following are supported:
                    project_id (str): The ID of the project
                    task_id (str): The ID of the task

        Returns:
            str: The constructed API URL
        """
        if deployment_type == CLOUD:
            *_, portal_url = self.servicedesk_helper.get_configuration_params(
                self.configuration, CLOUD
            )
            url = endpoint.format(
                base_url=base_url,
                portal_filter_cloud=PORTAL_FILTER_CLOUD.format(
                    portal_url=portal_url
                ),
                project_id=kwargs.get("project_id"),
                task_id=kwargs.get("task_id"),
            )
        elif deployment_type == ON_PREMISE:
            url = endpoint.format(
                base_url=base_url,
                portal_filter_cloud="",
                project_id=kwargs.get("project_id"),
                task_id=kwargs.get("task_id")
            )
        return url

    def _get_query_param(
        self,
        page_limit: int,
        search_field: str = None,
        search_value: List[str] = None,
        fields_required: List[str] = None,
        portal_filter: str = None,
    ) -> Dict[str, Union[Dict, str]]:
        """
        Construct the query parameters for a given page limit and search
        criteria.

        Args:
            page_limit (int): The page limit for the query
            search_field (str): The field to search on
            search_value (List[str]): The values to search for
            fields_required (List[str]): The fields to return in response
            portal_filter (str): The portal filter. Only applicable for
                deployment type On Premise

        Returns:
            Dict: The query parameters as a dictionary
        """
        input_data = deepcopy(INPUT_DATA_FOR_GET)
        input_data["list_info"]["row_count"] = page_limit
        if fields_required:
            input_data["list_info"]["fields_required"] = fields_required
        if search_field and search_value:
            search_criteria = deepcopy(SEARCH_CRITERIA)
            search_criteria["field"] = search_field
            search_criteria["values"] = search_value
            input_data["list_info"]["search_criteria"] = [search_criteria]
        if portal_filter:
            # Portal filter will only be populated when Deployment
            # Type = On premise
            return {
                "input_data": input_data,
                "PORTALID": portal_filter,
            }
        else:
            return {"input_data": input_data}

    def _get_base_url_and_auth_headers(self) -> Tuple[
        Dict, str, Literal["cloud", "onpremise"]
    ]:
        """
        Get the base URL and the authentication headers from the configuration
        parameters and storage.


        Returns:
            Tuple: The headers, base_url and deployment_type as a tuple
        """
        deployment_type = self.configuration.get(
            "sdp_deployment_type", {}
        ).get("deployment_type", "")
        (
            base_url, auth_token, *_
        ) = self.servicedesk_helper.get_configuration_params(
            configuration=self.configuration,
            deployment_type=deployment_type
        )
        if deployment_type == ON_PREMISE:
            headers = self.servicedesk_helper.get_auth_headers(
                token=auth_token, deployment_type=deployment_type
            )
        elif deployment_type == CLOUD:
            auth_token = self._get_storage().get("access_token")
            headers = self.servicedesk_helper.get_auth_headers(
                token=auth_token, deployment_type=deployment_type
            )
        return headers, base_url, deployment_type

    def _is_user_present_in_storage(
        self, user_email_id: str
    ) -> Union[Dict, None]:
        """
        Checks if the given user email id is present in storage.
        If not, fetches all users and then checks again.
        If the user is still not present, returns None.

        Args:
            user_email_id (str): The user email id to search for

        Returns:
            Union[Dict, None]: The user details as a dictionary if
                the user is present in storage, else None
        """
        storage = self._get_storage()
        if user_email_id in storage.get("users", {}):
            return storage["users"][user_email_id]
        else:
            self._fetch_all_users(
                deployment_type=self.servicedesk_helper.get_deployment_type(
                    configuration=self.configuration
                )
            )
            if user_email_id in storage.get("users", {}):
                return storage["users"][user_email_id]
            else:
                return None

    @api_ssl_wrapper
    def _fetch_all_users(
        self,
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ):
        """
        Fetches all users from the ManageEngine ServiceDesk platform.

        Fetches all the users from the ManageEngine ServiceDesk platform
        and stores them in the storage. The storage is updated with
        the user details in the format of
        {
            "users": {
                "user_email_id": {
                    "id": "user_id",
                    "status": "user_status"
                }
            }
        }
        The function returns nothing.

        Args:
            deployment_type (Literal["cloud", "onpremise"]): The deployment
                type of the ManageEngine ServiceDesk platform.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to None.

        Raises:
            ServiceDeskPluginException: If any unexpected error occurs
                while fetching the users.
        """
        storage = self._get_storage()
        logger_msg_base = (
            "fetching users for page {page_number} from"
            " {platform_name} platform"
        )
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        fetch_users_url = self._get_api_url(
            base_url=base_url,
            endpoint=USERS_ENDPOINT_URL,
            deployment_type=deployment_type,
        )
        query_params = self._get_query_param(
            page_limit=DEFAULT_PAGE_LIMIT,
            fields_required=["email_id", "id", "status", "name"],
            portal_filter=(
                storage.get("portal_id")
            ) if deployment_type == ON_PREMISE else None
        )

        # Using offset and limit for pagination instead of page number
        # as on premise Users API endpoint does not support page number
        query_params["input_data"]["list_info"].pop("page", None)

        # Empty users dict in storage as we will fetch
        # all the users again
        storage.update({"users": {}})
        users_dict = {}
        page_number = 1
        has_more_rows = True
        try:
            while has_more_rows:
                logger_msg = logger_msg_base.format(
                    page_number=page_number,
                    platform_name=PLATFORM_NAME,
                )
                response = self.servicedesk_helper.api_helper(
                    logger_msg=logger_msg,
                    url=fetch_users_url,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=verify,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    is_validation=False,
                    deployment_type=deployment_type,
                    configuration=self.configuration,
                    storage=storage,
                )
                users_response = response.get("users", [])
                for user in users_response:
                    email_id = user.get("email_id")
                    if email_id:
                        users_dict[email_id] = {
                            "id": user.get("id"),
                            "status": user.get("status", "")
                        }
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(users_response)} users for page"
                    f" {page_number} from {PLATFORM_NAME} platform."
                )
                has_more_rows = response.get(
                    "list_info", {}
                ).get("has_more_rows")
                # Using offset and limit for pagination
                query_params["input_data"]["list_info"][
                    "start_index"
                ] += DEFAULT_PAGE_LIMIT
                page_number += 1
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)
        storage.update(
            {
                "users": users_dict
            }
        )

    @api_ssl_wrapper
    def _fetch_projects(
        self,
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ) -> Dict[str, str]:
        """
        Fetches all projects from ManageEngine ServiceDesk Plus.

        Args:
            deployment_type (Literal["cloud", "onpremise"]): The deployment
                type of the ManageEngine ServiceDesk Plus instance.
            verify (bool, optional): Whether or not to verify the SSL
                certificate of the ManageEngine ServiceDesk Plus instance.
                Defaults to None.

        Returns:
            Dict: A dictionary where the keys are the display names
                of the projects and the values are the IDs of the projects.
        """
        storage = self._get_storage()
        logger_msg_base = (
            "fetching projects for page {page_number} from"
            " {platform_name} platform as queues"
        )
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        get_projects_url = self._get_api_url(
            base_url=base_url,
            endpoint=GET_ALL_PROJECTS_ENDPOINT,
            deployment_type=deployment_type,
        )
        query_params = self._get_query_param(
            page_limit=DEFAULT_PAGE_LIMIT,
            fields_required=[
                "title",
                "id",
                "code",
                "display_id",
                "project_code"
            ],
            portal_filter=(
                storage.get("portal_id")
            ) if deployment_type == ON_PREMISE else None
        )
        projects_dict = {}
        has_more_rows = True
        try:
            while has_more_rows:
                logger_msg = logger_msg_base.format(
                    page_number=query_params["input_data"]["list_info"][
                        "page"
                    ],
                    platform_name=PLATFORM_NAME,
                )
                response = self.servicedesk_helper.api_helper(
                    logger_msg=logger_msg,
                    url=get_projects_url,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=verify,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    is_validation=False,
                    deployment_type=deployment_type,
                    configuration=self.configuration,
                    storage=storage,
                )
                projects_response = response.get("projects", [])
                for project in projects_response:
                    project_title = project.get("title")
                    if deployment_type == ON_PREMISE:
                        queue_display_name = project_title
                    elif deployment_type == CLOUD:
                        project_code = project.get("display_id", {}).get(
                            "display_value", ""
                        )
                        queue_display_name = f"{project_code}: {project_title}"
                    projects_dict[queue_display_name] = project.get("id")
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(projects_response)} project(s) for page"
                    f" {query_params['input_data']['list_info']['page']}"
                    f" from {PLATFORM_NAME} platform."
                )
                has_more_rows = response.get(
                    "list_info", {}
                ).get("has_more_rows")
                query_params["input_data"]["list_info"]["page"] += 1
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

        return projects_dict

    @api_ssl_wrapper
    def _fetch_tasks(
        self,
        task_id_list: List[str],
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ) -> Dict:
        """
        Fetches tasks from ServiceDesk using the given list of task IDs

        Args:
            task_id_list (List[str]): A list of task IDs to fetch.
            deployment_type (Literal["cloud", "onpremise"]): The deployment
                type of the ServiceDesk instance.
            verify (bool, optional): Whether to verify the SSL certificate of
                the ServiceDesk instance. Defaults to None.

        Returns:
            Dict: A dictionary containing the task details, with the task ID
                as the key.
        """
        storage = self._get_storage()
        logger_msg_base = (
            "fetching tasks for page {page_number} from"
            " {platform_name} platform"
        )
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        get_tasks_url = self._get_api_url(
            base_url=base_url,
            endpoint=GET_TASKS_ENDPOINT,
            deployment_type=deployment_type,
        )
        query_params = self._get_query_param(
            page_limit=FETCH_TASK_PAGE_LIMIT,
            search_field="id",
            search_value=["temp_value"],
            fields_required=[
                "title",
                "id",
                "project",
                "status",
                "priority",
                "description",
                "owner"
            ],
            portal_filter=(
                storage.get("portal_id")
            ) if deployment_type == ON_PREMISE else None
        )
        task_dict = {}
        try:
            page_number = 1
            for start in range(0, len(task_id_list), FETCH_TASK_PAGE_LIMIT):
                logger_msg = logger_msg_base.format(
                    page_number=page_number,
                    platform_name=PLATFORM_NAME,
                )
                query_params["input_data"]["list_info"][
                    "search_criteria"
                ][0]["values"] = task_id_list[
                    start:start + FETCH_TASK_PAGE_LIMIT
                ]
                response = self.servicedesk_helper.api_helper(
                    logger_msg=logger_msg,
                    url=get_tasks_url,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=verify,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    is_validation=False,
                    deployment_type=deployment_type,
                    configuration=self.configuration,
                    storage=storage,
                )
                tasks_response = response.get("tasks", [])
                for task in tasks_response:
                    temp_task_dict = {}
                    task_id = task.get("id")
                    owner_details = task.get("owner", {})
                    temp_task_dict["id"] = task_id
                    temp_task_dict["title"] = task.get("title")
                    temp_task_dict["description"] = task.get("description")
                    temp_task_dict["project"] = task.get("project", {})
                    if owner_details:
                        temp_task_dict["owner"] = owner_details.get(
                            "email_id", owner_details.get("name")
                        )
                    if task.get("priority", {}):
                        temp_task_dict["priority"] = task.get(
                            "priority", {}
                        ).get("name")
                    if task.get("status", {}):
                        temp_task_dict["status"] = (
                            task.get("status", {}).get("name")
                        )
                    task_dict[task_id] = temp_task_dict
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(tasks_response)} task for page"
                    f" {page_number} from {PLATFORM_NAME} platform."
                )
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

        return task_dict

    @api_ssl_wrapper
    def _create_project_task(
        self,
        project_id: str,
        project_name: str,
        task_details: Dict,
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ) -> Tuple:
        """
        This function creates a new task in a project on the ManageEngine
        ServiceDesk Plus.

        Args:
            project_id (str): The ID of the project in which the task is to be
                created.
            project_name (str): The name of the project in which the task is to
                be created.
            task_details (Dict): A dictionary containing the details of the
                task to be created.
            deployment_type (Literal["cloud", "onpremise"]): Whether the task
                is to be created on a cloud or on-premise server.
            verify (bool, optional): Whether to verify the SSL certificate of
                the server. Defaults to None.

        Returns:
            Tuple: A tuple containing the ID of the task created, the status
                of the task, the UI link of the task and the owner of the task.
        """
        storage = self._get_storage()
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        create_task_url = self._get_api_url(
            base_url=base_url,
            endpoint=CREATE_PROJECT_TASK,
            deployment_type=deployment_type,
            project_id=project_id,
        )
        request_body = {"input_data": task_details}
        query_params = {}
        if deployment_type == ON_PREMISE:
            query_params = {"PORTALID": storage.get("portal_id")}
        logger_msg = (
            f"creating task in project '{project_name}' on {PLATFORM_NAME}"
            " platform"
        )
        try:
            response = self.servicedesk_helper.api_helper(
                logger_msg=logger_msg,
                url=create_task_url,
                method="POST",
                headers=headers,
                data=request_body,
                params=query_params,
                verify=verify,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=False,
                deployment_type=deployment_type,
                configuration=self.configuration,
                storage=storage,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully created task for project"
                f" '{project_name}'."
            )
            created_task_details = response.get("task", {})
            task_id = created_task_details.get("id")
            if deployment_type == CLOUD:
                ui_link = self._get_api_url(
                    base_url=base_url,
                    endpoint=TASK_UI_LINK_CLOUD,
                    deployment_type=deployment_type,
                    task_id=task_id,
                )
            elif deployment_type == ON_PREMISE:
                ui_link = self._get_api_url(
                    base_url=base_url,
                    endpoint=TASK_UI_LINK_ON_PREMISE,
                    deployment_type=ON_PREMISE,
                    task_id=task_id,
                )
            status = created_task_details.get("status", "")
            if status:
                status = status.get("name", "other")
            owner = created_task_details.get("owner", "")
            if owner:
                owner = owner.get("email_id", "")
            return task_id, status, ui_link, owner
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

    @api_ssl_wrapper
    def _update_project_task(
        self,
        project_id: str,
        task_id: str,
        task_details: Dict,
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ) -> None:
        """
        This function is used to update a task in ManageEngine ServiceDesk
        Plus.

        Args:
            project_id (str): The ID of the project in which the task is
                present.
            task_id (str): The ID of the task to be updated.
            task_details (Dict): A dictionary containing the task details.
            deployment_type (Literal["cloud", "onpremise"]): Whether the task
                is to be created on a cloud or on-premise server.
            verify (bool, optional): Whether to verify the SSL certificate of
                the server. Defaults to None.

        Returns:
            None

        Raises:
            ServiceDeskPluginException: If any error occurs while updating the
                task.
        """
        storage = self._get_storage()
        logger_msg = f"updating task '{task_id}'"
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        update_task_url = self._get_api_url(
            base_url=base_url,
            endpoint=UPDATE_TASK_ENDPOINT,
            deployment_type=deployment_type,
            project_id=project_id,
            task_id=task_id,
        )
        request_body = {"input_data": task_details}
        query_params = {}
        if deployment_type == ON_PREMISE:
            query_params = {"PORTALID": storage.get("portal_id")}
        try:
            self.servicedesk_helper.api_helper(
                logger_msg=logger_msg,
                url=update_task_url,
                method="PUT",
                headers=headers,
                data=request_body,
                params=query_params,
                verify=verify,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=False,
                deployment_type=deployment_type,
                configuration=self.configuration,
                storage=storage,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated task '{task_id}'."
            )
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

    @api_ssl_wrapper
    def _add_comment_in_task(
        self,
        project_id: str,
        task_id: str,
        comment: str,
        deployment_type: Literal["cloud", "onpremise"],
        verify: bool = None,
    ) -> bool:
        """
        This function is used to add a comment in a task in ManageEngine
        ServiceDesk Plus.

        Args:
            project_id (str): The ID of the project in which the task is
                present.
            task_id (str): The ID of the task in which the comment is to be
                added.
            comment (str): The comment to be added in the task.
            deployment_type (Literal["cloud", "onpremise"]): Whether the task
                is to be created on a cloud or on-premise server.
            verify (bool, optional): Whether to verify the SSL certificate of
                the server. Defaults to None.

        Returns:
            bool: True if the comment was added successfully, False otherwise.

        Raises:
            ServiceDeskPluginException: If any error occurs while adding the
                comment.
        """
        storage = self._get_storage()
        logger_msg = (
            f"adding comment in task '{task_id}'"
        )
        (
            headers, base_url, deployment_type
        ) = self._get_base_url_and_auth_headers()
        add_task_comment_url = self._get_api_url(
            base_url=base_url,
            endpoint=ADD_TASK_COMMENTS_ENDPOINT,
            deployment_type=deployment_type,
            project_id=project_id,
            task_id=task_id,
        )
        if deployment_type == CLOUD:
            request_body = {
                "task_comment": {
                    "comment": comment
                }
            }
            query_params = {}
        elif deployment_type == ON_PREMISE:
            request_body = {
                "comment": {
                    "content": comment
                }
            }
            query_params = {"PORTALID": storage.get("portal_id")}
        else:
            err_msg = (
                f"Invalid deployment type {deployment_type} received"
                f" while {logger_msg}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ServiceDeskPluginException(err_msg)
        try:
            response = self.servicedesk_helper.api_helper(
                logger_msg=logger_msg,
                url=add_task_comment_url,
                method="POST",
                headers=headers,
                data={"input_data": request_body},
                params=query_params,
                proxies=self.proxy,
                verify=verify,
                is_handle_error_required=False,
                is_validation=False,
                deployment_type=deployment_type,
                configuration=self.configuration,
                storage=storage,
            )
            if response.status_code == 201:
                return True
            elif response.status_code == 404:
                self.logger.error(
                    f"{self.log_prefix}: Skipped adding comment for"
                    f" task '{task_id}' as the task was not found on"
                    f" {PLATFORM_NAME}."
                )
                return False
            else:
                self.servicedesk_helper.handle_error(
                    resp=response,
                    logger_msg=logger_msg,
                    is_validation=False,
                    deployment_type=deployment_type,
                )
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)

    @api_ssl_wrapper
    def _fetch_all_portals(
        self,
        base_url: str,
        auth_token: str,
        deployment_type: Literal["cloud", "onpremise"],
        configuration: Dict,
        storage: Dict,
        verify: bool = None,
    ) -> Dict[str, str]:
        """
        Fetch all portals from the ManageEngine ServiceDesk Plus.

        Args:
            base_url (str): The instance URL of the server.
            auth_token (str): The authentication token for the API.
            deployment_type (str): The deployment type, either "cloud" or
                "onpremise".
            configuration (Dict): The configuration dictionary.
            storage (Dict): The storage dictionary.
            verify (bool, optional): Whether to verify the SSL certificate of
                the server. Defaults to None.

        Returns:
            Dict: A dictionary where the keys are the portal urls and
                the values are the portal ids.

        Raises:
            ServiceDeskPluginException: If there was an error while fetching
                the portals.
        """
        get_portal_url = self._get_api_url(
            base_url=base_url,
            endpoint=GET_ALL_PORTALS_ENDPOINT,
            deployment_type=deployment_type,
        )
        headers = self.servicedesk_helper.get_auth_headers(
            token=auth_token, deployment_type=deployment_type
        )
        query_params = self._get_query_param(
            page_limit=DEFAULT_PAGE_LIMIT,
        )
        portals_dict = {}
        has_more_rows = True
        try:
            logger_msg = f"fetching all portals from {PLATFORM_NAME} platform."
            while has_more_rows:
                response = self.servicedesk_helper.api_helper(
                    url=get_portal_url,
                    method="GET",
                    logger_msg=logger_msg,
                    params=query_params,
                    headers=headers,
                    verify=verify,
                    proxies=self.proxy,
                    is_validation=True,
                    is_handle_error_required=True,
                    deployment_type=deployment_type,
                    regenerate_auth_token=True,
                    configuration=configuration,
                    storage=storage,
                )
                for portal_details in response.get("portals", []):
                    if deployment_type == CLOUD:
                        app_context = portal_details.get("app_context")
                        portals_dict[app_context] = app_context
                    elif deployment_type == ON_PREMISE:
                        portals_dict[
                            portal_details.get("alias_url")
                        ] = portal_details.get("id")
                has_more_rows = response.get(
                    "list_info", {}
                ).get("has_more_rows")
                query_params["input_data"]["list_info"]["page"] += 1
        except ServiceDeskPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(err_msg)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(portals_dict)}"
            f" portals from {PLATFORM_NAME} platform."
        )
        return portals_dict

    def _validate_connectivity_cloud(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        auth_code: str,
        portal_url: str,
        configuration: Dict,
    ) -> ValidationResult:
        """
        Validate connectivity with ManageEngine ServiceDesk Plus cloud
        platform.

        Args:
            base_url (str): Base URL of ManageEngine ServiceDesk Plus
                cloud platform.
            client_id (str): Client ID of ManageEngine ServiceDesk Plus
                cloud platform.
            client_secret (str): Client Secret of ManageEngine ServiceDesk
                Plus cloud platform.
            auth_code (str): Authorization Code of ManageEngine ServiceDesk
                Plus cloud platform.
            portal_url (str): URL of the portal to validate.
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: ValidationResult object with success status
                and message.

        Raises:
            ServiceDeskPluginException: If any error occurs while validating
                connectivity.
        """
        storage = self._get_storage()
        try:
            current_config_hash = (
                self.servicedesk_helper.generate_auth_param_hash(
                    f"{base_url}{client_id}{client_secret}{auth_code}"
                )
            )
            if (
                storage.get("access_token") and storage.get("refresh_token")
            ) and storage.get("config_hash") == current_config_hash:
                access_token = storage.get("access_token")
            else:
                (
                    access_token, refresh_token
                ) = self.servicedesk_helper.access_token_operation(
                    base_url=base_url,
                    client_id=client_id,
                    client_secret=client_secret,
                    auth_code=auth_code,
                    refresh_token=None,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_validation=True,
                    operation="generate",
                )

                storage.update(
                    {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "config_hash": (
                            self.servicedesk_helper.generate_auth_param_hash(
                                f"{base_url}{client_id}{client_secret}{auth_code}"
                            )
                        )
                    }
                )

            portals_dict = self._fetch_all_portals(
                base_url=base_url,
                auth_token=access_token,
                deployment_type=CLOUD,
                configuration=configuration,
                storage=storage,
            )
            if portal_url in portals_dict:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated connectivity"
                    f" with {PLATFORM_NAME} platform."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                err_msg = (
                    f"Invalid URL Name {portal_url} provided in"
                    " configuration parameter."
                )
                available_url_names = ""
                for url_name in portals_dict.keys():
                    if url_name:
                        available_url_names += f"{url_name}, "
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=(
                        f"Available URL Names:"
                        f" {available_url_names.rstrip(', ')}"
                    )
                )
                return ValidationResult(success=False, message=err_msg)
        except ServiceDeskPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                f"Unexpected validation error occurred while validating"
                f" connectivity with {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_connectivity_onpremise(
        self,
        base_url: str,
        auth_token: str,
        portal_url: str,
        configuration: Dict,
    ) -> ValidationResult:
        """
        Validates connectivity with the on-premise deployment of
        ManageEngine ServiceDesk Plus.

        Args:
            base_url (str): The base URL of the ManageEngine ServiceDesk Plus
                platform.
            auth_token (str): The authentication token used to access the
                ManageEngine ServiceDesk Plus platform.
            portal_url (str): The URL of the portal to validate connectivity
                with.
            configuration (Dict): The plugin configuration.

        Returns:
            ValidationResult: ValidationResult object with success status
                and message.
        """
        storage = self._get_storage()
        try:
            portals_dict = self._fetch_all_portals(
                base_url=base_url,
                auth_token=auth_token,
                deployment_type=ON_PREMISE,
                configuration=configuration,
                storage=storage,
            )
            if portal_url in portals_dict:
                storage.update(
                    {
                        "portal_id": portals_dict.get(portal_url)
                    }
                )
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated connectivity"
                    f" with {PLATFORM_NAME} platform."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                err_msg = (
                    f"Invalid Alias URL {portal_url} provided in"
                    " configuration parameter."
                )
                available_alias_url = ""
                for alias_url in portals_dict.keys():
                    if alias_url:
                        available_alias_url += f"{alias_url}, "
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=(
                        f"Available Alias URLs:"
                        f" {available_alias_url.rstrip(', ')}"
                    )
                )
                return ValidationResult(success=False, message=err_msg)
        except ServiceDeskPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                f"Unexpected validation error occurred while validating"
                f" connectivity with {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_connectivity(
        self,
        configuration: Dict,
        deployment_type: Literal["cloud", "onpremise"],
    ) -> ValidationResult:
        """
        Validates the connectivity with the ServiceDesk platform.

        Args:
            configuration (Dict): The plugin configuration.
            deployment_type (Literal["cloud", "onpremise"]): The deployment
                type of the ServiceDesk platform.

        Returns:
            ValidationResult: ValidationResult object with success status
                and message.
        """
        if deployment_type == CLOUD:
            base_url, client_id, client_secret, auth_code, portal_url = (
                self.servicedesk_helper.get_configuration_params(
                    configuration=configuration,
                    deployment_type=deployment_type,
                )
            )
            return self._validate_connectivity_cloud(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                auth_code=auth_code,
                portal_url=portal_url,
                configuration=configuration,
            )
        elif deployment_type == ON_PREMISE:
            base_url, auth_token, ssl_certificate, portal_url = (
                self.servicedesk_helper.get_configuration_params(
                    configuration=configuration,
                    deployment_type=deployment_type,
                )
            )
            return self._validate_connectivity_onpremise(
                base_url=base_url,
                auth_token=auth_token,
                portal_url=portal_url,
                configuration=configuration,
            )
        else:
            return ValidationResult(
                success=False,
                message=f"Invalid Deployment type {deployment_type}."
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme and parsed.netloc

    def _validate_auth_params(self, configuration):
        """Validate plugin authentication parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        deployment_type = configuration.get("sdp_deployment_type", {}).get(
            "deployment_type", ""
        )
        base_url, *other_auth_params, portal_url = (
            self.servicedesk_helper.get_configuration_params(
                configuration=configuration,
                deployment_type=deployment_type,
            )
        )
        if deployment_type == CLOUD:
            api_url_field_name = "API Domain URL"
            portal_url_field_name = "URL Name"
        elif deployment_type == ON_PREMISE:
            api_url_field_name = "Service Desk Plus On Premise Instance URL"
            portal_url_field_name = "Alias URL"

        # Validate Common Auth Params
        if validation_result := self._validate_configuration_parameters(
            field_name=api_url_field_name,
            field_value=base_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_result

        if validation_result := self._validate_configuration_parameters(
            field_name=portal_url_field_name,
            field_value=portal_url,
            field_type=str
        ):
            return validation_result

        # Validate Cloud specific auth params
        if deployment_type == CLOUD:
            client_id = other_auth_params[0]
            client_secret = other_auth_params[1]
            auth_code = other_auth_params[2]

            if validation_result := self._validate_configuration_parameters(
                field_name="Client ID",
                field_value=client_id,
                field_type=str,
            ):
                return validation_result

            if validation_result := self._validate_configuration_parameters(
                field_name="Client Secret",
                field_value=client_secret,
                field_type=str,
            ):
                return validation_result

            if validation_result := self._validate_configuration_parameters(
                field_name="Auth Code",
                field_value=auth_code,
                field_type=str,
            ):
                return validation_result

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated Cloud"
                " specific authentication parameters."
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        # Validate On Premise specific auth params
        elif deployment_type == ON_PREMISE:
            auth_token = other_auth_params[0]

            if validation_result := self._validate_configuration_parameters(
                field_name="Auth Token",
                field_value=auth_token,
                field_type=str,
            ):
                return validation_result

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated On-Premise"
                " specific authentication parameters."
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        else:
            err_msg = f"Invalid Deployment Type: {deployment_type}."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

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
        if name == "sdp_deployment_type":
            deployment_type = configuration.get("sdp_deployment_type", {}).get(
                "deployment_type", ""
            )
            if validation_result := self._validate_configuration_parameters(
                field_name="Deployment Type",
                field_value=deployment_type,
                field_type=str,
                allowed_values=[CLOUD, ON_PREMISE],
            ):
                return validation_result
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated Deployment Type."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif name == "auth":
            return self._validate_auth_params(configuration)
        elif name == "mapping_config":
            deployment_type = configuration.get(
                "sdp_deployment_type", {}
            ).get("deployment_type", "")
            return self._validate_connectivity(
                configuration=configuration,
                deployment_type=deployment_type
            )
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[bool, int, List, str],
        field_type: type,
        allowed_values: List = None,
        custom_validation_func: Callable = None,
        validation_err_msg: str = "Validation error occurred. ",
    ):
        """
        Validate a configuration parameter and return ValidationResult
        if validation fails.

        Args:
            field_name (str): Name of the configuration field.
            field_value: Value of the configuration field.
            field_type (type): Expected type of the configuration field.
            validation_err_msg (str, optional): Base error message for
                validation failures.
            custom_validation_func (Callable, optional): Custom validation
                function.
            allowed_values (List, optional): List of allowed values for the
                configuration field.

        Returns:
            ValidationResult: ValidationResult if validation fails,
                None if passes.
        """
        if field_type is str:
            field_value = field_value.strip()
        if not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values and field_value not in allowed_values:
            allowed_values_str = ", ".join(
                [allowed_value for allowed_value in allowed_values]
            )
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {allowed_values_str}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the available fields for requests.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            List[MappingField]: List of mapping fields.
        """
        """Get list of all the available fields."""
        fields = []
        for field_value, field_label in AVAILABLE_FIELDS.items():
            if field_value == "comment":
                fields.append(
                    MappingField(
                        label=field_label["queue_field_label"],
                        value=field_value,
                        updateAble=True,
                    )
                )
            else:
                fields.append(
                    MappingField(
                        label=field_label["queue_field_label"],
                        value=field_value,
                    )
                )

        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            dict: Default mappings.
        """
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="title",
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName, Event Name: $alert_name"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="description",
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\nAlert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\n"
                        "Alert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                )
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="comment",
                    custom_message=(
                        "Received new alert/event with Alert/Event ID: $id "
                        "and Alert Name: $alertName, Event Name: $alert_name "
                        "in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_queues(self) -> List[Queue]:
        """Get list of Service Desk Plus projects as queues.

        Returns:
            List[Queue]: List of queues.
        """
        queues = []
        projects_dict = self._fetch_projects(
            deployment_type=self.servicedesk_helper.get_deployment_type(
                configuration=self.configuration
            )
        )

        for queue_title, project_id in projects_dict.items():
            queues.append(
                Queue(
                    label=queue_title,
                    value=project_id,
                )
            )

        return queues

    def get_fields(self, name: str, configuration: dict):
        """Get dynamic configuration fields.

        Args:
            name (str): Stepper name
            configuration (dict): Configuration parameters dictionary.

        Returns:
            dict: List of fields.
        """
        fields = []
        if name == "auth":
            deployment_type = configuration.get("sdp_deployment_type", {}).get(
                "deployment_type", ""
            )
            if deployment_type == "cloud":
                fields.extend(
                    [
                        {
                            "label": "API Domain URL",
                            "key": "sdp_api_url",
                            "type": "choice",
                            "choices": [
                                {
                                    "key": "United States - Data centre (https://sdpondemand.manageengine.com)",
                                    "value": "https://sdpondemand.manageengine.com",
                                },
                                {
                                    "key": "Europe - Data centre (https://sdpondemand.manageengine.eu)",
                                    "value": "https://sdpondemand.manageengine.eu",
                                },
                                {
                                    "key": "India - Data centre (https://sdpondemand.manageengine.in)",
                                    "value": "https://sdpondemand.manageengine.in",
                                },
                                {
                                    "key": "Australia - Data centre (https://servicedeskplus.net.au)",
                                    "value": "https://servicedeskplus.net.au",
                                },
                                {
                                    "key": "China - Data centre (https://servicedeskplus.cn)",
                                    "value": "https://servicedeskplus.cn",
                                },
                                {
                                    "key": "Japan - Data centre (https://servicedeskplus.jp)",
                                    "value": "https://servicedeskplus.jp",
                                },
                                {
                                    "key": "Canada - Data centre (https://servicedeskplus.ca)",
                                    "value": "https://servicedeskplus.ca",
                                },
                                {
                                    "key": "United Kingdom - Data centre (https://servicedeskplus.uk)",
                                    "value": "https://servicedeskplus.uk",
                                },
                                {
                                    "key": "Saudi Arabia - Data centre (https://servicedeskplus.sa/)",
                                    "value": "https://servicedeskplus.sa/",
                                },
                            ],
                            "default": "https://sdpondemand.manageengine.com",
                            "mandatory": True,
                            "description": (
                                "Manage Engine Service Desk Plus Cloud"
                                " API Domain URL."
                            ),
                        },
                        {
                            "label": "Client ID",
                            "key": "client_id",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Client ID for your Service Desk Plus"
                                " Cloud account, can be generated from the"
                                " ZOHO Developer Console. "
                                " In the Developer console navigate to"
                                " 'Self Service > Client Secret' to obtain"
                                " the Client ID."
                            ),
                        },
                        {
                            "label": "Client Secret",
                            "key": "client_secret",
                            "type": "password",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Client Secret for your Service Desk Plus"
                                " Cloud account, can be generated from the"
                                " ZOHO Developer Console. "
                                " In the Developer console navigate to"
                                " 'Self Service > Client Secret' to obtain"
                                " the Client Secret."
                            ),
                        },
                        {
                            "label": "Auth Code",
                            "key": "auth_code",
                            "type": "password",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Auth Code for your Service Desk Plus"
                                " Cloud account. Can be generated from the"
                                " ZOHO Developer Console. "
                                " In the Developer console navigate to"
                                " 'Self Service > Generate Code' to generate"
                                " the Auth Code."
                            ),
                        },
                        {
                            "label": "URL Name",
                            "key": "portal_url",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Service Desk Plus Portal URL Name. Navigate"
                                " to 'ESM Directory > Service Instances' then"
                                " copy the URL Name of the portal."
                            ),
                        },
                    ]
                )
            elif deployment_type == "onpremise":
                fields.extend(
                    [
                        {
                            "label": (
                                "Service Desk Plus On Premise Instance URL"
                            ),
                            "key": "sdp_api_url",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Manage Engine Service Desk Plus On Premise"
                                " instance URL."
                            ),
                        },
                        {
                            "label": "Auth Token",
                            "key": "auth_token",
                            "type": "password",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Auth Token for your Manage Engine Service"
                                " Desk Plus On Premise account, can be"
                                " generated from 'Profile > Generate"
                                " Authtoken'."
                            ),
                        },
                        {
                            "label": "Alias URL",
                            "key": "portal_url",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "description": (
                                "Service Desk Plus Portal Alias URL. Navigate"
                                " to 'ESM Directory > Service Desk Instances'"
                                " then copy the Alias URL of the portal. Only"
                                " provide the Alias URL name and not the"
                                " actual URL"
                            ),
                        },
                        {
                            "label": "SSL Certificate",
                            "key": "ssl_certificate",
                            "type": "textarea",
                            "mandatory": False,
                            "description": (
                                "Provide the content of the .crt file. Provide"
                                " the self-signed certificate for the Service"
                                " Desk Plus On Premise instance."
                            ),
                        },
                    ]
                )
            else:
                self.logger.error(
                    f"{self.log_prefix}: Unknown Service Desk Plus deployment"
                    f" type: {deployment_type}."
                )
                return []
            return fields

    def get_default_custom_mappings(self) -> List[
        CustomFieldsSectionWithMappings
    ]:
        """
        Get default custom field mappings with values for Netskope ITSM plugin.

        Returns:
            list[CustomFieldsSectionWithMappings]: List of sections with \
                field-to-value mappings
        """
        return [
            CustomFieldsSectionWithMappings(
                section="status",
                event_field="status",
                destination_label="Manage Engine Service Desk Plus",
                field_mappings=[
                    CustomFieldMapping(
                        name="New",
                        mapped_value="Open",
                        is_default=True
                    ),
                    CustomFieldMapping(
                        name="In Progress",
                        mapped_value="In Progress",
                        is_default=True
                    ),
                    CustomFieldMapping(
                        name="On Hold",
                        mapped_value="On Hold",
                        is_default=True
                    ),
                    CustomFieldMapping(
                        name="Closed",
                        mapped_value="Closed",
                        is_default=True
                    ),
                    CustomFieldMapping(
                        name="Deleted",
                        mapped_value="",
                        is_default=True
                    ),
                    CustomFieldMapping(
                        name="Other",
                        mapped_value="",
                        is_default=True
                    ),
                ]
            )
        ]
