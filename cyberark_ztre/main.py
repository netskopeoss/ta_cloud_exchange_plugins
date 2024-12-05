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

CyberArk URE plugin.
"""

import json
import traceback
import urllib.parse
from typing import List, Dict, Optional

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)
from .utils.helper import (
    CyberArkPluginHelper,
    CyberArkPluginException,
)
from .utils.constants import (
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    PLUGIN_NAME,
    USERS_ENTITY,
    USERS_FIELD_MAPPING,
    PAGE_SIZE,
    BATCH_SIZE,
    NORMALIZATION_MAPPING,
)


class CyberArkPlugin(PluginBase):
    """CyberArk plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize SyslogPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.cyberark_helper = CyberArkPluginHelper(
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
            manifest_json = CyberArkPlugin.metadata
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

    def fetch_records(self, entity: Entity) -> list:
        """Pull Records from CyberArk.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        records = []

        logger_msg = "fetching users"
        headers = self.cyberark_helper.get_protected_cyberark_headers(
            logger_msg,
            ssl_validation=self.ssl_validation,
            proxies=self.proxy,
            configuration=self.configuration
        )

        try:
            if entity == USERS_ENTITY:
                records.extend(self._fetch_users(headers))
            else:
                err_msg = (
                    f"Invalid entity found {PLATFORM_NAME} only supports "
                    f"{USERS_ENTITY} Entities."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise CyberArkPluginException(err_msg)
            return records
        except CyberArkPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def _extract_user_fields(self, entity, user):
        """Extract IOA fields.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        mapping = USERS_FIELD_MAPPING
        for field_name, field_value in mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, user, default, transformation
                ),
            )
        return extracted_fields

    def fetch_risk_level(self, risk_level):
        """Fetch risk level.

        Args:
            user_id (str): User ID.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            str: Risk level.

        """
        normalized_score = NORMALIZATION_MAPPING.get(risk_level, None)
        return normalized_score

    def run_query(self, url, headers, fields, page_number=1):
        """
        Run a query on the CyberArk API.

        Args:
            url (str): URL to make the request to.
            headers (dict): Request headers.
            fields (str): Comma-separated list of fields to fetch.
            page_number (int, optional): Page number to fetch. Defaults to 1.

        Returns:
            dict: API response.

        Raises:
            CyberArkPluginException: If an unexpected error occurs.
        """
        try:
            body = f"""
                {{
                    "Script": "Select {fields} from Users ORDER BY Username",
                    "args": {{
                        "PageNumber": {page_number},
                        "PageSize": {PAGE_SIZE},
                        "Limit": {PAGE_SIZE},
                        "Caching": -1,
                        "direction": true,
                        "SortBy": "Username"
                    }}
                }}
            """
            response = self.cyberark_helper.api_helper(
                logger_msg=f"fetching users from page {page_number}",
                url=url,
                method="POST",
                params=None,
                data=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            return response
        except CyberArkPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling users "
                f"from page {page_number} from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)

    def get_number_of_pages(self, url, headers, fields, page_number):
        """
        Get the number of pages for the current query.

        Args:
            url (str): Base URL for the query.
            headers (dict): Headers for the query.
            fields (str): Fields to query.
            page_number (int): Page number to query.

        Returns:
            int: Number of pages.
        """
        users = self.run_query(url, headers, fields, page_number)
        full_count = users.get("Result", {}).get("FullCount", "")
        number_of_pages = full_count // PAGE_SIZE + (
            1 if full_count % PAGE_SIZE != 0 else 0
        )
        return number_of_pages

    def _fetch_users(self, headers):
        """
        Fetch users from CyberArk.

        Args:
            headers (dict): CyberArk API request headers.

        Returns:
            List[dict]: List of extracted user fields.
        """
        try:
            url_endpoint = "/RedRock/query"
            url = self.cyberark_helper.build_url(
                self.configuration,
                url_endpoint
            )
            fields = ", ".join(
                value["key"].split(".")[1]
                for value in USERS_FIELD_MAPPING.values()
            )
            page_number = 1
            final_users_list = []
            skip_count = 0

            number_of_pages = self.get_number_of_pages(
                url, headers, fields, page_number
            )
            for page_number in range(1, number_of_pages + 1):
                current_page_count = 0
                response = self.run_query(
                    url, headers, fields, page_number
                )
                resp_user_list = response.get("Result", {}).get("Results", [])
                for user in resp_user_list:
                    try:
                        extracted_fields = self._extract_user_fields(
                            entity=USERS_ENTITY, user=user
                        )
                        if extracted_fields:
                            final_users_list.append(extracted_fields)
                            current_page_count += 1
                        else:
                            skip_count += 1
                    except Exception as exp:
                        user_id = user.get("Row", {}).get("ID", "")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f" having User ID '{user_id}' from "
                            f"page {page_number}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {user}",
                        )
                        skip_count += 1
                log_message = (
                    f"Successfully fetched {current_page_count} users(s) "
                    f"in page {page_number}. Total users fetched: "
                    f"{len(final_users_list)}."
                )
                self.logger.info(f"{self.log_prefix}: {log_message}")
            log_message = (
                f"Completed fetching users from {PLATFORM_NAME}. "
                f"Total users fetched: {len(final_users_list)}."
            )
            if skip_count:
                log_message += (
                    f" Skipped fetching {skip_count} user(s) "
                    "as some error occurred while fetching the details."
                )
            self.logger.info(f"{self.log_prefix}: {log_message}")
            return final_users_list

        except CyberArkPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling users "
                f"from page {page_number} from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        return event

    def update_users(self, user_names, headers):
        """
        Fetch users from CyberArk.

        Args:
            user_names (List[str]): List of user IDs.
            headers (dict): CyberArk API request headers.

        Returns:
            List[dict]: List of extracted user fields with normalized score.
        """
        try:
            batch_count = 0
            updated_users_list = []
            skip_count = 0
            for batch in self.batch_generator(user_names, BATCH_SIZE):
                batch_count += 1
                current_page_count = 0
                # process the batch
                url_endpoint = "/RedRock/query"
                url = self.cyberark_helper.build_url(
                    self.configuration,
                    url_endpoint
                )
                fields = ", ".join(
                    value["key"].split(".")[1]
                    for value in USERS_FIELD_MAPPING.values()
                )
                usernames = ", ".join(f"'{username}'" for username in batch)
                script = (
                    f"select {fields} from Users where Username IN "
                    f"({usernames})"
                )
                body = f'{{"Script": "{script}"}}'
                response = self.cyberark_helper.api_helper(
                    logger_msg=f"updating users batch {batch_count}",
                    url=url,
                    method="POST",
                    params=None,
                    data=body,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    configuration=self.configuration
                )
                resp_user_list = response.get("Result", {}).get("Results", [])
                for user in resp_user_list:
                    try:
                        extracted_fields = self._extract_user_fields(
                            entity=USERS_ENTITY, user=user
                        )
                        risk_level = extracted_fields.get("Risk Level", "")
                        if risk_level:
                            extracted_fields["Netskope Normalized Score"] = (
                                self.fetch_risk_level(risk_level)
                            )
                        if extracted_fields:
                            updated_users_list.append(extracted_fields)
                            current_page_count += 1
                        else:
                            skip_count += 1
                    except Exception as exp:
                        user_id = user.get("Row", {}).get("ID", "")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having User ID "{user_id}" '
                            f"from batch {batch_count}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {user}",
                        )
                        skip_count += 1
                log_message = (
                    f"Successfully updated {current_page_count} users(s) "
                    f"in batch {batch_count}. Total users updated: "
                    f"{len(updated_users_list)}."
                )
                self.logger.info(f"{self.log_prefix}: {log_message}")
            log_message = (
                f"Completed updating users from {PLATFORM_NAME}. "
                f"Total users updated {len(updated_users_list)}."
            )
            if skip_count:
                log_message += (
                    f" Skipped updating {skip_count} user(s) "
                    "as some error occurred while fetching the details."
                )
            self.logger.info(f"{self.log_prefix}: {log_message}")
            return updated_users_list

        except CyberArkPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while updating {USERS_ENTITY} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)

    def batch_generator(self, lst, batch_size):
        """
        A generator to yield batches of a given list. The list is split
        into chunks of size batch_size and each chunk is yielded.

        Args:
            lst (list): The list to be split into batches.
            batch_size (int): The size of each batch.

        Yields:
            list: A batch of the list with size batch_size.

        """
        for i in range(0, len(lst), batch_size):
            yield lst[i: i + batch_size]

    def update_records(
            self,
            entity: str,
            records: list[dict]
    ) -> list[dict]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = {}
        self.logger.info(
            f"{self.log_prefix}: Updating {entity.lower()}"
            f" records from {PLATFORM_NAME}."
        )
        logger_msg = "updating users"
        headers = self.cyberark_helper.get_protected_cyberark_headers(
            logger_msg,
            ssl_validation=self.ssl_validation,
            proxies=self.proxy,
            configuration=self.configuration
        )

        if entity == USERS_ENTITY:
            user_ids = []

            for record in records:
                user_id = record.get("User ID", "")
                user_name = record.get("Username", "")
                if user_id and user_name:
                    user_ids.append(user_name)
            skipped_records = len(records) - len(user_ids)
            log_msg = f"{len(user_ids)} user record(s) will " "be updated."
            if skipped_records:
                log_msg += (
                    f" {skipped_records} "
                    "record(s) will be skipped "
                    "as they do not contain 'User ID' or 'Username' field."
                )
            self.logger.info(f"{self.log_prefix}: " f"{log_msg}")
            updated_records = self.update_users(
                user_ids,
                headers,
            )
        else:
            err_msg = (
                f"Invalid entity found {PLATFORM_NAME} only supports "
                f"{USERS_ENTITY} Entities."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise CyberArkPluginException(err_msg)

        return updated_records

    def get_entities(self) -> list[Entity]:
        """
        Returns a list of entities that this plugin can work with.

        This plugin can fetch Users from CyberArk.
        The entities and their fields are as follows:

        - Users:
            - User ID (string, required)
            - Email (email, required)
            - Display Name (string)
            - Username (string)
            - Login Name (string)
            - Status (string)
            - Status Enum (Localized Status) (string)
            - Risk Level (string)
            - Risk Level Localized (string)
            - Risk Level Rank (string)
            - Netskope Normalized Score (number)
        """
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Display Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Username",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Login Name", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Status", type=EntityFieldType.STRING),
                    EntityField(
                        name="Status Enum (Localized Status)",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Level", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Risk Level Localized",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Level Rank", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]

    def _add_to_role(
        self, user_id: str, role_id: str, role_name: str, headers: Dict
    ):
        """Add specified user to the specified role.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            role_id (str): Role ID of the role.

        Raises:
            HTTPError: If the role does not exist on CyberArk.
        """
        url_endpoint = "/SaasManage/AddUsersAndGroupsToRole"
        url = self.cyberark_helper.build_url(
            self.configuration,
            url_endpoint
        )
        body = {"Users": [user_id], "Name": role_id}
        logger_msg = f"adding user '{user_id}' to role '{role_name}'"
        try:
            resp = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=headers,
                data=json.dumps(body),
                params=None,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            if resp.get("success", True) == False:  # noqa
                error_msg = (
                    f"Failed to add user '{user_id}' to role '{role_name}'.",
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    details=str(resp),
                )
                raise CyberArkPluginException(error_msg)
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = "Unexpected error occurred while " f"{logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def _remove_from_role(
        self, user_id: str, role_id: str, role_name, headers: Dict
    ):
        """Remove specified user from the specified role.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            role_id (str): Role ID of the role.

        Raises:
            HTTPError: If the role does not exist on CyberArk.
        """
        url_endpoint = "/SaasManage/RemoveUsersAndGroupsFromRole"
        url = self.cyberark_helper.build_url(
            self.configuration,
            url_endpoint
        )
        body = {"Users": [user_id], "Name": role_id}
        logger_msg = f"removing user '{user_id}' from role '{role_name}'"
        try:
            resp = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=headers,
                data=json.dumps(body),
                params=None,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            if resp.get("success", True) == False:  # noqa
                error_msg = (
                    f"Failed to remove user '{user_id}' from role "
                    f"'{role_name}'.",
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    details=str(resp),
                )
                raise CyberArkPluginException(
                    error_msg,
                )
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = "Unexpected error occurred while " f"{logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def _get_all_roles(self) -> List:
        """Get list of all the role.
        Args:
            configuration (Dict): Configuration parameters.
        Returns:
            List: List of all the roles.
        """
        try:
            logger_msg = "fetching all roles for action configuration"
            headers = self.cyberark_helper.get_protected_cyberark_headers(
                logger_msg,
                ssl_validation=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration
            )
            url_endpoint = "/RedRock/query"
            url = self.cyberark_helper.build_url(
                self.configuration,
                url_endpoint
            )
            body = "{'Script': 'Select ID, Name from Role order by Name'}"
            response = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=None,
                data=body,
                retry=False,
                headers=headers,
                json_params=None,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            roles_list = []

            for roles in response.get("Result", {}).get("Results", []):
                role_row = roles.get("Row", {})
                roles_list.append(
                    {
                        "grp_name": role_row.get("Name", ""),
                        "grp_id": role_row.get("ID", ""),
                    }
                )
            return roles_list
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def _find_user_by_username(
        self, username: str, headers: Dict
    ) -> Optional[Dict]:
        """Find user by username.

        Args:
            username (str): username to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        url_endpoint = "/RedRock/query"
        url = self.cyberark_helper.build_url(
            self.configuration,
            url_endpoint
        )
        body = (
            '{"Script": "select ID, Username from Users where Username = \''
            + username
            + "'\"}"
        )
        try:
            logger_msg = f"finding user '{username}' on {PLATFORM_NAME}"
            response = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=None,
                data=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            matched_user = response.get("Result", {}).get("Results", [])
            if matched_user:
                return matched_user[0]
            else:
                return None
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = "Unexpected error occurred while " f"{logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def _find_role_by_name(self, name: str, headers: Dict) -> Optional[Dict]:
        """Find role from list by name.

        Args:
            name (str): Name to find.

        Returns:
            Optional[Dict]: Role dictionary if found, None otherwise.
        """
        url_endpoint = "/RedRock/query"
        url = self.cyberark_helper.build_url(
            self.configuration,
            url_endpoint
        )
        body = (
            '{"Script": "select ID, Name from Role where Name = \''
            + name
            + "'\"}"
        )
        logger_msg = "finding role '{}' on {}".format(name, PLATFORM_NAME)
        try:
            response = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=None,
                data=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )
            matched_user = response.get("Result", {}).get("Results", [])
            if matched_user:
                return matched_user[0].get("Row", "").get("ID", "")
            else:
                return None
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to role", value="add"),
            ActionWithoutParams(label="Remove from role", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _create_role(self, name: str, headers: Dict) -> Dict:
        """Create a new role with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the role to create.
            description (str): Role description.

        Returns:
            Dict: Newly created role dictionary.
        """
        url_endpoint = "/Roles/StoreRole"
        url = self.cyberark_helper.build_url(
            self.configuration,
            url_endpoint
        )
        body = {"Description": "Created from Netskope CE", "Name": name}
        logger_msg = f"creating role '{name}' on {PLATFORM_NAME}"
        try:
            response = self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=None,
                data=json.dumps(body),
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                configuration=self.configuration
            )

            if response.get("success", False) == True:  # noqa
                self.logger.info(
                    f"{self.log_prefix}: Successfully created role with name "
                    f"{name} on {PLATFORM_NAME}."
                )
                return response.get("Result", {}).get("_RowKey", "")
            error_msg = (
                f"Failed to create role with name {name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=f"API response: {response.text}"
            )
            raise CyberArkPluginException(
                error_msg
            )
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def execute_action(self, action: Action):
        """
        Execute action on the user.

        Args:
            action (Action): Action to be executed.

        Raises:
            CyberArkPluginException: If the action fails to execute.
        """
        try:
            action_parameters = action.parameters
            action_label = action.label
            action_value = action.value
            user = action_parameters.get("email", "")
            if not user:
                info_msg = (
                    "The record does not contain an email address. "
                    f"Action '{action_label}' will be skipped. "
                    "If Source is selected for the Email field, "
                    "make sure that the selected source field contains values."
                )
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"{info_msg}"
                )
                return
            if action_value == "generate":
                self.logger.debug(
                    '{}: Successfully executed "{}" action on record "{}". '
                    "Note: No processing will be done from plugin for "
                    'the "{}" action.'.format(
                        self.log_prefix, action_label, user, action_label
                    )
                )
                return
            logger_msg = "performing action"
            headers = self.cyberark_helper.get_protected_cyberark_headers(
                logger_msg,
                ssl_validation=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration
            )
            match_user = self._find_user_by_username(user, headers)
            if match_user is None:
                info_msg = (
                    f"{self.log_prefix}: User '{user}' not "
                    f"found on {PLATFORM_NAME}. "
                    f"Hence action '{action.label}' will be skipped."
                )
                self.logger.info(info_msg)
                return
            self.logger.info(
                f"{self.log_prefix}: User '{user}' found on {PLATFORM_NAME}. "
                f"Hence action '{action.label}' will be executed."
            )
            role_dict = json.loads(action_parameters.get("role_name", ""))
            role_name = role_dict.get("grp_name", "")
            is_create_new_grp = role_name == "create_new_role"
            if is_create_new_grp:
                role_name = action_parameters.get("new_role_name", "")
            match_role_id = self._find_role_by_name(role_name, headers)
            if action_value == "add":
                # either provided grp is deleted or create new grp is selected
                if not match_role_id:
                    if is_create_new_grp:
                        self.logger.info(
                            f"{self.log_prefix}: Creating new role "
                            f"with name '{role_name}' on {PLATFORM_NAME}."
                        )
                        match_role_id = self._create_role(role_name, headers)
                    else:
                        error_msg = (
                            f"{self.log_prefix}: Selected role "
                            f"with name '{role_name}' not found on CyberArk, "
                            f"hence action '{action.label}' will be skipped. "
                            "Either select a an existing role in the action "
                            "configuration or select 'Create New Role' option."
                        )
                        self.logger.error(error_msg)
                        raise CyberArkPluginException(error_msg)
                self._add_to_role(user, match_role_id, role_name, headers)
                self.logger.info(
                    f"{self.log_prefix}: Successfully added user '{user}' "
                    f"to role '{role_name}'."
                )
            elif action_value == "remove":
                if not match_role_id:
                    error_msg = (
                        f"{self.log_prefix}: Role with name '{role_name}' "
                        f"not found on {PLATFORM_NAME}, "
                        f"hence action '{action.label}' will be skipped."
                    )
                    self.logger.error(error_msg)
                    raise CyberArkPluginException(error_msg)
                self._remove_from_role(user, match_role_id, role_name, headers)
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed user "
                    f"'{user}' from role '{role_name}'."
                )
        except CyberArkPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Unexpected error occurred while "
                f"performing action '{action_label}' "
                f"on {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(error_msg)

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == "generate":
            return []
        create_new_role_dict = {"grp_name": "create_new_role", "grp_id": "id"}
        roles = self._get_all_roles()
        choice_list = [
            {"key": role.get("grp_name", ""), "value": json.dumps(role)}
            for role in roles
        ]
        choice_list_with_create = choice_list + [
            {
                "key": "Create New Role",
                "value": json.dumps(create_new_role_dict),
            }
        ]
        email_field = [
            {
                "label": "User Email",
                "key": "email",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Email ID of the user to perform the action on. "
                    "This field will be matched with the CyberArk user's "
                    "Username or Login Name."
                ),
            }
        ]
        if action.value == "add":
            return email_field + [
                {
                    "label": "Role Name",
                    "key": "role_name",
                    "type": "choice",
                    "choices": choice_list_with_create,
                    "default": (
                        choice_list_with_create[0]["value"]
                        if choice_list_with_create
                        else ""
                    ),
                    "mandatory": True,
                    "description": "Select a role to add the user to.",
                },
                {
                    "label": "New Role Name (only applicable when "
                    "Create New Role is selected)",
                    "key": "new_role_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "New Role Name where the "
                    "users will be added.",
                },
            ]
        elif action.value == "remove":
            if not choice_list:
                choice_list = [
                    {
                        "key": "No Roles found on CyberArk",
                        "value": json.dumps(
                            {
                                "grp_name": "No Roles found on CyberArk",
                                "grp_id": "",
                            }
                        ),
                    }
                ]
            return email_field + [
                {
                    "label": "Role Name",
                    "key": "role_name",
                    "type": "choice",
                    "choices": choice_list,
                    "default": (
                        choice_list[0].get("value", "") if choice_list else ""
                    ),
                    "mandatory": True,
                    "description": "Select a role to remove the user from.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate CyberArk action configuration."""
        action_value = action.value
        action_parameters = action.parameters
        action_label = action.label

        if action_value not in ["add", "remove", "generate"]:
            self.logger.error(
                f"{self.log_prefix}: "
                "Unsupported action selected. "
                "Select the action form the available list."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully validated action '{action_label}'."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )

        roles = self._get_all_roles()
        if action_value == "remove" and not roles:
            error_msg = (
                "No roles found on CyberArk. "
                "Make sure roles exists on the platform "
                "and the user has the administrative rights to manage roles."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        role_value = action_parameters.get("role_name", "")

        # Validate Empty Role provided
        if not role_value or "$" in role_value:
            error_msg = (
                "Role Name is a required field and it should not be a "
                "'Source' field. Please select the Static option and "
                "select a role from the available list."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validate type of Role Name provided
        elif not isinstance(role_value, str):
            error_msg = "Invalid Role Name provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        role_value_dict = json.loads(role_value)
        role_name = role_value_dict.get("grp_name", "")
        is_create_new_grp = role_name == "create_new_role"

        # Validate Role Name create new role is not selected
        if not is_create_new_grp and not (
            any(d == role_value_dict for d in roles)
        ):
            error_msg = (
                "Invalid Role Name provided. "
                "Select Role Name from the provided list "
                "or select 'Create New Role'."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validate New Role Name if action value is add
        # and create new role is selected
        new_role_name = action_parameters.get("new_role_name", "")
        if action_value == "add" and is_create_new_grp and not new_role_name:
            error_msg = (
                "New Role Name is a required field when "
                "'Create New Role' is selected in the "
                "'Role Name' field."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)
        if "$" in new_role_name:
            error_msg = (
                "New Role Name should not be a "
                "'Source' field. Please select the Static option and "
                "provide the New Role Name."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validation Successful
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_auth(self, configuration: dict) -> ValidationResult:
        """Validate CyberArk credentials."""
        # Generate the bearer token to verify the credentials
        try:
            logger_msg = "validating configuration parameters"
            headers = self.cyberark_helper.get_protected_cyberark_headers(
                logger_msg,
                ssl_validation=self.ssl_validation,
                proxies=self.proxy,
                configuration=configuration,
                regenerate_auth_token=False
            )
            url_endpoint = "/UserMgmt/GetUserInfo"
            url = self.cyberark_helper.build_url(
                configuration,
                url_endpoint
            )
            logger_msg = "getting user information for validating credentials"
            self.cyberark_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=headers,
                is_handle_error_required=True,
                verify=self.ssl_validation,
                proxies=self.proxy,
                regenerate_auth_token=False,
                configuration=configuration,
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except CyberArkPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            error_msg = f"Unexpected Error occurred while {logger_msg}"
            self.logger.error(
                f"{self.log_prefix}: {error_msg}. " f"Error: {err}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )

    def validate_cyberark_domain(self, url: str):
        """Validate Cyberark domain."""
        valid_domains = [".idaptive.com", ".cyberark.cloud"]
        for domain in valid_domains:
            if domain in url:
                parsed = urllib.parse.urlparse(url)
                return (
                    parsed.scheme.strip() != ""
                    and parsed.netloc.strip() != ""
                    and (
                        parsed.path.strip() == "/" or parsed.path.strip() == ""
                    )
                )
        return False

    def validate(self, configuration: Dict):
        """Validate CyberArk configuration."""
        url = configuration.get("url", "").strip().rstrip("/")
        validation_msg = "Validation error occurred."
        if not url:
            err_msg = "Tenant URL is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(url, str) or not self.validate_cyberark_domain(
            url
        ):
            err_msg = (
                "Invalid Tenant URL provided in the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        service_user = configuration.get("service_user", "").strip()
        if not service_user:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(service_user, str):
            err_msg = (
                "Invalid Username provided in the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        service_password = configuration.get("service_password")
        if not service_password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(service_password, str):
            err_msg = (
                "Invalid Password provided in the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {validation_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        return self._validate_auth(configuration)
