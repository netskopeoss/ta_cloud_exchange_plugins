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

CRE Mimecast Plugin."""

import json
import base64
import hashlib
import hmac
import re
import uuid
from datetime import datetime
from typing import List, Dict, Optional
import traceback
from urllib.parse import urlparse

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.helper import MimecastPluginHelper, MimecastPluginException
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MAX_PAGE_SIZE,
    USER_FIELD_MAPPING,
    SECRET_KEY_REGEX,
    EMAIL_ADDRESS_REGEX,
)


class MimecastPlugin(PluginBase):
    """Mimecast plugin implementation."""

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
        self.mimecast_helper = MimecastPluginHelper(
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
            metadata_json = MimecastPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _parse_errors(self, failures):
        """Parse the error message from Mimecast response."""
        messages = []
        for failure in failures:
            for error in failure.get("errors", []):
                messages.append(error.get("message"))
        return messages

    def _find_group_by_name(self, groups: List, name: str):
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("name") == name:
                return group
        return None

    def _get_auth_headers(self, configuration: dict, endpoint: str):
        """Generate Mimecast authentication headers."""
        request_url = (
            f"{configuration.get('url').strip().strip('/')}{endpoint}"
        )
        request_id = str(uuid.uuid4())
        request_datetime = (
            f"{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S')} UTC"
        )

        # Create the HMAC SA1 of the Base64 decoded secret key for the
        # Authorization header
        hmac_sha1 = hmac.new(
            base64.b64decode(configuration.get("secret_key")),
            ":".join(
                [
                    request_datetime,
                    request_id,
                    endpoint,
                    configuration.get("app_key"),
                ]
            ).encode("utf-8"),
            digestmod=hashlib.sha1,
        ).digest()

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": f"MC {configuration.get('access_key')}:"
            f"{sig.decode('utf-8')}",
            "x-mc-app-id": configuration.get("app_id").strip(),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        return request_url, headers

    def _get_all_groups(
        self, configuration: Dict, is_validation=False
    ) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.
            is_validation (bool): Whether calling from validate method

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        endpoint = "/api/directory/find-groups"
        pageSize = MAX_PAGE_SIZE
        nextPageToken = ""
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        body = {
            "meta": {
                "pagination": {
                    "pageSize": pageSize,
                    "pageToken": nextPageToken,
                }
            }
        }
        try:
            while True:
                groups = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg="fetching all groups",
                    is_handle_error_required=True,
                    is_validation=is_validation,
                )
                all_groups += [
                    {"id": group.get("id"), "name": group.get("description")}
                    for group in groups.get("data", [{}])[0].get("folders", [])
                    if group.get("id") and group.get("description")
                ]
                nextPage = (
                    groups.get("meta", {})
                    .get("pagination", {})
                    .get("next", "")
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                else:
                    break

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(all_groups)}"
                f" groups from {PLATFORM_NAME}."
            )
            return all_groups
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An error occurred while retrieving existing group details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _create_group(self, configuration: Dict, name: str):
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters
            name (str): Name of the group to create.

        Returns:
            Dict: Newly created group dictionary.
        """
        endpoint = "/api/directory/create-group"
        body = {"data": [{"description": name}]}
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        logger_msg = f"Creating group with name {name}"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
        err_msg = f"An error occurred while creating group with name {name}."
        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(body),
                logger_msg=logger_msg,
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                )
                raise MimecastPluginException(error)
            return response
        except MimecastPluginException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _add_to_group(
        self, configuration: Dict, user_id: str, group_id: str, group_name: str
    ):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group IF of the group.

        Returns:
            HTTPError: If the group doesn't exist on Mimecast.
        """
        endpoint = "/api/directory/add-group-member"
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        self.logger.debug(
            f"{self.log_prefix}: Adding user {user_id} to group {group_name}."
        )
        err_msg = (
            f"An error occurred while adding {user_id} "
            f"to group {group_name}."
        )
        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"adding user {user_id} to group {group_name}",
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(error)
        except MimecastPluginException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _remove_from_group(
        self, configuration: Dict, user_id: str, group_id: str, group_name: str
    ):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Mimecast.
        """
        endpoint = "/api/directory/remove-group-member"
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        self.logger.debug(
            f"{self.log_prefix}: Removing {user_id} "
            f"from the group {group_name}."
        )
        err_msg = (
            f"An error occurred while removing {user_id} "
            f"from group {group_name}."
        )
        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"removing {user_id} from the group {group_name}",
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(err_msg)
        except MimecastPluginException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _get_all_users(self) -> List:
        """Get list of all the users.

        Returns:
            List: List of all the users.
        """
        records = []
        endpoint = "/api/awareness-training/company/get-safe-score-details"
        pageSize = MAX_PAGE_SIZE
        nextPageToken = ""
        request_url, headers = self._get_auth_headers(
            self.configuration, endpoint
        )
        body = {
            "meta": {
                "pagination": {
                    "pageSize": pageSize,
                    "pageToken": nextPageToken,
                }
            }
        }
        err_msg = "An error occurred while fetching users."
        logger_msg = f"fetching user details from {PLATFORM_NAME}"
        page_count = 1
        while True:
            try:
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=logger_msg,
                    is_handle_error_required=True,
                )
                failures = response.get("fail", [])
                if failures:
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {response}",
                    )
                    raise MimecastPluginException(error)
                fetch_records = response.get("data", [])
                records += fetch_records
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(fetch_records)} users from page {page_count}."
                    f" Total users fetched: {len(records)}."
                )
                nextPage = (
                    response.get("meta", {})
                    .get("pagination", {})
                    .get("next", "")
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                    page_count += 1
                else:
                    break
            except MimecastPluginException:
                raise
            except Exception as e:
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastPluginException(err_msg)
        return records

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries
            email (str): Email to find.

        Returns:
            Optional[Dict]: user dictionary if found, None otherwise.
        """
        if users:
            for user in users:
                if user.get("emailAddress", "") == email:
                    return user
        return None

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

    def _extract_each_device_fields(
        self, event: dict, include_normalization: bool = True
    ) -> dict:
        """Extract user.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}

        for field_name, field_value in USER_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        if event.get("risk") and include_normalization:
            risk_level = event.get("risk")
            normalized_score = None
            risk_category = ""
            if risk_level == "A":
                normalized_score = 800
                risk_category = "Low"
            elif risk_level == "B":
                normalized_score = 600
                risk_category = "Medium"
            elif risk_level == "C":
                normalized_score = 400
                risk_category = "High"
            elif risk_level == "D":
                normalized_score = 200
                risk_category = "Critical"
            elif risk_level == "F":
                normalized_score = 1
                risk_category = "Critical"
            else:
                err_msg = f"Invalid risk '{risk_level}' found in response."
                self.logger.error(message=f"{self.log_prefix}: {err_msg}")
                raise MimecastPluginException(err_msg)
            self.add_field(
                extracted_fields, "Netskope Normalized Score", normalized_score
            )
            self.add_field(
                extracted_fields, "Netskope Risk Category", risk_category
            )

        return extracted_fields

    def is_email(self, address):
        """Validate email address."""
        # Simple email regex pattern
        pattern = EMAIL_ADDRESS_REGEX
        return re.match(pattern, address) is not None

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Mimecast.

        Returns:
            List: List of records to be stored on the platform.
        """
        total_records = []
        skip_count = 0
        entity_name = entity.lower()
        if entity == "Users":
            self.logger.info(
                f"{self.log_prefix}: Fetching {entity_name} from "
                f"{PLATFORM_NAME} platform."
            )
            try:
                fetched_records = self._get_all_users()
                if fetched_records:
                    self.logger.debug(
                        f"{self.log_prefix}: Processing "
                        f"{len(fetched_records)} records."
                    )

                    for record in fetched_records:
                        try:
                            extracted_fields = (
                                self._extract_each_device_fields(
                                    record,
                                    include_normalization=False,
                                )
                            )
                            if extracted_fields:
                                total_records.append(extracted_fields)
                            else:
                                skip_count += 1
                        except MimecastPluginException:
                            skip_count += 1
                        except Exception as err:
                            email_address = record.get("emailAddress")
                            err_msg = (
                                "Unable to extract fields from user"
                                f' having Email Address "{email_address}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} Error: {err}"
                                ),
                                details=f"Record: {record}",
                            )
                            skip_count += 1
            except MimecastPluginException:
                raise
            except Exception as e:
                err_msg = "An error occurred while fetching records."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastPluginException(err_msg)

            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} {entity_name}"
                    f" because they might not contain Email Address"
                    " in their response or fields could "
                    "not be extracted from them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {len(total_records)} {entity_name} "
                f"from {PLATFORM_NAME} platform."
            )
            return total_records

        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = []
        entity_name = entity.lower()
        skip_count = 0
        if entity == "Users":
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)} {entity_name}"
                f" records from {PLATFORM_NAME}."
            )
            user_list = []
            for record in records:
                if record.get("User Email"):
                    user_list.append(record.get("User Email"))

            log_msg = (
                f"{len(user_list)} user record(s) will be updated out"
                f" of {len(records)} records."
            )
            if len(records) - len(user_list) > 0:
                log_msg += (
                    f" Skipped {len(records) - len(user_list)} user(s) as they"
                    " do not have User Email field in them."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            try:
                fetched_records = self._get_all_users()
                if fetched_records:
                    for record in fetched_records:
                        try:
                            extracted_fields = (
                                self._extract_each_device_fields(
                                    record,
                                    include_normalization=True,
                                )
                            )
                            if extracted_fields:
                                updated_records.append(extracted_fields)
                            else:
                                skip_count += 1
                        except MimecastPluginException:
                            skip_count += 1
                        except Exception as err:
                            email_address = record.get("emailAddress")
                            err_msg = (
                                "Unable to extract fields from user"
                                f' having Email Address "{email_address}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} Error: {err}"
                                ),
                                details=f"Record: {record}",
                            )
                            skip_count += 1

            except MimecastPluginException:
                raise
            except Exception as e:
                err_msg = "An error occurred while updating records."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastPluginException(err_msg)

            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} {entity_name}"
                    f" because they might not contain Email Address"
                    " in their response or fields could "
                    "not be extracted from them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated "
                f"{len(updated_records)} {entity_name} record(s)"
                f" out of {len(records)} from {PLATFORM_NAME}."
            )

            return updated_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

    def get_actions(self) -> list[ActionWithoutParams]:
        """Get Available actions."""
        return [
            ActionWithoutParams(label="Add to Group", value="add"),
            ActionWithoutParams(label="Remove from Group", value="remove"),
            ActionWithoutParams(label="No Action", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action."""
        email_field = [
            {
                "label": "User Email",
                "key": "email",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Email ID of the user to perform the action on."
                ),
            }
        ]

        if action.value == "generate":
            return []

        groups = self._get_all_groups(self.configuration)
        groups = sorted(groups, key=lambda g: g.get("name", "").lower())
        new_group_dict = json.dumps({"id": "create"})

        if action.value == "add":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("name"),
                            "value": json.dumps(g),
                        }
                        for g in groups
                    ]
                    + [{"key": "Create New Group", "value": new_group_dict}],
                    "default": (
                        json.dumps(groups[0]) if groups else new_group_dict
                    ),
                    "mandatory": True,
                    "description": (
                        "Select an existing group from the available"
                        " options or opt to create a new group by "
                        "selecting 'Create New Group' for "
                        "adding users into it."
                    ),
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "A_Cloud_Exchange",
                    "mandatory": False,
                    "description": (
                        "Add a new group name if you have opted for "
                        "the 'Create New Group' actions from "
                        "the above section on Group."
                    ),
                },
            ]

        elif action.value == "remove":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("name"),
                            "value": json.dumps(g),
                        }
                        for g in groups
                    ],
                    "default": (
                        json.dumps(groups[0])
                        if groups
                        else f"No groups found on {PLATFORM_NAME} platform."
                    ),
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def execute_action(self, action: Action):
        """Execute action on the user."""
        action_label = action.label
        action_parameters = action.parameters
        user = action_parameters.get("email", "")
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action."
        )
        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {user}"
            )
            return
        elif not self.is_email(user):
            error_msg = (
                f"{PLATFORM_NAME} plugin expects "
                "the value of 'User Email' parameter to be a "
                "valid email hence skipping "
                f"execution of action {action_label} on '{user}'."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            raise MimecastPluginException(error_msg)

        users = self._get_all_users()
        match = self._find_user_by_email(users, user)

        if match is None:
            self.logger.info(
                f"{self.log_prefix}: The user with email address"
                f" {user} was not found on {PLATFORM_NAME}. "
                f"Hence cannot perform {action_label} action."
            )
            return

        if action.value == "add":
            group_info = json.loads(action_parameters.get("group", ""))
            if group_info.get("id", "") == "create":
                group_name = action_parameters.get("name", "").strip()
                groups = self._get_all_groups(self.configuration)
                match_group = self._find_group_by_name(groups, group_name)
                if not match_group:
                    group = self._create_group(self.configuration, group_name)
                    group_info = group.get("data", [{}])[0]
                else:
                    group_info = match_group

            self._add_to_group(
                self.configuration,
                match.get("emailAddress", ""),
                group_info.get("id", ""),
                group_info.get("description", ""),
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action"
                f" '{action_label}' on user with email {user}."
            )
        elif action.value == "remove":
            group_info = json.loads(action_parameters.get("group", ""))
            self._remove_from_group(
                self.configuration,
                match.get("emailAddress", ""),
                group_info.get("id", ""),
                group_info.get("description", ""),
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action"
                f" '{action_label}' on user with email {user}."
            )

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Mimecast action configuration."""
        try:
            validation_err_msg = "Unsupported action provided."
            if action.value not in ["add", "remove", "generate"]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}"
                        "Supported actions are 'Add to Group', "
                        "'Remove from Group' and 'No action'."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=(
                        f"{validation_err_msg} Supported actions are "
                        "'Add to Group', 'Remove from Group' and 'No action'."
                    ),
                )
            if action.value == "generate":
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            create_dict = json.dumps({"id": "create"})
            email = action.parameters.get("email", "")
            if not email:
                err_msg = "User Email is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(email, str):
                err_msg = "Invalid User Email provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif isinstance(email, str) and "$" in email:
                log_msg = (
                    "User Email contains the Source Field"
                    " hence validation for this field will be performed"
                    f" while executing the {action.label} action."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")

            groups = self._get_all_groups(
                self.configuration, is_validation=True
            )
            if create_dict not in action.parameters.get("group", "") and (
                "$" in action.parameters.get("group")
            ):
                err_msg = (
                    "Group contains the Source Field."
                    " Please select group from Static Field dropdown only."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if create_dict not in action.parameters.get(
                "group", ""
            ) and not any(
                map(
                    lambda g: g.get("id", "")
                    == json.loads(action.parameters.get("group", ""))["id"],
                    groups,
                )
            ):
                err_msg = (
                    "Invalid Group Name Provided in action parameters. "
                    "Select group names from drop down list."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if (
                action.value == "add"
                and create_dict in action.parameters.get("group", "")
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                err_msg = (
                    "Invalid Group Name provided in action parameters,"
                    " Group Name can not be empty."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if (
                action.value == "add"
                and create_dict in action.parameters.get("group", "")
                and "$" in action.parameters.get("name", "")
            ):
                err_msg = (
                    "New Group Name contains the Source Field."
                    " Please provide a group name using Static Field only."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if (
                action.value == "remove"
                and f"No groups found on {PLATFORM_NAME} platform."
                in action.parameters.get("group", "")
            ):
                err_msg = (
                    "Action will not be saved as no groups"
                    " found on {} server.".format(PLATFORM_NAME)
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except Exception as e:
            err_msg = "Unexpected error occurred while validating actions."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_credentials(self, configuration: dict):
        """Validate credentials by making REST API call."""
        try:
            validation_err_msg = "Validation error occurred"
            url, headers = self._get_auth_headers(
                configuration, "/api/account/get-account"
            )
            response = self.mimecast_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg="validating the credentials",
                is_handle_error_required=True,
                is_validation=True,
            )
            failures = response.get("fail", [])
            if not failures:
                return ValidationResult(
                    success=True,
                    message=(
                        "Validation successful for {} {} Plugin.".format(
                            MODULE_NAME, PLATFORM_NAME
                        )
                    ),
                ), response.get("data", [{}])[0].get("packages", [])
            return (
                ValidationResult(
                    success=False,
                    message="{}: {}. Error: {}".format(
                        self.log_prefix,
                        validation_err_msg,
                        ", ".join(self._parse_errors(failures)),
                    ),
                ),
                None,
            )
        except MimecastPluginException:
            raise
        except Exception:
            err_msg = f"{validation_err_msg} while validating credentials."
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

    def validate(self, configuration: Dict):
        """Validate Mimecast configuration."""

        validation_err_msg = "Validation error occurred."
        base_url = configuration.get("url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            err_msg = (
                "Invalid Base URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Application ID.
        app_id = configuration.get("app_id", "").strip()
        if not app_id:
            err_msg = "Application ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(app_id, str)):
            err_msg = (
                "Invalid Application ID provided in the "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Application Key.
        app_key = configuration.get("app_key", "")
        if not app_key:
            err_msg = "Application Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(app_key, str)):
            err_msg = (
                "Invalid Application Key provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Access Key.
        access_key = configuration.get("access_key", "")
        if not access_key:
            err_msg = "Access Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(access_key, str)):
            err_msg = (
                "Invalid Access Key provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Secret Key.
        secret_key = configuration.get("secret_key", "")
        if not secret_key:
            err_msg = "Secret Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(secret_key, str)) or not re.match(
            SECRET_KEY_REGEX,
            secret_key,
        ):
            err_msg = (
                "Invalid Secret Key provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        validation_result, packages = self._validate_credentials(configuration)

        if not validation_result.success:
            return validation_result

        if "Awareness Training [1078]" not in packages:
            err_msg = (
                "Awareness Training' package is not enabled in "
                "configured account and hence fetching score is not possible."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return validation_result

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User Email",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Risk",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Netskope Risk Category",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
