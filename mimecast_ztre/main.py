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
import re
import sys
from typing import List, Dict, Optional
import traceback

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
    EMAIL_ADDRESS_REGEX,
    BASE_URL,
    GET_ACCOUNT_DETAILS_ENDPOINT,
    FIND_GROUPS_ENDPOINT,
    GET_SAFE_SCORE_DETAILS_ENDPOINT,
    CREATE_GROUP_ENDPOINT,
    ADD_GROUP_MEMBER_ENDPOINT,
    REMOVE_GROUP_MEMBER_ENDPOINT,
    MIMECAST_SCORE_MAPPING,
    NETSKOPE_RISK_CATEGORY_MAPPING,
    ADD_TO_GROUP_BATCH_SIZE,
    MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
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
        """
        Parse the error message from Mimecast response.
        args:
            failures: Mimecast response
        returns:
            List: List of error messages
        """
        messages = set()
        for failure in failures:
            message = failure.get("message")
            errors = failure.get("errors", [])
            if message:
                messages.add(message)
            if errors and isinstance(errors, list):
                for error in errors:
                    messages.add(error.get("message"))
        return list(messages)

    def split_into_size(self, total_payload):
        """
        Split a list into parts, each approximately with a target
            size in 2048 bytes.

        Parameters:
        - total_payload: The list of data to be split.

        Returns:
        - A list of parts, each with a total size approximately equal
            to the target size.
        """
        result = []
        current_part = []
        current_size_bytes = 0
        chunk_part = 1
        for chunk in total_payload:
            item_size_bytes = sys.getsizeof(json.dumps(chunk))
            if (
                current_size_bytes + item_size_bytes
                <= MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES
            ):
                current_part.append(chunk)
                current_size_bytes += item_size_bytes
            else:
                self.logger.debug(
                    f"{self.log_prefix}: Remove from group API payload"
                    f" chunk size for chunk {chunk_part}"
                    f" is {current_size_bytes} bytes."
                )
                chunk_part += 1
                result.append(current_part)
                current_part = [chunk]
                current_size_bytes = item_size_bytes

        if current_part:
            self.logger.debug(
                f"{self.log_prefix}: Remove from group API payload"
                f" Chunk size for chunk {chunk_part}"
                f" is {current_size_bytes} bytes."
            )
            result.append(current_part)

        return result

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

        self.logger.debug(
            f"{self.log_prefix}: Removing {user_id} "
            f"from the group '{group_name}'."
        )
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        request_url = f"{BASE_URL}/{REMOVE_GROUP_MEMBER_ENDPOINT}"

        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"removing {user_id} from the group '{group_name}'",
                is_handle_error_required=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while removing {user_id} "
                    f"from group '{group_name}'."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(err_msg)
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                f"An unexpected error occurred while removing {user_id} "
                f"from group '{group_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _bulk_remove_from_group(
        self,
        configuration: Dict,
        payload: List,
        group_name: str,
        action_label: str,
        skip_count: int = 0,
    ):
        """Remove users from group.

        Args:
            configuration (Dict): Configuration parameters.
            payload (List): List of dictionaries, each dictionary
                            representing the payload for removing a
                            user from a group.
            group_name (str): Name of the group.
            action_label (str): Action label
            skip_count (int): Number of users skipped
        """

        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        request_url = f"{BASE_URL}/{REMOVE_GROUP_MEMBER_ENDPOINT}"
        total_users = len(payload)
        self.logger.info(
            f"{self.log_prefix}: Removing {total_users} "
            f"user(s) from group {group_name}."
        )
        batch_count = 1
        skip_count = skip_count

        try:
            payload_chunks = self.split_into_size(payload)
            for chunk in payload_chunks:
                body = {"data": chunk}
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    data=json.dumps(body),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"removing {len(chunk)} user(s) from group"
                        f" {group_name} for batch {batch_count}"
                    ),
                    is_handle_error_required=True,
                    configuration=configuration,
                )
                data = response.get("data", [])
                failures = response.get("fail", [])
                if failures:
                    skip = len(chunk) - len(data)
                    err_msg = (
                        f"An error occurred while removing {skip} "
                        f"user(s) for batch {batch_count} from group "
                        f"{group_name}. Hence these user(s) records"
                        " will be skipped."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {response}",
                    )
                    skip_count += skip
                    batch_count += 1
                    continue

                self.logger.info(
                    f"{self.log_prefix}: Successfully removed {len(data)}"
                    f" user(s) from group {group_name} "
                    f"for batch {batch_count}."
                )
                batch_count += 1

            msg = (
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {total_users-skip_count} "
                f"user(s)."
            )
            if skip_count > 0:
                msg += (
                    f" Skipped removing {skip_count} user(s) as "
                    "an error occurred while removing these "
                    f"user(s) from group {group_name}."
                )

            self.logger.info(f"{self.log_prefix}: {msg}")
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An unexpected error occurred while removing "
                f"user(s) from group {group_name}."
            )
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

        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        self.logger.debug(
            f"{self.log_prefix}: Adding user {user_id} "
            f"to group '{group_name}'."
        )
        request_url = f"{BASE_URL}/{ADD_GROUP_MEMBER_ENDPOINT}"

        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"adding user {user_id} to group '{group_name}'",
                is_handle_error_required=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while adding {user_id} "
                    f"to group '{group_name}'."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(error)
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                f"An unexpected error occurred while adding {user_id} "
                f"to group '{group_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _bulk_add_to_group(
        self,
        configuration: Dict,
        payload: List,
        group_name: str,
        action_label: str,
        skip_count: int = 0,
    ):
        """Add users to group.

        Args:
            configuration (Dict): Configuration parameters.
            payload (List): List of dictionaries, each dictionary
                            representing the payload for adding a user
                            to a group.
            group_name (str): Name of the group.
            action_label (str): Action label
            skip_count (int): Number of users skipped
        """

        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        request_url = f"{BASE_URL}/{ADD_GROUP_MEMBER_ENDPOINT}"
        total_users = len(payload)
        self.logger.info(
            f"{self.log_prefix}: Adding {total_users} "
            f"user(s) to group {group_name} in batch"
            f" of {ADD_TO_GROUP_BATCH_SIZE}."
        )
        batch_count = 1
        skip_count = skip_count
        try:
            payload_chunks = [
                payload[i : i + ADD_TO_GROUP_BATCH_SIZE]
                for i in range(0, len(payload), ADD_TO_GROUP_BATCH_SIZE)
            ]
            for chunk in payload_chunks:
                body = {"data": chunk}
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    data=json.dumps(body),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"adding {len(chunk)} user(s) to group {group_name}"
                        f" for batch {batch_count}"
                    ),
                    is_handle_error_required=True,
                    configuration=configuration,
                )
                data = response.get("data", [])
                failures = response.get("fail", [])
                if failures:
                    skip = len(chunk) - len(data)
                    err_msg = (
                        f"An error occurred while adding {skip} "
                        f"user(s) for batch {batch_count} to "
                        f"group {group_name}. Hence these user(s)"
                        " records will be skipped."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {response}",
                    )
                    skip_count += skip
                    batch_count += 1
                    continue
                self.logger.info(
                    f"{self.log_prefix}: Successfully added {len(chunk)}"
                    f" user(s) to group {group_name} for batch {batch_count}."
                )
                batch_count += 1

            msg = (
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {total_users-skip_count} "
                f"user(s)."
            )
            if skip_count > 0:
                msg += (
                    f" Skipped adding {skip_count} user(s) as "
                    "an error occurred while adding these "
                    f"user(s) to group {group_name}."
                )

            self.logger.info(f"{self.log_prefix}: {msg}")
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An unexpected error occurred while adding "
                f"user(s) to group {group_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

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

    def _get_all_users(self) -> List:
        """Get list of all the users.

        Returns:
            List: List of all the users.
        """
        records = []
        nextPageToken = ""
        headers = self.mimecast_helper.get_headers(
            self.configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {
            "meta": {
                "pagination": {
                    "pageSize": MAX_PAGE_SIZE,
                    "pageToken": nextPageToken,
                }
            }
        }
        request_url = f"{BASE_URL}/{GET_SAFE_SCORE_DETAILS_ENDPOINT}"

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
                    logger_msg=f"fetching user details from {PLATFORM_NAME}",
                    is_handle_error_required=True,
                    configuration=self.configuration,
                )
                failures = response.get("fail", [])
                if failures:
                    err_msg = (
                        "An error occurred while fetching "
                        f"users from {PLATFORM_NAME}."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {str(response)}",
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
                err_msg = (
                    "An unexpected error occurred while "
                    f"fetching user details from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastPluginException(err_msg)

        return records

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
        normalized_score_skip_count = 0

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

        risk_level = event.get("risk")
        if risk_level and include_normalization:
            normalized_score = MIMECAST_SCORE_MAPPING.get(risk_level)
            netskope_risk_category = NETSKOPE_RISK_CATEGORY_MAPPING.get(
                risk_level
            )
            if not normalized_score:
                err_msg = (
                    f"{self.log_prefix}: Invalid "
                    f"Risk '{risk_level}' found in response "
                    f"for User '{event.get('emailAddress')}'. "
                    "Netskope Normalized Score will not be "
                    "calculated for this user. "
                    "Valid Risk range is A to F."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Risk : '{risk_level}'",
                )
                normalized_score_skip_count += 1

            self.add_field(
                extracted_fields, "Netskope Normalized Score", normalized_score
            )
            self.add_field(
                extracted_fields,
                "Netskope Risk Category",
                netskope_risk_category,
            )

        return extracted_fields, normalized_score_skip_count

    def is_email(self, address):
        """
        Validate email address.

        Args:
            address (str): Email address to validate.

        Returns:
            bool: True if valid else False
        """
        return re.match(EMAIL_ADDRESS_REGEX, address) is not None

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Mimecast action configuration."""
        try:
            validation_err_msg = "Unsupported action provided."
            if action.value not in ["add", "remove", "generate"]:
                msg = (
                    "Supported actions are 'Add to group', "
                    "'Remove from group' and 'No action'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {validation_err_msg} {msg}",
                )
                return ValidationResult(
                    success=False,
                    message=f"{validation_err_msg} {msg}",
                )
            if action.value == "generate":
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated "
                    f"action configuration for '{action.label}'."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )

            create_dict = json.dumps({"id": "create"})
            email = action.parameters.get("email", "")

            if not email:
                err_msg = "User Email is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if ("$" not in email) and (
                not isinstance(email, str) or not self.is_email(email)
            ):
                err_msg = (
                    "Invalid User Email value provided in action parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif isinstance(email, str) and "$" in email:
                log_msg = (
                    "User Email contains the source field"
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
                    lambda g: (
                        isinstance(
                            group_dict := json.loads(
                                action.parameters.get("group", "")
                            ),
                            dict,
                        )
                        and "id" in group_dict
                        and g.get("id", "") == group_dict["id"]
                    ),
                    groups,
                )
            ):
                err_msg = (
                    "Invalid Group name Provided in action parameters. "
                    "Select Group name from drop down list."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if (
                action.value == "add"
                and create_dict in action.parameters.get("group", "")
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                err_msg = (
                    "Invalid New Group Name provided in action parameters,"
                    " New Group Name can not be empty."
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
                    f" found on {PLATFORM_NAME} server."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except MimecastPluginException:
            raise
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
                        " options or choose 'Create New Group' to "
                        "create a new group and add users to it. "
                        "Select Group from Static field dropdown only."
                    ),
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "A_Cloud_Exchange",
                    "mandatory": False,
                    "description": (
                        "Create group with given name. Provide New"
                        " Group Name in Static field if you have selected"
                        " 'Create New Group' in Group."
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
                    "description": (
                        "Group to remove the user from. "
                        "Select Group from Static field dropdown only."
                    ),
                }
            ]

    def execute_action(self, action: Action):
        """
        Execute action on the user.

        Args:
            action (Action): Action to be executed.
        """
        action_label = action.label
        action_parameters = action.parameters
        user = action_parameters.get("email", "")
        self.logger.debug(
            f"{self.log_prefix}: Executing action "
            f"'{action_label}' for user '{user}'."
        )
        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}'."
            )
            return
        elif not self.is_email(user):
            error_msg = (
                f"{PLATFORM_NAME} plugin expects "
                "the value of 'User Email' parameter to be a "
                "valid email hence skipping "
                f"execution of action '{action_label}' on '{user}'."
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

            group_name = None
            if group_info.get("description", ""):
                group_name = group_info.get("description", "")
            else:
                group_name = group_info.get("name", "")

            self._add_to_group(
                self.configuration,
                match.get("emailAddress", ""),
                group_info.get("id", ""),
                group_name,
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
                group_info.get("name", ""),
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action"
                f" '{action_label}' on user with email {user}."
            )

    def execute_actions(self, actions: List[Action]):
        """
        Execute actions in bulk.

        Args:
            actions (List[Action]): List of actions to be executed.
        """

        if len(actions) > 0:
            action = actions[0]
            action_label = action.label
            action_value = action.value
            self.logger.debug(
                f"{self.log_prefix}: Executing '{action_label}'"
                f" action on {len(actions)} user(s)."
            )
            if action_value == "generate":
                self.logger.info(
                    f"{self.log_prefix}: Successfully performed action "
                    f"'{action_label}'."
                )
                return

            if action_value == "add":
                skip_count = 0
                group_name = None
                total_payload = []
                action_parameters = action.parameters
                users = self._get_all_users()
                groups = self._get_all_groups(self.configuration)

                group_info = json.loads(action_parameters.get("group", ""))
                if group_info.get("id", "") == "create":
                    group_name = action_parameters.get("name", "").strip()
                    match_group = self._find_group_by_name(groups, group_name)
                    if not match_group:
                        group = self._create_group(
                            self.configuration, group_name
                        )
                        group_info = group.get("data", [{}])[0]
                    else:
                        group_info = match_group

                if group_info.get("description", ""):
                    group_name = group_info.get("description", "")
                else:
                    group_name = group_info.get("name", "")

                for action in actions:
                    action_parameters = action.parameters
                    user = action_parameters.get("email", "")
                    if not self.is_email(user):
                        error_msg = (
                            f"{PLATFORM_NAME} plugin expects "
                            "the value of 'User Email' parameter"
                            "valid email hence skipping to be a "
                            f"execution of action '{action_label}'"
                            f" on '{user}'."
                        )
                        self.logger.error(f"{self.log_prefix}: {error_msg}")
                        skip_count += 1
                        continue

                    match = self._find_user_by_email(users, user)
                    if match is None:
                        self.logger.info(
                            f"{self.log_prefix}: The user with email address"
                            f" {user} was not found on {PLATFORM_NAME}. "
                            f"Hence cannot perform {action_label} action "
                            f"on '{user}'."
                        )
                        skip_count += 1
                        continue

                    total_payload.append(
                        {
                            "id": group_info.get("id", ""),
                            "emailAddress": match.get("emailAddress", ""),
                        }
                    )

                self._bulk_add_to_group(
                    self.configuration,
                    total_payload,
                    group_name,
                    action_label,
                    skip_count,
                )

            elif action_value == "remove":
                skip_count = 0
                group_name = None
                total_payload = []
                action_parameters = action.parameters
                users = self._get_all_users()
                group_info = json.loads(action_parameters.get("group", ""))
                group_name = group_info.get("name", "")
                for action in actions:
                    action_parameters = action.parameters
                    user = action_parameters.get("email", "")
                    if not self.is_email(user):
                        error_msg = (
                            f"{PLATFORM_NAME} plugin expects "
                            "the value of 'User Email' parameter"
                            "valid email hence skipping  to be a "
                            f"execution of action '{action_label}'"
                            f" on '{user}'."
                        )
                        self.logger.error(f"{self.log_prefix}: {error_msg}")
                        skip_count += 1
                        continue

                    match = self._find_user_by_email(users, user)
                    if match is None:
                        self.logger.info(
                            f"{self.log_prefix}: The user with email address"
                            f" {user} was not found on {PLATFORM_NAME}. "
                            f"Hence cannot perform {action_label} action "
                            f"on '{user}'."
                        )
                        skip_count += 1
                        continue

                    total_payload.append(
                        {
                            "id": group_info.get("id", ""),
                            "emailAddress": match.get("emailAddress", ""),
                        }
                    )

                self._bulk_remove_from_group(
                    self.configuration,
                    total_payload,
                    group_name,
                    action_label,
                    skip_count,
                )

    def _create_group(self, configuration: Dict, name: str):
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters
            name (str): Name of the group to create.

        Returns:
            Dict: Newly created group dictionary.
        """
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {"data": [{"description": name}]}
        request_url = f"{BASE_URL}/{CREATE_GROUP_ENDPOINT}"
        logger_msg = f"Creating group with name {name}"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
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
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while creating group with name {name}."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                )
                raise MimecastPluginException(error)
            return response
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An Unexpected error occurred while creating"
                f" group with name {name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

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

        page_count = 1
        all_groups = []
        nextPageToken = ""
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {
            "meta": {
                "pagination": {
                    "pageSize": MAX_PAGE_SIZE,
                    "pageToken": nextPageToken,
                }
            }
        }
        url = f"{BASE_URL}/{FIND_GROUPS_ENDPOINT}"
        try:
            while True:
                per_page_fetched_count = 0
                groups_fetched_per_page = []
                groups = self.mimecast_helper.api_helper(
                    url=url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=f"fetching all groups from {PLATFORM_NAME}",
                    is_handle_error_required=True,
                    is_validation=is_validation,
                    configuration=configuration,
                )

                failures = groups.get("fail", [])
                if failures:
                    err_msg = (
                        "An error occurred while fetching "
                        f"groups from {PLATFORM_NAME}."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {str(groups)}",
                    )
                    raise MimecastPluginException(error)

                groups_fetched_per_page = [
                    {"id": group.get("id"), "name": group.get("description")}
                    for group in groups.get("data", [{}])[0].get("folders", [])
                    if group.get("id") and group.get("description")
                ]
                all_groups += groups_fetched_per_page
                per_page_fetched_count = len(groups_fetched_per_page)
                nextPage = (
                    groups.get("meta", {})
                    .get("pagination", {})
                    .get("next", "")
                )
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{per_page_fetched_count} groups from "
                    f"{PLATFORM_NAME} for page {page_count}."
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                    page_count += 1
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
                "An unexpected error occurred while "
                "retrieving existing group details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Mimecast.

        Args:
            entity (str): Entity name.

        Returns:
            List: List of records to be stored on the platform.
        """
        total_records = []
        skip_count = 0
        entity_name = entity.lower()

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )
        try:
            fetched_records = self._get_all_users()
            if fetched_records:
                for record in fetched_records:
                    try:
                        extracted_fields, _ = self._extract_each_device_fields(
                            record,
                            include_normalization=False,
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
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching "
                f"{entity_name} from {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
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

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = []
        entity_name = entity.lower()
        total_normalized_score_skip_count = 0
        skip_count = 0

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" records from {PLATFORM_NAME}."
        )
        user_list = set()
        for record in records:
            user_email = record.get("User Email")
            if user_email:
                user_list.add(user_email)

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
                        if record.get("emailAddress"):
                            (extracted_fields, normalized_score_skip_count) = (
                                self._extract_each_device_fields(
                                    record,
                                    include_normalization=True,
                                )
                            )
                            if extracted_fields:
                                current_email = extracted_fields.get(
                                    "User Email", ""
                                )
                                if current_email in user_list:
                                    updated_records.append(extracted_fields)
                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1

                            total_normalized_score_skip_count += (
                                normalized_score_skip_count
                            )
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
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred "
                f"while updating {entity_name} "
                f"from {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
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

        if total_normalized_score_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating "
                "Netskope Normalized Score for "
                f"{total_normalized_score_skip_count} {entity_name}"
                " record(s) as invalid Risk value received from the "
                f"{PLATFORM_NAME} platform."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{len(updated_records)} {entity_name} record(s)"
            f" out of {len(records)} from {PLATFORM_NAME}."
        )

        return updated_records

    def get_actions(self) -> list[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def _validate_auth_params(self, configuration: dict):
        """Validate the authentication params with Mimecast platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            validation_err_msg = "Validation error occurred"
            headers = self.mimecast_helper.get_headers(
                configuration,
                is_handle_error_required=True,
                is_validation=True,
                proxy=self.proxy,
                verify=self.ssl_validation,
            )
            url = f"{BASE_URL}/{GET_ACCOUNT_DETAILS_ENDPOINT}"

            response = self.mimecast_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"checking connectivity with {PLATFORM_NAME} platform"
                ),
                is_handle_error_required=True,
                regenerate_auth_token=False,
                is_validation=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if not failures:
                msg = (
                    f"Validation successful for {MODULE_NAME} "
                    f"{PLATFORM_NAME} plugin."
                )
                self.logger.debug(f"{self.log_prefix}: {msg}")
                packages = response.get("data", [{}])[0].get("packages", [])

                if "Awareness Training [1078]" not in packages:
                    err_msg = (
                        "Awareness Training' package is not enabled in "
                        "configured account and hence fetching score"
                        " is not possible."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                return ValidationResult(
                    success=True,
                    message=msg,
                )
            return ValidationResult(
                success=False,
                message="{}: {}. Error: {}".format(
                    self.log_prefix,
                    validation_err_msg,
                    ", ".join(self._parse_errors(failures)),
                ),
            )
        except MimecastPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )

        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: Dict):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """

        validation_err_msg = "Validation error occurred."

        # Validate Client ID.
        client_id = configuration.get("client_id", "")
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(client_id, str)):
            err_msg = (
                "Invalid Client ID provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Client Secret Key.
        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_auth_params(configuration)

    def get_entities(self) -> list[Entity]:
        """
        Get available entities.

        returns:
            List: List of available entities
        """
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
