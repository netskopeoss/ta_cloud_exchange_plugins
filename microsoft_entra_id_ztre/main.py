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

CRE Microsoft Entra ID Plugin.
"""

import datetime
import json
import time
import traceback
from typing import Dict, List, Optional

from pydantic import ValidationError

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)

from .utils.constants import (
    BASE_URL,
    GROUP_TYPES,
    MAX_GROUPS,
    MODULE_NAME,
    PAGE_RECORD_SCORE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)
from .utils.helper import MicrosoftEntraIDException, MicrosoftEntraIDPluginHelper


class MicrosoftEntraIDPlugin(PluginBase):
    """Microsoft Entra ID plugin implementation."""

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
        self.entra_ID_helper = MicrosoftEntraIDPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MicrosoftEntraIDPlugin.metadata
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

    def _add_to_group(self, user_info: dict, group_info: dict, headers: dict = {}) -> None:
        """Add specified user to the specified group.

        Args:
            user_info (dict): Dictionary containing user email and id.
            group_id (str): Group ID of the group.

        Raises:
            MicrosoftEntraIDException: If any unexpected error occurred
            from API side
        """
        user_id, user_email = user_info.get("id", ""), user_info.get("email", "")
        group_id, group_name = group_info.get("id", ""), group_info.get(
            "displayName",
            ""
        )
        logger_msg = (
            "user with email '{}' to group "
            "named '{}' and ID '{}'".format(user_email, group_name, group_id)
        )
        self.logger.info(f"{self.log_prefix}: Adding {logger_msg}.")
        headers = self.get_headers(headers)
        url = f"{BASE_URL}/groups/{group_id}/members/$ref"
        data = {"@odata.id": f"{BASE_URL}/directoryObjects/{user_id}"}

        response = self.entra_ID_helper.api_helper(
            url=url,
            method="POST",
            headers=headers,
            data=json.dumps(data),
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=f"adding {logger_msg}",
            is_handle_error_required=False,
        )

        if response.status_code == 204:
            # We return because there is an empty JSON response
            # So it is successful and we do not need to anything
            # more after adding the member to group
            self.logger.info(
                f"{self.log_prefix}: Successfully added {logger_msg}."
            )
            return
        elif response.status_code == 400:
            resp_json = self.entra_ID_helper.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            )
            self.logger.warn(
                (
                    "{}: Unable to add {}. This error may occur if user "
                    "already exist in group. Error: {}".format(
                        self.log_prefix,
                        logger_msg,
                        str(api_err_msg),
                    )
                )
            )
            return

        self.entra_ID_helper.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _remove_from_group(self, user_info: dict, group_info: str, headers: dict = {}) -> None:
        """Remove specified user to the specified group.

        Args:
            user_info (dict): Dictionary containing user email and id.
            group_info (str): Dictionary containing group email and id.

        Raises:
            MicrosoftEntraIDException: If any unexpected error occurred
            from API side
        """
        user_id, user_email = user_info.get("id", ""), user_info.get("email", "")

        group_id, group_name = group_info.get("id", ""), group_info.get(
            "displayName",
            ""
        )
        logger_msg = (
            "user with email '{}' from group named '{}' "
            "and ID '{}'".format(user_email, group_name, group_id)
        )
        self.logger.info(f"{self.log_prefix}: Removing {logger_msg}.")
        headers = self.get_headers(headers)
        url = f"{BASE_URL}/groups/{group_id}/members/{user_id}/$ref"

        response = self.entra_ID_helper.api_helper(
            url=url,
            method="DELETE",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )

        if response.status_code == 204:
            self.logger.info(
                "{}: Successfully removed {}.".format(
                    self.log_prefix, logger_msg
                )
            )
            return

        elif response.status_code == 404:
            resp_json = self.entra_ID_helper.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            )
            err_msg = (
                "{}: Unable to remove {}. This error may occur if user does"
                " not exist in the group. Error: {}".format(
                    self.log_prefix,
                    logger_msg,
                    api_err_msg,
                )
            )
            self.logger.warn(err_msg)
            return

        self.entra_ID_helper.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _create_group(self, group_name: str, group_type: str, headers: dict = {}) -> Dict:
        """Create a new group with name.

        Args:
            group_name (str): Name of the group to create.
            group_type (str): Type of the group.

        Returns:
            Dict: Newly created group dictionary.
        """
        self.logger.info(
            "{}: Creating new group named '{}' of type '{}' on "
            "{} platform.".format(
                self.log_prefix, group_name, group_type, PLATFORM_NAME
            )
        )
        # details required of group will be in the body of request
        body = {
            "description": (
                "Created group from Netskope Cloud Exchange via"
                " {} User Risk Exchange plugin.".format(PLATFORM_NAME)
            ),
            "displayName": group_name,
            "mailNickname": group_name.replace(" ", ""),
        }

        if group_type == "Microsoft 365":
            # If Microsoft 365 is selected create Microsoft 365 group.
            body.update(
                {
                    "groupTypes": [
                        "Unified"
                    ],  # Unified means Microsoft 365 group.
                    "mailEnabled": True,
                    "securityEnabled": False,
                }
            )
        else:
            body.update(
                {
                    # For security group we are not
                    # having anything in groupTypes field.
                    "groupTypes": [],
                    "mailEnabled": False,
                    "securityEnabled": True,
                }
            )
        url = f"{BASE_URL}/groups"
        headers = self.get_headers(headers)
        logger_msg = "creating new group named '{}' on {}".format(
            group_name, PLATFORM_NAME
        )
        response = self.entra_ID_helper.api_helper(
            url=url,
            method="POST",
            headers=headers,
            data=json.dumps(body),
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )

        if response.status_code in [200, 201]:
            self.logger.info(
                "{}: Successfully created group named '{}' of type '{}' on "
                "{} platform.".format(
                    self.log_prefix, group_name, group_type, PLATFORM_NAME
                )
            )
            response_json = self.entra_ID_helper.parse_response(response=response)
            return {
                "id": response_json.get("id", ""),  # Group ID
                "displayName": response_json.get("displayName", ""),  # Group Name
            }

        elif response.status_code == 400:
            resp_json = self.entra_ID_helper.parse_response(response=response)
            err_msg = (
                "Unable to create group named '{}' on "
                "{} platform.".format(group_name, PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(
                    resp_json.get(
                        "error", "No error details found in API response."
                    )
                ),
            )
            raise MicrosoftEntraIDException(err_msg)

        return self.entra_ID_helper.handle_error(
            response, logger_msg
        )  # For capturing any unexpected error.

    def _get_all_groups(self, headers: dict = {}) -> List:
        """Get all group details.

        Returns:
            total_group_name_array (list): List of groups.
        """
        try:
            url = f"{BASE_URL}/groups?$filter=not groupTypes/any(s:s eq 'DynamicMembership')"  # noqa

            params = {
                "$top": MAX_GROUPS,
                "$orderby": "displayName",  # To get data in sorted order.
                "$select": "id,displayName,groupTypes",
                # We need only id,displayName and groupTypes hence
                # getting those fields only from API.
                "$count": "true",  # To enable advance query on Entra ID.
            }
            # all the group names will be added in this variable.
            total_group_name_array = []

            while True:
                headers = self.get_headers(headers)
                headers["ConsistencyLevel"] = (
                    "eventual"  # Enable advance query on Entra ID.
                )
                resp_json = self.entra_ID_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    params=params,
                    logger_msg=f"fetching groups from {PLATFORM_NAME}",
                )

                # stores the number of groups in that particular pagination query
                current_group_array = resp_json.get("value", [])
                for each_group in current_group_array:
                    if each_group.get("membershipRule", ""):
                        # Skip all the dynamic groups.
                        continue
                    group_type = each_group.get("groupTypes", [])

                    display_name = each_group.get("displayName", "")
                    if (
                        not group_type
                        and not each_group.get("mailEnabled", False)
                        and each_group.get("securityEnabled", True)
                    ):
                        total_group_name_array.append(
                            {
                                "id": each_group.get("id", ""),
                                "displayName": display_name,
                                "group_type": "Security",
                                "display_name": f"{display_name} (Security)",
                            }
                        )
                        continue
                    elif "Unified" in group_type:
                        total_group_name_array.append(
                            {
                                "id": each_group.get("id", ""),
                                "displayName": display_name,
                                "group_type": "Microsoft 365",
                                "display_name": f"{display_name} (Microsoft 365)",
                            }
                        )
                    else:
                        continue

                # if number of groups is less than page size, we know that
                # this is the last page of the request. Hence, we break
                if len(current_group_array) < MAX_GROUPS:
                    break
                # likewise this is another check for last page
                # Microsoft graph won't provide nextLink of page
                # Hence, we break
                if "@odata.nextLink" not in resp_json.keys():
                    break

                url = resp_json.get("@odata.nextLink", "")  # For pagination
                params = {}  # Reset params for next page
        except Exception as err:
            err_msg = (
                    f"Error occurred while fetching groups from "
                    f"{PLATFORM_NAME} platform. Error: {str(err)}"
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise MicrosoftEntraIDException(err_msg)

        return total_group_name_array

    def _find_group(
        self, groups: List, name: str, type: str
    ) -> Optional[Dict]:
        """Find group from list by name and type.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to group to find.
            type (str): Type of group to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if (
                group.get("displayName", "") == name
                and group.get("group_type", "") == type
            ):
                return group

    def _get_email_to_id(self, email: str, headers: dict = {}) -> dict:
        """Get unique id of the user from provided email.

        Args:
            email (str):  User Principle email.

        Raises:
            MicrosoftEntraIDException: If user with email does not exist on
            Microsoft Entra ID platform.

        Returns:
            dict: Dictionary containing user id and email.
        """
        url = f"{BASE_URL}/users/{email}"
        headers = self.get_headers(headers)
        logger_msg = (
            "fetching user details for user with email {} from {}".format(
                email, PLATFORM_NAME
            )
        )
        response = self.entra_ID_helper.api_helper(
            url=url,
            method="GET",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )

        if response.status_code == 200:
            resp_json = self.entra_ID_helper.parse_response(response=response)
            # Return email address and user id from response.
            return {"email": email, "id": resp_json.get("id", "")}

        elif response.status_code == 404:
            resp_json = self.entra_ID_helper.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            )
            err_msg = (
                "Unable to fetch user details for user with email '{}'. This "
                "error may occur if user does not exist on {} "
                "platform.".format(email, PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(api_err_msg),
            )
            raise MicrosoftEntraIDException(err_msg)

        self.entra_ID_helper.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def get_actions(self) -> List[ActionWithoutParams]:
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
            ActionWithoutParams(
                label="Confirm compromised", value="confirm_compromised"
            ),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _confirm_compromised(self, user_info: dict, headers: dict = {}) -> None:
        """Perform Confirm Compromised action on user.

        Args:
            user_info (dict): Dictionary containing user id and email.

        Raises:
            MicrosoftEntraIDException: Raises exception if unable to
            perform action on user.
        """
        user_id = user_info.get("id", "")
        user_email = user_info.get("email", "")
        url = f"{BASE_URL}/identityProtection/riskyUsers/confirmCompromised"

        headers = self.get_headers(headers)
        data = {"userIds": [user_id]}
        logger_msg = (
            "performing Confirm compromised action on user "
            "with email '{}'".format(user_email)
        )
        response = self.entra_ID_helper.api_helper(
            url=url,
            method="POST",
            headers=headers,
            data=json.dumps(data),
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )

        if response.status_code == 204:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed Confirm "
                f"compromised action on user with email '{user_email}'."
            )
            return

        self.entra_ID_helper.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def execute_action(self, action: Action):
        """Execute action on the user.

        Args:
            record: Record of a user on which action will be
            performed.
            action (Action): Action that needs to be perform on user.

        Returns:
            None
        """
        action_label = action.label
        action_parameters = action.parameters
        if action.value == "generate":
            return

        email = action_parameters.get("email", "").strip()
        if not email:
            err_msg = (
                "Email not found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return
        elif not isinstance(email, str):
            err_msg = (
                "Invalid Email found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return


        logger_msg = f"executing '{action.value}' action"
        headers = self.entra_ID_helper.get_auth_json(self.configuration, logger_msg)

        user_info = self._get_email_to_id(
            email=action_parameters["email"],
            headers=headers,
        )  # Raises MicrosoftEntraIDException if user
        # does not exist on Microsoft Entra ID platform.

        if action.value == "add":
            group_info = json.loads(action_parameters.get("group", ""))
            # Logic for creating new group.
            if group_info.get("id", "") == "create":
                try:
                    new_group_name = action_parameters.get("name", "").strip()
                    new_group_type = action_parameters.get("new_group_type", "")
                    groups = self._get_all_groups(headers=headers)  # Get all groups.

                    # Get match if group already exist or not.
                    match_group = self._find_group(
                        groups, new_group_name, new_group_type
                    )
                    # If no match found create a new group.
                    if match_group is None:
                        match_group = self._create_group(
                            new_group_name, new_group_type, headers=headers
                        )
                        time.sleep(10)
                    group_info = match_group
                except Exception as exp:
                    err_msg = (
                        "Error occurred while creating "
                        "new group named {} of type {}. Error: {}".format(
                            new_group_name, new_group_type, exp
                        )
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                    )
                    raise MicrosoftEntraIDException(err_msg)

            # Add user to group.
            try:
                self._add_to_group(user_info=user_info, group_info=group_info, headers=headers)
            except Exception as exp:
                err_msg = (
                    "Error occurred while adding user "
                    "with email '{}' to group named '{}' and"
                    " ID '{}'. Error: {}".format(
                        user_info.get("email", ""),
                        group_info.get("displayName", ""),
                        group_info.get("id", ""),
                        exp,
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftEntraIDException(err_msg)

        elif action.value == "remove":
            group_info = json.loads(action_parameters.get("group", ""))
            try:
                # Remove user from group.
                self._remove_from_group(
                    user_info,
                    group_info,
                    headers=headers
                )
            except Exception as exp:
                err_msg = (
                    "Error occurred while removing user with email '{}'"
                    " from group named '{}' and ID '{}'. Error: {}".format(
                        user_info.get("email", ""),
                        group_info.get("displayName", ""),
                        group_info.get("id", ""),
                        exp,
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftEntraIDException(err_msg)

        elif action.value == "confirm_compromised":
            try:
                # Perform Confirm compromised action on user.
                self._confirm_compromised(user_info=user_info, headers=headers)
            except Exception as exp:
                err_msg = (
                    "Error occurred while performing Confirm compromised"
                    " action on user with email '{}'. Error: {}".format(
                        user_info.get("email", ""), exp
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftEntraIDException(err_msg)

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate"]:
            return []

        logger_msg = f"fetching all {PLATFORM_NAME} groups"
        headers = self.entra_ID_helper.get_auth_json(self.configuration, logger_msg)
        groups = self._get_all_groups(headers=headers)

        new_group_dict = json.dumps({"id": "create"})
        if action.value == "add":
            return [
                {
                    "label": "Email",
                    "key": "email",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Email ID of the user to perform the action on.",
                },
                {
                    "label": "Groups",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("display_name", ""), "value": json.dumps(g)}
                        for g in groups
                    ]
                    + [{"key": "Create new group", "value": new_group_dict}],
                    "default": (
                        json.dumps(groups[0]) if groups else new_group_dict
                    ),
                    "mandatory": True,
                    "description": f"Select a {PLATFORM_NAME} group to add the user to.",
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create {} group with "
                        "given name if create new group is selected in Groups.".format(
                            PLATFORM_NAME
                        )
                    ),
                },
                {
                    "label": "New Group Type",
                    "key": "new_group_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Security", "value": "Security"},
                        {"key": "Microsoft 365", "value": "Microsoft 365"},
                    ],
                    "default": "Microsoft 365",
                    "mandatory": False,
                    "description": f"Select {PLATFORM_NAME} group type for new group if create new group is selected in Groups.",  # noqa
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Email",
                    "key": "email",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Email ID of the user to perform the action on.",
                },
                {
                    "label": "Groups",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("display_name", ""), "value": json.dumps(g)}
                        for g in groups
                    ],
                    "default": (
                        json.dumps(groups[0])
                        if groups
                        else f"No groups found on {PLATFORM_NAME} platform."
                    ),
                    "mandatory": True,
                    "description": (
                        "Select group(s) from which the user"
                        " should be removed."
                    ),
                },
            ]
        elif action.value == "confirm_compromised":
            return [
                {
                    "label": "Email",
                    "key": "email",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Email ID of the user to perform the action on.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Microsoft Entra ID action configuration."""
        try:
            action_value = action.value
            action_params = action.parameters
            if action_value not in [
                "add",
                "remove",
                "generate",
                "confirm_compromised",
            ]:
                return ValidationResult(
                    success=False, message="Unsupported action provided."
                )

            if action_value in ["generate", "confirm_compromised"]:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            groups = self._get_all_groups()

            create_dict = json.dumps({"id": "create"})
            groups = [group.get("id", "") for group in groups]

            email = action_params.get("email", "")
            if not email:
                err_msg = "Email is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(email, str):
                err_msg = "Invalid Email provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if action_value == "add":
                if not action_params.get("group", ""):
                    err_msg = "Select a group to perform action on."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif (
                    create_dict in action_params.get("group", "")
                    and len(action_params.get("name", "").strip()) == 0
                ):
                    err_msg = "Group Name can not be empty field."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif (
                    create_dict in action_params.get("group", "")
                    and action_params.get("new_group_type", "")
                    not in GROUP_TYPES
                ):
                    err_msg = (
                        "Invalid New Group Type value selected in action"
                        " configuration. Possible values are Microsoft 365"
                        " and Security."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif create_dict not in action_params.get("group", "") and (
                    "$" in action_params.get("group")
                ):
                    err_msg = (
                        "Group contains the Business Rule Record Field."
                        " Please select group from Static Field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False, message=err_msg
                    )

                elif create_dict not in action_params.get("group", "") and (
                    not any(
                        map(
                            lambda id: id
                            == json.loads(action_params.get("group", ""))[
                                "id"
                            ],
                            groups,
                        )
                    )
                ):
                    err_msg = (
                        "Invalid Group Name Provided. "
                        "Select group names from drop down list."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            else:
                if (
                    f"No groups found on {PLATFORM_NAME} platform."
                    in action_params.get("group", "")
                ):
                    err_msg = (
                        "Action will not be saved as no groups"
                        " found on {} server.".format(PLATFORM_NAME)
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif not any(
                    map(
                        lambda id: id
                        == json.loads(action_params.get("group", "")).get(
                            "id",
                            ""
                        ),
                        groups,
                    )
                ):
                    err_msg = "Invalid Group Name Provided."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except Exception as exp:
            self.logger.error(
                "{}: Exception Occurred in Validate Action. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=str(traceback.format_exc()),
            )
            raise MicrosoftEntraIDException(traceback.format_exc())

    def get_headers(self, headers):
        """Get headers with additional fields.

        Args:
            headers (dict): Request headers

        Returns:
            headers: headers with additional fields.
        """
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "*/*"
        return headers

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
                                token.
            tenant_id (str): Tenant ID that user wants

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate client_id
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client (Application) ID is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_id, str):
            err_msg = "Invalid Client (Application) ID value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate client_secret
        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate tenant_id
        tenant_id = configuration.get("tenant_id", "")
        if not tenant_id:
            err_msg = "Tenant ID is a required field."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(tenant_id, str):
            err_msg = "Invalid Tenant ID value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with Microsoft Entra ID platform.

        Args: configuration (dict): Contains the below keys:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate
                OAUTH2 token.
            tenant_id (str): Tenant ID that user wants

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            # This method calls check_url_valid, which makes a
            # request to Microsoft Graph API to let validate API credentials.

            self.check_url_valid(configuration)

            return ValidationResult(
                success=True,
                message=(
                    "Validation successful for {} {} Plugin.".format(
                        MODULE_NAME, self.plugin_name
                    )
                ),
            )

        except MicrosoftEntraIDException as exp:
            self.logger.error(
                message="{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))

        except Exception as exp:
            err_msg = "Validation error occurred while validating credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def check_url_valid(self, configuration):
        """
        Validate the URL of Microsoft Entra ID platform.

        Args:
            Args: configuration (dict): Contains the below keys:
                client_id (str): Client ID required to generate OAUTH2 token.
                client_secret (str): Client Secret required to generate
                    OAUTH2 token.
                tenant_id (str): Tenant ID that user wants

        Returns:
            Raise error if valid base url is not selected.
        """
        log_msg = "validating auth credentials"
        headers = self.entra_ID_helper.get_auth_json(configuration, log_msg, True)

        # get the top 1 user from Microsoft Graph for checking
        # whether we are connected to the API
        user_endpoint = f"{BASE_URL}/identityProtection/riskyUsers?$top=1"

        self.entra_ID_helper.api_helper(
            url=user_endpoint,
            method="GET",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=f"checking connectivity for users with {PLATFORM_NAME} platform",
            is_validation=True,
            regenerate_auth_token=False
        )

        # get the top 1 application from Microsoft Graph for checking
        # whether we are connected to the API
        app_endpoint = f"{BASE_URL}/applications?$top=1"
        self.entra_ID_helper.api_helper(
            url=app_endpoint,
            method="GET",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=f"checking connectivity for applications with {PLATFORM_NAME} platform",
            is_validation=True,
            regenerate_auth_token=False
        )

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Microsoft Entra ID.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching records from "
            f"{PLATFORM_NAME} platform."
        )
        if entity == "Users":
            url = (
                f"{BASE_URL}/identityProtection/riskyUsers?$top="
                + PAGE_RECORD_SCORE
            )
        elif entity == "Applications":
            url = (
                f"{BASE_URL}/applications?$top="
                + PAGE_RECORD_SCORE
            )

        logger_msg = "fetching records"
        total_records = []
        page_count = 1
        entity_name = entity.lower()

        headers = self.entra_ID_helper.get_auth_json(self.configuration, logger_msg)
        headers = self.get_headers(headers)
        while True:
            try:
                self.logger.info(
                    f"{self.log_prefix}: Fetching {entity_name} for page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                resp_json = self.entra_ID_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"fetching {entity_name} for page {page_count} from {PLATFORM_NAME}",  # noqa
                )

                current_user_list = resp_json.get("value", [])
                current_user_count = len(current_user_list)

                # We get all the user id and store it in total user id list
                for each_user in current_user_list:
                    try:
                        if entity == "Users":
                            currRecord = {
                                "User ID": each_user.get("id", ""),
                                "User Email": each_user.get("userPrincipalName", ""),
                                "Risk Level": each_user.get("riskLevel", ""),
                                "Risk State": each_user.get("riskState", ""),
                                "Risk Detail": each_user.get("riskDetail", ""),
                                "User Name": each_user.get("userDisplayName", "")
                            }
                        elif entity == "Applications":
                            currRecord = {
                                "Application ID": each_user.get("appId", ""),
                                "Application Name": each_user.get("displayName", ""),
                                "Tags": each_user.get("tags", []),
                                "Publisher Domain": [each_user.get("publisherDomain", "")],
                                "Created Date": (
                                    datetime.datetime.strptime(
                                        each_user.get("createdDateTime", ""),
                                        "%Y-%m-%dT%H:%M:%SZ"
                                    )
                                )
                            }
                        total_records.append(currRecord)
                    except ValidationError as err:
                        self.logger.error(
                            message="{}: Skipping {} with id {}.".format(
                                self.log_prefix,
                                entity[:-1],
                                each_user.get("id", f"{entity[:-1]} ID Not Found."),
                            ),
                            details="Error Details: {}. \nRecord Data: {}".format(
                                err, each_user
                            ),
                        )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{current_user_count} {entity_name} in page {page_count}."
                    f" Total {entity_name} fetched: {len(total_records)}."
                )
                page_count += 1
                # if number of groups is less than page size, we know that
                # this is the last page of the request. Hence, we break
                if current_user_count < int(PAGE_RECORD_SCORE):
                    break
                # likewise this is another check for last page
                # Microsoft graph won't provide nextLink of page
                # Hence, we break
                if "@odata.nextLink" not in resp_json.keys():
                    break

                url = resp_json.get("@odata.nextLink", "")
            except MicrosoftEntraIDException:
                raise
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while fetching {entity_name} from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_records)}"
            f" {entity_name} from {PLATFORM_NAME} platform."
        )
        return total_records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        entity_name = entity.lower()
        if entity == "Applications":
            self.logger.debug(
                f"{self.log_prefix}: No fields to update for"
                f" {entity_name} record(s) from {PLATFORM_NAME} platform."
            )
            return []

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)}"
            f" {entity_name} record(s) from {PLATFORM_NAME} platform."
        )
        url = (
            f"{BASE_URL}/identityProtection/riskyUsers?$top="
            + PAGE_RECORD_SCORE
        )

        logger_msg = f"updating {entity_name} records"
        score_users = {}
        page_count = 1

        headers = self.entra_ID_helper.get_auth_json(self.configuration, logger_msg)
        headers = self.get_headers(headers)
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Updating records for {entity_name} in page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                resp_json = self.entra_ID_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"updating records for {entity_name} from {PLATFORM_NAME}",
                )

                current_user_list = resp_json.get("value", [])
                current_user_count = len(current_user_list)

                record_uid_list = []

                # store just emails in an array
                for record in records:
                    record_uid_list.append(record["User Email"])

                for each_user in current_user_list:
                    current_uid = each_user.get("userPrincipalName", "")
                    if current_uid in record_uid_list:
                        current_score = each_user.get("riskLevel", "")
                        # store email as key and score as value
                        score_users[current_uid] = current_score

                self.logger.debug(
                        f"{self.log_prefix}: Successfully updated records for "
                        f"{current_user_count} {entity_name} in page {page_count}."
                        f" Total record(s) updated: {len(score_users)}."
                    )
                page_count += 1
                if current_user_count < int(PAGE_RECORD_SCORE):
                    break
                if "@odata.nextLink" not in resp_json.keys():
                    break

                url = resp_json.get("@odata.nextLink", "")
            except MicrosoftEntraIDException:
                raise
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while updating records from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        user_count = 0
        for record in records:
            try:
                if record["User Email"] in score_users:
                    record["Risk Level"] = score_users[record["User Email"]]

                    risk_level = record.get("Risk Level", "")
                    if (
                        risk_level == "none"
                        or risk_level == "hidden"
                        or risk_level == "unknownFutureValue"
                    ):
                        record["Netskope Normalized Score"] = None
                    elif risk_level == "low":
                        record["Netskope Normalized Score"] = 875
                    elif risk_level == "medium":
                        record["Netskope Normalized Score"] = 625
                    elif risk_level == "high":
                        record["Netskope Normalized Score"] = 375
                    user_count += 1
                for k, v in list(record.items()):
                    if v is None:
                        record.pop(k)
            except ValidationError as error:
                self.logger.error(
                    message={
                        "{}: Error occurred while updating record"
                        " for user {}.".format(self.log_prefix, record["userPrincipalName"])
                    },
                    details=f"Error details: {error}",
                )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{user_count} record(s) from {PLATFORM_NAME} platform."
        )
        return records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(name="User ID", type=EntityFieldType.STRING),
                    EntityField(name="Risk Level", type=EntityFieldType.STRING),
                    EntityField(name="Risk State", type=EntityFieldType.STRING),
                    EntityField(name="Risk Detail", type=EntityFieldType.STRING),
                    EntityField(name="User Name", type=EntityFieldType.STRING),
                    EntityField(name="User Email", type=EntityFieldType.STRING, required=True),
                    EntityField(name="Netskope Normalized Score", type=EntityFieldType.NUMBER),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(name="Application ID", type=EntityFieldType.STRING, required=True),
                    EntityField(name="Application Name", type=EntityFieldType.STRING),
                    EntityField(name="Tags", type=EntityFieldType.LIST),
                    EntityField(name="Publisher Domain", type=EntityFieldType.LIST),
                    EntityField(name="Created Date", type=EntityFieldType.DATETIME),
                ],
            )
        ]
