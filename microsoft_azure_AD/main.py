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

URE Microsoft Azure AD Plugin.
"""

import datetime
import json
import os
import time
import traceback
from typing import Dict, List, Optional

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from pydantic import ValidationError

PAGE_SIZE = "999"
PAGE_RECORD_SCORE = "500"
BASE_URL = "https://graph.microsoft.com/v1.0"
GROUP_TYPES = ["Security", "Microsoft 365"]
PLATFORM_NAME = "Microsoft Azure AD"
MODULE_NAME = "URE"
PLUGIN_VERSION = "1.2.0"
MAX_API_CALLS = 4


class MicrosoftAzureADException(Exception):
    """Microsoft Azure AD exception class."""

    pass


class MicrosoftAzureADPlugin(PluginBase):
    """Microsoft Azure AD plugin implementation."""

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
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _add_user_agent(self, header=None) -> Dict:
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        headers = add_user_agent(header=header)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        headers.update(
            {
                "User-Agent": "{}-{}-{}-v{}".format(
                    ce_added_agent,
                    MODULE_NAME.lower(),
                    self.plugin_name.lower().replace(" ", "_"),
                    self.plugin_version,
                ),
            }
        )
        return headers

    def _add_to_group(self, user_info: dict, group_info: dict) -> None:
        """Add specified user to the specified group.

        Args:
            user_info (dict): Dictionary containing user email and id.
            group_id (str): Group ID of the group.

        Raises:
            MicrosoftAzureADException: If any unexpected error occurred
            from API side
        """
        headers = self.reload_auth_token(self.configuration)
        user_id, user_email = user_info.get("id"), user_info.get("email")
        group_id, group_name = group_info.get("id"), group_info.get(
            "displayName"
        )
        logger_msg = (
            "user with email '{}' to group "
            "named '{}' and ID '{}'".format(user_email, group_name, group_id)
        )
        self.logger.info(f"{self.log_prefix}: Adding {logger_msg}.")
        headers["Content-Type"] = "application/json"
        url = f"{BASE_URL}/groups/{group_id}/members/$ref"
        data = {"@odata.id": f"{BASE_URL}/directoryObjects/{user_id}"}

        response = self._api_helper(
            lambda: requests.post(
                url=url,
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(data),
            ),
            f"adding {logger_msg}",
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
            resp_json = self.parse_response(response=response)
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

        self.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _remove_from_group(self, user_info: dict, group_info: str) -> None:
        """Remove specified user to the specified group.

        Args:
            user_info (dict): Dictionary containing user email and id.
            group_info (str): Dictionary containing group email and id.

        Raises:
            MicrosoftAzureADException: If any unexpected error occurred
            from API side
        """
        headers = self.reload_auth_token(self.configuration)
        user_id, user_email = user_info.get("id"), user_info.get("email")

        group_id, group_name = group_info.get("id"), group_info.get(
            "displayName"
        )
        logger_msg = (
            "user with email '{}' from group named '{}' "
            "and ID '{}'".format(user_email, group_name, group_id)
        )
        self.logger.info(f"{self.log_prefix}: Removing {logger_msg}.")
        headers["Content-Type"] = "application/json"
        url = f"{BASE_URL}/groups/{group_id}/members/{user_id}/$ref"

        response = self._api_helper(
            lambda: requests.delete(
                url=url,
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
            logger_msg,
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
            resp_json = self.parse_response(response=response)
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

        self.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _create_group(self, group_name: str, group_type: str) -> Dict:
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
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"
        logger_msg = "creating new group named '{}' on {}".format(
            group_name, PLATFORM_NAME
        )
        response = self._api_helper(
            lambda: requests.post(
                url=url,
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(body),
            ),
            logger_msg,
            is_handle_error_required=False,
        )

        if response.status_code in [200, 201]:
            self.logger.info(
                "{}: Successfully created group named '{}' of type '{}' on "
                "{} platform.".format(
                    self.log_prefix, group_name, group_type, PLATFORM_NAME
                )
            )
            response_json = self.parse_response(response=response)
            return {
                "id": response_json.get("id"),  # Group ID
                "displayName": response_json.get("displayName"),  # Group Name
            }

        elif response.status_code == 400:
            resp_json = self.parse_response(response=response)
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
            raise MicrosoftAzureADException(err_msg)

        return self.handle_error(
            response, logger_msg
        )  # For capturing any unexpected error.

    def _get_all_groups(self) -> List:
        """Gets all group details.

        Returns:
            total_group_name_array (list): List of groups.
        """
        url = f"{BASE_URL}/groups"
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        params = {
            "$top": PAGE_RECORD_SCORE,
            "$orderby": "displayName",  # To get data in sorted order.
            "$select": "id,displayName,groupTypes",
            # We need only id,displayName and groupTypes hence
            # getting those fields only from API.
        }
        # all the group names will be added in this variable.
        total_group_name_array = []

        while True:
            resp_json = self._api_helper(
                lambda: requests.get(
                    url,
                    headers=self._add_user_agent(headers),
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                ),
                f"fetching groups from {PLATFORM_NAME}",
            )
            # stores the number of groups in that particular pagination query
            current_group_array = resp_json.get("value", [])
            total_group_name_array.extend(
                [
                    {
                        "id": each_group.get("id"),
                        # Note: displayName is the actual group
                        # name shown in UI of Microsoft Azure AD
                        "displayName": each_group.get("displayName"),
                        # Note: display_name is the field we'll be using
                        # to show group name in URE action configuration
                        # E.g. If Security Group is there then group will be
                        # displayed as "Group Name (Security)". Similarly for
                        # Microsoft 365 group name will be
                        # "Group Name (Microsoft 365)"
                        "display_name": "{} (Security)".format(
                            each_group.get("displayName")
                        )
                        if not each_group.get("groupTypes")
                        else "{} (Microsoft 365)".format(
                            each_group.get("displayName")
                        ),
                        "group_type": "Security"
                        if not each_group.get("groupTypes")
                        else "Microsoft 365",
                    }
                    for each_group in current_group_array
                ]
            )

            # if number of groups is less than page size, we know that
            # this is the last page of the request. Hence, we break
            if len(current_group_array) < int(PAGE_SIZE):
                break
            # likewise this is another check for last page
            # Microsoft graph won't provide nextLink of page
            # Hence, we break
            if "@odata.nextLink" not in resp_json.keys():
                break

            url = resp_json.get("@odata.nextLink")  # For pagination

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
                group.get("displayName") == name
                and group.get("group_type") == type
            ):
                return group

    def _get_email_to_id(self, email: str) -> dict:
        """Get unique id of the user from provided email.

        Args:
            email (str):  User Principle email.

        Raises:
            MicrosoftAzureADException: If user with email does not exist on
            Microsoft Azure AD platform.

        Returns:
            dict: Dictionary containing user id and email.
        """
        url = f"{BASE_URL}/users/{email}"
        # Reload token for authentication.
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"
        logger_msg = (
            "fetching user details for user with email {} from {}".format(
                email, PLATFORM_NAME
            )
        )
        response = self._api_helper(
            lambda: requests.get(
                url,
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
            logger_msg,
            is_handle_error_required=False,
        )
        if response.status_code == 200:
            resp_json = self.parse_response(response=response)
            # Return email address and user id from response.
            return {"email": email, "id": resp_json.get("id")}

        elif response.status_code == 404:
            resp_json = self.parse_response(response=response)
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
            raise MicrosoftAzureADException(err_msg)

        self.handle_error(
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

    def _confirm_compromised(self, user_info: dict) -> None:
        """Perform Confirm Compromised action on user.

        Args:
            user_info (dict): Dictionary containing user id and email.

        Raises:
            MicrosoftAzureADException: Raises exception if unable to
            perform action on user.
        """
        user_id = user_info.get("id")
        user_email = user_info.get("email")
        url = f"{BASE_URL}/identityProtection/riskyUsers/confirmCompromised"

        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"
        data = {"userIds": [user_id]}
        logger_msg = (
            "performing Confirm compromised action on user "
            "with email '{}'".format(user_email)
        )
        response = self._api_helper(
            lambda: requests.post(
                url=url,
                headers=self._add_user_agent(headers),
                data=json.dumps(data),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
            logger_msg,
            is_handle_error_required=False,
        )
        if response.status_code == 204:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed Confirm "
                f"compromised action on user with email '{user_email}'."
            )
            return

        self.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user.

        Args:
            record (Record): Record of a user on which action will be
            performed.
            action (Action): Action that needs to be perform on user.

        Returns:
            None
        """
        if action.value == "generate":
            return

        user_info = self._get_email_to_id(
            email=record.uid
        )  # Raises MicrosoftAzureADException if user
        # does not exist on Microsoft Azure AD platform.

        if action.value == "add":
            group_info = json.loads(action.parameters.get("group"))
            # Logic for creating new group.
            if group_info.get("id") == "create":
                try:
                    new_group_name = action.parameters.get("name").strip()
                    new_group_type = action.parameters.get("new_group_type")
                    groups = self._get_all_groups()  # Get all groups.

                    # Get match if group already exist or not.
                    match_group = self._find_group(
                        groups, new_group_name, new_group_type
                    )
                    # If no match found create a new group.
                    if match_group is None:
                        match_group = self._create_group(
                            new_group_name, new_group_type
                        )
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
                    raise MicrosoftAzureADException(err_msg)

            # Add user to group.
            try:
                self._add_to_group(user_info=user_info, group_info=group_info)
            except Exception as exp:
                err_msg = (
                    "Error occurred while adding user "
                    "with email '{}' to group named '{}' and"
                    " ID '{}'. Error: {}".format(
                        user_info.get("email"),
                        group_info.get("displayName"),
                        group_info.get("id"),
                        exp,
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureADException(err_msg)

        elif action.value == "remove":
            group_info = json.loads(action.parameters.get("group"))
            try:
                # Remove user from group.
                self._remove_from_group(
                    user_info,
                    group_info,
                )
            except Exception as exp:
                err_msg = (
                    "Error occurred while removing user with email '{}'"
                    " from group named '{}' and ID '{}'. Error: {}".format(
                        user_info.get("email"),
                        group_info.get("displayName"),
                        group_info.get("id"),
                        exp,
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureADException(err_msg)

        elif action.value == "confirm_compromised":
            try:
                # Perform Confirm compromised action on user.
                self._confirm_compromised(user_info=user_info)
            except Exception as exp:
                err_msg = (
                    "Error occurred while performing Confirm compromised"
                    " action on user with email '{}'. Error: {}".format(
                        user_info.get("email"), exp
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureADException(err_msg)

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate", "confirm_compromised"]:
            return []
        groups = self._get_all_groups()

        new_group_dict = json.dumps({"id": "create"})
        if action.value == "add":
            return [
                {
                    "label": "Groups",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("display_name"), "value": json.dumps(g)}
                        for g in groups
                    ]
                    + [{"key": "Create new group", "value": new_group_dict}],
                    "default": json.dumps(groups[0])
                    if groups
                    else new_group_dict,
                    "mandatory": True,
                    "description": "Select a group to add the user to.",
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create {} group with "
                        "given name if it does not exist.".format(
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
                    "description": "Select group type for new group.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Groups",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("display_name"), "value": json.dumps(g)}
                        for g in groups
                    ],
                    "default": json.dumps(groups[0])
                    if groups
                    else f"No groups found on {PLATFORM_NAME} platform.",
                    "mandatory": True,
                    "description": (
                        "Select group(s) from which the user"
                        " should be removed."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Microsoft Azure AD action configuration."""
        try:
            if action.value not in [
                "add",
                "remove",
                "generate",
                "confirm_compromised",
            ]:
                return ValidationResult(
                    success=False, message="Unsupported action provided."
                )

            if action.value in ["generate", "confirm_compromised"]:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            groups = self._get_all_groups()

            create_dict = json.dumps({"id": "create"})
            groups = [group.get("id") for group in groups]

            if action.value == "add":
                if not action.parameters.get("group"):
                    err_msg = "Select a group to perform action on."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif (
                    create_dict in action.parameters.get("group")
                    and len(action.parameters.get("name", "").strip()) == 0
                ):
                    err_msg = "Group Name can not be empty field."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif (
                    create_dict in action.parameters.get("group")
                    and action.parameters.get("new_group_type")
                    not in GROUP_TYPES
                ):
                    err_msg = (
                        "Invalid New Group Type value selected in action"
                        " configuration. Possible values are Microsoft 365"
                        " and Security."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                elif create_dict not in action.parameters.get("group") and (
                    not any(
                        map(
                            lambda id: id
                            == json.loads(action.parameters.get("group"))[
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
                    in action.parameters.get("group")
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
                        == json.loads(action.parameters.get("group")).get(
                            "id"
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
            raise MicrosoftAzureADException(traceback.format_exc())

    def get_auth_json(self, configuration):
        """Get the OAUTH2 Json object with access token from
            Microsoft Azure AD platform.

        Args:
            Args: configuration (dict): Contains the below keys:
                client_id (str): Client ID required to generate OAUTH2 token.
                client_secret (str): Client Secret required to generate
                    OAUTH2 token.
                tenant_id (str): Tenant ID that user wants

        Returns:
            json: JSON response data in case of Success.
        """
        # Note this is the method that actually interacts with the token
        # url and provides a response not only of the token but other
        # details as well. But the token is only what we need.

        client_id = configuration.get("client_id").strip()
        client_secret = configuration.get("client_secret")
        tenant_id = configuration.get("tenant_id").strip()

        # This is the token link.
        # Looks like https://login.microsoftonline.com/xxxxxxxx
        # -xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/token
        auth_endpoint = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
        )
        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "resource": "https://graph.microsoft.com",
        }
        logger_msg = "validating auth credentials"
        resp = self._api_helper(
            lambda: requests.get(
                auth_endpoint,
                data=auth_params,
                proxies=self.proxy,
                verify=self.ssl_validation,
                headers=self._add_user_agent(),
            ),
            logger_msg,
            is_handle_error_required=False,
        )

        if resp.status_code == 400:
            resp_json = self.parse_response(response=resp)
            err_msg = (
                "Received exit code 400. Invalid Request. Verify Client "
                "(Application) ID and Tenant ID provided in "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MicrosoftAzureADException(err_msg)
        elif resp.status_code == 401:
            err_msg = (
                "Received exit code 401. Verify Client Secret provided"
                " in configuration parameters."
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MicrosoftAzureADException(err_msg)
        elif resp.status_code == 404:
            err_msg = (
                "Received exit code 404. Resource not found. Verify the "
                "Tenant ID provided in configuration parameters."
            )
            try:
                resp_json = self.parse_response(response=resp)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resp_json),
                )
                raise MicrosoftAzureADException(err_msg)
            except MicrosoftAzureADException as exp:
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureADException(err_msg)

        # Check for other possible errors
        auth_json = self.handle_error(resp, logger_msg)
        if self.storage is not None:
            # The logic of adding time is necessary so we can use
            # the same token for 30 mins. We store in storage with
            # current time + 30 mins (1799 seconds)
            self.storage[
                "token_expiry"
            ] = datetime.datetime.now() + datetime.timedelta(
                seconds=int(auth_json.get("expires_in", 1799))
            )

        auth_token = auth_json.get("access_token")
        # We store the headers in configuration. This is important
        # because we can access the token header simply via self
        # Methods we created will demand configuration in method arguments
        headers = {"Authorization": f"Bearer {auth_token}"}
        self.configuration["headers"] = headers

        return auth_json

    def reload_auth_token(self, configuration: dict) -> dict:
        """Reload Auth Token.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            dict: Headers dictionary.
        """
        headers = self.configuration.get("headers", None)
        if headers is None:
            # create a token
            auth_json = self.get_auth_json(configuration)
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            return headers

        elif self.storage is not None:
            if (
                self.storage.get(
                    "token_expiry",
                    datetime.datetime.now() - datetime.timedelta(minutes=1),
                )
                < datetime.datetime.now()
            ):
                # Reload token
                self.logger.info(
                    f"{self.log_prefix}: OAUTH2 token expired. "
                    "Generating a new token."
                )
                auth_json = self.get_auth_json(configuration)
                auth_token = auth_json.get("access_token")
                headers = {"Authorization": f"Bearer {auth_token}"}
            return headers
        else:
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
        if (
            "client_id" not in configuration
            or not str(configuration.get("client_id", "")).strip()
        ):
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

        elif not isinstance(configuration.get("client_id"), str):
            err_msg = "Invalid Client (Application) ID value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if "client_secret" not in configuration or not str(
            configuration.get("client_secret", "")
        ):
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

        elif not isinstance(configuration.get("client_secret"), str):
            err_msg = "Invalid Client Secret value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            "tenant_id" not in configuration
            or not str(configuration.get("tenant_id", "")).strip()
        ):
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

        elif not isinstance(configuration.get("tenant_id"), str):
            err_msg = "Invalid Tenant ID value provided."
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with Microsoft Azure AD platform.

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

        except requests.exceptions.ProxyError as err:
            err_msg = "Invalid proxy configuration."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Unable to establish connection with {} platform API.".format(
                    PLATFORM_NAME
                )
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        except requests.HTTPError as err:
            err_msg = "HTTP Error occurred while validating credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )

        except MicrosoftAzureADException as exp:
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
        Validate the URL of Microsoft Azure AD platform.

        Args:
            Args: configuration (dict): Contains the below keys:
                client_id (str): Client ID required to generate OAUTH2 token.
                client_secret (str): Client Secret required to generate
                    OAUTH2 token.
                tenant_id (str): Tenant ID that user wants

        Returns:
            Raise error if valid base url is not selected.
        """
        auth_json = self.get_auth_json(configuration)
        auth_token = auth_json.get("access_token")

        headers = {"Authorization": f"Bearer {auth_token}"}

        # get the top 1 user from Microsoft Graph for checking
        # whether we are connected to the API
        query_endpoint = f"{BASE_URL}/identityProtection/riskyUsers?$top=1"

        self._api_helper(
            lambda: requests.get(
                query_endpoint,
                headers=self._add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
            "validating authentication credentials",
        )

    def fetch_records(self) -> List[Record]:
        """Pull Records from Microsoft Azure AD.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        url = (
            f"{BASE_URL}/identityProtection/riskyUsers?$top="
            + PAGE_RECORD_SCORE
        )

        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        total_records = []

        while True:
            resp_json = self._api_helper(
                lambda: requests.get(
                    url,
                    headers=self._add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                ),
                f"fetching user(s) from {PLATFORM_NAME}",
            )
            current_user_list = resp_json.get("value")
            current_user_count = len(current_user_list)

            # We get all the user id and store it in total user id list
            for each_user in current_user_list:
                try:
                    currRecord = Record(
                        uid=each_user.get(
                            "userPrincipalName",
                        ),
                        type=RecordType.USER,
                        score=None,
                    )
                    total_records.append(currRecord)
                except ValidationError as err:
                    self.logger.error(
                        message="{}: Skipping user with id {}.".format(
                            self.log_prefix,
                            each_user.get("id", "User ID Not Found."),
                        ),
                        details="Error Details: {}. \nRecord Data: {}".format(
                            err, each_user
                        ),
                    )

            # if number of groups is less than page size, we know that
            # this is the last page of the request. Hence, we break
            if current_user_count < int(PAGE_RECORD_SCORE):
                break
            # likewise this is another check for last page
            # Microsoft graph won't provide nextLink of page
            # Hence, we break
            if "@odata.nextLink" not in resp_json.keys():
                break

            url = resp_json.get("@odata.nextLink")

        return total_records

    def fetch_scores(self, records: List[Record]) -> List[Record]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        url = (
            f"{BASE_URL}/identityProtection/riskyUsers?$top="
            + PAGE_RECORD_SCORE
        )
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        score_users = {}
        total_scores = []

        while True:
            resp_json = self._api_helper(
                lambda: requests.get(
                    url,
                    headers=self._add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                ),
                f"fetching scores for users from {PLATFORM_NAME}",
            )

            current_user_list = resp_json.get("value")
            current_user_count = len(current_user_list)

            record_uid_list = []

            # store just emails in an array
            for record in records:
                record_uid_list.append(record.uid)

            for each_user in current_user_list:
                current_uid = each_user.get("userPrincipalName")
                if current_uid in record_uid_list:
                    current_score = each_user.get("riskLevel")
                    # store email as key and score as value
                    score_users[current_uid] = current_score

            if current_user_count < int(PAGE_RECORD_SCORE):
                break
            if "@odata.nextLink" not in resp_json.keys():
                break

            url = resp_json.get("@odata.nextLink")

        if score_users:
            for key, value in score_users.items():
                try:
                    if (
                        value == "none"
                        or value == "hidden"
                        or value == "unknownFutureValue"
                    ):
                        total_scores.append(
                            Record(uid=key, type=RecordType.USER, score=None)
                        )
                    elif value == "low":
                        total_scores.append(
                            Record(uid=key, type=RecordType.USER, score=875)
                        )
                    elif value == "medium":
                        total_scores.append(
                            Record(uid=key, type=RecordType.USER, score=625)
                        )
                    elif value == "high":
                        total_scores.append(
                            Record(uid=key, type=RecordType.USER, score=375)
                        )
                except ValidationError as error:
                    self.logger.error(
                        message={
                            "{}: Error occurred while fetching score"
                            " for user {}.".format(self.log_prefix, key)
                        },
                        details=f"Error details: {error}",
                    )

        return total_scores

    def parse_response(self, response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {err}"
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MicrosoftAzureADException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureADException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg: str
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            MicrosoftAzureADException: When the response code is
            not 200,201 and 204.
        """
        if resp.status_code in [200, 201]:
            return self.parse_response(response=resp)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 403:
            err_msg = (
                "Received exit code 403, Forbidden user while {}.".format(
                    logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MicrosoftAzureADException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP client error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MicrosoftAzureADException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = (
                f"Received exit code {resp.status_code}. HTTP Server Error."
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MicrosoftAzureADException(err_msg)
        else:
            err_msg = f"Received exit code {resp.status_code}. HTTP Error."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MicrosoftAzureADException(err_msg)

    def _api_helper(
        self, request, logger_msg: str, is_handle_error_required=True
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            logger_msg (str): Logger string.
            is_handle_error_required (bool, optional): Is handling status
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            retry_counter = 0
            for _ in range(MAX_API_CALLS):
                response = request()
                if response.status_code == 429:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get(
                            "error",
                            "No error details found in API response.",
                        )
                    )
                    if retry_counter == 3:
                        err_msg = (
                            "Received exit code 429, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code 429.".format(logger_msg)
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MicrosoftAzureADException(err_msg)
                    retry_after = int(response.headers.get("Retry-After", 60))
                    retry_counter += 1
                    self.logger.error(
                        message=(
                            "{}: Received exit code 429, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                logger_msg,
                                retry_after,
                                3 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    if retry_after > 300:
                        err_msg = (
                            "'Retry-After' value received from response "
                            "headers while {} is greater than 5 minutes hence"
                            " returning status code 429.".format(logger_msg)
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise MicrosoftAzureADException(err_msg)
                    time.sleep(retry_after)
                    continue
                else:
                    return (
                        self.handle_error(response, logger_msg)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as error:
            err_msg = "Invalid proxy configuration provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureADException(err_msg)

        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform. Proxy server or {}"
                " is not reachable. Error: {}".format(
                    PLATFORM_NAME, PLATFORM_NAME, error
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureADException(err_msg)

        except Exception as exp:
            err_msg = (
                "Error occurred while requesting "
                "to {} server. Error: {}".format(PLATFORM_NAME, exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureADException(err_msg)
