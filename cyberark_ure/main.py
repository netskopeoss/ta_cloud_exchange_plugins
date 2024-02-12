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

"""CyberArk URE plugin."""

import json
import traceback
import urllib.parse

from typing import Dict
from typing import List, Dict, Optional
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    ActionWithoutParams,
    Action,
)
from .utils.cyberark_helper import (
    CyberArkPluginHelper,
    CyberArkPluginException,
)
from .utils.cyberark_constants import(
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    PLUGIN_NAME,
)


class CyberArkPlugin(PluginBase):
    """CyberArk plugin implementation."""
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
        self.log_prefix = f"{MODULE_NAME} {PLUGIN_NAME} [{name}]"
        self.cyberark_helper = CyberArkPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            configuration=self.configuration,
            plugin_name=PLUGIN_NAME,
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

    def fetch_records(self) -> List[Record]:
        """Pull Records from CyberArk.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        return []

    def fetch_scores(self, records: List[Record]) -> List[Record]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        return []

    def _add_to_role(self, user_id: str, role_id: str, role_name: str, headers: Dict):
        """Add specified user to the specified role.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            role_id (str): Role ID of the role.

        Raises:
            HTTPError: If the role does not exist on CyberArk.
        """
        url_endpoint = "/SaasManage/AddUsersAndGroupsToRole"
        body = {
              "Users": [
                user_id
              ],
              "Name": role_id
            }
        logger_msg = f"adding user '{user_id}' to role '{role_name}'"
        resp = self.cyberark_helper.api_helper(
            logger_msg=logger_msg,
            url_endpoint=url_endpoint,
            method="POST",
            headers=headers,
            data=json.dumps(body),
            params=None,
            is_handle_error_required=True,
        )
        if resp.get("success", True) == False:
            error_msg = (
                f"Failed to add user '{user_id}' to role '{role_name}'.",
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=str(resp),
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
        body = {
              "Users": [
                user_id
              ],
              "Name": role_id
            }
        logger_msg = f"removing user '{user_id}' from role '{role_name}'"
        resp = self.cyberark_helper.api_helper(
            logger_msg=logger_msg,
            url_endpoint=url_endpoint,
            method="POST",
            headers=headers,
            data=json.dumps(body),
            params=None,
            is_handle_error_required=True,
        )
        if resp.get("success", True) == False:
            error_msg = (
                f"Failed to remove user '{user_id}' from role '{role_name}'.",
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=str(resp),
            )
            raise CyberArkPluginException(
                error_msg,
            )

    def _get_all_roles(self) -> List:
        """Get list of all the role.
        Args:
            configuration (Dict): Configuration parameters.
        Returns:
            List: List of all the roles.
        """
        headers = self.cyberark_helper.get_protected_cyberark_headers()
        headers = self.cyberark_helper._add_user_agent(headers)
        url_endpoint = "/RedRock/query"
        body = "{'Script': 'Select ID, Name from Role order by Name'}"
        response = self.cyberark_helper.api_helper(
            logger_msg="fetching all roles",
            url_endpoint=url_endpoint,
            method="POST",
            params=None,
            data=body,
            retry=False,
            headers=headers,
            json_params=None,
            is_handle_error_required=True,
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

    def _find_user_by_username(self, username: str, headers: Dict) -> Optional[Dict]:
        """Find user by username.

        Args:
            username (str): username to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        url_endpoint = "/RedRock/query"
        body = "{\"Script\": \"select ID, Username from Users where Username = '" + username + "'\"}"
        response = self.cyberark_helper.api_helper(
            logger_msg=f"finding user '{username}' on {PLATFORM_NAME}",
            url_endpoint=url_endpoint,
            method="POST",
            params=None,
            data=body,
            headers=headers,
            is_handle_error_required=True,
        )
        matched_user = response.get("Result", {}).get("Results", [])
        if matched_user:
            return matched_user[0]
        else:
            return None

    def _find_role_by_name(self, name: str, headers: Dict) -> Optional[Dict]:
        """Find role from list by name.

        Args:
            name (str): Name to find.

        Returns:
            Optional[Dict]: Role dictionary if found, None otherwise.
        """
        url_endpoint = "/RedRock/query"
        body = "{\"Script\": \"select ID, Name from Role where Name = '" + name + "'\"}"
        response = self.cyberark_helper.api_helper(
            logger_msg="finding role '{}' on {}".format(name, PLATFORM_NAME),
            url_endpoint=url_endpoint,
            method="POST",
            params=None,
            data=body,
            headers=headers,
            is_handle_error_required=True,
        )
        matched_user = response.get("Result", {}).get("Results", [])
        if matched_user:
            return matched_user[0].get("Row", "").get("ID", "")
        else:
            return None

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to Role", value="add"),
            ActionWithoutParams(label="Remove from Role", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _create_role(self, name: str, headers: Dict) -> Dict:
        """Create a new ole with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the role to create.
            description (str): Role decription.

        Returns:
            Dict: Newly created role dictionary.
        """
        url_endpoint = "/Roles/StoreRole"
        body = {
              "Description": "Created from Netskope CE",
              "Name": name
            }
        response = self.cyberark_helper.api_helper(
            logger_msg=f"creating role '{name}' on {PLATFORM_NAME}",
            url_endpoint=url_endpoint,
            method="POST",
            params=None,
            data=json.dumps(body),
            headers=headers,
            is_handle_error_required=True,
        )

        if response.get("success", False) == True:
            self.logger.info(
                f"{self.log_prefix}: Successfully created role with name {name} on {PLATFORM_NAME}."
            )
            return response.get("Result", {}).get("_RowKey", "")
        raise CyberArkPluginException(
            "Failed to create role with name {name}.".format(name=name)
        )

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        user = record.uid
        if action.value == "generate":
            self.logger.debug(
                '{}: Successfully executed "{}" action on record "{}". '
                "Note: No processing will be done from plugin for "
                'the "{}" action.'.format(
                    self.log_prefix, action.label, user, action.label
                )
            )
            return
        headers = self.cyberark_helper.get_protected_cyberark_headers()
        headers = self.cyberark_helper._add_user_agent(headers)
        match_user = self._find_user_by_username(user, headers)
        if match_user is None:
            info_msg = (
                f"{self.log_prefix}: User '{user}' not found on {PLATFORM_NAME}. "
                f"Hence action '{action.label}' will be skipped."
            )
            self.logger.info(
                info_msg
            )
            return
        self.logger.info(
            f"{self.log_prefix}: User '{user}' found on {PLATFORM_NAME}. "
            f"Hence action '{action.label}' will be executed."
        )
        action_parameters = action.parameters
        role_dict = json.loads(action_parameters.get("role_name", ""))
        role_name = role_dict.get("grp_name", "")
        is_create_new_grp = role_name == "create_new_role"
        if is_create_new_grp:
            role_name = action_parameters.get("new_role_name", "")
        match_role_id = self._find_role_by_name(role_name, headers)
        if action.value == "add":
            # either provided grp is deleted or create new grp is selected
            if not match_role_id:
                if is_create_new_grp:
                    self.logger.info(
                            f"{self.log_prefix}: Creating new role with name '{role_name}' on {PLATFORM_NAME}."
                        )
                    match_role_id = self._create_role(role_name, headers)
                else:
                    error_msg = (
                        f"{self.log_prefix}: Selected role with name '{role_name}' "
                        "not found on CyberArk, "
                        f"hence action '{action.label}' will be skipped. "
                        "Either select a an existing role in the action configuration or"
                        "select 'Create New Role' option."
                    )
                    self.logger.error(
                        error_msg
                    )
                    raise CyberArkPluginException(error_msg)
            self._add_to_role(user, match_role_id, role_name, headers)
            self.logger.info(
                f"{self.log_prefix}: Successfully added user '{user}' to role '{role_name}'."
            )
        elif action.value == "remove":
            if not match_role_id:
                error_msg = (
                    f"{self.log_prefix}: Role with name '{role_name}' not found on CyberArk, "
                    f"hence action '{action.label}' will be skipped."
                )
                self.logger.error(
                    error_msg
                )
                raise CyberArkPluginException(error_msg)
            self._remove_from_role(
                user,
                match_role_id,
                role_name,
                headers
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully removed user '{user}' from role '{role_name}'."
            )

    def get_action_fields(self, action: Action) -> List:
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
        if action.value == "add":
            return [
                {
                    "label": "Role Name",
                    "key": "role_name",
                    "type": "choice",
                    "choices": choice_list_with_create,
                    "default": choice_list_with_create[0]["value"] if choice_list_with_create else "",
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
                                "grp_id": ""
                            }
                        ),
                    }
                ]
            return [
                {
                    "label": "Role Name",
                    "key": "role_name",
                    "type": "choice",
                    "choices": choice_list,
                    "default": choice_list[0].get("value", "") if choice_list else "",
                    "mandatory": True,
                    "description": "Select a role to remove the user from.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate CyberArk action configuration."""
        if action.value not in ["add", "remove", "generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.value == "generate":
            return ValidationResult(
                success=True,
                message="Validation successful."
            )
        action_parameters = action.parameters
        roles = self._get_all_roles()
        if action.value == "remove" and not roles:
            error_msg = (
                "No roles found on CyberArk. Make sure roles exists on the platform "
                "and the user has the administrative rights to view roles."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        role_value = action_parameters.get("role_name", "")

        # Validate Empty Role provided
        if not role_value:
            error_msg = "Role Name is a required field."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validate type of Role Name provided
        elif not isinstance(
            role_value, str
        ):
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
            error_msg = "Invalid Role Name provided. Select Role Name from the provided list or select 'Create New Role'."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validate New Role Name if action value is add and create new role is selected
        new_role_name = action_parameters.get("new_role_name", "")
        if action.value == "add" and is_create_new_grp and not new_role_name:
            error_msg = (
                "New Role Name is a required field when "
                "'Create New Role' is selected in the "
                "'Role Name' field."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        # Validation Successful
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_auth(self, configuration: dict) -> ValidationResult:
        """Validate CyberArk credentials."""
        # Generate the bearer token to verify the credentials
        try:
            logger_msg = "generating auth token"
            headers = self.cyberark_helper.get_protected_cyberark_headers(configuration)
            url_endpoint = "/UserMgmt/GetUserInfo"
            logger_msg = "getting user information for validating credentials"
            headers = self.cyberark_helper._add_user_agent(headers)
            self.cyberark_helper.api_helper(
                url_endpoint=url_endpoint,
                method="POST",
                headers=headers,
                is_handle_error_required=True,
                logger_msg=logger_msg,
                regenerate_auth_token=False,
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except CyberArkPluginException as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while {logger_msg}. {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while {logger_msg}. {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Invalid CyberArk Tenant URL, Username or Password. Please Check logs.",
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
                    and (parsed.path.strip() == "/" or parsed.path.strip() == "")
                )
        return False

    def validate(self, configuration: Dict):
        """Validate CyberArk configuration."""
        url = configuration.get("url", "").strip().rstrip("/")
        validation_msg = "Validation error occurred."
        if not url:
            err_msg = "Tenant URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        elif not isinstance(url, str) or not self.validate_cyberark_domain(url):
            err_msg = "Invalid Tenant URL provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        service_user = configuration.get("service_user", "").strip()
        if not service_user:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        elif not isinstance(service_user, str):
            err_msg = "Invalid Username provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )

        service_password = configuration.get("service_password", "")
        if not service_password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        elif not isinstance(service_password, str):
            err_msg = "Invalid Password provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {err_msg}."
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        return self._validate_auth(configuration)
