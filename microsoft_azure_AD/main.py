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

"""Microsoft Azure AD CRE Plugin."""

import datetime
import json
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

PAGE_SIZE = "999"
PAGE_RECORD_SCORE = "500"


class MicrosoftAzureADException(Exception):
    """Microsoft Azure AD exception class."""

    pass


class MicrosoftAzureADPlugin(PluginBase):
    """Microsoft Azure AD plugin implementation."""

    def _add_to_group(self, configuration: Dict, email: str, group_id: str):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Dict object having all the Plugin
                configuration parameters: client_id, client_secret,
                and tenant_id.
            email (str): Principle email of member to add
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Microsoft Azure AD.
        """
        headers = self.reload_auth_token(configuration)
        # we convert email, which we received in parameters of method, into id
        # as the API demands id for identifying the user
        id = self._get_email_to_id(self.configuration, email).get("id")
        headers["Content-Type"] = "application/json"

        data = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/"
            f"directoryObjects/{id}"
        }
        response = self.handle_request_exception(
            lambda: requests.post(
                f"https://graph.microsoft.com/v1.0/"
                f"groups/{group_id}/members/$ref",
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(data),
            )
        )

        if response.status_code == 204:
            # We return because there is an empty JSON response
            # So it is successful and we do not need to anything
            # more after adding the member to group
            return
        if response.status_code == 400:
            self.logger.warn(
                f"Plugin: Microsoft Azure AD, cannot add as "
                f"{email} already exists in the group."
            )
            return

        response_json = self.handle_error(response)
        auth_errors = response_json.get("errors")

        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            raise requests.HTTPError(
                f"Plugin: Microsoft Azure AD, unable to add {email} to group. "
                f"Error: {err_msg}."
            )

        return response_json

    def _remove_from_group(
        self, configuration: Dict, email: str, group_id: str
    ):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Dict object having all the Plugin
                configuration parameters: client_id, client_secret,
                and tenant_id.
            email (str): Principle email of member to remove.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Microsoft Azure AD.
        """
        headers = self.reload_auth_token(configuration)
        id = self._get_email_to_id(self.configuration, email).get("id")
        headers["Content-Type"] = "application/json"

        response = self.handle_request_exception(
            lambda: requests.delete(
                f"https://graph.microsoft.com/v1.0/"
                f"groups/{group_id}/members/{id}/$ref",
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
        )

        if response.status_code == 204:
            return

        if response.status_code == 404:
            self.logger.warn(
                f"Plugin: Microsoft Azure AD, cannot remove as "
                f"{email} does not exist in the group."
            )
            return

        response_json = self.handle_error(response)
        auth_errors = response_json.get("errors")

        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            raise requests.HTTPError(
                f"Plugin: Microsoft Azure AD, unable to remove {email} "
                f"to group. "
                f"Error: {err_msg}."
            )

        return response_json

    def _create_group(
        self, configuration: Dict, name: str, mail_nickname: str
    ) -> Dict:
        """Create a new group with name.

        Args:
            configuration (Dict): Dict object having all the Plugin
                configuration parameters: client_id, client_secret,
                and tenant_id.
            name (str): Name of the group to create.
            description (str): Group decription.

        Returns:
            Dict: Newly created group dictionary.
        """
        # details required of group will be in the body of request
        body = {
            "description": "Created From Netskope CRE.",
            "displayName": name,
            "groupTypes": ["Unified"],
            "mailEnabled": True,
            "mailNickname": mail_nickname,
            "securityEnabled": False,
        }

        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"

        response = self.handle_request_exception(
            lambda: requests.post(
                "https://graph.microsoft.com/v1.0/groups",
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(body),
            )
        )
        response_json = self.handle_error(response)
        auth_errors = response_json.get("errors")

        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            raise requests.HTTPError(
                "Plugin: Microsoft Azure AD, unable to create group. "
                f"Error: {err_msg}."
            )

        return response_json.get("id")

    def _get_all_groups(self, configuration: Dict) -> List:
        """Gets all group names

        Args:
            configuration (dict): Dict object having all the Plugin
                configuration parameters: client_id, client_secret,
                and tenant_id

        Returns:
            total_group_name_array (list): List of group names

        """
        url = f"https://graph.microsoft.com/v1.0/groups?$top={PAGE_SIZE}"
        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"
        # all the group names will be added in this variable
        total_group_name_array = []

        while True:
            response = self.handle_request_exception(
                lambda: requests.get(
                    url,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
            )

            response_json = self.handle_error(response)
            auth_errors = response_json.get("errors")
            if auth_errors:
                err_msg = auth_errors[0].get("message", "")
                raise requests.HTTPError(
                    "Plugin: Microsoft Azure AD unable to get all group. "
                    f"Error: {err_msg}."
                )
            # stores the number of groups in that particular pagination query
            current_group_array = response_json.get("value")
            # number of groups received count
            current_group_count = len(current_group_array)

            for each_group in current_group_array:
                # note that mailNickname is unique that is why we use it
                # instead of display name
                group_and_id = {}
                group_and_id["id"] = each_group.get("id")
                group_and_id["mail_nickname"] = each_group.get("mailNickname")
                total_group_name_array.append(group_and_id)

            # if number of groups is less than page size, we know that
            # this is the last page of the request. Hence, we break
            if current_group_count < int(PAGE_SIZE):
                break
            # likewise this is another check for last page
            # Microsoft graph won't provide nextLink of page
            # Hence, we break
            if "@odata.nextLink" not in response_json.keys():
                break

            url = response_json.get("@odata.nextLink")

        return total_group_name_array

    def _find_group_by_name(self, groups: List, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("mail_nickname") == name:
                return group
        return None

    def _get_all_users(self, configuration):
        """Returns all the users in a list.

        Args:
            configuration (str): Details needed for a REST call to API

        Returns:
            users (List): all the users under the tenant

        """

        url = f"https://graph.microsoft.com/v1.0/users?$top={PAGE_SIZE}"
        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"

        total_users_id_list = []

        while True:
            response = self.handle_request_exception(
                lambda: requests.get(
                    url,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
            )
            response_json = self.handle_error(response)
            auth_errors = response_json.get("errors")
            if auth_errors:
                err_msg = auth_errors[0].get("message", "")
                raise requests.HTTPError(
                    "Plugin: Microsoft Azure AD unable to get all users. "
                    f"Error: {err_msg}."
                )

            current_user_list = response_json.get("value")
            current_user_count = len(current_user_list)

            # We get all the user id and store it in total user id list
            for each_user in current_user_list:
                total_users_id_list.append(each_user.get("userPrincipalName"))

            # if number of groups is less than page size, we know that
            # this is the last page of the request. Hence, we break
            if current_user_count < int(PAGE_SIZE):
                break
            # likewise this is another check for last page
            # Microsoft graph won't provide nextLink of page
            # Hence, we break
            if "@odata.nextLink" not in response_json.keys():
                break

            url = response_json.get("@odata.nextLink")

        return total_users_id_list

    def _get_email_to_id(self, configuration, email):

        """Add specified user to the specified group.

        Args:
            email (str): User Principle email to change to id

        Returns:
            email_and_id (Dict): Dict containing email and id

        """
        url = f"https://graph.microsoft.com/v1.0/users/{email}"
        # reload token for authentication
        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"

        response = self.handle_request_exception(
            lambda: requests.get(
                url,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
        )

        response_json = self.handle_error(response)
        auth_errors = response_json.get("errors")

        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            raise requests.HTTPError(
                f"Plugin: Microsoft Azure AD, unable to get id from email. "
                f"Error: {err_msg}."
            )
        id = response_json["id"]
        return {"email": email, "id": id}

    def _match_user_by_email(self, user, all_users_ids_names):
        for each_user in all_users_ids_names:
            if user == each_user:
                return each_user
        return None

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

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user.

        Args:
            record (Record): Record of a user you want to perform an action on
            action (Action): The type of action

        Returns:
            None
        """
        if action.value == "generate":
            return
        user = record.uid
        all_users = self._get_all_users(self.configuration)
        match = self._match_user_by_email(user, all_users)

        if match is None:
            self.logger.warn(
                f"Microsoft Azure AD CRE: User with email {user} not "
                f"found on Azure AD."
            )
            return

        if action.value == "add":
            # gets the group name. Note the group with string "create"
            # will create a new group that does not exist
            group_id = action.parameters.get("group")
            # here we have the logic of creating a new group
            if group_id == "create":
                groups = self._get_all_groups(self.configuration)
                mail_nickname = action.parameters.get("name").strip()
                match_group = self._find_group_by_name(groups, mail_nickname)
                if match_group is None:  # create group
                    # create group returns group id
                    group_id = self._create_group(
                        self.configuration, mail_nickname, mail_nickname
                    )
                else:
                    group_id = match_group.get("id")
            self._add_to_group(self.configuration, match, group_id)
            self.logger.info(
                f"Microsoft Azure AD: Added {user} to group with "
                f"ID {action.parameters.get('group')}."
            )
        elif action.value == "remove":
            self._remove_from_group(
                # note that action.parameters.get("group")
                # is the unique id and not display name
                self.configuration,
                match,
                action.parameters.get("group"),
            )
            self.logger.info(
                f"Microsoft Azure AD: Removed {user} from group with "
                f"ID {action.parameters.get('group')}."
            )
        elif action.value == "confirm_compromised":
            user_info = self._get_email_to_id(
                configuration=self.configuration, email=user
            )
            user_id = user_info.get("id")
            url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised"
            headers = self.reload_auth_token(self.configuration)
            data = {"userIds": [user_id]}
            response = requests.post(
                url=url,
                headers=add_user_agent(headers),
                json=data,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            self.handle_error(resp=response)
            if response.status_code == 204:
                self.logger.info(
                    "Microsoft Azure AD: Successfully performed Confirm "
                    f"compromised action on user: {user_info.get('email')}."
                )
            else:
                self.logger.error(
                    "Microsoft Azure AD: Could not perform Confirm compromised"
                    f" action on user {user_info.get('email')}."
                )

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate", "confirm_compromised"]:
            return []
        groups = self._get_all_groups(self.configuration)
        groups = sorted(groups, key=lambda g: g.get("mail_nickname").lower())
        if action.value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["mail_nickname"], "value": g["id"]}
                        for g in groups
                    ]
                    + [{"key": "Create new group", "value": "create"}],
                    "default": groups[0]["id"],
                    "mandatory": True,
                    "description": "Select a group to add the user to.",
                },
                {
                    "label": "Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Create Microsoft Azure AD group with "
                    + "given name if it does not exist.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["mail_nickname"], "value": g["id"]}
                        for g in groups
                    ],
                    "default": groups[0]["id"],
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Microsoft Azure AD action configuration."""
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
        groups = self._get_all_groups((self.configuration))
        if action.parameters.get("group") != "create" and not any(
            map(lambda g: g["id"] == action.parameters.get("group"), groups)
        ):
            return ValidationResult(
                success=False, message="Invalid group ID provided."
            )
        if (
            action.value == "add"
            and action.parameters.get("group") == "create"
            and len(action.parameters.get("name", "").strip()) == 0
        ):
            return ValidationResult(
                success=False, message="Group Name can not be empty."
            )
        return ValidationResult(success=True, message="Validation successful.")

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
        client_secret = configuration.get("client_secret").strip()
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

        resp = self.handle_request_exception(
            lambda: requests.get(
                auth_endpoint,
                data=auth_params,
                proxies=self.proxy,
                verify=self.ssl_validation,
                headers=add_user_agent(),
            )
        )

        auth_json = self.handle_error(resp)
        auth_errors = auth_json.get("errors")
        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            raise requests.HTTPError(
                f"Plugin: Microsoft Azure AD Unable to generate Auth token. "
                f"Error: {err_msg}."
            )
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

    def reload_auth_token(self, configuration):
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
                    "Plugin: Microsoft Azure AD OAUTH2 token expired. "
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
        self.logger.info(
            "Plugin: Executing validate method for Microsoft Azure AD plugin"
        )

        if (
            "client_id" not in configuration
            or not configuration["client_id"].strip()
            or type(configuration["client_id"]) != str
        ):
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation error occurred. "
                "Error: Type of Client ID should be a non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client ID provided.",
            )

        if (
            "client_secret" not in configuration
            or not configuration["client_secret"]
            or type(configuration["client_secret"]) != str
        ):
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation error occurred. "
                "Error: Type of Client Secret should be a non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client Secret provided.",
            )

        if (
            "tenant_id" not in configuration
            or not configuration["tenant_id"]
            or type(configuration["tenant_id"]) != str
        ):
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation error occurred. "
                "Error: Type of Tenant ID should be a non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Tenant ID provided.",
            )

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
            # in short, this calls the check_url_valid, which makes a
            # request to Microsoft Graph API to get the top 1 user.
            # That is how we validate whether we have been connected
            # and validated to Microsoft Azure AD

            self.check_url_valid(configuration)

            return ValidationResult(
                success=True,
                message="Validation successful "
                + "for Microsoft Azure AD Plugin.",
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation Error, "
                "invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation Error, "
                "unable to establish connection with "
                "Microsoft Azure AD Platform API."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, unable to establish connection "
                + "with API.",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Microsoft Azure AD Plugin: Validation Error, "
                f"error in validating credentials {repr(err)}."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, error in validating credentials.",
            )
        except Exception as e:
            self.logger.error(f"Microsoft Azure AD, Unexpected Exception: {e}")
            return ValidationResult(
                success=False,
                message="Validation Error (Check logs for more details).",
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
        query_endpoint = "https://graph.microsoft.com/v1.0/users?$top=1"
        all_agent_resp = requests.get(
            query_endpoint,
            headers=add_user_agent(headers),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        if all_agent_resp.status_code == 401:
            raise requests.HTTPError("Invalid base url.")

        agent_resp_json = self.handle_error(all_agent_resp)
        errors = agent_resp_json.get("errors")
        if errors:
            err_msg = errors[0].get("message", "")
            raise requests.HTTPError(
                f"Plugin: Microsoft Azure Unable to Fetch Agents, "
                f"Error: {err_msg}."
            )
        return agent_resp_json

    def fetch_records(self) -> List[Record]:
        """Pull Records from Microsoft Azure AD.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        url = (
            "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top="
            + PAGE_RECORD_SCORE
        )
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        total_records = []

        while True:
            response = self.handle_request_exception(
                lambda: requests.get(
                    url,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
            )
            response_json = self.handle_error(response)
            auth_errors = response_json.get("errors")
            if auth_errors:
                err_msg = auth_errors[0].get("message", "")
                raise requests.HTTPError(
                    "Plugin: Microsoft Azure AD unable to get all users. "
                    f"Error: {err_msg}."
                )

            current_user_list = response_json.get("value")
            current_user_count = len(current_user_list)

            # We get all the user id and store it in total user id list
            for each_user in current_user_list:
                currRecord = Record(
                    uid=each_user.get("userPrincipalName"),
                    type=RecordType.USER,
                    score=None,
                )
                total_records.append(currRecord)

            # if number of groups is less than page size, we know that
            # this is the last page of the request. Hence, we break
            if current_user_count < int(PAGE_RECORD_SCORE):
                break
            # likewise this is another check for last page
            # Microsoft graph won't provide nextLink of page
            # Hence, we break
            if "@odata.nextLink" not in response_json.keys():
                break

            url = response_json.get("@odata.nextLink")

        return total_records

    def fetch_scores(self, records: List[Record]) -> List[Record]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        url = (
            "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top="
            + PAGE_RECORD_SCORE
        )
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        score_users = {}
        total_scores = []

        while True:
            response = self.handle_request_exception(
                lambda: requests.get(
                    url,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
            )
            response_json = self.handle_error(response)
            auth_errors = response_json.get("errors")
            if auth_errors:
                err_msg = auth_errors[0].get("message", "")
                raise requests.HTTPError(
                    "Plugin: Microsoft Azure AD unable to get all users. "
                    f"Error: {err_msg}."
                )

            current_user_list = response_json.get("value")
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
            if "@odata.nextLink" not in response_json.keys():
                break

            url = response_json.get("@odata.nextLink")

        if score_users:
            for key, value in score_users.items():
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

        return total_scores

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code in [200, 201]:
            try:
                return resp.json()
            except ValueError:
                raise MicrosoftAzureADException(
                    "Plugin: Microsoft Azure AD, "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 204:
            return
        elif resp.status_code == 401:
            raise MicrosoftAzureADException(
                "Plugin: Microsoft Azure AD, "
                "Received exit code 401, Authentication Error."
            )
        elif resp.status_code == 403:
            raise MicrosoftAzureADException(
                "Plugin: Microsoft Azure AD, "
                "Received exit code 403, Forbidden User."
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            raise MicrosoftAzureADException(
                f"Plugin: Microsoft Azure AD, "
                f"Received exit code {resp.status_code}, HTTP client Error."
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            raise MicrosoftAzureADException(
                f"Plugin: Microsoft Azure AD, "
                f"Received exit code {resp.status_code}, HTTP server Error."
            )
        else:
            raise MicrosoftAzureADException(
                f"Plugin: Microsoft Azure AD, "
                f"Received exit code {resp.status_code}, HTTP Error."
            )

    def handle_request_exception(self, one_request):
        try:
            return one_request()
        except requests.exceptions.ProxyError:
            raise requests.HTTPError(
                "Plugin: Microsoft Azure AD, invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            requests.HTTPError(
                "Plugin: Microsoft Azure AD, unable to establish connection "
                "with Microsoft Azure AD platform. "
                "Proxy server or Microsoft Azure AD is not reachable."
            )
