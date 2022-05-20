""" This is the Microsoft Azure Plugin class.
    It has generate, add, and remove actions for a user into groups.
    This Plugin class does not ingest records or users, however performs
    all other necessary functions like validate, execute actions,
    get action fields, etc.

    There is another class called MicrosoftAzureADException, which
    helps in making the user understand that the exception comes from
    the plugin of Microsoft Azure AD.
"""

from typing import List, Dict, Optional
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)
import datetime
import requests
import json

PAGE_SIZE = "999"
PAGE_RECORD_SCORE = "500"


class MicrosoftAzureADException(Exception):
    """Microsoft Azure AD exception class."""

    pass


class MicrosoftAzureADPlugin(PluginBase):
    """Microsoft Azure AD Plugin plugin implementation."""

    def _add_to_group(self, configuration: Dict, email: str, group_id: str):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Dict object having all the Plugin
                configuration parameters: token_login_url, base_url,
                client_id, client_secret, and tenant_id.
            email (str): Principle email of member to add
            group_id (str): Group ID of the group.

        Returns:

        Raises:
            HTTPError: If the group does not exist on Microsoft Azure AD.
        """

        headers = self.reload_auth_token(configuration)
        # we convert email, which we recieved in parameters of method, into id
        # as the API demands id for identifying the user
        id = self._get_email_to_id(self.configuration, email).get("id")
        headers["Content-Type"] = "application/json"

        data = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/"
            f"directoryObjects/{id}"
        }
        response = self.handle_request_exception(lambda: requests.post(
                f"{configuration.get('base_url').strip()}/v1.0/"
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
            self.logger.warn(f"Plugin: Microsoft Azure AD, cannot add as "
                             f"{email} already exists in the group.")
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
                configuration parameters:token_login_url, base_url,
                client_id, client_secret, and tenant_id.
            email (str): Principle email of member to remove.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Microsoft Azure AD.
        """

        headers = self.reload_auth_token(configuration)
        # we convert email, which we recieved in parameters of method, into id
        # as the API demands id for identifying the user
        id = self._get_email_to_id(self.configuration, email).get("id")
        headers["Content-Type"] = "application/json"

        response = self.handle_request_exception(lambda: requests.delete(
                f"{configuration.get('base_url').strip()}/v1.0/"
                f"groups/{group_id}/members/{id}/$ref",
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
        )

        if response.status_code == 204:
            # We return because there is an empty JSON response
            # So it is successful and we do not need to anything
            # more after adding the member to groups
            return

        if response.status_code == 404:
            self.logger.warn(f"Plugin: Microsoft Azure AD, cannot remove as "
                             f"{email} does not exist in the group.")
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
                configuration parameters: token_login_url, base_url,
                client_id, client_secret, and tenant_id.
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

        response = self.handle_request_exception(lambda: requests.post(
                f"{configuration.get('base_url').strip()}/v1.0/groups",
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
                configuration parameters: token_login_url, base_url,
                client_id, client_secret, and tenant_id

        Returns:
            total_group_name_array (list): List of group names

        """
        url = f"{configuration.get('base_url')}/v1.0/groups?$top=" + PAGE_SIZE
        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"
        # all the group names will be added in this variable
        total_group_name_array = []

        while True:
            response = self.handle_request_exception(lambda: requests.get(
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
            # number of groups recieved count
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

        url = f"{configuration.get('base_url')}/v1.0/users?$top=" + PAGE_SIZE
        headers = self.reload_auth_token(configuration)
        headers["Content-Type"] = "application/json"

        total_users_id_list = []

        while True:
            response = self.handle_request_exception(lambda: requests.get(
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

        response = self.handle_request_exception(lambda: requests.get(
                url,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation
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
        # store id from the response
        id = response_json["id"]
        # create a variable that has both email and id both
        email_and_id = {"email": email, "id": id}

        # we return that variable with email and id finally
        return email_and_id

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
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user.
        Calls _add_to_group or _remove_to_group in the case
            of add or remove action
        Passes when action is generate

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

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        # return nothing when action is generate
        if action.value == "generate":
            return []
        groups = self._get_all_groups(self.configuration)
        # sort the groups in ascending order by names
        groups = sorted(groups, key=lambda g: g.get("mail_nickname").lower())
        # return the all details for add group option
        # and all choices of groups to add user to
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
                    "description": "Create Microsoft Azure AD group with " +
                    "given name if it does not exist.",
                },
            ]
        # return the all details for add remove option
        # and all choices of groups to remove user from
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
        if action.value not in ["add", "remove", "generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.value == "generate":
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
                base_url (str): Base URL of Microsoft Azure AD and the
                    resource in body of GET request.
                token_login_url (str): The microsoft login token URL
                    requried to generate OAUTH2 token.
        Returns:
            json: JSON response data in case of Success.
        """
        # Note this is the method that actually interacts with the token
        # url and provides a response not only of the token but other
        # details as well. But the token is only what we need.

        client_id = configuration.get("client_id").strip()
        client_secret = configuration.get("client_secret").strip()
        tenant_id = configuration.get("tenant_id").strip()
        base_url = configuration.get("base_url").strip()
        token_login_url = configuration.get("token_login_url").strip()

        # This is the token link.
        # Looks like https://login.microsoftonline.com/xxxxxxxx
        # -xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/token
        auth_endpoint = f"{token_login_url}/{tenant_id}/oauth2/token"
        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "resource": base_url,
        }

        resp = self.handle_request_exception(lambda: requests.get(
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
            if self.storage.get(
                "token_expiry", datetime.datetime.now()
                - datetime.timedelta(minutes=1)
            ) < datetime.datetime.now():
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
            Args: configuration (dict): Contains the below keys:
                client_id (str): Client ID required to generate OAUTH2 token.
                client_secret (str): Client Secret required to generate
                    OAUTH2 token.
                tenant_id (str): Tenant ID that user wants
                base_url (str): Base URL of Microsoft Azure AD and the
                    resource in body of GET request.
                token_login_url (str): The microsoft login token URL required
                    to generate OAUTH2 token.
        Returns:.

            cte.plugin_base.ValidateResult: ValidateResult object with success
                flag and message.
        """

        self.logger.info(
            "Plugin: Executing validate method for Microsoft Azure AD plugin"
        )

        if (
            "token_login_url" not in configuration
            or not configuration["token_login_url"].strip()
            or type(configuration["token_login_url"]) != str
        ):
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation error occurred. "
                "Error: Token not found or Type of Token Login URL should "
                "be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Token Login URL provided.",
            )

        if (
            "base_url" not in configuration
            or not configuration["base_url"].strip()
            or type(configuration["base_url"]) != str
        ):
            self.logger.error(
                "Plugin: Microsoft Azure AD Validation error occurred. "
                "Error: Type of Base URL should be a non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Base URL provided.",
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
            base_url (str): Base URL of Microsoft Azure AD and the resource
                in body of GET request.
            token_login_url (str): The microsoft login token URL requried to
                generate OAUTH2 token.
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
                message="Validation successful " +
                "for Microsoft Azure AD Plugin.",
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
                message="Validation Error, unable to establish connection " +
                "with API.",
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
            self.logger.error(
                f"Microsoft Azure AD, Unexpected Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error (Check logs for more details).",
            )

    def check_url_valid(self, configuration):
        """
        Validate the base URL of Microsoft Azure AD platform.

        Args:
            Args: configuration (dict): Contains the below keys:
                client_id (str): Client ID required to generate OAUTH2 token.
                client_secret (str): Client Secret required to generate
                    OAUTH2 token.
                tenant_id (str): Tenant ID that user wants
                base_url (str): Base URL of Microsoft Azure AD and the
                    resource in body of GET request.
                token_login_url (str): The microsoft login token URL
                    requried to generate OAUTH2 token.
        Returns:
            Raise error if valid base url is not selected.
        """

        base_url = configuration.get("base_url")

        auth_json = self.get_auth_json(configuration)
        auth_token = auth_json.get("access_token")

        headers = {"Authorization": f"Bearer {auth_token}"}

        # get the top 1 user from Microsoft Graph for checking
        # whether we are connected to the API
        query_endpoint = f"{base_url}/v1.0/users?$top=1"
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
        url = f"{self.configuration.get('base_url')}/v1.0/identityProtection/riskyUsers?$top=" + PAGE_RECORD_SCORE
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"
        
        total_records = []
        
        while True:
            response = self.handle_request_exception(lambda: requests.get(
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
                currRecord = Record(uid=each_user.get("userPrincipalName"),
                                    type=RecordType.USER,
                                    score=None
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
        url = f"{self.configuration.get('base_url')}/v1.0/identityProtection/riskyUsers?$top=" + PAGE_RECORD_SCORE
        headers = self.reload_auth_token(self.configuration)
        headers["Content-Type"] = "application/json"

        score_users = {}
        total_scores = []
        
        while True:
            response = self.handle_request_exception(lambda: requests.get(
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

            # current_user_list = [{userPrincipalName,riskLevel},{userPrincipalName,riskLevel}]
            # records = [Record,Record,Record]
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
                if value == "none" or value == "hidden" or value == "unknownFutureValue":
                    total_scores.append(
                        Record(uid=key, type=RecordType.USER, score=None)
                    )
                elif value == "low":
                    total_scores.append(
                        Record(uid=key, type=RecordType.USER, score=300)
                    )
                elif value == "medium":
                    total_scores.append(
                        Record(uid=key, type=RecordType.USER, score=600)
                    )
                elif value == "high":
                    total_scores.append(
                        Record(uid=key, type=RecordType.USER, score=900)
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
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                raise MicrosoftAzureADException(
                    "Plugin: Microsoft Azure AD, "
                    "Exception occurred while parsing JSON response."
                )
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
        # exception handling
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
