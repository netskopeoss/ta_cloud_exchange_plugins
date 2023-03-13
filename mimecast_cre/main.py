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

"""Mimecast URE Plugin."""

from typing import List, Dict, Optional

import requests
import re
import base64
import hashlib
import hmac
import uuid

from datetime import datetime

from requests.models import HTTPError

from netskope.common.utils import add_user_agent

from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)

PLUGIN_NAME = "Mimecast URE Plugin"


class MimecastPlugin(PluginBase):
    """Mimecast plugin implementation."""

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
            if group.get("description") == name:
                return group
        return None

    def _get_auth_headers(
        self, configuration: dict, endpoint: str
    ) -> (str, dict):
        """Generate Mimecast authentication headers."""
        request_url = f"{configuration.get('url').strip('/')}{endpoint}"
        request_id = str(uuid.uuid4())
        request_datetime = (
            f"{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S')} UTC"
        )

        # Create the HMAC SA1 of the Base64 decoded secret key for the Authorization header
        hmac_sha1 = hmac.new(
            base64.b64decode(configuration.get("secret_key").strip()),
            ":".join(
                [
                    request_datetime,
                    request_id,
                    endpoint,
                    configuration.get("app_key").strip(),
                ]
            ).encode("utf-8"),
            digestmod=hashlib.sha1,
        ).digest()

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": f"MC {configuration.get('access_key').strip()}:"
            f"{sig.decode('utf-8')}",
            "x-mc-app-id": configuration.get("app_id").strip(),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        return request_url, headers

    def _get_all_groups(self, configuration: Dict) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        endpoint = "/api/directory/find-groups"
        pageSize = 100
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
        while True:
            groups = requests.post(
                url=request_url,
                headers=add_user_agent(headers),
                data=str(body),
                proxies=self.proxy,
            )
            groups.raise_for_status()
            groups = groups.json()
            all_groups += groups.get("data", {})[0].get("folders", {})
            nextPage = (
                groups.get("meta", {}).get("pagination", {}).get("next", "")
            )
            if nextPage:
                body["meta"]["pagination"]["pageToken"] = nextPage
            else:
                break
        return all_groups

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
        response = requests.post(
            url=request_url,
            headers=add_user_agent(headers),
            data=str(body),
            proxies=self.proxy,
        )
        if response.status_code == 200:
            failures = response.json().get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                raise HTTPError(error)
        response.raise_for_status()
        return response.json()

    def _add_to_group(self, configuration: Dict, user_id: str, group_id: str):
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
        response = requests.post(
            url=request_url, headers=add_user_agent(headers), data=str(body)
        )
        if response.status_code == 200:
            failures = response.json().get("fail", [])
            if failures:
                for failure in failures:
                    for error in failure.get("errors", []):
                        if (
                            error["code"]
                            != "err_folder_group_member_already_exists"
                        ):
                            raise HTTPError(error["message"])
        response.raise_for_status()

    def _remove_from_group(
        self, configuration: Dict, user_id: str, group_id: str
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
        response = requests.post(
            url=request_url, headers=add_user_agent(headers), data=str(body)
        )
        if response.status_code == 200:
            failures = response.json().get("fail", [])
            if failures:
                for failure in failures:
                    for error in failure.get("errors", []):
                        if (
                            error["code"]
                            != "err_folder_email_address_not_found"
                        ):
                            raise HTTPError(error["message"])
        response.raise_for_status()

    def _get_all_users(self, action: bool) -> List:
        """Get list of all the users.

        Args:
            action (Boolean): Whether this method is called from execute_action or not

        Returns:
            List: List of all the users.
        """
        rec = []
        endpoint = "/api/awareness-training/company/get-safe-score-details"
        pageSize = 100
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
        while True:
            response = requests.post(
                url=request_url,
                headers=add_user_agent(headers),
                data=str(body),
                proxies=self.proxy,
            )
            response = self.handle_error(response, action)
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    f"{PLUGIN_NAME}: Unable to fetch users, Error: {error}"
                )
                raise HTTPError(
                    f"{PLUGIN_NAME}: Unable to fetch users, Error: {error}"
                )
            records = response.get("data", [])
            rec += records
            nextPage = (
                response.get("meta", {}).get("pagination", {}).get("next", "")
            )
            if nextPage:
                body["meta"]["pagination"]["pageToken"] = nextPage
            else:
                break
        return rec

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries
            email (str): Email to find.

        Returns:
            Optional[Dict]: user dictionary if found, None otherwise.
        """
        for user in users:
            if user.get("emailAddress") == email:
                return user
        return None

    def fetch_records(self) -> List[Record]:
        """Pull Records from Mimecast.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        rec = []
        records = self._get_all_users(False)
        self.logger.info(f"{PLUGIN_NAME}: Processing users.")
        for record in records:
            rec.append(
                Record(
                    uid=record["emailAddress"],
                    type=RecordType.USER,
                    score=None,
                )
            )
        return rec

    def fetch_scores(self, res):
        """Fetch user scores."""
        # A 800 - 1000
        # B 600 - 799
        # C 400 - 599
        # D 200 - 399
        # F 1 - 199
        scored_users = []
        score_users = {}
        users = self._get_all_users(False)
        for user in users:
            for record in res:
                if user["emailAddress"] in record.uid:
                    score_users[user["emailAddress"]] = user["risk"]
        if score_users:
            minvalue = 1
            maxvalue = 1000
            for key, value in score_users.items():
                if value == "A":
                    score = 800
                    scored_users.append(
                        Record(uid=key, type=RecordType.USER, score=score)
                    )
                elif value == "B":
                    score = 600
                    scored_users.append(
                        Record(uid=key, type=RecordType.USER, score=score)
                    )
                elif value == "C":
                    score = 400
                    scored_users.append(
                        Record(uid=key, type=RecordType.USER, score=score)
                    )
                elif value == "D":
                    score = 200
                    scored_users.append(
                        Record(uid=key, type=RecordType.USER, score=score)
                    )
                elif value == "F":
                    score = 1
                    scored_users.append(
                        Record(uid=key, type=RecordType.USER, score=score)
                    )
            self.logger.info(
                f"{PLUGIN_NAME}: processing scores and normalizing for min value {minvalue} and "
                f"max value {maxvalue}."
            )
        return scored_users

    def get_actions(self) -> list[ActionWithoutParams]:
        """Get Available actions."""
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == "generate":
            return []
        groups = self._get_all_groups(self.configuration)
        groups = sorted(groups, key=lambda g: g.get("description").lower())
        if action.value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [{"key": "Create new group", "value": "create"}]
                    + [
                        {"key": g["description"], "value": g["id"]}
                        for g in groups
                    ],
                    "default": "create",
                    "mandatory": True,
                    "description": "Select a group to add the user to. ",
                },
                {
                    "label": "Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "A_Cloud_Exchange",
                    "mandatory": False,
                    "description": "Create a Mimecast group with given name if it does not exits.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["description"], "value": g["id"]}
                        for g in groups
                    ],
                    "default": groups[0]["id"],
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        user = record.uid
        users = self._get_all_users(True)
        match = self._find_user_by_email(users, user)
        if match is None:
            self.logger.warn(
                f"{PLUGIN_NAME}: User with email {user} not found on Mimecast."
            )
            return
        if action.value == "generate":
            pass
        if action.value == "add":
            group_id = action.parameters.get("group")
            if group_id == "create":
                groups = self._get_all_groups(self.configuration)
                group_name = action.parameters.get("name").strip()
                match_group = self._find_group_by_name(groups, group_name)
                if match_group is None:
                    group = self._create_group(self.configuration, group_name)
                    group_id = group.get("data", {})[0].get("id", "")
                else:
                    group_id = match_group["id"]
            self._add_to_group(
                self.configuration, match["emailAddress"], group_id
            )
        elif action.value == "remove":
            self._remove_from_group(
                self.configuration,
                match["emailAddress"],
                action.parameters.get("group"),
            )
            self.logger.info(
                f"{PLUGIN_NAME}: Removed {user} from group with ID {action.parameters.get('group')}."
            )

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Mimecast action configuration."""
        if action.value not in ["add", "remove", "generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        groups = self._get_all_groups(self.configuration)
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

    def _validate_credentials(
        self, configuration: dict
    ) -> (ValidationResult, List[str]):
        """Validate credentials by making REST API call."""
        try:
            url, headers = self._get_auth_headers(
                configuration, "/api/account/get-account"
            )
            response = requests.post(
                url,
                json={"data": []},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

            if response.status_code == 200:
                failures = response.json().get("fail", [])
                if not failures:
                    return ValidationResult(
                        success=True, message="Validation successful."
                    ), response.json().get("data", [{}])[0].get("packages", [])
                return (
                    ValidationResult(
                        success=False,
                        message=", ".join(self._parse_errors(failures)),
                    ),
                    None,
                )

            elif response.status_code == 401:
                return (
                    ValidationResult(
                        success=False,
                        message="Incorrect access key or secret key or application key provided.",
                    ),
                    None,
                )
            else:
                return (
                    ValidationResult(
                        success=False,
                        message=(
                            f"An HTTP error occurred while validating configuration "
                            f"parameters. Status code {response.status_code}."
                        ),
                    ),
                    None,
                )
        except requests.ConnectionError as ex:
            self.logger.error(f"{PLUGIN_NAME}: {repr(ex)}")
            return (
                ValidationResult(
                    success=False,
                    message="Incorrect Mimecast base URL provided.",
                ),
                None,
            )
        except Exception as ex:
            self.logger.error(f"{PLUGIN_NAME}: {repr(ex)}")
            return (
                ValidationResult(
                    success=False,
                    message="Error occurred while validating configuration parameters. Check logs for more detail.",
                ),
                None,
            )

    def validate(self, configuration: Dict):
        """Validate Mimecast configuration."""

        if (
            "url" not in configuration
            or not configuration["url"].strip()
            or type(configuration["url"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Mimecast base URL must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Mimecast base URL must be a valid non-empty string.",
            )

        if (
            "app_id" not in configuration
            or not configuration["app_id"].strip()
            or type(configuration["app_id"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Application ID must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Application ID must be a valid non-empty string.",
            )

        if (
            "app_key" not in configuration
            or not configuration["app_key"].strip()
            or type(configuration["app_key"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Application Key must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Application Key must be a valid non-empty string.",
            )

        if (
            "access_key" not in configuration
            or not configuration["access_key"].strip()
            or type(configuration["access_key"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Access Key must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Access Key must be a valid non-empty string.",
            )

        if (
            "secret_key" not in configuration
            or not configuration["secret_key"].strip()
            or type(configuration["secret_key"]) != str
            or
            # Base 64 check
            not re.match(
                r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
                configuration["secret_key"],
            )
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Access Secret must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Access Secret must be a valid non-empty string.",
            )
        validation_result, packages = self._validate_credentials(configuration)

        if not validation_result.success:
            return validation_result

        if "Awareness Training [1078]" not in packages:
            self.logger.error(
                f"{PLUGIN_NAME}: 'Awareness Training' package is not enabled in "
                "configured account and hence fetching score is not possible."
            )
            return ValidationResult(
                success=False,
                message="'Awareness Training' package is not enabled in "
                "configured account and hence fetching score is not possible.",
            )

        return validation_result

    def handle_error(self, resp, action):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
            action (bool): Whether this method is called from execute_action or not.
        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if action:
            resp.raise_for_status()
            return resp.json()
        else:
            if resp.status_code == 200 or resp.status_code == 201:
                try:
                    return resp.json()
                except ValueError:
                    self.notifier.error(
                        f"{PLUGIN_NAME}: "
                        "Exception occurred while parsing JSON response."
                    )
                    self.logger.error(
                        f"{PLUGIN_NAME}: "
                        "Exception occurred while parsing JSON response."
                    )
            elif resp.status_code == 401:
                self.notifier.error(
                    f"{PLUGIN_NAME}: "
                    "Received exit code 401, Authentication Error"
                )
                self.logger.error(
                    f"{PLUGIN_NAME}: "
                    "Received exit code 401, Authentication Error"
                )
            elif resp.status_code == 403:
                self.notifier.error(
                    f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
                )
                self.logger.error(
                    f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
                )
            elif resp.status_code >= 400 and resp.status_code < 500:
                self.notifier.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP client Error"
                )
                self.logger.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP client Error"
                )
            elif resp.status_code >= 500 and resp.status_code < 600:
                self.notifier.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP server Error"
                )
                self.logger.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP server Error"
                )
            else:
                self.notifier.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP Error"
                )
                self.logger.error(
                    f"{PLUGIN_NAME}: "
                    f"Received exit code {resp.status_code}, HTTP Error"
                )
            resp.raise_for_status()
