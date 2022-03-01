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

"""Okta CRE plugin."""


from typing import List, Dict, Optional

import requests
import re

from urllib.parse import urlparse, parse_qs

from requests.models import HTTPError

from netskope.common.utils import add_user_agent

from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    ActionWithoutParams,
    Action,
)


class OktaPlugin(PluginBase):
    """Okta plugin implementation."""

    def fetch_records(self) -> List[Record]:
        """Pull Records from Okta.

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

    def _add_to_group(self, configuration: Dict, user_id: str, group_id: str):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Okta.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f'SSWS {configuration.get("api_token").strip()}',
        }
        response = requests.put(
            f"{configuration.get('url').strip()}/api/v1/groups/{group_id}/users/{user_id}",
            headers=add_user_agent(headers),
            proxies=self.proxy,
        )
        if response.status_code == 404:
            raise HTTPError(
                f"Group with id {group_id} does not exist on okta."
            )
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
            HTTPError: If the group does not exist on Okta.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f'SSWS {configuration.get("api_token").strip()}',
        }
        response = requests.delete(
            f"{configuration.get('url').strip()}/api/v1/groups/{group_id}/users/{user_id}",
            headers=add_user_agent(headers),
            proxies=self.proxy,
        )
        if response.status_code == 404:
            raise HTTPError(
                f"Group with id {group_id} does not exist on okta."
            )
        response.raise_for_status()

    def _get_all_groups(self, configuration: Dict) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        params = {}
        url = f"{configuration.get('url').strip()}/api/v1/groups"
        params["limit"] = 200
        params["filter"] = 'type eq "OKTA_GROUP"'
        after = ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {configuration.get('api_token').strip()}",
        }
        while True:
            groups = requests.get(
                url=url,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            groups.raise_for_status()
            all_groups += groups.json()
            links = re.findall(r"(https?://\S+)", groups.headers["link"])
            flag = False
            for link in links:
                if "after" in link:
                    parsed_url = urlparse(link)
                    after_from_link = parse_qs(parsed_url.query)["after"]
                    if after_from_link != after:
                        params["after"] = after_from_link
                        after = after_from_link
                        flag = True
                    else:
                        flag = False
            if not flag:
                break
        return all_groups

    def _get_all_users(self, configuration: Dict) -> List:
        """Get list of all the users.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the users.
        """
        all_users = []
        params = {}
        url = f"{configuration.get('url').strip()}/api/v1/users"
        params["limit"] = 200
        after = ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "okta-response": "omitCredentials, omitCredentialsLinks, omitTransitioningToStatus",
            "Authorization": f"SSWS {configuration.get('api_token').strip()}",
        }
        while True:
            users = requests.get(
                url=url,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            users.raise_for_status()
            all_users += users.json()
            links = re.findall(r"(https?://\S+)", users.headers["link"])
            flag = False
            for link in links:
                if "after" in link:
                    parsed_url = urlparse(link)
                    after_from_link = parse_qs(parsed_url.query)["after"]
                    if after_from_link != after:
                        params["after"] = after_from_link
                        after = after_from_link
                        flag = True
                    else:
                        flag = False
            if not flag:
                break
        return all_users

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries.
            email (str): Email to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        for user in users:
            if user.get("profile").get("email") == email:
                return user
        return None

    def _find_group_by_name(self, groups: List, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("profile").get("name") == name:
                return group
        return None

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _create_group(self, configuration: Dict, name: str) -> Dict:
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the group to create.
            description (str): Group decription.

        Returns:
            Dict: Newly created group dictionary.
        """
        body = {
            "profile": {
                "name": name,
                "description": "Created From Netskop CRE",
            }
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {configuration.get('api_token').strip()}",
        }
        response = requests.post(
            f"{configuration.get('url').strip()}/api/v1/groups",
            headers=add_user_agent(headers),
            json=body,
            proxies=self.proxy,
        )
        if response.status_code == 400:
            err = response.json()["errorCauses"][0]["errorSummary"]
            raise HTTPError(err)
        response.raise_for_status()
        return response.json()

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        if action.value == "generate":
            pass
        user = record.uid
        users = self._get_all_users(self.configuration)
        match = self._find_user_by_email(users, user)
        if match is None:
            self.logger.warn(
                f"Okta CRE: User with email {user} not found on Okta."
            )
            return
        if action.value == "add":
            group_id = action.parameters.get("group")
            if group_id == "create":
                groups = self._get_all_groups(self.configuration)
                group_name = action.parameters.get("name").strip()
                match_group = self._find_group_by_name(groups, group_name)
                if match_group is None:  # create group
                    group = self._create_group(self.configuration, group_name)
                    group_id = group["id"]
                else:
                    group_id = match_group["id"]
            self._add_to_group(self.configuration, match["id"], group_id)
        elif action.value == "remove":
            self._remove_from_group(
                self.configuration, match["id"], action.parameters.get("group")
            )
            self.logger.info(
                f"Okta CRE: Removed {user} from group with ID {action.parameters.get('group')}."
            )

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == "generate":
            return []
        groups = self._get_all_groups(self.configuration)
        groups = sorted(
            groups, key=lambda g: g.get("profile").get("name").lower()
        )
        if action.value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["profile"]["name"], "value": g["id"]}
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
                    "description": "Create Okta group with given name if it does not exist.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["profile"]["name"], "value": g["id"]}
                        for g in groups
                    ],
                    "default": groups[0]["id"],
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Okta action configuration."""
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

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_auth(self, domain, token):
        """Validate okta credentials."""
        url = f"{domain}/api/v1/users?limit=1"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {token}",
        }
        try:
            response = requests.get(
                url=url, headers=headers, proxies=self.proxy
            )
            response.raise_for_status()
            if response.status_code in [200, 201]:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except Exception as err:
            self.logger.error(
                f"Okta CRE: Error occured while authentication. {err}"
            )
        return ValidationResult(
            success=False, message="Invalid Okta domain or API Token. check logs."
        )

    def validate_okta_domain(self, url: str):
        """Validate okta domain."""
        valid_domains = [".oktapreview.com", ".okta.com", ".okta-emea.com"]
        for domain in valid_domains:
            if domain in url:
                return True
        return False

    def validate(self, configuration: Dict):
        """Validate Okta configuration."""
        if (
            "url" not in configuration
            or not configuration["url"].strip()
            or not self._validate_url(configuration["url"])
            or not self.validate_okta_domain(configuration["url"].strip())
        ):
            self.logger.error("Okta CRE: Invalid Okta domain provided.")
            return ValidationResult(
                success=False, message="Invalid Okta domain provided."
            )

        if (
            "api_token" not in configuration
            or not configuration["api_token"].strip()
        ):
            self.logger.error("Okta CRE: API Token should not be empty.")
            return ValidationResult(
                success=False,
                message="API Token should not be empty.",
            )
        return self._validate_auth(
            configuration["url"].strip(), configuration["api_token"].strip()
        )
