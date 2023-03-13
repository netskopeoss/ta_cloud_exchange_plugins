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

"""Security Advisor URE plugin."""


from typing import List, Dict
import requests
from requests.exceptions import ConnectionError
from netskope.common.utils import add_user_agent
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)

PLUGIN_NAME = "Security Advisor URE Plugin"


class SecurityAdvisorPlugin(PluginBase):
    """Security Advisor plugin implementation."""

    def fetch_records(self) -> List:
        """Fetch list of users."""
        USERS_URL = self.configuration.get("base_url").strip()
        page = 1
        total_pages = 1
        res = []
        headers = {
            "Authorization": f"Token {self.configuration.get('API_token').strip()}"
        }
        while True:
            users = requests.get(
                f"{USERS_URL}/apis/v1/behaviorscore",
                headers=add_user_agent(headers),
                params={"page": page},
                proxies=self.proxy,
            )
            users_resp_json = self.handle_error(users)
            self.logger.info(f"{PLUGIN_NAME}: Processing users.")
            users = users_resp_json["results"]
            for user in users:
                res.append(
                    Record(uid=user["email"], type=RecordType.USER, score=None)
                )
            total_pages = users_resp_json["total_pages"]
            page = page + 1
            if page == total_pages + 1:
                break
        return res

    def fetch_scores(self, res):
        """Fetch user scores."""
        USERS_URL = self.configuration.get("base_url").strip()
        scored_users = []
        score_users = {}
        page = 1
        total_pages = 1
        headers = {
            "Authorization": f"Token {self.configuration.get('API_token').strip()}"
        }
        while True:
            users = requests.get(
                f"{USERS_URL}/apis/v1/behaviorscore",
                headers=add_user_agent(headers),
                params={"page": page},
                proxies=self.proxy,
            )
            users.raise_for_status()
            users_resp_json = self.handle_error(users)
            self.logger.info(f"{PLUGIN_NAME}: processing scores.")
            users = users_resp_json["results"]
            for user in users:
                for re in res:
                    if user["email"] in re.uid:
                        score_users[user["email"]] = user["behavior_score"]
            total_pages = users_resp_json["total_pages"]
            page = page + 1
            if page == total_pages + 1:
                break
        if score_users:
            minvalue = 1
            maxvalue = users_resp_json["max_score"]
            for key, value in score_users.items():
                score = (value - minvalue) / (maxvalue - minvalue)
                score = (score * 999) + 1
                scored_users.append(
                    Record(uid=key, type=RecordType.USER, score=score)
                )
            self.logger.info(
                f"{PLUGIN_NAME}: processing scores and normalizing for min value {minvalue} and "
                f"max value {maxvalue}."
            )
        return scored_users

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def validate(self, configuration: Dict):
        """Validate Netskope configuration."""

        page = 1
        if (
            "base_url" not in configuration
            or not configuration["base_url"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Invalid Security Advisor configuration, URL required."
            )
            return ValidationResult(
                success=False, message="BASE URL not provided."
            )

        if "API_token" not in configuration or not configuration["API_token"]:
            self.logger.error(
                f"{PLUGIN_NAME}: API Token not provided, token required."
            )
            return ValidationResult(
                success=False, message="API token not provided."
            )

        try:
            headers = {"Authorization": f"Token {configuration['API_token']}"}
            groups = requests.get(
                f"{configuration['base_url']}/apis/v1/behaviorscore",
                headers=add_user_agent(headers),
                params={"page": page},
                proxies=self.proxy,
            )
            if groups.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif groups.status_code == 401:
                return ValidationResult(
                    success=False,
                    message="Invalid API Token provided, enter valid Token.",
                )
            elif groups.status_code == 400:
                return ValidationResult(
                    success=False,
                    message="Error occurred while validating Security Advisor details.",
                )
            self.logger.error(
                f"{PLUGIN_NAME}: Could not validate details. "
                f"Status code: {groups.status_code}, Response: {groups.text}"
            )
            return ValidationResult(
                success=False,
                message="Error occurred while validating details. Check logs.",
            )
        except ConnectionError:
            return ValidationResult(
                success=False,
                message="Could not connect to the Security Advisor URL provided.",
            )

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value != "generate":
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def execute_action(self, user: str, action: Action):
        """Execute the action for the user."""
        pass

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
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
