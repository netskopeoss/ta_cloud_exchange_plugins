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

"""Netskope CRE plugin."""


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


class ProofpointPlugin(PluginBase):
    """Proofpoint plugin implementation."""

    def fetch_records(self) -> List:
        """Fetch list of users."""
        USERS_URL = self.configuration.get("proofpoint_url").strip()
        offset = 1
        SIZE = 3
        res = []
        while True:
            users = requests.get(
                f"{USERS_URL}/v2/people/vap",
                auth=(
                    self.configuration.get("proofpoint_username").strip(),
                    self.configuration.get("proofpoint_password").strip(),
                ),
                params={
                    "window": self.configuration.get("window"),
                    "page": offset,
                    "size": SIZE,
                },
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            users_resp_json = self.handle_error(users)
            errors = users_resp_json.get("errors")

            if errors:
                err_msg = errors[0].get("message", "")

                self.logger.error(
                    "Plugin: Proofpoint CRE Unable to Fetch Users, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: Proofpoint CRE Unable to Fetch Users, "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: Proofpoint CRE Unable to Fetch Users, "
                    f"Error: {err_msg}"
                )
            self.logger.info("Proofpoint CRE: Processing users.")
            users = users_resp_json["users"]
            for user in users:
                res.append(
                    Record(
                        uid=user["identity"]["emails"][0],
                        type=RecordType.USER,
                        score=None,
                    )
                )
            offset += 1
            if len(users) < SIZE:
                break
        return res

    def fetch_scores(self, res):
        """Fetch user scores."""
        USERS_URL = self.configuration.get("proofpoint_url").strip()
        scored_users = []
        score_users = {}
        offset = 1
        SIZE = 3
        while True:
            proofpoint_fetch_users = requests.get(
                f"{USERS_URL}/v2/people/vap",
                auth=(
                    self.configuration.get("proofpoint_username").strip(),
                    self.configuration.get("proofpoint_password").strip(),
                ),
                params={
                    "window": self.configuration.get("window"),
                    "page": offset,
                    "size": SIZE,
                },
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            proofpoint_fetch_users.raise_for_status()
            users_resp_json = self.handle_error(proofpoint_fetch_users)
            errors = users_resp_json.get("errors")

            if errors:
                err_msg = errors[0].get("message", "")

                self.logger.error(
                    "Plugin: Proofpoint CRE Unable to Fetch Scores, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: Proofpoint CRE Unable to Fetch Scores, "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: Proofpoint CRE Unable to Fetch Scores, "
                    f"Error: {err_msg}"
                )

            self.logger.info("Proofpoint CRE: processing scores.")
            users = users_resp_json["users"]
            for user in users:
                for re in res:
                    if user["identity"]["emails"][0] in re.uid:
                        score_users[user["identity"]["emails"][0]] = user[
                            "threatStatistics"
                        ]["attackIndex"]
            offset += 1
            if len(users) < SIZE:
                break
        if score_users:
            all_values = score_users.values()
            minvalue = min(all_values)
            maxvalue = max(all_values)
            for key, value in score_users.items():
                score = (value - minvalue) / (maxvalue - minvalue)
                score = 1 - score
                score = (score * 999) + 1
                scored_users.append(
                    Record(uid=key, type=RecordType.USER, score=score)
                )
            self.logger.info(
                f"Proofpoint CRE: processing scores and normalizing for min value {minvalue} and "
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
        if "proofpoint_url" not in configuration:
            self.logger.error(
                "Proofpoint CRE: Invalid proofpoint configurations, URL required."
            )
            return ValidationResult(
                success=False, message="Proofpoint URL not provided."
            )

        if "proofpoint_username" not in configuration:
            self.logger.error(
                "Proofpoint CRE: Invalid proofpoint configurations, username required."
            )
            return ValidationResult(
                success=False,
                message="Proofpoint credentials username not provided.",
            )

        if "proofpoint_password" not in configuration:
            self.logger.error(
                "Proofpoint CRE: Invalid proofpoint configurations, password required."
            )
            return ValidationResult(
                success=False,
                message="Proofpoint credentials password not provided.",
            )

        if "window" not in configuration:
            self.logger.error(
                "Proofpoint CRE: Invalid proofpoint configurations, window required."
            )
            return ValidationResult(
                success=False, message="Proofpoint window not provided."
            )

        try:
            groups = requests.get(
                f"{configuration.get('proofpoint_url').strip()}/v2/people/vap",
                auth=(
                    configuration.get("proofpoint_username"),
                    configuration.get("proofpoint_password"),
                ),
                params={"window": configuration.get("window"), "size": 1},
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            if groups.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif groups.status_code == 401:
                return ValidationResult(
                    success=False, message="Invalid auth parameters provided."
                )
            elif groups.status_code == 400:
                return ValidationResult(
                    success=False,
                    message=f"Error occurred while validating Proofpoint details. {groups.json().get('description')}",
                )
            self.logger.error(
                f"Proofpoint CRE: Could not validate Proofpoint details. "
                f"Status code: {groups.status_code}, Response: {groups.text}"
            )
            return ValidationResult(
                success=False,
                message="Error occurred while validating proofpoint details. Check logs.",
            )
        except ConnectionError:
            return ValidationResult(
                success=False,
                message="Could not connect to the Proofpoint URL provided.",
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
                    "Plugin: Proofpoint CRE,"
                    "Exception occurred while parsing JSON response."
                )
                self.logger.error(
                    "Plugin: Proofpoint CRE, "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.notifier.error(
                "Plugin: Proofpoint CRE, "
                "Received exit code 401, Authentication Error"
            )
            self.logger.error(
                "Plugin: Proofpoint CRE, "
                "Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.notifier.error(
                "Plugin: Proofpoint CRE, "
                "Received exit code 403, Forbidden User"
            )
            self.logger.error(
                "Plugin: Proofpoint CRE, "
                "Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.notifier.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
            self.logger.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.notifier.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
            self.logger.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.notifier.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                f"Plugin: Proofpoint CRE, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
        resp.raise_for_status()
