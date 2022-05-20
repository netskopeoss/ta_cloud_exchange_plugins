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
"""BeyondCorp CRE plugin."""
import json
from typing import Dict, List

import google.auth.transport.requests
import requests
from google.oauth2 import service_account

from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices"]
BASE_URL = "https://cloudidentity.googleapis.com/v1"
PARTNER_ID = "616b839f-3f79-4d49-a3e6-f8ec620c84f2"


class BeyondCorpPlugin(PluginBase):
    """BeyondCorp plugin implementation."""

    def fetch_records(self) -> List[Record]:
        """Pull Records from BeyondCorp.

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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Share Aggregate Score", value="share_aggregate_score"
            ),
            ActionWithoutParams(
                label="Share Plugin Score", value="share_plugin_score"
            ),
            ActionWithoutParams(
                label="Update Compliance State",
                value="update_compliance_state",
            ),
            ActionWithoutParams(
                label="Update Health Score", value="update_health_score"
            ),
            ActionWithoutParams(label="No actions", value="no_action"),
        ]

    def _create_delegated_credentials(
        self, service_account_string: str, user_email: str
    ):
        """Create delegated credentials for the given email."""
        credentials = service_account.Credentials.from_service_account_info(
            json.loads(service_account_string), scopes=SCOPES
        )
        delegated_credentials = credentials.with_subject(user_email)
        return delegated_credentials

    def _get_users(self, email: str, headers: dict) -> List[str]:
        page_token = None
        params = {"filter": f"email:{email}"}
        users = []
        while True:
            if page_token is not None:
                params["pageToken"] = page_token
            response = requests.get(
                f"{BASE_URL}/devices/-/deviceUsers",
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            response.raise_for_status()
            response_json = response.json()
            response_users = response_json.get("deviceUsers", [])
            for user in response_users:
                users.append(user.get("name"))
            page_token = response_json.get("nextPageToken")
            if not page_token:
                break
        return users

    def _get_auth_headers(self, configuration: dict) -> dict:
        """Get authentication headers."""
        request = google.auth.transport.requests.Request()
        dc = self._create_delegated_credentials(
            configuration.get("service_account_json"),
            configuration.get("admin_email"),
        )
        dc.refresh(request)
        return {
            "Authorization": f"Bearer {dc.token}",
            "Content-Type": "application/json",
        }

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        if action.value == "no_action" or record.type != RecordType.USER:
            return

        headers = self._get_auth_headers(self.configuration)

        update_mask = ["keyValuePairs"]
        if action.value == "share_aggregate_score":
            data = {
                "keyValuePairs": {
                    "NetskopeUserAggregateScoreRange": {
                        "string_value": record.normalizedScore.range
                    },
                    "NetskopeUserAggregateScore": {
                        "number_value": record.normalizedScore.current
                    },
                }
            }
        elif action.value == "share_plugin_score":
            score_range_to_share = None
            score_to_share = None
            found = False
            for score in record.scores:
                if score.source == action.parameters.get("configuration"):
                    found = True
                    score_to_share = score.current
                    score_range_to_share = score.range
            if not found:
                self.logger.error(
                    f"BeyondCorp: Could not share plugin score as CRE configuration "
                    f"{action.parameters.get('configuration')} might not exist or "
                    f"has not provided score for {record.uid}."
                )
                return
            data = {
                "keyValuePairs": {
                    "NetskopeUserPluginScoreRange": {
                        "string_value": "N/A"
                        if score_range_to_share is None
                        else score_range_to_share
                    },
                    "NetskopeUserPluginScore": {
                        "number_value": score_to_share
                    },
                }
            }
        elif action.value == "update_compliance_state":
            update_mask.append("complianceState")
            data = {
                "complianceState": action.parameters.get(
                    "state", "COMPLIANCE_STATE_UNSPECIFIED"
                )
            }
        elif action.value == "update_health_score":
            update_mask.append("healthScore")
            data = {
                "healthScore": action.parameters.get(
                    "score", "HEALTH_SCORE_UNSPECIFIED"
                )
            }

        users = self._get_users(record.uid, headers)
        customer_id = self.configuration.get("customer_id").strip()
        if customer_id[0].lower() == "c":  # remove "c" prefix if exists
            customer_id = customer_id[1:]
        if not users:
            self.logger.warn(
                f"BeyondCorp: User with email {record.uid} does not exist on BeyondCorp."
            )
            return
        for user in users:
            self.logger.info(
                f"BeyondCorp: Updating client state for user {record.uid}."
            )
            response = requests.patch(
                f"{BASE_URL}/{user}/clientStates/{PARTNER_ID}",
                params={
                    "customer": f"customers/{customer_id}",
                    "updateMask": ",".join(update_mask),
                },
                headers=add_user_agent(headers),
                json=data,
                proxies=self.proxy,
            )
            response.raise_for_status()

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value in ["no_action", "share_aggregate_score"]:
            return []
        if action.value == "share_plugin_score":
            return [
                {
                    "label": "Plugin Configuration Name",
                    "key": "configuration",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Name of the confguration to share scores from.",
                },
            ]
        if action.value == "update_compliance_state":
            return [
                {
                    "label": "State",
                    "key": "state",
                    "type": "choice",
                    "choices": [
                        {
                            "value": "COMPLIANCE_STATE_UNSPECIFIED",
                            "key": "Unspecified",
                        },
                        {"value": "COMPLIANT", "key": "Compliant"},
                        {"value": "NON_COMPLIANT", "key": "Non-compliant"},
                    ],
                    "default": "COMPLIANCE_STATE_UNSPECIFIED",
                    "mandatory": True,
                    "description": "Select the compliance state.",
                },
            ]
        if action.value == "update_health_score":
            return [
                {
                    "label": "Score",
                    "key": "score",
                    "type": "choice",
                    "choices": [
                        {
                            "value": "HEALTH_SCORE_UNSPECIFIED",
                            "key": "Unspecified",
                        },
                        {"value": "VERY_POOR", "key": "Very Poor"},
                        {"value": "POOR", "key": "Poor"},
                        {"value": "NEUTRAL", "key": "Neutral"},
                        {"value": "GOOD", "key": "Good"},
                        {"value": "VERY_GOOD", "key": "Very Good"},
                    ],
                    "default": "HEALTH_SCORE_UNSPECIFIED",
                    "mandatory": True,
                    "description": "Select the health score.",
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate BeyondCorp action configuration."""
        if action.value not in [
            "share_aggregate_score",
            "share_plugin_score",
            "update_health_score",
            "update_compliance_state",
            "no_action",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if (
            action.value == "share_plugin_score"
            and not action.parameters.get("configuration").strip()
        ):
            return ValidationResult(
                success=False,
                message="Plugin Configuration Name cannot be empty.",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def _is_empty(self, string: str) -> bool:
        """Check if string is empty."""
        if string is None or not string.strip():
            return True
        return False

    def validate(self, configuration: Dict):
        """Validate BeyondCorp configuration."""

        if "customer_id" not in configuration or self._is_empty(
            configuration["customer_id"]
        ):
            return ValidationResult(
                success=False,
                message="Customer Id cannot be empty.",
            )

        if "admin_email" not in configuration or self._is_empty(
            configuration["admin_email"]
        ):
            return ValidationResult(
                success=False,
                message="Administrator Email cannot be empty.",
            )

        if "service_account_json" not in configuration or self._is_empty(
            configuration["service_account_json"]
        ):
            return ValidationResult(
                success=False,
                message="Service Account JSON cannot be empty.",
            )

        try:
            json.loads(configuration["service_account_json"])
        except json.decoder.JSONDecodeError:
            return ValidationResult(
                success=False,
                message="Service Account JSON must be valid JSON.",
            )

        try:
            headers = self._get_auth_headers(configuration)
            response = requests.get(
                f"{BASE_URL}/devices",
                headers=add_user_agent(headers),
                proxies=self.proxy,
            )
            response.raise_for_status()
        except Exception as ex:
            self.logger.error(f"BeyondCorp: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Error occurred while validating credentials.",
            )
        return ValidationResult(success=True, message="Validation successful.")
