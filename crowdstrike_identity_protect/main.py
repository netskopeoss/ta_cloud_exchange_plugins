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

"""CrowdStrike Falcon Identity Protection URE plugin."""
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List

from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from pydantic import ValidationError

from .lib.falconpy import IdentityProtection


class CrowdStrikeIdentityProtectException(Exception):
    """CrowdStrikeIdentityProtectException exception class."""

    pass


BATCH_SIZE = 1000
PLUGIN_NAME = "URE CrowdStrike Falcon Identity Protection"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class CrowdStrikeIdentityProtectPlugin(PluginBase):
    """CrowdStrike Falcon Identity Protection URE plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.log_prefix = f"{PLUGIN_NAME} [{name}]"

    def _add_user_agent(self) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """
        plugin_version = ""
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_version = manifest_json.get("version", "")

        except Exception:
            pass
        header = add_user_agent()
        plugin_name = "crowdstrike_identity_protect"
        ce_added_agent = header.get("User-Agent", "netskope-ce")

        return "{}-ure-{}-v{}".format(
            ce_added_agent, plugin_name, plugin_version
        )

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API
            call.
        Returns:
            dict: Returns the dictionary of response JSON when the response
            code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.get("status_code")
        if status_code == 200:
            return resp.get("body", {})

        elif status_code == 401:
            err_msg = f"Received exit code {status_code}. Invalid authorization parameters provided"
            errors = resp.get("body", {}).get(
                "errors",
                [{"message": "No error message found in response."}],
            )
            resp_err_msg = errors[0].get("message")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. {resp_err_msg}",
                details=str(errors),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

        elif status_code == 403:
            err_msg = "API client does not have enough permissions to configure plugin"
            errors = resp.get("body", {}).get(
                "errors",
                [{"message": "No error message found in response."}],
            )
            resp_err_msg = errors[0].get("message")
            self.logger.error(
                message=f"{self.log_prefix}: Received exit code {status_code}. {err_msg}. {resp_err_msg}",
                details=str(errors),
            )
            raise CrowdStrikeIdentityProtectException(
                f"Received exit code {status_code}. {err_msg}"
            )

        elif status_code >= 400 and status_code < 500:
            err_msg = f"Received exit code {status_code}. HTTP client error"
            errors = resp.get("body", {}).get(
                "errors", [{"message": "No error message found in response."}]
            )
            resp_err_msg = errors[0].get("message")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. {resp_err_msg}.",
                details=str(errors),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

        elif status_code >= 500 and status_code < 600:
            err_msg = f"Received exit code {status_code}, HTTP server error."
            errors = resp.get("body", {}).get(
                "errors", [{"message": "No error message found in response."}]
            )
            resp_err_msg = errors[0].get("message")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {resp_err_msg}",
                details=str(errors),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

        else:
            err_msg = f"Received exit code {status_code}, HTTP Error"
            errors = resp.get("body", {}).get(
                "errors", [{"message": "No error message found in reponse."}]
            )
            resp_err_msg = errors[0].get("message")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. {resp_err_msg}",
                details=str(errors),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

    def _get_falcon(
        self, base_url: str, client_id: str, client_secret: str
    ) -> IdentityProtection:
        """Get Falcon Identity protection object to perform operations.

        Args:
            base_url (str): Base URL for CrowdStrike.
            client_id (str): Client ID.
            client_secret (str): Client Secret.

        Returns:
            IdentityProtection: IdentityProtection object.
        """
        try:
            return IdentityProtection(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                proxy=self.proxy,
                ssl_verify=self.ssl_validation,
                user_agent=self._add_user_agent(),
            )
        except Exception as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Error occurred while creating CrowdSrike Identity Protect object.",
                details=str(exp),
            )
            raise CrowdStrikeIdentityProtectException(exp)

    def _get_query(self):
        """Get Query to fetch users from CrowdStrike Falcon Identity Protection platform."""
        return """query ($after: Cursor, $creationTime: DateTimeInput) {
                    entities(types: [USER], sortKey: CREATION_TIME, sortOrder: DESCENDING, first: 1000, accountCreationStartTime: $creationTime, after: $after,archived: false) {
                        nodes {
                        primaryDisplayName
                        secondaryDisplayName
                        ... on UserEntity {
                            emailAddresses
                        }
                        riskScore
                        }
                        pageInfo {
                        hasNextPage
                        endCursor
                        }
                    }
                    }"""

    def _get_scores_query(self):
        "Get graphql query for fetching scores of the users."
        return """query ($email: [String!]) {
                    entities(types: [USER], first: 1000, emailAddresses: $email, archived: false) {
                        nodes {
                        ... on UserEntity {
                            emailAddresses
                        }
                        riskScore
                        }
                    }
                    }"""

    def _extract_users(self, data: Dict) -> List:
        """Extract users from response data.

        Args:
            data (Dict): Response Data.

        Returns:
            List: List of extracted users.
        """
        users = []
        nodes = data.get("data", {}).get("entities", {}).get("nodes", [])
        for node in nodes:
            # emailAddresses is an array hence we will be ingesting only
            # the first email address we get in this array.
            if node.get("emailAddresses", []):
                try:
                    email = node.get("emailAddresses")[0]
                    users.append(
                        Record(
                            uid=email,
                            type=RecordType.USER,
                        )
                    )
                except ValidationError as error:
                    self.logger.error(
                        message=f"{self.log_prefix}: Validation error occurred.",
                        details=str(error),
                    )
        return users

    def fetch_records(self):
        """Get all the records from CrowdStrike Falcon Identity Protection platform."""
        self.logger.info(
            f"{self.log_prefix}: Fetching records from CrowdStrike Falcon Identity Protection platform."
        )
        falcon = self._get_falcon(
            base_url=self.configuration.get("base_url", "").strip(),
            client_id=self.configuration.get("client_id", "").strip(),
            client_secret=self.configuration.get("client_secret"),
        )
        end_cursor = None
        users = []
        while True:
            last_run_time = None
            if (
                self.last_run_at
            ):  # Check if plugin is previously sync to fetch only updated users.
                last_run_time = self.last_run_at.strftime(DATE_FORMAT)
            else:
                # Fetch users on the base of Initial range provided.
                last_run_time = datetime.now() - timedelta(
                    days=self.configuration.get("days")
                )
                last_run_time = last_run_time.strftime(DATE_FORMAT)

            query = self._get_query()  # Get query for fetching records

            variables = {
                "after": end_cursor,
                "creationTime": last_run_time,
            }  # Variables for pagination and fetching only the updated users.
            response = self._rate_limit_handler(
                falcon=falcon,
                query=query,
                variables=variables,
                endpoint_used="scores",
            )

            data = self.handle_error(resp=response)

            users.extend(self._extract_users(data))

            has_next_page = (
                data.get("data", {})
                .get("entities", {})
                .get("pageInfo", {})
                .get("hasNextPage")
            )

            end_cursor = (
                data.get("data", {})
                .get("entities", {})
                .get("pageInfo", {})
                .get(
                    "endCursor",
                )
            )

            if (not has_next_page) or (end_cursor is None):
                # Break if no more records found.
                break
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(users)} users"
            " from CrowdStrike Falcon Identity Protection platform."
        )
        return users

    def _extract_scores(self, data: Dict) -> List:
        """Extract scores from the response data.

        Args:
            data (Dict): Response data that we got from querying.

        Returns:
            List: List of users with scores.
        """
        users_with_scores = []
        nodes = data.get("data", {}).get("entities", {}).get("nodes", [])
        for node in nodes:
            if node.get("emailAddresses", []):
                email = node.get("emailAddresses")[0]
                try:
                    # Map the scores fetched from the CrowdStrike identity
                    # protection platform with respect to Netskope CE
                    # score scale.
                    # CrowdStrike Score scale:
                    # 0-1 where 0 (no or unknown risk) and 1 (maximum risk).
                    # Netskope Score Scale:
                    # 0-1000 where 0 is maximum risk 1000 means low.
                    score = abs(1 - node.get("riskScore")) * 1000
                    users_with_scores.append(
                        Record(uid=email, type=RecordType.USER, score=score),
                    )

                except ValidationError as error:
                    self.logger.error(
                        message=f"{self.log_prefix}: Validation error occurred.",
                        details=str(error),
                    )
                except Exception as exp:
                    err_msg = "Error occurred while extrating scores."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(exp),
                    )
        return users_with_scores

    def _rate_limit_handler(
        self,
        falcon: IdentityProtection,
        query: str,
        variables: Dict,
        endpoint_used: str,
    ) -> Dict:
        """API Call Helper method.

        Args:
            falcon (IdentityProtection): Falcon Object.
            query (str): Query String.
            variables (Dict): Query Variables.
        """
        for i in range(3):
            response = falcon.api_preempt_proxy_post_graphql(
                query=query, variables=variables
            )
            if response.get("status_code") == 429:
                self.logger.info(
                    f"{self.log_prefix}: Rate Limit Exceeded. Retrying "
                    f"{i+1} while fetching {endpoint_used} from CrowdStrike "
                    f"Identity Protect Endpoint."
                )
                time.sleep(60)
            else:
                break

        return response

    def _get_users_list(self, users: List) -> List:
        """Get users list from the users uids..

        Args:
            users (List): List of users in record format.

        Returns:
            List: List of users in string format.
        """
        users_list = []
        for user in users:
            users_list.append(user.uid)
        return users_list

    def fetch_scores(self, users: List) -> List[Record]:
        """Fetch scores of users.

        Args:
            users (List): list of users without scores

        Returns:
            List[Record]: List of users with scores.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching scores from CrowdStrike "
            "Identity Protection platform."
        )
        falcon = self._get_falcon(
            base_url=self.configuration.get("base_url", "").strip(),
            client_id=self.configuration.get("client_id", "").strip(),
            client_secret=self.configuration.get("client_secret"),
        )
        users_with_scores = []

        for i in range(0, len(users), BATCH_SIZE):
            current_user_batch = users[i : i + BATCH_SIZE]
            query = self._get_scores_query()
            variables = {"email": self._get_users_list(current_user_batch)}

            response = self._rate_limit_handler(
                falcon=falcon,
                query=query,
                variables=variables,
                endpoint_used="users",
            )

            resp_data = self.handle_error(resp=response)

            users_with_scores.extend(self._extract_scores(resp_data))

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched scores of "
            f"{len(users_with_scores)} users from CrowdStrike Identity "
            "Protection platform."
        )
        return users_with_scores

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record."""
        if (
            action.value == "generate"
            or record.type != RecordType.HOST
            or record.scores
        ):
            pass

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin configuration
            parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        if (
            "base_url" not in configuration
            or not configuration.get("base_url").strip()
            or type(configuration.get("base_url")) != str
        ):
            err_msg = "Base URL is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message="Base URL is a required field.",
            )

        if (
            "client_id" not in configuration
            or not configuration.get("client_id").strip()
            or type(configuration.get("client_id")) != str
        ):
            err_msg = "Client ID is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if (
            "client_secret" not in configuration
            or not configuration.get("client_secret")
            or type(configuration.get("client_secret")) != str
        ):
            err_msg = "Client Secret is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if (
            "days" not in configuration
            or not configuration["days"]
            or type(configuration["days"]) != int
            or configuration["days"] <= 0
        ):
            err_msg = "Type of Initial Range (in days) should be non-zero positive integer."
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred.",
                details=err_msg,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return self._validate_auth_params(
            base_url=configuration.get("base_url", "").strip(),
            client_id=configuration.get("client_id", "").strip(),
            client_secret=configuration.get("client_secret"),
        )

    def _validate_auth_params(
        self, base_url: str, client_id: str, client_secret: str
    ) -> ValidationResult:
        """Validate auth configuration parameters.

        Args:
            base_url (str): Base URL.
            client_id (str): Client ID.
            client_secret (str): Client Secret.

        Return:
            ValidationResult: ValidateResult which indicate whether validate
        """
        try:
            falcon = self._get_falcon(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
            )
            query = self._get_query()  # Get GraphQL query

            variables = {
                "after": None,
                "creationTime": self.last_run_at,
            }  # Variables that will be used by query.
            response = falcon.api_preempt_proxy_post_graphql(
                query=query, variables=variables
            )

            self.handle_error(resp=response)

            return ValidationResult(
                success=True,
                message="Validation successful for CrowdStrike Falcon Identity Protection Plugin.",
            )
        except CrowdStrikeIdentityProtectException as exp:
            err_msg = str(exp)
            self.logger.error(
                message=f"{self.log_prefix}: Validation Error Occurred.",
                details=err_msg,
            )
            return ValidationResult(success=False, message=err_msg)
        except Exception as exp:
            err_msg = "Authentication Failed."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.", details=str(exp)
            )
            return ValidationResult(success=False, message=err_msg)
