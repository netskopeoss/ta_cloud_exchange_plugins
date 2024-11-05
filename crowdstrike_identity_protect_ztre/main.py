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

CRE CrowdStrike Falcon Identity Protection plugin.
"""

import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from pydantic import ValidationError

from .utils.constants import (
    BATCH_SIZE,
    DATE_FORMAT,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    NETSKOPE_NORMALIZED_FIELD,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RISK_SCORE_FIELD,
    USER_EMAIL_FIELD,
)
from .utils.helper import (
    CrowdStrikeIdentityProtectException,
    CrowdStrikeIdentityProtectPluginHelper,
)


class CrowdStrikeIdentityProtectPlugin(PluginBase):
    """CrowdStrike Falcon Identity Protection CRE plugin implementation."""

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
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.crowdstrike_ip_helper = CrowdStrikeIdentityProtectPluginHelper(
            log_prefix=self.log_prefix,
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CrowdStrikeIdentityProtectPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_query(self):
        """Get Query to fetch users from CrowdStrike Falcon Identity
        Protection platform."""
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
                    user_dict = {}
                    email = node.get("emailAddresses", [])[0]
                    if email:
                        user_dict[USER_EMAIL_FIELD] = email
                    score = node.get("riskScore")
                    if score is not None:
                        score = round(score, 2)
                        user_dict[RISK_SCORE_FIELD] = score
                    if user_dict:
                        users.append(user_dict)
                except (ValidationError, Exception) as error:
                    error_message = (
                        "Validation error occurred"
                        if isinstance(error, ValidationError)
                        else "Unexpected error occurred"
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} while "
                            f"creating User. Hence {email} user "
                            f"will be skipped. Error: {error}"
                        ),
                        details=str(traceback.format_exc()),
                    )
        return users

    def fetch_records(self, _: Entity):
        """Get all the records from CrowdStrike Falcon Identity Protection
        platform."""
        self.logger.info(
            f"{self.log_prefix}: Pulling users from {PLATFORM_NAME}."
        )
        base_url, client_id, client_secret = (
            self.crowdstrike_ip_helper.get_credentials(self.configuration)
        )
        initial_range = int(self.configuration.get("days"))
        try:
            falcon = self.crowdstrike_ip_helper.get_falcon(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                proxy=self.proxy,
                ssl_validation=self.ssl_validation,
                logger_msg=f"pulling users from {PLATFORM_NAME}",
            )
            end_cursor = None
            users = []
            last_run_time = None
            if self.last_run_at:
                # Check if plugin is previously sync to fetch only
                # updated users.
                last_run_time = self.last_run_at.strftime(DATE_FORMAT)
            else:
                # Fetch users on the base of Initial range provided.
                last_run_time = datetime.now() - timedelta(days=initial_range)
                last_run_time = last_run_time.strftime(DATE_FORMAT)

            page = 1
            query = self._get_query()  # Get query for fetching records
            while True:
                # Variables for pagination and fetching only the updated users.
                variables = {
                    "after": end_cursor,
                    "creationTime": last_run_time,
                }

                data = self.crowdstrike_ip_helper.api_helper(
                    falcon=falcon,
                    query=query,
                    variables=variables,
                    logger_msg=(
                        f"pulling users for page {page} from {PLATFORM_NAME}"
                    ),
                )
                page_users = self._extract_users(data)
                users.extend(page_users)

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
                log_msg = (
                    f"Successfully fetched {len(page_users)} user(s) in page "
                    f"{page} from {PLATFORM_NAME}. Total user(s) fetched: "
                    f"{len(users)}."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                if (not has_next_page) or (end_cursor is None):
                    # Break if no more records found.
                    break
                # Increment the page counter.
                page += 1

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(users)} user(s)"
                f" from {PLATFORM_NAME}."
            )
            return users
        except CrowdStrikeIdentityProtectException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while fetching"
                f" users from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

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
                    # CrowdStrike Score scale:
                    # 0-1 where 0 (no or unknown risk) and 1 (maximum risk).
                    score = node.get("riskScore")
                    if score is not None:
                        score = round(score, 2)
                        normalized_risk_score = (
                            self.crowdstrike_ip_helper.normalize_risk_score(
                                score
                            )
                        )
                        users_with_scores.append(
                            {
                                USER_EMAIL_FIELD: email,
                                RISK_SCORE_FIELD: score,
                                NETSKOPE_NORMALIZED_FIELD: normalized_risk_score,  # noqa
                            }
                        )
                except (ValidationError, Exception) as error:
                    error_message = (
                        "Validation error occurred"
                        if isinstance(error, ValidationError)
                        else "Unexpected error occurred"
                    )
                    err_msg = f"{error_message} while extracting scores."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=str(traceback.format_exc()),
                    )

        return users_with_scores

    def _get_users_list(self, users: List) -> List:
        """Get users list from the users uids..

        Args:
            users (List): List of users in record format.

        Returns:
            List: List of users in string format.
        """
        users_list = []
        for user in users:
            if user.get(USER_EMAIL_FIELD):
                users_list.append(user.get(USER_EMAIL_FIELD))
        return users_list

    def update_records(self, _: str, records: list[dict]) -> List[dict]:
        """Fetch scores of users.

        Args:
            users (List): list of users without scores

        Returns:
            List[Record]: List of users with scores.
        """
        self.logger.info(
            f"{self.log_prefix}: Updating user records from {PLATFORM_NAME}."
        )
        base_url, client_id, client_secret = (
            self.crowdstrike_ip_helper.get_credentials(self.configuration)
        )
        try:
            falcon = self.crowdstrike_ip_helper.get_falcon(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                proxy=self.proxy,
                ssl_validation=self.ssl_validation,
                logger_msg=f"updating user records from {PLATFORM_NAME}",
            )
            users_with_scores = []
            page = 1
            for i in range(0, len(records), BATCH_SIZE):
                current_user_batch = records[i : i + BATCH_SIZE]  # noqa
                query = self._get_scores_query()
                variables = {"email": self._get_users_list(current_user_batch)}
                resp_data = self.crowdstrike_ip_helper.api_helper(
                    falcon=falcon,
                    query=query,
                    variables=variables,
                    logger_msg=(
                        f"pulling user records for page {page}"
                        f" from {PLATFORM_NAME}"
                    ),
                    show_variables=False,
                )
                page_scores = self._extract_scores(resp_data)
                users_with_scores.extend(page_scores)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(page_scores)} user record(s) in page {page}"
                    f" from {PLATFORM_NAME}. Total user records "
                    f"fetched: {len(users_with_scores)}."
                )
                page += 1

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(users_with_scores)} user record(s) from "
                f"{PLATFORM_NAME} platform."
            )
            return users_with_scores
        except CrowdStrikeIdentityProtectException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while"
                f" fetching user records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate plugin action configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_params(self, action: Action):
        """Get fields required for an action."""
        return []

    def execute_action(self, action: Action):
        """Execute action on the record."""
        if action.value == "generate":
            pass

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (Dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_err_msg = "Validation error occurred."
        # Validate Base URL
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(base_url, str) or not self._validate_url(base_url):
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Select the Base URL from the available options."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client ID
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client Secret
        client_secret = configuration.get("client_secret")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Client Secret should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 1 or days > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 1 to 2^62."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
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
            falcon = self.crowdstrike_ip_helper.get_falcon(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                proxy=self.proxy,
                ssl_validation=self.ssl_validation,
                logger_msg=f"validating connectivity with {PLATFORM_NAME}",
            )
            query = self._get_query()  # Get GraphQL query

            variables = {
                "after": None,
                "creationTime": self.last_run_at,
            }  # Variables that will be used by query.
            self.crowdstrike_ip_helper.api_helper(
                falcon=falcon,
                variables=variables,
                query=query,
                is_validation=True,
                logger_msg=f"validating connectivity with {PLATFORM_NAME}",
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated connectivity "
                f"with {PLATFORM_NAME} plugin."
            )
            return ValidationResult(
                success=True,
                message=f"Validation successful for {PLUGIN_NAME} plugin.",
            )
        except CrowdStrikeIdentityProtectException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name=USER_EMAIL_FIELD,
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name=RISK_SCORE_FIELD,
                        type=EntityFieldType.NUMBER,
                        required=False,
                    ),
                    EntityField(
                        name=NETSKOPE_NORMALIZED_FIELD,
                        type=EntityFieldType.NUMBER,
                        required=False,
                    ),
                ],
            )
        ]
