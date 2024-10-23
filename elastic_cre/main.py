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

CRE Elastic plugin.
"""

import json
import re
import traceback
from datetime import datetime, timedelta
from pydantic import ValidationError
from typing import Dict, Tuple, List
from urllib.parse import urlparse

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)

from .utils.elastic_constants import (
    MODULE_NAME,
    PAGE_COUNT,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    DATE_FORMAT,
    BATCH_SIZE,
)

from .utils.elastic_helper import ElasticPluginException, ElasticPluginHelper


class ElasticPlugin(PluginBase):
    """Elastic plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Elastic plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.elastic_helper = ElasticPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ElasticPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [ActionWithoutParams(label="No action", value="generate")]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate"]:
            return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Wiz action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value not in ["generate"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration. "
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        if action.value == "generate":
            return

    def _extract_users(self, hits: List) -> Tuple[List, str]:
        """Extract users from hits.

        Args:
            hits (List): Lists of object received from API call.

        Returns:
            Tuple[List[Record], str]: Tuple containing list of
            users extracted and search after timestamp.
        """
        page_users, search_after = [], None
        if not hits.get("hits", []):
            return page_users, search_after
        for hit in hits.get("hits", []):
            user_name = str(
                hit.get("_source", {}).get("user", {}).get("name", "")
            )
            if bool(re.search(r"^\[.*\]$", user_name)):
                user_name = user_name.replace("'", '"')
                user_name = json.loads(user_name)
            if user_name:
                if isinstance(user_name, list):
                    for usr in user_name:
                        page_users.append({"username": usr})
                else:
                    page_users.append({"username": user_name})
        search_after = (
            hits.get("hits", [{}])[-1].get("sort", [None])[0] if hits else None
        )

        return page_users, search_after

    def fetch_records(self, entity: str) -> List:
        """Pull Users records from Elastic.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        (
            base_url,
            auth_method,
            auth_creds,
            initial_range
        ) = self.elastic_helper.get_config_params(self.configuration)
        headers = self.elastic_helper.get_auth_token(
            verify=self.ssl_validation,
            proxy=self.proxy,
            base_url=base_url,
            auth_method=auth_method,
            auth_creds=auth_creds
        )
        api_endpoint = f"{base_url}/logs-*/_search"
        last_run_time = None
        users = []
        if (
            self.last_run_at
        ):  # Check if plugin is previously sync to fetch only updated users.
            last_run_time = self.last_run_at.strftime(DATE_FORMAT)
        else:
            # Fetch users on the base of Initial range provided.
            last_run_time = datetime.now() - timedelta(days=initial_range)
            last_run_time = last_run_time.strftime(DATE_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: This is an initial pull of the plugin "
                f"hence pulling {entity_name} for last {initial_range} day(s) "
                f"from {PLATFORM_NAME} platform."
            )
        page_count = 1
        total_skip_count = 0
        users_query = self.get_users_query(time_filter=last_run_time)
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {entity_name} for page {page_count} "
                    f"from {PLATFORM_NAME} platform. Query: {users_query}"
                )
                resp_json = self.elastic_helper.api_helper(
                    url=api_endpoint,
                    method="POST",
                    json=users_query,
                    headers=headers,
                    configuration=self.configuration,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"fetching {entity_name} for page {page_count} "
                        f"from {PLATFORM_NAME} platform"
                    ),
                )
                total_hits = len(resp_json.get("hits", {}).get("hits", []))
                page_users, search_after = self._extract_users(
                    resp_json.get("hits", {})
                )
                page_users_count = len(page_users)
                combine_users = users + page_users
                curr_count = 0
                for user in combine_users:
                    name = user.get("username", "")
                    if name and not (
                        any(usr.get("username") == name for usr in users)
                    ):
                        users.append(user)
                        curr_count += 1

                skipped_count = total_hits - page_users_count
                duplicate_count = page_users_count - curr_count
                if skipped_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped {skipped_count} log(s) "
                        f"from {total_hits} logs in page {page_count}."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_users_count} {entity_name} and "
                    f"{duplicate_count} user(s) were duplicated "
                    f"from {total_hits} logs in page {page_count}. "
                    f"Total {entity_name} fetched: {len(users)}."
                )
                page_count += 1
                total_skip_count += skipped_count
                if not search_after or (total_hits < PAGE_COUNT):
                    break
                users_query["search_after"] = [search_after]
            except ElasticPluginException:
                raise
            except Exception as exp:
                error_message = (
                    "Error occurred"
                    if isinstance(exp, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"while fetching {entity_name} from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                f"{entity_name} as the 'user.name' field might not be available in "
                "the log object."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(users)} "
            f"{entity_name} from {PLATFORM_NAME} platform."
        )
        return users

    def _map_risk_scores(self, elastic_risk_score: int) -> int:
        """Map Risk score.

        Args:
            elastic_risk_score (int): Elastic risk score.

        Returns:
            int: Netskope mapped risk score.
        """
        netskope_risk_score = abs(100 - int(elastic_risk_score)) * 10
        return netskope_risk_score

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        entity_name = entity.lower()

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )

        (
            base_url,
            auth_method,
            auth_creds,
            _
        ) = self.elastic_helper.get_config_params(self.configuration)
        headers = self.elastic_helper.get_auth_token(
            verify=self.ssl_validation,
            proxy=self.proxy,
            base_url=base_url,
            auth_method=auth_method,
            auth_creds=auth_creds
        )

        total_score_count = 0
        api_endpoint = f"{base_url}/risk-score.*/_search"
        record_uid_list = {record["username"]: record for record in records}
        record_ids = list(record_uid_list.keys())
        batch_no = 1
        for i in range(0, len(record_ids), BATCH_SIZE):
            try:
                user_batch = record_ids[i: i + BATCH_SIZE]
                if not user_batch:
                    break
                logger_msg = (
                    f"fetching score(s) for {len(user_batch)} record(s) "
                    f"from {PLATFORM_NAME} platform"
                )
                resp_json = self.elastic_helper.api_helper(
                    url=api_endpoint,
                    method="POST",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    json=self.get_score_query(user_batch),
                    logger_msg=logger_msg,
                )
                score_update_count = 0
                for hit in resp_json.get("hits", {}).get("hits", []):
                    user_name = hit.get("_source", {}).get("user", {}).get("name", "")
                    calculated_score_norm = round(
                        hit.get("_source", {})
                        .get("user", {})
                        .get("risk", {})
                        .get("calculated_score_norm", None)
                    )
                    if user_name in record_uid_list:
                        record = record_uid_list[user_name]
                        record.update({
                            "calculated_score_norm": calculated_score_norm,
                            "calculated_score": round(
                                hit.get("_source", {})
                                .get("user", {})
                                .get("risk", {})
                                .get("calculated_score", None)
                            ),
                            "calculated_level": (
                                hit.get("_source", {})
                                .get("user", {})
                                .get("risk", {})
                                .get("calculated_level", "")
                            ),
                            "Netskope Normalized Score": self._map_risk_scores(
                                calculated_score_norm
                            )
                        })
                        score_update_count += 1
                total_score_count += score_update_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched scores for "
                    f"{score_update_count} record(s) from {len(user_batch)} "
                    f"record(s) in batch {batch_no}. Total score(s) fetched"
                    f": {total_score_count}."
                )
                batch_no += 1

            except (ElasticPluginException, Exception) as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                batch_no += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while "
                        f"fetching scores for batch {batch_no}. "
                        f"Hence batch {batch_no} will be skipped. "
                        f"Error: {error}"
                    ),
                    details=str(traceback.format_exc()),
                )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{total_score_count} {entity_name} record(s) and skipped updating "
            f"record(s) for {len(records) - total_score_count} {entity_name} as scores "
            f"might not be available on {PLATFORM_NAME} platform."
        )
        return records

    def get_users_query(self, time_filter: str, limit=PAGE_COUNT) -> Dict:
        """Get Users Query.

        Args:
            time_filter (str): Time range in which to search.
            limit (int, optional): No of objects to pull. Defaults to 10000.

        Returns:
            Dict: Fetch users query.
        """
        return {
            "query": {
                "bool": {
                    "must_not": {"exists": {"field": "host.name"}},
                    "filter": [
                        {"exists": {"field": "user.name"}},
                        {"range": {"@timestamp": {"gte": time_filter}}},
                    ],
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "_source": True,
            "size": limit,
        }

    def get_score_query(self, users: List[str]) -> Dict:
        """Get score query.

        Args:
            users (List[str]): List of users.

        Returns:
            Dict: Query to fetch the scores of users.
        """
        phrases = [{"match_phrase": {"user.name": user}} for user in users]
        return {
            "query": {
                "bool": {
                    "minimum_should_match": 1,
                    "should": phrases,
                }
            }
        }

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate Base URL.
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            err_msg = (
                "Invalid Base URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Authentication Method.
        auth_method = configuration.get("authentication_method", "").strip()
        if not auth_method:
            err_msg = (
                "Authentication method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif auth_method not in ["basic_auth", "api_key_auth"]:
            err_msg = (
                "Invalid Authentication Method provided in "
                "the configuration parameters. Allowed values are "
                "Basic Authentication and API Key Authentication."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if auth_method == "basic_auth":
            # Validate username.
            username = configuration.get("username", "").strip()
            if not username:
                err_msg = (
                    "Username is a required configuration parameter "
                    "when Basic Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(username, str)):
                err_msg = (
                    "Invalid Username provided in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate password.
            password = configuration.get("password")
            if not password:
                err_msg = (
                    "Password is a required configuration parameter "
                    "when Basic Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(password, str)):
                err_msg = (
                    "Invalid Password provided in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
        elif auth_method == "api_key_auth":
            # Validate API key.
            api_key = configuration.get("api_key")
            if not api_key:
                err_msg = (
                    "API key is a required configuration parameter "
                    "when API Key Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(api_key, str)):
                err_msg = (
                    "Invalid API key provided in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Validate Initial Range
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters. "
                "Valid value should be an integer greater than zero."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate connectivity to the server.
        return self._validate_connectivity(
            base_url=base_url,
            auth_method=auth_method,
            auth_creds={
                "username": username,
                "password": password,
            }
            if auth_method == "basic_auth"
            else {"api_key": api_key},
        )

    def _validate_connectivity(
        self, base_url: str, auth_method: str, auth_creds: Dict
    ) -> ValidationResult:
        """Validate connectivity with Elastic server.

        Args:
            base_url (str): Base URL.
            auth_method (str): Authentication Method.
            auth_creds (Dict): Dictionary of authentication credentials.

        Returns:
            ValidationResult: Validation Result.
        """
        api_endpoint = f"{base_url}/logs-*/_search"
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                "Elastic server."
            )
            headers = self.elastic_helper.get_auth_token(
                verify=self.ssl_validation,
                proxy=self.proxy,
                auth_method=auth_method,
                base_url=base_url,
                auth_creds=auth_creds,
                is_validation=True,
            )
            query = self.get_users_query(
                time_filter=datetime.now().strftime(DATE_FORMAT), limit=1
            )
            self.elastic_helper.api_helper(
                url=api_endpoint,
                method="POST",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                json=query,
                logger_msg="validating connectivity with Elastic server",
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                "auth credentials and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message=(
                    "Validation successful for "
                    f"{self.plugin_name} plugin configuration."
                ),
            )
        except ElasticPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(name="username", type=EntityFieldType.STRING, required=True),
                    EntityField(name="calculated_score_norm", type=EntityFieldType.NUMBER),
                    EntityField(name="calculated_score", type=EntityFieldType.NUMBER),
                    EntityField(name="calculated_level", type=EntityFieldType.STRING),
                    EntityField(name="Netskope Normalized Score", type=EntityFieldType.NUMBER),
                ]
            )
        ]
