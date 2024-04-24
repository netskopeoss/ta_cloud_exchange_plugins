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

URE Elastic plugin.
"""

from datetime import datetime, timedelta
import traceback
from typing import Dict, Tuple, List
from urllib.parse import urlparse
from base64 import b64encode

from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult

from .utils.elastic_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    DATE_FORMAT,
    BATCH_SIZE,
)

from .utils.elastic_helper import ElasticPluginException, ElasticPluginHelper
from pydantic import ValidationError


class UREElasticPlugin(PluginBase):
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
            manifest_json = UREElasticPlugin.metadata
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

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def basic_auth(self, username, password):
        token = b64encode(f"{username}:{password}".encode("utf-8")).decode(
            "ascii"
        )
        return f"Basic {token}"

    def _get_auth_creds(self, configuration: Dict) -> Dict:
        """Get auth credentials.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Dict: Dictionary containing the auth creds.
        """
        return (
            {
                "username": configuration.get("username", "").strip(),
                "password": configuration.get("password"),
            }
            if configuration.get("authentication_method", "").strip()
            == "basic_auth"
            else {"api_key": configuration.get("api_key")}
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
            auth_token = self.get_auth_token(
                auth_method=auth_method,
                base_url=base_url,
                auth_creds=auth_creds,
                is_validation=True,
            )
            query = self.get_users_query(
                time_filter=datetime.now().strftime(DATE_FORMAT), limit=1
            )
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
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
                f"{self.log_prefix}: Successfully validated"
                " auth credentials and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message=(
                    "Validation successful for"
                    f" {self.plugin_name} plugin configuration."
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

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        if action.value == "generate":
            return
        return

    def _extract_users(self, hits: List) -> Tuple[List[Record], str]:
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
            user_name = str(hit.get("_source", {}).get("user", {}).get("name"))
            if user_name:
                page_users.append(Record(uid=user_name, type=RecordType.USER))
        search_after = (
            hits.get("hits", [{}])[-1].get("sort", [None])[0] if hits else None
        )

        return page_users, search_after

    def fetch_records(self) -> List[Record]:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.

        Returns:
            List[Record]: List of hosts fetched from Elastic.
        """
        self.logger.debug(
            f"{self.log_prefix}: Fetching records from "
            f"{PLATFORM_NAME} platform."
        )
        base_url = self.configuration.get("base_url", "").strip().strip("/")
        auth_method = self.configuration.get(
            "authentication_method", ""
        ).strip()
        auth_creds = self._get_auth_creds(self.configuration)
        auth_token = self.get_auth_token(
            base_url=base_url, auth_method=auth_method, auth_creds=auth_creds
        )
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        api_endpoint = f"{base_url}/logs-*/_search"
        last_run_time = None
        users = []
        if (
            self.last_run_at
        ):  # Check if plugin is previously sync to fetch only updated users.
            last_run_time = self.last_run_at.strftime(DATE_FORMAT)
        else:
            # Fetch users on the base of Initial range provided.
            initial_range = int(self.configuration.get("days"))
            last_run_time = datetime.now() - timedelta(days=initial_range)
            last_run_time = last_run_time.strftime(DATE_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: This is an initial pull of the plugin "
                f"hence pulling users for last {initial_range} day(s) "
                f"from {PLATFORM_NAME} platform."
            )
        page_count = 1
        total_skip_count = 0
        users_query = self.get_users_query(time_filter=last_run_time)
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Fetching users for page {page_count}"
                    f" from {PLATFORM_NAME} platform. Query: {users_query}"
                )
                headers = self.reload_auth_token(headers)
                resp_json = self.elastic_helper.api_helper(
                    url=api_endpoint,
                    method="POST",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    json=users_query,
                    logger_msg=f"pulling user(s) for page {page_count} from {PLATFORM_NAME} platform",  # noqa
                    is_handle_error_required=True,
                )
                page_users, search_after = self._extract_users(
                    resp_json.get("hits", {})
                )
                total_hits = len(resp_json.get("hits", {}).get("hits", []))
                page_users_count = len(page_users)
                users.extend(page_users)
                skipped_count = total_hits - page_users_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_users_count} user(s) and skipped "
                    f"{skipped_count} user(s) in page "
                    f"{page_count}. Total user(s) fetched: {len(users)}"
                )
                page_count += 1
                total_skip_count += skipped_count
                if not (page_users and search_after):
                    break
                users_query["search_after"] = [search_after]
            except ElasticPluginException:
                raise
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while pulling users from {PLATFORM_NAME} "
                        f"platform. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                "user(s) as the user.name field might not be available in "
                "the log object."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(users)}"
            f" user(s) from {PLATFORM_NAME} platform."
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

    def _extract_scores(self, hits: Dict) -> Dict:
        """Extract scores from hits.

        Args:
            hits (Dict): List of hits received from the API response.

        Returns:
            Dict: Dictionary containing scored users.
        """
        page_scored_records = {}

        if not hits.get("hits", []):
            return page_scored_records
        for hit in hits.get("hits", []):
            try:
                user_name = hit.get("_source", {}).get("user", {}).get("name")
                risk_score = self._map_risk_scores(
                    round(
                        hit.get("_source", {})
                        .get("user", {})
                        .get("risk", {})
                        .get("calculated_score_norm")
                    )
                )
                if user_name:
                    page_scored_records.update({user_name: risk_score})
            except (ValidationError, Exception) as error:
                error_message = (
                    "Validation error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while"
                        f" fetching score for {user_name} user."
                    ),
                    details=f"{hit}",
                )
        return page_scored_records

    def fetch_scores(self, records: List[Record]) -> List[Record]:
        """Fetch scores of hosts from Elastic platform.

        Args:
            agent_ids (List[Record]): List of records containing host's
            agent ids.

        Returns:
            List[Record]: List of records with scores.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching score(s) for record(s)"
            f" from {PLATFORM_NAME} platform."
        )
        base_url = self.configuration.get("base_url", "").strip().strip("/")
        auth_method = self.configuration.get(
            "authentication_method", ""
        ).strip()

        auth_creds = self._get_auth_creds(self.configuration)
        auth_token = self.get_auth_token(
            base_url=base_url, auth_method=auth_method, auth_creds=auth_creds
        )
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        scores_list = []
        scores_dict = {}
        api_endpoint = f"{base_url}/risk-score.*/_search"
        record_ids = [ids.uid for ids in records]
        batch_no = 1
        for i in range(0, len(record_ids), BATCH_SIZE):
            try:
                user_batch = record_ids[i : i + BATCH_SIZE]  # noqa
                if not user_batch:
                    break
                headers = self.reload_auth_token(headers)
                resp_json = self.elastic_helper.api_helper(
                    url=api_endpoint,
                    method="POST",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    json=self.get_score_query(user_batch),
                    logger_msg=f"fetching score(s) for {len(user_batch)} record(s) from {PLATFORM_NAME} platform",  # noqa
                    is_handle_error_required=True,
                )
                page_scores = self._extract_scores(resp_json.get("hits", {}))
                scores_dict.update(page_scores)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched scores for "
                    f"{len(page_scores)} record(s) from {len(user_batch)} "
                    f"record(s) in batch {batch_no}. Total score(s) fetched"
                    f": {len(scores_dict)}."
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

        for record in records:
            if record.uid in scores_dict:
                scores_list.append(
                    Record(
                        uid=record.uid,
                        type=record.type,
                        score=scores_dict[record.uid],
                    )
                )
        no_scored_users = len(scores_list)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched score(s) for "
            f"{no_scored_users} record(s) and skipped fetching "
            f"score(s) for {len(records)-no_scored_users} as they"
            f" might not be available on {PLATFORM_NAME} platform."
        )
        return scores_list

    def get_users_query(self, time_filter: str, limit=10000) -> Dict:
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

    def get_auth_token(
        self,
        auth_method: str,
        base_url: str,
        auth_creds: Dict,
        is_validation: bool = False,
    ) -> str:
        """Get auth token.

        Args:
            auth_method (str): Authentication Method.
            base_url (str): Base URL.
            auth_creds (Dict): Authentication credentials.
            is_validation (bool): Is validation required.

        Returns:
            str: OAuth2 token.
        """
        api_endpoint = f"{base_url}/_security/oauth2/token"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if auth_method == "basic_auth":
            username = auth_creds.get("username").strip()
            password = auth_creds.get("password")
            headers["Authorization"] = self.basic_auth(username, password)
        elif auth_method == "api_key_auth":
            api_key = auth_creds.get("api_key")
            headers["Authorization"] = f"ApiKey {api_key}"
        else:
            err_msg = (
                f"Invalid authentication method found {auth_method}."
                " Supported authentication methods are "
                "Basic Authentication and API Key Authentication."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ElasticPluginException(err_msg)

        body = {
            "grant_type": "client_credentials",
        }
        try:
            response = self.elastic_helper.api_helper(
                url=api_endpoint,
                method="POST",
                json=body,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                logger_msg="getting OAuth2 token",
                is_validation=is_validation,
            )
            if response.status_code == 200:
                resp_json = self.elastic_helper.parse_response(response)
                access_token = resp_json.get("access_token")
                if not access_token:
                    err_msg = (
                        "No access token or OAuth2 token found in "
                        "the API Response."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"API Response: {resp_json}",
                    )
                    raise ElasticPluginException(err_msg)
                else:
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully fetched OAuth2 "
                        "token from Elastic."
                    )
                    if self.storage is not None:
                        self.storage[
                            "token_expiry"
                        ] = datetime.now() + timedelta(
                            seconds=int(resp_json.get("expires_in", 1200))
                        )
                    return access_token
            if response.status_code in [400, 404]:
                err_msg = (
                    f"Received exit code {response.status_code}. Resource"
                    " not found. Verify Base URL provided in the "
                    "configuration parameters."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred."
                        f" {err_msg}"
                    ),
                    details=str(response.text),
                )
                raise ElasticPluginException(err_msg)
            elif response.status_code == 401:
                err_msg = (
                    "Received exit code 401, Unauthorized access. "
                    "Verify Username/Password or API Key provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred."
                        f" {err_msg}"
                    ),
                    details=str(response.text),
                )
                raise ElasticPluginException(err_msg)
            elif response.status_code == 403:
                err_msg = (
                    "Received exit code 403, Forbidden access. "
                    "Verify API Scope assigned to the user "
                    "or API Key provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(response.text),
                )
                raise ElasticPluginException(err_msg)
            self.elastic_helper.handle_error(response, "getting OAuth2 token")
        except ElasticPluginException as exp:
            err_msg = "Error occurred while fetching OAuth2 token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(exp)
        except Exception as exp:
            err_msg = "Unexpected error occurred while fetching OAuth2 token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)

    def reload_auth_token(self, headers: Dict) -> Dict:
        """Reload OAuth2 token.

        Args:
            headers (Dict): Headers dictionary.

        Returns:
            Dict: Headers dictionary with new OAuth2 token.
        """
        base_url = self.configuration.get("base_url", "").strip().strip("/")
        auth_method = self.configuration.get("auth_method", "").strip()
        auth_creds = self._get_auth_creds(self.configuration)
        if self.storage is None or self.storage.get("token_expiry") < (
            datetime.now() + timedelta(seconds=5)
        ):
            auth_token = self.get_auth_token(
                base_url=base_url,
                auth_method=auth_method,
                auth_creds=auth_creds,
            )
            headers.update({"Authorization": f"Bearer {auth_token}"})
        return headers

    def get_actions(self):
        """Get available actions."""
        return [ActionWithoutParams(label="No action", value="generate")]

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action.value}" '
                "provided in the action configuration. "
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

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
                "the configuration parameters. Allowed values are"
                " Basic Authentication and API Key Authentication."
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
                    "Username is a required configuration parameter"
                    " when Basic Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(username, str)):
                err_msg = (
                    "Invalid Username provided in the"
                    " configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate password.
            password = configuration.get("password")
            if not password:
                err_msg = (
                    "Password is a required configuration parameter"
                    " when Basic Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(password, str)):
                err_msg = (
                    "Invalid Password provided in the"
                    " configuration parameters."
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
                    "API key is a required configuration parameter"
                    " when API Key Authentication is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not (isinstance(api_key, str)):
                err_msg = (
                    "Invalid API key provided in the"
                    " configuration parameters."
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
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer greater than zero."
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
