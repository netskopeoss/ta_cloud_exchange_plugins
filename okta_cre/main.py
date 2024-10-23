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

"""Okta URE plugin."""

import os
import json
import uuid
import jwt
import traceback
import time
from datetime import datetime
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import requests
import re

from urllib.parse import urlparse, parse_qs

from typing import Dict, Union

from netskope.common.utils import add_user_agent

from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)

MAX_RETRY_COUNT = 4
PLATFORM_NAME = "Okta"
MODULE_NAME = "URE"
PLUGIN_VERSION = "1.1.2"
EVENTS_PROVIDER = "Netskope Security Events Provider"


class OktaException(Exception):
    """Okta exception class."""

    pass


class OktaPlugin(PluginBase):
    """Okta plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize SyslogPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = OktaPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLATFORM_NAME, PLUGIN_VERSION

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def handle_error(self, resp):
        resp_json = self.parse_response(resp)

        if resp.status_code == 200:
            return resp_json

        toast_message = ""
        error_summary = resp_json.get("errorSummary", "")
        error_msg = f"Received error code {resp.status_code}."
        error_causes = resp_json.get("errorCauses", [])
        error = resp_json.get("err", "")
        error_description = resp_json.get("description", "")
        if error_summary:
            error_msg += f" Error Summary: {error_summary}."
            toast_message += error_summary
        if error_causes:
            error_msg += f" Error Causes: {error_causes}."
        if error:
            error_msg += f" Error: {error}."
        if error_description:
            error_msg += f" Error Description: {error_description}."
            toast_message += error_description
        if not (error_summary or error_causes or error or error_description):
            error_msg += " Unexpected error occurred."
            toast_message += "Unexpected error occurred, check logs."
        self.logger.error(message=f"{self.log_prefix}: {error_msg}", details=resp.text)

        raise OktaException(toast_message)

    def parse_response(self, response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received. "
                "Error: {}".format(err)
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=response.text,
            )
            raise OktaException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=response.text,
            )
            raise OktaException(err_msg)

    def make_request(self, method, calling_method, url_endpoint, headers, params={}, json={}, retry_req=True):
        try:
            req = getattr(requests, method)
            self.logger.debug(
                f"{self.log_prefix}: API endpoint for {calling_method}: {url_endpoint}."
            )
            headers = self._add_user_agent(headers)
            for retry in range(MAX_RETRY_COUNT + 1):
                response = req(
                    url_endpoint,
                    headers=headers,
                    params=params,
                    json=json,
                    proxies=self.proxy,
                )
                msg = (
                    f"{self.log_prefix}: API response for {calling_method}: {response.status_code}."
                )
                self.logger.debug(msg)
                if (
                    response.status_code == 429 or
                    response.status_code >= 500 and response.status_code <= 600
                ) and retry < MAX_RETRY_COUNT and retry_req:
                    increamnt_counter = (retry + 1) * 60
                    retry_after_epoch = int(
                        response.headers.get(
                            "x-rate-limit-reset",
                            int(time.time()) + increamnt_counter,
                        )
                    )
                    retry_after = retry_after_epoch - int(time.time())
                    if retry_after > 300:
                        self.logger.error(
                            f"{self.log_prefix}: Received Too many requests error "
                            f"while {calling_method}. The retry time exceeds "
                            f"5 minutes, hence returning status "
                            f"code {response.status_code}."
                        )
                        break
                    self.logger.info(
                        f"{self.log_prefix}: Received status code {response.status_code} "
                        f"while {calling_method}. "
                        f"Retrying after: {retry_after} seconds - Retry Attempt ({retry + 1})."
                    )
                    time.sleep(retry_after)
                else:
                    break
            return response
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while '{calling_method}'. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise OktaException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} "
                f"platform while '{calling_method}'. Proxy server or {self.plugin_name}"
                " server is not reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise OktaException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {calling_method}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise OktaException(err_msg)
        except Exception as err:
            err_msg = f"Error occurred while {calling_method}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise OktaException(err)

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

    def _add_to_group(self, configuration: Dict, user_id: str, group_id: str, user: str):
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
            "Authorization": f'SSWS {configuration.get("api_token")}',
        }
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}"
            f"/api/v1/groups/{group_id}/users/{user_id}"
        )
        response = self.make_request(
            "put",
            "Adding user(s) to Group",
            url,
            headers
        )
        if response.status_code == 204:
            self.logger.info(
                f"{self.log_prefix}: Successfully added user '{user}' to the selected group."
            )
            return
        elif response.status_code == 404:
            err_msg = f"Group with id '{group_id}' does not exist on {PLATFORM_NAME}."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=response.text
            )
            raise OktaException(err_msg)
        else:
            self.handle_error(response)

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
            "Authorization": f'SSWS {configuration.get("api_token")}',
        }
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}"
            f"/api/v1/groups/{group_id}/users/{user_id}"
        )
        response = self.make_request(
            "delete",
            "Removing user(s) from group",
            url,
            headers
        )
        if response.status_code == 204:
            return
        elif response.status_code == 404:
            err_msg = (
                f"Group with id '{group_id}' does not exist on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=response.text
            )
            raise OktaException(err_msg)
        else:
            self.handle_error(response)

    def _get_all_groups(self, configuration: Dict, retry=True) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        params = {}
        url = f"{configuration.get('url', '').strip().rstrip('/')}/api/v1/groups"
        params["limit"] = 200
        params["filter"] = 'type eq "OKTA_GROUP"'
        after = ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {configuration.get('api_token')}",
        }
        while True:
            groups = self.make_request(
                "get",
                "Getting all groups",
                url,
                headers,
                params,
                retry_req=retry
            )
            all_groups += self.handle_error(groups)
            links = re.findall(r"(https?://\S+)", groups.headers.get("link", ""))
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
        url = f"{configuration.get('url', '').strip().rstrip('/')}/api/v1/users"
        params["limit"] = 200
        after = ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "okta-response": "omitCredentials, omitCredentialsLinks, omitTransitioningToStatus",
            "Authorization": f"SSWS {configuration.get('api_token')}",
        }
        while True:
            users = self.make_request(
                "get",
                "Getting all users",
                url,
                headers,
                params
            )
            all_users += self.handle_error(users)
            links = re.findall(r"(https?://\S+)", users.headers.get("link", ""))
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
            if user.get("profile", {}).get("email", "") == email or user.get("profile", {}).get("login", "") == email:
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
            if group.get("profile", {}).get("name", "") == name:
                return group
        return None

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="Push risk score", value="push_risk_score"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_score_level(self, score):
        """Assign level on the basis of current score."""
        if isinstance(score, int) and (0 <= score <= 1000):
            if 751 <= score <= 1000:
                return "low"
            elif 501 <= score <= 750:
                return "medium"
            else:
                return "high"
        else:
            return "none"

    def get_kid_from_jwks_url(self, base_url):
        """Extract KID from the Public Key hosted in JWKS URL."""
        try:
            resp = self.make_request(
                "get",
                "Fetching Key ID",
                base_url,
                headers={}
            )
            if resp.status_code != 200:
                self.handle_error(resp)
            json_resp = self.parse_response(resp)
            keys = json_resp.get("keys", [])
            if keys and keys[0].get("kid", ""):
                return keys[0].get("kid", "")
            else:
                err_msg = (
                    "Invalid Public Key found on JWKS URL. "
                    "Check the format for Public Key and make sure that the Public key contains 'kid'."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}"
                )
                raise OktaException(err_msg)
        except Exception as err:
            error_msg = (
                "Error occurred while extracting KID from Publicly hosted URL."
                "Make sure that the JWS URL is reachable and "
                "the format of the Public Key is valid "
                f"Error: {err}"
            )
            raise OktaException(error_msg)

    def generate_set_token(
        self,
        issuer_url,
        private_key,
        base_url,
        kid,
        user,
        configuration,
        current_score,
        historical_score
    ):
        """Generate JWT SET Token."""
        try:
            current_score_level = self.get_score_level(
                current_score
            )
            previous_score_level = self.get_score_level(
                historical_score
            )
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Calculated current score level: '{current_score_level}', "
                f"Calculated previous score level: '{previous_score_level}' "
                "on the basis of Netskope-Okta mapping (see plugin guide for more details), "
                f"for the user {user} and configuration {configuration}."
            )
            header = {"kid": kid, "alg": "RS256", "typ": "secevent+jwt"}
            event = {
                    "iss": issuer_url,
                    "jti": uuid.uuid1().hex,
                    "iat": datetime.now(),
                    "aud": base_url,
                    "events": {
                        "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
                            "subject": {
                                "user": {
                                    "format": "email",
                                    "email": user,
                                }
                            },
                            "current_level": current_score_level, # Current Score
                            "previous_level": previous_score_level, # Previous Score
                            "event_timestamp": datetime.now().timestamp(),
                        }
                    },
                }

            set_token = jwt.encode(
                event,
                key=private_key,
                headers=header,
            )
            return set_token
        except Exception as err:
            error_msg = (
                "Error occurred while generating SET Token. "
                f"Error: {err}"
            )
            raise OktaException(error_msg)

    def push_event_to_okta(self, base_url, set_token):
        """Create events on Okta for pushing risk score."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/secevent+jwt"
        }
        try:
            push_endpoint = f"{base_url}/security/api/v1/security-events"
            resp = self.make_request(
                "post",
                "Pushing event to Okta",
                push_endpoint,
                headers,
                json=set_token
            )
            if resp.status_code not in [200, 202]:
                self.handle_error(resp)
        except Exception as err:
            error_message = (
                f"Error occurred while pushing risk score "
                f"to {PLATFORM_NAME} user. Error: {err}"
            )
            raise OktaException(error_message)

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
                "description": "Created From Netskope URE",
            }
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {configuration.get('api_token')}",
        }
        response = self.make_request(
            "post",
            "Creating group",
            f"{configuration.get('url', '').strip().rstrip('/')}/api/v1/groups",
            headers,
            json=body
        )
        resp_json = self.handle_error(response)
        return resp_json

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        action_value = action.value
        action_label = action.label
        action_parameters = action.parameters
        user = record.uid
        self.logger.debug(
            f"{self.log_prefix}: Executing action '{action_label}' for user '{user}'."
        )
        if action_value == "generate":
            self.logger.debug(
                "{}: Successfully executed '{}' action on user '{}'. "
                "Note: No processing will be done from plugin for "
                "the '{}' action.".format(
                    self.log_prefix, action_label, user, action_label
                )
            )
            return
        elif record.type != RecordType.USER:
            self.logger.info(
                f"{self.log_prefix}: {PLATFORM_NAME} plugin only supports sharing scores for Users hence skipping"
                f" execution of action {action_label} on host '{user}'."
            )
            return
        users = self._get_all_users(self.configuration)
        match = self._find_user_by_email(users, user)
        if match is None:
            self.logger.info(
                f"{self.log_prefix}: User '{user}' not found on {PLATFORM_NAME}. '{action_label}' action will not be performed."
            )
            return
        if action_value == "add":
            group_id = action_parameters.get("group", "")
            if group_id == "create":
                # Get ids of the group
                groups = self._get_all_groups(self.configuration)
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched all the available groups on "
                    f"{PLATFORM_NAME} in order to match the selected group."
                )
                group_name = action_parameters.get("name", "").strip()
                match_group = self._find_group_by_name(groups, group_name)
                if match_group is None:  # create group
                    group = self._create_group(self.configuration, group_name)
                    group_id = group.get("id", "")
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created group with name: '{group_name}' on {PLATFORM_NAME}."
                    )
                else:
                    self.logger.info(
                        f"{self.log_prefix}: Group with name: {group_name} already exists, user '{user}' will be added in the existing group."
                    )
                    group_id = match_group.get("id", "")
            self._add_to_group(self.configuration, match.get("id", ""), group_id, user)
        elif action_value == "remove":
            self._remove_from_group(
                self.configuration, match.get("id", ""), action_parameters.get("group", "")
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully removed '{user}' "
                f"from group with ID {action_parameters.get('group', '')}."
            )
        elif action_value == "push_risk_score":
            try:
                scores = record.scores
                selected_configuration = action_parameters.get("configuration", {})
                if scores:
                    for score in scores:
                        score_source = score.source
                        current_score = score.current
                        score_historical = score.historical
                        if score_source == selected_configuration.strip():
                            self.logger.debug(
                                f"{self.log_prefix}: Selected source '{selected_configuration}' is associated with the user '{user}'."
                            )
                            if current_score is not None:
                                self.logger.debug(
                                    f"{self.log_prefix}: Current score present for the configuration '{selected_configuration}' for the user '{user}'."
                                    f" Current score value: {current_score}."
                                )
                                historical_score = "none"
                                if score_historical and len(score_historical) > 1:
                                    historical_score = score_historical[-2].get("value", "none")
                                    self.logger.debug(
                                        f"{self.log_prefix}: Historical score present for the configuration '{selected_configuration}' for the user '{user}'."
                                        f" Historical score value: {historical_score}."
                                    )
                                key_id = self.get_kid_from_jwks_url(
                                    action_parameters.get("jwks_url", "").strip()
                                )
                                self.logger.info(
                                    f"{self.log_prefix}: Successfully fetched Key ID from the JWKS URL for the user '{user}'."
                                )
                                set_token = self.generate_set_token(
                                    action_parameters.get("issuer_url", "").strip(),
                                    action_parameters.get("private_key", ""),
                                    self.configuration.get("url", "").strip().rstrip("/"),
                                    key_id,
                                    user,
                                    action_parameters.get("configuration", {}).strip(),
                                    current_score,
                                    historical_score
                                )
                                self.logger.info(
                                    f"{self.log_prefix}: Successfully generated the SET Token for the user '{user}'."
                                )
                                self.push_event_to_okta(
                                    self.configuration.get("url", "").strip().rstrip("/"),
                                    set_token
                                )
                                self.logger.info(
                                    f"{self.log_prefix}: Successfully pushed risk score "
                                    f"for user '{user}'."
                                )
                            else:
                                msg = (
                                    f"No score is associated with the user '{user}' for the configuration '{action_parameters.get('configuration', {}).strip()}', "
                                    "hence Push risk score action will not be performed."
                                )
                                self.logger.info(
                                    f"{self.log_prefix}: {msg}"
                                )
                            return
                    else:
                        msg = (
                                f"No score is associated with the user '{user}' for the configuration '{action_parameters.get('configuration', {}).strip()}', "
                                f"hence '{action_label}' action will not be performed. Check if the provided Plugin Configuration Name exists."
                            )
                        self.logger.info(
                            f"{self.log_prefix}: {msg}"
                        )
                        return
                else:
                    msg = (
                        f"No score associated with the user '{user}', "
                        "hence Push risk score action will not be performed."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: {msg}"
                    )
                    return
            except OktaException as err:
                raise OktaException(err)
            except Exception as err:
                error_msg = (
                    f"{self.log_prefix}: "
                    "Error occurred while pushing risk score. "
                    f"Error: {err}"
                )
                self.logger.error(
                    message=error_msg,
                    details=str(traceback.format_exc())
                )
                raise OktaException(err)
            
    def get_all_security_events_provider(self, base_url, token, issuer, jwks_url):
        """Get all Security Events Providers and check settings."""
        url_endpoint = f"{base_url}/api/v1/security-events-providers"
        after = ""
        sep_id = None
        security_event_provider_list = []
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {token}",
        }
        params = {}
        while True:
            resp = self.make_request(
                method="get",
                calling_method=f"fetching existing security events providers from the {PLATFORM_NAME}",
                url_endpoint=url_endpoint,
                headers=headers,
                params=params,
                json={},
                retry_req=True
            )
            security_event_provider_list += self.handle_error(resp)
            links = re.findall(r"(https?://\S+)", resp.headers.get("link", ""))
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
        
        for provider in security_event_provider_list:
            if provider.get("name") == EVENTS_PROVIDER:
                settings = provider.get("settings", {})
                sep_id = provider.get("id", "")
                if settings.get("issuer", "") == issuer and settings.get("jwks_url", "") == jwks_url:
                    return True, sep_id
                else:
                    return False, sep_id
        return False, sep_id
    
    def update_security_event_provider(self, base_url, token, issuer, jwks_url, sep_id, retry=True):
        """Update the existing Security Event Provider"""
        url_endpoint = f"{base_url}/api/v1/security-events-providers/{sep_id}"
        body = {
            "name": EVENTS_PROVIDER,
            "type": "Netskope",
            "settings": {
                "issuer": issuer,
                "jwks_url": jwks_url
            },
        }
        headers = {
            "Authorization": f"SSWS {token}"
        }
        resp = self.make_request(
            "put",
            "updating security events provider",
            url_endpoint,
            headers,
            json=body,
            retry_req=retry
        )
        if resp.status_code in [200, 201]:
            self.logger.info(
                f"{self.log_prefix}: Successfully updated Security Events Provider with the issuer '{issuer}'."
            )
            return
        self.handle_error(resp)


    def generate_security_provider(self, base_url, token, issuer, jwks_url, retry=True):
        """Create Security Events Provider in Okta tenant."""
        url_endpoint = f"{base_url}/api/v1/security-events-providers"
        body = {
            "name": EVENTS_PROVIDER,
            "type": "Netskope",
            "settings": {
                "issuer": issuer,
                "jwks_url": jwks_url
            },
        }
        headers = {
            "Authorization": f"SSWS {token}"
        }
        resp = self.make_request(
            "post",
            "generating security events provider",
            url_endpoint,
            headers,
            json=body,
            retry_req=retry
        )
        if resp.status_code in [200, 201]:
            self.logger.info(
                f"{self.log_prefix}: Successfully created Security Events Provider with the issuer '{issuer}'."
            )
            return

        json_resp = self.parse_response(resp)
        error_causes = json_resp.get("errorCauses", [])
        for error_cause in error_causes:
            if (
                "Security Events Provider name must be unique"
                in error_cause.get("errorSummary", "")
            ):
                is_matched, sep_id = self.get_all_security_events_provider(base_url, token, issuer, jwks_url)
                if not is_matched:
                    error_msg = (
                        f"{EVENTS_PROVIDER} already exists with a different Issuer than provided in the configuration. "
                        f"Either delete the existing Security Events Provider from the {PLATFORM_NAME} platform or update the Issuer URL and JWKS URL."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_msg}",
                    )
                    raise OktaException(error_msg)
                
                # update SEP
                self.update_security_event_provider(base_url, token, issuer, jwks_url, sep_id, True)
                return
            elif (
                "The provided issuer already exists for this organization."
                in error_cause.get("errorSummary", "")
            ):
                error_message = (
                    f"{self.log_prefix}: "
                    "The provided Issuer URL is already associated with other Security Events Provider. "
                    "Either delete the existing Security Events Provider or use a unique Issuer URL."
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_message}",
                    details=str(error_cause)
                )
                raise OktaException(error_message)
        self.handle_error(resp)

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        action_value = action.value
        if action_value == "generate":
            return []
        if action_value != "push_risk_score":
            groups = self._get_all_groups(self.configuration, retry=False)
            groups = sorted(
                groups, key=lambda g: g.get("profile", {}).get("name", "").lower()
            )
        if action_value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("profile", {}).get("name", ""), "value": g.get("id", "")}
                        for g in groups
                    ]
                    + [{"key": "Create new group", "value": "create"}],
                    "default": groups[0].get("id", "") if groups else "",
                    "mandatory": True,
                    "description": "Select a group to add the user to.",
                },
                {
                    "label": "Group Name (only applicable for Create new group)",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Create Okta group with given name if it does not exist.",
                },
            ]
        elif action_value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g.get("profile", {}).get("name", ""), "value": g.get("id", "")}
                        for g in groups
                    ],
                    "default": groups[0].get("id", "") if groups else "",
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]
        elif action_value == "push_risk_score":
            return [
                {
                    "label": "Plugin Configuration Name",
                    "key": "configuration",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Name of the configuration to share scores from. Provide the configured name of Netskope URE Plugin. \nNote: The Plugin Configuration Name is case sensitive.",
                },
                {
                    "label": "Issuer URL",
                    "key": "issuer_url",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "The URL used to host the public key and generate the security provider.",
                },
                {
                    "label": "JWKS URL",
                    "key": "jwks_url",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "JSON Web Key Set URL, where the public key is hosted.",
                },
                {
                    "label": "Private Key",
                    "key": "private_key",
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": "Private Key associated with the public Key hosted on the JWKS URL. \nNote: Provide the Private Key in PEM format.",
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Okta action configuration."""
        action_value = action.value
        action_parameters = action.parameters
        if action_value not in ["add", "remove", "generate", "push_risk_score"]:
            return ValidationResult(
                success=False,
                message="Unsupported action provided."
            )
        if action_value == "generate":
            return ValidationResult(
                success=True,
                message="Validation successful."
            )

        if action_value != "push_risk_score":
            try:
                groups = self._get_all_groups(self.configuration, retry=False)
            except OktaException:
                return ValidationResult(
                    success=False,
                    message="Error occurred while fetching groups."
                )
            except Exception as err:
                error_msg = "Error occurred while fetching groups."
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg} Error: {err}",
                    details=str(traceback.format_exc())
                )
                return ValidationResult(
                    success=False,
                    message=error_msg
                )

            if action_value == "add" and action_parameters.get("group", "") != "create" and not any(
                map(lambda g: g.get("id", "") == action_parameters.get("group", ""), groups)
            ):
                return ValidationResult(
                    success=False, message="Invalid group provided."
                )
            if action_value == "remove" and not any(
                map(lambda g: g.get("id", "") == action_parameters.get("group", ""), groups)
            ):
                return ValidationResult(
                    success=False, message="Invalid group provided."
                )
            if (
                action_value == "add"
                and action_parameters.get("group", "") == "create"
                and not action_parameters.get("name", "").strip()
            ):
                return ValidationResult(
                    success=False,
                    message="Group Name can not be empty when 'Create new group' is selected in the Group field."
                )
            return ValidationResult(
                success=True,
                message="Validation successful."
            )

        # for Push risk score action
        if (
            "configuration" not in action_parameters
            or not action_parameters.get("configuration", "").strip()
        ):
            error_msg = "Plugin Configuration Name can not be empty."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )
        elif (
            not isinstance(action_parameters.get("configuration", "").strip(), str)
        ):
            error_msg = "Invalid Plugin Configuration Name provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )
        if (
            "issuer_url" not in action_parameters
            or not action_parameters.get("issuer_url", "").strip()
        ):
            error_msg = "Issuer URL can not be empty."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )
        elif not self._validate_url(action_parameters.get("issuer_url", "").strip()):
            error_msg = "Invalid Issuer URL provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )

        if (
            "jwks_url" not in action_parameters
            or not action_parameters.get("jwks_url", "").strip()
        ):
            error_msg = "JWKS URL can not be empty."
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(
                success=False, message=f"{error_msg}."
            )
        elif not self._validate_url(action_parameters.get("jwks_url", "").strip()):
            error_msg = "Invalid JWKS URL provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(
                success=False, message=f"{error_msg}."
            )

        if (
            "private_key" not in action_parameters
            or not action_parameters.get("private_key", "").strip()
        ):
            error_msg = "Private Key can not be empty."
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )
        try:
            # Attempt to load the key using the cryptography library
            load_pem_private_key(
                action_parameters.get("private_key", "").strip().encode(),
                password=None
            )
        except ValueError:
            error_msg = (
                "Invalid Private Key provided, "
                "make sure the Private Key is in PEM format."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )

        try:
            self.generate_security_provider(
                self.configuration.get("url", "").strip().rstrip("/"),
                self.configuration.get("api_token"),
                action_parameters.get("issuer_url", "").strip(),
                action_parameters.get("jwks_url", "").strip(),
                retry = False
            )
            return ValidationResult(
                success=True,
                message="Validation successful."
            )
        except OktaException as err:
            error_msg = (
                "Error occurred while generating security provider. "
                f"{err}"
            )
            self.logger.error(
                f"{self.log_prefix}: {err}",
                details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        except Exception as err:
            error_msg = (
                "Error occurred while generating security evnets provider. "
                "Check the credentials provided. "
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}, Error: {err}",
                details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message="Error occurred while generating security provider. "
                "Check the credentials provided."
            )

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
            response = self.make_request(
                "get",
                "Validating Okta credentials",
                url,
                headers,
                retry_req=False
            )
            if response.status_code in [200, 201]:
                return ValidationResult(
                    success=True,
                    message="Validation successful."
                )
            elif response.status_code == 401:
                error_msg = "Authentication failed, check the API Token provided."
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: {error_msg}",
                    details=response.text,
                )
                return ValidationResult(success=False, message=error_msg)
            elif response.status_code == 403:
                error_msg = "You do not have permission to perform the requested action, check the API Token provided."
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: {error_msg}",
                    details=response.text,
                )
                return ValidationResult(success=False, message=error_msg)
            self.handle_error(response)
        except OktaException as err:
            return ValidationResult(
                success=False,
                message=f"{err}",
            )
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while authentication. {err}"
            )
            return ValidationResult(
                success=False,
                message="Invalid Okta Domain or API Token. Check logs.",
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

        # Okta Domain
        okta_domain = configuration.get("url", "").strip().rstrip("/")
        if (
            "url" not in configuration
            or not okta_domain
        ):
            error_msg = "Okta Domain is a required field."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False, message=f"{error_msg}"
            )
        elif (
            not self._validate_url(okta_domain)
            or not self.validate_okta_domain(okta_domain)
        ):
            error_msg = "Invalid Okta Domain provided."
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details="Okta Domain must end with '.oktapreview.com', '.okta.com' or '.okta-emea.com'"
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )

        api_token = configuration.get("api_token")
        if (
            "api_token" not in configuration
            or not api_token
        ):
            error_msg = "API Token is a required field."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=f"{error_msg}"
            )
        return self._validate_auth(
            configuration.get("url", "").strip().rstrip('/'),
            configuration.get("api_token")
        )
