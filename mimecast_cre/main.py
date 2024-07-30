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

import json
import base64
import hashlib
import hmac
import re
import uuid
from datetime import datetime
from typing import List, Dict, Optional
import traceback
from urllib.parse import urlparse
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult

from .utils.helper import MimecastUREPluginHelper, MimecastUREException
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MAX_USER_SCORE,
    MIN_USER_SCORE,
    MIMECAST_SCORE_MAPPING,
    MAX_PAGE_SIZE,
)


class MimecastUREPlugin(PluginBase):
    """Mimecast plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.mimecast_ure_helper = MimecastUREPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MimecastUREPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            err = f"{self.log_prefix}: Error occurred while getting plugin details. "
            f"Error: {exp}"
            self.logger.error(
                message=err,
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err)

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

    def _get_auth_headers(self, configuration: dict, endpoint: str) -> (str, dict):
        """Generate Mimecast authentication headers."""
        request_url = f"{configuration.get('url').strip().strip('/')}{endpoint}"
        request_id = str(uuid.uuid4())
        request_datetime = f"{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S')} UTC"

        # Create the HMAC SA1 of the Base64 decoded secret key for the Authorization header
        hmac_sha1 = hmac.new(
            base64.b64decode(configuration.get("secret_key")),
            ":".join(
                [
                    request_datetime,
                    request_id,
                    endpoint,
                    configuration.get("app_key"),
                ]
            ).encode("utf-8"),
            digestmod=hashlib.sha1,
        ).digest()

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": f"MC {configuration.get('access_key')}:"
            f"{sig.decode('utf-8')}",
            "x-mc-app-id": configuration.get("app_id").strip(),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        return request_url, headers

    def _get_all_groups(self, configuration: Dict, is_validation=False) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.
            is_validation (bool): Whether calling from validate method

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        endpoint = "/api/directory/find-groups"
        pageSize = MAX_PAGE_SIZE
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
        try:
            while True:
                groups = self.mimecast_ure_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=f"fetching all groups",
                    is_handle_error_required=True,
                    is_validation=is_validation,
                )
                all_groups += groups.get("data", [{}])[0].get("folders", {})
                nextPage = groups.get("meta", {}).get("pagination", {}).get("next", "")
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                else:
                    break
            return all_groups
        except MimecastUREException:
            raise
        except Exception as e:
            err_msg = "An error occurred while retrieving existing group details."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

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
        logger_msg = f"Creating group with name {name}"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
        err_msg = f"An error occurred while creating group with name {name}."
        try:
            response = self.mimecast_ure_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(body),
                logger_msg=logger_msg,
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {error}")
                raise MimecastUREException(error)
            return response
        except MimecastUREException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

    def _add_to_group(
        self, configuration: Dict, user_id: str, group_id: str, group_name: str
    ):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group IF of the group.
            group_name (str): Name of Group.

        Returns:
            HTTPError: If the group doesn't exist on Mimecast.
        """
        endpoint = "/api/directory/add-group-member"
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        logger_msg = f"Adding user {user_id} to group {group_name}"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
        err_msg = (
            f"An error occurred while adding {user_id} to group with name {group_name}."
        )
        try:
            response = self.mimecast_ure_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=logger_msg,
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {error}")
                raise MimecastUREException(error)
        except MimecastUREException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

    def _remove_from_group(self, configuration: Dict, user_id: str, group_id: str):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.
            group_name (str): Name of the Group name.

        Raises:
            HTTPError: If the group does not exist on Mimecast.
        """
        endpoint = "/api/directory/remove-group-member"
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        request_url, headers = self._get_auth_headers(configuration, endpoint)
        logger_msg = f"Removing {user_id} from the group"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
        err_msg = f"An error occurred while removing {user_id} from group."
        try:
            response = self.mimecast_ure_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=logger_msg,
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            if failures:
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {error}")
                raise MimecastUREException(err_msg)
        except MimecastUREException:
            raise
        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

    def _get_all_users(self) -> List:
        """Get list of all the users.

        Returns:
            List: List of all the users.
        """
        records = []
        endpoint = "/api/awareness-training/company/get-safe-score-details"
        pageSize = MAX_PAGE_SIZE
        nextPageToken = ""
        request_url, headers = self._get_auth_headers(self.configuration, endpoint)
        body = {
            "meta": {
                "pagination": {
                    "pageSize": pageSize,
                    "pageToken": nextPageToken,
                }
            }
        }
        err_msg = "An error occurred while fetching users."
        logger_msg = "fetching user details"
        page_count = 1
        while True:
            try:
                response = self.mimecast_ure_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=logger_msg,
                    is_handle_error_required=True,
                )
                failures = response.get("fail", [])
                if failures:
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(f"{self.log_prefix}: {err_msg} Error: {error}")
                    raise MimecastUREException(error)
                fetch_records = response.get("data", [])
                records += fetch_records
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled {len(fetch_records)} users from page {page_count}. Total users pulled {len(records)}."
                )
                nextPage = (
                    response.get("meta", {}).get("pagination", {}).get("next", "")
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                    page_count += 1
                else:
                    break
            except MimecastUREException:
                raise
            except Exception as e:
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastUREException(err_msg)
        return records

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries
            email (str): Email to find.

        Returns:
            Optional[Dict]: user dictionary if found, None otherwise.
        """
        if users:
            for user in users:
                if user.get("emailAddress", "") == email:
                    return user
        return None

    def fetch_records(self) -> List[Record]:
        """Pull Records from Mimecast.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        records = []
        try:
            fetched_records = self._get_all_users()
            if fetched_records:
                self.logger.debug(
                    f"{self.log_prefix}: Processing {len(fetched_records)} records."
                )
                for record in fetched_records:
                    records.append(
                        Record(
                            uid=record["emailAddress"],
                            type=RecordType.USER,
                            score=None,
                        )
                    )
            return records
        except Exception as e:
            err_msg = "An error occurred while fetching records."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

    def fetch_scores(self, records):
        """Fetch user scores."""
        # A 800 - 1000
        # B 600 - 799
        # C 400 - 599
        # D 200 - 399
        # F 1 - 199
        scored_users = []
        score_users = {}
        users = self._get_all_users()
        unique_records = {record.uid for record in records}
        if users:
            for user in users:
                if user["emailAddress"] in unique_records:
                    score_users[user["emailAddress"]] = user["risk"]
        if score_users:
            for key, value in score_users.items():
                scored_users.append(
                    Record(
                        uid=key,
                        type=RecordType.USER,
                        score=MIMECAST_SCORE_MAPPING[value],
                    )
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched scores for {len(scored_users)} users."
            )
        return scored_users

    def get_actions(self) -> list[ActionWithoutParams]:
        """Get Available actions."""
        return [
            ActionWithoutParams(label="Add to Group", value="add"),
            ActionWithoutParams(label="Remove from Group", value="remove"),
            ActionWithoutParams(label="No Action", value="generate"),
        ]

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == "generate":
            return []
        groups = self._get_all_groups(self.configuration)
        groups = sorted(groups, key=lambda g: g.get("description", "").lower())
        if action.value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [{"key": "Create New Group", "value": "create"}]
                    + [{"key": g["description"], "value": g["id"]} for g in groups],
                    "default": "create",
                    "mandatory": True,
                    "description": "Select an existing group from the available options or opt to create a new group by selecting 'Create New Group' for adding users into it.",
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "A_Cloud_Exchange",
                    "mandatory": False,
                    "description": "Add a new group name if you have opted for the 'Create New Group' actions from the above section on Group.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["description"], "value": g["id"]} for g in groups
                    ],
                    "default": groups[0]["id"] if len(groups) > 0 else "",
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        user = record.uid
        users = self._get_all_users()
        match = self._find_user_by_email(users, user)
        self.logger.debug(
            f"{self.log_prefix}: Performing '{action.label}' action on user '{user}'."
        )
        if match is None:
            self.logger.info(
                f"{self.log_prefix}: The user with email address {user} was not found on {self.plugin_name}. Hence action {action.label} will be skipped."
            )
            return
        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action '{action.label}' on {user}"
            )
        if action.value == "add":
            group_id = action.parameters.get("group", "")
            group_name = action.parameters.get("name", "").strip()
            if group_id == "create":
                groups = self._get_all_groups(self.configuration)
                match_group = self._find_group_by_name(groups, group_name)
                if match_group is None:
                    group = self._create_group(self.configuration, group_name)
                    group_id = group.get("data", [{}])[0].get("id", "")
                else:
                    group_id = match_group["id"]
            self._add_to_group(
                self.configuration, match["emailAddress"], group_id, group_name
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action '{action.label}' on user with email {user}."
            )
        elif action.value == "remove":
            group_id = action.parameters.get("group", "")
            self._remove_from_group(
                self.configuration,
                match["emailAddress"],
                group_id,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action '{action.label}' on user with email {user}."
            )

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Mimecast action configuration."""
        try:
            if action.value not in ["add", "remove", "generate"]:
                return ValidationResult(
                    success=False, message="Unsupported action provided."
                )
            if action.value == "generate":
                return ValidationResult(success=True, message="Validation successful.")
            groups = self._get_all_groups(self.configuration, is_validation=True)
            if action.parameters.get("group", "") != "create" and not any(
                map(lambda g: g["id"] == action.parameters.get("group", ""), groups)
            ):
                err_msg = "Invalid Group ID Provided."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if (
                action.value == "add"
                and action.parameters.get("group", "") == "create"
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                err_msg = "Group Name can not be empty"
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            return ValidationResult(success=True, message="Validation successful.")
        except Exception as e:
            err_msg = "Error occurred while validating actions."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_credentials(
        self, configuration: dict
    ) -> (ValidationResult, List[str]):
        """Validate credentials by making REST API call."""
        try:
            url, headers = self._get_auth_headers(
                configuration, "/api/account/get-account"
            )
            response = self.mimecast_ure_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg="validating the credentials",
                is_handle_error_required=True,
                is_validation=True,
            )
            failures = response.get("fail", [])
            if not failures:
                return ValidationResult(
                    success=True,
                    message=(
                        "Validation successful for {} {} Plugin.".format(
                            MODULE_NAME, self.plugin_name
                        )
                    ),
                ), response.get("data", [{}])[0].get("packages", [])
            return (
                ValidationResult(
                    success=False,
                    message="{}: Validation error occurred. Error: {}".format(
                        self.log_prefix, ", ".join(self._parse_errors(failures))
                    ),
                ),
                None,
            )
        except MimecastUREException:
            raise
        except Exception:
            err_msg = "Validation error occurred while validating credentials."
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

    def validate(self, configuration: Dict):
        """Validate Mimecast configuration."""
        base_url = configuration.get("url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            err_msg = "Invalid Base URL provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Application ID.
        app_id = configuration.get("app_id", "").strip()
        if not app_id:
            err_msg = "Application ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(app_id, str)):
            err_msg = "Invalid Application ID provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Application Key.
        app_key = configuration.get("app_key", "")
        if not app_key:
            err_msg = "Application Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(app_key, str)):
            err_msg = (
                "Invalid Application Key provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Access Key.
        access_key = configuration.get("access_key", "")
        if not access_key:
            err_msg = "Access Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(access_key, str)):
            err_msg = "Invalid Access Key provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Secret Key.
        secret_key = configuration.get("secret_key", "")
        if not secret_key:
            err_msg = "Secret Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(secret_key, str)) or not re.match(
            r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", secret_key
        ):
            err_msg = "Invalid Secret Key provided in the configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        validation_result, packages = self._validate_credentials(configuration)

        if not validation_result.success:
            return validation_result

        if "Awareness Training [1078]" not in packages:
            err_msg = (
                "Awareness Training' package is not enabled in "
                "configured account and hence fetching score is not possible."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return validation_result
