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

CRE Mimecast Plugin."""

import json
import re
from typing import Any, Callable, List, Dict, Optional
from urllib.parse import urlparse
import traceback

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.helper import MimecastPluginHelper, MimecastPluginException
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    MAX_PAGE_SIZE,
    USER_FIELD_MAPPING,
    EMAIL_ADDRESS_REGEX,
    GET_ACCOUNT_DETAILS_ENDPOINT,
    FIND_GROUPS_ENDPOINT,
    GET_SAFE_SCORE_DETAILS_ENDPOINT,
    CREATE_GROUP_ENDPOINT,
    ADD_GROUP_MEMBER_ENDPOINT,
    REMOVE_GROUP_MEMBER_ENDPOINT,
    MIMECAST_SCORE_MAPPING,
    NETSKOPE_RISK_CATEGORY_MAPPING,
    ADD_TO_GROUP_BATCH_SIZE,
    MAX_GROUP_MEMBER_PAYLOAD_BYTES,
    ENGAGE_CORE_PACKAGE,
)


class MimecastPlugin(PluginBase):
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
        self.mimecast_helper = MimecastPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        # Lets execute_actions() receive each action's own action-log
        # id, so per-record success/failure can be reported back to
        # CE via ActionResult.failed_action_ids instead of the whole
        # batch being marked successful whenever the call itself
        # doesn't raise.
        self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MimecastPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _parse_errors(self, failures):
        """
        Parse the error message from Mimecast response.
        args:
            failures: Mimecast response
        returns:
            List: List of error messages
        """
        messages = set()
        for failure in failures:
            message = failure.get("message")
            errors = failure.get("errors", [])
            if message:
                messages.add(message)
            if errors and isinstance(errors, list):
                for error in errors:
                    messages.add(error.get("message"))
        return list(messages)

    def _remove_from_group(
        self, configuration: Dict, user_id: str, group_id: str, group_name: str
    ):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Mimecast.
        """

        self.logger.debug(
            f"{self.log_prefix}: Removing {user_id} "
            f"from the group '{group_name}'."
        )
        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        base_url = self._get_base_url(configuration)
        request_url = f"{base_url}/{REMOVE_GROUP_MEMBER_ENDPOINT}"

        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"removing {user_id} from the group '{group_name}'",
                is_handle_error_required=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while removing {user_id} "
                    f"from group '{group_name}'."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(err_msg)
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                f"An unexpected error occurred while removing {user_id} "
                f"from group '{group_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _chunk_by_payload_size(
        self, payload: List, max_bytes: int = MAX_GROUP_MEMBER_PAYLOAD_BYTES
    ) -> List[List]:
        """Split payload items into chunks by actual request body size.

        Each chunk's real encoded byte size - measured as the exact
        JSON the API call sends, {"data": [...]}, not an estimate -
        stays at or under max_bytes. A single item that alone exceeds
        max_bytes is still placed in its own chunk rather than
        dropped, since Mimecast's own response is the authority on
        whether it's rejected.

        Args:
            payload (List): Items to chunk.
            max_bytes (int): Maximum allowed size, in bytes, of the
                encoded {"data": [...]} body per chunk.

        Returns:
            List[List]: Chunks of payload, each within max_bytes.
        """
        chunks = []
        current_chunk = []
        for item in payload:
            candidate = current_chunk + [item]
            body_size = len(
                json.dumps({"data": candidate}).encode("utf-8")
            )
            if body_size > max_bytes and current_chunk:
                chunks.append(current_chunk)
                current_chunk = [item]
            else:
                current_chunk = candidate
        if current_chunk:
            chunks.append(current_chunk)
        return chunks

    def _bulk_remove_from_group(
        self,
        configuration: Dict,
        payload: List,
        group_name: str,
        action_label: str,
        skip_count: int = 0,
        revert: bool = False,
    ) -> set:
        """Remove users from group.

        Args:
            configuration (Dict): Configuration parameters.
            payload (List): List of dictionaries, each dictionary
                            representing the payload for removing a
                            user from a group.
            group_name (str): Name of the group.
            action_label (str): Action label
            skip_count (int): Number of users skipped
            revert (bool): Whether this removal is reverting a
                previously executed 'Add to Group' action. Defaults
                to False.

        Returns:
            set: Email addresses that failed at the Mimecast API
                level, so the caller can attribute failures back to
                specific action log entries.
        """

        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        base_url = self._get_base_url(configuration)
        request_url = f"{base_url}/{REMOVE_GROUP_MEMBER_ENDPOINT}"
        total_users = len(payload)
        # 'skip_count' (passed in) counts records excluded before this
        # call - invalid emails or users not found on Mimecast - and
        # is already reflected in 'total_users' not including them.
        # 'api_skip_count' tracks failures from this call's own API
        # requests, kept separate so the two are never double-counted
        # in the success total below.
        api_skip_count = 0
        failed_emails = set()
        # Unique reasons the API itself gave for skipped users across
        # all chunks (e.g. "Group member does not exist"), surfaced in
        # the final summary line so it's not just a generic "an error
        # occurred" - the details/reason are already in the per-chunk
        # error log, but the summary should say why too.
        api_skip_reasons = set()
        self.logger.info(
            f"{self.log_prefix}: Removing {total_users} "
            f"user(s) from group {group_name}, chunked to stay under "
            f"{MAX_GROUP_MEMBER_PAYLOAD_BYTES} bytes per request"
            + (
                f" while reverting the '{action_label}' action."
                if revert
                else "."
            )
        )
        batch_count = 1

        payload_chunks = self._chunk_by_payload_size(payload)
        for chunk in payload_chunks:
            body = {"data": chunk}
            try:
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    data=json.dumps(body),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"removing {len(chunk)} user(s) from group"
                        f" {group_name} for batch {batch_count}"
                    ),
                    is_handle_error_required=True,
                    configuration=configuration,
                )
            except Exception as e:
                # A chunk that fails outright (e.g. a 5xx that
                # outlives the retry budget, or a connection error)
                # must not abort chunks that already succeeded or
                # have yet to run - every item in this chunk is
                # marked failed and the loop continues.
                for item in chunk:
                    item_email = item.get("emailAddress")
                    if item_email:
                        failed_emails.add(item_email)
                api_skip_count += len(chunk)
                api_skip_reasons.add(str(e))
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to remove "
                        f"{len(chunk)} user(s) from group {group_name}"
                        f" for batch {batch_count}. Error: {e} "
                        "Continuing with next batch."
                    ),
                    details=str(traceback.format_exc()),
                )
                batch_count += 1
                continue

            data = response.get("data", [])
            failures = response.get("fail", [])
            if failures:
                skip = len(chunk) - len(data)
                err_msg = (
                    f"An error occurred while removing {skip} "
                    f"user(s) for batch {batch_count} from group "
                    f"{group_name}. Hence these user(s) records"
                    " will be skipped."
                )
                error_list = self._parse_errors(failures)
                error = ", ".join(error_list)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                api_skip_reasons.update(error_list)
                # A failure without a per-item 'key' (e.g. a
                # content-length rejection) applies to the whole
                # request, not specific items - Mimecast never
                # attempted them individually, so every item in
                # this chunk failed, not just the keyed ones.
                if any(
                    not isinstance(f.get("key"), dict)
                    for f in failures
                ):
                    for item in chunk:
                        item_email = item.get("emailAddress")
                        if item_email:
                            failed_emails.add(item_email)
                else:
                    for failure in failures:
                        failed_key = failure.get("key", {})
                        failed_email = failed_key.get("emailAddress")
                        if failed_email:
                            failed_emails.add(failed_email)
                api_skip_count += skip
                batch_count += 1
                continue

            self.logger.info(
                f"{self.log_prefix}: Successfully removed {len(data)}"
                f" user(s) from group {group_name} "
                f"for batch {batch_count}."
            )
            batch_count += 1

        msg = (
            f"Successfully {'reverted' if revert else 'performed'} "
            f"action '{action_label}' on "
            f"{total_users - api_skip_count} user(s) out of "
            f"{total_users + skip_count} record(s)."
        )
        if skip_count > 0:
            msg += (
                f" Skipped {skip_count} user(s) as they were "
                f"not found on {PLATFORM_NAME} or had an "
                "invalid email address."
            )
        if api_skip_count > 0:
            msg += (
                f" Skipped removing {api_skip_count} user(s) "
                f"from group {group_name}."
            )
            if api_skip_reasons:
                msg += f" Reason(s): {'; '.join(api_skip_reasons)}."

        self.logger.info(f"{self.log_prefix}: {msg}")
        return failed_emails

    def _add_to_group(
        self, configuration: Dict, user_id: str, group_id: str, group_name: str
    ):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group IF of the group.

        Returns:
            HTTPError: If the group doesn't exist on Mimecast.
        """

        body = {"data": [{"emailAddress": user_id, "id": group_id}]}
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        self.logger.debug(
            f"{self.log_prefix}: Adding user {user_id} "
            f"to group '{group_name}'."
        )
        base_url = self._get_base_url(configuration)
        request_url = f"{base_url}/{ADD_GROUP_MEMBER_ENDPOINT}"

        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                data=json.dumps(body),
                verify=self.ssl_validation,
                logger_msg=f"adding user {user_id} to group '{group_name}'",
                is_handle_error_required=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while adding {user_id} "
                    f"to group '{group_name}'."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                raise MimecastPluginException(error)
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                f"An unexpected error occurred while adding {user_id} "
                f"to group '{group_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _bulk_add_to_group(
        self,
        configuration: Dict,
        payload: List,
        group_name: str,
        action_label: str,
        skip_count: int = 0,
        revert: bool = False,
    ) -> set:
        """Add users to group.

        Args:
            configuration (Dict): Configuration parameters.
            payload (List): List of dictionaries, each dictionary
                            representing the payload for adding a user
                            to a group.
            group_name (str): Name of the group.
            action_label (str): Action label
            skip_count (int): Number of users skipped
            revert (bool): Whether this addition is reverting a
                previously executed 'Remove from Group' action.
                Defaults to False.

        Returns:
            set: Email addresses that failed at the Mimecast API
                level (e.g. an already-existing membership), so the
                caller can attribute failures back to specific
                action log entries.
        """

        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        base_url = self._get_base_url(configuration)
        request_url = f"{base_url}/{ADD_GROUP_MEMBER_ENDPOINT}"
        total_users = len(payload)
        # 'skip_count' (passed in) counts records excluded before this
        # call - invalid emails or users not found on Mimecast - and
        # is already reflected in 'total_users' not including them.
        # 'api_skip_count' tracks failures from this call's own API
        # requests, kept separate so the two are never double-counted
        # in the success total below.
        api_skip_count = 0
        failed_emails = set()
        # Unique reasons the API itself gave for skipped users across
        # all chunks (e.g. "Group member already exists"), surfaced in
        # the final summary line so it's not just a generic "an error
        # occurred" - the details/reason are already in the per-chunk
        # error log, but the summary should say why too.
        api_skip_reasons = set()
        self.logger.info(
            f"{self.log_prefix}: Adding {total_users} "
            f"user(s) to group {group_name} in batch"
            f" of {ADD_TO_GROUP_BATCH_SIZE}"
            + (
                f" while reverting the '{action_label}' action."
                if revert
                else "."
            )
        )
        batch_count = 1
        payload_chunks = [
            payload[i: i + ADD_TO_GROUP_BATCH_SIZE]
            for i in range(0, len(payload), ADD_TO_GROUP_BATCH_SIZE)
        ]
        for chunk in payload_chunks:
            body = {"data": chunk}
            try:
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    data=json.dumps(body),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"adding {len(chunk)} user(s) to group {group_name}"
                        f" for batch {batch_count}"
                    ),
                    is_handle_error_required=True,
                    configuration=configuration,
                )
            except Exception as e:
                # A chunk that fails outright (e.g. a 5xx that
                # outlives the retry budget, or a connection error)
                # must not abort chunks that already succeeded or
                # have yet to run - every item in this chunk is
                # marked failed and the loop continues.
                for item in chunk:
                    item_email = item.get("emailAddress")
                    if item_email:
                        failed_emails.add(item_email)
                api_skip_count += len(chunk)
                api_skip_reasons.add(str(e))
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to add {len(chunk)} "
                        f"user(s) to group {group_name} for batch "
                        f"{batch_count}. Error: {e} "
                        "Continuing with next batch."
                    ),
                    details=str(traceback.format_exc()),
                )
                batch_count += 1
                continue

            data = response.get("data", [])
            failures = response.get("fail", [])
            if failures:
                skip = len(chunk) - len(data)
                err_msg = (
                    f"An error occurred while adding {skip} "
                    f"user(s) for batch {batch_count} to "
                    f"group {group_name}. Hence these user(s)"
                    " records will be skipped."
                )
                error_list = self._parse_errors(failures)
                error = ", ".join(error_list)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=f"API response: {response}",
                )
                api_skip_reasons.update(error_list)
                # A failure without a per-item 'key' (e.g. a
                # content-length rejection) applies to the whole
                # request, not specific items - Mimecast never
                # attempted them individually, so every item in
                # this chunk failed, not just the keyed ones.
                if any(
                    not isinstance(f.get("key"), dict)
                    for f in failures
                ):
                    for item in chunk:
                        item_email = item.get("emailAddress")
                        if item_email:
                            failed_emails.add(item_email)
                else:
                    for failure in failures:
                        failed_key = failure.get("key", {})
                        failed_email = failed_key.get("emailAddress")
                        if failed_email:
                            failed_emails.add(failed_email)
                api_skip_count += skip
                batch_count += 1
                continue
            self.logger.info(
                f"{self.log_prefix}: Successfully added {len(chunk)}"
                f" user(s) to group {group_name} for batch {batch_count}."
            )
            batch_count += 1

        msg = (
            f"Successfully {'reverted' if revert else 'performed'} "
            f"action '{action_label}' on "
            f"{total_users - api_skip_count} user(s) out of "
            f"{total_users + skip_count} record(s)."
        )
        if skip_count > 0:
            msg += (
                f" Skipped {skip_count} user(s) as they were "
                f"not found on {PLATFORM_NAME} or had an "
                "invalid email address."
            )
        if api_skip_count > 0:
            msg += (
                f" Skipped adding {api_skip_count} user(s) to "
                f"group {group_name}."
            )
            if api_skip_reasons:
                msg += f" Reason(s): {'; '.join(api_skip_reasons)}."

        self.logger.info(f"{self.log_prefix}: {msg}")
        return failed_emails

    def _find_group_by_name(self, groups: List, name: str):
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("name") == name:
                return group
        return None

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

    def _get_all_users(self) -> List:
        """Get list of all the users.

        Returns:
            List: List of all the users.
        """
        records = []
        nextPageToken = ""
        headers = self.mimecast_helper.get_headers(
            self.configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {
            "meta": {
                "pagination": {
                    "pageSize": MAX_PAGE_SIZE,
                    "pageToken": nextPageToken,
                }
            }
        }
        base_url = self._get_base_url(self.configuration)
        request_url = f"{base_url}/{GET_SAFE_SCORE_DETAILS_ENDPOINT}"

        page_count = 1
        while True:
            try:
                response = self.mimecast_helper.api_helper(
                    url=request_url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=f"fetching user details from {PLATFORM_NAME}",
                    is_handle_error_required=True,
                    configuration=self.configuration,
                )
                failures = response.get("fail", [])
                if failures:
                    err_msg = (
                        "An error occurred while fetching "
                        f"users from {PLATFORM_NAME}."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {str(response)}",
                    )
                    raise MimecastPluginException(error)
                fetch_records = response.get("data", [])
                records += fetch_records
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(fetch_records)} users from page {page_count}."
                    f" Total users fetched: {len(records)}."
                )
                nextPage = (
                    response.get("meta", {})
                    .get("pagination", {})
                    .get("next", "")
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                    page_count += 1
                else:
                    break
            except MimecastPluginException:
                raise
            except Exception as e:
                err_msg = (
                    "An unexpected error occurred while "
                    f"fetching user details from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=str(traceback.format_exc()),
                )
                raise MimecastPluginException(err_msg)

        return records

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        return event

    def _extract_each_device_fields(
        self, event: dict, include_normalization: bool = True
    ) -> dict:
        """Extract user.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        normalized_score_skip_count = 0

        for field_name, field_value in USER_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        risk_level = event.get("risk")
        if risk_level and include_normalization:
            normalized_score = MIMECAST_SCORE_MAPPING.get(risk_level)
            netskope_risk_category = NETSKOPE_RISK_CATEGORY_MAPPING.get(
                risk_level
            )
            if not normalized_score:
                err_msg = (
                    f"{self.log_prefix}: Invalid "
                    f"Risk '{risk_level}' found in response "
                    f"for User '{event.get('emailAddress')}'. "
                    "Netskope Normalized Score will not be "
                    "calculated for this user. "
                    "Valid Risk range is A to F."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Risk : '{risk_level}'",
                )
                normalized_score_skip_count += 1

            self.add_field(
                extracted_fields, "Netskope Normalized Score", normalized_score
            )
            self.add_field(
                extracted_fields,
                "Netskope Risk Category",
                netskope_risk_category,
            )

        return extracted_fields, normalized_score_skip_count

    def is_email(self, address):
        """
        Validate email address.

        Args:
            address (str): Email address to validate.

        Returns:
            bool: True if valid else False
        """
        if not isinstance(address, str):
            return False
        return re.match(EMAIL_ADDRESS_REGEX, address) is not None

    def _get_base_url(self, configuration: Dict) -> str:
        """Get the configured API Base URL for building API requests.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            str: API Base URL, stripped of surrounding whitespace and
                any trailing slash.
        """
        return configuration.get("base_url", "").strip().rstrip("/")

    def _validate_url(self, url: str) -> bool:
        """Validate the API Base URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True if the URL has a valid scheme and network
                location, False otherwise.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_field(
        self,
        value,
        field_label: str,
        field_type: type = str,
        required: bool = True,
        extra_check: Optional[Callable[[Any], bool]] = None,
        extra_check_err: Optional[str] = None,
        context: str = "configuration parameters",
    ) -> ValidationResult:
        """Common field validation used by validate() and validate_action().

        Centralizes the "required -> type-check -> extra predicate"
        sequence so every field-level validation failure logged by the
        plugin carries a consistent, convention-following error message
        and resolution.

        Args:
            value: The value to validate.
            field_label (str): Human-readable field name used in
                messages (e.g. "Client ID").
            field_type (type): Expected python type of the value.
                Defaults to str.
            required (bool): Whether the field is mandatory. Defaults
                to True.
            extra_check (Callable, optional): Additional predicate the
                value must satisfy once the required/type checks pass
                (e.g. a valid-email or non-empty-after-strip check).
            extra_check_err (str, optional): Message fragment describing
                what the extra_check enforces. Used to compose both the
                error detail and the resolution when extra_check fails.
            context (str): Whether the field belongs to "configuration
                parameters" or "action parameters". Defaults to
                "configuration parameters".

        Returns:
            ValidationResult: success=True when the value satisfies all
                checks, else success=False with a fully formed and
                logged error message.
        """
        if required and not value:
            err_msg = (
                f"Error occurred while validating {context}. "
                f"'{field_label}' is a required field."
            )
            resolution = (
                "Ensure that a valid value is provided for the "
                f"'{field_label}' field."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if value and not isinstance(value, field_type):
            err_msg = (
                f"Error occurred while validating {context}. "
                f"'{field_label}' must be of type "
                f"{field_type.__name__}."
            )
            resolution = (
                f"Ensure that '{field_label}' is provided as a "
                f"valid {field_type.__name__}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if extra_check is not None and not extra_check(value):
            err_msg = (
                f"Error occurred while validating {context}. "
                f"'{field_label}' is invalid."
            )
            resolution = f"Ensure that {extra_check_err}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Mimecast action configuration."""
        try:
            if action.value not in ["add", "remove", "generate"]:
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "Unsupported action provided."
                )
                resolution = (
                    "Ensure that a supported action ('Add to group', "
                    "'Remove from group' or 'No action') is selected."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            if action.value == "generate":
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated "
                    f"action configuration for '{action.label}'."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )

            create_dict = json.dumps({"id": "create"})
            email = action.parameters.get("email", "")

            result = self._validate_field(
                email, "User Email", context="action parameters"
            )
            if not result.success:
                return result

            if ("$" not in email) and (
                not isinstance(email, str) or not self.is_email(email)
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "User Email must be a valid email address."
                )
                resolution = (
                    "Ensure that a valid email address is provided for "
                    "the User Email field."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            elif isinstance(email, str) and "$" in email:
                log_msg = (
                    "User Email contains the source field"
                    " hence validation for this field will be performed"
                    f" while executing the {action.label} action."
                )
                self.logger.debug(f"{self.log_prefix}: {log_msg}")

            groups = self._get_all_groups(
                self.configuration, is_validation=True
            )
            if create_dict not in action.parameters.get("group", "") and (
                "$" in action.parameters.get("group")
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "Group field contains a Source Field value."
                )
                resolution = (
                    "Ensure that Group is selected from the Static "
                    "Field dropdown only."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            group_dict = json.loads(action.parameters.get("group", ""))
            if create_dict not in action.parameters.get(
                "group", ""
            ) and not any(
                isinstance(group_dict, dict)
                and "id" in group_dict
                and g.get("id", "") == group_dict.get("id")
                for g in groups
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "Group must reference an existing group."
                )
                resolution = (
                    "Ensure that a valid Group is selected from the "
                    "available dropdown options."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            if (
                action.value == "add"
                and create_dict in action.parameters.get("group", "")
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "New Group Name cannot be empty."
                )
                resolution = (
                    "Ensure that a non-empty New Group Name is "
                    "provided when creating a new group."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            if (
                action.value == "add"
                and create_dict in action.parameters.get("group", "")
                and "$" in action.parameters.get("name", "")
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "New Group Name contains a Source Field value."
                )
                resolution = (
                    "Ensure that New Group Name is provided using the "
                    "Static Field only."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            if (
                action.value == "remove"
                and f"No groups found on {PLATFORM_NAME} platform."
                in action.parameters.get("group", "")
            ):
                err_msg = (
                    "Error occurred while validating action parameters. "
                    "No groups were found on the Mimecast platform."
                )
                resolution = (
                    "Ensure that at least one group exists on the "
                    "Mimecast platform before configuring this action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "Error occurred while validating action parameters due "
                "to an unexpected error."
            )
            resolution = (
                "Ensure that the action parameters are valid. Check "
                "logs for more details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action."""
        email_field = [
            {
                "label": "User Email",
                "key": "email",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Email ID of the user to perform the action on."
                ),
            }
        ]

        if action.value == "generate":
            return []

        groups = self._get_all_groups(self.configuration)
        groups = sorted(groups, key=lambda g: g.get("name", "").lower())
        new_group_dict = json.dumps({"id": "create"})

        if action.value == "add":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("name"),
                            "value": json.dumps(g),
                        }
                        for g in groups
                    ]
                    + [{"key": "Create New Group", "value": new_group_dict}],
                    "default": (
                        json.dumps(groups[0]) if groups else new_group_dict
                    ),
                    "mandatory": True,
                    "description": (
                        "Select an existing group from the available"
                        " options or choose 'Create New Group' to "
                        "create a new group and add users to it. "
                        "Select Group from Static field dropdown only."
                    ),
                },
                {
                    "label": "New Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "A_Cloud_Exchange",
                    "mandatory": False,
                    "description": (
                        "Create group with given name. Provide New"
                        " Group Name in Static field if you have selected"
                        " 'Create New Group' in Group."
                    ),
                },
            ]

        elif action.value == "remove":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("name"),
                            "value": json.dumps(g),
                        }
                        for g in groups
                    ],
                    "default": (
                        json.dumps(groups[0])
                        if groups
                        else f"No groups found on {PLATFORM_NAME} platform."
                    ),
                    "mandatory": True,
                    "description": (
                        "Group to remove the user from. "
                        "Select Group from Static field dropdown only."
                    ),
                }
            ]

    def execute_action(self, action: Action, revert: bool = False):
        """
        Execute action on the user.

        Args:
            action (Action): Action to be executed.
            revert (bool): If True, undo a previously executed action
                instead of performing it. Reverting 'Add to Group'
                removes the user from that group; reverting 'Remove
                from Group' adds the user back to it. Defaults to
                False.
        """
        action_label = action.label
        action_parameters = action.parameters
        user = action_parameters.get("email", "")
        self.logger.debug(
            f"{self.log_prefix}: Executing "
            f"{'revert action' if revert else 'action'} "
            f"'{action_label}' for user '{user}'."
        )
        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'reverted' if revert else 'performed'} action "
                f"'{action_label}'."
            )
            return
        elif not self.is_email(user):
            error_msg = (
                f"{PLATFORM_NAME} plugin expects "
                "the value of 'User Email' parameter to be a "
                "valid email hence skipping "
                f"{'revert of the ' if revert else ''}"
                f"execution of action '{action_label}' on '{user}'."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            raise MimecastPluginException(error_msg)

        if revert and action.value not in ("add", "remove"):
            err_msg = (
                f"Revert action is not supported for '{action.value}' "
                f"action in {PLATFORM_NAME} plugin."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NotImplementedError(err_msg)

        users = self._get_all_users()
        match = self._find_user_by_email(users, user)

        if match is None:
            self.logger.info(
                f"{self.log_prefix}: The user with email address"
                f" {user} was not found on {PLATFORM_NAME}. Hence "
                f"cannot {'revert' if revert else 'perform'} "
                f"{action_label} action."
            )
            return

        # Reverting 'Add to Group' behaves like 'Remove from Group'
        # and vice-versa; the group targeted stays the same one the
        # original action used.
        effective_value = action.value
        if revert:
            effective_value = "remove" if action.value == "add" else "add"

        if effective_value == "add":
            group_info = json.loads(action_parameters.get("group", ""))
            if not revert and group_info.get("id", "") == "create":
                group_name = action_parameters.get("name", "").strip()
                groups = self._get_all_groups(self.configuration)
                match_group = self._find_group_by_name(groups, group_name)
                if not match_group:
                    group = self._create_group(self.configuration, group_name)
                    created_group = group.get("data", [{}])[0]
                    # Mimecast's create-group response also carries
                    # source, parentId, userCount, folderCount - none
                    # of which the plugin uses; keep only id and
                    # description, matching the {id, name} shape an
                    # existing group already has.
                    group_info = {
                        "id": created_group.get("id", ""),
                        "description": created_group.get(
                            "description", ""
                        ),
                    }
                else:
                    group_info = match_group
                # Persist the resolved group so that a later revert of
                # this same action removes the user from the actual
                # created/matched group instead of the ambiguous
                # 'create' placeholder.
                action_parameters["group"] = json.dumps(group_info)

            group_name = None
            if group_info.get("description", ""):
                group_name = group_info.get("description", "")
            else:
                group_name = group_info.get("name", "")

            self._add_to_group(
                self.configuration,
                match.get("emailAddress", ""),
                group_info.get("id", ""),
                group_name,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'reverted' if revert else 'performed'} action"
                f" '{action_label}' on user with email {user}."
            )
        elif effective_value == "remove":
            group_info = json.loads(action_parameters.get("group", ""))
            if group_info.get("id", "") == "create":
                # Only reachable when reverting an 'Add to Group'
                # action whose created/matched group was never
                # resolved back into the stored parameters (e.g. an
                # action executed before this persistence fix).
                # Resolve the real group by name; never create one
                # here, since a group just created for a revert would
                # never actually contain the user being removed.
                lookup_name = action_parameters.get("name", "").strip()
                groups = self._get_all_groups(self.configuration)
                match_group = self._find_group_by_name(groups, lookup_name)
                if not match_group:
                    err_msg = (
                        f"Error occurred while reverting action "
                        f"'{action_label}'. The group '{lookup_name}' "
                        f"created for this action could not be found "
                        f"on {PLATFORM_NAME}."
                    )
                    resolution = (
                        f"Ensure that the group '{lookup_name}' still "
                        f"exists on {PLATFORM_NAME}, or manually "
                        f"remove the user from the appropriate group."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=resolution,
                    )
                    raise MimecastPluginException(err_msg)
                group_info = match_group

            group_name = None
            if group_info.get("description", ""):
                group_name = group_info.get("description", "")
            else:
                group_name = group_info.get("name", "")

            self._remove_from_group(
                self.configuration,
                match.get("emailAddress", ""),
                group_info.get("id", ""),
                group_name,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'reverted' if revert else 'performed'} action"
                f" '{action_label}' on user with email {user}."
            )

    def execute_actions(
        self, actions: List[Dict], revert: bool = False
    ) -> Optional[ActionResult]:
        """
        Execute actions in bulk.

        Args:
            actions (List[Dict]): List of {"params": Action, "id": str}
                dicts - one per action log entry - since
                self.provide_action_id is set.
            revert (bool): If True, undo the previously executed
                actions as a single batch: reverting 'Add to Group'
                bulk-removes the batch from that group, and reverting
                'Remove from Group' bulk-adds the batch back to it.
                Defaults to False.

        Returns:
            Optional[ActionResult]: None when every record succeeded
                (CE then marks the whole batch as Success), otherwise
                an ActionResult naming exactly which action log
                entries failed via failed_action_ids.

        Raises:
            NotImplementedError: If revert is True for an action
                other than 'add'/'remove', since revert is only
                supported for group membership actions.
        """
        if len(actions) == 0:
            return None

        first_action = actions[0].get("params")
        action_label = first_action.label
        action_value = first_action.value
        self.logger.debug(
            f"{self.log_prefix}: "
            f"{'Reverting' if revert else 'Executing'} '{action_label}'"
            f" action on {len(actions)} user(s)."
        )
        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'reverted' if revert else 'performed'} action "
                f"'{action_label}'."
            )
            return None

        if revert and action_value not in ("add", "remove"):
            err_msg = (
                f"Batch revert action is not supported for "
                f"'{action_value}' action in {PLATFORM_NAME} plugin."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NotImplementedError(err_msg)

        # Reverting 'Add to Group' behaves like 'Remove from Group'
        # and vice-versa, for the whole batch; the group targeted
        # stays the same one the original batch action used.
        effective_value = action_value
        if revert:
            effective_value = "remove" if action_value == "add" else "add"

        # Tracks which action log entries (by id) failed, so CE can
        # mark exactly those Failed instead of defaulting every
        # record in the batch to Success.
        failed_action_ids = []
        # A matched user's confirmed Mimecast email can map to more
        # than one action log entry (e.g. two records for the same
        # user); every entry sharing that email gets the same outcome.
        email_to_action_ids: Dict[str, List[str]] = {}

        # A single business rule/action can still carry different
        # stored 'group' values across its action log entries - e.g.
        # the action's Group field was edited after some records had
        # already executed, or (for revert) different original
        # actions targeted different groups. CE batches purely by
        # (configuration, action.value), with no awareness of the
        # per-record group, so the batch must never be assumed to
        # share one target - it's grouped here first, mirroring how
        # netskope_ztre groups a private-app batch by app_name, and
        # one bulk API call is made per distinct group.
        group_buckets: Dict[str, List[Dict]] = {}
        for action_dict in actions:
            action_parameters = action_dict.get("params").parameters
            raw_group = action_parameters.get("group", "")
            parsed_group = json.loads(raw_group) if raw_group else {}
            if not revert and parsed_group.get("id", "") == "create":
                # Records requesting 'Create New Group' with the same
                # New Group Name are grouped together so the group is
                # only created/matched once per distinct name.
                bucket_key = "create:" + action_parameters.get(
                    "name", ""
                ).strip()
            else:
                bucket_key = raw_group
            group_buckets.setdefault(bucket_key, []).append(action_dict)

        invalid_email_values = []
        users = self._get_all_users()
        groups = self._get_all_groups(self.configuration)

        if effective_value == "add":
            for bucket_actions in group_buckets.values():
                bucket_params = bucket_actions[0].get("params").parameters
                group_info = json.loads(bucket_params.get("group", ""))
                if not revert and group_info.get("id", "") == "create":
                    group_name_input = bucket_params.get(
                        "name", ""
                    ).strip()
                    match_group = self._find_group_by_name(
                        groups, group_name_input
                    )
                    if not match_group:
                        group = self._create_group(
                            self.configuration, group_name_input
                        )
                        created_group = group.get("data", [{}])[0]
                        # Mimecast's create-group response also
                        # carries source, parentId, userCount,
                        # folderCount - none of which the plugin
                        # uses; keep only id and description,
                        # matching the {id, name} shape an existing
                        # group already has.
                        group_info = {
                            "id": created_group.get("id", ""),
                            "description": created_group.get(
                                "description", ""
                            ),
                        }
                    else:
                        group_info = match_group
                    # Persist the resolved group on every action in
                    # this bucket so a later revert removes it from
                    # the actual created/matched group instead of the
                    # ambiguous 'create' placeholder.
                    for pending_action in bucket_actions:
                        pending_action.get(
                            "params"
                        ).parameters["group"] = json.dumps(group_info)

                if group_info.get("description", ""):
                    group_name = group_info.get("description", "")
                else:
                    group_name = group_info.get("name", "")

                # Per-record skip reasons are not logged individually
                # here (a batch can hold thousands of records) -
                # invalid email values are collected and logged once
                # for the whole action, across all buckets, below.
                skip_count = 0
                total_payload = []
                for action_dict in bucket_actions:
                    action_id = action_dict.get("id")
                    action_parameters = action_dict.get(
                        "params"
                    ).parameters
                    user = action_parameters.get("email", "")
                    if not self.is_email(user):
                        skip_count += 1
                        invalid_email_values.append(str(user))
                        if action_id:
                            failed_action_ids.append(action_id)
                        continue

                    match = self._find_user_by_email(users, user)
                    if match is None:
                        skip_count += 1
                        if action_id:
                            failed_action_ids.append(action_id)
                        continue

                    matched_email = match.get("emailAddress", "")
                    total_payload.append(
                        {
                            "id": group_info.get("id", ""),
                            "emailAddress": matched_email,
                        }
                    )
                    if action_id:
                        email_to_action_ids.setdefault(
                            matched_email, []
                        ).append(action_id)

                failed_emails = self._bulk_add_to_group(
                    self.configuration,
                    total_payload,
                    group_name,
                    action_label,
                    skip_count,
                    revert=revert,
                )
                for failed_email in failed_emails or set():
                    failed_action_ids.extend(
                        email_to_action_ids.get(failed_email, [])
                    )

        elif effective_value == "remove":
            for bucket_actions in group_buckets.values():
                bucket_params = bucket_actions[0].get("params").parameters
                group_info = json.loads(bucket_params.get("group", ""))
                if group_info.get("id", "") == "create":
                    # Only reachable when reverting a batch 'Add to
                    # Group' action whose created/matched group was
                    # never resolved back into the stored parameters
                    # (e.g. a batch executed before this persistence
                    # fix). Resolve the real group by name; never
                    # create one here, since a group just created for
                    # a revert would never actually contain the users
                    # being removed.
                    lookup_name = bucket_params.get("name", "").strip()
                    match_group = self._find_group_by_name(
                        groups, lookup_name
                    )
                    if not match_group:
                        err_msg = (
                            f"Error occurred while reverting action "
                            f"'{action_label}'. The group "
                            f"'{lookup_name}' created for this action "
                            f"could not be found on {PLATFORM_NAME}."
                        )
                        resolution = (
                            f"Ensure that the group '{lookup_name}' "
                            f"still exists on {PLATFORM_NAME}, or "
                            f"manually remove the affected users "
                            f"from the appropriate group."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            resolution=resolution,
                        )
                        raise MimecastPluginException(err_msg)
                    group_info = match_group

                if group_info.get("description", ""):
                    group_name = group_info.get("description", "")
                else:
                    group_name = group_info.get("name", "")

                # Per-record skip reasons are not logged individually
                # here (a batch can hold thousands of records) -
                # invalid email values are collected and logged once
                # for the whole action, across all buckets, below.
                skip_count = 0
                total_payload = []
                for action_dict in bucket_actions:
                    action_id = action_dict.get("id")
                    action_parameters = action_dict.get(
                        "params"
                    ).parameters
                    user = action_parameters.get("email", "")
                    if not self.is_email(user):
                        skip_count += 1
                        invalid_email_values.append(str(user))
                        if action_id:
                            failed_action_ids.append(action_id)
                        continue

                    match = self._find_user_by_email(users, user)
                    if match is None:
                        skip_count += 1
                        if action_id:
                            failed_action_ids.append(action_id)
                        continue

                    matched_email = match.get("emailAddress", "")
                    total_payload.append(
                        {
                            "id": group_info.get("id", ""),
                            "emailAddress": matched_email,
                        }
                    )
                    if action_id:
                        email_to_action_ids.setdefault(
                            matched_email, []
                        ).append(action_id)

                failed_emails = self._bulk_remove_from_group(
                    self.configuration,
                    total_payload,
                    group_name,
                    action_label,
                    skip_count,
                    revert=revert,
                )
                for failed_email in failed_emails or set():
                    failed_action_ids.extend(
                        email_to_action_ids.get(failed_email, [])
                    )

        if invalid_email_values:
            err_msg = (
                "Error occurred while validating action parameters. "
                f"{len(invalid_email_values)} user(s) were skipped "
                "because an invalid value was provided for the "
                "User Email field: "
                f"{', '.join(invalid_email_values)}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the User Email field is mapped "
                    "to a Source Field that provides a valid "
                    "email address for every record."
                ),
            )

        if not failed_action_ids:
            return None
        return ActionResult(
            success=True,
            message=(
                f"{'Reverted' if revert else 'Performed'} action "
                f"'{action_label}' with {len(set(failed_action_ids))} "
                f"failed record(s) out of {len(actions)}."
            ),
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _create_group(self, configuration: Dict, name: str):
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters
            name (str): Name of the group to create.

        Returns:
            Dict: Newly created group dictionary.
        """
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {"data": [{"description": name}]}
        base_url = self._get_base_url(configuration)
        request_url = f"{base_url}/{CREATE_GROUP_ENDPOINT}"
        logger_msg = f"Creating group with name {name}"
        self.logger.debug(f"{self.log_prefix}: {logger_msg}.")
        try:
            response = self.mimecast_helper.api_helper(
                url=request_url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                data=json.dumps(body),
                logger_msg=logger_msg,
                is_handle_error_required=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if failures:
                err_msg = (
                    f"An error occurred while creating group with name {name}."
                )
                error = ", ".join(self._parse_errors(failures))
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                )
                raise MimecastPluginException(error)
            return response
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An Unexpected error occurred while creating"
                f" group with name {name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _get_all_groups(
        self, configuration: Dict, is_validation=False
    ) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.
            is_validation (bool): Whether calling from validate method

        Returns:
            List: List of all the groups.
        """

        page_count = 1
        all_groups = []
        nextPageToken = ""
        headers = self.mimecast_helper.get_headers(
            configuration,
            regenerate_auth_token=True,
            proxy=self.proxy,
            verify=self.ssl_validation,
        )
        body = {
            "meta": {
                "pagination": {
                    "pageSize": MAX_PAGE_SIZE,
                    "pageToken": nextPageToken,
                }
            }
        }
        base_url = self._get_base_url(configuration)
        url = f"{base_url}/{FIND_GROUPS_ENDPOINT}"
        try:
            while True:
                per_page_fetched_count = 0
                groups_fetched_per_page = []
                groups = self.mimecast_helper.api_helper(
                    url=url,
                    method="POST",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    data=json.dumps(body),
                    logger_msg=f"fetching all groups from {PLATFORM_NAME}",
                    is_handle_error_required=True,
                    is_validation=is_validation,
                    configuration=configuration,
                )

                failures = groups.get("fail", [])
                if failures:
                    err_msg = (
                        "An error occurred while fetching "
                        f"groups from {PLATFORM_NAME}."
                    )
                    error = ", ".join(self._parse_errors(failures))
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=f"API response: {str(groups)}",
                    )
                    raise MimecastPluginException(error)

                groups_fetched_per_page = [
                    {"id": group.get("id"), "name": group.get("description")}
                    for group in groups.get("data", [{}])[0].get("folders", [])
                    if group.get("id") and group.get("description")
                ]
                all_groups += groups_fetched_per_page
                per_page_fetched_count = len(groups_fetched_per_page)
                nextPage = (
                    groups.get("meta", {})
                    .get("pagination", {})
                    .get("next", "")
                )
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{per_page_fetched_count} groups from "
                    f"{PLATFORM_NAME} for page {page_count}."
                )
                if nextPage:
                    body["meta"]["pagination"]["pageToken"] = nextPage
                    page_count += 1
                else:
                    break

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(all_groups)}"
                f" groups from {PLATFORM_NAME}."
            )
            return all_groups
        except MimecastPluginException:
            raise
        except Exception as e:
            err_msg = (
                "An unexpected error occurred while "
                "retrieving existing group details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def fetch_records(self, entity: str) -> List:
        """Fetch records from Mimecast.

        Args:
            entity (str): Entity name.

        Returns:
            List: List of records to be stored on the platform.
        """
        total_records = []
        skip_count = 0
        entity_name = entity.lower()

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )
        try:
            fetched_records = self._get_all_users()
            if fetched_records:
                for record in fetched_records:
                    try:
                        extracted_fields, _ = self._extract_each_device_fields(
                            record,
                            include_normalization=False,
                        )
                        if extracted_fields:
                            total_records.append(extracted_fields)
                        else:
                            skip_count += 1
                    except MimecastPluginException:
                        skip_count += 1
                    except Exception as err:
                        email_address = record.get("emailAddress")
                        err_msg = (
                            "Unable to extract fields from user"
                            f' having Email Address "{email_address}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching "
                f"{entity_name} from {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} {entity_name}"
                f" because they might not contain Email Address"
                " in their response or fields could "
                "not be extracted from them."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {len(total_records)} {entity_name} "
            f"from {PLATFORM_NAME} platform."
        )
        return total_records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = []
        entity_name = entity.lower()
        total_normalized_score_skip_count = 0
        skip_count = 0

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" records from {PLATFORM_NAME}."
        )
        user_list = set()
        for record in records:
            user_email = record.get("User Email")
            if user_email:
                user_list.add(user_email)

        log_msg = (
            f"{len(user_list)} user record(s) will be updated out"
            f" of {len(records)} records."
        )
        if len(records) - len(user_list) > 0:
            log_msg += (
                f" Skipped {len(records) - len(user_list)} user(s) as they"
                " do not have User Email field in them."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")

        try:
            fetched_records = self._get_all_users()
            if fetched_records:
                for record in fetched_records:
                    try:
                        if record.get("emailAddress"):
                            (extracted_fields, normalized_score_skip_count) = (
                                self._extract_each_device_fields(
                                    record,
                                    include_normalization=True,
                                )
                            )
                            if extracted_fields:
                                current_email = extracted_fields.get(
                                    "User Email", ""
                                )
                                if current_email in user_list:
                                    updated_records.append(extracted_fields)
                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1

                            total_normalized_score_skip_count += (
                                normalized_score_skip_count
                            )
                        else:
                            skip_count += 1
                    except MimecastPluginException:
                        skip_count += 1
                    except Exception as err:
                        email_address = record.get("emailAddress")
                        err_msg = (
                            "Unable to extract fields from user"
                            f' having Email Address "{email_address}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred "
                f"while updating {entity_name} "
                f"from {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} {entity_name}"
                f" because they might not contain Email Address"
                " in their response or fields could "
                "not be extracted from them."
            )

        if total_normalized_score_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating "
                "Netskope Normalized Score for "
                f"{total_normalized_score_skip_count} {entity_name}"
                " record(s) as invalid Risk value received from the "
                f"{PLATFORM_NAME} platform."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{len(updated_records)} {entity_name} record(s)"
            f" out of {len(records)} from {PLATFORM_NAME}."
        )

        return updated_records

    def get_actions(self) -> list[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def _validate_auth_params(self, configuration: dict):
        """Validate the authentication params with Mimecast platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            headers = self.mimecast_helper.get_headers(
                configuration,
                is_handle_error_required=True,
                is_validation=True,
                proxy=self.proxy,
                verify=self.ssl_validation,
            )
            base_url = self._get_base_url(configuration)
            url = f"{base_url}/{GET_ACCOUNT_DETAILS_ENDPOINT}"

            response = self.mimecast_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"checking connectivity with {PLATFORM_NAME} platform"
                ),
                is_handle_error_required=True,
                regenerate_auth_token=False,
                is_validation=True,
                configuration=configuration,
            )
            failures = response.get("fail", [])
            if not failures:
                msg = (
                    f"Validation successful for {MODULE_NAME} "
                    f"{PLATFORM_NAME} plugin."
                )
                self.logger.debug(f"{self.log_prefix}: {msg}")
                packages = response.get("data", [{}])[0].get("packages", [])

                if ENGAGE_CORE_PACKAGE not in packages:
                    err_msg = (
                        "Error occurred while validating account "
                        "entitlements. 'Engage Core' package is not "
                        "enabled for the configured Mimecast account."
                    )
                    resolution = (
                        "Ensure that the 'Engage Core' package is "
                        "enabled for the configured Mimecast account "
                        "and that the API credentials belong to an "
                        "account with access to Engage > Reporting "
                        "and Insights. If the credentials lack the "
                        "required permissions, verify the API user's "
                        "role under Account > Admin Role."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=resolution,
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                return ValidationResult(
                    success=True,
                    message=msg,
                )
            err_msg = (
                "Error occurred while validating configuration "
                "parameters."
            )
            return ValidationResult(
                success=False,
                message="{}: {} Error: {}".format(
                    self.log_prefix,
                    err_msg,
                    ", ".join(self._parse_errors(failures)),
                ),
            )
        except MimecastPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )

        except Exception as exp:
            err_msg = (
                "Error occurred while validating configuration "
                "parameters due to an unexpected error."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: Dict):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """

        # Validate API Base URL.
        base_url = configuration.get("base_url", "")
        if isinstance(base_url, str):
            base_url = base_url.strip().rstrip("/")
        result = self._validate_field(
            base_url,
            "API Base URL",
            extra_check=self._validate_url,
            extra_check_err=(
                "a valid API Base URL is provided (e.g. "
                "https://api.services.mimecast.com)"
            ),
        )
        if not result.success:
            return result

        # Validate Client ID.
        result = self._validate_field(
            configuration.get("client_id", ""), "Client ID"
        )
        if not result.success:
            return result

        # Validate Client Secret. Do not strip password-type fields.
        result = self._validate_field(
            configuration.get("client_secret", ""), "Client Secret"
        )
        if not result.success:
            return result

        return self._validate_auth_params(configuration)

    def get_entities(self) -> list[Entity]:
        """
        Get available entities.

        returns:
            List: List of available entities
        """
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User Email",
                        type=EntityFieldType.STRING,
                        description=(
                            "Email address of the user fetched from "
                            "Engage > Reporting and Insights > Risk "
                            "Center on the Mimecast platform."
                        ),
                        required=True,
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                        description="Name of the Mimecast user.",
                    ),
                    EntityField(
                        name="User Risk",
                        type=EntityFieldType.STRING,
                        description=(
                            "Raw risk grade (e.g. A, B, C, D, F) reported "
                            "for the user by Mimecast Engage > Reporting "
                            "and Insights > Risk Center."
                        ),
                    ),
                    EntityField(
                        name="Netskope Risk Category",
                        type=EntityFieldType.STRING,
                        description=(
                            "Risk category derived from the Mimecast "
                            "user risk grade."
                        ),
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                        description=(
                            "Mimecast user risk grade normalized to the "
                            "Netskope 1-1000 score range (1=most risky, "
                            "1000=least risky)."
                        ),
                    ),
                ],
            )
        ]
