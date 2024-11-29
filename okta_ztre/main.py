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

Okta CRE plugin.
"""

import uuid
import jwt
import traceback
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import re
from urllib.parse import urlparse, parse_qs

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    EVENTS_PROVIDER,
    PLUGIN_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    PAGE_LIMIT_APP,
    INTEGER_THRESHOLD,
    OKTA_DATE_FORMAT,
    USERS_ENTITY,
    APPLICATIONS_ENTITY,
    USERS_FIELD_MAPPING,
    NORMALIZATION_MAPPING,
    APPLICATION_FIELD_MAPPING,
)

from .utils.helper import (
    OktaPluginHelper,
    OktaPluginException,
    OktaRiskLevelException,
)


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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.okta_helper = OktaPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

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

    def fetch_records(self, entity: Entity) -> list:
        """Pull Records from Okta.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        checkpoint = self.last_run_at
        if not checkpoint:
            initial_range = int(self.configuration.get("days", 7))
            checkpoint = datetime.now() - timedelta(days=initial_range)

        checkpoint = checkpoint.strftime(OKTA_DATE_FORMAT)

        records = []

        base_url = self.configuration.get("url", "").strip().rstrip("/")
        token = self.configuration.get("api_token", "")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {token}",
        }

        try:
            if entity == USERS_ENTITY:
                records.extend(
                    self._fetch_users(checkpoint, base_url, headers)
                )
            elif entity == APPLICATIONS_ENTITY:
                records.extend(self._fetch_applications(base_url, headers))
            else:
                err_msg = (
                    f"Invalid entity found {PLATFORM_NAME} only supports "
                    f"{USERS_ENTITY} and {APPLICATIONS_ENTITY} Entities."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise OktaPluginException(err_msg)
            return records
        except OktaPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise OktaPluginException(err_msg)

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

    def _extract_user_fields(self, entity, user):
        """Extract IOA fields.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        mapping = USERS_FIELD_MAPPING
        if entity == APPLICATIONS_ENTITY:
            mapping = APPLICATION_FIELD_MAPPING
        for field_name, field_value in mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, user, default, transformation
                ),
            )
        return extracted_fields

    def fetch_risk_level(self, headers, base_url, user_id, user_email):
        """Fetch risk level.

        Args:
            user_id (str): User ID.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            str: Risk level.

        """
        url = f"{base_url}/api/v1/users/{user_id}/risk"
        logger_msg = f"fetching risk level for user {user_email}"
        try:
            risk_level_resp = self.okta_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
            )
            risk_level = risk_level_resp.get("riskLevel", "NONE")
            normalized_score = NORMALIZATION_MAPPING.get(risk_level, "NONE")
            return risk_level, normalized_score

        except OktaPluginException as err:
            raise OktaRiskLevelException(str(err))
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching risk level "
                f" of User '{user_email}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"{err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise OktaRiskLevelException(err_msg)

    def _fetch_users(self, checkpoint, base_url, headers):
        """
        Fetch users from Okta.

        Args:
            checkpoint (str): Last update time of user.
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.

        Returns:
            List[dict]: List of extracted user fields.
        """
        try:
            url_endpoint = f"{base_url}/api/v1/users"
            after = ""
            final_users_list = []
            params = {
                "limit": PAGE_LIMIT_APP,
                "search": f'lastUpdated gt "{checkpoint}"',
                "sortBy": "lastUpdated",
            }
            page = 1
            total_count = 0
            skip_count = 0

            while True:
                current_page_count = 0
                logger_msg = f"fetching users for page {page}"
                resp = self.okta_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url_endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                json_resp = self.okta_helper.handle_error(resp, logger_msg)
                for user in json_resp:
                    try:
                        extracted_fields = self._extract_user_fields(
                            entity=USERS_ENTITY, user=user
                        )
                        if extracted_fields:
                            final_users_list.append(extracted_fields)
                            current_page_count += 1
                        else:
                            skip_count += 1
                    except Exception as exp:
                        user_id = user.get("id")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having User ID "{user_id}" from page {page}.'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {user}",
                        )
                        skip_count += 1
                total_count += current_page_count
                links = re.findall(
                    r"(https?://\S+)", resp.headers.get("link", "")
                )
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
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Successfully fetched {current_page_count} "
                    f"user(s) from page {page}. "
                    f"Total users fetched: {total_count}."
                )
                if not flag:
                    break
                page += 1

            log_msg = (
                f"{self.log_prefix}: "
                f"Completed fetching user(s) "
                f"from {PLATFORM_NAME} platform. "
                f"Total users fetched: {total_count}."
            )
            if skip_count:
                log_msg += (
                    f" Skipped {skip_count} user(s) as "
                    " some error occurred while extracting the fields or"
                    " there or the expected fields were empty."
                )
            self.logger.info(log_msg)
            return final_users_list
        except OktaPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling users "
                f"from page {page} from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise OktaPluginException(err_msg)

    def _fetch_applications(self, base_url, headers):
        """
        Fetch applications from Okta.

        Args:
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.

        Returns:
            List[dict]: List of extracted application fields.
        """
        try:
            final_app_list = []
            url_endpoint = f"{base_url}/api/v1/apps"
            after = ""
            final_app_list = []
            params = {"limit": 10}
            page = 1
            total_count = 0
            skip_count = 0
            while True:
                current_page_count = 0
                logger_msg = f"fetching applications for page {page}"
                resp = self.okta_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url_endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                json_resp = self.okta_helper.handle_error(resp, logger_msg)

                for app in json_resp:
                    try:
                        extracted_fields = self._extract_user_fields(
                            entity=APPLICATIONS_ENTITY, user=app
                        )
                        if extracted_fields:
                            final_app_list.append(extracted_fields)
                            current_page_count += 1
                        else:
                            skip_count += 1
                    except Exception as exp:
                        app_id = app.get("id")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having User ID "{app_id}" from page {page}.'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {app}",
                        )
                        skip_count += 1
                total_count += current_page_count
                links = re.findall(
                    r"(https?://\S+)", resp.headers.get("link", "")
                )
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
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Successfully fetched {current_page_count} "
                    f"application(s) from page {page}. "
                    f"Total applications fetched: {total_count}."
                )
                if not flag:
                    break
                page += 1

            self.logger.info(
                f"{self.log_prefix}: "
                f"Completed fetching application "
                f"from {PLATFORM_NAME} platform. "
                f"Total applications fetched: {total_count}."
            )
            return final_app_list
        except OktaPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred "
                f"while fetching applications of page {page} "
                f"from {PLATFORM_NAME} "
                f"platform."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} "
                    f"Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise OktaPluginException(err_msg)

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

    def update_records(
        self,
        entity: str,
        records: list[dict]
    ) -> list[dict]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        updated_records = {}
        self.logger.info(
            f"{self.log_prefix}: Updating {entity.lower()}"
            f" records from {PLATFORM_NAME}."
        )
        base_url = self.configuration.get("url", "").strip().rstrip("/")
        token = self.configuration.get("api_token", "")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {token}",
        }

        if entity == USERS_ENTITY:
            user_ids = []

            for record in records:
                if record.get("User ID"):
                    user_ids.append(record.get("User ID"))
            skipped_records = len(records) - len(user_ids)
            log_msg = (
                f"{len(user_ids)} user record(s) will "
                "be updated."
            )
            if skipped_records:
                log_msg += (
                    f" {skipped_records} "
                    "record(s) will be skipped "
                    "as they do not have 'User ID' field in it."
                )
            self.logger.info(
                f"{self.log_prefix}: "
                f"{log_msg}"
            )
            updated_records = self.update_users(
                user_ids,
                base_url,
                headers,
            )

        elif entity == APPLICATIONS_ENTITY:
            record_id_list = {record["ID"]: record for record in records}
            self.logger.info(
                f"{self.log_prefix}: {len(record_id_list)} application "
                "record(s) will be updated and "
                f"{len(records) - len(record_id_list)} records will be "
                "skipped as they do not have 'ID' field in it."
            )
            updated_records = self.update_applications(
                base_url, headers, record_id_list
            )
        return updated_records

    def update_applications(self, base_url, headers, record_id_list):
        """
        Fetch and update applications scores.

        Args:
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.
            record_id_list (dict): Dictionary of record IDs and their \
                corresponding records.

        Returns:
            List[dict]: List of updated application records.
        """
        try:
            url_endpoint = f"{base_url}/api/v1/apps"
            params = {"limit": PAGE_LIMIT_APP}
            page = 1
            total_count, app_count = 0, 0
            after = ""
            final_updated_list = []
            unmatched_count, skip_count = 0, 0
            while True:
                current_page_count = 0
                logger_msg = (
                    "fetching applications to check for updates "
                    f"for page {page}"
                )
                resp = self.okta_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url_endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                json_resp = self.okta_helper.handle_error(resp, logger_msg)
                for each_user in json_resp:
                    try:
                        current_id = each_user.get("id", "")
                        if current_id in record_id_list:
                            extracted_fields = self._extract_user_fields(
                                entity=APPLICATIONS_ENTITY, user=each_user
                            )
                            if extracted_fields:
                                final_updated_list.append(extracted_fields)
                            else:
                                skip_count += 1
                            app_count += 1
                        else:
                            unmatched_count += 1
                    except OktaRiskLevelException:
                        skip_count += 1
                    except Exception as exp:
                        current_id = each_user.get("id", "")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having User ID "{current_id}" for page {page}.'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {current_id}",
                        )
                        skip_count += 1

                current_page_count = len(json_resp)
                total_count += current_page_count
                links = re.findall(
                    r"(https?://\S+)", resp.headers.get("link", "")
                )
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
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{current_page_count} applications for checking "
                    f"for updates in page {page}."
                    f" Total {app_count} applications(s) updated from "
                    "the available applications."
                )
                if not flag:
                    break
                page += 1
            log_msg = (
                f"{self.log_prefix}: "
                f"Completed updating application(s) "
                f"from {PLATFORM_NAME} platform. "
                f"Total applications fetched: {total_count}."
            )
            if skip_count:
                log_msg += (
                    f" Skipped {skip_count} application(s) as "
                    " some error occurred while extracting the fields or"
                    " there or the expected fields were empty."
                )
            if unmatched_count:
                log_msg += (
                    f" Skipped {unmatched_count} application(s) as "
                    " they were not found on the platform."
                )
            self.logger.info(log_msg)
            return final_updated_list
        except OktaPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred "
                f"while updating applications "
                f"of page {page} from {PLATFORM_NAME} "
                f"platform."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f"Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise OktaPluginException(err_msg)

    def update_users(self, user_ids, base_url, headers):
        """
        Fetch and update users scores.

        Args:
            user_ids (list): List of user IDs.
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.

        Returns:
            List[dict]: List of updated user records.

        Raises:
            OktaPluginException: If there is an unexpected error while fetching
                users or fetching risk level.
        """

        try:
            skip_risk = 0
            url_endpoint = f"{base_url}/api/v1/users"
            after = ""
            final_users_list = []
            params = {
                "limit": PAGE_LIMIT_APP
            }
            page = 1
            total_count = 0
            skip_count = 0
            unmatched_count = 0
            total_actual_fetched = 0

            while True:
                actual_fetched = 0
                logger_msg = (
                    f"fetching users to check for updates for page {page}"
                )
                resp = self.okta_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url_endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                json_resp = self.okta_helper.handle_error(resp, logger_msg)
                for user in json_resp:
                    try:
                        actual_fetched += 1
                        user_id = user.get("id", "")
                        if user_id in user_ids:
                            extracted_fields = self._extract_user_fields(
                                entity=USERS_ENTITY, user=user
                            )
                            primary_email = extracted_fields.get(
                                "Primary Email"
                            )
                            (
                                extracted_fields["Risk Level"],
                                extracted_fields["Netskope Normalized Score"],
                            ) = self.fetch_risk_level(
                                headers, base_url, user_id, primary_email
                            )
                            if extracted_fields:
                                final_users_list.append(extracted_fields)
                                total_count += 1
                            else:
                                skip_count += 1
                        else:
                            unmatched_count += 1
                    except OktaRiskLevelException:
                        skip_risk += 1
                    except Exception as exp:
                        user_id = user.get("id")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having User ID "{user_id}" for page {page}.'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"User: {user}",
                        )
                        skip_count += 1
                total_actual_fetched += actual_fetched
                links = re.findall(
                    r"(https?://\S+)", resp.headers.get("link", "")
                )
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
                self.logger.info(
                    f"{self.log_prefix} : "
                    f"Successfully fetched {actual_fetched} "
                    f"user(s) from page {page}. "
                    f"Total users fetched: {total_actual_fetched}."
                )
                if not flag:
                    break
                page += 1

            log_msg = (
                f"{self.log_prefix}: "
                f"Completed updating users "
                f"from {PLATFORM_NAME} platform. "
                f"{total_count} user(s) updated successfully."
            )
            if unmatched_count:
                log_msg += (
                    f" {unmatched_count} user(s) "
                    "not updated since matching records not found in CE."
                )
            if skip_count:
                log_msg += (
                    f" Skipped {skip_count} user(s) as "
                    "some error occurred while extracting the fields or "
                    "or the required fields were empty."
                )
            if skip_risk:
                log_msg += (
                    f" Skipped fetching risk level for {skip_risk} user(s) as "
                    "some error occurred while fetching risk level."
                )
            self.logger.info(log_msg)
            return final_users_list
        except OktaPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while "
                f"pulling users of page {page} from "
                f"{PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise OktaPluginException(err_msg)

    def get_entities(self) -> list[Entity]:
        """
        Returns a list of entities that this plugin can work with.

        This plugin can fetch users and applications from Okta and update user
        risk scores in Okta. The entities and their fields are as follows:

        - Users:
            - User ID (string, required)
            - Primary Email (string, required)
            - Login Username (email) (string, required)
            - Second Email (string)
            - First Name (string)
            - Last Name (string)
            - Risk Level (string)
            - Status (string)
            - Netskope Normalized Score (number)
        - Applications:
            - ID (string, required)
            - Name (string)
            - Label (string)
            - Status (string)
            - SignOnMode (string)
        """
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Primary Email",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),  # email
                    EntityField(
                        name="Login Username (email)",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),  # login
                    EntityField(
                        name="Second Email", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="First Name", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Last Name", type=EntityFieldType.STRING),
                    EntityField(
                        name="Risk Level", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Status", type=EntityFieldType.STRING),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(
                        name="ID", type=EntityFieldType.STRING, required=True
                    ),
                    EntityField(name="Name", type=EntityFieldType.STRING),
                    EntityField(name="Label", type=EntityFieldType.STRING),
                    EntityField(name="Status", type=EntityFieldType.STRING),
                    EntityField(
                        name="SignOnMode", type=EntityFieldType.STRING
                    ),
                ],
            ),
        ]

    def _add_to_group(
        self,
        configuration: dict,
        headers: dict,
        user_id: str,
        group_id: str,
        user: str,
    ):
        """Add specified user to the specified group.

        Args:
            configuration (dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Okta.
        """
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}"
            f"/api/v1/groups/{group_id}/users/{user_id}"
        )
        logger_msg = f"Adding user '{user}' to the selected group."
        response = self.okta_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="PUT",
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=False,
        )
        if response.status_code == 204:
            self.logger.info(
                f"{self.log_prefix}: Successfully added user '{user}' "
                "to the selected group."
            )
            return
        elif response.status_code == 404:
            err_msg = (
                f"Group with id '{group_id}' "
                f"does not exist on {PLATFORM_NAME}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}", details=response.text
            )
            raise OktaPluginException(err_msg)
        else:
            self.okta_helper.handle_error(response, logger_msg=logger_msg)

    def _remove_from_group(
        self,
        configuration: dict,
        headers: dict,
        user_id: str,
        group_id: str,
        user: str,
    ):
        """Remove specified user from the specified group.

        Args:
            configuration (dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on Okta.
        """
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}"
            f"/api/v1/groups/{group_id}/users/{user_id}"
        )
        logger_msg = f"Removing user '{user}' from group"
        response = self.okta_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="DELETE",
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=False,
        )
        if response.status_code == 204:
            return
        elif response.status_code == 404:
            err_msg = (
                f"Group with id '{group_id}' "
                f"does not exist on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=response.text
            )
            raise OktaPluginException(err_msg)
        else:
            self.okta_helper.handle_error(response, logger_msg)

    def _upsert_risk_score(
        self, headers, configuration: dict, user_id, risk_level, username
    ):
        """Upsert risk score for a user.

        Args:
            headers (dict): Request headers.
            configuration (dict): Configuration parameters.
            user_id (str): User ID of the user.
            risk_level (str): Risk level to be updated.
            username (str): Username of the user.

        Raises:
            HTTPError: If the user does not exist on Okta.
        """
        """"""
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}"
            f"/api/v1/users/{user_id}/risk"
        )
        json_body = {"riskLevel": risk_level}
        logger_msg = (
            f"updating the risk level to {risk_level} "
            f"for the user '{username}'"
        )
        self.okta_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="PUT",
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            json=json_body,
            is_handle_error_required=True,
        )

    def _get_all_groups(
        self,
        base_url: str,
        headers: dict,
        is_validation=False
    ) -> list:
        """Get list of all the groups.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        params = {}
        url = (
            f"{base_url}/api/v1/groups"
        )
        params["limit"] = 200
        params["filter"] = 'type eq "OKTA_GROUP"'
        after = ""
        logger_msg = "fetching all groups"
        page = 1
        current_page_count = 0
        total_count = 0
        while True:
            groups = self.okta_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                is_validation=is_validation,
            )
            all_groups += self.okta_helper.parse_response(
                groups, logger_msg, is_validation
            )
            current_page_count += len(all_groups)
            total_count += current_page_count
            links = re.findall(
                r"(https?://\S+)", groups.headers.get("link", "")
            )
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
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully fetched {current_page_count} group(s) "
                f"from page {page}. "
                f"Total Groups fetched so far: {total_count}."
            )
            if not flag:
                break
            page += 1
        return all_groups

    def _get_all_users(self, configuration: dict) -> list:
        """Get list of all the users.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            List: List of all the users.
        """
        try: 
            all_users = []
            params = {}
            url = (
                f"{configuration.get('url', '').strip().rstrip('/')}/api/v1/users" # noqa
            )
            params["limit"] = 200
            after = ""
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "okta-response": "omitCredentials, omitCredentialsLinks, omitTransitioningToStatus",  # noqa
                "Authorization": f"SSWS {configuration.get('api_token')}",
            }
            page = 1
            current_page_count = 0
            total_count = 0
            while True:
                logger_msg = f"fetching users from page {page}"
                users = self.okta_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                all_users += self.okta_helper.parse_response(users, logger_msg)
                current_page_count += len(all_users)
                total_count += current_page_count
                links = re.findall(
                    r"(https?://\S+)", users.headers.get("link", "")
                )
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
                self.logger.debug(
                    f"{self.log_prefix}: "
                    f"Successfully fetched {current_page_count} user(s) "
                    f"from page {page}. Total users fetched: {total_count}."
                )
                if not flag:
                    break
                page += 1
            self.logger.info(
                f"{self.log_prefix}: "
                f"Total {total_count} user(s) fetched "
                f"from {PLATFORM_NAME}."
            )
            return all_users
        except OktaPluginException:
            raise
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while "
                f"fetching users from page {page}."
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"{error_msg} Error: {err}"
            )
            raise OktaPluginException(error_msg)

    def _find_user_by_email(self, users: list, email: str):
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries.
            email (str): Email to find.

        Returns:
            dict: User dictionary if found, None otherwise.
        """
        for user in users:
            if (
                user.get("profile", {}).get("email", "") == email
                or user.get("profile", {}).get("login", "") == email
            ):
                return user
        return None

    def _find_group_by_name(self, groups: list, name: str):
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            dict: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("profile", {}).get("name", "") == name:
                return group
        return None

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(
                label="Upsert User Risk", value="upsert_risk_score"
            ),
            ActionWithoutParams(
                label="Push risk score (using Security Events Provider)",
                value="push_risk_score"
            ),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_kid_from_jwks_url(self, base_url):
        """
        Get Key ID from public key URL.

        Args:
            base_url (str): Public key URL.

        Returns:
            str: Key ID if found, None otherwise.

        Raises:
            OktaPluginException: If there is an unexpected error or if the
                Public Key is invalid.
        """
        try:
            json_resp = self.okta_helper.api_helper(
                logger_msg="fetching Key ID from public key",
                url=base_url,
                method="GET",
                headers={},
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            keys = json_resp.get("keys", [])
            if keys and keys[0].get("kid", ""):
                return keys[0].get("kid", "")
            else:
                err_msg = (
                    "Invalid Public Key found on JWKS URL. "
                    "Check the format for Public Key and make sure "
                    "that the Public key contains 'kid'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise OktaPluginException(err_msg)
        except OktaPluginException:
            raise
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while extracting KID from "
                "Publicly hosted URL."
                "Make sure that the JWS URL is reachable and "
                "the format of the Public Key is valid."
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"{error_msg} Error: {err}"
            )
            raise OktaPluginException(error_msg)

    def generate_set_token(
        self,
        issuer_url,
        private_key,
        base_url,
        kid,
        user,
        current_score,
        historical_score,
        reason_admin,
    ):
        """
        Generate a SET Token for the given user, current_score,
            historical_score, and reason_admin.

        Args:
            issuer_url (str): The URL of the issuer.
            private_key (str): The private key to use for signing the token.
            base_url (str): The base URL of the Okta tenant.
            kid (str): The KID of the private key.
            user (str): The email address of the user.
            current_score (int): The current risk score.
            historical_score (int): The previous risk score.
            reason_admin (str): The reason for the risk score change.

        Returns:
            str: The generated SET Token.
        """
        try:
            header = {"kid": kid, "alg": "RS256", "typ": "secevent+jwt"}
            event = {
                "iss": issuer_url,
                "jti": uuid.uuid1().hex,
                "iat": datetime.now(),
                "aud": base_url,
                "events": {
                    "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {  # noqa
                        "subject": {
                            "user": {
                                "format": "email",
                                "email": user,
                            }
                        },
                        "current_level": current_score,  # Current Score
                        "previous_level": historical_score,  # Previous Score
                        "event_timestamp": datetime.now().timestamp(),
                        "reason_admin": {"en": reason_admin},
                    }
                },
            }

            set_token = jwt.encode(
                event,
                key=private_key,
                headers=header,
            )
            return set_token
        except OktaPluginException:
            raise
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while "
                "generating SET Token."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"{error_msg} Error: {err}"
                ),
                details=traceback.format_exc(),

            )
            raise OktaPluginException(error_msg)

    def push_event_to_okta(self, base_url, set_token):
        """
        Push risk score event to Okta.

        Args:
            base_url (str): Okta base URL.
            set_token (str): SET Token containing risk score event.

        Raises:
            OktaPluginException: If there is an unexpected error while pushing
                the event to Okta.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/secevent+jwt",
        }
        try:
            push_endpoint = f"{base_url}/security/api/v1/security-events"
            logger_msg = "Pushing event to Okta"
            resp = self.okta_helper.api_helper(
                logger_msg=logger_msg,
                url=push_endpoint,
                method="POST",
                json=set_token,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
            )
            if resp.status_code not in [200, 202]:
                self.okta_helper.handle_error(resp, logger_msg)
        except OktaPluginException:
            raise
        except Exception as err:
            error_message = (
                f"Unexpected error occurred while pushing risk score "
                f"to {PLATFORM_NAME} user."
            )
            self.logger.erorr(
                message=(
                    f"{self.log_prefix}: {error_message}"
                    f"Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise OktaPluginException(error_message)

    def _create_group(
        self, configuration: dict, headers: dict, name: str
    ) -> dict:
        """Create a new group with name.

        Args:
            configuration (dict): Configuration parameters.
            name (str): Name of the group to create.
            description (str): Group decription.

        Returns:
            dict: Newly created group dictionary.
        """
        body = {
            "profile": {
                "name": name,
                "description": "Created From Netskope URE",
            }
        }
        url = (
            f"{configuration.get('url', '').strip().rstrip('/')}/api/v1/groups"
        )
        response = self.okta_helper.api_helper(
            logger_msg=f"creating group with name '{name}'",
            url=url,
            method="POST",
            headers=headers,
            json=body,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=True,
        )
        return response

    def is_email(self, address):
        # Simple email regex pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, address) is not None

    def check_last_values_condition(self, items):
        # Define the set of allowed values
        """
        Check if the last two items in a list match the allowed values.
        Args:
            items (list): List of items to check.
        Returns:
            bool: True if the last two items are valid, False otherwise.
        """
        allowed_values = {"low", "medium", "high"}

        # Check if the list is empty
        if not items:
            return True  # Return True for an empty list

        # Slice the last up to two items
        last_items = items[-2:]

        # Check if at least one of these last items does not meet the criteria
        invalid_items = [
            item
            for item in last_items
            if not (isinstance(item, str) and item in allowed_values)
        ]

        # If there's at least one invalid item, return False, else True
        return False if invalid_items else True

    def execute_action(self, action: Action):
        """
        Execute action on the user.

        Args:
            action (Action): Action to be executed.

        Raises:
            OktaPluginException: If the action fails to execute.
        """

        action_value = action.value
        action_label = action.label
        action_parameters = action.parameters
        scores = action_parameters.get("scores")
        user = action_parameters.get("email", "")  # record.uid
        risk_level = action_parameters.get("risk_level", "LOW")
        self.logger.debug(
            f"{self.log_prefix}: Executing action "
            f"'{action_label}' for user '{user}'."
        )
        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: Successfully executed "
                f"action - '{action_label}'."
            )
            return
        elif not self.is_email(user):
            error_msg = (
                f"{PLATFORM_NAME} plugin expects "
                "the value of 'User Email' parameter to be a "
                "valid email hence skipping "
                f"execution of action {action_label} on '{user}'."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            raise OktaPluginException(error_msg)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f'SSWS {self.configuration.get("api_token")}',
        }
        base_url = self.configuration.get("url", "").strip().rstrip("/")

        users = self._get_all_users(self.configuration)
        match = self._find_user_by_email(users, user)
        match_id = match.get("id", "")
        if match is None:
            self.logger.info(
                f"{self.log_prefix}: User '{user}' not "
                f"found on {PLATFORM_NAME}. "
                f"'{action_label}' action will not be performed."
            )
            return
        if action_value == "add":
            group_id = action_parameters.get("group", "")
            if group_id == "create":
                # Get ids of the group
                groups = self._get_all_groups(
                    base_url,
                    headers
                )
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched all "
                    "the available groups on "
                    f"{PLATFORM_NAME} in order to match the selected group."
                )
                group_name = action_parameters.get("name", "").strip()
                match_group = self._find_group_by_name(groups, group_name)
                if match_group is None:  # create group
                    group = self._create_group(
                        self.configuration, headers, group_name
                    )
                    group_id = group.get("id", "")
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created group "
                        f"with name: '{group_name}' on {PLATFORM_NAME}."
                    )
                else:
                    self.logger.info(
                        f"{self.log_prefix}: Group with name: {group_name} "
                        f"already exists, user '{user}' will be added in "
                        "the existing group."
                    )
                    group_id = match_group.get("id", "")
            self._add_to_group(
                self.configuration, headers, match_id, group_id, user
            )
        elif action_value == "remove":
            self._remove_from_group(
                self.configuration,
                headers,
                match_id,
                action_parameters.get("group", ""),
                user,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully removed '{user}' "
                f"from group with ID {action_parameters.get('group', '')}."
            )
        elif action_value == "upsert_risk_score":
            if risk_level not in ["LOW", "HIGH"]:
                error_msg = (
                    "Invalid Risk Level received form the selected "
                    f"source field for user '{user}'. Make sure that "
                    "the selected source "
                    "field contains the Risk Level 'LOW' or 'HIGH'."
                )
                self.logger.error(message=f"{self.log_prefix}: {error_msg}")
                raise OktaPluginException(error_msg)
            self._upsert_risk_score(
                headers, self.configuration, match_id, risk_level, user
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated risk level "
                f"for the user '{user}' to {risk_level}."
            )
        elif action_value == "push_risk_score":
            if isinstance(scores, str):
                scores_list = scores.split(",")
                # Remove empty strings and strip whitespace from each score
                scores_list = [
                    score.strip() for score in scores_list if score.strip()
                ]
            else:
                scores_list = scores

            if not isinstance(scores_list, list):
                err_msg = (
                    "Invalid User Score provided in the action parameter. "
                    "The selected field must be of the type list."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise OktaPluginException(err_msg)

            elif not self.check_last_values_condition(scores_list):
                error_msg = (
                    f"{PLATFORM_NAME} plugin expects "
                    "the value of 'Scores' parameter to be any of "
                    "the following values: low, medium or high."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                raise OktaPluginException(error_msg)
            try:
                if scores_list:
                    current_score = scores_list[-1] if scores else "none"
                    historical_score = (
                        scores_list[-2]
                        if scores and len(scores_list) > 1
                        else "none"
                    )
                    if current_score == "none" and historical_score == "none":
                        error_msg = (
                            f"No score associated with the user '{user}', "
                            "hence 'Push Risk Score' action cannot "
                            "be performed."
                        )
                        self.logger.error(f"{self.log_prefix}: {error_msg}")
                        raise OktaPluginException(error_msg)
                    key_id = self.get_kid_from_jwks_url(
                        action_parameters.get("jwks_url", "").strip()
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched Key ID from "
                        f"the JWKS URL for the user '{user}'."
                    )
                    reason_admin = action_parameters.get(
                        "reason_admin", "Triggered by Netskope CE"
                    )
                    set_token = self.generate_set_token(
                        action_parameters.get("issuer_url", "").strip(),
                        action_parameters.get("private_key", ""),
                        base_url,
                        key_id,
                        user,
                        current_score,
                        historical_score,
                        reason_admin,
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully generated "
                        f"the SET Token for the user '{user}'."
                    )
                    self.push_event_to_okta(
                        self.configuration.get("url", "").strip().rstrip("/"),
                        set_token,
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully pushed risk score "
                        f"for user '{user}'."
                    )
                else:
                    msg = (
                        f"No score associated with the user '{user}', "
                        "hence Push risk score action will not be performed."
                    )
                    self.logger.info(f"{self.log_prefix}: {msg}")
                    return
            except OktaPluginException as err:
                raise OktaPluginException(err)
            except Exception as err:
                error_msg = (
                    "Error occurred while pushing risk score."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_msg} "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise OktaPluginException(err)

    def get_all_security_events_provider(
        self, base_url, headers, issuer, jwks_url
    ):
        """
        Fetch all existing security events providers from the Okta tenant.

        Args:
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.
            issuer (str): Issuer URL.
            jwks_url (str): JWKS URL.

        Returns:
            Tuple[bool, str]: A tuple indicating if the security events
                provider with the given issuer and jwks_url exists or not,
                and the ID of the security events provider if it exists.
        """
        url_endpoint = f"{base_url}/api/v1/security-events-providers"
        after = ""
        sep_id = None
        security_event_provider_list = []
        params = {}
        page = 1
        total_count = 0
        while True:
            current_page_count = 0
            logger_msg = (
                "fetching existing security events providers "
                f"from the {PLATFORM_NAME} for page {page}"
            )
            resp = self.okta_helper.api_helper(
                logger_msg=logger_msg,
                url=url_endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
            )
            security_event_provider_list += self.okta_helper.handle_error(
                resp, logger_msg
            )
            current_page_count = len(security_event_provider_list)
            total_count += current_page_count
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
            self.logger.info(
                f"{self.log_prefix}: "
                f"Successfully fetched {current_page_count} "
                f"Security Events Provider(s) from page {page}. "
                f"Total Security Events Providers fetched: {total_count}."
            )
            if not flag:
                break
            page += 1

        for provider in security_event_provider_list:
            if provider.get("name") == EVENTS_PROVIDER:
                settings = provider.get("settings", {})
                sep_id = provider.get("id", "")
                if (
                    settings.get("issuer", "") == issuer
                    and settings.get("jwks_url", "") == jwks_url
                ):
                    return True, sep_id
                else:
                    return False, sep_id
        return False, sep_id

    def update_security_event_provider(
        self, base_url, headers, issuer, jwks_url, sep_id
    ):
        """
        Update existing Security Events Provider in Okta tenant.

        Args:
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.
            issuer (str): Issuer URL.
            jwks_url (str): JWKS URL.
            sep_id (str): Security Events Provider ID.

        Returns:
            None
        """
        url_endpoint = f"{base_url}/api/v1/security-events-providers/{sep_id}"
        body = {
            "name": EVENTS_PROVIDER,
            "type": "Netskope",
            "settings": {"issuer": issuer, "jwks_url": jwks_url},
        }
        logger_msg = "updating Security Events Provider"
        resp = self.okta_helper.api_helper(
            logger_msg=logger_msg,
            url=url_endpoint,
            method="PUT",
            json=body,
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=False,
        )
        if resp.status_code in [200, 201]:
            self.logger.info(
                f"{self.log_prefix}: Successfully updated Security "
                f"Events Provider with the issuer '{issuer}'."
            )
            return
        self.okta_helper.handle_error(resp, logger_msg)

    def generate_security_provider(
        self, base_url, headers, issuer, jwks_url, is_validation=False
    ):
        """
        Generate a Security Events Provider in Okta tenant.

        Args:
            base_url (str): Okta base URL.
            headers (dict): Okta API request headers.
            issuer (str): Issuer URL.
            jwks_url (str): JWKS URL.
            is_validation (bool, optional): Is this request coming from
                validate method?. Defaults to False.

        Returns:
            None
        """
        url_endpoint = f"{base_url}/api/v1/security-events-providers"
        body = {
            "name": EVENTS_PROVIDER,
            "type": "Netskope",
            "settings": {"issuer": issuer, "jwks_url": jwks_url},
        }
        logger_msg = "generating security events provider"
        resp = self.okta_helper.api_helper(
            logger_msg=logger_msg,
            url=url_endpoint,
            method="POST",
            json=body,
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=False,
            is_validation=is_validation,
        )
        if resp.status_code in [200, 201]:
            self.logger.info(
                f"{self.log_prefix}: Successfully created Security "
                f"Events Provider with the issuer '{issuer}'."
            )
            return

        json_resp = self.okta_helper.parse_response(resp, logger_msg)
        error_causes = json_resp.get("errorCauses", [])
        for error_cause in error_causes:
            if (
                "Security Events Provider name must be unique"
                in error_cause.get("errorSummary", "")
            ):
                is_matched, sep_id = self.get_all_security_events_provider(
                    base_url, headers, issuer, jwks_url
                )
                if not is_matched:
                    error_msg = (
                        f"{EVENTS_PROVIDER} already exists with a different "
                        "Issuer than provided in the configuration. "
                        f"Either delete the existing Security Events Provider "
                        f"from the {PLATFORM_NAME} platform or update the "
                        "Issuer URL and JWKS URL."
                    )
                    raise OktaPluginException(error_msg)

                # update SEP
                self.update_security_event_provider(
                    base_url, headers, issuer, jwks_url, sep_id
                )
                return
            elif (
                "The provided issuer already exists for this organization."
                in error_cause.get("errorSummary", "")
            ):
                error_message = (
                    "The provided Issuer URL is already associated with "
                    "other Security Events Provider. "
                    "Either delete the existing Security "
                    "Events Provider or use a unique Issuer URL."
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_message}",
                    details=str(error_cause),
                )
                raise OktaPluginException(error_message)
        self.okta_helper.handle_error(resp, logger_msg)

    def get_action_params(self, action: Action):
        """Get fields required for an action."""
        base_url = (
            f"{self.configuration.get('url', '').rstrip('/').rstrip('/')}"
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.configuration.get('api_token')}",
        }
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
        action_value = action.value
        if action_value == "generate":
            return []
        if action_value != "push_risk_score":
            groups = self._get_all_groups(
                base_url,
                headers,
                is_validation=True
            )
            groups = sorted(
                groups,
                key=lambda g: g.get("profile", {}).get("name", "").lower(),
            )
        if action_value == "add":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("profile", {}).get("name", ""),
                            "value": g.get("id", ""),
                        }
                        for g in groups
                    ]
                    + [{"key": "Create new group", "value": "create"}],
                    "default": groups[0].get("id", "") if groups else "",
                    "mandatory": True,
                    "description": "Select a group to add the user to.",
                },
                {
                    "label": (
                        "Group Name (only applicable for Create new group)"
                    ),
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create Okta group with given name "
                        "if it does not exist."
                    ),
                },
            ]
        elif action_value == "remove":
            return email_field + [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {
                            "key": g.get("profile", {}).get("name", ""),
                            "value": g.get("id", ""),
                        }
                        for g in groups
                    ],
                    "default": groups[0].get("id", "") if groups else "",
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]
        elif action_value == "upsert_risk_score":
            return email_field + [
                {
                    "label": "Risk Level",
                    "key": "risk_level",
                    "type": "choice",
                    "choices": [
                        {"key": "LOW", "value": "LOW"},
                        {"key": "HIGH", "value": "HIGH"},
                    ],
                    "default": "LOW",
                    "mandatory": True,
                    "description": "Select the Risk Level.",
                }
            ]
        elif action_value == "push_risk_score":
            return email_field + [
                {
                    "label": "User Score",
                    "key": "scores",
                    "type": "text",
                    "default": "low, medium",
                    "mandatory": True,
                    "description": (
                        "Score associated with the User Email. "
                        "Should be in the form of levels - low, medium, high. "
                        "If you select 'Static' option for this field provide "
                        "comma separated values - 'previous_level', "
                        "'current_level'. Eg., low, medium. "
                        "If you select 'Source' Field make sure the "
                        "Aggregate Strategy is set to 'Append' in the "
                        "Schema Editor for the selected field."
                    ),
                },
                {
                    "label": "Reason Admin",
                    "key": "reason_admin",
                    "type": "text",
                    "default": "Triggered by Netskope CE",
                    "mandatory": True,
                    "description": (
                        "Reason Admin field to provide explanation "
                        "of the event. Eg., Policy name of the "
                        "Netskope Event."
                    ),
                },
                {
                    "label": "Issuer URL",
                    "key": "issuer_url",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The URL used to host the public key "
                        "and generate the security provider."
                    ),
                },
                {
                    "label": "JWKS URL",
                    "key": "jwks_url",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "JSON Web Key Set URL, where the public key is hosted."
                    ),
                },
                {
                    "label": "Private Key",
                    "key": "private_key",
                    "type": "textarea",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Private Key associated with the public "
                        "Key hosted on the JWKS URL. "
                        "\nNote: Provide the Private Key in PEM format."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Okta action configuration."""
        action_value = action.value
        action_parameters = action.parameters
        action_label = action.label

        if action_value not in [
            "add",
            "remove",
            "generate",
            "upsert_risk_score",
            "push_risk_score",
        ]:
            self.logger.error(
                f"{self.log_prefix}: "
                "Unsupported action selected. "
                "Select the action form the available list."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully validated action '{action_label}'."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )

        email = action_parameters.get("email", "")

        if not email:
            err_msg = "User Email is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(email, str):
            err_msg = "Invalid User Email provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if action_value == "upsert_risk_score":
            risk_level = action_parameters.get("risk_level", "")
            if not risk_level:
                err_msg = "Risk Level is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif "$" not in risk_level and risk_level not in ["LOW", "HIGH"]:
                err_msg = (
                    "Invalid Risk Level provided in the action parameter."
                    " Allowed values are 'LOW', 'HIGH'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully validated action '{action_label}'."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.configuration.get('api_token')}",
        }
        base_url = (
            f"{self.configuration.get('url', '').strip().rstrip('/')}"
        )
        if action_value != "push_risk_score":
            try:
                groups = self._get_all_groups(
                    base_url=base_url,
                    headers=headers,
                    is_validation=True
                )
            except OktaPluginException:
                return ValidationResult(
                    success=False,
                    message=(
                        "Error occurred while fetching groups for "
                        "the action configuration."
                    ),
                )
            except Exception as err:
                error_msg = (
                    "Error occurred while fetching groups for "
                    "the action configuration."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=error_msg)

            group = action_parameters.get("group", "")
            if not group or "$" in group:
                error_msg = (
                    "Group is a required field and it should not be a "
                    "'Source' field. Please select the Static option and "
                    "select a group from the available list."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=error_msg)
            if (
                action_value == "add"
                and group != "create"
                and not any(
                    map(
                        lambda g: g.get("id", "")
                        == action_parameters.get("group", ""),
                        groups,
                    )
                )
            ):
                error_msg = (
                    "Invalid Group selected in the action configuration."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=error_msg)

            if action_value == "remove" and not any(
                map(
                    lambda g: g.get("id", "")
                    == action_parameters.get("group", ""),
                    groups,
                )
            ):
                return ValidationResult(
                    success=False, message="Invalid group provided."
                )

            if (
                action_value == "add"
                and action_parameters.get("group", "") == "create"
                and not (action_parameters.get("name") or "").strip()
            ):
                return ValidationResult(
                    success=False,
                    message=(
                        "Group Name can not be empty when 'Create new group' "
                        "is selected in the Group field."
                    ),
                )
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully validated action '{action_label}'."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )

        # for Push risk score action
        scores = action_parameters.get("scores")

        if not scores:
            err_msg = "User Score is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if "$" not in scores:
            if isinstance(scores, str):
                scores_list = scores.split(",")
                # Remove empty strings and strip whitespace from each score
                scores_list = [
                    score.strip() for score in scores_list if score.strip()
                ]
            else:
                scores_list = scores

            if not isinstance(scores_list, list):
                err_msg = (
                    "Invalid User Score provided in the action parameter. "
                    "The selected field must be of the type list."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not self.check_last_values_condition(scores_list):
                error_msg = (
                    f"{PLATFORM_NAME} plugin expects "
                    "the value of 'Scores' parameter to be any of the "
                    "following values: "
                    "low, medium or high."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=error_msg)

        issuer_url = action_parameters.get("issuer_url", "").strip()
        if not issuer_url:
            error_msg = (
                "Issuer URL is a required action parameter "
                "for  the action Push risk score"
                "(using Security Events Provider)."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=f"{error_msg}")

        if "$" in issuer_url:
            error_msg = (
                "Issuer URL can not be a 'Source' field. "
                "Please select the Static option and provide the Issuer URL."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        elif not self.okta_helper._validate_url(
            issuer_url
        ):
            error_msg = "Invalid Issuer URL provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=f"{error_msg}")

        jwks_url = action_parameters.get("jwks_url", "").strip()
        if not jwks_url:
            error_msg = (
                "JWKS URL is a required action parameter "
                "for the action Push risk score "
                "(using Security Events Provider)."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(success=False, message=f"{error_msg}.")

        if "$" in jwks_url:
            error_msg = (
                "JWKS URL can not be a 'Source' field. "
                "Please select the Static option and provide the JWKS URL."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        elif not self.okta_helper._validate_url(
            jwks_url
        ):
            error_msg = "Invalid JWKS URL provided."
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(success=False, message=f"{error_msg}.")

        private_key = action_parameters.get("private_key", "").strip()
        if not private_key:
            error_msg = (
                "Private Key can not be empty "
                "for the action Push risk score "
                "(using Security Events Provider)."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(success=False, message=f"{error_msg}")

        if "$" in private_key:
            error_msg = (
                "Private Key can not be a 'Source' field. "
                "Please select the Static option and provide the Private Key."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=error_msg)

        reason_admin = action_parameters.get("reason_admin", "")
        if not reason_admin:
            error_msg = "Reason Admin can not be empty."
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(success=False, message=f"{error_msg}")

        elif not isinstance(reason_admin, str):
            error_msg = (
                "Invalid Reason Admin value provided in "
                "the configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}.")
            return ValidationResult(success=False, message=f"{error_msg}")

        try:
            # Attempt to load the key using the cryptography library
            load_pem_private_key(
                private_key.encode(),
                password=None,
            )
        except ValueError:
            error_msg = (
                "Invalid Private Key provided, "
                "make sure the Private Key is in PEM format."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=f"{error_msg}")

        try:
            self.generate_security_provider(
                base_url,
                headers,
                issuer_url,
                jwks_url,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Successfully validated action '{action_label}'."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except OktaPluginException:
            raise
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while generating "
                "security events provider. "
                "Check the credentials provided. "
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}, Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )

    def _validate_auth(self, domain, token):
        """
        Validate Okta credentials.

        Args:
            domain (str): Okta domain URL.
            token (str): Okta API Token.

        Returns:
            ValidationResult: ValidationResult object with success status and
            appropriate message.
        """

        url = f"{domain}/api/v1/users?limit=1"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {token}",
        }
        logger_msg = "validating Okta credentials"
        try:
            response = self.okta_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                is_validation=True,
            )
            if response.status_code in [200, 201]:
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Validation successful for {PLATFORM_NAME}."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 401:
                error_msg = (
                    "Authentication failed, check the API Token provided."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred."
                        f" Error: {error_msg}"
                    ),
                    details=response.text,
                )
                return ValidationResult(success=False, message=error_msg)
            elif response.status_code == 403:
                error_msg = (
                    "You do not have permission to perform the requested "
                    "action, check the API Token and the Roles "
                    "attached to the API Token provided."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    f"Error: {error_msg}",
                    details=response.text,
                )
                return ValidationResult(success=False, message=error_msg)
            self.okta_helper.handle_error(response, logger_msg)
        except OktaPluginException as err:
            return ValidationResult(
                success=False,
                message=f"{err}",
            )
        except Exception as err:
            error_msg = (
                "Unexpected error "
                "occurred while authenticating "
                f"{PLATFORM_NAME} credentials."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg} "
                f"Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=(
                    f"{error_msg}. "
                    "Check logs for more details."
                ),
            )

    def validate(self, configuration: dict):
        """
        Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:
                - url (str): Okta domain.
                - api_token (str): Okta API Token.
                - days (int): Initial Range in days.

        Returns:
            ValidationResult: ValidationResult object with success flag and
                              message.
        """
        # Okta Domain
        okta_domain = configuration.get("url", "").strip().rstrip("/")
        if not okta_domain:
            error_msg = "Okta Domain is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=f"{error_msg}")
        elif not self.okta_helper._validate_url(
            okta_domain
        ) or not self.okta_helper.validate_okta_domain(okta_domain):
            error_msg = (
                "Invalid Okta Domain provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details="Okta Domain must end with '.oktapreview.com', "
                "'.okta.com' or '.okta-emea.com'",
            )
            return ValidationResult(success=False, message=f"{error_msg}")

        # API Token
        api_token = configuration.get("api_token")
        if not api_token:
            error_msg = "API Token is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=f"{error_msg}")

        elif not isinstance(api_token, str):
            error_msg = (
                "Invalid API Token provided in the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(success=False, message=f"{error_msg}")

        # Initial Range
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return self._validate_auth(
            okta_domain,
            api_token
        )
