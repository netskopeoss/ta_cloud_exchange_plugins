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

CRE Wiz Plugin.
"""

import datetime
import traceback
from dateutil import parser
from typing import List

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)

from .utils.wiz_constants import (
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    GRAPHQL_QUERY
)
from .utils.wiz_helper import WizPluginException, WizPluginHelper


class WizPlugin(PluginBase):
    """Wiz plugin implementation."""

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
        self.wiz_helper = WizPluginHelper(
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
            metadata_json = WizPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            record: Record of a application on which action will be
            performed.
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        if action.value == "generate":
            return

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
        if action_value not in [
            "generate"
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Wiz.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        total_records = []
        skipped_records = 0
        page_count = 1

        (base_url, token_url, client_id, client_secret) = (
            self.wiz_helper.get_config_params(self.configuration)
        )

        # Prepare headers.
        headers = self.wiz_helper.get_auth_header(
            client_id, client_secret, token_url
        )

        graphql_url = f"{base_url}/graphql"
        graphql_query = GRAPHQL_QUERY
        graphql_query.update(
            {
                "variables": {
                    "filterBy": {
                        "type": "BUCKET"
                    },
                    "first": PAGE_SIZE
                }
            }
        )
        while True:
            try:
                self.logger.info(
                    f"{self.log_prefix}: Fetching {entity_name} for page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                resp_json = self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    json=graphql_query,
                    headers=headers,
                    configuration=self.configuration,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching {entity_name} for page {page_count} from {PLATFORM_NAME}"
                    )
                )

                current_app_list = (
                    resp_json.get("data", {}).get("cloudResources", {}).get("nodes", [])
                )
                current_app_count = len(current_app_list)
                page_app_count = 0
                page_app_skip_count = 0

                # We get all the app id and store it in total app id list
                for each_app in current_app_list:
                    try:
                        currRecord = {
                            "Application ID": each_app.get("id", ""),
                            "Subscription External ID": each_app.get("subscriptionExternalId", ""),
                            "Subscription ID": each_app.get("subscriptionId", ""),
                            "Application Name": each_app.get("name", ""),
                            "Cloud Platform": (
                                each_app.get("graphEntity", {})
                                .get("properties", {}).get("cloudPlatform", "")
                            ),
                            "Cloud Provider URL": (
                                each_app.get("graphEntity", {})
                                .get("properties", {}).get("cloudProviderURL", "")
                            ),
                            "Creation Date": parser.parse(
                                each_app.get("graphEntity", {})
                                .get("properties", {}).get("creationDate", "")
                            ),
                            "First Seen": parser.parse(
                                each_app.get("graphEntity", {}).get("firstSeen", "")
                            ),
                            "Last Seen": parser.parse(
                                    each_app.get("graphEntity", {}).get("lastSeen", "")
                            )
                        }
                        total_records.append(currRecord)
                        page_app_count += 1
                    except Exception as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Skipping {entity[:-1]} with "
                                f"id {each_app.get('id', f'{entity[:-1]} ID Not Found')}."
                            ),
                            details=f"Error Details: {err}. \nRecord Data: {each_app}"
                        )
                        page_app_skip_count += 1
                if page_app_skip_count:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped {page_app_skip_count} "
                        f"{entity_name} in page {page_count}."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_app_count} {entity_name} in page {page_count}."
                    f" Total {entity_name} fetched: {len(total_records)}."
                )
                page_count += 1
                skipped_records += page_app_skip_count
                # if hasNextPage value in pageInfo is False then break
                page_info = resp_json.get("data", {}).get("cloudResources", {}).get("pageInfo", {})
                if not page_info.get("hasNextPage", False) or (current_app_count < PAGE_SIZE):
                    break

                after_cursor = page_info.get("endCursor", "")
                graphql_query["variables"]["after"] = after_cursor
            except WizPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Unexpected error occurred "
                    f"while fetching {entity_name} from {PLATFORM_NAME} "
                    f"platform. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise WizPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_records)}"
            f" {entity_name} and skipped {skipped_records} {entity_name} "
            f"from {PLATFORM_NAME} platform. "
        )
        return total_records

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
            f"{self.log_prefix}: Updating {len(records)}"
            f" {entity_name} record(s) from {PLATFORM_NAME} platform."
        )

        record_uid_list = {record["Application ID"]: record for record in records}

        page_count = 1
        total_app_count = 0

        (base_url, token_url, client_id, client_secret) = (
            self.wiz_helper.get_config_params(self.configuration)
        )

        # Prepare headers.
        headers = self.wiz_helper.get_auth_header(
            client_id, client_secret, token_url
        )

        graphql_url = f"{base_url}/graphql"
        graphql_query = GRAPHQL_QUERY
        graphql_query.update(
            {
                "variables": {
                    "filterBy": {
                        "type": "BUCKET"
                    },
                    "first": PAGE_SIZE
                }
            }
        )
        while True:
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Updating records for {entity_name} in page {page_count}"
                    f" from {PLATFORM_NAME} platform."
                )
                resp_json = self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    json=graphql_query,
                    headers=headers,
                    configuration=self.configuration,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching {entity_name} for page {page_count} from {PLATFORM_NAME}"
                    )
                )

                current_app_list = (
                    resp_json.get("data", {}).get("cloudResources", {}).get("nodes", [])
                )
                current_app_count = len(current_app_list)
                app_update_count = 0

                for each_application in current_app_list:
                    current_uid = each_application.get("id", "")
                    if current_uid in record_uid_list:
                        record = record_uid_list[current_uid]
                        record.update({
                            "Subscription External ID": each_application.get("subscriptionExternalId", ""),
                            "Subscription ID": each_application.get("subscriptionId", ""),
                            "Application Name": each_application.get("name", ""),
                            "Cloud Platform": (
                                each_application.get("graphEntity", {})
                                .get("properties", {}).get("cloudPlatform", "")
                            ),
                            "Cloud Provider URL": (
                                each_application.get("graphEntity", {})
                                .get("properties", {}).get("cloudProviderURL", "")
                            ),
                            "Creation Date": parser.parse(
                                each_application.get("graphEntity", {})
                                .get("properties", {}).get("creationDate", "")
                            ),
                            "First Seen": parser.parse(
                                each_application.get("graphEntity", {}).get("firstSeen", "")
                            ),
                            "Last Seen": parser.parse(
                                    each_application.get("graphEntity", {}).get("lastSeen", "")
                            )
                        })
                        app_update_count += 1

                total_app_count += app_update_count
                self.logger.debug(
                        f"{self.log_prefix}: Successfully updated records for "
                        f"{app_update_count} {entity_name} in page {page_count}."
                        f" Total record(s) updated: {total_app_count}."
                    )
                page_count += 1
                # if hasNextPage value in pageInfo is False then break
                page_info = resp_json.get("data", {}).get("cloudResources", {}).get("pageInfo", {})
                if not page_info.get("hasNextPage", False) or (current_app_count < PAGE_SIZE):
                    break

                after_cursor = page_info.get("endCursor", "")
                graphql_query["variables"]["after"] = after_cursor
            except WizPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Unexpected error occurred "
                    f"while updating records from {PLATFORM_NAME} "
                    f"platform. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise WizPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {total_app_count} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )
        return records

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
                                token.
            base_url (str): Base URL of Wiz.
            token_url (str): Token URL of Wiz.

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate base url
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(base_url, str):
            err_msg = "Invalid Base URL value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate token url
        token_url = configuration.get("token_url", "").strip().strip("/")
        if not token_url:
            err_msg = "Token URL is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(token_url, str):
            err_msg = "Invalid Token URL value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate client_id
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate client_secret
        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required field."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret value provided."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with Wiz platform.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating auth credentials."
            )
            (base_url, token_url, client_id, client_secret) = (
                self.wiz_helper.get_config_params(configuration)
            )

            # Prepare headers.
            headers = self.wiz_helper.get_auth_header(
                client_id, client_secret, token_url, is_validation=True
            )

            graphql_url = f"{base_url}/graphql"
            graphql_query = GRAPHQL_QUERY
            graphql_query.update(
                {
                    "variables": {
                        "filterBy": {
                            "type": "BUCKET"
                        },
                        "first": 1
                    }
                }
            )

            self.wiz_helper.api_helper(
                url=graphql_url,
                method="POST",
                headers=headers,
                json=graphql_query,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=f"checking connectivity with {PLATFORM_NAME} platform",
                is_validation=True,
                regenerate_auth_token=False
            )

            return ValidationResult(
                success=True,
                message=f"Validation successful for {MODULE_NAME} {self.plugin_name} Plugin."
            )

        except WizPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
            )
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

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Applications",
                fields=[
                    EntityField(name="Application ID", type=EntityFieldType.STRING, required=True),
                    EntityField(name="Subscription External ID", type=EntityFieldType.STRING),
                    EntityField(name="Subscription ID", type=EntityFieldType.STRING),
                    EntityField(name="Application Name", type=EntityFieldType.STRING),
                    EntityField(name="Cloud Platform", type=EntityFieldType.STRING),
                    EntityField(name="Cloud Provider URL", type=EntityFieldType.STRING),
                    EntityField(name="Creation Date", type=EntityFieldType.DATETIME),
                    EntityField(name="First Seen", type=EntityFieldType.DATETIME),
                    EntityField(name="Last Seen", type=EntityFieldType.DATETIME),
                ],
            )
        ]
