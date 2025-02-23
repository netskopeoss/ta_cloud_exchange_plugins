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

CRE Zylo Plugin.
"""

import traceback
from typing import List
from pydantic import ValidationError

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    BASE_URL,
    APPLICATION_ENDPOINT,
    PAGE_SIZE,
    APPLICATION_FIELD_MAPPING,
    VALIDATION_PAGE_SIZE,
)
from .utils.helper import (
    ZyloPluginException,
    ZyloPluginHelper,
)


class ZyloPlugin(PluginBase):
    """Zylo plugin implementation."""

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
        self.zylo_helper = ZyloPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = ZyloPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
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
        """Validate Zylo action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value not in ["generate"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            f"action configuration for '{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        action_label = action.label

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

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
            if field_name == "Subscription ID":
                value = value.replace("subscription/", "")
            elif field_name == "Application ID":
                value = value.replace("application/", "")
            fields_dict[field_name] = value

    def _extract_entity_fields(
        self,
        event: dict,
        include_tags=False,
    ) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}

        for field_name, field_value in APPLICATION_FIELD_MAPPING.items():
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

        if event.get("tags") and include_tags:
            tags = event.get("tags", [])
            if isinstance(tags, list):
                self.add_field(extracted_fields, "Tags", tags)
            else:
                self.add_field(extracted_fields, "Tags", [])

        return extracted_fields

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_err_msg = "Validation error occurred."

        # Validate token id
        token_id = configuration.get("token_id", "").strip()
        if not token_id:
            err_msg = "Token ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(token_id, str):
            err_msg = (
                "Invalid Token ID value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate token secret
        token_secret = configuration.get("token_secret")
        if not token_secret:
            err_msg = "Token Secret is a required configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(token_secret, str):
            err_msg = (
                "Invalid Token Secret value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """
        Validate the authentication params with Zylo platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )

            headers = self.zylo_helper.get_auth_headers(configuration)

            url = f"{BASE_URL}/{APPLICATION_ENDPOINT}"
            params = {
                "pageSize": VALIDATION_PAGE_SIZE,
            }
            self.zylo_helper.api_helper(
                url=url,
                method="GET",
                params=params,
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )

            logger_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.debug(f"{self.log_prefix}: {logger_msg}")
            return ValidationResult(
                success=True,
                message=logger_msg,
            )
        except ZyloPluginException as exp:
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
                name="Applications",
                fields=[
                    EntityField(
                        name="Subscription ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Application ID", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Application Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Application Name", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Launch URL", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Application Owners Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Business Owners Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IT Owners Email",
                        type=EntityFieldType.STRING,
                    ),
                ],
            )
        ]

    def _fetch_applications(self) -> List:
        """Fetch applications from Zylo.

        Args:
            headers (dict): Headers with API Token.

        Returns:
            List: List of applications.
        """
        total_applications = []
        page_count = 1
        total_skip_count = 0
        url = f"{BASE_URL}/{APPLICATION_ENDPOINT}"
        headers = self.zylo_helper.get_auth_headers(self.configuration)
        while True:
            try:
                logger_msg = (
                    f"applications for page {page_count} "
                    f"from {PLATFORM_NAME} platform"
                )
                params = {
                    "pageSize": PAGE_SIZE,
                }
                resp_json = self.zylo_helper.api_helper(
                    url=url,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=f"fetching {logger_msg}",
                )
                applications_list = resp_json.get("subscriptions", [])
                page_applications_count = 0
                for application in applications_list:
                    try:
                        if application.get("id"):
                            extracted_fields = self._extract_entity_fields(
                                event=application
                            )
                            if extracted_fields:
                                total_applications.append(extracted_fields)
                                page_applications_count += 1
                            else:
                                total_skip_count += 1
                        else:
                            total_skip_count += 1
                    except Exception as err:
                        application_id = application.get("id")
                        err_msg = (
                            "Unable to extract fields from "
                            f"application with ID '{application_id}' "
                            f"from page {page_count}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                        total_skip_count += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_applications_count} applications record(s) "
                    f"in page {page_count}. "
                    f"Total applications fetched: {len(total_applications)}."
                )
                page_count += 1

                nextPageToken = resp_json.get("nextPageToken")

                if not nextPageToken:
                    break

                params["pageToken"] = nextPageToken

            except ZyloPluginException:
                raise
            except Exception as exp:
                error_message = (
                    "Error occurred"
                    if isinstance(exp, ValidationError)
                    else "Unexpected error occurred"
                )
                error_message += f" while fetching {logger_msg}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise ZyloPluginException(error_message)

        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                "application record(s) because they either do not "
                "have an 'Subscription ID' or fields could not be "
                "extracted from the application record."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {len(total_applications)} application "
            f"record(s) from {PLATFORM_NAME} platform."
        )
        return total_applications

    def fetch_records(self, entity: str) -> List:
        """Fetch application records from Zylo.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        try:
            if entity == "Applications":
                records.extend(self._fetch_applications())
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Applications' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise ZyloPluginException(err_msg)
        except ZyloPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching application "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ZyloPluginException(err_msg)
        return records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update application records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        updated_records = []
        entity_name = entity.lower()
        if entity == "Applications":
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)} {entity_name}"
                f" records from {PLATFORM_NAME}."
            )
            appid_list = []
            for record in records:
                if record.get("Subscription ID"):
                    appid_list.append(record.get("Subscription ID"))

            log_msg = (
                f"{len(appid_list)} {entity_name} record(s) will be "
                f"updated out of {len(records)} records."
            )

            skipped_count = len(records) - len(appid_list)
            if skipped_count > 0:
                log_msg += (
                    f" {skipped_count} {entity_name} record(s) "
                    "will be skipped as they do not contain "
                    "'Subscription ID' field."
                )

            headers = self.zylo_helper.get_auth_headers(self.configuration)

            url = f"{BASE_URL}/{APPLICATION_ENDPOINT}"

            page_count = 1
            total_skip_count = 0
            total_application_update_count = 0

            while True:
                try:
                    logger_msg = (
                        f"applications for page {page_count} "
                        f"from {PLATFORM_NAME} platform"
                    )
                    params = {
                        "pageSize": PAGE_SIZE,
                    }
                    resp_json = self.zylo_helper.api_helper(
                        url=url,
                        method="GET",
                        params=params,
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=f"fetching {logger_msg}",
                    )
                    applications_list = resp_json.get("subscriptions", [])
                    page_applications_count = 0
                    for application in applications_list:
                        try:
                            if application.get("id"):
                                extracted_fields = self._extract_entity_fields(
                                    event=application, include_tags=True
                                )
                                if extracted_fields:
                                    updated_records.append(extracted_fields)
                                    page_applications_count += 1
                                else:
                                    total_skip_count += 1
                            else:
                                total_skip_count += 1
                        except Exception as err:
                            application_id = application.get("id")
                            err_msg = (
                                "Unable to extract fields from "
                                f"application with ID '{application_id}' "
                                f"from page {page_count}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} "
                                    f"Error: {err}."
                                ),
                                details=str(traceback.format_exc()),
                            )
                            total_skip_count += 1

                    total_application_update_count += page_applications_count

                    self.logger.info(
                        f"{self.log_prefix}: Successfully updated "
                        f"{page_applications_count} applications record(s) "
                        f"in page {page_count}. Total record(s) updated: "
                        f"{total_application_update_count}."
                    )
                    page_count += 1

                    nextPageToken = resp_json.get("nextPageToken")

                    if not nextPageToken:
                        break

                    params["pageToken"] = nextPageToken

                except ZyloPluginException:
                    raise
                except Exception as exp:
                    error_message = (
                        "Error occurred"
                        if isinstance(exp, ValidationError)
                        else "Unexpected error occurred"
                    )
                    error_message += f" while updating {logger_msg}."
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} Error: {exp}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    raise ZyloPluginException(error_message)

            if total_skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {total_skip_count} "
                    "application record(s) because they either do not "
                    "have an 'Subscription ID' or fields could not be "
                    "extracted from the application record."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated"
                f" {len(updated_records)} application "
                f"record(s) from {PLATFORM_NAME} platform."
            )
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ZyloPluginException(err_msg)
        return updated_records
