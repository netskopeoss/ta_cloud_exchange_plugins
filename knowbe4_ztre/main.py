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

CRE KnowBe4 Plugin.
"""

import traceback
from typing import List

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    USER_FIELD_MAPPING,
    PAGE_SIZE,
    USERS_ENDPOINT,
    BASE_URLS,
)
from .utils.helper import (
    KnowBe4PluginException,
    KnowBe4PluginHelper,
)


class KnowBe4Plugin(PluginBase):
    """KnowBe4 plugin implementation."""

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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.knowBe4_helper = KnowBe4PluginHelper(
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
            metadata_json = KnowBe4Plugin.metadata
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
        return [
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []

    def execute_action(self, action: Action):
        """Execute action on the users.

        Args:
            action (Action): Action that needs to be perform on users.

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

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate KnowBe4 action configuration.

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

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate base_url
        validation_err_msg = "Validation error occurred."
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str):
            err_msg = (
                "Invalid Base URL value provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                "Base URL should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)
        elif base_url not in BASE_URLS:
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Select the Base URL from the available options."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate api_key
        api_key = configuration.get("api_key")
        if not api_key:
            err_msg = "API Token is a required configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid API Token value provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                " API Token should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with KnowBe4 platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            base_url, _ = self.knowBe4_helper.get_credentials(
                configuration=configuration
            )
            headers = self.knowBe4_helper.get_headers(
                configuration=configuration
            )
            params = {
                "page": 1,
                "per_page": 1,
            }

            url = f"{base_url}/{USERS_ENDPOINT}"

            self.knowBe4_helper.api_helper(
                url=url,
                method="GET",
                headers=headers,
                params=params,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"checking connectivity with {PLATFORM_NAME} platform"
                ),
                is_validation=True,
            )

            msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{PLATFORM_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {msg}")
            return ValidationResult(
                success=True,
                message=msg,
            )

        except KnowBe4PluginException as exp:
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
        elif transformation and transformation == "integer":
            return int(event)
        elif transformation and transformation == "float":
            return float(event)
        return event

    def _extract_each_user_fields(
        self, event: dict, include_normalization: bool = True
    ) -> dict:
        """Extract user fields.

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

        if include_normalization:
            risk_score = event.get("current_risk_score")
            if isinstance(risk_score, float) and 0.0 <= risk_score <= 100.0:
                normalized_score = 1000 - (risk_score * 10)

                self.add_field(
                    extracted_fields,
                    "Netskope Normalized Score",
                    normalized_score,
                )
            else:
                err_msg = (
                    f"{self.log_prefix}: Invalid "
                    f"{PLATFORM_NAME} Risk Score received "
                    f"for User ID: {event.get('id')}. "
                    "Netskope Normalized Score will not be "
                    "calculated for this user. "
                    "Valid Risk Score range is 0 to 100."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Risk Score: '{risk_score}'",
                )
                normalized_score_skip_count += 1

        return extracted_fields, normalized_score_skip_count

    def fetch_records(self, entity: str) -> List:
        """Pull Records from KnowBe4.

        Returns:
            List: List of records to be stored on the platform.
        """
        total_records = []
        entity_name = entity.lower()

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise KnowBe4PluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )
        base_url, _ = self.knowBe4_helper.get_credentials(
            configuration=self.configuration
        )
        headers = self.knowBe4_helper.get_headers(
            configuration=self.configuration
        )

        url = f"{base_url}/{USERS_ENDPOINT}"
        page_count = 1
        skip_count = 0

        while True:
            try:
                params = {"page": page_count, "per_page": PAGE_SIZE}
                user_list = self.knowBe4_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching {entity_name} for page "
                        f"{page_count} from {PLATFORM_NAME}"
                    ),
                )

                for each_user in user_list:
                    try:
                        if each_user.get("id"):
                            extracted_fields, _ = (
                                self._extract_each_user_fields(
                                    each_user,
                                    include_normalization=False,
                                )
                            )
                            if extracted_fields:
                                total_records.append(extracted_fields)
                            else:
                                skip_count += 1
                        else:
                            skip_count += 1
                    except KnowBe4PluginException:
                        skip_count += 1
                    except Exception as err:
                        id = each_user.get("id")
                        err_msg = (
                            "Unable to extract fields from user"
                            f' having User ID "{id}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                                f" Error: {err}"
                            ),
                            details=f"Record: {each_user}",
                        )
                        skip_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(user_list)} user(s) "
                    f"in page {page_count}. Total {entity_name}"
                    f" fetched: {len(total_records)} record(s)."
                )

                if not user_list:
                    break

                page_count += 1

            except KnowBe4PluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred "
                    f"while fetching {entity_name} from {PLATFORM_NAME} "
                    f"platform. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise KnowBe4PluginException(err_msg)
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} because they might not contain User ID"
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
        total_normalized_score_skip_count = 0
        entity_name = entity.lower()

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise KnowBe4PluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" records from {PLATFORM_NAME}."
        )
        id_list = set()
        for record in records:
            if record.get("User ID"):
                id_list.add(record.get("User ID"))

        log_msg = (
            f"{len(id_list)} user record(s) will be updated out"
            f" of {len(records)} records."
        )

        if len(records) - len(id_list) > 0:
            log_msg += (
                f" Skipped {len(records) - len(id_list)} user(s) as they"
                " do not have User ID field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")

        base_url, _ = self.knowBe4_helper.get_credentials(
            configuration=self.configuration
        )
        headers = self.knowBe4_helper.get_headers(
            configuration=self.configuration
        )
        url = f"{base_url}/{USERS_ENDPOINT}"

        page_count = 1
        skip_count = 0

        while True:
            try:
                params = {"page": page_count, "per_page": PAGE_SIZE}

                user_list = self.knowBe4_helper.api_helper(
                    url=url,
                    method="GET",
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching {entity_name} for page "
                        f"{page_count} from {PLATFORM_NAME}"
                    ),
                )

                user_update_count = 0
                for each_user in user_list:
                    try:
                        if each_user.get("id"):
                            extracted_fields, normalized_score_skip_count = (
                                self._extract_each_user_fields(
                                    each_user,
                                    include_normalization=True,
                                )
                            )

                            if extracted_fields:
                                current_id = extracted_fields.get(
                                    "User ID", ""
                                )
                                if current_id in id_list:
                                    updated_records.append(extracted_fields)
                                    user_update_count += 1
                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1

                            total_normalized_score_skip_count += (
                                normalized_score_skip_count
                            )
                        else:
                            skip_count += 1
                    except KnowBe4PluginException:
                        skip_count += 1
                    except Exception as err:
                        id = each_user.get("id")
                        err_msg = (
                            "Unable to extract fields from user"
                            f' having User ID "{id}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                                f" Error: {err}"
                            ),
                            details=f"Record: {each_user}",
                        )
                        skip_count += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully updated records for "
                    f"{user_update_count} {entity_name} in"
                    f" page {page_count}. Total record(s) "
                    f"updated: {len(updated_records)} record(s)."
                )

                if not user_list:
                    break

                page_count += 1

            except KnowBe4PluginException:
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
                raise KnowBe4PluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} user(s) "
                f"because they might not contain User ID in their "
                "response or fields could not be extracted from them."
            )

        if total_normalized_score_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating "
                "Netskope Normalized Score for "
                f"{total_normalized_score_skip_count} {entity_name}"
                " record(s) as invalid Risk Score value received from the "
                f"{PLATFORM_NAME} platform."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated "
            f"{len(updated_records)} {entity_name} record(s)"
            f" out of {len(records)} from {PLATFORM_NAME}."
        )

        return updated_records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User ID",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="First Name", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Last Name", type=EntityFieldType.STRING),
                    EntityField(
                        name="User Email", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="User Status", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="User Current Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
