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

CRE StealthMole plugin.
"""
import traceback
from dateutil import parser
from datetime import datetime, timedelta
from typing import List
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)
from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    VALIDATION_ERROR_MSG,
    INTEGER_THRESHOLD,
    API_BASE_URL,
    USER_FIELD_MAPPING,
    FETCH_USERS_ENDPOINT,
    VALIDATE_CREDENTIALS_ENDPOINT,
)

from .utils.helper import (
    StealthMolePluginException,
    StealthMolePluginHelper,
)


class StealthMolePlugin(PluginBase):
    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """StealthMole plugin initializer.

        Args:
            name (str): Plugin configuration name.
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
        self.stealthmole_helper = StealthMolePluginHelper(
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
            manifest_json = StealthMolePlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="Email",
                        type=EntityFieldType.STRING,
                        required=True
                    ),
                    EntityField(
                        name="Leaked From",
                        type=EntityFieldType.STRING,
                        required=True
                    ),
                    EntityField(
                        name="Leaked Date",
                        type=EntityFieldType.DATETIME
                    ),
                    EntityField(
                        name="Score",
                        type=EntityFieldType.NUMBER
                    )
                ],
            )
        ]

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
        """Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def _extract_entity_fields(self, event: dict) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.

        Returns:
            dict: Dictionary containing required fields.
        """
        extracted_fields = {}
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
        leaked_date = extracted_fields.get("Leaked Date", "")
        if leaked_date:
            extracted_fields["Leaked Date"] = parser.parse(leaked_date)

        return extracted_fields

    def _fetch_users(
        self,
        search_domain: str,
        score: int,
        start_time: int,
        headers: dict,
    ) -> List:
        """Fetch users from StealthMole.

        Args:
            search_domain (str): Search query.
            score (int): Score to be added with users.
            start_time (int): Start time in epoch.
            headers (dict): Request headers.

        Returns:
            List: List of users.
        """
        total_users = []
        users_count, users_skip_count = 0, 0
        api_endpoint = f"{API_BASE_URL}{FETCH_USERS_ENDPOINT}"
        parameters = {
            "query": f"email:{search_domain}",
            "limit": 0,
            "exportType": "json",
            "start": start_time,
        }
        try:
            logger_msg = (
                f"fetching user records from {PLATFORM_NAME} platform"
            )
            resp_json = self.stealthmole_helper.api_helper(
                url=api_endpoint,
                method="GET",
                headers=headers,
                params=parameters,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=logger_msg,
                configuration=self.configuration
            )
            users_list = resp_json.get("data", [])
            for user in users_list:
                try:
                    email = user.get("user", "")
                    host = user.get("host", "")
                    if not email and not host:
                        users_skip_count += 1
                        continue
                    extracted_fields = self._extract_entity_fields(
                        event=user
                    )
                    if extracted_fields:
                        extracted_fields["Score"] = score
                        total_users.append(extracted_fields)
                        users_count += 1
                    else:
                        users_skip_count += 1
                except Exception as err:
                    user_id = user.get("id", "")
                    err_msg = (
                        "Unable to extract fields from "
                        f"user with ID '{user_id}'."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} Error: {err}."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    users_skip_count += 1

        except StealthMolePluginException:
            raise
        except Exception as exp:
            error_message = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise StealthMolePluginException(error_message)

        if users_skip_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Skipped "
                f"{users_skip_count} user record(s) "
                "due to missing values for required "
                f"fields from {PLATFORM_NAME}."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(total_users)} user record(s) from "
            f"{PLATFORM_NAME} platform."
        )
        return total_users

    def fetch_records(self, entity: str):
        """Fetch users records from StealthMole.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        try:
            if entity == "Users":
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {entity_name} records from "
                    f"{PLATFORM_NAME} platform."
                )

                (
                    access_key,
                    secret_key,
                    search_domain,
                    score,
                    init_range,
                ) = self.stealthmole_helper.get_config_params(
                    self.configuration
                )

                if self.last_run_at:
                    start = self.last_run_at
                else:
                    self.logger.debug(
                        f"{self.log_prefix}: This is initial data fetch. "
                        f"Fetching user records for last {init_range} days."
                    )
                    start = datetime.now() - timedelta(days=init_range)

                headers = self.stealthmole_helper.create_header(
                    access_key=access_key,
                    secret_key=secret_key,
                )
                records = self._fetch_users(
                        search_domain=search_domain,
                        score=score,
                        start_time=int(start.timestamp()),
                        headers=headers
                    )
                return records
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Users' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise StealthMolePluginException(err_msg)
        except StealthMolePluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching user "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise StealthMolePluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        return []

    def _validate_field_empty_and_type(
        self,
        field_name: str,
        field_value: str,
        field_type: type,
    ):
        """Validate field tye and empty.

        Args:
            field_name (str): Field name.
            field_value (str): Field value.
            field_type (type): Field type.
        """
        empty_err_msg = f"{field_name} is a required configuration parameter."
        type_err_msg = (
            f"Invalid {field_name} provided in the configuration parameters."
        )
        if isinstance(field_value, str):
            field_value = field_value.strip()

        logger_msg_empty = f"{VALIDATION_ERROR_MSG} {empty_err_msg}"
        logger_msg_type = f"{VALIDATION_ERROR_MSG} {type_err_msg}"

        if field_type == str:
            if not field_value:
                self.logger.error(f"{self.log_prefix}: {logger_msg_empty}")
                return ValidationResult(
                    success=False,
                    message=logger_msg_empty
                )
        else:
            if field_value is None:
                self.logger.error(f"{self.log_prefix}: {logger_msg_empty}")
                return ValidationResult(
                    success=False,
                    message=logger_msg_empty
                )
        if not isinstance(field_value, field_type):
            self.logger.error(f"{self.log_prefix}: {logger_msg_type}")
            return ValidationResult(success=False, message=logger_msg_type)

    def _validate_credentials(
        self,
        access_key: str,
        secret_key: str
    ) -> ValidationResult:
        """Validate credentials for StealthMole platform.

        Args:
            access_key (str): Access Key.
            secret_key (str): Secret Key.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating credentials for "
                f"{PLATFORM_NAME} platform."
            )
            headers = self.stealthmole_helper.create_header(
                access_key=access_key,
                secret_key=secret_key,
            )

            # StealthMole API Endpoint
            api_endpoint = f"{API_BASE_URL}{VALIDATE_CREDENTIALS_ENDPOINT}"
            response = self.stealthmole_helper.api_helper(
                url=api_endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating credentials for "
                    f"{PLATFORM_NAME} platform"
                ),
                is_validation=True,
                regenerate_auth_token=False
            )

            allowed_limit = response.get("UB", {}).get("allowed", 0)
            used_limit = response.get("UB", {}).get("used", 0)
            if used_limit >= allowed_limit:
                err_msg = (
                    f"{VALIDATION_ERROR_MSG} Your account has exceeded "
                    "UB query limit."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            logger_msg = (
                "Successfully validated "
                f"credentials for {PLATFORM_NAME} platform."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True,
                message=logger_msg,
            )
        except StealthMolePluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp)
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

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        (
            access_key,
            secret_key,
            search_domain,
            score,
            init_range,
        ) = self.stealthmole_helper.get_config_params(configuration)

        # Validate Access Key.
        if validation_result := self._validate_field_empty_and_type(
            "Access Key", access_key, str
        ):
            return validation_result

        # Validate Secret Key.
        if validation_result := self._validate_field_empty_and_type(
            "Secret Key", secret_key, str
        ):
            return validation_result

        # Validate Search Domain.
        if validation_result := self._validate_field_empty_and_type(
            "Search Domain", search_domain, str
        ):
            return validation_result
        elif len(search_domain.split(",")) > 1:
            err_msg = (
                "Multiple Search Domain provided in the configuration "
                "parameters. Provide only one Search Domain."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Score.
        if validation_result := self._validate_field_empty_and_type(
            "Score", score, int
        ):
            return validation_result
        elif score < 0 or score > 1000:
            err_msg = (
                "Invalid Score provided in the configuration parameters. "
                "Valid value should be in range of 0 to 1000."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Initial Range.
        if validation_result := self._validate_field_empty_and_type(
            "Initial Range (in days)", init_range, int
        ):
            return validation_result
        elif init_range <= 0:
            err_msg = (
                "Invalid Initial Range (in days) provided "
                "in the configuration parameters."
                "Valid value should be an integer greater than 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif init_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range (in days) provided "
                "in the configuration parameters."
                "Valid value should be in range of 1 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate credentials
        return self._validate_credentials(
            access_key=access_key,
            secret_key=secret_key,
        )

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
        """Validate StealthMole action configuration.

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

        validation_message = (
            "Successfully validated "
            f"action configuration for '{action.label}'."
        )
        self.logger.debug(
            f"{self.log_prefix}: {validation_message}"
        )
        return ValidationResult(success=True, message=f"{validation_message}")

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
