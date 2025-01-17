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

CRE Proofpoint plugin.
"""

import json
import traceback
from typing import List, Dict

from os.path import join
import tempfile

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
    USERS_ENDPOINT,
    SCORE_FILE,
    PROOFPOINT_VALID_WINDOW_SIZE,
)

from .utils.helper import (
    ProofpointPluginException,
    ProofpointPluginHelper,
)


class ProofpointPlugin(PluginBase):
    """Proofpoint plugin implementation."""

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
        self.proofpoint_helper = ProofpointPluginHelper(
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
            metadata_json = ProofpointPlugin.metadata
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
                details=str(traceback.format_exc()),
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
        """Validate action configuration.

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

    def validate(self, configuration: Dict):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """

        validation_err_msg = "Validation error occurred."

        # validation for Proofpoint URL
        proofpoint_url = (
            configuration.get("proofpoint_url", "").strip().strip("/")
        )
        if not proofpoint_url:
            err_msg = "Proofpoint URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(proofpoint_url, str):
            err_msg = (
                "Invalid Proofpoint URL value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                " Proofpoint URL should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)

        # validation for Proofpoint Username
        proofpoint_username = configuration.get(
            "proofpoint_username", ""
        ).strip()
        if not proofpoint_username:
            err_msg = (
                "Proofpoint Username is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(proofpoint_username, str):
            err_msg = (
                "Invalid Proofpoint Username value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                " Proofpoint Username should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)

        # validation for Proofpoint Password
        proofpoint_password = configuration.get("proofpoint_password", "")
        if not proofpoint_password:
            err_msg = (
                "Proofpoint Password is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(proofpoint_password, str):
            err_msg = (
                "Invalid Proofpoint Password value provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                " Proofpoint Password should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)

        # validation for window
        proofpoint_window = configuration.get("window")
        if not proofpoint_window:
            err_msg = "Date Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if (
            proofpoint_window
            and proofpoint_window not in PROOFPOINT_VALID_WINDOW_SIZE
        ):
            err_msg = (
                "Invalid Date Range provided in configuration"
                " parameters. Valid values are 14, 30, 90."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with Proofpoint platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            (proofpoint_url, proofpoint_username, proofpoint_password, _) = (
                self.proofpoint_helper.get_credentials(
                    configuration=configuration
                )
            )
            params = self.proofpoint_helper.get_params(
                configuration=configuration, is_validation=True
            )

            url = f"{proofpoint_url}/{USERS_ENDPOINT}"

            self.proofpoint_helper.api_helper(
                url=url,
                method="GET",
                params=params,
                auth=(proofpoint_username, proofpoint_password),
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

        except ProofpointPluginException as exp:
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
            if field_name == "User Email" and isinstance(value, list):
                value = value[0]
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
        return event

    def _extract_each_user_fields(self, event: dict) -> dict:
        """Extract user fields.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
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

        return extracted_fields

    def _normalize_score(self, updated_records, scores_list):
        """
        Normalize the fetched user score.

        args:
            updated_records (list): List of updated records.
            scores_list (list): List of scores.

        returns:
            list: List of updated records with normalized scores.
        """

        records_with_normalized_score = []
        normalize_score_skip_count = 0
        if not scores_list:
            err_msg = (
                "Error occurred while updating user records. "
                f"No User Attack Index received from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise ProofpointPluginException(err_msg)

        minvalue = min(scores_list)
        maxvalue = max(scores_list)

        self.logger.debug(
            message=(
                f"{self.log_prefix}: Min value: {minvalue} "
                f"and Max value: {maxvalue} will be used for "
                "calculating Netskope Normalized Score."
            )
        )
        for record in updated_records:
            risk_score = record.get("User Attack Index")
            if risk_score or risk_score == 0:
                score = (risk_score - minvalue) / (maxvalue - minvalue)
                score = 1 - score
                score = round((score * 999) + 1, 1)
                if score < 0:
                    normalize_score_skip_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Invalid "
                            f"{PLATFORM_NAME} Risk Score received "
                            f"for User Email: {record.get('User Email')}. "
                            "Netskope Normalized Score will not be "
                            "calculated for this user."
                        ),
                        details=f"Risk Score: '{risk_score}'",
                    )
                    continue
                record["Netskope Normalized Score"] = score
                records_with_normalized_score.append(record)
            else:
                normalize_score_skip_count += 1

        return records_with_normalized_score, normalize_score_skip_count

    def fetch_records(self, entity: str) -> List:
        """Fetch Records from Proofpoint.

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
            raise ProofpointPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )

        proofpoint_url, username, password, _ = (
            self.proofpoint_helper.get_credentials(
                configuration=self.configuration
            )
        )
        params = self.proofpoint_helper.get_params(
            configuration=self.configuration
        )

        url = f"{proofpoint_url}/{USERS_ENDPOINT}"
        offset = 1
        skip_count = 0
        with open(join(tempfile.gettempdir(), SCORE_FILE), "w") as score_file:
            while True:
                try:
                    params["page"] = offset
                    users_resp_json = self.proofpoint_helper.api_helper(
                        url=url,
                        method="GET",
                        auth=(
                            username,
                            password,
                        ),
                        params=params,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=(
                            f"fetching {entity_name} for page "
                            f"{offset} from {PLATFORM_NAME}"
                        ),
                    )
                    users = users_resp_json.get("users", [])

                    for each_user in users:
                        try:
                            identity = each_user.get("identity", {})
                            if identity and isinstance(identity, dict):
                                extracted_fields = (
                                    self._extract_each_user_fields(each_user)
                                )
                                if extracted_fields:
                                    total_records.append(extracted_fields)
                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1
                        except ProofpointPluginException:
                            skip_count += 1
                        except Exception as err:
                            email = None
                            identity = each_user.get("identity", {})
                            if (
                                isinstance(identity, dict)
                                and identity.get("emails")
                                and isinstance(identity.get("emails"), list)
                            ):
                                email = identity.get("emails")[0]
                            err_msg = (
                                "Unable to extract fields from user"
                                f' having User email "{email}".'
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
                        f"{len(users)} user(s) "
                        f"in page {offset}. Total {entity_name} "
                        f"record(s) fetched: {len(total_records)}."
                    )
                    offset += 1
                    if users_resp_json:
                        score_file.write(f"{json.dumps(users_resp_json)}\n")

                    if not users:
                        break

                except ProofpointPluginException:
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
                    raise ProofpointPluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} because they might not contain User Email"
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
        """Update user records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            list: List of updated records.
        """
        updated_records = []
        score_list = []
        skip_count = 0
        entity_name = entity.lower()

        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ProofpointPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" records from {PLATFORM_NAME}."
        )

        user_emails = {
            record.get("User Email"): record
            for record in records
            if record.get("User Email")
        }

        log_msg = (
            f"{len(user_emails)} user record(s) will be updated out"
            f" of {len(records)} records."
        )

        if len(records) - len(user_emails) > 0:
            log_msg += (
                f" Skipped {len(records) - len(user_emails)} user(s) as they"
                " do not have User Email field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")

        try:

            with open(
                join(tempfile.gettempdir(), SCORE_FILE), "r"
            ) as score_file:
                for line in score_file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        users = data.get("users", [])
                        for user in users:
                            current_email = user.get("identity").get("emails")[
                                0
                            ]
                            if current_email in user_emails:
                                record = user_emails[current_email]
                                threat_statistics = user.get(
                                    "threatStatistics", {}
                                )
                                if isinstance(
                                    threat_statistics, dict
                                ) and threat_statistics.get("attackIndex"):
                                    risk_score = threat_statistics.get(
                                        "attackIndex"
                                    )
                                    record["User Attack Index"] = risk_score
                                    score_list.append(risk_score)
                                    updated_records.append(record)
                                else:
                                    skip_count += 1
                            else:
                                skip_count += 1
                    except json.JSONDecodeError:
                        self.logger.warn(
                            f"{PLATFORM_NAME}: Unable to fetch scores, "
                            "could not parse a line."
                        )
                        skip_count += 1

            normalized_updated_records, total_normalized_score_skip_count = (
                self._normalize_score(updated_records, score_list)
            )

        except FileNotFoundError:
            self.logger.warn(
                f"{PLATFORM_NAME}: Unable to fetch scores for {entity_name}, "
                f"score file does not exist."
            )
        except ProofpointPluginException:
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
            raise ProofpointPluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} user(s) "
                f"because they might not contain User Email in their "
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

        return normalized_updated_records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User Email",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="User Attack Index",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
