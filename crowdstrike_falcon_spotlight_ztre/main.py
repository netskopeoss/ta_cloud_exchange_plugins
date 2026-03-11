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

CRE CrowdStrike Falcon Spotlight Plugin plugin.
"""

import traceback
from typing import Callable, Dict, List, Tuple, Union
from datetime import datetime
from urllib.parse import urlparse

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from packaging import version

from .utils.constants import (
    BASE_URLS,
    DATETIME_FORMAT,
    FETCH_VULNERABILITIES_API_ENDPOINT,
    INTEGER_THRESHOLD,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    VALIDATION_ERROR_MSG,
    VULNERABILITY_FIELD_MAPPING,
)
from .utils.exceptions import (
    CrowdstrikeFalconSpotlightPluginException,
    exception_handler,
)
from .utils.helper import CrowdstrikeFalconSpotlightHelper
from .utils.parser import CrowdstrikeFalconSpotlightParser


class CrowdstrikeFalconSpotlightPlugin(PluginBase):
    """CrowdStrike Falcon Spotlight plugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """CrowdStrike Falcon Spotlight plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.parser = CrowdstrikeFalconSpotlightParser(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )
        self.crowdstrike_helper = CrowdstrikeFalconSpotlightHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            parser=self.parser,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CrowdstrikeFalconSpotlightPlugin.metadata
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

    def _check_ce_version(self) -> bool:
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    @exception_handler
    def _get_access_token_and_storage(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        is_validation: bool = False
    ) -> Tuple[str, Dict]:
        """
        Get access token and storage.

        Args:
            base_url (str): Base URL.
            client_id (str): Client ID.
            client_secret (str): Client secret.
            is_validation (bool, optional): Is validation. Defaults to False.

        Returns:
            Tuple[str, Dict]: Access token and storage.
        """
        storage = self._get_storage()
        stored_access_token = storage.get("access_token")
        stored_config_hash = storage.get("config_hash")
        current_config_hash = self.crowdstrike_helper.hash_string(
            string=f"{base_url}{client_id}{client_secret}"
        )
        if stored_access_token and stored_config_hash == current_config_hash:
            return stored_access_token, storage
        else:
            access_token = self.crowdstrike_helper.generate_access_token(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=is_validation,
                context={},
            )
            storage.update(
                {
                    "access_token": access_token,
                    "config_hash": current_config_hash,
                }
            )
            return access_token, storage

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Vulnerabilities",
                fields=[
                    EntityField(
                        name="ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="AID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Confidence",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Local IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Machine Domain",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Site name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Asset Criticality",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Internet Exposure",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Service Provider Account ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Service Provider",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Managed By",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Host Confidence",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE Base Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CVE Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE Exploit Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE ExPRT Rating",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE Types",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="CVE Actors",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="CVE Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE Exploitability Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CVE Impact Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CVE Vector",
                        type=EntityFieldType.STRING,
                    ),
                ],
            ),
        ]

    @exception_handler
    def _fetch_vulnerabilities(self, context: dict = {}):
        base_url, client_id, client_secret, initial_range = (
            self.crowdstrike_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        access_token, storage = self._get_access_token_and_storage(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            is_validation=False,
        )
        headers = self.crowdstrike_helper.get_auth_headers(
            access_token=access_token,
        )
        query_params = {
            "limit": PAGE_SIZE,
            "facet": ["host_info", "cve"],
            "sort": "updated_timestamp.asc"
        }
        last_run_at = self.last_run_at
        query_params = self.crowdstrike_helper.get_filter_parameter(
            query_params=query_params,
            last_run_at=self.last_run_at,
            initial_range=initial_range
        )
        if last_run_at:
            self.logger.info(
                f"{self.log_prefix}: Fetching vulnerabilities seen after"
                f" '{last_run_at}' time from {PLATFORM_NAME} platform.",
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch hence"
                f" fetching vulnerabilities from the last {initial_range}"
                " days."
            )
        records = []
        page_number = 1
        url = FETCH_VULNERABILITIES_API_ENDPOINT.format(base_url=base_url)
        total_success = 0
        total_skip = 0
        while True:
            page_success = 0
            page_skip = 0
            logger_msg = (
                f"fetching vulnerabilities for page {page_number} from"
                f" {PLATFORM_NAME} platform"
            )
            context["logger_msg"] = logger_msg
            response = self.crowdstrike_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=headers,
                params=query_params,
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
                configuration=self.configuration,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            pagination_details = response.get("meta", {}).get("pagination", {})
            for vulnerability in response.get("resources", []):
                try:
                    extracted_data = self.parser.extract_entity_fields(
                        event=vulnerability,
                        entity_field_mapping=VULNERABILITY_FIELD_MAPPING,
                    )
                    if extracted_data:
                        records.append(extracted_data)
                        page_success += 1
                    else:
                        page_skip += 1
                except Exception as e:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while extracting"
                        f" fields from vulnerability. Error: {e}"
                    )
                    page_skip += 1
                    continue
            total_success += page_success
            total_skip += page_skip
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {page_success}"
                f" vulnerability record(s) from page {page_number}."
                f" Total vulnerabilities fetched: {total_success}."
            )
            if page_skip > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped fetching {page_skip}"
                    f" vulnerability record(s) from page {page_number}."
                )
            next_page_token = pagination_details.get("after")
            if not next_page_token:
                break
            query_params["after"] = next_page_token
            page_number += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total_success}"
            f" vulnerability record(s) from {PLATFORM_NAME} platform."
        )
        if total_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped fetching {total_skip} "
                f"vulnerability record(s) from {PLATFORM_NAME} platform."
            )
        return records

    def fetch_records(self, entity: str) -> list:
        """Fetch vulnerability records from CrowdStrike Falcon Spotlight.

        Args:
            entity (str): Entity name to fetch records for.

        Returns:
            list: List of vulnerability records fetched from CrowdStrike.
        """
        entity_name = entity.lower()
        fetched_records = []
        if entity_name == "vulnerabilities":
            fetched_records = self._fetch_vulnerabilities(context={})
            return fetched_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Vulnerabilities' Entity."
            )
            resolution = "Ensure that the entity is 'Vulnerabilities'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CrowdstrikeFalconSpotlightPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch scores of hosts from CrowdStrike platform.

        Args:
            entity (str): Entity name.
            agent_ids (list[Record]): list of records containing host's
            host ids.

        Returns:
            list[Record]: list of records with scores.
        """
        entity_name = entity.lower()
        if entity_name == "vulnerabilities":
            return []
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Vulnerabilities' Entity."
            )
            resolution = "Ensure that the entity is 'Vulnerabilities'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CrowdstrikeFalconSpotlightPluginException(err_msg)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        max_value: int = None,
        min_value: int = None,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str:
            field_value = field_value.strip()
        if not isinstance(field_value, int) and not field_value:
            err_msg = f"'{field_name}' is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            if field_value not in allowed_values:
                valid_values = ", ".join(list(allowed_values.values()))
                err_msg = (
                    "Invalid value provided for configuration parameter"
                    f" '{field_name}'"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    details=f"Allowed values are: {valid_values}",
                    resolution=(
                        f"Ensure that the value for '{field_name}' is selected"
                        " from the allowed values in the configuration"
                        f"parameter.\nAllowed values are: {valid_values}."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        if max_value is not None and min_value is not None:
            if min_value > field_value or max_value < field_value:
                if max_value == INTEGER_THRESHOLD:
                    max_value = "2^62"
                err_msg = (
                    f"Invalid value provided for configuration parameter"
                    f" '{field_name}'. Valid value should be an integer "
                    f"greater than {min_value} and less than {max_value}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Please provide a valid value greater than"
                        f" {min_value} and less than {max_value}."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["generate"]:
            err_msg = (
                f"Unsupported action '{action_value}'"
                f" provided in the action configuration."
                " Supported Actions are - 'No Action'."
            )
            resolution = (
                "Ensure that the action is selected from the "
                "supported actions 'No Action' in the action"
                " configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_params(self, action: Action):
        """Get action params.

        Args:
            action (Action): Action object.

        Returns:
            list: List of action parameters.
        """
        if action.value == "generate":
            return []
        return []

    def execute_action(self, action: Action):
        """Execute action on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        action_label = action.label
        action_value = action.value
        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: Successfully executed '{action_label}'"
                f" action. Note: No processing will be done from plugin for "
                f'the "{action_label}" action.'
            )
        else:
            err_msg = (
                f"Unsupported action '{action_value}'"
                f" provided in the action configuration. Supported Actions"
                "are - 'No Action'."
            )
            resolution = (
                "Ensure that the action is selected from the "
                "supported actions 'No Action' in the action"
                " configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
        return

    def execute_actions(self, actions: List[Action]):
        """Bulk Execute action on the record."""
        action_label = actions[0].label
        action_value = actions[0].value
        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: Successfully executed '{action_label}'"
                f" action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
        else:
            err_msg = (
                f"Unsupported action '{action_value}'"
                f" provided in the action configuration. Supported Actions"
                " are - 'No Action'."
            )
            resolution = (
                "Ensure that the action is selected from the "
                "supported actions 'No Action' in the action "
                "configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
        return

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        base_url, client_id, client_secret, initial_range = (
            self.crowdstrike_helper.get_configuration_parameters(
                configuration=configuration,
            )
        )
        # Validate Base URL
        if validation_result := self._validate_parameters(
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self._validate_url,
            allowed_values=BASE_URLS,
        ):
            return validation_result

        # Validate Client ID
        if validation_result := self._validate_parameters(
            field_name="Client ID",
            field_value=client_id,
            field_type=str,
        ):
            return validation_result

        # Validate Client Secret
        if validation_result := self._validate_parameters(
            field_name="Client Secret",
            field_value=client_secret,
            field_type=str,
        ):
            return validation_result

        # Validate Initial range
        if validation_result := self._validate_parameters(
            field_name="Initial Range",
            field_value=initial_range,
            field_type=int,
            min_value=0,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Auth Credentials
        return self._validate_connectivity(configuration=configuration)

    def _validate_connectivity(self, configuration: Dict) -> ValidationResult:
        """Validate the authentication params with CrowdStrike platform.

        Args:
            configuration (Dict): Configuration parameters containing base_url,
                client_id, client_secret and initial pull range.
        Returns:
            ValidationResult: ValidationResult object having validation
                results after making an API call.
        """
        try:
            base_url, client_id, client_secret, _ = (
                self.crowdstrike_helper.get_configuration_parameters(
                    configuration=configuration
                )
            )
            access_token, storage = self._get_access_token_and_storage(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                is_validation=True
            )
            headers = self.crowdstrike_helper.get_auth_headers(
                access_token=access_token
            )
            current_time = datetime.strftime(datetime.now(), DATETIME_FORMAT)
            self.crowdstrike_helper.api_helper(
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME} platform."
                ),
                url=FETCH_VULNERABILITIES_API_ENDPOINT.format(
                    base_url=base_url,
                ),
                method="GET",
                headers=headers,
                params={
                    "limit": 1,
                    "filter": f"created_timestamp:>'{current_time}'",
                },
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
                configuration=configuration,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            success_msg = (
                f"Successfully validated connectivity with {PLATFORM_NAME}."
            )
            self.logger.debug(f"{self.log_prefix}: {success_msg}")
            return ValidationResult(
                success=True,
                message=success_msg,
            )
        except CrowdstrikeFalconSpotlightPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
