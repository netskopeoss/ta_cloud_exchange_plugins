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

CRE Infoblox SOC Insights plugin.
"""

import traceback
from typing import Tuple, List, Iterator, Union, Callable, Optional
from urllib.parse import urlparse
from datetime import datetime, timedelta

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)

from .utils.infoblox_soc_insights_constants import (
    PAGE_LIMIT,
    MODULE_NAME,
    DATE_FORMAT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RISK_SCORE_MAPPING,
    DEVICE_FIELD_MAPPING,
    LIST_INSIGHTS_ENDPOINT,
    INSIGHT_ASSETS_ENDPOINT,
)

from .utils.infoblox_soc_insights_helper import (
    InfobloxSOCInsightsPluginException,
    InfobloxSOCInsightsPluginHelper
)


class InfobloxSOCInsightsPlugin(PluginBase):
    """Infoblox plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Infoblox SOC Insights plugin initializer.

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
        self.infoblox_helper = InfobloxSOCInsightsPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = InfobloxSOCInsightsPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

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

    def _add_field(self, fields_dict: dict, field_name: str, value):
        """Add field to the extracted_fields dictionary.

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

    def _extract_entity_fields(
            self,
            event: dict,
            entity_name: str,
            total_norm_score_errors: int
    ) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.
            entity_name (str): Entity name.

        Returns:
            dict: Dictionary containing required fields.
        """
        extracted_fields = {}
        entity_field_mapping = (
            DEVICE_FIELD_MAPPING
            if entity_name == "devices"
            else {}
        )
        for field_name, field_value in entity_field_mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self._add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        # extract the norm score
        # threatLevelMax possible values: -1, 1, 2, 3
        threat_level = event.get("threatLevelMax")
        if threat_level and (-1 <= int(threat_level) <= 3):
            self._add_field(
                extracted_fields,
                "Netskope Normalized Score",
                self._normalize_risk_score(int(threat_level))
            )
        else:
            total_norm_score_errors += 1

        return extracted_fields, total_norm_score_errors

    def _iterate_insights_with_time_chunks(
        self,
        total_insights: List[dict],
        from_time: datetime,
        to_time: datetime
    ) -> Iterator[Tuple[int, int, str, str]]:
        """
        Iterate through all combinations of insight IDs and time chunks.

        Args:
            insight_ids: List of insight IDs
            from_time: Start of the time range
            to_time: End of the time range

        Yields:
            Tuples of (insight_id, formatted_chunk_start, formatted_chunk_end)
            where times are formatted as "YYYY-MM-DDTHH:MM:SS.mmm"
        """
        if from_time > to_time:
            err_msg = (
                "Invalid start and end times. "
                "Start time cannot be greater than end time."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise InfobloxSOCInsightsPluginException(err_msg)

        # Format a datetime to string in the required format
        def format_datetime(dt: datetime) -> str:
            return dt.strftime(DATE_FORMAT)[:-3]

        # Generate all time chunks with formatted strings
        time_chunks = []
        current = from_time
        min_chunk_size = timedelta(minutes=2)

        while current < to_time:
            next_chunk = current + timedelta(hours=24)
            chunk_end = min(next_chunk, to_time)

            # If the remaining time is less than
            # the minimum chunk size, extend to to_time
            if to_time - chunk_end < min_chunk_size:
                chunk_end = to_time

            time_chunks.append(
                (format_datetime(current), format_datetime(chunk_end))
            )

            current = chunk_end

        # For each insight ID, yield it with each formatted time chunk
        for insight in total_insights:
            page_count = 0
            insight_id = insight.get("insightId", None)
            for chunk_start_str, chunk_end_str in time_chunks:
                page_count += 1
                yield page_count, insight_id, chunk_start_str, chunk_end_str

    def _fetch_devices(
            self,
            base_url: str,
            from_time: datetime,
            to_time: datetime,
            headers: dict
    ) -> List:
        """Fetch devices from Infoblox.

        Args:
            base_url (str): Base URL of Infoblox.
            headers (dict): Headers with API key.

        Returns:
            List: List of devices.
        """
        total_devices = []
        total_insights = []
        api_endpoint = LIST_INSIGHTS_ENDPOINT.format(base_url)
        total_skipped_insights = 0
        total_skipped_devices = 0
        total_norm_score_errors = 0
        self.logger.info(
            f"{self.log_prefix}: Starting to fetch devices from "
            f"{PLATFORM_NAME}."
        )
        try:
            resp_json = self.infoblox_helper.api_helper(
                url=api_endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching all insights "
                    f"from {PLATFORM_NAME}"
                )
            )
            total_insights = resp_json.get("insightList", [])
        except InfobloxSOCInsightsPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occured while fetching insights "
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise InfobloxSOCInsightsPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Fetched {len(total_insights)} insights "
            f"from {PLATFORM_NAME}."
        )
        if not total_insights:
            return []

        for (
            page_count, insight_id, start, end
        ) in self._iterate_insights_with_time_chunks(
            total_insights, from_time, to_time
        ):
            try:
                page_devices_skip_count = 0
                page_devices_count = 0
                api_endpoint = INSIGHT_ASSETS_ENDPOINT.format(
                    base_url, insight_id
                )
                params = {
                    "limit": PAGE_LIMIT,
                    "from": start,
                    "to": end
                }
                resp_json = self.infoblox_helper.api_helper(
                    url=api_endpoint,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"fetching devices from page {page_count} "
                        f"for insight '{insight_id}' "
                        f"from {PLATFORM_NAME}"
                    )
                )
                insight_assets = resp_json.get("assets", [])
                if not insight_assets:
                    self.logger.info(
                        f"{self.log_prefix}: No devices found from page "
                        f"{page_count} of insight '{insight_id}'."
                    )
                    continue
                for asset in insight_assets:
                    try:
                        (
                            extracted_fields,
                            total_norm_score_errors
                        ) = self._extract_entity_fields(
                            event=asset, entity_name="devices",
                            total_norm_score_errors=total_norm_score_errors
                        )
                        if extracted_fields:
                            total_devices.append(extracted_fields)
                            page_devices_count += 1
                        else:
                            page_devices_skip_count += 1
                    except Exception as err:
                        device_id = asset.get("cid", "")
                        err_msg = (
                            "Unable to extract fields from "
                            f"device with ID '{device_id}'."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {err}."
                            ),
                            details=f"Device: {asset}"
                        )
                        page_devices_skip_count += 1

                if page_devices_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped {page_devices_skip_count} "
                        f"device(s) for insight '{insight_id}'."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_devices_count} device record(s) "
                    f"from page {page_count} of insight '{insight_id}'. "
                    f"Total devices fetched: {len(total_devices)}."
                )
                total_skipped_devices += page_devices_skip_count
            except InfobloxSOCInsightsPluginException:
                total_skipped_insights += 1
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while fetching devices for insight '{insight_id}' "
                        f"from {PLATFORM_NAME}. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                total_skipped_insights += 1

        if total_norm_score_errors > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped Netskope Normalized Score"
                f" calculation for {total_norm_score_errors} device(s)"
                f" due to error parsing fields."
            )

        err_msgs = []
        if total_skipped_insights > 0:
            err_msgs.append(f"{total_skipped_insights} insight record(s)")
        if total_skipped_devices > 0:
            err_msgs.append(f"{total_skipped_devices} device record(s)")
        if err_msgs:
            err_msg = " and ".join(err_msgs)
            self.logger.info(
                f"{self.log_prefix}: Skipped {err_msg} "
                "due to some error while fetching."
                "Check logs for more details."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(total_devices)} "
            f"total device record(s) from {PLATFORM_NAME}."
        )
        return total_devices

    def fetch_records(self, entity: str) -> List:
        """Pull Users records from Infoblox SOC Insights.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME}."
        )

        (
            base_url,
            api_key,
            initial_range
        ) = self.infoblox_helper.get_config_params(self.configuration)
        headers = self.infoblox_helper.get_auth_header(
            api_key=api_key
        )
        try:
            if self.last_run_at:
                from_time = self.last_run_at
                self.logger.info(
                    f"{self.log_prefix}: Pulling {entity_name} records from "
                    f"{PLATFORM_NAME} using checkpoint: {from_time}"
                )
            else:
                from_time = datetime.now() - timedelta(
                    days=initial_range
                )
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since "
                    f"checkpoint is empty. Pulling {entity_name} records for "
                    f"last {initial_range} days."
                )
            to_time = datetime.now()
            if entity_name == "devices":
                records.extend(
                    self._fetch_devices(
                        base_url,
                        from_time,
                        to_time,
                        headers
                    )
                )
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} only supports "
                    "Device Entities."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise InfobloxSOCInsightsPluginException(err_msg)
        except InfobloxSOCInsightsPluginException:
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
            raise InfobloxSOCInsightsPluginException(err_msg)
        return records

    def _normalize_risk_score(self, threat_level: int) -> int:
        return RISK_SCORE_MAPPING.get(threat_level)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update devices

        Args:
            entity (str): Type of entity.
            records (list[dict]): List of devices to update.

        Returns:
            List: Updated list of devices.
        """
        return []

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
        """Validate Tanium action configuration.

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

    def _validate_parameter(
        self,
        field_name: str,
        field_value: Union[str, int],
        field_type: type,
        validation_err_msg: str = "Validation error occurred.",
        custom_validation_func: Callable = None,
        custom_error_msg: str = None,
        min_value: int = None,
        max_value: int = None,
    ) -> Optional[ValidationResult]:
        """
        Validate a configuration parameter and 
            return ValidationResult if validation fails.

        Args:
            field_name (str): Name of the configuration field.
            field_value: Value of the configuration field.
            field_type (type): Expected type of the configuration field.
            validation_err_msg (str): Base error message 
                for validation failures.
            custom_validation_func (Callable, optional): Custom validation
                function.
            custom_error_msg (str, optional): Custom error message
                for validation failures.
            min_value (int, optional): Minimum allowed value
                for numeric fields.
            max_value (int, optional): Maximum allowed value
                for numeric fields.

        Returns:
            Optional[ValidationResult]: ValidationResult
                if validation fails, None if passes.
        """

        # Check type and 
        # Custom validation (like URL validation)
        invalid_msg = (
            "Invalid {} provided "
            "in the configuration parameters."
        )
        if (
            not isinstance(field_value, field_type)
            or (
                custom_validation_func
                and not custom_validation_func(field_value)
            )
        ):
            err_msg = invalid_msg.format(field_name)
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Range validation for numeric types
        if (
            field_type is int
            and (min_value is not None or max_value is not None)
        ):
            min_check = min_value is None or field_value >= min_value
            max_check = max_value is None or field_value <= max_value

            if not (min_check and max_check):
                min_str = str(min_value) if min_value is not None else "any"
                max_str = str(max_value) if max_value is not None else "any"
                err_msg = (
                    f"Invalid value for {field_name} provided. "
                    f"Select a value between {min_str} to {max_str}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        # Check if value is empty
        if not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validation passed
        return None

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_err_msg = "Validation error occurred."
        (
            base_url,
            api_key,
            initial_range
        ) = self.infoblox_helper.get_config_params(configuration)

        # Validate Base URL
        if validation_result := self._validate_parameter(
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            validation_err_msg=validation_err_msg,
            custom_validation_func=self._validate_url,
            custom_error_msg=(
                "Invalid Base URL provided in the configuration parameters."
            )
        ):
            return validation_result

        # Validate API key
        if validation_result := self._validate_parameter(
            field_name="API key",
            field_value=api_key,
            field_type=str,
            validation_err_msg=validation_err_msg
        ):
            return validation_result

        # Validate Initial Range
        if validation_result := self._validate_parameter(
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            validation_err_msg=validation_err_msg,
            min_value=1,
            max_value=30,
            custom_error_msg=(
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 to 30."
            )
        ):
            return validation_result

        # Validate connectivity to the Infoblox server.
        return self._validate_connectivity(
            base_url=base_url,
            api_key=api_key
        )

    def _validate_connectivity(
        self, base_url: str, api_key: str
    ) -> ValidationResult:
        """Validate connectivity with Infoblox server.

        Args:
            base_url (str): Base URL.
            api_key (Dict): API key.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )
            headers = self.infoblox_helper.get_auth_header(
                api_key=api_key
            )

            # Device API Endpoint
            device_endpoint = LIST_INSIGHTS_ENDPOINT.format(base_url)

            self.infoblox_helper.api_helper(
                url=device_endpoint,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity for devices "
                    f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"connectivity with {PLATFORM_NAME} server and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message=(
                    "Validation successful."
                ),
            )
        except InfobloxSOCInsightsPluginException as exp:
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

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        valid = False
        try:
            parsed_url = urlparse(url)
            valid = parsed_url.scheme and parsed_url.netloc
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Error: {e}"
            )
        return valid

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(name="Device ID", type=EntityFieldType.STRING),
                    EntityField(name="Device MAC", type=EntityFieldType.STRING),
                    EntityField(name="Device IP", type=EntityFieldType.STRING),
                    EntityField(name="Device Location", type=EntityFieldType.STRING),
                    EntityField(name="Device OS Version", type=EntityFieldType.STRING),
                    EntityField(name="Device Threat Level", type=EntityFieldType.NUMBER),
                    EntityField(name="Device Threat Indicator Count", type=EntityFieldType.NUMBER),
                    EntityField(name="Device Username", type=EntityFieldType.STRING),
                    EntityField(name="Netskope Normalized Score", type=EntityFieldType.NUMBER),
                ]
            )
        ]
