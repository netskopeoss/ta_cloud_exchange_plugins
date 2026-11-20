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

CTE ServiceNow plugin main file.
"""

import re
import traceback
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Generator, List, Set, Tuple, Type, Union
from urllib.parse import urlparse

from pydantic import ValidationError

from netskope.integrations.cte.models import Indicator
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.constants import (
    ALLOWED_FINDINGS,
    ALLOWED_THREAT_TYPES,
    DATE_FORMAT,
    EMPTY_ERROR_MESSAGE,
    INVALID_VALUE_ERROR_MESSAGE,
    MAX_DAYS,
    MAX_RETRACTION_INTERVAL_DAYS,
    MODULE_NAME,
    OBSERVABLE_ENDPOINT,
    OBSERVABLE_FIELDS,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RECORD_URL_PATH,
    RETRACTION,
    SERVICENOW_TO_INDICATOR_TYPE,
    SOURCE_LABEL,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exception import ServiceNowPluginException
from .utils.helper import ServiceNowPluginHelper


class ServiceNowPlugin(PluginBase):
    """ServiceNow CTE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """ServiceNow plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.servicenow_helper = ServiceNowPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest metadata.

        Returns:
            Tuple[str, str]: Plugin name and version.
        """
        try:
            manifest_json = ServiceNowPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get(
                "version", PLUGIN_VERSION
            )
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred"
                    f" while getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_storage(self) -> Dict:
        """Safely access the plugin storage dict.

        Returns:
            Dict: Storage dict, or empty dict if storage is None.
        """
        return self.storage if self.storage is not None else {}

    def _validate_url(self, url: str) -> bool:
        """Validate that a URL has both a scheme and a network
        location.

        Args:
            url (str): URL string to validate.

        Returns:
            bool: True if valid URL; False otherwise.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
        )

    def _validate_configuration_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type: Type,
        allowed_values: Union[Set, List] = None,
        custom_validation_func: Callable = None,
        should_strip_str: bool = True,
    ):
        """Validate a single configuration or action parameter.

        Args:
            parameter_type (str): "configuration" or "action".
            field_name (str): Human-readable field name.
            field_value: Value to validate.
            field_type (Type): Expected Python type.
            allowed_values: Optional set/list of allowed values.
            custom_validation_func: Optional callable returning bool.
            should_strip_str (bool): Strip string before checks.

        Returns:
            ValidationResult if invalid; None if valid.
        """
        if isinstance(field_value, str) and should_strip_str:
            field_value = field_value.strip()
        if not field_value and field_value != 0:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Ensure that some value is provided for field"
                    f" '{field_name}'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type) or (
            custom_validation_func
            and not custom_validation_func(field_value)
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided for"
                    f" '{field_name}' field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if allowed_values and field_value not in allowed_values:
            allowed_str = ", ".join(
                f"'{v}'" for v in allowed_values
            )
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_str
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided from the"
                    f" allowed values.\nAllowed values: {allowed_str}"
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_multichoice_field(
        self,
        field_name: str,
        values: List[str],
        allowed_values: List[str],
    ) -> Union[ValidationResult, None]:
        """Validate a multichoice configuration parameter's values.

        Args:
            field_name (str): Human-readable field name.
            values (List[str]): Submitted values to validate.
            allowed_values (List[str]): Allowed values for this field.

        Returns:
            ValidationResult if invalid; None if valid.
        """
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name=field_name,
            field_value=values,
            field_type=list,
        ):
            return validation_result
        for value in values:
            if value not in allowed_values:
                allowed_str = ", ".join(
                    f"'{v}'" for v in allowed_values
                )
                err_msg = (
                    "Invalid value provided for the configuration"
                    f" parameter '{field_name}'."
                    f"{INVALID_VALUE_ERROR_MESSAGE.format(allowed_values=allowed_str)}"  # noqa: E501
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}:"
                        f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                    ),
                    resolution=(
                        "Ensure that values are selected from the"
                        " allowed list."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_days_range(
        self, field_name: str, value: int, max_days: int
    ) -> Union[ValidationResult, None]:
        """Validate that a days-based parameter is within range.

        Args:
            field_name (str): Human-readable field name.
            value (int): Submitted value to range-check.
            max_days (int): Upper bound allowed for this field.

        Returns:
            ValidationResult if invalid; None if valid.
        """
        if value < 1 or value > max_days:
            err_msg = f"{field_name} must be between 1 and {max_days}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} is within the"
                    " allowed range."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_connectivity(
        self, configuration: dict, username: str, password: str
    ) -> ValidationResult:
        """Validate connectivity and credentials against ServiceNow.

        Must be called last in validate(), after all other
        configuration parameters have passed validation.

        Args:
            configuration (dict): Configuration parameters dict.
            username (str): Validated ServiceNow username.
            password (str): Validated ServiceNow password.

        Returns:
            ValidationResult: Result of the connectivity check.
        """
        try:
            self.servicenow_helper.api_helper(
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME}"
                ),
                url=self.servicenow_helper.build_url(
                    OBSERVABLE_ENDPOINT, configuration
                ),
                method="GET",
                params={"sysparm_limit": 1},
                auth=(username, password),
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=True,
                is_retraction=False,
            )
        except ServiceNowPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred"
                    f" while validating connectivity with"
                    f" {PLATFORM_NAME}. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters are"
                    " valid."
                ),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Unexpected error occurred. Check logs for more"
                    " details."
                ),
            )

        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True,
            message=(
                f"Successfully validated connectivity with"
                f" {PLATFORM_NAME}."
            ),
        )

    # ----------------------------------------------------------------
    # PULL FLOW
    # ----------------------------------------------------------------

    def _build_sysparm_query(
        self,
        threat_type: List[str],
        finding: List[str],
        start_time: datetime,
        end_time: datetime = None,
    ) -> str:
        """Build the ServiceNow sysparm_query string.

        Args:
            threat_type (List[str]): Selected threat type values.
            finding (List[str]): Selected finding values.
            start_time (datetime): Window start (exclusive lower
                bound on sys_updated_on).
            end_time (datetime, optional): Window end (exclusive
                upper bound on sys_updated_on). Omitted for the
                retraction re-query, which has no upper bound.

        Returns:
            str: The constructed sysparm_query value.
        """
        query = f"sys_updated_on>{start_time.strftime(DATE_FORMAT)}"
        if end_time is not None:
            query += f"^sys_updated_on<{end_time.strftime(DATE_FORMAT)}"
        if threat_type:
            query += "^" + "^OR".join(
                f"type.value={t}" for t in threat_type
            )
        if finding:
            query += f"^findingIN{','.join(finding)}"
        query += "^ORDERBYsys_updated_on"
        return query

    def _resolve_pull_start_time(
        self, storage: Dict, end_time: datetime
    ) -> datetime:
        """Resolve the pull window start time.

        Checkpoint priority: sub_checkpoint -> storage checkpoint ->
        last_run_at -> now - days.

        Args:
            storage (Dict): Plugin storage dict.
            end_time (datetime): Window end, used to compute the
                initial-range fallback.

        Returns:
            datetime: Resolved start time.
        """
        sub_checkpoint = getattr(self, "sub_checkpoint", {}) or {}
        checkpoint_value = sub_checkpoint.get("pull_checkpoint")
        if not checkpoint_value:
            checkpoint_value = storage.get("checkpoints", {}).get(
                "pull_checkpoint"
            )

        if checkpoint_value:
            try:
                return datetime.strptime(
                    checkpoint_value, DATE_FORMAT
                )
            except (ValueError, TypeError):
                pass

        if self.last_run_at:
            return self.last_run_at

        days = int(self.configuration.get("days", 7))
        self.logger.info(
            f"{self.log_prefix}: This is an initial data pull since"
            " a checkpoint is not available. Querying observable(s)"
            f" for the last {days} day(s)."
        )
        return end_time - timedelta(days=days)

    def _pull(
        self, is_retraction: bool = False
    ) -> Generator[Tuple[List, Dict], None, None]:
        """Internal pull generator yielding indicator batches.

        Args:
            is_retraction (bool): When True, re-query the active set
                for the retraction window instead of the normal pull
                window. Defaults to False.

        Yields:
            Tuple[List, Dict]: Batch of indicators (or active values
                during retraction) and a checkpoint dict.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"

        storage = self._get_storage()
        threat_type = self.configuration.get("threat_type", [])
        finding = self.configuration.get("finding", [])
        end_time = datetime.now(timezone.utc).replace(tzinfo=None)

        if is_retraction:
            retraction_interval = int(
                self.configuration.get("retraction_interval")
            )
            start_time = end_time - timedelta(days=retraction_interval)
            query = self._build_sysparm_query(
                threat_type, finding, start_time
            )
        else:
            current_hash = self.servicenow_helper.get_config_hash(
                self.configuration
            )
            if storage.get("config_hash") != current_hash:
                storage["checkpoints"] = {}
            storage["config_hash"] = current_hash

            start_time = self._resolve_pull_start_time(
                storage, end_time
            )
            query = self._build_sysparm_query(
                threat_type, finding, start_time, end_time
            )

        offset = 0
        page_count = 0
        total_pulled = 0
        total_skipped = 0
        retraction_seen = set()
        auth = self.servicenow_helper.get_auth(self.configuration)
        url = self.servicenow_helper.build_url(
            OBSERVABLE_ENDPOINT, self.configuration
        )

        while True:
            page_count += 1
            params = {
                "sysparm_query": query,
                "sysparm_limit": PAGE_SIZE,
                "sysparm_offset": offset,
                "sysparm_fields": OBSERVABLE_FIELDS,
            }
            logger_msg = (
                f"pulling observable(s) page {page_count} from"
                f" {PLATFORM_NAME}"
            )
            try:
                response = self.servicenow_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="GET",
                    params=params,
                    auth=auth,
                    proxy=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=False,
                    is_validation=False,
                    is_retraction=is_retraction,
                )
            except ServiceNowPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" {logger_msg}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                break
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        f" occurred while {logger_msg}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                break

            try:
                total_count = int(
                    response.headers.get("X-Total-Count", 0)
                )
            except (TypeError, ValueError):
                total_count = 0

            try:
                parsed = self.servicenow_helper.handle_error(
                    response, logger_msg, is_validation=False
                )
            except ServiceNowPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" parsing response for {logger_msg}."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                break

            results = parsed.get("result", [])
            if not results:
                break

            if is_retraction:
                active_values = []
                for record in results:
                    value = record.get("value")
                    if value and value not in retraction_seen:
                        retraction_seen.add(value)
                        active_values.append(value)
                total_pulled += len(active_values)
                self.logger.info(
                    f"{self.log_prefix}: Pulled"
                    f" {len(active_values)} active observable(s) in"
                    f" page {page_count}. Total active observable(s)"
                    f" pulled: {total_pulled}."
                )
                yield active_values, {}
            else:
                indicators_batch, skip_count = self._build_indicators(
                    results
                )
                total_pulled += len(indicators_batch)
                total_skipped += skip_count

                checkpoint = {}
                last_updated = results[-1].get("sys_updated_on")
                if last_updated:
                    storage.setdefault("checkpoints", {})[
                        "pull_checkpoint"
                    ] = last_updated
                    checkpoint = {"pull_checkpoint": last_updated}

                page_log = (
                    f"{self.log_prefix}: Pulled"
                    f" {len(indicators_batch)} indicator(s) in page"
                    f" {page_count}. Total indicator(s) pulled:"
                    f" {total_pulled}."
                )
                if skip_count:
                    page_log += (
                        f" Skipped {skip_count} indicator(s)."
                    )
                self.logger.info(page_log)

                yield indicators_batch, checkpoint

            offset += PAGE_SIZE
            if offset >= total_count:
                break

        if is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled"
                f" {total_pulled} active observable(s) from"
                f" {PLATFORM_NAME} for retraction."
            )
        else:
            completion_log = (
                f"{self.log_prefix}: Successfully pulled"
                f" {total_pulled} indicator(s) from {PLATFORM_NAME}."
            )
            if total_skipped:
                completion_log += (
                    f" Skipped {total_skipped} indicator(s)."
                )
            self.logger.info(completion_log)

    def pull(self):
        """Pull indicators from ServiceNow.

        Returns:
            List[Indicator]: Pulled indicators, or generator when
                sub_checkpoint is present.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", "Yes"
        )
        if is_pull_required != "Yes":
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in the"
                " configuration parameters. Skipping pulling of"
                f" indicator(s) from {PLATFORM_NAME}."
            )
            return []

        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)

        indicators = []
        for batch, _ in self._pull():
            indicators.extend(batch)
        self.logger.info(
            f"{self.log_prefix}: Total {len(indicators)} indicator(s)"
            f" pulled from {PLATFORM_NAME}."
        )
        return indicators

    def _create_tags(self, tags: List[str]) -> List[str]:
        """Create tags in CE if they do not already exist.

        Args:
            tags (List[str]): Tag names to create.

        Returns:
            List[str]: Tag names successfully created or already
                existing in CE.
        """
        tag_utils = TagUtils()
        created_tags = []
        for tag in tags:
            tag_name = tag.strip() if tag else ""
            if not tag_name:
                continue
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(
                        TagIn(name=tag_name, color="#ED3347")
                    )
                created_tags.append(tag_name)
            except ValueError:
                self.logger.debug(
                    f"{self.log_prefix}: Skipped tag '{tag_name}'"
                    " as it could not be created in CE."
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        f" occurred while creating tag '{tag_name}'."
                        f" Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
        return created_tags

    def _build_indicators(
        self, results: List[Dict]
    ) -> Tuple[List[Indicator], int]:
        """Build CE Indicator objects from ServiceNow observable
        records.

        Args:
            results (List[Dict]): Raw observable records from the
                ServiceNow Table API.

        Returns:
            Tuple[List[Indicator], int]: Indicators and skip count.
        """
        indicators = []
        skip_count = 0
        instance_url = (
            self.configuration.get("url", "").strip().rstrip("/")
        )

        for record in results:
            value = record.get("value")
            if not value:
                skip_count += 1
                continue

            notes = record.get("notes") or ""
            if SOURCE_LABEL in notes:
                # This observable was created by this plugin's own
                # push. Skip it on pull to avoid a push -> pull ->
                # push cycle.
                skip_count += 1
                continue

            type_value = record.get("type.value")
            indicator_type = SERVICENOW_TO_INDICATOR_TYPE.get(
                type_value
            )
            if indicator_type is None:
                skip_count += 1
                continue

            finding = record.get("finding", "")
            tags = (
                self._create_tags([f"ServiceNow-{finding}"])
                if finding
                else []
            )

            sys_id = record.get("sys_id", "")
            extended_info = (
                f"{instance_url}{RECORD_URL_PATH}{sys_id}"
                if sys_id
                else None
            )

            first_seen = self._parse_servicenow_datetime(
                record.get("sys_created_on")
            )
            last_seen = self._parse_servicenow_datetime(
                record.get("sys_updated_on")
            )

            try:
                indicator = Indicator(
                    value=value,
                    type=indicator_type,
                    comments=notes,
                    firstSeen=first_seen,
                    lastSeen=last_seen,
                    tags=tags,
                    extendedInformation=extended_info,
                )
                indicators.append(indicator)
            except ValidationError as err:
                skip_count += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error"
                        f" occurred while creating indicator for"
                        f" '{value}'. Skipping. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
            except Exception as err:
                skip_count += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        f" occurred while creating indicator for"
                        f" '{value}'. Skipping. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )

        return indicators, skip_count

    def _parse_servicenow_datetime(self, value: str):
        """Parse a ServiceNow datetime string as UTC.

        Args:
            value (str): Datetime string in DATE_FORMAT.

        Returns:
            datetime or None: Parsed UTC datetime, or None if the
                value is missing or malformed.
        """
        if not value:
            return None
        try:
            return datetime.strptime(value, DATE_FORMAT).replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return None

    # ----------------------------------------------------------------
    # PULL RETRACTION
    # ----------------------------------------------------------------

    def get_modified_indicators(
        self, source_indicators: List[List[Indicator]]
    ) -> Generator[Tuple[list, bool], None, None]:
        """Yield indicators that should be retracted in CE.

        Args:
            source_indicators (List[List[Indicator]]): Pages of
                indicators currently stored in CE for this
                configuration.

        Yields:
            Tuple[list, bool]: List of indicator values to retract
                and a completion/skip flag.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"

        retraction_interval = self.configuration.get(
            "retraction_interval"
        )
        if not (
            retraction_interval
            and isinstance(retraction_interval, int)
        ):
            self.logger.info(
                f"{self.log_prefix}: Retraction Interval is not"
                " configured. Skipping pull retraction of"
                f" indicator(s) for {PLATFORM_NAME}."
            )
            yield [], True
            return

        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators"
            f" from {PLATFORM_NAME}."
        )

        active_values = set()
        for batch, _ in self._pull(is_retraction=True):
            active_values.update(batch)

        self.logger.info(
            f"{self.log_prefix}: Pulled {len(active_values)} active"
            f" indicator(s) from {PLATFORM_NAME}."
        )

        batch_number = 0
        total_source = 0
        total_to_retract = 0
        for indicator_list in source_indicators:
            batch_number += 1
            source_values = set(ind.value for ind in indicator_list)
            source_total = len(source_values)
            to_retract = source_values - active_values
            total_source += source_total
            total_to_retract += len(to_retract)
            self.logger.info(
                f"{self.log_prefix}: "
                f"{len(to_retract)} indicator(s) will be marked as"
                f" retracted out of total {source_total}"
                f" indicator(s) from batch {batch_number}."
            )
            yield list(to_retract), False

        self.logger.info(
            f"{self.log_prefix}: Total {total_to_retract} indicator(s) "
            f"marked as retracted out of total {total_source} indicator(s)"
            f" across {batch_number} batch(es)."
        )

    # ----------------------------------------------------------------
    # PUSH FLOW
    # ----------------------------------------------------------------

    def _check_observable_exists(self, value: str) -> bool:
        """Check whether an observable with the given value already
        exists in ServiceNow.

        Args:
            value (str): Indicator value to check.

        Returns:
            bool: True if a matching observable exists.
        """
        response = self.servicenow_helper.api_helper(
            logger_msg=(
                f"checking existence of observable '{value}' on"
                f" {PLATFORM_NAME}"
            ),
            url=self.servicenow_helper.build_url(
                OBSERVABLE_ENDPOINT, self.configuration
            ),
            method="GET",
            params={"sysparm_query": f"value={value}"},
            auth=self.servicenow_helper.get_auth(self.configuration),
            proxy=self.proxy,
            verify=self.ssl_validation,
            is_handle_error_required=True,
            is_validation=False,
            is_retraction=False,
        )
        return bool(response.get("result", []))

    def _push_indicators(
        self, indicators: List[Indicator], plugin_name: str = None
    ) -> Tuple[int, int, int, List[str]]:
        """Share indicators to ServiceNow one at a time.

        Args:
            indicators (List[Indicator]): Indicators to push.
            plugin_name (str): Name of the source plugin the
                indicator(s) originated from, as resolved by CE core.
                The bare source label is used when CE core does not
                supply it, matching the convention used by other CTE
                plugins.

        Returns:
            Tuple[int, int, int, List[str]]: (success_count,
                failed_count, skipped_existing_count, failed
                indicator values).
        """
        success_count = 0
        failed_count = 0
        skipped_existing_count = 0
        failed_iocs = []
        source_label = (
            f"{SOURCE_LABEL} | {plugin_name}"
            if plugin_name
            else SOURCE_LABEL
        )

        for indicator in indicators:
            try:
                if self._check_observable_exists(indicator.value):
                    skipped_existing_count += 1
                    failed_iocs.append(indicator.value)
                    self.logger.debug(
                        f"{self.log_prefix}: Observable"
                        f" '{indicator.value}' already exists on"
                        f" {PLATFORM_NAME}. Skipping creation."
                    )
                    continue

                comments = getattr(indicator, "comments", "") or ""
                notes = (
                    f"{source_label} | {comments}"
                    if comments
                    else source_label
                )
                body = {
                    "value": indicator.value,
                    "notes": notes,
                }
                self.servicenow_helper.api_helper(
                    logger_msg=(
                        f"creating observable '{indicator.value}'"
                        f" on {PLATFORM_NAME}"
                    ),
                    url=self.servicenow_helper.build_url(
                        OBSERVABLE_ENDPOINT, self.configuration
                    ),
                    method="POST",
                    json=body,
                    auth=self.servicenow_helper.get_auth(
                        self.configuration
                    ),
                    proxy=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=True,
                    is_validation=False,
                    is_retraction=False,
                )
                success_count += 1
            except ServiceNowPluginException as err:
                failed_count += 1
                failed_iocs.append(indicator.value)
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" sharing observable '{indicator.value}' to"
                        f" {PLATFORM_NAME}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
            except Exception as err:
                failed_count += 1
                failed_iocs.append(indicator.value)
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        " occurred while sharing observable"
                        f" '{indicator.value}'. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
        return (
            success_count,
            failed_count,
            skipped_existing_count,
            failed_iocs,
        )

    def push(
        self,
        indicators: List[Indicator],
        action_dict: dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Share indicators to the ServiceNow Observables table.

        Args:
            indicators (List[Indicator]): Indicators to push.
            action_dict (dict): Action configuration from CE.
            source (str): Source configuration name from CE core.
            business_rule (str): Business rule name from CE core.
            plugin_name (str): Name of the source plugin the
                indicator(s) originated from, as resolved by CE core.

        Returns:
            PushResult: Result of push operation.
        """
        action_label = action_dict.get("label", "Share Indicators")
        self.logger.info(
            f"{self.log_prefix}: Executing push for '{action_label}'"
            " action."
        )

        supported_types = set(SERVICENOW_TO_INDICATOR_TYPE.values())

        # The 'Type of Threat Data to Pull' parameter only scopes the
        # pull-side query (see `_build_sysparm_query`). Sharing is not
        # restricted by it -- any indicator of a type ServiceNow can
        # accept is pushed regardless of the configured filter.
        valid_indicators = []
        skip_count = 0
        for indicator in indicators:
            if indicator.type not in supported_types:
                skip_count += 1
            else:
                valid_indicators.append(indicator)
        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                " indicator(s) as their type is not supported by"
                f" {PLATFORM_NAME}."
            )

        success_count, failed_count, skipped_existing_count, failed_iocs = (
            self._push_indicators(valid_indicators, plugin_name)
        )

        push_summary = (
            f"{self.log_prefix}: Successfully shared"
            f" {success_count} indicator(s) to {PLATFORM_NAME}."
        )
        if failed_count:
            push_summary += (
                f" Failed to share {failed_count} indicator(s)."
            )
        if skipped_existing_count:
            push_summary += (
                f" Skipped {skipped_existing_count} indicator(s)"
                f" as they already exist on {PLATFORM_NAME} or have "
                "invalid value(s)."
            )
        self.logger.info(push_summary)

        return PushResult(
            success=True,
            message=f"Successfully executed '{action_label}' action.",
            failed_iocs=failed_iocs,
        )

    # ----------------------------------------------------------------
    # PUSH RETRACTION
    # ----------------------------------------------------------------

    def _resolve_sys_id(self, indicator: Indicator) -> Union[str, None]:
        """Resolve the ServiceNow sys_id for an indicator this plugin
        created, verifying ownership before returning it.

        Primary: parse `sys_id=<...>` from extendedInformation (only
        ever set by this plugin's own pull, so inherently owned).
        Fallback: GET by value and confirm SOURCE_LABEL is present in
        the record's `notes` before trusting the match -- otherwise
        the value may belong to a customer-created observable, or one
        this plugin only ever pulled and never shared.

        Args:
            indicator (Indicator): Indicator to resolve.

        Returns:
            Union[str, None]: Resolved sys_id, or None if not found
                or not owned by this plugin.
        """
        extended_info = getattr(
            indicator, "extendedInformation", ""
        ) or ""
        match = re.search(r"sys_id=([0-9a-fA-F]+)", extended_info)
        if match:
            return match.group(1)

        try:
            response = self.servicenow_helper.api_helper(
                logger_msg=(
                    f"resolving sys_id for '{indicator.value}' from"
                    f" {PLATFORM_NAME}"
                ),
                url=self.servicenow_helper.build_url(
                    OBSERVABLE_ENDPOINT, self.configuration
                ),
                method="GET",
                params={
                    "sysparm_query": f"value={indicator.value}",
                    "sysparm_fields": "sys_id,notes",
                },
                auth=self.servicenow_helper.get_auth(
                    self.configuration
                ),
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=False,
                is_retraction=True,
            )
        except ServiceNowPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" resolving sys_id for '{indicator.value}'."
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return None
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred"
                    f" while resolving sys_id for"
                    f" '{indicator.value}'. Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return None

        results = response.get("result", [])
        if not results:
            return None

        notes = results[0].get("notes") or ""
        if SOURCE_LABEL not in notes:
            self.logger.info(
                f"{self.log_prefix}: Observable '{indicator.value}'"
                f" on {PLATFORM_NAME} was not created by this"
                " plugin. Skipping deletion to avoid removing"
                " unrelated data."
            )
            return None
        return results[0].get("sys_id")

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[dict],
    ) -> Generator[ValidationResult, None, None]:
        """Delete previously shared observables from ServiceNow.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Batches of indicators to retract.
            list_action_dict (List[dict]): Action configuration(s)
                from CE.

        Yields:
            ValidationResult: Result of the retraction operation.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"

        enable_push_retraction = self.configuration.get(
            "enable_push_retraction", "No"
        )
        if enable_push_retraction != "Yes":
            self.logger.info(
                f"{self.log_prefix}: Push retraction is disabled in"
                " the configuration parameters. Skipping push"
                f" retraction of indicator(s) for {PLATFORM_NAME}."
            )
            yield ValidationResult(
                success=False,
                disabled=True,
                message=(
                    "Push retraction is disabled in the"
                    " configuration parameters. Skipping push"
                    " retraction."
                ),
            )
            return

        self.logger.info(
            f"{self.log_prefix}: Starting retraction of"
            f" indicator(s) from {PLATFORM_NAME}."
        )

        supported_types = list(SERVICENOW_TO_INDICATOR_TYPE.values())
        success_count = 0
        failed_count = 0
        skip_count = 0

        for indicator_list in retracted_indicators_lists:
            for indicator in indicator_list:
                if indicator.type not in supported_types:
                    skip_count += 1
                    continue

                sys_id = self._resolve_sys_id(indicator)
                if not sys_id:
                    skip_count += 1
                    continue

                try:
                    self.servicenow_helper.api_helper(
                        logger_msg=(
                            f"deleting observable"
                            f" '{indicator.value}' from"
                            f" {PLATFORM_NAME}"
                        ),
                        url=self.servicenow_helper.build_url(
                            f"{OBSERVABLE_ENDPOINT}/{sys_id}",
                            self.configuration,
                        ),
                        method="DELETE",
                        auth=self.servicenow_helper.get_auth(
                            self.configuration
                        ),
                        proxy=self.proxy,
                        verify=self.ssl_validation,
                        is_handle_error_required=True,
                        is_validation=False,
                        is_retraction=True,
                    )
                    success_count += 1
                except ServiceNowPluginException as err:
                    failed_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred"
                            " while deleting observable"
                            f" '{indicator.value}' from"
                            f" {PLATFORM_NAME}. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                    )
                except Exception as err:
                    failed_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error"
                            " occurred while deleting observable"
                            f" '{indicator.value}'. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                    )

        self.logger.info(
            f"{self.log_prefix}: Successfully deleted"
            f" {success_count} observable(s) from {PLATFORM_NAME}."
            f" Failed to delete {failed_count} observable(s)."
            f" Skipped {skip_count} observable(s)."
        )

        yield ValidationResult(
            success=True, message="Push retraction completed."
        )

    # ----------------------------------------------------------------
    # ACTION DEFINITIONS
    # ----------------------------------------------------------------

    def get_actions(self) -> List[ActionWithoutParams]:
        """Return list of supported push actions.

        Returns:
            List[ActionWithoutParams]: Supported actions.
        """
        return [
            ActionWithoutParams(
                label="Share Indicators", value="share"
            )
        ]

    def get_action_fields(self, action: Action) -> List[dict]:
        """Return parameter fields for the given action.

        Args:
            action (Action): Selected push action.

        Returns:
            List[dict]: Empty list; the "Share Indicators" action
                takes no parameters.
        """
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action parameters.

        Args:
            action (Action): Action to validate.

        Returns:
            ValidationResult: Validation result.
        """
        if action.value not in ["share"]:
            return ValidationResult(
                success=False,
                message=(
                    f"Unsupported action '{action.value}' provided."
                    " Supported action is 'Share Indicators'."
                ),
            )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    # ----------------------------------------------------------------
    # CONFIGURATION VALIDATION
    # ----------------------------------------------------------------

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate plugin configuration parameters.

        Args:
            configuration (dict): Configuration parameters dict.

        Returns:
            ValidationResult: Validation result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration"
            " parameters."
        )

        url = configuration.get("url", "").strip().rstrip("/")
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="ServiceNow Instance URL",
            field_value=url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_result

        username = configuration.get("username", "").strip()
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Username",
            field_value=username,
            field_type=str,
        ):
            return validation_result

        password = configuration.get("password")
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Password",
            field_value=password,
            field_type=str,
            should_strip_str=False,
        ):
            return validation_result

        threat_type = configuration.get("threat_type", [])
        if threat_type:
            if validation_result := self._validate_multichoice_field(
                "Type of Threat Data to Pull",
                threat_type,
                ALLOWED_THREAT_TYPES,
            ):
                return validation_result

        finding = configuration.get("finding", [])
        if finding:
            if validation_result := self._validate_multichoice_field(
                "Type of Finding to Pull", finding, ALLOWED_FINDINGS
            ):
                return validation_result

        is_pull_required = (
            configuration.get("is_pull_required", "").strip()
        )
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return validation_result

        enable_push_retraction = (
            configuration.get("enable_push_retraction", "").strip()
        )
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Enable Push Retraction",
            field_value=enable_push_retraction,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return validation_result

        retraction_interval = configuration.get("retraction_interval")
        if (
            retraction_interval is not None
            and str(retraction_interval).strip() != ""
        ):
            if validation_result := (
                self._validate_configuration_parameters(
                    parameter_type="configuration",
                    field_name="Retraction Interval (in days)",
                    field_value=retraction_interval,
                    field_type=int,
                    should_strip_str=False,
                )
            ):
                return validation_result
            if validation_result := self._validate_days_range(
                "Retraction Interval (in days)",
                retraction_interval,
                MAX_RETRACTION_INTERVAL_DAYS,
            ):
                return validation_result

        days = configuration.get("days")
        if validation_result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Initial Range (in days)",
            field_value=days,
            field_type=int,
            should_strip_str=False,
        ):
            return validation_result
        if validation_result := self._validate_days_range(
            "Initial Range (in days)", days, MAX_DAYS
        ):
            return validation_result

        # Connectivity check (must be last).
        return self._validate_connectivity(
            configuration, username, password
        )
