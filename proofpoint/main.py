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

Implementation of Proofpoint CTE plugin.
"""
import traceback
from typing import List, Tuple, Union, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pydantic import ValidationError
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.api import __version__ as CE_VERSION
from packaging import version
from .utils.constants import (
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    SIEM_ALL_ENDPOINT,
    DEFAULT_RESPONSE_FORMAT,
    MAX_HOURS,
    BOUNDARY_SAFETY_SECONDS,
    MIN_QUERY_INTERVAL_SECONDS,
    PAGINATION_INTERVAL_HOURS,
    NON_OVERLAPPING_OFFSET_SECONDS,
    SECONDS_PER_HOUR,
    MAXIMUM_CE_VERSION,
    EVENT_CLICKS_PERMITTED,
    EVENT_CLICKS_BLOCKED,
    EVENT_MESSAGES_DELIVERED,
    EVENT_MESSAGES_BLOCKED,
    VALID_EVENT_TYPES,
    EVENT_TYPE_TAG_MAP,
    DEFAULT_TAG_COLOR,
    VALIDATION_ERROR_MSG,
    AUTH_SUCCESS_MSG,
    AUTH_UNEXPECTED_ERROR_MSG,
    RETRACTION,
)
from .utils.helper import (
    ProofpointPluginHelper,
    ProofpointPluginException,
)

INDICATOR_TYPE_MAP = {
    "url": IndicatorType.URL,
    "attachment": IndicatorType.SHA256,
}

class ProofpointPlugin(PluginBase):
    """The Proofpoint plugin implementation class."""

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
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.proofpoint_helper = ProofpointPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _check_ce_version(self):
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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = ProofpointPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def pull(self) -> List[Indicator]:
        """Pull indicators from Proofpoint."""
        if hasattr(self, "sub_checkpoint"):
            def wrapper(self):
                yield from self._pull()
            return wrapper(self)
        else:
            indicators = []
            try:
                for batch in self._pull():
                    if isinstance(batch, tuple):
                        indicators.extend(batch[0])
                    else:
                        indicators.extend(batch)
            except ProofpointPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while pulling "
                    f"indicators from {PLUGIN_NAME}. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise ProofpointPluginException(err_msg)
            return indicators

    def _pull(
        self,
        is_retraction: bool = False,
        retraction_start_time: datetime = None,
    ):
        """Pull indicators from Proofpoint.

        Args:
            is_retraction (bool, optional): Is this retraction call?
                Defaults to False.
            retraction_start_time (datetime, optional): Start time for
                retraction pull. Defaults to None.

        Yields:
            Tuple|List|set: Tuple of indicator list and checkpoint, or
                indicator list, or set of indicator values for retraction.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        config_params = self.proofpoint_helper.get_config_params(self.configuration)
        end_time = datetime.now()
        threat_status = ["active"]
        supports_sub_checkpoint = (
            hasattr(self, "sub_checkpoint") and not is_retraction
        )
        sub_checkpoint = (
            getattr(self, "sub_checkpoint", {})
            if supports_sub_checkpoint else {}
        )

        def _parse_checkpoint_value(
            checkpoint_value: str
        ) -> Optional[datetime]:
            """Parse checkpoint timestamp into datetime."""
            if not checkpoint_value:
                return None
            try:
                # Strip timezone info after parsing to keep datetimes naive,
                # consistent with end_time = datetime.now() used for comparisons.
                normalized_value = str(checkpoint_value).replace("Z", "+00:00")
                return datetime.fromisoformat(normalized_value).replace(
                    tzinfo=None
                )
            except Exception:
                self.logger.info(
                    f"{self.log_prefix}: Ignoring invalid sub-checkpoint "
                    f"value: {checkpoint_value}."
                )
                return None

        if is_retraction and retraction_start_time:
            start_time = retraction_start_time
        else:
            stored_checkpoint = None
            if isinstance(sub_checkpoint, dict):
                stored_checkpoint = (
                    sub_checkpoint.get("checkpoint")
                )
            start_time = (
                _parse_checkpoint_value(stored_checkpoint)
                if stored_checkpoint else None
            )
            if not start_time:
                start_time = self.last_run_at  # datetime.datetime object.
            if not start_time:
                initial_hours = int(
                    config_params.get("hours")
                )
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since "
                    f"checkpoint is empty. Querying indicators for last "
                    f"{initial_hours} hour(s)."
                )
                start_time = end_time - timedelta(hours=initial_hours)
            else:
                # If the start time is older than MAX_HOURS, the data which is
                # older than MAX_HOURS from current time will be lost because
                # Proofpoint only supports maximum of MAX_HOURS query in past.
                if end_time - start_time > timedelta(hours=MAX_HOURS):
                    self.logger.info(
                        f"{self.log_prefix}: Found checkpoint older than "
                        f"{MAX_HOURS} hours. Fetching the indicators only "
                        f"from last {MAX_HOURS} hours. Indicators older "
                        "than that will not be retrieved."
                    )
                    start_time = end_time - timedelta(hours=MAX_HOURS)
                    
        max_allowed_start = end_time - timedelta(hours=MAX_HOURS)
        if start_time <= max_allowed_start:
            start_time = max_allowed_start + timedelta(
                seconds=BOUNDARY_SAFETY_SECONDS
            )

        if is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators for retraction from "
                f"{PLUGIN_NAME} platform using checkpoint: {str(start_time)}."
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from "
                f"{PLUGIN_NAME} platform using checkpoint: {str(start_time)}."
            )

        total_success = 0
        total_url_count = 0
        total_sha256_count = 0
        total_domain_count = 0
        total_fqdn_count = 0
        interval_start = start_time
        interval_end = min(
            interval_start + timedelta(hours=PAGINATION_INTERVAL_HOURS),
            end_time
        )

        page = 1
        while interval_start < end_time:
            interval_duration = (interval_end - interval_start).total_seconds()
            if interval_duration < MIN_QUERY_INTERVAL_SECONDS:
                interval_start = interval_start - timedelta(
                    seconds=MIN_QUERY_INTERVAL_SECONDS - int(interval_duration)
                )
                interval_duration = MIN_QUERY_INTERVAL_SECONDS
            try:
                if interval_duration >= SECONDS_PER_HOUR:
                    interval = self.proofpoint_helper.get_interval_query(
                        interval_start, interval_end
                    )
                    iocs, ioc_counts = self._fetch_iocs(
                        interval,
                        config_params=config_params,
                        threat_status=threat_status,
                        is_retraction=is_retraction,
                    )
                else:
                    iocs, ioc_counts = self._fetch_iocs(
                        int(interval_duration),
                        config_params=config_params,
                        is_interval=False,
                        threat_status=threat_status,
                        is_retraction=is_retraction,
                    )
            except ProofpointPluginException:
                raise
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while fetching indicators "
                    f"for page {page} from {PLUGIN_NAME}. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise ProofpointPluginException(err_msg)

            batch_success = len(iocs)
            if not is_retraction:
                total_url_count += ioc_counts.get("url", 0)
                total_sha256_count += ioc_counts.get("sha256", 0)
                total_domain_count += ioc_counts.get("domain", 0)
                total_fqdn_count += ioc_counts.get("fqdn", 0)
            total_success += batch_success
            if is_retraction:
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled {batch_success} "
                    f"indicator(s) for page {page} from "
                    f"{PLUGIN_NAME} platform. "
                    f"Total indicator(s) pulled: {total_success}."
                )
            else:
                page_stats = ", ".join(
                    f"{label}: {count}"
                    for label, count in [
                        ("URLs", ioc_counts.get("url", 0)),
                        ("SHA256", ioc_counts.get("sha256", 0)),
                        ("Domains", ioc_counts.get("domain", 0)),
                        ("FQDNs", ioc_counts.get("fqdn", 0)),
                    ]
                    if count > 0
                )
                self.logger.info(
                    f"{self.log_prefix}: Pulled {batch_success}"
                    f" indicator(s) from page {page} of the {PLUGIN_NAME}"
                    f" platform. Pull Stats: {page_stats}. "
                    f"Total indicator(s) pulled - {total_success}."
                )

            if iocs:
                if supports_sub_checkpoint:
                    yield iocs, {"checkpoint": interval_end.isoformat()}
                else:
                    yield iocs

            interval_start = interval_end + timedelta(
                seconds=NON_OVERLAPPING_OFFSET_SECONDS
            )
            interval_end = min(
                interval_start + timedelta(hours=PAGINATION_INTERVAL_HOURS),
                end_time
            )
            page += 1

        if is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled "
                f"{total_success} modified indicator(s) from {PLUGIN_NAME} platform "
                "for retraction."
            )
        else:
            total_stats = ", ".join(
                f"{label}: {count}"
                for label, count in [
                    ("URLs", total_url_count),
                    ("SHA256", total_sha256_count),
                    ("Domains", total_domain_count),
                    ("FQDNs", total_fqdn_count),
                ]
                if count > 0
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled {total_success}"
                f" indicator(s) from {PLUGIN_NAME} platform."
                + (f" Pull Stats: {total_stats}." if total_stats else "")
            )

    def _create_tag(
        self,
        tag_utils: TagUtils,
        tag: str,
        config_params: dict,
        color: str = DEFAULT_TAG_COLOR,
    ) -> List[str]:
        """Create given tag if it not already exist."""
        if config_params.get("enable_tagging") != "yes":
            return []

        try:
            if not tag_utils.exists(tag.strip()):
                tag_utils.create_tag(TagIn(name=tag.strip(), color=color))
            return [tag]
        except ValueError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Value error occurred while "
                    f"creating tag '{tag}'. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while "
                    f"creating tag '{tag}'. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
        return []

    def _parse_click_events(
        self,
        click_events: list,
        event_type: str,
        config_params: dict,
        is_retraction: bool = False,
    ) -> Union[List[Indicator], set]:
        """Parse given list of click events.

        Args:
            click_events (list): List of click events from API response.
            event_type (str): Event type tag label.
            config_params (dict): Configuration parameters dictionary.
            is_retraction (bool, optional): If True, return a set of
                indicator values. Defaults to False.

        Returns:
            Union[List[Indicator], set]: List of Indicator objects or set
                of indicator values for retraction.
        """
        indicators = set() if is_retraction else []
        counts = {"url": 0, "sha256": 0, "domain": 0, "fqdn": 0}
        tag_utils = TagUtils()
        skipped_count = 0
        for click_event in click_events:
            try:
                url_value = click_event.get("url")
                if not url_value:
                    skipped_count += 1
                    continue

                indicator_type = self.proofpoint_helper.determine_indicator_type(url_value)
                indicator_value = url_value

                if is_retraction:
                    indicators.add(indicator_value)
                else:
                    indicators.append(
                        Indicator(
                            value=indicator_value,
                            type=indicator_type,
                            firstSeen=click_event.get("threatTime", None),
                            extendedInformation=click_event.get(
                                "threatURL", ""
                            ),
                            comments=click_event.get("classification", ""),
                            tags=self._create_tag(
                                tag_utils, event_type, config_params
                            ),
                        )
                    )
                    if indicator_type == IndicatorType.URL:
                        counts["url"] += 1
                    elif indicator_type == IndicatorType.SHA256:
                        counts["sha256"] += 1
                    elif indicator_type == getattr(IndicatorType, "DOMAIN", None):
                        counts["domain"] += 1
                    elif indicator_type == getattr(IndicatorType, "FQDN", None):
                        counts["fqdn"] += 1
            except (ValidationError, Exception) as err:
                skipped_count += 1
                error_message = (
                    "Validation error occurred"
                    if isinstance(err, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while "
                        "creating indicator from click event. "
                        "This record will be skipped. "
                        f"Error: {err}."
                    ),
                    details=str(traceback.format_exc()),
                )
        if skipped_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skipped_count} click event "
                f"record(s) from event type '{event_type}' as indicator value "
                "might be empty or due to validation errors."
            )
        return indicators, counts

    def _parse_message_events(
        self,
        message_events: list,
        event_type: str,
        config_params: dict,
        is_retraction: bool = False,
    ) -> Union[List[Indicator], set]:
        """Parse given list of message events.

        Args:
            message_events (list): List of message events from API response.
            event_type (str): Event type tag label.
            config_params (dict): Configuration parameters dictionary.
            is_retraction (bool, optional): If True, return a set of
                indicator values. Defaults to False.

        Returns:
            Union[List[Indicator], set]: List of Indicator objects or set
                of indicator values for retraction.
        """
        indicators = set() if is_retraction else []
        counts = {"url": 0, "sha256": 0, "domain": 0, "fqdn": 0}
        tag_utils = TagUtils()
        skipped_count = 0
        for message_event in message_events:
            for threat_info in message_event.get("threatsInfoMap", []):
                if (
                    threat_info.get("threatType", "").lower()
                    in INDICATOR_TYPE_MAP
                ):
                    try:
                        threat_value = threat_info.get("threat")
                        if not threat_value:
                            skipped_count += 1
                            continue

                        threat_type_lower = (
                            threat_info.get("threatType", "").lower()
                        )
                        indicator_type = (
                            INDICATOR_TYPE_MAP.get(threat_type_lower)
                        )

                        if threat_type_lower == "url":
                            indicator_type = (
                                self.proofpoint_helper.determine_indicator_type(threat_value)
                            )

                        if is_retraction:
                            indicators.add(threat_value)
                        else:
                            indicators.append(
                                Indicator(
                                    value=threat_value,
                                    type=indicator_type,
                                    firstSeen=threat_info.get(
                                        "threatTime", None
                                    ),
                                    extendedInformation=threat_info.get(
                                        "threatUrl", ""
                                    ),
                                    comments=threat_info.get(
                                        "classification", ""
                                    ),
                                    tags=self._create_tag(
                                        tag_utils, event_type, config_params
                                    ),
                                )
                            )
                            if indicator_type == IndicatorType.URL:
                                counts["url"] += 1
                            elif indicator_type == IndicatorType.SHA256:
                                counts["sha256"] += 1
                            elif indicator_type == getattr(IndicatorType, "DOMAIN", None):
                                counts["domain"] += 1
                            elif indicator_type == getattr(IndicatorType, "FQDN", None):
                                counts["fqdn"] += 1
                    except (ValidationError, Exception) as err:
                        skipped_count += 1
                        error_message = (
                            "Validation error occurred"
                            if isinstance(err, ValidationError)
                            else "Unexpected error occurred"
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {error_message} while "
                                "creating indicator from message event. "
                                "This record will be skipped. "
                                f"Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                        )
        if skipped_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skipped_count} message event "
                f"record(s) from event type '{event_type}' as indicator value "
                "might be empty or due to validation errors."
            )
        return indicators, counts

    def _parse_indicators(
        self,
        response: dict,
        config_params: dict,
        is_retraction: bool = False,
    ) -> Union[List[Indicator], set]:
        """Parse the indicators from Proofpoint response JSON.

        Args:
            response (dict): Proofpoint API response dictionary.
            config_params (dict): Configuration parameters dictionary.
            is_retraction (bool, optional): If True, return a
                set of indicator values. Defaults to False.

        Returns:
            Union[List[Indicator], set]: List of Indicator objects or set
                of indicator values for retraction.
        """
        indicators = set() if is_retraction else []
        total_counts = {"url": 0, "sha256": 0, "domain": 0, "fqdn": 0}
        event_types = (
            config_params.get("event_types") or VALID_EVENT_TYPES
        )

        event_handler_map = {
            EVENT_CLICKS_PERMITTED: self._parse_click_events,
            EVENT_CLICKS_BLOCKED: self._parse_click_events,
            EVENT_MESSAGES_DELIVERED: self._parse_message_events,
            EVENT_MESSAGES_BLOCKED: self._parse_message_events,
        }

        for event_type, handler in event_handler_map.items():
            if event_type in event_types:
                parsed_data, batch_counts = handler(
                    response.get(event_type, []),
                    EVENT_TYPE_TAG_MAP.get(event_type, event_type),
                    config_params=config_params,
                    is_retraction=is_retraction,
                )
                if is_retraction:
                    indicators.update(parsed_data)
                else:
                    indicators.extend(parsed_data)
                    for key in total_counts:
                        total_counts[key] += batch_counts.get(key, 0)

        return indicators, total_counts

    def _make_rest_call(
        self, params, config_params, is_validation=False, is_retraction=False
    ):
        """Make REST API call to Proofpoint using given configurations."""
        base_url = config_params.get("base_url", "").strip().rstrip("/")
        url = f"{base_url}{SIEM_ALL_ENDPOINT}"
        return self.proofpoint_helper.api_helper(
            logger_msg=(
                "validating authentication credentials"
                if is_validation
                else "pulling indicators from Proofpoint"
            ),
            url=url,
            method="GET",
            params=params,
            auth=(
                config_params.get("username", ""),
                config_params.get("password", "")
            ),
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_handle_error_required=True,
            is_validation=is_validation,
            is_retraction=is_retraction,
        )

    def _fetch_iocs(
        self,
        query: Union[str, int],
        config_params: dict,
        is_interval: bool = True,
        threat_status: List[str] = None,
        is_retraction: bool = False,
    ) -> Union[List[Indicator], set]:
        """Make REST API call to Proofpoint and fetch all the indicators for
        given time range.

        Args:
            query (Union[str, int]): Either an interval string or
                sinceSeconds integer.
            config_params (dict): Configuration parameters dictionary.
            is_interval (bool, optional): If True, use the interval
                parameter; otherwise use sinceSeconds. Defaults to True.
            threat_status (List[str], optional): List of threat status
                values to filter by (e.g. active, cleared, falsePositive).
                Defaults to None.
            is_retraction (bool, optional): If True, return a set of
                indicator values. Defaults to False.

        Returns:
            Union[List[Indicator], set]: List of Indicator objects or set
                of indicator values for retraction.
        """
        # Build params as list of tuples to support multiple values
        # for the same key (threatStatus).
        params = [("format", DEFAULT_RESPONSE_FORMAT)]
        if is_interval:
            params.append(("interval", query))
        else:
            params.append(("sinceSeconds", query))

        if threat_status:
            for status in threat_status:
                params.append(("threatStatus", status))

        try:
            response_json = self._make_rest_call(
                params, config_params, is_retraction=is_retraction
            )
            iocs, counts = self._parse_indicators(
                response_json, config_params, is_retraction=is_retraction
            )
            return iocs, counts
        except ProofpointPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while fetching indicators "
                f"from {PLUGIN_NAME}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise ProofpointPluginException(err_msg)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, int, list],
        field_type: type,
        allowed_values: list = None,
        allowed_values_display: list = None,
        is_required: bool = False,
        range_validation: bool = False,
        range_values: Tuple[int, int] = None,
        custom_validation_func: callable = None,
        skip_strip: bool = False,
    ) -> Union[ValidationResult, None]:
        """Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, int, list): Value of the configuration field.
            field_type (type): Expected type of the configuration field.
            allowed_values (list, optional): List of allowed values for
                the configuration field. Defaults to None.
            allowed_values_display (list, optional): List of user-friendly
                display names for allowed values. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to False.
            range_validation (bool, optional): Whether to validate range.
                Defaults to False.
            range_values (Tuple[int, int], optional): Range values for
                validation. Defaults to None.
            custom_validation_func (callable, optional): Custom validation
                function to be applied. Defaults to None.
            skip_strip (bool, optional): Whether to skip stripping the value.
                Defaults to False.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not, or None if validation passes.
        """
        # Strip string values except for password fields
        if (
            field_type is str and isinstance(field_value, str)
            and not skip_strip
        ):
            field_value = (
                field_value.strip()
            )
        # Handle integer type conversion and validation
        if field_type is int:
            if isinstance(field_value, str):
                if not field_value.strip():
                    if is_required:
                        err_msg = (
                            f"{field_name} is a required "
                            "configuration parameter."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: "
                                f"{VALIDATION_ERROR_MSG}{err_msg}"
                            ),
                            resolution=(
                                f"Ensure that the field {field_name} "
                                "is not empty."
                            ),
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
                    return None
                try:
                    field_value = int(field_value)
                except (ValueError, TypeError):
                    err_msg = (
                        f"{field_name} must be a valid integer."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: "
                            f"{VALIDATION_ERROR_MSG}{err_msg}"
                        ),
                        resolution=(
                            f"Ensure that the value provided for "
                            f"{field_name} is a valid integer."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
            elif not isinstance(field_value, int):
                err_msg = (
                    f"Invalid value provided for {field_name}. "
                    f"It should be an integer."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: "
                        f"{VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that {field_name} is a valid integer value."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        # Check if required field is empty
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=f"Ensure that the field {field_name} is not empty.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Type validation
        if (field_value and not isinstance(field_value, field_type)) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                f"Invalid value provided for the configuration "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=f"Ensure that {field_name} has a valid value.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Range validation
        if range_validation and range_values:
            if not (
                range_values[0] <= field_value <= range_values[1]
            ):
                err_msg = (
                    f"Invalid value provided for the configuration "
                    f"parameter '{field_name}'. It should be "
                    f"in range {range_values[0]} to {range_values[1]}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that {field_name} is in the range "
                        f"{range_values[0]} to {range_values[1]}."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        # Allowed values validation
        if allowed_values:
            display_values = (
                allowed_values_display
                if allowed_values_display
                else allowed_values
            )
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. "
            )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    details=(
                        f"Allowed values are: "
                        f"{', '.join(str(value) for value in display_values)}."
                    ),
                    resolution=(
                        "Ensure that the value is from the "
                        "allowed values."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type is list:
                if not all(
                    item in allowed_values for item in field_value
                ):
                    allowed_values_str = ', '.join(
                        str(value) for value in display_values
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: "
                            f"{VALIDATION_ERROR_MSG}{err_msg}"
                        ),
                        details=(
                            f"Allowed values are: {allowed_values_str}."
                        ),
                        resolution=(
                            "Ensure that all values are from the "
                            "allowed values."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configurations."""
        config_params = self.proofpoint_helper.get_config_params(configuration)

        if base_url_validation := self._validate_configuration_parameters(
            field_name="Base URL",
            field_value=config_params.get("base_url"),
            field_type=str,
            is_required=True,
            custom_validation_func=self._validate_url,
        ):
            return base_url_validation

        if username_validation := self._validate_configuration_parameters(
            field_name="Username",
            field_value=config_params.get("username"),
            field_type=str,
            is_required=True,
        ):
            return username_validation

        if password_validation := self._validate_configuration_parameters(
            field_name="Password",
            field_value=config_params.get("password"),
            field_type=str,
            is_required=True,
            skip_strip=True,
        ):
            return password_validation

        if hours_validation := self._validate_configuration_parameters(
            field_name="Initial Range (in hours)",
            field_value=config_params.get("hours"),
            field_type=int,
            is_required=True,
            range_validation=True,
            range_values=(1, MAX_HOURS),
        ):
            return hours_validation

        if config_params.get("event_types"):
            if event_types_validation := (
                self._validate_configuration_parameters(
                    field_name="Event Type(s)",
                    field_value=config_params.get("event_types"),
                    field_type=list,
                    is_required=False,
                    allowed_values=VALID_EVENT_TYPES,
                )
            ):
                return event_types_validation

        if enable_tagging_validation := (
            self._validate_configuration_parameters(
                field_name="Enable Tagging",
                field_value=config_params.get("enable_tagging"),
                field_type=str,
                is_required=True,
                allowed_values=["yes", "no"],
            )
        ):
            return enable_tagging_validation

        if config_params.get("retraction_interval") is not None:
            if retraction_validation := (
                self._validate_configuration_parameters(
                    field_name="Retraction Interval (in hours)",
                    field_value=config_params.get("retraction_interval"),
                    field_type=int,
                    is_required=False,
                    range_validation=True,
                    range_values=(1, MAX_HOURS),
                )
            ):
                return retraction_validation

        return self.validate_auth_credentials(configuration)

    def validate_auth_credentials(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the authentication parameters using Proofpoint API call."""
        try:
            config_params = self.proofpoint_helper.get_config_params(configuration)
            self._make_rest_call(
                {"format": DEFAULT_RESPONSE_FORMAT, "sinceSeconds": 1},
                config_params,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                "authentication credentials."
            )
            return ValidationResult(
                success=True, message=AUTH_SUCCESS_MSG
            )
        except ProofpointPluginException as ex:
            return ValidationResult(
                success=False,
                message=str(ex),
            )
        except Exception as ex:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while "
                    "validating authentication credentials. "
                    f"Error: {ex}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the Proofpoint configuration parameters "
                    "and ensure the Proofpoint service is reachable."
                ),
            )
            return ValidationResult(
                success=False,
                message=AUTH_UNEXPECTED_ERROR_MSG,
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate proofpoint configuration."""
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def get_modified_indicators(
        self, source_indicators: List[List[Indicator]],
    ):
        """Get all modified indicators status for retraction.

        This method is called by the CE framework when 'IoC(s) Retraction'
        is enabled. It re-pulls indicators from Proofpoint for the
        configured retraction interval and compares the currently active
        indicator values with the source indicators. Any source indicators
        not found in the re-pulled data are considered retracted.

        Args:
            source_indicators (List[List[Indicator]]): Source Indicators.

        Yields:
            tuple: (list of retracted indicator values, bool status).
                status=True means skip (no retraction), status=False means
                retraction list is valid.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators status"
            f" from {PLUGIN_NAME}."
        )
        config_params = self.proofpoint_helper.get_config_params(self.configuration)
        retraction_interval = config_params.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" for {PLUGIN_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
            return

        retraction_interval = int(retraction_interval)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=retraction_interval)

        # Clamp to MAX_HOURS
        if (end_time - start_time) > timedelta(hours=MAX_HOURS):
            self.logger.info(
                f"{self.log_prefix}: Retraction interval exceeds the "
                f"maximum allowed {MAX_HOURS} hours. Only the last "
                f"{MAX_HOURS} hours of indicators will be considered "
                "for retraction."
            )
            start_time = end_time - timedelta(hours=MAX_HOURS)

        modified_indicators = set()
        for batch in self._pull(
            is_retraction=True,
            retraction_start_time=start_time,
        ):
            modified_indicators.update(batch)

        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                retracted_iocs = iocs - modified_indicators
                self.logger.info(
                    f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) "
                    f"will be marked as retracted from {len(iocs)} total "
                    "indicator(s) present in Cloud Exchange"
                    f" for {PLUGIN_NAME}."
                )
                yield list(retracted_iocs), False
            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while fetching "
                    "modified indicators from "
                    f"{PLUGIN_NAME} for retraction."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )
                raise ProofpointPluginException(err_msg)
