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

TrendAI Vision One Plugin to push and pull data from the TrendAI Vision One
Platform.
"""

import ipaddress
import json
import re
import traceback
from datetime import datetime, timedelta
from typing import Callable, Dict, Generator, List, Set, Tuple, Type, Union
from urllib.parse import urlparse

from pydantic import ValidationError

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
)

from .utils.trend_micro_helper import (
    TrendMicroPluginHelper,
    TrendMicroPluginException,
    MaximumLimitExceededException,
)

from .utils.trend_micro_constant import (
    BASE_URL_FIELD,
    CUSTOM_REGION,
    DATA_REGIONS,
    DATE_FORMAT_FOR_IOCS,
    EMPTY_ERROR_MESSAGE,
    ENABLE_PUSH_RETRACTION_FIELD,
    INDICATOR_TYPES,
    INITIAL_RANGE_FIELD,
    INTERNAL_SEVERITY_TO_TRENDMICRO,
    INVALID_VALUE_ERROR_MESSAGE,
    IS_PULL_REQUIRED_FIELD,
    LEGACY_SOURCE_LABEL,
    MAX_DESCRIPTION_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_INITIAL_RANGE_DAYS,
    MAX_IP_LENGTH,
    MAX_PAYLOAD_BYTES,
    MAX_RETRACTION_INTERVAL_DAYS,
    MAX_URL_LENGTH,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    RETRACTION_BATCH,
    RETRACTION_INTERVAL_FIELD,
    SHA256_LENGTH,
    SOURCE_LABEL,
    SUSPICIOUS_OBJECT_BATCH_SIZE,
    SUSPICIOUS_OBJECT_EXCEPTION_BATCH_SIZE,
    TOKEN_FIELD,
    TRENDMICRO_TO_INTERNAL_SEVERITY,
    TRENDMICRO_TO_INTERNAL_TYPE,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)


def check_url_domain_ip(type):
    """Categorize a bare URL-typed value as Domain, IP or URL.

    Fallback for indicators that arrive as the generic
    IndicatorType.URL but are actually a bare domain or IP string.
    Indicators that already carry a specific IndicatorType (DOMAIN,
    IPV4, IPV6) skip this entirely - see prepare_payload().
    """
    regex_domain = (
        "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    )
    try:
        ipaddress.ip_address(type)
        return "ip"
    except Exception:
        if re.search(regex_domain, type):
            return "domain"
        else:
            return "url"


class TrendMicroPlugin(PluginBase):
    """TrendAI Vision One Plugin class for pulling and pushing threat
    indicators."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.retraction_batch = RETRACTION_BATCH
        self.trend_micro_helper = TrendMicroPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version read from manifest.
        """
        try:
            manifest_json = TrendMicroPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}."
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        The Data Region choice's value IS the API host URL itself for
        every fixed region; only "Custom Region" needs the separate,
        dynamically-populated Base URL field (see get_dynamic_fields).

        A configuration saved before 2.0.0 has no "data_region" key at
        all - it stored the selected region's host directly under
        "base_url". Treating an empty/absent data_region alongside a
        present base_url as this legacy shape lets such a
        configuration keep working after upgrade without forcing an
        immediate reconfigure; saving the configuration again always
        selects a real Data Region and this fallback stops applying.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL and Authentication Token.
        """
        data_region = (configuration.get("data_region") or "").strip()
        base_url_cfg = (
            (configuration.get("base_url") or "").strip().strip("/")
        )
        is_legacy_config = not data_region and base_url_cfg
        if data_region == CUSTOM_REGION or is_legacy_config:
            base_url = base_url_cfg
        else:
            base_url = data_region.strip("/")
        return base_url, configuration.get("token")

    def get_dynamic_fields(self) -> list:
        """Return every configuration field after Data Region.

        Data Region is the only static field in manifest.json; every
        other field - including Base URL, which only applies to
        Custom Region - is returned here instead. CE always renders
        dynamic fields after the trigger field, never spliced in at
        the trigger's position, so keeping every other field dynamic
        (rather than mixing static and dynamic) is what places Base
        URL immediately after Data Region instead of after the whole
        static form. CE calls this whenever Data Region changes
        (has_api_call/payload_fields on that field in manifest.json).

        Returns:
            list: Field definitions to render after Data Region, in
            order - Base URL first (only for Custom Region), then
            every other configuration parameter.
        """
        data_region = self.configuration.get("data_region", "")
        fields = []
        if data_region == CUSTOM_REGION:
            fields.append(BASE_URL_FIELD)
        fields.extend(
            [
                TOKEN_FIELD,
                IS_PULL_REQUIRED_FIELD,
                ENABLE_PUSH_RETRACTION_FIELD,
                RETRACTION_INTERVAL_FIELD,
                INITIAL_RANGE_FIELD,
            ]
        )
        return fields

    def get_headers(self, authentication_token: str) -> Dict:
        """Get headers required for the API call."""
        return self.trend_micro_helper._add_user_agent(
            {
                "Authorization": "Bearer " f"{authentication_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _validate_url(self, url: str) -> bool:
        """Validate that a URL has an https scheme and a network
        location - TrendAI Vision One's API is https-only.

        Args:
            url (str): URL string to validate.

        Returns:
            bool: True if a valid https URL; False otherwise.
        """
        parsed = urlparse(url)
        return parsed.scheme == "https" and parsed.netloc.strip() != ""

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
        """Validate a single configuration parameter.

        Common validator reused for every configuration parameter in
        validate() instead of one bespoke check per field. Password-
        type fields must be validated with should_strip_str=False so
        leading/trailing whitespace that is part of the credential is
        never silently dropped.

        Args:
            parameter_type (str): "configuration" (only usage here).
            field_name (str): Human-readable field name.
            field_value: Value to validate.
            field_type (Type): Expected Python type.
            allowed_values: Optional set/list of allowed values.
            custom_validation_func: Optional callable returning bool.
            should_strip_str (bool): Strip string before checks. Must
                be False for password-type fields.

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
            allowed_str = ", ".join(f"'{v}'" for v in allowed_values)
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
        return None

    def _validate_days_range(
        self, field_name: str, value, max_days: int
    ) -> Union[ValidationResult, None]:
        """Validate a days-based parameter's type and range together.

        A non-integer value and an out-of-range value are the same
        problem from the user's point of view - the field doesn't
        hold a valid day count - so both produce the identical
        message/resolution here instead of the type check surfacing
        the generic "Invalid value provided for the configuration
        parameter" wording from _validate_configuration_parameters
        while the range check surfaces this field-specific one; that
        made Initial Range and Retraction Interval (in days) - the
        same kind of field - read inconsistently depending on which
        specific way the submitted value was invalid.

        Args:
            field_name (str): Human-readable field name.
            value: Submitted value to validate.
            max_days (int): Upper bound allowed for this field.

        Returns:
            ValidationResult if invalid; None if valid.
        """
        if not isinstance(value, int) or value < 1 or value > max_days:
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

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        data_region = (configuration.get("data_region") or "").strip()
        base_url_cfg = (
            (configuration.get("base_url") or "").strip().strip("/")
        )
        # A configuration saved before 2.0.0 has no "data_region" key -
        # it stored the selected region's host directly under
        # "base_url". Skip the Data Region check for that legacy shape
        # instead of failing validation for every existing customer on
        # upgrade; the moment the configuration is saved again a real
        # Data Region is always selected and this no longer applies.
        is_legacy_config = not data_region and base_url_cfg
        if not is_legacy_config:
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name="Data Region",
                field_value=data_region,
                field_type=str,
                allowed_values=DATA_REGIONS,
            ):
                return result

        if data_region == CUSTOM_REGION or is_legacy_config:
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name="Base URL",
                field_value=base_url_cfg,
                field_type=str,
                custom_validation_func=self._validate_url,
            ):
                return result

        # Password field - should_strip_str=False so the credential
        # is validated exactly as entered, never stripped.
        authentication_token = configuration.get("token")
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Authentication Token",
            field_value=authentication_token,
            field_type=str,
            should_strip_str=False,
        ):
            return result

        is_pull_required = (
            configuration.get("is_pull_required") or ""
        ).strip()
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return result

        enable_push_retraction = (
            configuration.get("enable_push_retraction") or ""
        ).strip()
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Enable Push Retraction",
            field_value=enable_push_retraction,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return result

        retraction_interval = configuration.get("retraction_interval")
        if retraction_interval is not None and str(
            retraction_interval
        ).strip() != "":
            if result := self._validate_days_range(
                "Retraction Interval (in days)",
                retraction_interval,
                MAX_RETRACTION_INTERVAL_DAYS,
            ):
                return result

        initial_range = configuration.get("initial_range")
        if result := self._validate_days_range(
            "Initial Range (in days)",
            initial_range,
            MAX_INITIAL_RANGE_DAYS,
        ):
            return result

        # Connectivity check (must be last).
        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration) -> ValidationResult:
        """Validate the TrendAI Vision One Plugin Authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating Authentication parameters"
        )
        try:
            (base_url, authentication_token) = self._get_credentials(
                configuration
            )

            query_params = {
                "top": 1,
            }
            headers = self.get_headers(authentication_token)
            self.trend_micro_helper.api_helper(
                logger_msg="validating Authentication parameters",
                url=f"{base_url}/v3.0/threatintel/suspiciousObjects",
                method="GET",
                params=query_params,
                headers=headers,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated"
                " Authentication parameters."
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except TrendMicroPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}, Check logs for more details.",
            )

    def pull(self) -> List[Indicator]:
        """Pull the Threat information from TrendAI Vision One platform.

        Returns : List[cte.models.Indicators] :
        List of indicator objects received from the
        TrendAI Vision One platform.
        """
        try:
            is_pull_required = (
                self.configuration.get("is_pull_required") or "Yes"
            ).strip()
            if is_pull_required == "No":
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self.get_indicators()

                return wrapper(self)

            else:
                indicators = []
                for batch in self.get_indicators():
                    indicators.extend(batch)

                total_counts_msg = (
                    f"Total {len(indicators)} indicator(s) pulled"
                    f" from {PLATFORM_NAME}."
                )
                self.logger.info(f"{self.log_prefix}: {total_counts_msg}")
                return indicators

        except TrendMicroPluginException as err:
            raise err
        except Exception as exp:
            err_msg = (
                f"Error occurred while pulling indicators from"
                f" {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)

    def get_indicators(self, is_retraction: bool = False):
        """Get indicators from TrendAI Vision One.

        Reused by both pull() and get_modified_indicators(): the
        same endpoint and nextLink pagination serve pull retraction
        by bounding the time window with Retraction Interval instead
        of the normal pull checkpoint, and by yielding raw IOC value
        strings instead of Indicator batches/sub-checkpoints - the
        diff in get_modified_indicators() only needs values.

        Args:
            is_retraction (bool): When True, re-query the suspicious
                objects list for the retraction window instead of
                the normal pull window, and yield lists of raw IOC
                values instead of Indicator objects.

        Returns:
            Generator: Indicator batches (or, when is_retraction,
            lists of raw IOC value strings) as per TrendAI Vision One
            API.
        """
        (base_url, authentication_token) = self._get_credentials(
            self.configuration
        )

        query_endpoint = f"{base_url}/v3.0/threatintel/suspiciousObjects"

        if is_retraction:
            retraction_interval = int(
                self.configuration.get("retraction_interval")
            )
            checkpoint = (
                datetime.now() - timedelta(days=retraction_interval)
            ).strftime(DATE_FORMAT_FOR_IOCS)
        else:
            sub_checkpoint = getattr(self, "sub_checkpoint", None)
            if sub_checkpoint:
                checkpoint = sub_checkpoint.get("checkpoint")
            else:
                checkpoint = self._get_trend_micro_last_seen()

        query_params = {
            "startDateTime": checkpoint,
            "endDateTime": datetime.now().strftime(DATE_FORMAT_FOR_IOCS),
            "top": 200,
        }
        headers = self.get_headers(authentication_token)

        next_page = True
        page_count = 0
        total_indicators = 0
        total_skipped = 0
        any_batch_yielded = False
        indicator_checkpoint = checkpoint

        try:
            while next_page:
                page_count += 1
                logger_msg = (
                    f"Pulling indicators for page {page_count} "
                    f"from {PLATFORM_NAME}."
                )
                self.logger.info(f"{self.log_prefix}: {logger_msg}")

                resp_json = self.trend_micro_helper.api_helper(
                    logger_msg=f"pulling data for page {page_count}",
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    is_retraction=is_retraction,
                )
                if resp_json.get("code"):
                    log_msg = (
                        "Unexpected response received from Trend"
                        " Vision One APIs, reach out to the Trend"
                        " Vision One Support for more information."
                    )
                    self.logger.error(f"{self.log_prefix}: {log_msg}")
                    raise TrendMicroPluginException(str(log_msg))

                indicators_json_list = resp_json.get("items", [])

                if is_retraction:
                    active_values = []
                    for indicator in indicators_json_list:
                        indicator_checkpoint = indicator.get(
                            "lastModifiedDateTime",
                            str(
                                datetime.now().strftime(
                                    DATE_FORMAT_FOR_IOCS
                                )
                            ),
                        )
                        description = indicator.get("description", "")
                        ioc_type = indicator.get("type")
                        if (
                            SOURCE_LABEL not in description
                            and LEGACY_SOURCE_LABEL not in description
                            and ioc_type in INDICATOR_TYPES
                        ):
                            ioc_value = indicator.get(ioc_type)
                            if ioc_value:
                                active_values.append(ioc_value)

                    total_indicators += len(active_values)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully pulled"
                        f" {len(active_values)} active indicator(s)"
                        f" in page {page_count} for retraction. Total"
                        " active indicator(s) pulled:"
                        f" {total_indicators}."
                    )
                    yield active_values

                else:
                    indicator_list = []
                    skip_count = 0
                    type_counts = {
                        "fileSha256": 0,
                        "domain": 0,
                        "url": 0,
                        "ip": 0,
                    }
                    # Separate counters per skip reason, so the page
                    # log can say *why* items were skipped instead of
                    # leaving a bare count that reads as data loss.
                    # skipped_type_counts is keyed by the raw TrendAI
                    # Vision One "type" string so an unsupported type
                    # (e.g. a SHA-1 hash, which this plugin does not
                    # support) is identifiable rather than just a
                    # number.
                    skipped_echo_count = 0
                    skipped_type_counts: Dict[str, int] = {}
                    skipped_invalid_value_count = 0

                    for indicator in indicators_json_list:

                        indicator_checkpoint = indicator.get(
                            "lastModifiedDateTime",
                            str(
                                datetime.now().strftime(
                                    DATE_FORMAT_FOR_IOCS
                                )
                            ),
                        )

                        description = indicator.get("description", "")
                        ioc_type = indicator.get("type")

                        if (
                            SOURCE_LABEL in description
                            or LEGACY_SOURCE_LABEL in description
                        ):
                            skip_count += 1
                            skipped_echo_count += 1
                            continue

                        if ioc_type not in INDICATOR_TYPES:
                            skip_count += 1
                            skipped_type_counts[ioc_type] = (
                                skipped_type_counts.get(ioc_type, 0) + 1
                            )
                            continue

                        ioc_value = indicator.get(ioc_type)
                        indicator_type, skipped = (
                            self._detect_indicator_type(
                                str(ioc_type), ioc_value
                            )
                        )

                        if skipped:
                            skip_count += 1
                            skipped_invalid_value_count += 1
                            continue
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=ioc_value,
                                    type=indicator_type,
                                    comments=str(description),
                                    lastSeen=datetime.strptime(
                                        indicator.get(
                                            "lastModifiedDateTime"
                                        ),
                                        DATE_FORMAT_FOR_IOCS,
                                    ),
                                    severity=(
                                        TRENDMICRO_TO_INTERNAL_SEVERITY
                                        .get(
                                            indicator.get("riskLevel")
                                        )
                                    ),
                                )
                            )
                        except ValidationError:
                            skip_count += 1
                            skipped_invalid_value_count += 1
                            continue

                        type_counts[ioc_type] += 1

                    total_indicators += len(indicator_list)
                    total_skipped += skip_count

                    page_log = (
                        f"{self.log_prefix}: Successfully pulled"
                        f" {len(indicator_list)} indicator(s) in page"
                        f" {page_count}. Pull Stats:"
                        f" SHA256={type_counts['fileSha256']},"
                        f" Domain={type_counts['domain']},"
                        f" IP={type_counts['ip']},"
                        f" URL={type_counts['url']}. Total indicators"
                        f" pulled till now {total_indicators}."
                    )
                    if skip_count:
                        skip_reason_parts = []
                        if skipped_type_counts:
                            skip_reason_parts.append(
                                ", ".join(
                                    f"{count} of unsupported type"
                                    f" '{skipped_ioc_type}'"
                                    for skipped_ioc_type, count in (
                                        skipped_type_counts.items()
                                    )
                                )
                            )
                        if skipped_echo_count:
                            skip_reason_parts.append(
                                f"{skipped_echo_count} already shared"
                                " by Netskope Cloud Exchange"
                            )
                        if skipped_invalid_value_count:
                            skip_reason_parts.append(
                                f"{skipped_invalid_value_count} with"
                                " an invalid value for their type"
                            )
                        skip_reason_msg = (
                            f" ({'; '.join(skip_reason_parts)})"
                            if skip_reason_parts
                            else ""
                        )
                        page_log += (
                            f" Skipped {skip_count}"
                            f" indicator(s){skip_reason_msg}."
                        )
                    self.logger.info(page_log)

                    # CE's pull consumer (plugin_lifecycle_task.py)
                    # breaks its entire loop the first time it
                    # receives an empty batch from this generator -
                    # yielding one every page (even when every
                    # indicator on that page was echo-suppressed or
                    # otherwise skipped) would stop CE from ever
                    # requesting a later page that does have new
                    # indicators. Only yield when this page actually
                    # has something; a single empty result is yielded
                    # after the loop below if the whole run found
                    # nothing at all, so CE still gets a clean "no
                    # new indicators" signal in that legitimate case.
                    if indicator_list:
                        any_batch_yielded = True
                        if hasattr(self, "sub_checkpoint"):
                            yield indicator_list, {
                                "checkpoint": indicator_checkpoint
                            }
                        else:
                            yield indicator_list

                if not resp_json.get("nextLink"):
                    next_page = False
                    break
                else:
                    query_params.clear()
                    query_endpoint = resp_json["nextLink"]

        except TrendMicroPluginException as trend_micro_err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while pulling"
                f" indicators from {PLATFORM_NAME}."
                f" Error: {trend_micro_err}"
            )
            raise TrendMicroPluginException(str(trend_micro_err))
        except Exception as exp:
            err_msg = (
                "Error occurred while pulling indicators from"
                f" {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise TrendMicroPluginException(err_msg)

        if not is_retraction:
            completion_log = (
                f"{self.log_prefix}: Successfully pulled"
                f" {total_indicators} indicator(s) from"
                f" {PLATFORM_NAME}."
            )
            if total_skipped:
                completion_log += (
                    f" Skipped {total_skipped} indicator(s)."
                )
            self.logger.info(completion_log)

            if not any_batch_yielded:
                if hasattr(self, "sub_checkpoint"):
                    yield [], {"checkpoint": indicator_checkpoint}
                else:
                    yield []

    def get_modified_indicators(
        self, source_indicators: List[List[Indicator]]
    ) -> Generator[Tuple[list, bool], None, None]:
        """Yield indicator values that should be retracted in CE.

        Pull retraction: re-queries the same Suspicious Object List
        endpoint pull() uses (see get_indicators), bounded by
        Retraction Interval days instead of the normal pull
        checkpoint, and diffs the resulting active-value set against
        what CE currently has stored for this source. A value CE has
        that TrendAI Vision One no longer reports is retracted.

        Output batching is decoupled from CE's input batching: values
        to retract are accumulated across CE-supplied batches and
        only flushed once self.retraction_batch of them are ready (or
        the input is exhausted), instead of yielding once per
        CE-supplied batch. CE's own retraction consumer
        (ioc_retraction.py) breaks its entire loop the first time it
        receives an empty batch from this generator - yielding one
        result per CE batch would silently stop checking every later
        batch the moment an earlier one happened to have nothing to
        retract. Accumulating first guarantees every yielded chunk is
        non-empty except a deliberate single empty result when
        nothing needed retracting across the whole run, and avoids
        fully materializing all of source_indicators at once (which
        can be far larger than a single retraction_batch chunk).

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

        retraction_interval = self.configuration.get("retraction_interval")
        if not (
            retraction_interval and isinstance(retraction_interval, int)
        ):
            self.logger.info(
                f"{self.log_prefix}: Retraction Interval is not"
                " configured. Skipping pull retraction of"
                f" indicator(s) for {PLATFORM_NAME}."
            )
            yield [], True
            return

        active_values = set()
        for batch in self.get_indicators(is_retraction=True):
            active_values.update(batch)

        self.logger.info(
            f"{self.log_prefix}: Successfully pulled"
            f" {len(active_values)} active indicator(s) from"
            f" {PLATFORM_NAME}."
        )

        batch_number = 0
        total_source = 0
        total_to_retract = 0
        chunks_yielded = 0
        pending = []
        for indicator_list in source_indicators:
            batch_number += 1
            source_values = set(ind.value for ind in indicator_list)
            source_total = len(source_values)
            to_retract = source_values - active_values
            total_source += source_total
            total_to_retract += len(to_retract)
            self.logger.info(
                f"{self.log_prefix}: {len(to_retract)} indicator(s)"
                " will be marked as retracted out of total"
                f" {source_total} indicator(s) from batch"
                f" {batch_number}."
            )
            pending.extend(to_retract)

            while len(pending) >= self.retraction_batch:
                chunk = pending[: self.retraction_batch]
                pending = pending[self.retraction_batch:]
                chunks_yielded += 1
                yield chunk, False

        if pending:
            chunks_yielded += 1
            yield pending, False
        elif chunks_yielded == 0:
            # Nothing to retract across the entire run - yield the
            # single empty result here (after every CE-supplied batch
            # has been checked) so CE still logs a clean "no new
            # indicators" result, instead of doing so per CE batch
            # and risking CE stopping early on the first one that had
            # nothing (see the docstring above).
            yield [], False

        self.logger.info(
            f"{self.log_prefix}: Total {total_to_retract} indicator(s)"
            f" marked as retracted out of total {total_source}"
            f" indicator(s) across {batch_number} batch(es)."
        )

    def _detect_indicator_type(
        self, indicator_type: str, value: str = ""
    ) -> Tuple[str, bool]:
        """Detect the CE IndicatorType for a TrendAI Vision One IOC.

        "ip" resolves to IPV4 or IPV6 based on the value itself,
        since TrendAI Vision One reports both under the single "ip"
        type. All other types use a fixed mapping.

        Returns:
            Tuple[str, bool]: (IndicatorType, False) for a valid,
            supported indicator, or ("skipped", True) when the type
            or value could not be mapped.
        """
        if indicator_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(value)
            except (ValueError, TypeError):
                return "skipped", True
            if isinstance(ip_obj, ipaddress.IPv6Address):
                return IndicatorType.IPV6, False
            return IndicatorType.IPV4, False

        detected = TRENDMICRO_TO_INTERNAL_TYPE.get(indicator_type)
        if not detected:
            return "skipped", True
        return detected, False

    def _get_trend_micro_last_seen(self) -> str:
        """Get TrendAI Vision One LastSeen Or DateChanged parameter.
        Returns:
            LastSeen/DateChanged (str):
                A datetime object as string representation.
        """
        if not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(self.configuration.get("initial_range"))
            )
        else:
            start_time = self.last_run_at
        return start_time.strftime(DATE_FORMAT_FOR_IOCS)

    def _validate_ioc_length(self, ioc_type: str, value: str) -> bool:
        """Check an outgoing IOC value against TrendAI Vision One's
        documented per-field length limits.

        Args:
            ioc_type (str): One of "url", "domain", "ip", "fileSha256".
            value (str): The IOC value to check.

        Returns:
            bool: True if the value satisfies the length constraint
                for its type; False if it should be skipped.
        """
        if ioc_type == "url":
            return len(value) <= MAX_URL_LENGTH
        if ioc_type == "domain":
            return len(value) <= MAX_DOMAIN_LENGTH
        if ioc_type == "ip":
            return len(value) <= MAX_IP_LENGTH
        if ioc_type == "fileSha256":
            return len(value) == SHA256_LENGTH
        return True

    def _resolve_trendmicro_type(self, indicator: Indicator) -> str:
        """Resolve the TrendAI Vision One JSON field name for an
        indicator, based on its CE IndicatorType.

        DOMAIN/IPV4/IPV6 map directly; a generic URL-typed indicator
        falls back to check_url_domain_ip() to detect a bare domain
        or IP string, matching the platform's own de-typed data.
        """
        if indicator.type == IndicatorType.DOMAIN:
            return "domain"
        if indicator.type in (IndicatorType.IPV4, IndicatorType.IPV6):
            return "ip"
        if indicator.type == IndicatorType.SHA256:
            return "fileSha256"
        # IndicatorType.URL (and any other type reaching this point -
        # callers filter to the supported types before calling this).
        return check_url_domain_ip(indicator.value)

    def divide_in_chunks_by_size(
        self, payload_list: List[Dict], max_items: int
    ) -> Generator[List[Dict], None, None]:
        """Divide a payload list into chunks bounded by both item
        count and serialized JSON byte size, so a chunk stays under
        TrendAI Vision One's documented 1MB request body limit.

        Args:
            payload_list (List[Dict]): Full list of IOC payload dicts.
            max_items (int): Maximum items per chunk for this target.

        Yields:
            List[Dict]: Successive chunks.
        """
        chunk: List[Dict] = []
        chunk_bytes = 2  # account for the enclosing []
        for item in payload_list:
            item_bytes = len(json.dumps(item).encode("utf-8")) + 1
            if chunk and (
                len(chunk) >= max_items
                or chunk_bytes + item_bytes > MAX_PAYLOAD_BYTES
            ):
                yield chunk
                chunk, chunk_bytes = [], 2
            chunk.append(item)
            chunk_bytes += item_bytes
        if chunk:
            yield chunk

    def push_indicators_to_trendmicro(self, json_payload, action_value, batch):
        """Push Indicators to TrendAI Vision One's selected Target List."""
        (base_url, authentication_token) = self._get_credentials(
            self.configuration
        )
        if action_value == "suspicious_object":
            push_endpoint = f"{base_url}/v3.0/threatintel/suspiciousObjects"
        else:
            push_endpoint = (
                f"{base_url}/v3.0/threatintel/suspiciousObjectExceptions"
            )

        headers = self.get_headers(authentication_token)
        check_flag = True
        fail_count = 0
        success_count = 0
        failed_iocs = []
        try:

            response = self.trend_micro_helper.api_helper(
                logger_msg=(
                    f"sharing {len(json_payload)} indicator(s) to"
                    f" {PLATFORM_NAME} in batch {batch}"
                ),
                url=push_endpoint,
                method="POST",
                json=json_payload,
                headers=headers,
            )
            if isinstance(response, list):
                success_count, fail_count, failed_iocs = (
                    self.trend_micro_helper.process_multi_status_response(
                        response_items=response,
                        submitted_payload=json_payload,
                        logger_msg="share indicator",
                    )
                )
            else:
                if response.get("code"):
                    log_msg = (
                        "Unexpected response received, please"
                        " provide the required minimum permissions."
                    )
                else:
                    log_msg = "Unexpected response received."
                self.logger.error(
                    message=f"{self.log_prefix}: {log_msg}",
                    details=f"{response}",
                )
                raise TrendMicroPluginException(str(log_msg))
        except MaximumLimitExceededException:
            fail_count += len(json_payload)
            failed_iocs.extend(
                next(iter(item.values()), "") for item in json_payload
            )
            check_flag = False
            return fail_count, success_count, check_flag, failed_iocs
        except TrendMicroPluginException:
            fail_count += len(json_payload)
            failed_iocs.extend(
                next(iter(item.values()), "") for item in json_payload
            )
        except Exception as exp:
            fail_count += len(json_payload)
            failed_iocs.extend(
                next(iter(item.values()), "") for item in json_payload
            )
            err_msg = (
                f"Error occurred while sharing indicator(s) of batch {batch}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )

        return fail_count, success_count, check_flag, failed_iocs

    def _push_result_has_skipped_iocs(self) -> bool:
        """Check whether this CE build's PushResult has skipped_iocs.

        The field and its "N/A" (not counted as shared or failed)
        handling in CE's own sharing task were added in the same
        change - there is no CE build where the field exists without
        also being honored. So its presence alone tells
        prepare_payload() whether it is safe to report an
        unsupported-type IOC through skipped_iocs alone, or whether
        failed_iocs is still needed as the only way to keep it from
        being marked "shared" on an older CE build that has no
        skipped_iocs field at all.

        Returns:
            bool: True if skipped_iocs is a real field on this CE
            build's PushResult.
        """
        push_result_fields = getattr(
            PushResult, "model_fields", None
        ) or getattr(PushResult, "__fields__", {})
        return "skipped_iocs" in push_result_fields

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Action,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ):
        """Push indicators to TrendAI Vision One."""
        action_value = action_dict.get("value")
        action_params = action_dict.get("parameters", {})
        action_label = action_dict.get("label")

        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        if action_value == "suspicious_object":
            batch_chunk_size = SUSPICIOUS_OBJECT_BATCH_SIZE
        else:
            batch_chunk_size = SUSPICIOUS_OBJECT_EXCEPTION_BATCH_SIZE

        total_fail_count = 0
        total_success_count = 0
        payload_list, skipped_iocs, total_failed_iocs = self.prepare_payload(
            indicators, action_params, action_value, plugin_name
        )
        batch = 1
        for chunked_list in self.divide_in_chunks_by_size(
            payload_list, batch_chunk_size
        ):
            chunk_size = len(chunked_list)
            chunk_fail_count, chunk_success_count, check_flag, failed_iocs = (
                self.push_indicators_to_trendmicro(
                    chunked_list, action_value, batch
                )
            )
            total_fail_count += chunk_fail_count
            total_success_count += chunk_success_count
            total_failed_iocs.extend(failed_iocs)
            if not check_flag:
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared"
                    f" {total_success_count} indicator(s) and failed"
                    f" to share {total_fail_count} indicator(s) to"
                    f" '{action_label}'. No more indicators will be"
                    " shared as maximum limit has exceeded, delete"
                    " some indicators from the platform for sharing."
                )
                break

            self.logger.info(
                f"{self.log_prefix}: Successfully shared"
                f" {chunk_success_count} indicator(s) and failed to"
                f" share {chunk_fail_count} indicator(s) from"
                f" {chunk_size} indicators in batch {batch} to"
                f" '{action_label}'. Total indicator(s) shared:"
                f" {total_success_count}."
            )

            batch += 1
        log_msg = (
            f"Successfully shared {total_success_count} indicator(s)"
            f" to {PLATFORM_NAME} '{action_label}'."
        )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        push_result_kwargs = {
            "success": True,
            "message": log_msg,
            "failed_iocs": total_failed_iocs,
        }
        # skipped_iocs does not exist on PushResult in every supported
        # CE version (added in a later release than this plugin's
        # minimum_version) - passing it unconditionally is silently
        # ignored on older CE builds where pydantic's default
        # extra="ignore" applies, but do not rely on that across every
        # CE version. Only set it when this CE build's PushResult
        # actually declares the field, matching the same
        # forward-compatibility guard the "Netskope" CTE destination
        # plugin uses for the exact same reason. On a CE build without
        # this field, prepare_payload() also adds unsupported-type
        # IOCs to failed_iocs so they are still correctly excluded
        # from being marked "shared".
        if self._push_result_has_skipped_iocs():
            push_result_kwargs["skipped_iocs"] = skipped_iocs
        return PushResult(**push_result_kwargs)

    def prepare_payload(
        self, indicators, action_params, action_value, plugin_name=None
    ):
        """Prepare the JSON payload for Push.

        Distinguishes, like the "Netskope" CTE destination plugin
        does: an indicator of a type TrendAI Vision One does not accept
        at all is skipped (skipped_iocs); an indicator whose type IS
        accepted but whose value is invalid (exceeds Trend Vision
        One's documented length limit, or fails unexpectedly while
        building its payload) is failed (failed_iocs) rather than
        skipped, since the type itself was supported. riskLevel is
        only added for the Suspicious Object List - confirmed against
        the live API that the Exception List target rejects it with a
        400 (an exception has no risk concept, it is a value that is
        never flagged at all). When it is added, it is omitted
        entirely - rather than sent as an empty string - when the
        indicator's severity is SeverityType.UNKNOWN.

        Args:
            indicators (List[cte.models.Indicators]):
            List of Indicator objects to be pushed.
            action_params (Dict): The "parameters" dict of the
            action, containing the user-supplied "desc" field.
            action_value (str): The action's "value" -
            "suspicious_object" or "suspicious_object_exception" -
            identifying which target this payload is being built for.
            plugin_name (str): Name of the source plugin the
            indicator(s) originated from, as resolved by CE core -
            matches the "servicenow" CTE plugin's convention. The
            bare SOURCE_LABEL is used when CE core does not supply
            it.
        Returns:
            Tuple[List[dict], List[str], List[str]]: Payload dicts
            ready to submit, values of IOCs skipped for being an
            unsupported type, and values of IOCs of a supported type
            that failed to be prepared for sharing.
        """
        domain_count = 0
        url_count = 0
        ip_count = 0
        sha256_count = 0
        skip_count = 0
        invalid_value_count = 0
        skipped_iocs = []
        failed_iocs = []
        payload_list = []
        supported_types = (
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.SHA256,
        )
        source_label = (
            f"{SOURCE_LABEL} | {plugin_name}" if plugin_name else SOURCE_LABEL
        )
        desc = (action_params.get("desc") or "").strip()
        max_desc_len = MAX_DESCRIPTION_LENGTH - len(source_label) - 2
        if len(desc) > max_desc_len:
            desc = desc[:max_desc_len]
        description = f"{source_label}. {desc}".strip()
        push_result_has_skipped_iocs = self._push_result_has_skipped_iocs()

        for indicator in indicators:
            try:
                if indicator.type not in supported_types:
                    skip_count += 1
                    skipped_iocs.append(indicator.value)
                    # Only fall back to failed_iocs when this CE
                    # build has no skipped_iocs field at all - CE
                    # marks every indicator "shared" except those in
                    # failed_iocs, so without this an unsupported-type
                    # IOC that was never sent to TrendAI Vision One
                    # would still show as shared on such a build.
                    # When skipped_iocs IS honored, adding it to
                    # failed_iocs too would flip its status to
                    # "failed" before CE's own skipped_iocs handling
                    # can tag it "N/A", so it is left out here.
                    if not push_result_has_skipped_iocs:
                        failed_iocs.append(indicator.value)
                    continue

                trendmicro_type = self._resolve_trendmicro_type(indicator)
                indicator_value = indicator.value
                if trendmicro_type == "domain":
                    indicator_value = indicator_value.rstrip("/")

                if not self._validate_ioc_length(
                    trendmicro_type, indicator_value
                ):
                    invalid_value_count += 1
                    failed_iocs.append(indicator.value)
                    self.logger.info(
                        f"{self.log_prefix}: Failed to prepare IOC"
                        f" '{indicator.value}' for sharing as it"
                        " exceeds the maximum length allowed by"
                        f" TrendAI Vision One for type"
                        f" '{trendmicro_type}'."
                    )
                    continue

                payload = {
                    trendmicro_type: indicator_value,
                    "description": description,
                }
                # riskLevel is rejected outright (400) by the
                # Exception List API - an exception has no risk
                # concept, it is a value that is never flagged at
                # all - so it is only ever added for the Suspicious
                # Object List target. riskLevel maps to "" for
                # SeverityType.UNKNOWN (the Indicator model's own
                # default when severity was never set) - sending an
                # empty string for a field TrendAI Vision One
                # constrains to high/medium/low also causes a 400, so
                # the key is omitted entirely in that case too rather
                # than sending "".
                if action_value == "suspicious_object":
                    risk_level = INTERNAL_SEVERITY_TO_TRENDMICRO[
                        indicator.severity
                    ]
                    if risk_level:
                        payload["riskLevel"] = risk_level
                if trendmicro_type == "domain":
                    domain_count += 1
                elif trendmicro_type == "ip":
                    ip_count += 1
                elif trendmicro_type == "fileSha256":
                    sha256_count += 1
                else:
                    url_count += 1
                payload_list.append(payload)
            except Exception as err:
                invalid_value_count += 1
                failed_iocs.append(indicator.value)
                err_msg = "Exception occurred while Preparing Payload."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )

        log_msg = (
            f"Successfully created payload for {len(payload_list)}"
            f" indicator(s), skipped {skip_count} indicator(s) of an"
            " unsupported type (not shared - reported in"
            f" failed_iocs), and failed to prepare"
            f" {invalid_value_count} indicator(s) with an invalid"
            " value for sharing. Total"
            f" {sha256_count} SHA256, {url_count} URL(s),"
            f" {domain_count} domain(s), {ip_count} IP(s) will be"
            " shared."
        )

        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return payload_list, skipped_iocs, failed_iocs

    def _build_retraction_payload(
        self, indicators: List[Indicator]
    ) -> Tuple[List[Dict], List[str], List[str]]:
        """Build the delete payload for a batch of indicators to
        retract, applying the same type resolution and length
        validation as prepare_payload() but without description or
        riskLevel - the delete endpoints take only the value. Same
        skipped/failed split as prepare_payload(): unsupported type
        is skipped, a supported type with an invalid value is failed.

        Returns:
            Tuple[List[Dict], List[str], List[str]]: Payload dicts
            ready to submit, values of IOCs skipped as an unsupported
            type, and values of IOCs of a supported type that failed
            because their value is out of TrendAI Vision One's length
            limits.
        """
        payload_list = []
        skipped_iocs = []
        failed_iocs = []
        supported_types = (
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.SHA256,
        )
        for indicator in indicators:
            # CE's IndicatorGenerator.all() can hand back None for an
            # indicator document with no `sources` entry matching
            # this plugin's source name. Without this guard, that
            # None would crash on `.type` below - a batch-wide
            # exception CE has no partial-failure handling for (a
            # single failed batch marks the entire source
            # configuration's retraction "failed", including
            # already-succeeded batches - see retract_indicators()).
            if indicator is None:
                continue
            if indicator.type not in supported_types:
                skipped_iocs.append(indicator.value)
                continue

            trendmicro_type = self._resolve_trendmicro_type(indicator)
            indicator_value = indicator.value
            if trendmicro_type == "domain":
                indicator_value = indicator_value.rstrip("/")

            if not self._validate_ioc_length(
                trendmicro_type, indicator_value
            ):
                failed_iocs.append(indicator.value)
                continue

            payload_list.append({trendmicro_type: indicator_value})
        return payload_list, skipped_iocs, failed_iocs

    def _get_action_field(self, action, field: str, default=None):
        """Read a field off an action_config_list entry.

        Confirmed against CE's own retraction task source
        (share_indicators.py): entries here can be real Action
        pydantic model instances, not plain dicts like push()'s
        action_dict - CE's BusinessRuleDB pydantic-validates a stored
        business rule's sharedWith (typed
        Dict[str, Dict[str, List[Action]]]), coercing the raw stored
        data into real Action objects before handing one to
        retract_indicators(). CE's own code branches on
        isinstance(action_dict, Action) before falling back to
        dict-style .get() for exactly this reason; mirror that here
        rather than assuming action_config_list behaves like push()'s
        action_dict, since it comes from a different code path.

        Args:
            action: An entry from action_config_list - either an
                Action instance or a dict.
            field (str): Field name to read ("value" or "label").
            default: Value to return if the field is absent.

        Returns:
            The field's value, or default if not present.
        """
        if isinstance(action, Action):
            return getattr(action, field, default)
        return action.get(field, default)

    def retract_indicators(
        self,
        indicators: Generator[List[Indicator], bool, None],
        action_config_list: List[Action],
    ) -> Generator[ValidationResult, None, None]:
        """Delete previously shared indicators from TrendAI Vision One.

        Trigger (confirmed): an indicator is deleted from Trend
        Vision One when it is marked retracted in CE and was
        previously shared to TrendAI Vision One - CE determines this
        set and hands it over via `indicators`; this method does not
        re-query TrendAI Vision One's current object lists. Runs only
        when Enable Push Retraction is Yes, against both configured
        targets (Suspicious Object List, Exception List).

        Note: Retraction Interval is a pull-retraction parameter
        (see get_modified_indicators) - it has no role here.

        Args:
            indicators: Generator of indicator batches to retract.
            action_config_list (List[Action]): Push targets this
                indicator was shared to.

        Yields:
            ValidationResult: Result of the retraction operation.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"

        enable_push_retraction = self.configuration.get(
            "enable_push_retraction", "No"
        )
        if enable_push_retraction != "Yes":
            log_msg = (
                "Push Retraction is disabled in the configuration"
                f" parameters. Skipping retraction of indicator(s)"
                f" for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield ValidationResult(
                success=False,
                disabled=True,
                message=log_msg,
            )
            return

        self.logger.info(
            f"{self.log_prefix}: Starting retraction of"
            f" indicator(s) from {PLATFORM_NAME}."
        )

        target_actions = [
            action
            for action in action_config_list
            if self._get_action_field(action, "value") in (
                "suspicious_object",
                "suspicious_object_exception",
            )
        ]

        (base_url, authentication_token) = self._get_credentials(
            self.configuration
        )
        headers = self.get_headers(authentication_token)

        grand_total_success = 0
        grand_total_fail = 0
        grand_total_skipped = 0
        batch_number = 0

        for indicator_batch in indicators:
            batch_number += 1
            batch_success = 0
            batch_fail = 0
            batch_skipped = 0
            try:
                # Built once per batch - which IOCs are
                # supported/within length limits does not depend on
                # which target they are being retracted from.
                payload_list, skipped_iocs, invalid_iocs = (
                    self._build_retraction_payload(indicator_batch)
                )
                batch_skipped = len(skipped_iocs)
                batch_fail += len(invalid_iocs)
                if skipped_iocs:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped"
                        f" {len(skipped_iocs)} indicator(s) in batch"
                        f" {batch_number} for retraction as they are"
                        " of an unsupported type."
                    )
                if invalid_iocs:
                    self.logger.info(
                        f"{self.log_prefix}: Failed to delete"
                        f" {len(invalid_iocs)} indicator(s) in batch"
                        f" {batch_number} as their value exceeds the"
                        " maximum length allowed by TrendAI Vision One."
                    )

                for action in target_actions:
                    action_value = self._get_action_field(action, "value")
                    action_label = self._get_action_field(
                        action, "label", default=action_value
                    )
                    if action_value == "suspicious_object":
                        delete_endpoint = (
                            f"{base_url}/v3.0/threatintel/"
                            "suspiciousObjects/delete"
                        )
                        batch_chunk_size = SUSPICIOUS_OBJECT_BATCH_SIZE
                    else:
                        delete_endpoint = (
                            f"{base_url}/v3.0/threatintel/"
                            "suspiciousObjectExceptions/delete"
                        )
                        batch_chunk_size = (
                            SUSPICIOUS_OBJECT_EXCEPTION_BATCH_SIZE
                        )

                    for chunk_number, chunked_list in enumerate(
                        self.divide_in_chunks_by_size(
                            payload_list, batch_chunk_size
                        ),
                        start=1,
                    ):
                        try:
                            response = self.trend_micro_helper.api_helper(
                                logger_msg=(
                                    f"deleting {len(chunked_list)}"
                                    f" indicator(s) from"
                                    f" {PLATFORM_NAME}"
                                    f" '{action_label}' in"
                                    f" batch {batch_number}, chunk"
                                    f" {chunk_number}"
                                ),
                                url=delete_endpoint,
                                method="POST",
                                json=chunked_list,
                                headers=headers,
                                is_retraction=True,
                            )
                            if isinstance(response, list):
                                success_count, fail_count, _ = (
                                    self.trend_micro_helper
                                    .process_multi_status_response(
                                        response_items=response,
                                        submitted_payload=chunked_list,
                                        logger_msg="delete indicator",
                                    )
                                )
                            else:
                                success_count = 0
                                fail_count = len(chunked_list)
                            batch_success += success_count
                            batch_fail += fail_count
                            self.logger.info(
                                f"{self.log_prefix}: Successfully"
                                f" deleted {success_count}"
                                f" indicator(s) and failed to delete"
                                f" {fail_count} indicator(s) from"
                                f" {len(chunked_list)} indicator(s)"
                                f" in batch {batch_number}, chunk"
                                f" {chunk_number} for"
                                f" '{action_label}'."
                            )
                        except TrendMicroPluginException:
                            batch_fail += len(chunked_list)
                        except Exception as exp:
                            batch_fail += len(chunked_list)
                            err_msg = (
                                "Error occurred while deleting"
                                f" indicator(s) from {PLATFORM_NAME}"
                                f" '{action_label}'."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {err_msg}"
                                f" Error: {exp}",
                                details=str(traceback.format_exc()),
                            )
            except Exception as exp:
                # A batch of up to self.retraction_batch indicators
                # failing to even build its payload must not stop CE
                # from handing over the remaining batches - log and
                # move on to the next indicator_batch instead of
                # letting the exception propagate out of this
                # generator and end the whole retraction run.
                err_msg = (
                    "Unexpected error occurred while deleting"
                    f" indicator(s) in batch {batch_number} from"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                yield ValidationResult(
                    success=False,
                    message=(
                        f"{err_msg} Error: {exp}. Continuing with"
                        " the remaining batch(es)."
                    ),
                )
                continue

            grand_total_success += batch_success
            grand_total_fail += batch_fail
            grand_total_skipped += batch_skipped
            self.logger.info(
                f"{self.log_prefix}: Successfully deleted"
                f" {batch_success} indicator(s), failed to delete"
                f" {batch_fail} indicator(s), and skipped"
                f" {batch_skipped} indicator(s) in batch"
                f" {batch_number} from {PLATFORM_NAME}."
            )
            yield ValidationResult(
                success=True,
                message=(
                    f"Successfully deleted {batch_success}"
                    f" indicator(s), failed to delete {batch_fail}"
                    f" indicator(s), and skipped {batch_skipped}"
                    " indicator(s) for one batch."
                ),
            )

        self.logger.info(
            f"{self.log_prefix}: Retraction completed for"
            f" {batch_number} batch(es). Successfully deleted"
            f" {grand_total_success} indicator(s), failed to delete"
            f" {grand_total_fail} indicator(s), and skipped"
            f" {grand_total_skipped} indicator(s) from"
            f" {PLATFORM_NAME}."
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Add to Suspicious Object List",
                value="suspicious_object",
            ),
            ActionWithoutParams(
                label="Add to Exception List",
                value="suspicious_object_exception",
            ),
        ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Netskope configuration."""
        if action.value not in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:

            err_msg = "Unsupported action provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=f"{err_msg}")
        if action.parameters.get("desc") is None:

            err_msg = "Invalid Description Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=f"{err_msg}")

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:
            return [
                {
                    "label": "Description",
                    "key": "desc",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Description to be sent with Threat IOCs. If the "
                        "description exceeds the maximum limit of 1000 "
                        "characters allowed by TrendAI Vision One, "
                        "it will be truncated."
                    ),
                },
            ]
