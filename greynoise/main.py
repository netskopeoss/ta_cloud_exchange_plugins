"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE GreyNoise Plugin main file.
"""

import ipaddress
import traceback
from datetime import datetime
from typing import Dict, Generator, List, Optional, Tuple, Type, Union

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.utils import TagUtils

from pydantic import ValidationError

from .utils.constants import (
    CALLBACK_IP_ENDPOINT,
    CALLBACK_LIST_ENDPOINT,
    CALLBACK_PAGE_SIZE,
    DATE_FORMAT_FIRST_SEEN,
    DATE_FORMAT_LAST_SEEN,
    EMPTY_ERROR_MESSAGE,
    EXCLUDE_FIELDS,
    GNQL_ENDPOINT,
    GREYNOISE_URL,
    INVALID_VALUE_ERROR_MESSAGE,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    TAG_COLOR,
    TYPE_ERROR_MESSAGE,
    VALID_CLASSIFICATIONS,
    VALID_IOC_TYPES,
    VALID_RANGES,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.helper import GreyNoisePluginException, GreyNoisePluginHelper

INDICATOR_TYPE_MAP = {
    "ipv4": getattr(IndicatorType, "IPV4", IndicatorType.URL),
    "ipv6": getattr(IndicatorType, "IPV6", IndicatorType.URL),
    "ipv4_cidr": getattr(
        IndicatorType, "IPV4_CIDR", IndicatorType.URL
    ),
    "ipv6_cidr": getattr(
        IndicatorType, "IPV6_CIDR", IndicatorType.URL
    ),
}


class GreyNoisePlugin(PluginBase):
    """GreyNoise CTE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """GreyNoise plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = (
            self._get_plugin_info()
        )
        self.log_prefix = (
            f"{MODULE_NAME} {self.plugin_name}"
        )
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.greynoise_helper = GreyNoisePluginHelper(
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
            manifest_json = GreyNoisePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get(
                "version", PLUGIN_VERSION
            )
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error"
                    " occurred while getting plugin details."
                    f" Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _validate_configuration_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type: Type,
        allowed_values: Union[list, set, None] = None,
        custom_validation_func=None,
        should_strip_str: bool = True,
    ) -> Optional[ValidationResult]:
        """Validate a single configuration or action parameter.

        Args:
            parameter_type (str): "configuration" or "action".
            field_name (str): Human-readable field name.
            field_value: Value to validate.
            field_type (Type): Expected Python type.
            allowed_values: Optional allowed-values collection.
            custom_validation_func: Optional bool-returning callable.
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
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Ensure that some value is provided for"
                    f" field '{field_name}'."
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )
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
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided"
                    f" for '{field_name}' field."
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        if allowed_values and field_value not in allowed_values:
            allowed_str = ", ".join(
                f"'{v}'" for v in allowed_values
            )
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            ) + INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_str
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Ensure a valid value from the allowed"
                    f" values is provided.\nAllowed values:"
                    f" {allowed_str}"
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        return None

    def _validate_range_days(
        self,
        range_field: str,
        days_field: str,
        range_value: str,
        days_value,
    ) -> Optional[ValidationResult]:
        """Validate the (Days) companion field for a range selector.

        When range_value is 'custom', days_value must be 1-365.
        When range_value is anything else, days_value must be absent.
        """
        if range_value == "custom":
            try:
                days = int(days_value)
                if not (1 <= days <= 365):
                    raise ValueError
            except (ValueError, TypeError):
                err_msg = (
                    f"{days_field} is required when {range_field}"
                    " is set to 'Custom'."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}:"
                        f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                    ),
                    resolution=(
                        f"Provide a valid number between 1 and 365"
                        f" for '{days_field}'."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        elif days_value not in (None, "", 0):
            err_msg = (
                f"{days_field} should only be set when"
                f" {range_field} is set to 'Custom'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Clear the '{days_field}' field or set"
                    f" {range_field} to 'Custom'."
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        return None

    def _create_tags(
        self,
        tag_names: List[str],
    ) -> Tuple[List[str], List[str]]:
        """Create CE tags that do not already exist.

        Args:
            tag_names (List[str]): Tag name strings to create.

        Returns:
            Tuple[List[str], List[str]]: (created, skipped) tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = [], []
        for tag_name in tag_names:
            name = tag_name.strip()
            if not name:
                continue
            try:
                if not tag_utils.exists(name):
                    tag_utils.create_tag(
                        TagIn(name=name, color=TAG_COLOR)
                    )
                created_tags.append(name)
            except ValueError:
                skipped_tags.append(name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        f" creating tag '{name}'."
                        f" Error: {exp}"
                    ),
                    details=str(traceback.format_exc())
                )
                skipped_tags.append(name)
        return created_tags, skipped_tags

    def _build_comments(
        self,
        isc: Dict,
        metadata: Dict,
    ) -> Optional[str]:
        """Build the comments string from GreyNoise record metadata.

        Args:
            isc (Dict): internet_scanner_intelligence dict.
            metadata (Dict): metadata sub-dict from isc.

        Returns:
            Optional[str]: Comma-separated comment string or None.
        """
        parts = []
        source_country = metadata.get("source_country", "") or ""
        source_city = metadata.get("source_city", "") or ""
        organization = metadata.get("organization", "") or ""
        actor = isc.get("actor", "") or ""
        if source_country:
            parts.append(
                f"source_country: {source_country}"
            )
        if source_city:
            parts.append(f"source_city: {source_city}")
        if organization:
            parts.append(
                f"organization: {organization}"
            )
        if actor:
            parts.append(f"actor: {actor}")
        return ", ".join(parts) if parts else None

    def _build_file_hash_indicators(
        self,
        file_rec: Dict,
        fetch_sha256: bool,
        fetch_md5: bool,
        first_seen,
        last_seen,
        tags: list,
        extended_info,
    ) -> Tuple[List[Indicator], int, Dict[str, int]]:
        """Build SHA256/MD5 Indicators from a single active_files record.

        Returns:
            Tuple of (indicators, skip_count, type_counts).
        """
        indicators = []
        skip_count = 0
        type_counts: Dict[str, int] = {"sha256": 0, "md5": 0}

        for fetch, field_key, type_name in [
            (fetch_sha256, "sha256", "SHA256"),
            (fetch_md5, "md5", "MD5"),
        ]:
            if not fetch:
                continue
            hash_value = (file_rec.get(field_key, "") or "").strip()
            if not hash_value:
                continue
            try:
                ind = Indicator(
                    value=hash_value,
                    type=getattr(
                        IndicatorType, type_name, IndicatorType.URL
                    ),
                    firstSeen=first_seen,
                    lastSeen=last_seen,
                    tags=tags,
                    extendedInformation=extended_info,
                )
                indicators.append(ind)
                type_counts[field_key] += 1
            except (ValidationError, Exception):
                skip_count += 1

        return indicators, skip_count, type_counts

    def _parse_date(
        self, value: str, fmt: str
    ) -> Optional[datetime]:
        """Parse a date string with the given format.

        Returns None on failure.
        """
        if not value:
            return None
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            return None

    def _get_ip_type_key(self, ip_value: str) -> str:
        """Return the type key for the given IP or CIDR string.

        Returns 'ipv4', 'ipv6', 'ipv4_cidr', or 'ipv6_cidr'.

        Raises:
            ValueError: If ip_value is not a valid IP or CIDR.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            return (
                "ipv4"
                if isinstance(ip_obj, ipaddress.IPv4Address)
                else "ipv6"
            )
        except ValueError:
            pass
        try:
            ipaddress.IPv4Network(ip_value, strict=False)
            return "ipv4_cidr"
        except ValueError:
            pass
        try:
            ipaddress.IPv6Network(ip_value, strict=False)
            return "ipv6_cidr"
        except ValueError:
            pass
        raise ValueError(
            f"Invalid IP or CIDR address: '{ip_value}'"
        )

    def _build_indicator(
        self,
        value: str,
        indicator_type,
        isc: Dict,
        ip_value: str,
        enable_tagging: str,
        classification: str,
        extra_tags: Optional[List[str]] = None,
    ) -> Optional[Indicator]:
        """Build a single Indicator from a GreyNoise GNQL record.

        Args:
            value (str): IP or domain string value.
            indicator_type: CE IndicatorType enum value.
            isc (Dict): internet_scanner_intelligence dict.
            ip_value (str): Parent record IP (for extendedInfo).
            enable_tagging (str): "Yes" or "No".
            classification (str): GreyNoise classification string.
            extra_tags (List[str], optional): Additional tag names
                to attach, e.g. ["ipv4_cidr"] for CIDR indicators
                that fall back to URL type on older CE versions.

        Returns:
            Optional[Indicator]: Built indicator or None on error.
        """
        first_seen = self._parse_date(
            isc.get("first_seen") or "", DATE_FORMAT_FIRST_SEEN
        )
        last_seen = self._parse_date(
            isc.get("last_seen_timestamp") or "", DATE_FORMAT_LAST_SEEN
        ) or self._parse_date(
            isc.get("last_seen") or "", DATE_FORMAT_FIRST_SEEN
        )

        tags = []
        if enable_tagging.lower() == "yes":
            tag_names = [classification]
            if extra_tags:
                tag_names.extend(extra_tags)
            for tag in isc.get("tags", []):
                cat = tag.get("category", "") or ""
                name = tag.get("name", "") or ""
                if cat and name:
                    tag_names.append(f"{cat}:{name}")
                elif name:
                    tag_names.append(name)
            created_tags, skipped_tags = self._create_tags(
                tag_names
            )
            if skipped_tags:
                self.logger.debug(
                    f"{self.log_prefix}: Skipped tag(s)"
                    f" {skipped_tags} for indicator"
                    f" '{value}'."
                )
            tags = created_tags

        metadata = isc.get("metadata", {}) or {}
        comments = self._build_comments(isc, metadata)

        extended_info = None
        if ip_value:
            extended_info = (
                f"{GREYNOISE_URL.rstrip('/')}/ip/{ip_value}"
            )

        try:
            indicator = Indicator(
                value=value,
                type=indicator_type,
                firstSeen=first_seen,
                lastSeen=last_seen,
                tags=tags,
                comments=comments,
                extendedInformation=extended_info,
            )
            return indicator
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error"
                    f" creating indicator for '{value}'."
                    f" Skipping. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            return None

    def _compute_active_range(
        self,
        is_retraction: bool,
        initial_range: str,
        initial_range_days,
        retraction_interval: str,
        retraction_interval_days,
    ) -> Tuple:
        """Compute the query range for the current pull cycle.

        For retraction uses the retraction interval; for initial pull
        uses the configured initial range; for subsequent pulls derives
        the number of days elapsed since last_run_at.

        Returns:
            Tuple[str, any]: (active_range, active_range_days).
        """
        if is_retraction:
            return retraction_interval, retraction_interval_days

        if self.last_run_at is None:
            _range_label = (
                f"{initial_range_days} day(s)"
                if initial_range == "custom"
                else {
                    "today": "Today",
                    "1d": "1 day",
                    "1w": "1 week",
                    "1m": "1 month",
                    "1y": "1 year",
                }.get(initial_range, initial_range)
            )
            self.logger.info(
                f"{self.log_prefix}: Initial data fetch."
                f" Querying with initial range: {_range_label}."
            )
            return initial_range, initial_range_days

        # Subsequent runs: derive the window from last_run_at so no
        # data is missed when the pull interval exceeds a day or a run
        # is skipped. GNQL and the callback API both use day
        # granularity, so round the elapsed time up to whole days
        # (minimum 1) and query using a custom day range.
        elapsed = datetime.now() - self.last_run_at
        days_since_last_run = elapsed.days + (
            1 if (elapsed.seconds or elapsed.microseconds) else 0
        )
        days_since_last_run = max(1, days_since_last_run)
        self.logger.info(
            f"{self.log_prefix}: Querying indicator(s) updated in"
            f" the last {days_since_last_run} day(s) since the"
            " previous successful pull."
        )
        return "custom", days_since_last_run

    def _pull_ip_indicators(
        self,
        base_url: str,
        headers: Dict,
        enable_tagging: str,
        classifications_to_process: List[str],
        last_seen_param: str,
        active_range_days,
        is_retraction: bool,
        resume_classification: Optional[str] = None,
        resume_scroll: Optional[str] = None,
    ) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pull IP indicators via GNQL for each classification.

        Iterates over classifications_to_process, paginates through
        GNQL results using scroll cursors, and yields each page's
        indicators with a sub-checkpoint dict.

        On API error the exception is raised (not silently swallowed)
        so the CE framework preserves the last yielded checkpoint and
        resumes from the correct page on the next pull cycle.

        Args:
            classifications_to_process: Classifications still to pull
                (pre-filtered by caller when resuming).
            last_seen_param: Range string passed to GNQL last_seen.
            active_range_days: Day count used when last_seen_param is
                'custom'.
            resume_classification: Classification to resume mid-scroll.
            resume_scroll: Scroll cursor to restart from within
                resume_classification.

        Yields:
            Tuple[List[Indicator], Dict]: Batch and checkpoint dict.

        Raises:
            GreyNoisePluginException: On API or unexpected error so
                the CE sub-checkpoint is preserved for the next run.
        """
        if last_seen_param == "custom" and active_range_days:
            gnql_last_seen = f"{int(active_range_days)}d"
        else:
            gnql_last_seen = last_seen_param

        total_indicator_count = 0

        for cls_idx, classification in enumerate(
            classifications_to_process
        ):
            gnql_query = (
                f"classification:{classification}"
                f" AND last_seen:{gnql_last_seen}"
            )
            if (
                resume_classification
                and classification == resume_classification
            ):
                scroll = resume_scroll
                resume_classification = None
                resume_scroll = None
            else:
                scroll = None

            page_count = 0
            classification_indicator_count = 0
            classification_skip_count = 0
            self.logger.info(
                f"{self.log_prefix}: Pulling '{classification}'"
                " classification IP indicator(s)"
                f" from {PLATFORM_NAME}."
            )

            while True:
                params = {
                    "query": gnql_query,
                    "size": PAGE_SIZE,
                    "exclude": EXCLUDE_FIELDS,
                }
                if scroll:
                    params["scroll"] = scroll

                url = self.greynoise_helper.build_url(
                    GNQL_ENDPOINT, base_url
                )

                try:
                    response = self.greynoise_helper.api_helper(
                        logger_msg=(
                            f"pulling '{classification}' IP"
                            f" indicators from {PLATFORM_NAME}"
                        ),
                        url=url,
                        method="GET",
                        params=params,
                        headers=headers,
                        proxy=self.proxy,
                        verify=self.ssl_validation,
                        is_handle_error_required=True,
                        is_validation=False,
                        is_retraction=is_retraction,
                    )
                except GreyNoisePluginException as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error pulling"
                            f" '{classification}' IP indicators"
                            f" from {PLATFORM_NAME}. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME}"
                            " platform is reachable and the"
                            " API Key is valid."
                        ),
                    )
                    raise
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error"
                            f" pulling '{classification}' IP"
                            f" indicators from {PLATFORM_NAME}."
                            f" Error: {err}"
                        ),
                        details=traceback.format_exc(),
                    )
                    raise GreyNoisePluginException(str(err))

                data = response.get("data", [])
                request_metadata = response.get(
                    "request_metadata", {}
                )

                if not data:
                    break

                page_count += 1
                indicators_batch = []
                page_skip_count = 0
                page_type_counts = {
                    "ipv4": 0,
                    "ipv4_cidr": 0,
                    "ipv6": 0,
                }

                for record in data:
                    isc = record.get(
                        "internet_scanner_intelligence", {}
                    ) or {}
                    if not isc.get("found", True):
                        page_skip_count += 1
                        continue

                    ip_value = (
                        record.get("ip", "") or ""
                    ).strip()

                    if ip_value:
                        try:
                            ip_type_key = self._get_ip_type_key(
                                ip_value
                            )
                            if ip_type_key in (
                                "ipv6", "ipv6_cidr"
                            ):
                                # IPv6 / IPv6 CIDR not supported
                                # by the platform; skip silently.
                                continue
                            indicator = self._build_indicator(
                                value=ip_value,
                                indicator_type=INDICATOR_TYPE_MAP[
                                    ip_type_key
                                ],
                                isc=isc,
                                ip_value=ip_value,
                                enable_tagging=enable_tagging,
                                classification=classification,
                                extra_tags=(
                                    ["ipv4_cidr"]
                                    if ip_type_key == "ipv4_cidr"
                                    else None
                                ),
                            )
                            if indicator:
                                indicators_batch.append(indicator)
                                page_type_counts[ip_type_key] += 1
                            else:
                                page_skip_count += 1
                        except ValueError:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}:"
                                    f" Invalid IP '{ip_value}'."
                                    " Skipping."
                                ),
                                details="",
                                resolution=(
                                    "The GreyNoise API returned"
                                    " an invalid IP value."
                                ),
                            )
                            page_skip_count += 1

                total_indicator_count += len(indicators_batch)
                classification_indicator_count += len(
                    indicators_batch
                )
                classification_skip_count += page_skip_count

                scroll = (
                    request_metadata.get("scroll", "") or ""
                )
                checkpoint = {
                    "classification": classification,
                    "scroll": scroll,
                    "last_seen_param": last_seen_param,
                    "last_seen_param_days": active_range_days,
                    # Persist the not-yet-completed classifications
                    # (current onward) so a resume skips the ones
                    # already finished instead of re-pulling them.
                    "remaining_classifications": (
                        classifications_to_process[cls_idx:]
                    ),
                }

                if is_retraction:
                    page_log = (
                        f"{self.log_prefix}: Pulled"
                        f" {len(indicators_batch)} indicator(s)"
                        f" in page {page_count} for"
                        f" '{classification}' classification."
                        f" Total: {total_indicator_count}."
                    )
                else:
                    pull_stats = ", ".join(
                        f"{label}: {count}"
                        for label, count in [
                            ("IPv4", page_type_counts["ipv4"]),
                            (
                                "IPv4 CIDR",
                                page_type_counts["ipv4_cidr"],
                            ),
                        ]
                        if count > 0
                    )
                    page_log = (
                        f"{self.log_prefix}: Pulled"
                        f" {len(indicators_batch)} indicator(s)"
                        f" in page {page_count} for"
                        f" '{classification}' classification."
                    )
                    if pull_stats:
                        page_log += f" Pull Stats: {pull_stats}."
                    page_log += (
                        f" Total: {total_indicator_count}."
                    )
                if page_skip_count:
                    page_log += (
                        f" Skipped {page_skip_count}"
                        " indicator(s)."
                    )
                self.logger.info(page_log)

                if indicators_batch:
                    yield indicators_batch, checkpoint

                if (
                    request_metadata.get("complete")
                    or not scroll
                ):
                    break

            if not is_retraction:
                classification_log = (
                    f"{self.log_prefix}: Pulled"
                    f" {classification_indicator_count}"
                    " IP indicator(s)"
                    f" for '{classification}' classification."
                )
                if classification_skip_count:
                    classification_log += (
                        f" Skipped {classification_skip_count}"
                        " indicator(s)."
                    )
                self.logger.info(classification_log)

    def _pull(
        self,
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Internal pull generator yielding indicator batches.

        Orchestrates _pull_ip_indicators (GNQL) and _pull_callback,
        resolving the active query range and sub-checkpoint resume
        state before delegating to each section.

        Args:
            is_retraction (bool): When True, use retraction_interval
                as last_seen param. Defaults to False.

        Yields:
            Tuple[List[Indicator], Dict]: Batch and checkpoint dict.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = (
                f"{self.log_prefix} {RETRACTION}"
            )

        (
            base_url,
            api_key,
            enable_tagging,
            ioc_types,
            classifications,
            callback_stages,
            initial_range,
            initial_range_days,
            retraction_interval,
            retraction_interval_days,
        ) = self.greynoise_helper.get_config_params(
            self.configuration
        )
        headers = self.greynoise_helper._get_headers(api_key)

        sub_checkpoint = getattr(self, "sub_checkpoint", {}) or {}

        # Detect whether sub_checkpoint belongs to an IP pull or
        # a callback pull so we resume the right section.
        resuming_ip = (
            not is_retraction
            and bool(sub_checkpoint.get("last_seen_param"))
            and "callback_last_seen_after" not in sub_checkpoint
        )
        resuming_callback = (
            not is_retraction
            and "callback_last_seen_after" in sub_checkpoint
        )

        active_range, active_range_days = self._compute_active_range(
            is_retraction=is_retraction,
            initial_range=initial_range,
            initial_range_days=initial_range_days,
            retraction_interval=retraction_interval,
            retraction_interval_days=retraction_interval_days,
        )

        ip_pull_total = 0
        callback_pull_total = 0

        # ── IP indicators via GNQL ──────────────────────────────
        # Skip when resuming mid-callback — IP pull already completed.
        if "ip" in ioc_types and not resuming_callback:
            if resuming_ip:
                last_seen_param = sub_checkpoint["last_seen_param"]
                active_range_days = sub_checkpoint.get(
                    "last_seen_param_days"
                )
                # On resume, only process the classifications that
                # were not yet completed. The checkpoint persists the
                # remaining list (current + not-yet-started) so
                # classifications finished before the interruption
                # are not re-pulled from page 1.
                classifications_to_process = (
                    sub_checkpoint.get("remaining_classifications")
                    or classifications
                )
                resume_classification = sub_checkpoint.get(
                    "classification"
                )
                resume_scroll = sub_checkpoint.get("scroll")
            else:
                last_seen_param = active_range
                classifications_to_process = classifications
                resume_classification = None
                resume_scroll = None

            for batch, checkpoint in self._pull_ip_indicators(
                base_url=base_url,
                headers=headers,
                enable_tagging=enable_tagging,
                classifications_to_process=classifications_to_process,
                last_seen_param=last_seen_param,
                active_range_days=active_range_days,
                is_retraction=is_retraction,
                resume_classification=resume_classification,
                resume_scroll=resume_scroll,
            ):
                ip_pull_total += len(batch)
                yield batch, checkpoint

        # ── Callback IP / MD5 / SHA256 indicators ──────────────
        fetch_callback = "callback_ip" in ioc_types
        fetch_md5 = "md5" in ioc_types
        fetch_sha256 = "sha256" in ioc_types

        if fetch_callback or fetch_md5 or fetch_sha256:
            callback_start_page = 0
            callback_last_seen_after = None
            if resuming_callback:
                callback_start_page = sub_checkpoint.get(
                    "callback_page", 0
                )
                callback_last_seen_after = sub_checkpoint.get(
                    "callback_last_seen_after"
                )

            for batch, chk in self._pull_callback(
                base_url=base_url,
                headers=headers,
                enable_tagging=enable_tagging,
                callback_stages=callback_stages,
                active_range=active_range,
                active_range_days=active_range_days,
                fetch_callback=fetch_callback,
                fetch_md5=fetch_md5,
                fetch_sha256=fetch_sha256,
                is_retraction=is_retraction,
                start_page=callback_start_page,
                resume_last_seen_after=callback_last_seen_after,
            ):
                callback_pull_total += len(batch)
                yield batch, chk

        if not is_retraction:
            overall_total = ip_pull_total + callback_pull_total
            summary_parts = []
            if ip_pull_total > 0:
                summary_parts.append(f"IP: {ip_pull_total}")
            if callback_pull_total > 0:
                summary_parts.append(
                    f"Callback IPs/Hashes: {callback_pull_total}"
                )
            completion_log = (
                f"{self.log_prefix}: Successfully pulled"
                f" {overall_total} indicator(s)"
                f" from {PLATFORM_NAME}."
            )
            if summary_parts:
                completion_log += (
                    f" {', '.join(summary_parts)}."
                )
            self.logger.info(completion_log)

    def _pull_callback(
        self,
        base_url: str,
        headers: Dict,
        enable_tagging: str,
        callback_stages: List[str],
        active_range: str,
        active_range_days,
        fetch_callback: bool,
        fetch_md5: bool,
        fetch_sha256: bool,
        is_retraction: bool = False,
        start_page: int = 0,
        resume_last_seen_after: Optional[str] = None,
    ) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pull Callback IP, MD5, and SHA256 indicators.

        Uses POST /v1/callback/ips with last_seen_after date filter.
        For MD5, falls back to GET /v1/callback/ip/{ip} per record.

        Args:
            start_page: Page number to resume from (for interrupted runs).
            resume_last_seen_after: Pre-computed date from a previous
                interrupted run's checkpoint; if provided, this overrides
                the freshly computed date so all pages use the same window.

        Yields:
            Tuple[List[Indicator], Dict]: Batch and checkpoint dict.
        """
        if resume_last_seen_after:
            last_seen_after = resume_last_seen_after
        else:
            last_seen_after = self.greynoise_helper.range_to_date(
                active_range, active_range_days
            )

        pulling_types = []
        if fetch_callback:
            pulling_types.append("Callback IP")
        if fetch_sha256:
            pulling_types.append("SHA256")
        if fetch_md5:
            pulling_types.append("MD5")
        if pulling_types:
            self.logger.info(
                f"{self.log_prefix}: Pulling"
                f" {', '.join(pulling_types)} indicator(s)"
                f" from {PLATFORM_NAME}"
                f" for last_seen_after: {last_seen_after}."
            )

        request_body: Dict = {
            "last_seen_after": last_seen_after,
            "page": 0,
            "page_size": CALLBACK_PAGE_SIZE,
        }
        request_body["is_stage_1"] = "stage_1" in callback_stages
        request_body["is_stage_2"] = "stage_2" in callback_stages

        list_url = self.greynoise_helper.build_url(
            CALLBACK_LIST_ENDPOINT, base_url
        )

        page_num = start_page
        total_indicator_count = 0
        total_callback_count = 0
        total_md5_count = 0
        total_sha256_count = 0
        total_skip_count = 0

        while True:
            request_body["page"] = page_num
            types_label = (
                ", ".join(pulling_types)
                if pulling_types
                else "indicators"
            )

            try:
                response = self.greynoise_helper.api_helper(
                    logger_msg=(
                        f"pulling {types_label}"
                        f" (page {page_num + 1})"
                        f" from {PLATFORM_NAME}"
                    ),
                    url=list_url,
                    method="POST",
                    json_data=request_body,
                    headers=headers,
                    proxy=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=True,
                    is_validation=False,
                    is_retraction=is_retraction,
                )
            except GreyNoisePluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error pulling"
                        f" callback indicators from"
                        f" {PLATFORM_NAME}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        f"Ensure that the {PLATFORM_NAME}"
                        " platform is reachable and the"
                        " API Key is valid."
                    ),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        " pulling callback indicators from"
                        f" {PLATFORM_NAME}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                raise GreyNoisePluginException(str(err))

            items = response.get("items", [])
            total_records = response.get("total", 0)

            if not items:
                break

            indicators_batch = []
            page_skip = 0
            page_type_counts = {
                "callback_ip": 0,
                "sha256": 0,
                "md5": 0,
            }

            for record in items:
                ip_value = (record.get("ip", "") or "").strip()
                if not ip_value:
                    page_skip += 1
                    continue

                try:
                    ip_type_key = self._get_ip_type_key(ip_value)
                except ValueError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipped indicator(s)"
                            f" due to invalid or unsupported '{ip_value}'."
                        ),
                        details="",
                        resolution=(
                            "The GreyNoise API returned an invalid"
                            " IP value."
                        ),
                    )
                    page_skip += 1
                    continue

                if ip_type_key in ("ipv6", "ipv6_cidr"):
                    # IPv6 / IPv6 CIDR not supported; skip silently.
                    continue

                first_seen = self._parse_date(
                    (record.get("first_seen") or "")[:10],
                    DATE_FORMAT_FIRST_SEEN,
                )
                last_seen = self._parse_date(
                    (record.get("last_seen") or "")[:10],
                    DATE_FORMAT_FIRST_SEEN,
                )

                tags = []
                if enable_tagging.lower() == "yes":
                    tag_names = ["callback_ip"]
                    if record.get("is_stage_1"):
                        tag_names.append("stage_1")
                    if record.get("is_stage_2"):
                        tag_names.append("stage_2")
                    created, _ = self._create_tags(tag_names)
                    tags = created

                extended_info = (
                    f"{GREYNOISE_URL.rstrip('/')}/ip/{ip_value}"
                )

                if fetch_callback:
                    try:
                        ind = Indicator(
                            value=ip_value,
                            type=INDICATOR_TYPE_MAP[ip_type_key],
                            firstSeen=first_seen,
                            lastSeen=last_seen,
                            tags=tags,
                            extendedInformation=extended_info,
                        )
                        indicators_batch.append(ind)
                        total_callback_count += 1
                        page_type_counts["callback_ip"] += 1
                    except (ValidationError, Exception) as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error"
                                f" building Callback IP indicator"
                                f" '{ip_value}'. Skipping."
                                f" Error: {err}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                f"The {PLATFORM_NAME} API returned"
                                " an unexpected value for the"
                                " Callback IP indicator."
                            ),
                        )
                        page_skip += 1

                # SHA256 and MD5 both come from active_files in
                # the per-IP detail endpoint
                if (
                    (fetch_sha256 or fetch_md5)
                    and record.get("file_count", 0) > 0
                ):
                    detail_url = self.greynoise_helper.build_url(
                        f"{CALLBACK_IP_ENDPOINT}/{ip_value}",
                        base_url,
                    )
                    try:
                        detail = self.greynoise_helper.api_helper(
                            logger_msg=(
                                f"fetching file hashes for"
                                f" callback IP '{ip_value}'"
                            ),
                            url=detail_url,
                            method="GET",
                            headers=headers,
                            proxy=self.proxy,
                            verify=self.ssl_validation,
                            is_handle_error_required=True,
                            is_validation=False,
                            is_retraction=is_retraction,
                        )
                        for file_rec in detail.get(
                            "active_files", []
                        ):
                            inds, skipped, type_counts = (
                                self._build_file_hash_indicators(
                                    file_rec, fetch_sha256, fetch_md5,
                                    first_seen, last_seen, tags, extended_info,
                                )
                            )
                            indicators_batch.extend(inds)
                            page_skip += skipped
                            total_sha256_count += type_counts["sha256"]
                            total_md5_count += type_counts["md5"]
                            page_type_counts["sha256"] += type_counts["sha256"]
                            page_type_counts["md5"] += type_counts["md5"]
                    except (
                        GreyNoisePluginException,
                        Exception,
                    ) as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error"
                                f" fetching file hashes for"
                                f" callback IP '{ip_value}'."
                                f" Skipping. Error: {err}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                "Check logs for more details."
                            ),
                        )

            total_skip_count += page_skip
            total_indicator_count += len(indicators_batch)
            checkpoint = {
                "callback_page": page_num + 1,
                "callback_last_seen_after": last_seen_after,
            }

            stat_pairs = []
            if fetch_callback:
                stat_pairs.append(
                    ("Callback IP", page_type_counts["callback_ip"])
                )
            stat_pairs.append(("SHA256", page_type_counts["sha256"]))
            stat_pairs.append(("MD5", page_type_counts["md5"]))
            pull_stats = ", ".join(
                f"{label}: {count}"
                for label, count in stat_pairs
                if count > 0
            )
            page_log = (
                f"{self.log_prefix}: Pulled"
                f" {len(indicators_batch)} indicator(s)"
                f" in page {page_num + 1}."
            )
            if pull_stats:
                page_log += f" Pull Stats: {pull_stats}."
            page_log += f" Total: {total_indicator_count}."
            if page_skip:
                page_log += (
                    f" Skipped {page_skip} indicator(s)."
                )
            self.logger.info(page_log)

            if indicators_batch:
                yield indicators_batch, checkpoint

            fetched_so_far = (page_num + 1) * CALLBACK_PAGE_SIZE
            if (
                fetched_so_far >= total_records
                or len(items) < CALLBACK_PAGE_SIZE
            ):
                break
            page_num += 1

    def pull(self) -> List[Indicator]:
        """Pull indicators from GreyNoise.

        Returns:
            List[Indicator]: Fetched indicators, or generator
                when sub_checkpoint is present.
        """
        if hasattr(self, "sub_checkpoint"):
            def wrapper(self):
                yield from self._pull()
            return wrapper(self)

        indicators = []
        for batch, _ in self._pull():
            indicators.extend(batch)
        # _pull() already logs the "Successfully pulled …" summary
        # (with IP/Callback breakdown and skip counts) as the single
        # source of truth for the total, in both the generator and
        # flat-list paths. Avoid logging a second, separately computed
        # total here that could silently drift from it.
        return indicators

    def get_modified_indicators(
        self,
        source_indicators: List[List[Indicator]],
    ) -> Generator[Tuple[list, bool], None, None]:
        """Yield indicator values to retract in CE.

        Re-queries GreyNoise with retraction_interval and yields
        CE indicators that are no longer present in the active set.

        Args:
            source_indicators (List[List[Indicator]]): Pages of
                indicators stored in CE.

        Yields:
            Tuple[list, bool]: Retracted values and done flag.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = (
                f"{self.log_prefix} {RETRACTION}"
            )

        retraction_interval = (
            self.configuration.get("retraction_interval", "")
            or ""
        ).strip()

        if (
            not retraction_interval
            or retraction_interval not in VALID_RANGES
        ):
            self.logger.info(
                f"{self.log_prefix}: Retraction Interval is"
                " not configured. Skipping pull retraction"
                f" of IoC(s) for {PLATFORM_NAME}."
            )
            yield [], True
            return

        interval_display = (
            retraction_interval
            if retraction_interval != "custom"
            else (
                "custom"
                f" ({self.configuration.get('retraction_interval_days', '?')}"
                "d)"
            )
        )
        self.logger.info(
            f"{self.log_prefix}: Getting all modified"
            f" indicators from {PLATFORM_NAME}."
            f" Retraction interval: {interval_display}."
        )

        active_ioc_batches = []
        for batch, _ in self._pull(is_retraction=True):
            active_ioc_values = set(
                ind.value for ind in batch
            )
            active_ioc_batches.append(active_ioc_values)

        total_source = 0
        total_retracted = 0
        for ioc_list in source_indicators:
            source_iocs = set(ioc.value for ioc in ioc_list)
            source_ioc_len = len(source_iocs)
            total_source += source_ioc_len
            for active_iocs in active_ioc_batches:
                source_iocs -= active_iocs
            retracted_count = len(source_iocs)
            total_retracted += retracted_count
            self.logger.info(
                f"{self.log_prefix}: {retracted_count}"
                " indicator(s) will be marked as retracted"
                f" from total {source_ioc_len} indicator(s)"
                " in this batch."
            )
            if source_iocs:
                yield list(source_iocs), False

        self.logger.info(
            f"{self.log_prefix}: Total {total_retracted} "
            f"indicator(s) will be retracted "
            f"out of {total_source} active indicator(s)."
        )

    def validate(
        self, configuration: dict
    ) -> ValidationResult:
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

        # Base URL
        base_url = (
            configuration.get("base_url", "").strip().rstrip("/")
        )
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=(
                self.greynoise_helper.validate_url
            ),
        ):
            return result

        # API Key
        api_key = configuration.get("api_key", "")
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="API Key",
            field_value=api_key,
            field_type=str,
        ):
            return result

        # Enable Tagging
        enable_tagging = (
            configuration.get("enable_tagging", "").strip()
        )
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return result

        # IOC Types — must be a non-empty list of valid values
        ioc_types = configuration.get("ioc_types", [])
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="IOC Types",
            field_value=ioc_types,
            field_type=list,
        ):
            return result
        for ioc_type in ioc_types:
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name="IOC Types",
                field_value=ioc_type,
                field_type=str,
                allowed_values=VALID_IOC_TYPES,
            ):
                return result

        # Classification — required when IP is selected
        if "ip" in ioc_types:
            classifications = configuration.get("classification", [])
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name="Classification",
                field_value=classifications,
                field_type=list,
            ):
                return result
            for classification_value in classifications:
                if result := self._validate_configuration_parameters(
                    parameter_type="configuration",
                    field_name="Classification",
                    field_value=classification_value,
                    field_type=str,
                    allowed_values=VALID_CLASSIFICATIONS,
                ):
                    return result

        # Callback Stage 1 / Stage 2 — two independent Yes/No choice
        # fields. Validate each value against the allowed Yes/No set.
        for stage_field_name, stage_key in (
            (
                "Stage 1 (file downloaded from this IP)",
                "callback_stage_1",
            ),
            (
                "Stage 2 (suspected C2 based on VT/sandbox analysis)",
                "callback_stage_2",
            ),
        ):
            stage_value = (
                configuration.get(stage_key, "Yes") or "Yes"
            ).strip()
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name=stage_field_name,
                field_value=stage_value,
                field_type=str,
                allowed_values=["Yes", "No"],
            ):
                return result

        # Initial Range
        initial_range = (
            configuration.get("initial_range", "").strip()
        )
        if result := self._validate_configuration_parameters(
            parameter_type="configuration",
            field_name="Initial Range",
            field_value=initial_range,
            field_type=str,
            allowed_values=VALID_RANGES,
        ):
            return result

        # Initial Range (Days) — only relevant when range is "custom"
        if result := self._validate_range_days(
            "Initial Range",
            "Initial Range (Days)",
            initial_range,
            configuration.get("initial_range_days"),
        ):
            return result

        # Retraction Interval — optional; validate value if provided
        retraction_interval = (
            configuration.get("retraction_interval", "") or ""
        ).strip()
        if retraction_interval:
            if result := self._validate_configuration_parameters(
                parameter_type="configuration",
                field_name="Retraction Interval",
                field_value=retraction_interval,
                field_type=str,
                allowed_values=VALID_RANGES,
            ):
                return result

            # Retraction Interval (Days) — only relevant when "custom"
            if result := self._validate_range_days(
                "Retraction Interval",
                "Retraction Interval (Days)",
                retraction_interval,
                configuration.get("retraction_interval_days"),
            ):
                return result

        return self._validate_connectivity(api_key, base_url)

    def _validate_connectivity(
        self, api_key: str, base_url: str
    ) -> ValidationResult:
        """Validate API connectivity with a lightweight GNQL query.

        Args:
            api_key (str): GreyNoise API key.
            base_url (str): GreyNoise base URL.

        Returns:
            ValidationResult: Success or failure with message.
        """
        try:
            headers = self.greynoise_helper._get_headers(api_key)
            url = self.greynoise_helper.build_url(
                GNQL_ENDPOINT, base_url
            )
            self.greynoise_helper.api_helper(
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME}"
                ),
                url=url,
                method="GET",
                params={
                    "query": (
                        "classification:malicious"
                        " AND last_seen:today"
                    ),
                    "size": 1,
                },
                headers=headers,
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Validation completed"
                " successfully."
            )
        except GreyNoisePluginException as exp:
            return ValidationResult(
                success=False, message=str(exp)
            )
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating"
                f" connectivity with {PLATFORM_NAME}."
                f" Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=(
                    "Verify the Base URL and API Key provided"
                    " in the configuration parameters."
                ),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Unexpected error. Check logs for details."
                ),
            )

        return ValidationResult(
            success=True,
            message=(
                f"Successfully validated connectivity with"
                f" {PLATFORM_NAME} platform."
            ),
        )
