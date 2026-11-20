"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE VMRay Plugin main file.
"""

import ipaddress
import json
import re
import traceback
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Generator, List, Set, Tuple, Type, Union
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType, SeverityType
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from pydantic import ValidationError

from .utils.constants import (
    ALL_RETRACTION_VERDICTS,
    CE_TAG,
    DATE_FORMAT_VMRAY,
    DOMAIN_REGEX,
    EMPTY_ERROR_MESSAGE,
    FQDN_REGEX,
    INVALID_VALUE_ERROR_MESSAGE,
    MAX_INTERVAL_DAYS,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    SAMPLE_IOC_ENDPOINT,
    SUBMISSION_DELETE_ENDPOINT,
    SUBMISSION_FINISH_TIME_ENDPOINT,
    SUBMISSION_SEARCH_ENDPOINT,
    SUBMIT_SAMPLE_ENDPOINT,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exception import VMRayPluginException
from .utils.helper import (
    VMRayPluginHelper,
    IOC_TYPE_PULL_LABEL,
    NUMERIC_SEVERITY_MAP,
    VMRAY_IOC_TYPE_MAP,
)


class VMRayPlugin(PluginBase):
    """VMRay CTE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """VMRay plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.vmray_helper = VMRayPluginHelper(
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
            manifest_json = VMRayPlugin.metadata
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
                resolution="Check logs for more details.",
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _validate_parameters(
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
                    f"Ensure a valid value is provided from the"
                    f" allowed values.\nAllowed values: {allowed_str}"
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def determine_ioc_type(self, ioc_value: str) -> str:
        """Classify an indicator value as ipv4, ipv6, fqdn, domain, or url.

        Args:
            ioc_value (str): Indicator value to classify.

        Returns:
            str: One of "ipv4", "ipv6", "fqdn", "domain", "url".
        """
        try:
            ip = ipaddress.ip_address(ioc_value)
            return (
                "ipv6"
                if isinstance(ip, ipaddress.IPv6Address)
                else "ipv4"
            )
        except ValueError:
            pass
        if re.fullmatch(FQDN_REGEX, ioc_value):
            return "fqdn"
        if re.fullmatch(DOMAIN_REGEX, ioc_value):
            return "domain"
        return "url"

    # ----------------------------------------------------------------
    # PULL FLOW
    # ----------------------------------------------------------------

    def _resolve_pull_time_window(
        self, sub_checkpoint: Dict
    ) -> Tuple[datetime, datetime]:
        """Resolve (start_time, end_time) for a normal pull cycle.

        Precedence: sub_checkpoint → last_run_at → initial_range fallback.

        Args:
            sub_checkpoint (Dict): Active sub-checkpoint dict (may be empty).

        Returns:
            Tuple[datetime, datetime]: (start_time, end_time) without tz info.
        """
        end_time = datetime.now(timezone.utc).replace(tzinfo=None)

        if sub_checkpoint and sub_checkpoint.get("start_time"):
            try:
                return (
                    datetime.strptime(
                        sub_checkpoint["start_time"], DATE_FORMAT_VMRAY
                    ),
                    datetime.strptime(
                        sub_checkpoint["end_time"], DATE_FORMAT_VMRAY
                    ),
                )
            except (ValueError, KeyError):
                pass

        if self.last_run_at:
            return self.last_run_at, end_time

        initial_range = int(
            self.configuration.get("initial_range", 7)
        )
        self.logger.info(
            f"{self.log_prefix}: Initial data pull."
            f" Querying last {initial_range} days."
        )
        return end_time - timedelta(days=initial_range), end_time

    def pull(self) -> List[Indicator]:
        """Pull indicators from VMRay.

        Returns:
            List[Indicator]: Fetched indicators, or generator when
                sub_checkpoint is present.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", "Yes"
        )
        if is_pull_required != "Yes":
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in"
                " configuration parameter hence skipping pulling"
                f" of indicators from {PLATFORM_NAME}."
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
            f"{self.log_prefix}: Successfully pulled"
            f" {len(indicators)} indicator(s) from {PLATFORM_NAME}."
        )
        return indicators

    def _pull(
        self,
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Internal pull generator yielding indicator batches.

        Args:
            is_retraction (bool): When True, fetch for retraction
                diff (all verdicts). Defaults to False.

        Yields:
            Tuple[List[Indicator], Dict]: Batch of indicators and
                checkpoint dict.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = (
                f"{self.log_prefix} {RETRACTION}"
            )

        (
            base_url,
            api_token,
            sample_verdicts,
            ioc_types,
            _,
            _,
        ) = self.vmray_helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.vmray_helper._get_headers(api_token)

        sub_checkpoint = getattr(self, "sub_checkpoint", {}) or {}

        if is_retraction:
            retraction_interval = int(
                self.configuration.get("retraction_interval", 7)
            )
            end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            start_time = end_time - timedelta(days=retraction_interval)
        else:
            start_time, end_time = self._resolve_pull_time_window(
                sub_checkpoint
            )

        verdicts_to_fetch = ALL_RETRACTION_VERDICTS

        start_str = start_time.strftime(DATE_FORMAT_VMRAY)
        end_str = end_time.strftime(DATE_FORMAT_VMRAY)
        selected_ioc_types = ioc_types or [
            "domains", "ipv4", "urls", "md5", "sha256"
        ]

        checkpoint_base = {
            "start_time": start_str,
            "end_time": end_str,
        }

        resume_verdict = sub_checkpoint.get("verdict")
        resume_min_id = sub_checkpoint.get("min_id")
        total_indicator_count = 0
        total_skip_count = 0

        for verdict in verdicts_to_fetch:
            if (
                resume_verdict
                and verdict != resume_verdict
                and not is_retraction
            ):
                continue

            self.logger.info(
                f"{self.log_prefix}: Pulling submissions with"
                f" '{verdict}' verdict type from {PLATFORM_NAME}."
            )

            endpoint = SUBMISSION_FINISH_TIME_ENDPOINT.format(
                start=start_str, end=end_str
            )
            url = self.vmray_helper.build_url(endpoint, base_url)
            params = {
                "submission_verdict": verdict,
                "_limit": PAGE_SIZE,
                "_order": "asc",
            }

            if (
                resume_min_id
                and verdict == resume_verdict
                and not is_retraction
            ):
                params["_min_id"] = resume_min_id
                resume_min_id = None

            page_count = 0

            while True:
                try:
                    response = self.vmray_helper.api_helper(
                        logger_msg=(
                            f"pulling '{verdict}' submissions"
                            f" from {PLATFORM_NAME}"
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
                except VMRayPluginException as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error pulling"
                            f" '{verdict}' submissions. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME} platform"
                            " is reachable and the API Token is valid."
                        ),
                    )
                    break
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error"
                            f" pulling '{verdict}' submissions."
                            f" Error: {err}"
                        ),
                        details=traceback.format_exc(),
                        resolution="Check logs for more details.",
                    )
                    break

                data = response.get("data", [])
                if not data:
                    break

                page_count += 1
                indicators_batch = []
                ioc_skip_count = 0
                page_type_counts = {
                    "domain": 0,
                    "fqdn": 0,
                    "url": 0,
                    "ipv4": 0,
                    "md5": 0,
                    "sha256": 0,
                }

                for submission in data:
                    sub_tags = submission.get(
                        "submission_tags"
                    ) or []
                    if any(CE_TAG in tag for tag in sub_tags):
                        continue

                    sample_id = submission.get(
                        "submission_sample_id"
                    )
                    sub_webif_url = submission.get(
                        "submission_webif_url"
                    )

                    if sample_id is None:
                        continue

                    ioc_indicators, skipped = self._fetch_sample_iocs(
                        sample_id=sample_id,
                        submission_tags=sub_tags,
                        submission_webif_url=sub_webif_url,
                        selected_ioc_types=selected_ioc_types,
                        selected_verdicts=sample_verdicts,
                        base_url=base_url,
                        headers=headers,
                        is_retraction=is_retraction,
                    )
                    for ind in ioc_indicators:
                        type_key = IOC_TYPE_PULL_LABEL.get(ind.type)
                        if type_key:
                            page_type_counts[type_key] += 1
                    indicators_batch.extend(ioc_indicators)
                    ioc_skip_count += skipped

                last_id = data[-1].get("submission_id")
                if last_id is None:
                    break
                next_min_id = last_id + 1
                params["_min_id"] = next_min_id

                checkpoint = dict(checkpoint_base)
                checkpoint["verdict"] = verdict
                checkpoint["min_id"] = next_min_id

                total_indicator_count += len(indicators_batch)
                total_skip_count += ioc_skip_count
                if is_retraction:
                    page_log = (
                        f"{self.log_prefix}: Pulled"
                        f" {len(indicators_batch)} indicator(s) from"
                        f" {len(data)} submission(s) in page"
                        f" {page_count} for '{verdict}' verdict type."
                        f" Total indicator(s) pulled:"
                        f" {total_indicator_count}."
                    )
                else:
                    pull_stats = ", ".join(
                        f"{label}: {count}"
                        for label, count in [
                            ("Domains", page_type_counts["domain"]),
                            ("FQDNs", page_type_counts["fqdn"]),
                            ("URLs", page_type_counts["url"]),
                            ("IPv4", page_type_counts["ipv4"]),
                            ("MD5", page_type_counts["md5"]),
                            ("SHA256", page_type_counts["sha256"]),
                        ]
                        if count > 0
                    )
                    page_log = (
                        f"{self.log_prefix}: Pulled"
                        f" {len(indicators_batch)} indicator(s) from"
                        f" {len(data)} submission(s) in page"
                        f" {page_count} for '{verdict}' verdict type."
                        f" Pull Stats: {pull_stats}."
                        f" Total indicator(s) pulled:"
                        f" {total_indicator_count}."
                    )
                if ioc_skip_count:
                    page_log += (
                        f" Skipped {ioc_skip_count} indicator(s)."
                    )
                self.logger.info(page_log)

                if indicators_batch:
                    yield indicators_batch, checkpoint

            resume_verdict = None

        if not is_retraction:
            completion_log = (
                f"{self.log_prefix}: Successfully pulled"
                f" {total_indicator_count} indicator(s)"
                f" from {PLATFORM_NAME}."
            )
            if total_skip_count:
                completion_log += (
                    f" Skipped {total_skip_count} indicator(s)."
                )
            self.logger.info(completion_log)

    def _fetch_sample_iocs(
        self,
        sample_id: int,
        submission_tags: List[str],
        submission_webif_url: str,
        selected_ioc_types: List[str],
        selected_verdicts: List[str],
        base_url: str,
        headers: Dict,
        is_retraction: bool = False,
    ) -> Tuple[List[Indicator], int]:
        """Fetch and build Indicator objects for a single sample.

        Args:
            sample_id (int): VMRay sample ID.
            submission_tags (List[str]): Tags on the submission.
            submission_webif_url (str): Web interface URL.
            selected_ioc_types (List[str]): User-selected IOC types.
            selected_verdicts (List[str]): User-selected verdict types
                for IOC filtering.
            base_url (str): VMRay instance base URL.
            headers (Dict): Auth headers.
            is_retraction (bool): Retraction mode flag.

        Returns:
            Tuple[List[Indicator], int]: Indicators and skip count.
        """
        endpoint = SAMPLE_IOC_ENDPOINT.format(sample_id=sample_id)
        url = self.vmray_helper.build_url(endpoint, base_url)

        indicators = []
        skip_count = 0

        ioc_category_map = [
            ("domains", "domain", "domain"),
            ("urls", "url", "url"),
        ]

        for ioc_verdict in selected_verdicts:
            try:
                response = self.vmray_helper.api_helper(
                    logger_msg=(
                        f"pulling '{ioc_verdict}' IOCs for sample"
                        f" {sample_id} from {PLATFORM_NAME}"
                    ),
                    url=url,
                    method="GET",
                    params={
                        "all_artifacts": "true",
                        "ioc_verdict": ioc_verdict,
                    },
                    headers=headers,
                    proxy=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=True,
                    is_validation=False,
                    is_retraction=is_retraction,
                )
            except VMRayPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error pulling"
                        f" '{ioc_verdict}' IOCs for sample"
                        f" {sample_id}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        f"Ensure that the {PLATFORM_NAME} platform"
                        " is reachable and the API Token is valid."
                    ),
                )
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error pulling"
                        f" '{ioc_verdict}' IOCs for sample"
                        f" {sample_id}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution="Check logs for more details.",
                )
                continue

            ioc_data = (
                response.get("data", {}).get("iocs", {})
                if isinstance(response.get("data"), dict)
                else {}
            )

            for cfg_key, type_key, value_field in ioc_category_map:
                if cfg_key not in selected_ioc_types:
                    continue
                for item in ioc_data.get(cfg_key, []):
                    value = item.get(value_field, "")
                    if not value or not str(value).strip():
                        continue
                    value = str(value).strip()
                    resolved_type_key = (
                        self.determine_ioc_type(value)
                        if cfg_key in ("domains", "urls")
                        else type_key
                    )
                    indicator = self._build_indicator(
                        value=value,
                        type_key=resolved_type_key,
                        item=item,
                        submission_tags=submission_tags,
                        submission_webif_url=submission_webif_url,
                    )
                    if indicator:
                        indicators.append(indicator)
                    else:
                        skip_count += 1

            if "ipv4" in selected_ioc_types:
                for item in ioc_data.get("ips", []):
                    value = item.get("ip_address", "")
                    if not value or not str(value).strip():
                        continue
                    value = str(value).strip()
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        self.logger.debug(
                            f"{self.log_prefix}: Skipping invalid IP"
                            f" address '{value}' for sample {sample_id}."
                        )
                        skip_count += 1
                        continue
                    indicator = self._build_indicator(
                        value=value,
                        type_key=self.determine_ioc_type(value),
                        item=item,
                        submission_tags=submission_tags,
                        submission_webif_url=submission_webif_url,
                    )
                    if indicator:
                        indicators.append(indicator)
                    else:
                        skip_count += 1

            fetch_md5 = "md5" in selected_ioc_types
            fetch_sha256 = "sha256" in selected_ioc_types
            if fetch_md5 or fetch_sha256:
                for item in ioc_data.get("files", []):
                    hashes = item.get("hashes", [])
                    if not hashes:
                        continue
                    hash_entry = hashes[0]

                    if fetch_md5:
                        md5 = hash_entry.get("md5_hash")
                        if md5 and str(md5).strip():
                            indicator = self._build_indicator(
                                value=str(md5).strip(),
                                type_key="file_md5",
                                item=item,
                                submission_tags=submission_tags,
                                submission_webif_url=submission_webif_url,
                            )
                            if indicator:
                                indicators.append(indicator)
                            else:
                                skip_count += 1

                    if fetch_sha256:
                        sha256 = hash_entry.get("sha256_hash")
                        if sha256 and str(sha256).strip():
                            indicator = self._build_indicator(
                                value=str(sha256).strip(),
                                type_key="file_sha256",
                                item=item,
                                submission_tags=submission_tags,
                                submission_webif_url=submission_webif_url,
                            )
                            if indicator:
                                indicators.append(indicator)
                            else:
                                skip_count += 1

        return indicators, skip_count

    def _create_tags(self, tags: List[str]) -> Tuple[List, List]:
        """Create tags in CE if they do not already exist.

        Args:
            tags (List[str]): Tag names to create.

        Returns:
            Tuple[List, List]: (created_tags, skipped_tags).
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = [], []
        for tag in tags:
            tag_name = tag.strip()
            if not tag_name:
                continue
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(
                        TagIn(name=tag_name, color="#ED3347")
                    )
                created_tags.append(tag_name)
            except ValueError:
                skipped_tags.append(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error while"
                        f" creating tag '{tag_name}'. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                    resolution=(
                        "Ensure the CE platform API is accessible"
                        " and the required permissions are granted."
                    ),
                )
                skipped_tags.append(tag_name)
        return created_tags, skipped_tags

    def _build_indicator(
        self,
        value: str,
        type_key: str,
        item: Dict,
        submission_tags: List[str],
        submission_webif_url: str,
    ):
        """Build a single Indicator from a VMRay IOC entry.

        Args:
            value (str): IOC string value.
            type_key (str): Key into VMRAY_IOC_TYPE_MAP.
            item (Dict): Raw IOC entry dict from VMRay API.
            submission_tags (List[str]): Tags from the submission.
            submission_webif_url (str): Web interface URL.

        Returns:
            Indicator or None: Constructed indicator, or None on error.
        """
        indicator_type = VMRAY_IOC_TYPE_MAP.get(
            type_key, IndicatorType.URL
        )
        numeric_sev = item.get("numeric_severity", 0)
        try:
            numeric_sev = int(numeric_sev)
        except (TypeError, ValueError):
            numeric_sev = 0
        severity = NUMERIC_SEVERITY_MAP.get(
            numeric_sev, SeverityType.UNKNOWN
        )

        raw_tags = list(submission_tags or [])
        ioc_verdict = item.get("verdict", "")
        if ioc_verdict:
            raw_tags.append(ioc_verdict)
        protocols = item.get("protocols", [])
        if protocols:
            raw_tags.extend([str(p) for p in protocols if p])

        created_tags, skipped_tags = self._create_tags(raw_tags)
        if skipped_tags:
            self.logger.debug(
                f"{self.log_prefix}: Skipped tag(s) {skipped_tags}"
                f" for indicator '{value}' as they could not be"
                f" created in CE."
            )

        extended_info = (
            submission_webif_url if submission_webif_url else None
        )

        try:
            indicator = Indicator(
                value=value,
                type=indicator_type,
                severity=severity,
                tags=created_tags,
                comments=str(item.get("severity", "")) or None,
                extendedInformation=extended_info,
            )
            return indicator
        except ValidationError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error creating"
                    f" indicator for value '{value}'."
                    f" Skipping. Error: {err}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure the indicator value is valid and"
                    " supported by the CE platform."
                ),
            )
            return None
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error creating"
                    f" indicator for value '{value}'."
                    f" Skipping. Error: {err}"
                ),
                details=str(traceback.format_exc()),
                resolution="Check logs for more details.",
            )
            return None

    # ----------------------------------------------------------------
    # PULL RETRACTION
    # ----------------------------------------------------------------

    def get_modified_indicators(
        self,
        source_indicators: List[List[Indicator]],
    ) -> Generator[Tuple[list, bool], None, None]:
        """Yield indicators that should be retracted in CE.

        Fetches all currently-active (malicious + suspicious) IOCs
        from VMRay for the retraction window, then for each page of
        CE source indicators yields those no longer present in VMRay.

        Args:
            source_indicators (List[List[Indicator]]): Pages of
                indicators currently stored in CE.

        Yields:
            Tuple[list, bool]: List of indicator values to retract
                and a completion flag (always False).
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"

        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators"
            f" from {PLATFORM_NAME}."
        )

        retraction_interval = self.configuration.get(
            "retraction_interval"
        )
        if not (
            retraction_interval
            and isinstance(retraction_interval, int)
        ):
            log_msg = (
                "Retraction Interval is not configured. Skipping"
                f" pull retraction of IoC(s) for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
            return

        retraction_interval = int(retraction_interval)

        active_ioc_batches = []
        for batch, _ in self._pull(is_retraction=True):
            active_ioc_values = set(
                ind.value for ind in batch
            )
            active_ioc_batches.append(active_ioc_values)

        for ioc_list in source_indicators:
            source_iocs = set(ioc.value for ioc in ioc_list)
            source_ioc_len = len(source_iocs)
            for active_iocs in active_ioc_batches:
                source_iocs = source_iocs - active_iocs
            self.logger.info(
                f"{self.log_prefix}: {len(source_iocs)}"
                " indicator(s) will be marked as retracted"
                f" from total {source_ioc_len} indicator(s)."
            )
            if source_iocs:
                yield list(source_iocs), False

    # ----------------------------------------------------------------
    # PUSH FLOW
    # ----------------------------------------------------------------

    def push(
        self,
        indicators: List[Indicator],
        action_dict: dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Submit URL/Domain indicators to VMRay sandbox.

        Args:
            indicators (List[Indicator]): Indicators to push.
            action_dict (dict): Action configuration from CE.
            source (str): Source name from CE core.
            business_rule (str): Business rule name from CE core.
            plugin_name (str): Plugin configuration name from CE core.

        Returns:
            PushResult: Result of push operation.
        """
        action_label = action_dict.get("label", "Add To URL Basic Analysis")
        action_params = action_dict.get("parameters", {})
        indicators = list(indicators)

        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )

        (
            base_url,
            api_token,
            _,
            _,
            _,
            _,
        ) = self.vmray_helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.vmray_helper._get_headers(api_token)

        supported_types = [
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.FQDN,
            IndicatorType.IPV4,
        ]
        not_supported_type_names = {
            IndicatorType.IPV6: "IPv6",
            IndicatorType.HOSTNAME: "Hostname",
        }

        total_iocs = len(indicators)
        skip_count = sum(
            1 for ind in indicators
            if ind.type not in supported_types
        )
        skip_msg = (
            f" {skip_count} indicator(s) will be skipped as they"
            " are of invalid types."
            if skip_count > 0
            else ""
        )
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action for"
            f" {total_iocs - skip_count} indicator(s).{skip_msg}"
        )
        success_count = 0
        failed_count = 0
        failed_iocs = []
        skipped_type_iocs = []
        quota_exceeded = False

        for indicator in indicators:
            if indicator.type in not_supported_type_names:
                type_name = not_supported_type_names[indicator.type]
                self.logger.debug(
                    f"{self.log_prefix}: Skipping indicator"
                    f" '{indicator.value}'. {type_name} type"
                    f" is not supported by {PLATFORM_NAME}"
                    " for sharing."
                )
                skipped_type_iocs.append(indicator.value)
                continue
            if indicator.type not in supported_types:
                skipped_type_iocs.append(indicator.value)
                continue

            sample_url = indicator.value

            enable_reputation = action_params.get(
                "enable_reputation"
            )
            comment = action_params.get("comment", "").strip()

            indicator_tags = list(indicator.tags or [])
            ce_tag = (
                f"{CE_TAG}-{plugin_name.replace(' ', '-')}"
                if plugin_name else CE_TAG
            )
            tag_string = ",".join([ce_tag] + indicator_tags)

            submission_metadata = {
                "ce_severity": str(indicator.severity),
                "ce_reputation": str(
                    getattr(indicator, "reputation", "")
                ) if getattr(indicator, "reputation", None) is not None else "",
                "ioc_comment": indicator.comments or "",
            }

            submit_params = {"sample_url": sample_url}

            request_body = {
                "tags": tag_string,
                "submission_metadata": json.dumps(submission_metadata),
            }

            if enable_reputation is not None:
                request_body["enable_reputation"] = enable_reputation
            request_body["live_interaction"] = "false"
            if comment:
                request_body["comment"] = comment

            indicator_logger_msg = (
                f"pushing indicator '{indicator.value}'"
                f" to {PLATFORM_NAME}"
            )
            url = self.vmray_helper.build_url(
                SUBMIT_SAMPLE_ENDPOINT, base_url
            )
            try:
                response = self.vmray_helper.api_helper(
                    logger_msg=indicator_logger_msg,
                    url=url,
                    method="POST",
                    headers=headers,
                    params=submit_params,
                    json_data=request_body,
                    proxy=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=False,
                    is_validation=False,
                    is_retraction=False,
                )

                if not self.vmray_helper.handle_push_error(
                    response, indicator.value, indicator_logger_msg
                ):
                    failed_count += 1
                    failed_iocs.append(indicator.value)
                    continue

                parsed = self.vmray_helper.parse_response(
                    response,
                    logger_msg=indicator_logger_msg,
                )
                result = parsed.get("result", "")
                if result == "ok":
                    submission_errors = (
                        parsed.get("data", {}).get("errors", [])
                    )
                    quota_error = next(
                        (
                            e for e in submission_errors
                            if "exceed the Prepaid Report Quota"
                            in str(e.get("error_msg", ""))
                        ),
                        None,
                    )
                    if quota_error:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: An error occured while sharing"
                                f" indicator(s) to {PLATFORM_NAME} due to"
                                " quota exceeded."
                            ),
                            details=str(quota_error),
                        )
                        quota_exceeded = True
                        break
                    for err_entry in submission_errors:
                        self.logger.debug(
                            f"{self.log_prefix}: Submission"
                            f" warning for '{indicator.value}':"
                            f" {err_entry}"
                        )
                    success_count += 1
                else:
                    error_msg = parsed.get(
                        "error_msg", "Unknown error"
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: An error occured while sharing"
                            f" indicator(s) to {PLATFORM_NAME} due to"
                            " quota exceeded."
                        ),
                        details=error_msg,
                    )
                    if "exceed the Prepaid Report Quota" in error_msg:
                        quota_exceeded = True
                        break
                    failed_count += 1
                    failed_iocs.append(indicator.value)

            except VMRayPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error pushing"
                        f" '{indicator.value}'. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        f"Ensure the {PLATFORM_NAME} Base URL and"
                        " API Token in the configuration parameters"
                        " are correct."
                    ),
                )
                failed_count += 1
                failed_iocs.append(indicator.value)
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        f" pushing '{indicator.value}'."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution="Check logs for more details.",
                )
                failed_count += 1
                failed_iocs.append(indicator.value)

        if skipped_type_iocs:
            self.logger.debug(
                f"{self.log_prefix}: Skipped to push {len(skipped_type_iocs)} indicator(s)"
                f" on {PLATFORM_NAME}.",
                details=", ".join(skipped_type_iocs),
            )
        if failed_iocs:
            self.logger.debug(
                f"{self.log_prefix}: Failed to push {len(failed_iocs)} indicator(s)"
                f" on {PLATFORM_NAME}.",
                details=", ".join(failed_iocs),
            )
        quota_skipped_count = (
            total_iocs
            - success_count
            - failed_count
            - len(skipped_type_iocs)
            if quota_exceeded
            else 0
        )
        push_summary = (
            f"{self.log_prefix}: Successfully pushed"
            f" {success_count} indicator(s) to {PLATFORM_NAME}."
        )
        if failed_count > 0:
            push_summary += (
                f" Failed to push {failed_count} indicator(s)."
            )
        if skipped_type_iocs:
            push_summary += (
                f" {len(skipped_type_iocs)} indicator(s) skipped"
                " due to invalid or unsupported type."
            )
        if quota_skipped_count > 0:
            push_summary += (
                f" {quota_skipped_count} indicator(s) skipped"
                " due to quota exceeded."
            )
        self.logger.info(push_summary)

        return PushResult(
            success=True,
            message=(
                f"Successfully executed {action_label} action."
            ),
            failed_iocs=failed_iocs,
        )

    # ----------------------------------------------------------------
    # PUSH RETRACTION
    # ----------------------------------------------------------------

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        _action_dict: dict,
    ) -> Generator[ValidationResult, None, None]:
        """Delete VMRay submissions created by this plugin.

        The config-level push retraction toggle must be set to 'Yes'
        for deletion to execute.

        Args:
            retracted_indicators_lists (List[List[Indicator]]): Batches
                of indicators to retract.
            _action_dict (dict): Action configuration from CE.

        Yields:
            ValidationResult: Validation result.
        """
        retraction_log_prefix = self.log_prefix
        if RETRACTION not in self.log_prefix:
            retraction_log_prefix = (
                f"{self.log_prefix} {RETRACTION}"
            )

        config_gate = self.configuration.get(
            "enable_push_retraction", "No"
        )

        if config_gate != "Yes":
            self.logger.info(
                f"{retraction_log_prefix}: Push retraction is"
                " disabled in the configuration parameters."
                " Skipping push retraction."
            )
            yield ValidationResult(
                success=False,
                disabled=True,
                message=(   
                    "Push retraction is disabled in the"
                    " configuration parameters. Skipping push retraction."
                ),
            )
            return

        self.logger.info(
            f"{retraction_log_prefix}: Starting retraction of"
            f" indicator(s) from {PLATFORM_NAME} platform."
        )

        (
            base_url,
            api_token,
            _,
            _,
            _,
            _,
        ) = self.vmray_helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.vmray_helper._get_headers(api_token)

        supported_types = [
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.FQDN,
            IndicatorType.IPV4,
        ]

        success_count = 0
        failed_count = 0
        skip_count = 0

        for indicator_list in retracted_indicators_lists:
            for indicator in indicator_list:
                if indicator.type not in supported_types:
                    skip_count += 1
                    continue

                query = f'url == "{indicator.value}"'

                search_full_url = self.vmray_helper.build_url(
                    SUBMISSION_SEARCH_ENDPOINT, base_url
                )
                search_params = {"query": query}

                try:
                    search_response = self.vmray_helper.api_helper(
                        logger_msg=(
                            f"searching submission for"
                            f" '{indicator.value}'"
                        ),
                        url=search_full_url,
                        method="GET",
                        params=search_params,
                        headers=headers,
                        proxy=self.proxy,
                        verify=self.ssl_validation,
                        is_handle_error_required=True,
                        is_validation=False,
                        is_retraction=True,
                    )
                except VMRayPluginException as err:
                    self.logger.error(
                        message=(
                            f"{retraction_log_prefix}: Error searching"
                            f" submission for '{indicator.value}'."
                            f" Error: {err}"
                        ),
                        details=traceback.format_exc(),
                        resolution=(
                            f"Ensure the {PLATFORM_NAME} Base URL and"
                            " API Token in the configuration parameters"
                            " are correct."
                        ),
                    )
                    failed_count += 1
                    continue
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{retraction_log_prefix}: Unexpected error"
                            f" searching submission for"
                            f" '{indicator.value}'. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                        resolution="Check logs for more details.",
                    )
                    failed_count += 1
                    continue

                submission_ids_to_delete = []
                for submission in search_response.get("data", []):
                    sub_id = submission.get("submission_id")
                    sub_tags = submission.get(
                        "submission_tags"
                    ) or []
                    if sub_id and any(
                        CE_TAG in tag for tag in sub_tags
                    ):
                        submission_ids_to_delete.append(sub_id)

                for sub_id in submission_ids_to_delete:
                    delete_endpoint = SUBMISSION_DELETE_ENDPOINT.format(
                        submission_id=sub_id
                    )
                    delete_url = self.vmray_helper.build_url(
                        delete_endpoint, base_url
                    )
                    try:
                        del_response = self.vmray_helper.api_helper(
                            logger_msg=(
                                f"deleting submission {sub_id}"
                            ),
                            url=delete_url,
                            method="DELETE",
                            headers=headers,
                            proxy=self.proxy,
                            verify=self.ssl_validation,
                            is_handle_error_required=False,
                            is_validation=False,
                            is_retraction=True,
                        )
                        if self.vmray_helper.handle_delete_response(
                            del_response, sub_id, retraction_log_prefix
                        ):
                            success_count += 1
                        else:
                            failed_count += 1
                    except VMRayPluginException as err:
                        self.logger.error(
                            message=(
                                f"{retraction_log_prefix}: Error"
                                f" deleting submission {sub_id}."
                                f" Error: {err}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                f"Ensure the API Token has delete"
                                f" permissions on the {PLATFORM_NAME}"
                                " platform."
                            ),
                        )
                        failed_count += 1
                    except Exception as err:
                        self.logger.error(
                            message=(
                                f"{retraction_log_prefix}: Unexpected"
                                f" error deleting submission {sub_id}."
                                f" Error: {err}"
                            ),
                            details=traceback.format_exc(),
                            resolution="Check logs for more details.",
                        )
                        failed_count += 1

        success_logger = (
            f"Successfully deleted {success_count} submission(s)"
            " associated with retracted indicator(s)"
            f" from {PLATFORM_NAME} platform."
        )
        if skip_count > 0:
            success_logger += (
                f" Skipped deleting {skip_count} submission(s) associated"
                " with retracted indicator(s) as they"
                f" are not supported by {PLATFORM_NAME} platform."
            )
        self.logger.info(f"{retraction_log_prefix}: {success_logger}")
        if failed_count > 0:
            self.logger.info(
                f"{retraction_log_prefix}: Failed to delete"
                f" {failed_count} submission(s) associated with retracted"
                f" indicator(s) from {PLATFORM_NAME}"
                " platform as they were not present on the platform"
                " or were of invalid type."
            )

        yield ValidationResult(
            success=True,
            message="Push retraction completed.",
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
                label="Add To URL Basic Analysis",
                value="add_url_basic_analysis",
            )
        ]

    def get_action_fields(self, action: Action) -> List[dict]:
        """Return parameter fields for the given action.

        Args:
            action (Action): Selected push action.

        Returns:
            List[dict]: Field definitions for the action UI.
        """
        if action.value == "add_url_basic_analysis":
            return [
                {
                    "label": "Reputation Analysis",
                    "key": "enable_reputation",
                    "type": "choice",
                    "choices": [
                        {"key": "True", "value": "true"},
                        {"key": "False", "value": "false"},
                    ],
                    "default": "true",
                    "mandatory": False,
                    "description": (
                        "Select Reputation Analysis for URL basic analysis. "
                        "Set to True for find out if this sample is known "
                        "to be malicious or benign. Default value is True."
                    ),
                },
                {
                    "label": "Submission Comment",
                    "key": "comment",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Optional comment for URL basic analysis."
                        " Allowed maximum 255 characters."
                    ),
                },
            ]
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action parameters.

        Args:
            action (Action): Action to validate.

        Returns:
            ValidationResult: Validation result.
        """
        if action.value not in ["add_url_basic_analysis"]:
            return ValidationResult(
                success=False,
                message=(
                    f"Invalid action '{action.value}'."
                    " Supported actions: 'add_url_basic_analysis'."
                ),
            )

        params = action.parameters or {}

        comment = params.get("comment", "") or ""
        if len(comment.strip()) > 255:
            return ValidationResult(
                success=False,
                message=(
                    "Comment must not exceed 255 characters."
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

        base_url = (
            configuration.get("base_url", "").strip().rstrip("/")
        )
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=(
                self.vmray_helper.validate_url
            ),
        ):
            return validation_result

        api_token = configuration.get("api_token")
        if not api_token:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name="API Token",
                parameter_type="configuration",
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    "Ensure a valid API Token is provided in the"
                    " configuration parameters."
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        sample_verdicts = configuration.get(
            "sample_verdicts", []
        )
        if not sample_verdicts or not isinstance(
            sample_verdicts, list
        ):
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name="Type of Verdict",
                parameter_type="configuration",
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        for sv in sample_verdicts:
            if sv not in ["malicious", "suspicious"]:
                err_msg = (
                    f"Invalid value '{sv}' for Type of Verdict."
                    " Allowed: 'malicious', 'suspicious'."
                )
                return ValidationResult(
                    success=False, message=err_msg
                )

        ioc_types = configuration.get("ioc_types", [])
        if ioc_types and not isinstance(ioc_types, list):
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name="Type of IOCs",
                parameter_type="configuration",
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        for it in (ioc_types or []):
            if it not in ["domains", "ipv4", "urls", "md5", "sha256"]:
                err_msg = (
                    f"Invalid value '{it}' for Type of IOCs."
                    " Allowed: 'domains', 'ipv4', 'urls', 'md5',"
                    " 'sha256'."
                )
                return ValidationResult(
                    success=False, message=err_msg
                )

        is_pull_required = (
            configuration.get("is_pull_required", "").strip()
        )
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return validation_result

        enable_push_retraction = (
            configuration.get(
                "enable_push_retraction", ""
            ).strip()
        )
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Push Retraction",
            field_value=enable_push_retraction,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return validation_result

        retraction_interval = configuration.get(
            "retraction_interval"
        )
        if retraction_interval is not None and str(
            retraction_interval
        ).strip():
            try:
                ri = int(retraction_interval)
                if ri < 1 or ri > MAX_INTERVAL_DAYS:
                    return ValidationResult(
                        success=False,
                        message=(
                            "Retraction Interval must be between"
                            f" 1 and {MAX_INTERVAL_DAYS}."
                        ),
                    )
            except (TypeError, ValueError):
                return ValidationResult(
                    success=False,
                    message=(
                        "Retraction Interval must be a valid"
                        " integer."
                    ),
                )

        initial_range = configuration.get("initial_range")
        if initial_range is None:
            return ValidationResult(
                success=False,
                message=(
                    "Initial Range (in days) is a required"
                    " configuration parameter."
                ),
            )
        try:
            ir = int(initial_range)
            if ir < 1 or ir > MAX_INTERVAL_DAYS:
                return ValidationResult(
                    success=False,
                    message=(
                        "Initial Range must be between"
                        f" 1 and {MAX_INTERVAL_DAYS}."
                    ),
                )
        except (TypeError, ValueError):
            return ValidationResult(
                success=False,
                message=(
                    "Initial Range must be a valid integer."
                ),
            )

        # Connectivity check (must be last)
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            start = now - timedelta(minutes=1)
            start_str = start.strftime(DATE_FORMAT_VMRAY)
            end_str = now.strftime(DATE_FORMAT_VMRAY)
            endpoint = SUBMISSION_FINISH_TIME_ENDPOINT.format(
                start=start_str, end=end_str
            )
            url = self.vmray_helper.build_url(endpoint, base_url)
            headers = self.vmray_helper._get_headers(api_token)
            self.vmray_helper.api_helper(
                logger_msg=(
                    f"validating connectivity with"
                    f" {PLATFORM_NAME}"
                ),
                url=url,
                method="GET",
                params={"_limit": 1},
                headers=headers,
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated"
                f" connectivity with {PLATFORM_NAME}."
            )
        except VMRayPluginException as exp:
            err_msg = (
                f"Unable to connect to {PLATFORM_NAME}."
                f" Error: {exp}"
            )
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
                    "Verify the Base URL and API Token provided"
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
