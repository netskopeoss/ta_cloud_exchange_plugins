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

TAXIIPlugin implementation to push and pull the data."""

import pytz
from cabby import create_client, exceptions
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional
from stix.core import STIXPackage
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.domain_name_object import DomainName
from urllib.parse import urlparse
import re
import time
import requests
import tempfile
import traceback
from .lib.taxii2client.v20 import ApiRoot as ApiRoot20, as_pages as as_pages20
from .lib.taxii2client.v21 import ApiRoot as ApiRoot21, as_pages as as_pages21

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.indicator import SeverityType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from .utils.helper import (
    str_to_datetime,
    get_configuration_parameters,
    STIXTAXIIException,
    add_ce_user_agent,
    ensure_utc_aware,
)
from .utils.constants import (
    CONFIDENCE_TO_REPUTATION_MAPPINGS,
    LIKELY_IMPACT_TO_SEVERITY,
    OBSERVABLE_REGEXES,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    STIX_VERSION_1,
    STIX_VERSION_20,
    STIX_VERSION_21,
    SERVICE_TYPE,
    DATE_CONVERSION_STRING,
    DISCOVERY_URL_V1,
    DISCOVERY_URL_V2,
    USERNAME_CONFIG,
    PASSWORD_CONFIG,
    COLLECTION_NAMES_CONFIG,
    PAGINATION_METHOD_CONFIG_V2,
    INITIAL_RANGE_CONFIG,
    LOOK_BACK_CONFIG,
    TYPE_V1,
    TYPE_V2,
    SEVERITY_V1,
    SEVERITY_V2,
    REPUTATION_CONFIG,
    BATCH_SIZE_CONFIG_V20,
    BATCH_SIZE_CONFIG_V21,
    RETRACTION_INTERVAL_CONFIG,
    RETRACTION,
    IN_EXECUTION_MAX_RETRIES,
    IN_EXECUTION_SLEEP_TIME,
    VALIDITY_DISPLAY_FORMAT,
    PROXY_ERROR_RESOLUTION,
    CONNECTION_ERROR_RESOLUTION,
)


class STIXTAXIIPlugin(PluginBase):
    """The TAXIIPlugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self):
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = STIXTAXIIPlugin.metadata
            plugin_name = metadata.get("name", PLATFORM_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_dynamic_fields(self):
        """Get the dynamic fields based on STIX/TAXII version.

        Returns:
            list: List of dynamic configuration fields.
        """
        version = self.configuration.get("version", None)

        # Version-specific fields
        if version == STIX_VERSION_1:
            discovery_url = DISCOVERY_URL_V1
            type_config = TYPE_V1
            severity_config = SEVERITY_V1
        else:
            discovery_url = DISCOVERY_URL_V2
            type_config = TYPE_V2
            severity_config = SEVERITY_V2

        # Build configuration fields list
        fields = [
            discovery_url,
            USERNAME_CONFIG,
            PASSWORD_CONFIG,
            COLLECTION_NAMES_CONFIG,
            INITIAL_RANGE_CONFIG,
            LOOK_BACK_CONFIG,
            type_config,
            severity_config,
            REPUTATION_CONFIG,
        ]

        # Batch Size and Pagination Method - only applicable for version 2.x
        if version in [STIX_VERSION_20, STIX_VERSION_21]:
            fields.append(PAGINATION_METHOD_CONFIG_V2)
        
        if version == STIX_VERSION_20:
            fields.append(BATCH_SIZE_CONFIG_V20)
        if version == STIX_VERSION_21:
            fields.append(BATCH_SIZE_CONFIG_V21)
        
        fields.append(RETRACTION_INTERVAL_CONFIG)

        return fields

    def _filter_collections(self, all_collections, selected_collections):
        """Create or filter collection names.
        Args:
            all_collections (list): List of all available collections.
            selected_collections (str): Comma-separated string of selected
            collections.
        Returns:
            list: List of filtered collection names.
        """
        selected_collections = [
            x.strip() for x in selected_collections.split(",") if x.strip()
        ]
        if not selected_collections:
            return all_collections
        else:
            missing_collections = set(selected_collections) - set(
                all_collections
            )
            if missing_collections:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Following collections could not be "
                        f"found - {', '.join(missing_collections)}."
                    ),
                    resolution=(
                        "Ensure the collection names are correct and "
                        "available on the server."
                    )
                )
            return list(
                set(selected_collections).intersection(set(all_collections))
            )

    def _extract_fields_from_indicator(self, indicator, observable):
        """Extract severity and reputation from indicator for future usage.
        Args:
            indicator (Indicator): Indicator object.
            observable (Observable): Observable object.
        Returns:
            dict: Dictionary containing severity and reputation.
        """

        # Choose the output dict
        if observable.idref is None:
            data = {}
            data["firstSeen"] = indicator.timestamp
            data["lastSeen"] = indicator.timestamp
            if indicator.confidence:
                data["reputation"] = CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                    str(indicator.confidence.value), 5
                )
            if indicator.likely_impact:
                data["severity"] = LIKELY_IMPACT_TO_SEVERITY.get(
                    str(indicator.likely_impact.value),
                    SeverityType.UNKNOWN,
                )
            return data
        self._ids[observable.idref] = {}
        self._ids[observable.idref]["firstSeen"] = indicator.timestamp
        self._ids[observable.idref]["lastSeen"] = indicator.timestamp
        if indicator.confidence:
            self._ids[observable.idref]["reputation"] = (
                CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                    str(indicator.confidence.value), 5
                )
            )
        if indicator.likely_impact:
            self._ids[observable.idref]["severity"] = (
                LIKELY_IMPACT_TO_SEVERITY.get(
                    str(indicator.likely_impact.value),
                    SeverityType.UNKNOWN,
                )
            )
        return self._ids[observable.idref]

    def _is_indicator_expired_1x(self, indicator):
        """Check if a STIX 1.x indicator is expired based on valid_time_positions.

        Args:
            indicator: STIX 1.x indicator object.

        Returns:
            tuple: (is_expired: bool, validity_times_str: str)
                - is_expired: True if the indicator is expired, False otherwise.
                - validity_times_str: Formatted string of validity time windows.
        """
        # Check if valid_time_positions exists and is not empty
        if not getattr(indicator, "valid_time_positions", None):
            # No validity window means it's valid indefinitely
            return False, ""

        current_time = pytz.utc.localize(datetime.now())

        # Phase 1: Gather all validity windows
        # and determine expiration status
        validity_pairs = []  # List of (start_dt, end_dt, is_open_ended)
        all_windows_expired = True

        for window in indicator.valid_time_positions:
            if not window:
                continue

            # Extract start_time
            start_time_obj = getattr(window, "start_time", None)
            start_dt = None
            if start_time_obj and getattr(start_time_obj, "value", None):
                start_dt = start_time_obj.value
                if isinstance(start_dt, datetime) and start_dt.tzinfo is None:
                    start_dt = pytz.utc.localize(start_dt)

            # Extract end_time
            end_time_obj = getattr(window, "end_time", None)
            end_dt = None
            is_open_ended = False

            if not end_time_obj or not getattr(end_time_obj, "value", None):
                # Missing end_time implies validity "forever"
                is_open_ended = True
                all_windows_expired = False
            else:
                end_dt = end_time_obj.value
                if isinstance(end_dt, datetime):
                    if end_dt.tzinfo is None:
                        end_dt = pytz.utc.localize(end_dt)
                    # Check if this window is still valid
                    if end_dt > current_time:
                        all_windows_expired = False
                else:
                    # Non-datetime end_dt - treat as valid (don't expire)
                    all_windows_expired = False

            validity_pairs.append((start_dt, end_dt, is_open_ended))

        # Phase 2: Build the formatted validity times string
        validity_windows = []
        for start_dt, end_dt, is_open_ended in validity_pairs:
            # Format start_dt
            if isinstance(start_dt, datetime):
                start_str = start_dt.strftime(VALIDITY_DISPLAY_FORMAT)
            else:
                start_str = "N/A"

            # Format end_dt
            if is_open_ended:
                end_str = "N/A"
            elif isinstance(end_dt, datetime):
                end_str = end_dt.strftime(VALIDITY_DISPLAY_FORMAT)
            else:
                end_str = str(end_dt) if end_dt else "N/A"

            validity_windows.append(f"Valid From: {start_str}, Valid Until: {end_str}")

        validity_times_str = ", ".join(validity_windows) if validity_windows else ""

        return all_windows_expired, validity_times_str

    def _extract_from_indicator_1x(
        self, package_indicators, is_retraction: bool = False
    ):
        """Extract ioc from indicators.
        Args:
            package_indicators (list): List of indicators.
            is_retraction (bool): If True, return set of values instead of
                Indicator objects.
        Returns:
            tuple: (indicators, skipped_count)
                - indicators: List of Indicator objects or set of values.
                - skipped_count: Count of skipped indicators/observables.
        """
        indicators = set() if is_retraction else []
        skipped_indicators = {}
        for indicator in package_indicators:
            # Skip expired indicators (valid_time_positions check)
            try: 
                expired, validity_times_str = self._is_indicator_expired_1x(indicator)
            except Exception:
                expired = False
                validity_times_str = ""
            if expired:
                skipped_indicators["Expired"] = (
                    skipped_indicators.get("Expired", 0) + 1
                )
                continue
            for observable in indicator.observables:
                try:
                    data = self._extract_fields_from_indicator(
                        indicator, observable
                    )
                    if not observable.object_:
                        skipped_indicators["Missing object"] = (
                            skipped_indicators.get("Missing object", 0) + 1
                        )
                        continue
                    properties = observable.object_.properties
                    if not properties:
                        skipped_indicators["Missing properties"] = (
                            skipped_indicators.get("Missing properties", 0) + 1
                        )
                        continue
                    # Build base comments from description
                    base_comment = str(
                        observable.description
                        or indicator.description
                        or ""
                    )
                    # Append validity times if available
                    if validity_times_str:
                        if base_comment:
                            full_comment = f"{base_comment}, {validity_times_str}"
                        else:
                            full_comment = validity_times_str
                    else:
                        full_comment = base_comment

                    if (
                        type(properties) is File
                        and properties.hashes
                        and properties.hashes.md5
                    ):
                        if is_retraction:
                            indicators.add(str(properties.hashes.md5))
                        else:
                            indicators.append(
                                Indicator(
                                    value=str(properties.hashes.md5),
                                    type=IndicatorType.MD5,
                                    **data,
                                    comments=full_comment,
                                )
                            )
                    elif (
                        type(properties) is File
                        and properties.hashes
                        and properties.hashes.sha256
                    ):
                        if is_retraction:
                            indicators.add(str(properties.hashes.sha256))
                        else:
                            indicators.append(
                                Indicator(
                                    value=str(properties.hashes.sha256),
                                    type=IndicatorType.SHA256,
                                    **data,
                                    comments=full_comment,
                                )
                            )
                    elif type(properties) is URI and properties.value:
                        if is_retraction:
                            indicators.add(str(properties.value))
                        else:
                            indicators.append(
                                Indicator(
                                    value=str(properties.value),
                                    type=IndicatorType.URL,
                                    **data,
                                    comments=full_comment,
                                )
                            )
                    elif type(properties) is DomainName and properties.value:
                        if is_retraction:
                            indicators.add(str(properties.value))
                        else:
                            indicators.append(
                                Indicator(
                                    value=str(properties.value),
                                    type=getattr(
                                        IndicatorType, "DOMAIN", IndicatorType.URL
                                    ),
                                    **data,
                                    comments=full_comment,
                                )
                            )
                    else:
                        prop_type = type(properties).__name__
                        reason = f"Unsupported properties type '{prop_type}'"
                        skipped_indicators[reason] = (
                            skipped_indicators.get(reason, 0) + 1
                        )
                except Exception as e:
                    skipped_indicators["Exception"] = (
                        skipped_indicators.get("Exception", 0) + 1
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipping indicator. "
                            f"Exception: {e}"
                        ),
                        details=str(traceback.format_exc()),
                    )
        skipped_count = sum(skipped_indicators.values())
        if skipped_indicators:
            skip_reasons_stats = ", ".join(
                f"{reason}: {count}" for reason, count in skipped_indicators.items()
            )
            self.logger.debug(
                message=(
                    f"{self.log_prefix}:"
                    "Some indicators were skipped due to expiration, "
                    "missing fields or exceptions. Skip Stats: "
                    f"{skip_reasons_stats}"
                )
            )
        return indicators, skipped_count

    def _extract_from_observables_1x(
        self, observables, is_retraction: bool = False
    ):
        """Extract iocs from observables.

        Args:
            observables (list): List of observables.
            is_retraction (bool): If True, return set of values instead of
                Indicator objects.
        Returns:
            tuple: (indicators, skipped_count)
                - indicators: List of Indicator objects or set of values.
                - skipped_count: Count of skipped observables.
        """
        indicators = set() if is_retraction else []
        skipped_observables = {}
        for observable in observables:
            try:
                if not observable.object_:
                    skipped_observables["Missing object"] = (
                        skipped_observables.get("Missing object", 0) + 1
                    )
                    continue
                properties = observable.object_.properties
                if not properties:
                    skipped_observables["Missing properties"] = (
                        skipped_observables.get("Missing properties", 0) + 1
                    )
                    continue
                if (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.md5
                ):
                    if is_retraction:
                        indicators.add(str(properties.hashes.md5))
                    else:
                        indicators.append(
                            Indicator(
                                value=str(properties.hashes.md5),
                                type=IndicatorType.MD5,
                                **self._ids.get(observable.id_, {}),
                                comments=str(observable.description or ""),
                            )
                        )
                elif (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.sha256
                ):
                    if is_retraction:
                        indicators.add(str(properties.hashes.sha256))
                    else:
                        indicators.append(
                            Indicator(
                                value=str(properties.hashes.sha256),
                                type=IndicatorType.SHA256,
                                **self._ids.get(observable.id_, {}),
                                comments=str(observable.description or ""),
                            )
                        )
                elif type(properties) is URI and properties.value:
                    if is_retraction:
                        indicators.add(str(properties.value))
                    else:
                        indicators.append(
                            Indicator(
                                value=str(properties.value),
                                type=IndicatorType.URL,
                                comments=str(observable.description or ""),
                            )
                        )
                elif type(properties) is DomainName and properties.value:
                    if is_retraction:
                        indicators.add(str(properties.value))
                    else:
                        indicators.append(
                            Indicator(
                                value=str(properties.value),
                                type=getattr(
                                    IndicatorType, "DOMAIN", IndicatorType.URL
                                ),
                                comments=str(observable.description or ""),
                            )
                        )
                else:
                    prop_type = type(properties).__name__
                    reason = f"Unsupported properties type '{prop_type}'"
                    skipped_observables[reason] = (
                        skipped_observables.get(reason, 0) + 1
                    )
            except Exception as e:
                skipped_observables["Exception"] = (
                    skipped_observables.get("Exception", 0) + 1
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping observable. "
                        f"Exception: {e}"
                    ),
                    details=str(traceback.format_exc()),
                )
        skipped_count = sum(skipped_observables.values())
        if skipped_observables:
            skip_reasons_stats = ", ".join(
                f"{reason}: {count}" for reason, count in skipped_observables.items()
            )
            self.logger.debug(
                message=(
                    f"{self.log_prefix}:"
                    "Some observables were skipped due to "
                    "missing fields or exceptions. Skip Stats: "
                    f"{skip_reasons_stats}"
                )
            )
        return indicators, skipped_count

    def _extract_indicators_1x(self, package, is_retraction: bool = False):
        """Extract iocs from a STIX package.

        Args:
            package: STIX package object.
            is_retraction (bool): If True, return set of values instead of
                Indicator objects.

        Returns:
            tuple: (indicators, skipped_count)
                - indicators: List of Indicator objects or set of values.
                - skipped_count: Count of skipped indicators/observables.
        """
        if package.indicators:
            return self._extract_from_indicator_1x(
                package.indicators, is_retraction
            )
        elif package.observables:
            return self._extract_from_observables_1x(
                package.observables, is_retraction
            )
        else:
            return set() if is_retraction else [], 0

    def _build_client(self, configuration):
        """Build client for TAXII.

        Args:
            configuration (dict): Configuration dictionary.
        Returns:
            client: Client object.
        """
        (
            discovery_url,
            username,
            password,
        ) = get_configuration_parameters(
            configuration, keys=["discovery_url", "username", "password"]
        )
        parsed_url = urlparse(discovery_url)
        discovery_url = parsed_url.path
        if len(parsed_url.netloc.split(":")) > 1:
            base, port = parsed_url.netloc.split(":")
            port = int(port)
            client = create_client(
                base,
                port=port,
                use_https=True if parsed_url.scheme == "https" else False,
                discovery_path=discovery_url,
            )
        else:
            client = create_client(
                parsed_url.netloc,
                use_https=True if parsed_url.scheme == "https" else False,
                discovery_path=discovery_url,
            )
        client.set_proxies(self.proxy)

        if username and password:
            client.set_auth(
                username=username,
                password=password,
                verify_ssl=self.ssl_validation,
            )
        else:
            client.set_auth(verify_ssl=self.ssl_validation)
        return client

    def _get_collections(self, client):
        """Get collections from the server.

        Args:
            client (cabby.Client): The client object.

        Returns:
            list: List of collection names.
        """
        collection_uri = None
        services = client.discover_services()
        for service in services:
            if service.type == SERVICE_TYPE:
                collection_uri = service.address
                break
        if collection_uri is None:
            err_msg = "Failed to find collection management."
            raise STIXTAXIIException(err_msg)
        # to get collection form server
        return [c.name for c in client.get_collections(uri=collection_uri)]

    def convert_string_to_datetime(self, collections_dict):
        """Convert string to datetime.

        Args:
            collections_dict (dict): Dictionary of collection names and
              datetime values.

        Returns:
            dict: Dictionary of collection names and datetime values.
        """
        try:
            if collections_dict and isinstance(collections_dict, dict):
                for collection_name, str_datetime_value in (
                    collections_dict.items()
                ):
                    if isinstance(str_datetime_value, str):
                        collections_dict[collection_name] = str_to_datetime(
                            string=str_datetime_value,
                            date_format=DATE_CONVERSION_STRING,
                            replace_dot=False,
                        )
        except Exception as err:
            err_msg = "Error occurred while fetching the collection details."
            details = f"Collection details: {collections_dict}"
            self.handle_and_raise(
                err=err, err_msg=err_msg, details_msg=details
            )

        return collections_dict

    def convert_datetime_to_string(self, collections_dict):
        """Convert datetime to string.

        Args:
            collections_dict (dict): Dictionary of collection names and
            datetime values.

        Returns:
            dict: Dictionary of collection names and datetime values.
        """
        try:
            if collections_dict and isinstance(collections_dict, dict):
                for collection_name, datetime_value in (
                    collections_dict.items()
                ):
                    if isinstance(datetime_value, datetime):
                        collections_dict[collection_name] = (
                            datetime_value.strftime(DATE_CONVERSION_STRING)
                        )
        except Exception as err:
            err_msg = (
                "Error occurred while creating the collection"
                " details to store."
            )
            details = f"Collection details: {collections_dict}"
            self.handle_and_raise(
                err=err, err_msg=err_msg, details_msg=details
            )

        return collections_dict

    def handle_and_raise(
        self,
        err: Exception,
        err_msg: str,
        details_msg: str = "",
        if_raise: bool = True,
        resolution: str = "",
    ):
        """Handle and raise an exception.

        Args:
            err (Exception): Exception object.
            err_msg (str): Error message.
            details_msg (str): Details message.
            exc_type (Exception, optional): Exception type. Defaults to
                STIXTAXIIException.
            if_raise (bool, optional): Whether to raise the exception.
                Defaults to True.
            resolution (str, optional): Resolution message for the error.
                Defaults to empty string.
        """
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {err}",
            details=details_msg,
            resolution=resolution if resolution else None,
        )
        if if_raise:
            raise STIXTAXIIException(err_msg)

    def _format_type_breakdown(self, type_counts, type_to_pull):
        """Format type counts into a readable breakdown string.

        Args:
            type_counts (dict): Dictionary mapping type values to counts.
            type_to_pull (list): List of indicator types to pull.
                Empty list means include all types.

        Returns:
            str: Formatted breakdown string like "X SHA256, Y MD5, Z Domain(s)"
        """
        type_labels = {
            "sha256": "SHA256",
            "md5": "MD5",
            "url": "URL",
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "Domain"
        }
        
        # Determine which types to include in breakdown
        types_to_show = type_to_pull if type_to_pull else list(type_labels.keys())
        
        type_breakdown_parts = []
        for t in types_to_show:
            count = type_counts.get(t, 0)
            if count > 0:
                label = type_labels.get(t, t.title())
                type_breakdown_parts.append(f"{count} {label}")
        
        if not type_breakdown_parts:
            return "0"
        
        if len(type_breakdown_parts) == 1:
            return type_breakdown_parts[0]
        
        return ", ".join(type_breakdown_parts[:-1]) + f" and {type_breakdown_parts[-1]}"

    def _filter_indicators_by_config(
        self, indicators, type_to_pull, severity, reputation, type_counts
    ):
        """Filter indicators based on configuration parameters.

        Args:
            indicators (list): List of Indicator objects.
            type_to_pull (list): List of indicator types to pull.
                Empty list means include all types.
            severity (list): List of severity values to include.
                Empty list means include all severities.
            reputation (int): Minimum reputation value.
            type_counts (dict): Dictionary to accumulate type counts into.
                Updated in place.

        Returns:
            tuple: (filtered_indicators, skipped_count)
                - filtered_indicators: List of indicators that passed filters.
                - skipped_count: Number of indicators filtered out.
        """

        def matches_type(indicator_type):
            """Check if indicator type matches the configured types."""
            # Empty list means include all types
            if not type_to_pull:
                return True
            return (
                (indicator_type is IndicatorType.SHA256 and "sha256" in type_to_pull)
                or (indicator_type is IndicatorType.MD5 and "md5" in type_to_pull)
                or (indicator_type is IndicatorType.URL and "url" in type_to_pull)
                or (
                    indicator_type is getattr(IndicatorType, "IPV4", IndicatorType.URL)
                    and "ipv4" in type_to_pull
                )
                or (
                    indicator_type is getattr(IndicatorType, "IPV6", IndicatorType.URL)
                    and "ipv6" in type_to_pull
                )
                or (
                    indicator_type is getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
                    and "domain" in type_to_pull
                )
            )

        def matches_severity(indicator_severity):
            """Check if indicator severity matches the configured severities."""
            # Empty list means include all severities
            if not severity:
                return True
            return indicator_severity.value in severity

        filtered_list = []
        for ind in indicators:
            if (
                matches_severity(ind.severity)
                and ind.reputation >= int(reputation)
                and matches_type(ind.type)
            ):
                filtered_list.append(ind)
                # Count by type (lowercase to match config keys)
                type_key = ind.type.value.lower()
                if type_key in type_counts:
                    type_counts[type_key] += 1

        skipped_count = len(indicators) - len(filtered_list)
        return filtered_list, skipped_count

    def pull_1x(self, configuration, start_time, is_retraction: bool = False):
        """Pull implementation for version 1.x.

        Args:
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.
            is_retraction (bool): If True, yield sets of values instead of
                Indicator objects. Also filters out expired indicators.

        Yields:
            tuple: (indicators_batch, sub_checkpoint_dict) for each block.
                indicators_batch is list of Indicators or set of values.
        """
        (
            collection_names,
            delay_config,
            type_to_pull,
            severity,
            reputation,
        ) = get_configuration_parameters(
            configuration,
            keys=["collection_names", "delay", "type_to_pull", "severity", "reputation"]
        )
        if delay_config and isinstance(delay_config, int):
            delay_config = int(delay_config)
        else:
            delay_config = 0

        self._ids = {}
        try:
            client = self._build_client(configuration)
            collections = self._get_collections(client)
        except requests.exceptions.ProxyError as err:
            err_msg = "Invalid proxy configuration."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                resolution=PROXY_ERROR_RESOLUTION,
            )
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Discovery"
                " URL/API Root URL provided."
            )
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                resolution=CONNECTION_ERROR_RESOLUTION,
            )
        except requests.exceptions.RequestException as err:
            err_msg = "Request Exception occurred."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except STIXTAXIIException:
            raise
        except Exception as err:
            err_msg = "Exception occurred while fetching the collections."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

        filtered_collections = self._filter_collections(
            collections, collection_names
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will be"
            f" fetched - {', '.join(filtered_collections)}."
        )

        delay_time = int(delay_config)
        start_time = ensure_utc_aware(
            start_time - timedelta(minutes=delay_time)
        )

        total_indicators = 0
        total_skipped = 0
        total_type_counts = {
            "sha256": 0, "md5": 0, "url": 0,
            "ipv4": 0, "ipv6": 0, "domain": 0
        }

        for collection_idx, collection in enumerate(filtered_collections):
            self.logger.debug(
                f"{self.log_prefix}: Parsing collection - "
                f"'{collection}'. Start time: {start_time}."
            )
            try:
                content_blocks = client.poll(
                    collection_name=collection,
                    begin_date=start_time,
                )
            except requests.exceptions.ProxyError as err:
                err_msg = (
                    "Proxy Error occurred. Check the proxy configuration."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                    resolution=PROXY_ERROR_RESOLUTION,
                )
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the Discovery"
                    " URL/API Root URL provided."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                    resolution=CONNECTION_ERROR_RESOLUTION,
                )
            except requests.exceptions.RequestException as err:
                err_msg = "Request Exception occurred."
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except Exception as err:
                err_msg = (
                    "Exception occurred while fetching the"
                    " objects from collection."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )

            block_id = 1
            collection_indicator_count = 0
            collection_skip_count = 0
            for block in content_blocks:
                try:
                    temp = tempfile.TemporaryFile()
                    temp.write(block.content)
                    temp.seek(0)
                    stix_package = STIXPackage.from_xml(temp)
                    extracted, skipped_count = self._extract_indicators_1x(
                        stix_package, is_retraction
                    )

                    if is_retraction:
                        # For retraction: yield set of values, no filtering
                        collection_indicator_count += len(extracted)
                        total_indicators += len(extracted)
                        collection_skip_count += skipped_count
                        total_skipped += skipped_count

                        self.logger.info(
                            f"{self.log_prefix}: Extracted {len(extracted)} "
                            f"valid indicator(s) from Block-{block_id} "
                            f"for retraction check. Skipped {skipped_count} "
                            "indicator(s)."
                        )
                        temp.close()

                        if extracted:
                            yield extracted, None
                    else:
                        # Apply filtering for normal pull
                        filtered_batch, filter_skipped = (
                            self._filter_indicators_by_config(
                                extracted, type_to_pull, severity, reputation,
                                total_type_counts
                            )
                        )

                        collection_indicator_count += len(filtered_batch)
                        total_indicators += len(filtered_batch)
                        collection_skip_count += skipped_count + filter_skipped
                        total_skipped += skipped_count + filter_skipped

                        total_log = (
                            f"Total {collection_indicator_count} "
                            "indicator(s) pulled till now."
                        )
                        self.logger.info(
                            f"{self.log_prefix}: Pulled {len(filtered_batch)} "
                            f"indicator(s) from Block-{block_id}. Skipped "
                            f"{skipped_count} indicator(s), filtered "
                            f"{filter_skipped} indicator(s)."
                            f" {total_log}"
                        )
                        temp.close()

                        # Build sub_checkpoint
                        sub_checkpoint = {
                            "collection": collection,
                            "collection_idx": collection_idx,
                            "block_id": block_id,
                        }

                        if filtered_batch:
                            yield filtered_batch, sub_checkpoint

                except Exception as e:
                    err_msg = (
                        "Error occurred while extracting indicator(s)"
                        f" from Block-{block_id}."
                    )
                    self.handle_and_raise(
                        err=e,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                        if_raise=False,
                    )
                block_id += 1

            self.logger.info(
                f"{self.log_prefix}: Completed pulling of "
                f"indicator(s) from collection - '{collection}'."
                f" Total {collection_indicator_count}"
                " indicator(s) pulled."
                f" {collection_skip_count} indicator(s) skipped/filtered."
            )

        type_breakdown_str = self._format_type_breakdown(total_type_counts, type_to_pull)
        
        self.logger.info(
            f"{self.log_prefix}: Completed pulling of"
            " indicator(s) from collection(s) - "
            f"{', '.join(filtered_collections)}. "
            f"Total {total_indicators} indicator(s) pulled, "
            f"{total_skipped} skipped/filtered. "
            f"Pull Stats: {type_breakdown_str} indicator(s) were fetched."
        )

    def _extract_observables_2x(
        self,
        pattern: str,
        data: dict,
        is_retraction: bool = False,
    ):
        """Extract observables from a pattern.

        Args:
            pattern (str): The pattern to extract observables from.
            data (dict): The data to extract observables from.
            is_retraction (bool): If True, return set of values instead of
                Indicator objects.

        Returns:
            tuple: (observables, skipped_count, sha256_count, md5_count,
                skip_reason)
                - observables: List of observables (or set of values if
                  is_retraction).
                - skipped_count: Count of skipped indicators for this pattern.
                - skip_reason: Reason for skipping (None if not skipped).
        """
        sha256_count = 0
        md5_count = 0
        observables = set() if is_retraction else []
        match_count = 0
        exception_count = 0
        for kind in OBSERVABLE_REGEXES:
            matches = re.findall(kind["regex"], pattern, re.IGNORECASE)
            match_count += len(matches)
            for match in matches:
                try:
                    if (
                        kind["type"] == IndicatorType.SHA256
                        or kind["type"] == IndicatorType.MD5
                    ):
                        value = match.replace("'", "")
                        if is_retraction:
                            observables.add(value)
                        else:
                            observables.append(
                                Indicator(
                                    value=value,
                                    type=kind["type"],
                                    **data,
                                )
                            )
                        if kind["type"] == IndicatorType.SHA256:
                            sha256_count += 1
                        elif kind["type"] == IndicatorType.MD5:
                            md5_count += 1
                    else:
                        if "ipv4" in pattern or "ipv6" in pattern:
                            value = match.replace("'", "")
                        else:
                            value = match[1].replace("'", "")
                        if is_retraction:
                            observables.add(value)
                        else:
                            observables.append(
                                Indicator(
                                    value=value,
                                    type=kind["type"],
                                    **data,
                                )
                            )
                except Exception as e:
                    exception_count += 1
                    self.logger.debug(
                        message=(
                            f"{self.log_prefix}: Skipping observable in "
                            f"indicator. Exception: {e}"
                        ),
                        details=str(traceback.format_exc()),
                    )
        skipped_count = 0
        skip_reason = None
        if len(observables) == 0:
            skipped_count = 1
            if exception_count > 0:
                skip_reason = "Exception"
            elif match_count == 0:
                skip_reason = "No supported observables found"
            else:
                skip_reason = "Unsupported pattern"
        return observables, skipped_count, sha256_count, md5_count, skip_reason

    def _extract_indicators_2x(self, objects, is_retraction: bool = False):
        """Extract indicators from a list of objects.

        Args:
            objects (list): List of objects.
            is_retraction (bool): If True, return set of values instead of
                Indicator objects.

        Returns:
            tuple: (indicators, skipped_count, sha256_count, md5_count)
                indicators is a list of Indicator objects or set of values
                if is_retraction is True.
        """
        indicators = set() if is_retraction else []
        skipped_indicators = {}
        modified_time = None
        total_sha256_count = 0
        total_md5_count = 0
        current_time = datetime.now()

        for o in objects:
            indicator_type = o.get("type", "")
            try:
                if indicator_type.lower() != "indicator":
                    reason = f"Unsupported type '{indicator_type}'"
                    skipped_indicators[reason] = (
                        skipped_indicators.get(reason, 0) + 1
                    )
                    continue

                # Skip revoked indicators
                if o.get("revoked", False):
                    skipped_indicators["Revoked"] = (
                        skipped_indicators.get("Revoked", 0) + 1
                    )
                    continue

                # Skip expired indicators (valid_until < now)
                # format 2025-12-25T09:35:07.502007Z
                valid_until_str = o.get("valid_until")
                if valid_until_str:
                    valid_until = str_to_datetime(
                        valid_until_str,
                        date_format=DATE_CONVERSION_STRING,
                        replace_dot=False,
                        return_now_on_error=False,
                    )
                    if valid_until and valid_until < current_time:
                        skipped_indicators["Expired"] = (
                            skipped_indicators.get("Expired", 0) + 1
                        )
                        continue

                created_time = str_to_datetime(o.get("created"))
                modified_time = str_to_datetime(o.get("modified"))

                # Build base comments and append validity times
                base_comment = o.get("description") or o.get("pattern") or ""
                valid_from_str = o.get("valid_from")

                # Build validity times string
                validity_parts = []
                if valid_from_str:
                    validity_parts.append(f"Valid From: {valid_from_str}")
                if valid_until_str:
                    validity_parts.append(f"Valid Until: {valid_until_str}")

                if validity_parts:
                    validity_times_str = ", ".join(validity_parts)
                    if base_comment:
                        full_comment = f"{base_comment}, {validity_times_str}"
                    else:
                        full_comment = validity_times_str
                else:
                    full_comment = base_comment

                data = {
                    "comments": full_comment,
                    "reputation": int(o.get("confidence", 50) / 10),
                    "firstSeen": created_time,
                    "lastSeen": modified_time,
                }
                sha256 = 0
                md5 = 0
                extracted, observables_skipped, sha256, md5, skip_reason = (
                    self._extract_observables_2x(
                        o.get("pattern", ""),
                        data,
                        is_retraction,
                    )
                )
                total_sha256_count += sha256
                total_md5_count += md5
                if observables_skipped and skip_reason:
                    skipped_indicators[skip_reason] = (
                        skipped_indicators.get(skip_reason, 0) + 1
                    )

                if is_retraction:
                    indicators.update(extracted)
                else:
                    indicators += extracted
            except Exception as e:
                skipped_indicators["Exception"] = (
                    skipped_indicators.get("Exception", 0) + 1
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping indicator. "
                        f"Exception: {e}"
                    ),
                    details=str(traceback.format_exc()),
                )

        skipped_count = sum(skipped_indicators.values())
        if skipped_indicators:
            skip_reasons_stats = ", ".join(
                f"{reason}: {count}" for reason, count in skipped_indicators.items()
            )
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: "
                    "Some indicators were skipped due to expiration, "
                    "missing fields or exceptions. Skip Stats: "
                    f"{skip_reasons_stats}"
                )
            )
        return (
            indicators,
            skipped_count,
            total_sha256_count,
            total_md5_count
        )

    def update_storage(
        self,
        bundle,
        last_added_date,
        storage,
        collection,
        execution_details,
        bundle_id,
        start_offset,
        batch_size,
        version,
        pagination_method,
    ):
        """Update storage with new pagination details."""
        next_value_21 = bundle.get("next")
        objects = bundle.get("objects", [])

        if objects:
            if pagination_method == "next":
                if (
                    version == STIX_VERSION_21
                    and next_value_21
                ):
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": last_added_date,
                        }
                    }
                elif (
                    version == STIX_VERSION_20
                    and len(objects) >= batch_size
                ):
                    try:
                        next_value_20 = int(start_offset) + (
                            batch_size * bundle_id
                        )
                    except Exception:
                        next_value_20 = 0
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": last_added_date,
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = ensure_utc_aware(
                        datetime.now()
                    )
            else:
                resume_added_date = last_added_date
                if not resume_added_date:
                    fallback_date = execution_details.get(collection)
                    if isinstance(fallback_date, datetime):
                        resume_added_date = fallback_date.strftime(
                            DATE_CONVERSION_STRING
                        )
                    elif isinstance(fallback_date, str):
                        resume_added_date = fallback_date

                if (
                    version == STIX_VERSION_21
                    and bundle.get("more")
                    and resume_added_date
                ):
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": resume_added_date,
                        }
                    }
                elif (
                    version == STIX_VERSION_20
                    and len(objects) >= batch_size
                    and resume_added_date
                ):
                    try:
                        next_value_20 = int(start_offset) + (
                            batch_size * bundle_id
                        )
                    except Exception:
                        next_value_20 = 0
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": resume_added_date,
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = ensure_utc_aware(
                        datetime.now()
                    )
        else:
            storage["in_execution"] = {}
            execution_details[collection] = ensure_utc_aware(datetime.now())

    def paginate(
        self,
        configuration,
        pages,
        collection,
        storage=None,
        execution_details=None,
        start_offset: int = 0,
        is_retraction: bool = False,
    ):
        """Paginate through the collection and yield batches.

        Args:
            configuration (dict): Configuration dictionary.
            pages (generator): Generator of (bundle, last_added_date) tuples.
            collection (str): Collection name.
            storage (dict): Storage dictionary for resume details.
            execution_details (dict): Per-collection execution timestamps.
            start_offset (int): Starting offset for TAXII 2.0 pagination.
            is_retraction (bool): If True, yield sets of values instead of
                Indicator objects.

        Yields:
            tuple: (extracted_indicators, skipped_count, sub_checkpoint_dict)
                for each bundle. extracted_indicators is a list of Indicator
                objects or set of values if is_retraction is True.
        """
        (
            version,
            batch_size,
            pagination_method,
        ) = get_configuration_parameters(
            configuration, keys=["version", "batch_size", "pagination_method"]
        )

        bundle_id = 1
        collection_indicator_count = 0
        collection_skip_count = 0
        total_sha256_count = 0
        total_md5_count = 0

        for bundle, last_added_date in pages:
            objects = bundle.get("objects", [])
            extracted, skipped_count, sha256_count, md5_count = (
                self._extract_indicators_2x(objects, is_retraction)
            )
            total_sha256_count += sha256_count
            total_md5_count += md5_count

            extracted_count = len(extracted)
            collection_indicator_count += extracted_count
            collection_skip_count += skipped_count

            incremental_hash_msg = ""
            if sha256_count > 0 or md5_count > 0:
                incremental_hash_msg = (
                    f"(SHA256: {sha256_count}, MD5: {md5_count}) "
                )
            total_log = (
                f"Total {collection_indicator_count} indicators"
                f" pulled from '{collection}' collection till now."
            )
            if skipped_count > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Pulled {extracted_count} "
                    f"{incremental_hash_msg}"
                    f"indicator(s) from '{collection}' collection "
                    f"Bundle-{bundle_id}, {skipped_count} indicator(s) "
                    "have been discarded."
                    f" {total_log}"
                )
            else:
                self.logger.debug(
                    f"{self.log_prefix}: Pulled {extracted_count} "
                    f"{incremental_hash_msg}"
                    f"indicator(s) from '{collection}' collection "
                    f"Bundle-{bundle_id}. {total_log}"
                )

            # Build sub_checkpoint for resumption
            next_value = bundle.get("next")
            sub_checkpoint = {
                "collection": collection,
                "bundle_id": bundle_id,
                "last_added_date": last_added_date,
            }

            # For TAXII 2.1, use next token; for 2.0, calculate offset
            if version == STIX_VERSION_21:
                sub_checkpoint["next"] = next_value
                sub_checkpoint["has_more"] = bundle.get("more", False)
            else:
                # TAXII 2.0: calculate offset for next page
                # Offset = start_offset + (batch_size * bundles_processed)
                sub_checkpoint["next"] = start_offset + (batch_size * bundle_id)
                sub_checkpoint["has_more"] = len(objects) >= batch_size

            if (
                not is_retraction
                and storage is not None
                and execution_details is not None
            ):
                self.update_storage(
                    bundle=bundle,
                    last_added_date=last_added_date,
                    storage=storage,
                    collection=collection,
                    execution_details=execution_details,
                    bundle_id=bundle_id,
                    start_offset=start_offset,
                    batch_size=batch_size,
                    version=version,
                    pagination_method=pagination_method,
                )
                storage["collections"] = self.convert_datetime_to_string(
                    execution_details.copy()
                )
                sub_checkpoint["in_execution"] = storage.get(
                    "in_execution", {}
                )

            yield extracted, skipped_count, sub_checkpoint
            bundle_id += 1

        hash_msg = ""
        if total_sha256_count > 0 or total_md5_count > 0:
            hash_msg = (
                f"(SHA256: {total_sha256_count}, MD5: {total_md5_count}) "
            )
        self.logger.info(
            f"{self.log_prefix}: Completed pulling of"
            f" indicator(s) from collection - "
            f"'{collection}'."
            f" Total {collection_indicator_count} {hash_msg}"
            "indicator(s) pulled"
            f" and {collection_skip_count} skipped."
        )

    def get_page(self, func, configuration, start_time, next=None, start=0):
        """Get a page of indicators.

        Args:
            func (function): Function to get indicators.
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.
            next (str, optional): Next value. Defaults to None.
            start (int, optional): Start index. Defaults to 0.

        Returns:
            list: List of indicators.
        """
        (
            version,
            batch_size,
        ) = get_configuration_parameters(
            configuration, keys=["version", "batch_size"]
        )

        headers = add_ce_user_agent(
            plugin_name=self.plugin_name, plugin_version=self.plugin_version
        )
        if version == STIX_VERSION_21:
            pages = as_pages21(
                func,
                plugin=self,
                per_request=batch_size,
                added_after=start_time,
                next=next,
                with_header=True,
                headers=headers,
            )
        else:
            pages = as_pages20(
                func,
                plugin=self,
                per_request=batch_size,
                added_after=start_time,
                start=start,
                with_header=True,
                headers=headers,
            )

        return pages

    def pull_2x(self, configuration, start_time, is_retraction: bool = False):
        """Pull implementation for version 2.x.

        Args:
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.
            is_retraction (bool): If True, yield sets of values for retraction.

        Yields:
            tuple: (indicators_batch, sub_checkpoint_dict) for each bundle.
                indicators_batch is a list of Indicator objects or set of
                values if is_retraction is True.
        """
        (
            version,
            discovery_url,
            username,
            password,
            collection_names,
            pagination_method,
            delay,
            type_to_pull,
            severity,
            reputation,
        ) = get_configuration_parameters(
            configuration,
            keys=[
                "version",
                "discovery_url",
                "username",
                "password",
                "collection_names",
                "pagination_method",
                "delay",
                "type_to_pull",
                "severity",
                "reputation",
            ],
        )
        if delay and isinstance(delay, int):
            delay = int(delay)
        else:
            delay = 0

        collection_name_object = {}
        delay_time = int(delay)
        storage = {}
        collection_execution_details = {}
        new_collection_details = {}

        if not is_retraction and self.storage is not None:
            storage = self.storage
            if storage.get("collections", {}):
                collection_execution_details = self.convert_string_to_datetime(
                    storage.get("collections", {}).copy()
                )

        # Initialize API root based on version
        if version == STIX_VERSION_21:
            apiroot = ApiRoot21(
                discovery_url,
                user=username,
                password=password,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        else:
            apiroot = ApiRoot20(
                discovery_url,
                user=username,
                password=password,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )

        # Build collection mapping
        all_collections = []
        for c in apiroot.collections:
            all_collections.append(c.title)
            collection_name_object[c.title] = c

        filtered_collections = self._filter_collections(
            all_collections, collection_names
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will"
            f" be fetched - {', '.join(filtered_collections)}."
        )

        if not is_retraction:
            self.logger.debug(
                f"{self.log_prefix}: Collection execution details - {storage}."
            )

        total_indicators = 0
        total_skipped = 0
        total_type_counts = {
            "sha256": 0, "md5": 0, "url": 0,
            "ipv4": 0, "ipv6": 0, "domain": 0
        }

        def _process_pages(pages, collection, execution_details, start_offset):
            nonlocal total_indicators, total_skipped

            for extracted, skipped_count, bundle_checkpoint in self.paginate(
                configuration,
                pages,
                collection,
                storage=None if is_retraction else storage,
                execution_details=(
                    None if is_retraction else execution_details
                ),
                start_offset=start_offset,
                is_retraction=is_retraction,
            ):
                if is_retraction:
                    yield extracted, None
                    continue

                total_skipped += skipped_count
                if isinstance(extracted, list) and extracted:
                    filtered_batch, filter_skipped = (
                        self._filter_indicators_by_config(
                            extracted, type_to_pull, severity, reputation,
                            total_type_counts
                        )
                    )
                    total_indicators += len(filtered_batch)
                    total_skipped += filter_skipped

                    self.logger.info(
                        f"{self.log_prefix}: Pulled total "
                        f"{len(filtered_batch)} indicator(s) from "
                        f"'{collection}' collection's Bundle-"
                        f"{bundle_checkpoint.get('bundle_id')}, "
                        f"{filter_skipped} indicator(s) filtered, and "
                        f"{skipped_count} indicator(s) skipped."
                    )

                    if filtered_batch:
                        yield filtered_batch, bundle_checkpoint

        if not is_retraction and storage.get("in_execution", {}):
            for collection, next_page_details in storage.get(
                "in_execution", {}
            ).items():
                if collection not in filtered_collections:
                    break
                collection_object = collection_name_object[collection]

                next_start_time = collection_execution_details.get(
                    collection, start_time
                )
                next_val = None
                start_offset = 0

                if pagination_method == "next":
                    next_val = next_page_details.get("next")
                    if version == STIX_VERSION_20:
                        try:
                            start_offset = int(next_val) if next_val else 0
                        except Exception:
                            start_offset = 0
                else:
                    last_added_date = next_page_details.get("last_added_date")
                    if last_added_date:
                        next_start_time = str_to_datetime(
                            string=last_added_date,
                            date_format=DATE_CONVERSION_STRING,
                            replace_dot=False,
                        )
                    else:
                        next_start_time = collection_execution_details.get(
                            collection, start_time
                        )
                    next_val = None
                    start_offset = 0

                next_start_time = next_start_time - timedelta(
                    minutes=delay_time
                )
                next_start_time = ensure_utc_aware(next_start_time)

                resume_msg = ""
                if pagination_method == "next":
                    if version == STIX_VERSION_21 and next_val:
                        resume_msg = ", resuming with next token"
                    elif version == STIX_VERSION_20 and start_offset:
                        resume_msg = f", resuming from offset={start_offset}"

                for attempt in range(IN_EXECUTION_MAX_RETRIES):
                    self.logger.info(
                        f"{self.log_prefix}: Parsing collection - "
                        f"'{collection}'. Start time: {next_start_time} (UTC)"
                        f"{resume_msg}. Attempt {attempt + 1} of {IN_EXECUTION_MAX_RETRIES}."
                    )

                    try:
                        pages = self.get_page(
                            func=collection_object.get_objects,
                            configuration=configuration,
                            start_time=next_start_time,
                            next=next_val,
                            start=start_offset,
                        )

                        yield from _process_pages(
                            pages,
                            collection,
                            collection_execution_details,
                            start_offset,
                        )

                        storage["in_execution"] = {}
                        collection_execution_details[collection] = (
                            ensure_utc_aware(datetime.now())
                        )
                        break
                    except KeyError:
                        storage["in_execution"] = {}
                        collection_execution_details[collection] = (
                            ensure_utc_aware(datetime.now())
                        )
                        break
                    except requests.exceptions.ProxyError as err:
                        err_msg = f"Invalid proxy configuration. Retry attempt: {attempt}."
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                            if_raise=False,
                            resolution=PROXY_ERROR_RESOLUTION,
                        )
                    except requests.exceptions.ConnectionError as err:
                        err_msg = (
                            "Connection Error occurred. Check the "
                            "Discovery URL/API Root URL provided. "
                            f"Retry attempt: {attempt}."
                        )
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                            if_raise=False,
                            resolution=CONNECTION_ERROR_RESOLUTION,
                        )
                    except requests.exceptions.RequestException as err:
                        if (
                            "416" in str(err)
                            or "request range not satisfiable" in str(err).lower()
                        ):
                            storage["in_execution"] = {}
                            collection_execution_details[collection] = (
                                ensure_utc_aware(datetime.now())
                            )
                            self.logger.info(
                                f"{self.log_prefix}: Received status code 416, "
                                f"exiting the pulling of '{collection}' "
                                f"collection. Response: {str(err)}."
                            )
                            break

                        err_msg = (
                            "Exception occurred while fetching the "
                            "objects of collection. "
                            f"Retry attempt: {attempt}."
                        )
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                            if_raise=False,
                        )
                    except Exception as err:
                        if (
                            "416" in str(err)
                            or "request range not satisfiable" in str(err).lower()
                        ):
                            storage["in_execution"] = {}
                            collection_execution_details[collection] = (
                                ensure_utc_aware(datetime.now())
                            )
                            self.logger.info(
                                f"{self.log_prefix}: Received status code 416, "
                                f"exiting the pulling of '{collection}' "
                                f"collection. Response: {str(err)}."
                            )
                            break

                        err_msg = (
                            "Exception occurred while fetching the "
                            "objects of collection. "
                            f"Retry attempt: {attempt}."
                        )
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                            if_raise=False,
                        )

                    if attempt >= (IN_EXECUTION_MAX_RETRIES - 1):
                        storage["in_execution"] = {}
                        collection_execution_details[collection] = (
                            ensure_utc_aware(datetime.now())
                        )
                        self.logger.info(
                            f"{self.log_prefix}: Exhausted retries while "
                            f"resuming '{collection}'. Skipping this "
                            f"collection till current time."
                        )
                        break

                    time.sleep(IN_EXECUTION_SLEEP_TIME)

        for collection in filtered_collections:
            new_collection_details[collection] = ensure_utc_aware(
                collection_execution_details.get(collection, start_time)
            )

        sorted_collection = sorted(
            new_collection_details, key=lambda k: new_collection_details[k]
        )

        for collection in sorted_collection:
            collection_object = collection_name_object[collection]
            collection_start_time = new_collection_details[
                collection
            ] - timedelta(minutes=delay_time)

            self.logger.info(
                f"{self.log_prefix}: Parsing collection - "
                f"'{collection}'. Start time: {collection_start_time} (UTC)"
            )

            try:
                pages = self.get_page(
                    func=collection_object.get_objects,
                    configuration=configuration,
                    start_time=collection_start_time,
                )

                yield from _process_pages(
                    pages,
                    collection,
                    new_collection_details,
                    start_offset=0,
                )

                if not is_retraction:
                    storage["in_execution"] = {}
                    new_collection_details[collection] = ensure_utc_aware(
                        datetime.now()
                    )
            except KeyError:
                if not is_retraction:
                    storage["in_execution"] = {}
                    new_collection_details[collection] = ensure_utc_aware(
                        datetime.now()
                    )
                self.logger.info(
                    f"{self.log_prefix}: No data in collection "
                    f"'{collection}', continuing."
                )
            except requests.exceptions.ProxyError as err:
                err_msg = "Invalid proxy configuration."
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                    resolution=PROXY_ERROR_RESOLUTION,
                )
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the "
                    "Discovery URL/API Root URL provided."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                    resolution=CONNECTION_ERROR_RESOLUTION,
                )
            except requests.exceptions.RequestException as err:
                if (
                    "416" in str(err)
                    or "request range not satisfiable" in str(err).lower()
                ):
                    if not is_retraction:
                        storage["in_execution"] = {}
                        new_collection_details[collection] = (
                            ensure_utc_aware(datetime.now())
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, "
                        f"exiting the pulling of '{collection}' "
                        f"collection. Response: {str(err)}."
                    )
                else:
                    err_msg = (
                        "Exception occurred while fetching the "
                        "objects of collection."
                    )
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )
            except Exception as err:
                if (
                    "416" in str(err)
                    or "request range not satisfiable" in str(err).lower()
                ):
                    if not is_retraction:
                        storage["in_execution"] = {}
                        new_collection_details[collection] = (
                            ensure_utc_aware(datetime.now())
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, "
                        f"exiting the pulling of '{collection}' "
                        f"collection. Response: {str(err)}."
                    )
                else:
                    err_msg = (
                        "Exception occurred while fetching the "
                        "objects of collection."
                    )
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )

        if not is_retraction:
            storage["collections"] = self.convert_datetime_to_string(
                new_collection_details.copy()
            )
            self.logger.debug(
                f"{self.log_prefix}: Storage value after"
                f" completion of the pull cycle: {storage['collections']}."
            )

        type_breakdown_str = self._format_type_breakdown(total_type_counts, type_to_pull)
        
        self.logger.info(
            f"{self.log_prefix}: Completed pulling of "
            f"indicator(s) from all collection(s) - "
            f"{', '.join(filtered_collections)}. "
            f"Total {total_indicators} indicator(s) "
            f"pulled, {total_skipped} skipped due to filters. "
            f"Pull Stats: {type_breakdown_str} indicator(s) were fetched."
        )

    def _pull(self, configuration, last_run_at):
        """Pull implementation.

        Args:
            configuration (dict): Configuration dictionary.
            last_run_at (datetime): Last run time.

        Yields:
            tuple: (indicators_batch, sub_checkpoint_dict) for each batch.
        """
        (
            version,
            discovery_url,
            initial_range,
            type_to_pull,
            severity,
            reputation,
        ) = get_configuration_parameters(
            configuration,
            keys=["version", "discovery_url", "days", "type_to_pull", "severity", "reputation"]
        )

        if not last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(initial_range)
            )
            self.logger.debug(
                f"{self.log_prefix}: Starting the initial pull execution "
                "for Discovery URL: "
                f"{discovery_url},"
                f" Version: {version}"
                f" and start time: {start_time}."
            )
        else:
            start_time = last_run_at
            self.logger.debug(
                f"{self.log_prefix}: Starting the pull execution for "
                f"Discovery URL: "
                f"{discovery_url},"
                f" Version: {version}."
            )

        self.logger.debug(
            f"{self.log_prefix}: Filter details - Type:"
            f" {type_to_pull},"
            f" Severity: {severity},"
            f" Reputation: {reputation}."
        )

        if version == STIX_VERSION_1:
            yield from self.pull_1x(configuration, start_time)
        else:
            yield from self.pull_2x(configuration, start_time)

    def pull(self):
        """Pull indicators from TAXII server.

        Returns:
            Generator or List: If sub_checkpoint is available, returns the
                generator directly. Otherwise, consumes the generator and
                returns a list of all indicators.
        """
        try:
            return self._pull(self.configuration, self.last_run_at)
        except STIXTAXIIException as err:
            raise err
        except Exception as err:
            err_msg = "Error occurred while pulling the indicators."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def get_modified_indicators(self, source_indicators: List[List[Indicator]]):
        """Get all modified indicators status for retraction.

        This method identifies indicators that should be retracted because they
        either no longer exist on the TAXII server, have been revoked, or have
        expired (valid_until/valid_time_positions < current time).

        Applicable for both STIX/TAXII 1.x and 2.x.

        Args:
            source_indicators (List[List[Indicator]]): Batches of source indicators
                currently stored in Cloud Exchange.

        Yields:
            tuple: (list_of_ioc_values_to_retract, is_done_flag)
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        # Get configuration parameters
        (
            version,
            retraction_interval,
        ) = get_configuration_parameters(
            self.configuration,
            keys=["version", "retraction_interval"]
        )

        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not configured for "
                f'"{self.config_name}". Skipping retraction.'
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
            return

        retraction_interval = int(retraction_interval)
        self.logger.info(
            f"{self.log_prefix}: Pulling modified indicators from "
            f"{PLATFORM_NAME} for retraction. Looking back "
            f"{retraction_interval} days. Version: {version}."
        )

        # Calculate start time for retraction
        start_time = datetime.now() - timedelta(days=retraction_interval)

        try:
            # Fetch currently valid indicators from TAXII server
            # using is_retraction=True to get set of values
            fetched_iocs = set()

            if version == STIX_VERSION_1:
                # Use pull_1x for version 1.x
                for ioc_values_set, _ in self.pull_1x(
                    self.configuration, start_time, is_retraction=True
                ):
                    if isinstance(ioc_values_set, set):
                        fetched_iocs.update(ioc_values_set)
            else:
                # Use pull_2x for version 2.x
                for ioc_values_set, _ in self.pull_2x(
                    self.configuration, start_time, is_retraction=True
                ):
                    if isinstance(ioc_values_set, set):
                        fetched_iocs.update(ioc_values_set)

            self.logger.info(
                f"{self.log_prefix}: Fetched {len(fetched_iocs)} valid "
                f"indicator(s) from {PLATFORM_NAME}."
            )

            # Compare source indicators with fetched indicators
            for source_ioc_list in source_indicators:
                try:
                    total_iocs = len(source_ioc_list)

                    # Find indicators NOT in fetched set = should be retracted
                    iocs_to_retract = [
                        ioc.value for ioc in source_ioc_list
                        if ioc and ioc.value not in fetched_iocs
                    ]

                    self.logger.info(
                        f"{self.log_prefix}: {len(iocs_to_retract)} indicator(s) "
                        f"will be marked as retracted out of {total_iocs} "
                        f"total indicator(s) from {PLATFORM_NAME}."
                    )
                    yield iocs_to_retract, False

                except Exception as err:
                    err_msg = (
                        f"Error while processing source indicators for "
                        f"retraction from {PLATFORM_NAME}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    raise STIXTAXIIException(err_msg)

        except STIXTAXIIException:
            raise
        except Exception as err:
            err_msg = (
                f"Error occurred while fetching modified indicators "
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise STIXTAXIIException(err_msg)

    def _validate_collections(self, configuration):
        """Validate collections.
        Args:
            configuration (dict): Configuration dictionary.
        Returns:
            list: List of collections.
        """
        try:
            (
                version,
                discovery_url,
                username,
                password,
                collection_names,
            ) = get_configuration_parameters(
                configuration,
                keys=["version", "discovery_url", "username", "password", "collection_names"]
            )

            # Build clients
            if version == STIX_VERSION_1:
                client = self._build_client(configuration)
                all_collections = self._get_collections(client)
            elif version == STIX_VERSION_20:
                apiroot = ApiRoot20(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
            elif version == STIX_VERSION_21:
                apiroot = ApiRoot21(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
            
            # Gather collections
            collection_name_object = {}
            if version in [STIX_VERSION_20, STIX_VERSION_21]:
                collection_objects = list(apiroot.collections)
                all_collections = [c.title for c in collection_objects]
                collection_name_object = {
                    c.title: c for c in collection_objects
                }
            collections = [c.strip() for c in collection_names.split(",")]
            collections = list(filter(lambda x: len(x) > 0, collections))
            if collections and set(collections) - set(all_collections):
                return ValidationResult(
                    success=False,
                    message=(
                        f"Could not find the collection(s): "
                        f"{', '.join(set(collections) - set(all_collections))}"
                    ),
                )
            collections_to_validate = collections or all_collections

            # Validate collections
            if collections_to_validate:
                validation_collection = collections_to_validate[0]
                start_time = ensure_utc_aware(datetime.now())
                if version == STIX_VERSION_1:
                    content_blocks = client.poll(
                        collection_name=validation_collection,
                        begin_date=start_time,
                    )
                    next(iter(content_blocks), None)
                else:
                    collection_object = collection_name_object.get(
                        validation_collection
                    )
                    if collection_object:
                        pages = self.get_page(
                            func=collection_object.get_objects,
                            configuration=configuration,
                            start_time=start_time,
                        )
                        next(pages, None)

            return ValidationResult(
                success=True, message="Validated successfully."
            )
        except requests.exceptions.ProxyError as err:
            err_msg = "Invalid proxy configuration."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
                resolution=PROXY_ERROR_RESOLUTION,
            )
            return ValidationResult(success=False, message=err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the "
                "Discovery URL/API Root URL provided."
            )
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
                resolution=CONNECTION_ERROR_RESOLUTION,
            )
            return ValidationResult(success=False, message=err_msg)
        except requests.exceptions.RequestException as ex:
            err_msg = "Exception occurred while connecting to the the server."
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg + ". Check logs for more details.",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"validating credentials. Error: {str(ex)}"
                ),
                details=traceback.format_exc()
            )
            if ex.status == "UNAUTHORIZED":
                return ValidationResult(
                    success=False,
                    message="Invalid/Blank Username/Password provided.",
                )
            else:
                return ValidationResult(
                    success=False, message="Check logs for more details."
                )
        except STIXTAXIIException as ex:
            err_msg = (
                "Could not fetch the collection list "
                "from the server. Check logs"
            )
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except Exception as ex:
            err_msg = "Could not fetch the collection list from the server."
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg + " Check all of the parameters.",
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        (
            version,
            discovery_url,
            username,
            password,
            collection_names,
            pagination_method,
            initial_range,
            delay_config,
            type_to_pull,
            severity,
            reputation,
            batch_size,
            retraction_interval,
        ) = get_configuration_parameters(configuration, is_validation=True)

        # Discovery URL
        if validation_failure := self._validate_configuration_parameters(
            field_name="Discovery URL/API Root URL",
            field_value=discovery_url,
            field_type=str,
        ):
            return validation_failure

        # Username
        if validation_failure := self._validate_configuration_parameters(
            field_name="Username",
            field_value=username,
            field_type=str,
            is_required=False,
        ):
            return validation_failure

        # Password
        if validation_failure := self._validate_configuration_parameters(
            field_name="Password",
            field_value=password,
            field_type=str,
            is_required=False,
        ):
            return validation_failure

        # STIX/TAXII Version
        if validation_failure := self._validate_configuration_parameters(
            field_name="STIX/TAXII Version",
            field_value=version,
            field_type=str,
            allowed_values=[
                STIX_VERSION_1,
                STIX_VERSION_20,
                STIX_VERSION_21,
            ],
        ):
            return validation_failure

        # Collection Names
        if validation_failure := self._validate_configuration_parameters(
            field_name="Collection Names",
            field_value=collection_names,
            field_type=str,
            is_required=False,
        ):
            return validation_failure

        # Type of Threat data to pull
        valid_types = (
            [c["value"] for c in TYPE_V1["choices"]]
            if version == STIX_VERSION_1
            else [c["value"] for c in TYPE_V2["choices"]]
        )
        if validation_failure := self._validate_configuration_parameters(
            field_name="Type of Threat data to pull",
            field_value=type_to_pull,
            field_type=list,
            allowed_values=valid_types,
            is_required=False
        ):
            return validation_failure

        # Reputation
        if validation_failure := self._validate_configuration_parameters(
            field_name="Reputation",
            field_value=reputation,
            field_type=int,
            min_value=1,
            max_value=10,
        ):
            return validation_failure

        # Initial Range
        if validation_failure := self._validate_configuration_parameters(
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            min_value=1,
            max_value=365,
        ):
            return validation_failure

        # Retraction logic
        if validation_failure := self._validate_configuration_parameters(
            field_name="Retraction Interval (in days)",
            field_value=retraction_interval,
            field_type=int,
            min_value=1,
            max_value=365,
            is_required=False,
        ):
            return validation_failure

        # Delay
        if validation_failure := self._validate_configuration_parameters(
            field_name="Look Back",
            field_value=delay_config,
            field_type=int,
            min_value=1,
            max_value=1440,
            is_required=False,
        ):
            return validation_failure

        # Severity
        valid_severity = (
            [c["value"] for c in SEVERITY_V1["choices"]]
            if version == STIX_VERSION_1
            else [c["value"] for c in SEVERITY_V2["choices"]]
        )
        if validation_failure := self._validate_configuration_parameters(
            field_name="Severity",
            field_value=severity,
            field_type=list,
            allowed_values=valid_severity,
            is_required=False
        ):
            return validation_failure

        # Pagination method - only for version 2.x
        if version in [STIX_VERSION_20, STIX_VERSION_21]:
            if validation_failure := self._validate_configuration_parameters(
                field_name="Pagination Method",
                field_value=pagination_method,
                field_type=str,
                allowed_values=["next", "last_added_date"],
            ):
                return validation_failure

        # Batch Size - only for version 2.x
        # Range for 2.0 is 2 to 1000
        if version == STIX_VERSION_20:
            if validation_failure := self._validate_configuration_parameters(
                field_name="Batch Size",
                field_value=batch_size,
                field_type=int,
                min_value=2,
                max_value=1000,
            ):
                return validation_failure
        # Range for 2.1 is 1 to 1000
        if version == STIX_VERSION_21:
            if validation_failure := self._validate_configuration_parameters(
                field_name="Batch Size",
                field_value=batch_size,
                field_type=int,
                min_value=1,
                max_value=1000,
            ):
                return validation_failure

        # Validate collections
        validate_collections = self._validate_collections(configuration)
        if validate_collections.success is False:
            return validate_collections

        self.logger.info(
            f"{self.log_prefix}: Successfully validated"
            " configuration parameters."
        )
        return ValidationResult(
            success=True, message="Validated successfully."
        )

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Any,
        field_type: type,
        allowed_values: Optional[List] = None,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        custom_validation_func: Optional[Callable] = None,
        is_required: bool = True,
        validation_err_msg: str = "",
    ) -> Optional[ValidationResult]:
        """Validate a configuration field value."""
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if is_required and (
            (
                not isinstance(field_value, int)
                and not field_value
            )
            or (
                isinstance(field_value, int)
                and field_value is None
            )
        ):
            err_msg = (
                f"{field_name} is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if field_value and not isinstance(field_value, field_type) or (
            custom_validation_func
            and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}', expecting {field_type} type value."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if allowed_values:
            allowed_values_list = (
                list(allowed_values.values())
                if isinstance(allowed_values, dict)
                else list(allowed_values)
            )
            allowed_values_str = ", ".join(
                [str(value) for value in allowed_values_list]
            )
            err_msg = (
                f"Invalid value for {field_name} provided in configuration "
                f"parameters. Available values are {allowed_values_str}."
            )
            if field_type is str and field_value not in allowed_values_list:
                self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if field_type is list and any(
                value not in allowed_values_list for value in field_value
            ):
                self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
                return ValidationResult(success=False, message=err_msg)

        if isinstance(field_value, int):
            if min_value is not None and field_value < min_value:
                err_msg = (
                    f"Invalid value for {field_name} provided in "
                    "configuration parameters. Must be an integer greater "
                    f"than or equal to {min_value}."
                )
                self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if max_value is not None and field_value > max_value:
                err_msg = (
                    f"Invalid value for {field_name} provided in "
                    "configuration parameters. Must be an integer less "
                    f"than or equal to {max_value}."
                )
                self.logger.error(f"{self.log_prefix}: {validation_err_msg}{err_msg}")
                return ValidationResult(success=False, message=err_msg)

        return None

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate STIX/TAXII action configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get fields required for an action."""
        return []
