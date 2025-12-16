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

CTE Infoblox Plugin constants.
"""

import json
import traceback
import time
import re
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Callable, Dict, Generator, List, Literal, Set, Tuple, Union
from urllib.parse import quote, urlparse

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.constants import (
    ACTIVE_INDICATORS,
    ACTIVE_INDICATORS_RESPONSE_LIMIT,
    BASE_PULL_LOGGER_MESSAGE,
    CONFIGURATION_BOOLEAN_VALUES,
    DATA_PROFILES_ENDPOINT,
    DATETIME_FORMAT,
    DEFAULT_PUSH_BATCH,
    DEFAULT_SLEEP_TIME,
    FETCH_ACTIVE_INDICATORS_ENDPOINT,
    FETCH_INSIGHTS_ENDPOINT,
    FETCH_INSIGHTS_INDICATORS_ENDPOINT,
    FETCH_LOOKALIKE_DOMAINS_ENDPOINT,
    FETCH_PROPERTIES_ENDPOINT,
    HASH_TYPES,
    INDICATOR_TYPES,
    INDICATOR_SOURCE_PAGES,
    INFOBLOX_LOOKALIKE_DOMAINS_PULL_LIMIT,
    INFOBLOX_PAGE_TO_SERVICE_MAPPING,
    INTEGER_THRESHOLD,
    IOC_TYPE_REGEX,
    IOC_UI_ENDPOINT,
    IP_TYPES,
    LOOKALIKE_DOMAINS,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PULL,
    PUSH,
    PUSH_ACTIVE_INDICATORS_ENDPOINT,
    RETRACTION,
    SOC_INSIGHTS,
    SOC_INSIGHTS_PULL_LIMIT,
    SOC_INSIGHT_IOC_ACTION_TYPES,
    TIME_PAGINATION_INTERVAL_1_DAY,
    TIME_PAGINATION_INTERVAL_1_HOUR,
)
from .utils.helper import InfobloxPluginException, InfobloxPluginHelper

INFOBLOX_TO_INTERNAL_TYPE = {
    "host": IndicatorType.HOSTNAME,
    "ipv4": IndicatorType.IPV4,
    "ipv6": IndicatorType.IPV6,
    "url": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "domain": IndicatorType.DOMAIN,
}


class InfobloxPlugin(PluginBase):
    """Infoblox Plugin class"""

    def __init__(self, name, *args, **kwargs):
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
        self.infoblox_helper = InfobloxPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = InfobloxPlugin.metadata
            plugin_name = metadata.get("name", PLATFORM_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_storage(self) -> Dict:
        """
        Returns the storage dictionary.

        If the storage is not initialized, it will be initialized to an
        empty dictionary.

        Returns:
            Dict: The storage dictionary.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def _create_tags(
        self,
        utils: TagUtils,
        tags: List[str],
        enable_tagging: str,
        infoblox_service_name: str,
    ) -> Tuple[List[str], Set[str]]:
        """Create new tag(s) in database if required.

        Args:
            utils (TagUtils): Utils
            tags (List[str]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Tuple[List[str], Set[str]]: Created tags, Skipped tags
        """
        # Create tag for Infoblox Service Name
        tag_names, skipped_tags = [], set()
        if not utils.exists(infoblox_service_name):
            utils.create_tag(
                TagIn(
                    name=infoblox_service_name,
                    color="#ED3347",
                )
            )
        tag_names.append(infoblox_service_name)

        # Logic for creating other tags
        if enable_tagging != "yes":
            return tag_names, skipped_tags

        for tag in tags:
            tag = tag.strip()
            # Skip Empty tags
            if not tag:
                skipped_tags.add(tag)
                continue
            tag = f"{infoblox_service_name}-{tag}"
            try:
                if not utils.exists(tag):
                    utils.create_tag(
                        TagIn(
                            name=tag,
                            color="#ED3347",
                        )
                    )
            except ValueError:
                skipped_tags.add(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def _determine_ip_version(
        self, ip_string: str
    ) -> Union[Literal["ipv4", "ipv6"], None]:
        """
        Determine IP version of given string.

        Args:
            ip_string (str): IP string

        Returns:
            str: "IPv4" or "IPv6" if valid IP string, None otherwise
        """
        try:
            ip_obj = ip_address(ip_string)
            if isinstance(ip_obj, IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, IPv6Address):
                return "ipv6"
        except (ValueError, Exception):
            return None

    def _confidence_normalization(
        self,
        value: int,
        page: Literal[
            "Active Indicators", "SOC Insights", "Lookalike Domains"
        ],
        method: Literal["pull", "push"],
    ) -> Union[int, None]:
        """
        Normalize the given confidence value.

        If method is "pull", it takes a value from 0 to 100 and maps it to
        a value from 1 to 10. If the value is outside this range, it returns
        the value as is.

        If method is "push", it takes a value from 1 to 10 and maps it to
        a value from 0 to 100. If the value is outside this range, it returns
        the value as is.

        Args:
            value (int): Confidence value
            page (str): Page from which the confidence value is fetched
            method (str): Either "pull" or "push"

        Returns:
            int: Normalized confidence value
        """
        value = int(value)
        if page == ACTIVE_INDICATORS:
            if method == PULL:
                return round((value / 100) * 9 + 1)
            elif method == PUSH:
                return round(((value - 1) / 9) * 100)
        elif page == SOC_INSIGHTS:
            if method == PULL:
                if value == 0:
                    return 1
                elif value == 1:
                    return 3
                elif value == 2:
                    return 6
                elif value == 3:
                    return 10
                else:
                    return 5
            elif method == PUSH:
                self.logger.error(
                    f"{self.log_prefix}: Push method is not supported for"
                    f" {SOC_INSIGHTS} page."
                )
        elif page == LOOKALIKE_DOMAINS:
            return 5
        else:
            self.logger.error(f"{self.log_prefix}: Invalid method provided")
            return value

    def _severity_mapping(
        self,
        value: Union[int, SeverityType],
        page: Literal[
            "Active Indicators", "SOC Insights", "Lookalike Domains"
        ],
        method: Literal["pull", "push"],
    ) -> Union[int, SeverityType]:
        """
        Maps the given value to either an integer or a SeverityType.

        If method is "pull", it takes an integer from 0 to 100 and maps it to
        a SeverityType. If the value is outside this range, it returns
        SeverityType.UNKNOWN.

        If method is "push", it takes a SeverityType and maps it to an integer
        from 0 to 100. If the SeverityType is not recognized, it returns 0.

        The mapping is as follows:
            - 0-25: LOW
            - 25-50: MEDIUM
            - 50-75: HIGH
            - 75-100: CRITICAL
        """
        if page == ACTIVE_INDICATORS:
            if method == PULL:
                if value >= 0 and value <= 25:
                    return SeverityType.LOW
                elif value > 25 and value <= 50:
                    return SeverityType.MEDIUM
                elif value > 50 and value <= 75:
                    return SeverityType.HIGH
                elif value > 75 and value <= 100:
                    return SeverityType.CRITICAL
                else:
                    return SeverityType.UNKNOWN
            elif method == PUSH:
                if value == SeverityType.LOW:
                    return 25
                elif value == SeverityType.MEDIUM:
                    return 50
                elif value == SeverityType.HIGH:
                    return 75
                elif value == SeverityType.CRITICAL:
                    return 100
                else:
                    return None
        elif page == SOC_INSIGHTS:
            if method == PULL:
                if value == -1:
                    return SeverityType.LOW
                elif value == 1:
                    return SeverityType.MEDIUM
                elif value == 2:
                    return SeverityType.HIGH
                elif value == 3:
                    return SeverityType.CRITICAL
                else:
                    return SeverityType.UNKNOWN
            elif method == PUSH:
                self.logger.error(
                    f"{self.log_prefix}: Push method not supported"
                    f" for SOC Insights."
                )
        elif page == LOOKALIKE_DOMAINS:
            if method == PULL:
                return SeverityType.UNKNOWN
            elif method == PUSH:
                self.logger.error(
                    f"{self.log_prefix}: Push method not supported"
                    f" for Lookalike Domains."
                )
        else:
            self.logger.error(f"{self.log_prefix}: Invalid method provided")
            return value

    def _get_ioc_type_from_value(self, value: str) -> Tuple[str, str]:
        copy_value = value
        if ip_type := self._determine_ip_version(copy_value):
            return ip_type, ip_type
        elif re.fullmatch(IOC_TYPE_REGEX["domain"], value):
            return "domain", "domain"
        elif re.fullmatch(IOC_TYPE_REGEX["hostname"], value, re.IGNORECASE):
            return "host", "host"
        elif self._validate_url(value):
            return "url", "url"
        elif re.fullmatch(IOC_TYPE_REGEX["md5"], value):
            return "md5", "hash"
        elif re.fullmatch(IOC_TYPE_REGEX["sha256"], value):
            return "sha256", "hash"
        else:
            return "url", "url"

    def _get_profile_filter_query_param(self, data_profiles: str) -> str:
        """
        Takes a string of profile names and returns a string
        in the format required by the Infoblox API for the
        profile filter query parameter.

        The method first fetches all the profiles from the API.
        Then, it iterates over the given list of profile names.
        If a profile name matches any of the ones fetched from the
        API, it adds the corresponding profile ID to the list.
        Finally, it joins the list with commas and returns the
        resulting string.
        """
        if not data_profiles.strip():
            return ""
        profiles_to_filter = []
        profiles = self._get_profiles(configuration=self.configuration)
        data_profiles = [
            tok.strip() for tok in data_profiles.strip().split(",") if tok.strip()
        ]

        for profile_name, profile_id in profiles.items():
            if profile_name in data_profiles:
                profiles_to_filter.append(profile_id)
        return ",".join(profiles_to_filter)

    def _get_type_filter_query_param(self, iocs_to_be_pulled: list) -> str:
        """
        Takes a list of iocs_to_be_pulled and returns a string
        in the format required by the Infoblox API for the
        type filter query parameter.

        The method first makes a copy of the given list. Then, it
        checks if "ipv4" is in the list. If it is, it removes it and
        adds "ip". Next, it checks if "ipv6" is in the list. If it is,
        it removes it. If "ip" is not in the list, it adds it. Finally,
        it joins the list with commas and returns the resulting string.
        """
        type_to_filter = iocs_to_be_pulled.copy()
        if "domain" in type_to_filter:
            type_to_filter.remove("domain")
        if "ipv4" in iocs_to_be_pulled:
            type_to_filter.remove("ipv4")
            type_to_filter.append("ip")
        if "ipv6" in iocs_to_be_pulled:
            type_to_filter.remove("ipv6")
            if "ip" not in type_to_filter:
                type_to_filter.append("ip")
        type_to_filter = ",".join(type_to_filter)
        return type_to_filter

    def _fetch_properties(self) -> List[str]:
        """
        Fetches all properties from Infoblox server.

        Returns:
            List[str]: List of property IDs.
        """
        base_url, api_key, *_ = (
            self.infoblox_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        properties = []
        logger_msg = f"fetching properties from {PLATFORM_NAME} server"
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=FETCH_PROPERTIES_ENDPOINT.format(base_url=base_url),
                headers=self.infoblox_helper.get_auth_headers(api_key),
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
            )

            for property in response.get("property", []):
                if property.get("id"):
                    properties.append(property.get("id"))
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxPluginException(err_msg)

        return properties

    def _fetch_profiles(
        self,
        logger_msg: str = f"fetching profiles from {PLATFORM_NAME} server",
        is_validation: bool = False,
        base_url: str = None,
        api_key: str = None,
    ) -> Dict:
        """
        Fetches all active profiles from Infoblox server.

        Returns:
            List[str]: List of profile names.
        """
        if not is_validation:
            base_url, api_key, *_ = (
                self.infoblox_helper.get_configuration_parameters(
                    self.configuration,
                )
            )
        profiles_dict = {}
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=DATA_PROFILES_ENDPOINT.format(base_url=base_url),
                headers=self.infoblox_helper.get_auth_headers(api_key),
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=is_validation,
                is_handle_error_required=True,
            )

            for profile in response.get("profiles", []):
                if not profile.get("active"):
                    continue
                if profile.get("name"):
                    profiles_dict[profile.get("name")] = profile.get("id")
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxPluginException(err_msg)

        storage = self._get_storage()
        storage.update(
            {
                "profiles": profiles_dict,
            }
        )
        return profiles_dict

    def _get_profiles(self, configuration: Dict) -> Dict:
        """
        Retrieve Infoblox profiles from storage if the configuration
        hash matches, otherwise fetch and update profiles.

        Args:
            configuration (Dict): The configuration dictionary
                containing connection parameters.
            is_validation (bool, optional): Whether the operation is
                for validation. Defaults to False.

        Returns:
            Dict: The Infoblox profiles dictionary retrieved from storage
                or fetched from the server.
        """
        base_url, api_key, *_, data_profiles, _, _ = (
            self.infoblox_helper.get_configuration_parameters(
                configuration=configuration
            )
        )
        current_config_hash = self.infoblox_helper.generate_hash(
            f"{base_url}{api_key}{data_profiles}"
        )
        fetched_profiles = {}
        storage = self._get_storage()
        if storage.get("profiles") and (
            current_config_hash == storage.get("config_hash")
        ):
            fetched_profiles = storage.get("profiles")
        else:
            fetched_profiles = self._fetch_profiles(
                base_url=base_url,
                api_key=api_key,
                is_validation=False,
            )
        return fetched_profiles

    def _create_profile(self, profile_name: str) -> Union[str, None]:
        """
        Creates a new profile on Infoblox server.

        Args:
            profile_name (str): Name of the profile to be created.

        Returns:
            Union[str, None]: Created profile name if successful, else None.
        """
        base_url, api_key, *_ = (
            self.infoblox_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        logger_msg = (
            f"creating profile '{profile_name}' on {PLATFORM_NAME} server"
        )
        current_time = datetime.now(timezone.utc)
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                method="POST",
                url=DATA_PROFILES_ENDPOINT.format(base_url=base_url),
                headers=self.infoblox_helper.get_auth_headers(api_key),
                json={
                    "name": profile_name,
                    "description": (
                        f"Created via Netskope Cloud Exchange plugin "
                        f"{MODULE_NAME} {PLATFORM_NAME} v{PLUGIN_VERSION}"
                        f" on {current_time.strftime('%Y-%m-%d')} at"
                        f" {current_time.strftime('%H:%M:%S')} UTC."
                    ),
                    "default_ttl": True,
                },
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=False,
            )
            created_profile = response.get("profile", {})
            created_profile_name = created_profile.get("name", "")
            created_profile_id = created_profile.get("id")
            self.logger.info(
                f"{self.log_prefix}: Successfully created profile "
                f"'{created_profile_name}' on {PLATFORM_NAME} server."
            )
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxPluginException(err_msg)
        storage = self._get_storage()
        storage.get("profiles", {}).update(
            {created_profile_name: created_profile_id}
        )
        return created_profile_name

    def _create_iocs_ui_link(self, value: str, type: str) -> str:
        """
        Create a link to the Infoblox UI for the given IOC value and type.

        Args:
            value (str): The IOC value.
            type (str): The IOC type.

        Returns:
            str: The link to the Infoblox Dossier page.
        """
        base_url = self.configuration.get("base_url").strip().strip("/")
        if type == "url":
            try:
                value = quote(value, safe="")
            except Exception as err:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while creating URL encoded value for {value}."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                return ""
        return IOC_UI_ENDPOINT.format(base_url=base_url, value=value)

    def _get_success_and_skip_count_objects(
        self,
        ioc_source_page: Literal[
            "Active Indicators", "SOC Insights", "Lookalike Domains"
        ],
    ) -> Tuple[Dict, int, List]:
        success_ioc_count = {}
        if ioc_source_page == ACTIVE_INDICATORS:
            success_ioc_count = {
                "md5": 0,
                "sha256": 0,
                "host": 0,
                "ipv4": 0,
                "ipv6": 0,
                "url": 0,
            }
        elif ioc_source_page == LOOKALIKE_DOMAINS:
            success_ioc_count = {
                "domain": 0,
                "host": 0
            }
        elif ioc_source_page == SOC_INSIGHTS:
            success_ioc_count = {
                "md5": 0,
                "sha256": 0,
                "host": 0,
                "ipv4": 0,
                "ipv6": 0,
                "url": 0,
                "domain": 0
            }
        return success_ioc_count, 0, []

    def _create_time_based_pagination(
        self,
        start_time: str,
        end_time: str,
        pagination_interval: int = TIME_PAGINATION_INTERVAL_1_DAY,
    ) -> Generator[List[Tuple[str, str]], None, None]:
        """
        Create a generator that yields tuples of (start_time, end_time) from
        given start_time to end_time. The start_time and end_time of each tuple
        will not exceed the pagination interval.

        Args:
            start_time (str): The start time for pagination.
            end_time (str): The end time for pagination.
            pagination_interval (int): The pagination interval in hours.

        Yields:
            tuple: A tuple containing the start time and end time for
            pagination.
        """
        start_time = datetime.strptime(start_time, DATETIME_FORMAT)
        end_time = datetime.strptime(end_time, DATETIME_FORMAT)
        while True:
            if (end_time - start_time) > timedelta(
                hours=pagination_interval,
            ):
                intermediate_time = start_time + timedelta(
                    hours=pagination_interval,
                )
                yield (
                    datetime.strftime(start_time, DATETIME_FORMAT),
                    datetime.strftime(intermediate_time, DATETIME_FORMAT),
                )
                start_time = intermediate_time
            else:
                yield (
                    datetime.strftime(start_time, DATETIME_FORMAT),
                    datetime.strftime(end_time, DATETIME_FORMAT),
                )
                break

    def _create_indicator_object(
        self,
        threat_data: Dict,
        enable_tagging: str,
        success_ioc_count: Dict,
        skipped_ioc: int,
        skipped_tags: Set[str],
        tag_utils: TagUtils,
    ) -> Tuple[Indicator, Dict, int, Set[str]]:
        """
        Create an indicator object from the given threat data.

        Args:
            threat_data (Dict): Threat data in the format received from
                Infoblox API.
            enable_tagging (str): Whether to enable tagging or not.
            success_ioc_count (Dict): Dictionary to keep track of the count of
                indicators by type.
            skipped_ioc (int): Count of indicators that were skipped.
            skipped_tags (Set[str]): Set of tags that were skipped.
            tag_utils (TagUtils): An instance of TagUtils to create tags.

        Returns:
            tuple: A tuple containing the created indicator object, updated
                success_ioc_count, updated skipped_ioc count, and updated
                skipped_tags set.
        """
        if not threat_data.get("value"):
            skipped_ioc += 1
            return None, success_ioc_count, skipped_ioc, skipped_tags
        elif threat_data.get("value"):
            try:
                severity_mapping = threat_data.get("severity")
                reputation_mapping = threat_data.get("reputation")
                tags, tags_skipped = self._create_tags(
                    utils=tag_utils,
                    tags=threat_data.get("tags", []),
                    enable_tagging=enable_tagging,
                    infoblox_service_name=INFOBLOX_PAGE_TO_SERVICE_MAPPING[
                        severity_mapping[1]
                    ],
                )
                indicator_obj = Indicator(
                    value=threat_data.get("value"),
                    type=INFOBLOX_TO_INTERNAL_TYPE.get(
                        threat_data.get("type"),
                    ),
                    tags=tags,
                    severity=self._severity_mapping(
                        int(severity_mapping[0]), severity_mapping[1], PULL
                    ),
                    reputation=self._confidence_normalization(
                        reputation_mapping[0], reputation_mapping[1], PULL
                    ),
                    firstSeen=threat_data.get("first_seen"),
                    lastSeen=threat_data.get(
                        "last_seen", threat_data.get("first_seen")
                    ),
                    comments=threat_data.get("comments"),
                    extendedInformation=self._create_iocs_ui_link(
                        value=threat_data.get("value"),
                        type=threat_data.get("type"),
                    ),
                )
            except (ValidationError, Exception) as err:
                indicator_type = threat_data.get("type")
                indicator_value = threat_data.get("value")
                error_msg = (
                    "Validation error occurred"
                    if isinstance(err, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: {error_msg} while creating "
                        f"indicator object for indicator type "
                        f"'{indicator_type}' and indicator value "
                        f"'{indicator_value}' ."
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_ioc += 1
                skipped_tags.update(tags_skipped)
                return None, success_ioc_count, skipped_ioc, skipped_tags
            success_ioc_count[threat_data.get("type")] += 1
            skipped_tags.update(tags_skipped)
            return (
                indicator_obj,
                success_ioc_count,
                skipped_ioc,
                skipped_tags,
            )

    def _paginate_over_1_hour_intervals(
        self,
        base_url: str,
        headers: Dict,
        fetch_start_time: str,
        fetch_end_time: str,
        iocs_to_be_pulled: List[str],
        profile_filter: str,
        type_to_filter: str,
        page_number: int,
        is_retraction: bool,
    ) -> Generator[Tuple[List[Dict], str, int, int], None, None]:
        """
        Paginate threat data fetching over 1-hour intervals when IoC count
        exceeds 50k for a single page.

        This method is called when a single page contains more than 50,000
        IoCs, which requires splitting the time range into smaller 1-hour
        chunks to avoid API limits and ensure all data is retrieved
        successfully.

        Args:
            base_url (str): The base URL for the API endpoint.
            headers (Dict): HTTP headers to include in the API requests.
            fetch_start_time (str): Start time for the data fetch in ISO
                format.
            fetch_end_time (str): End time for the data fetch in ISO format.
            iocs_to_be_pulled (List[str]): List of IoC types to retrieve.
            profile_filter (str): Profile filter to apply to the query.
            type_to_filter (str): Type filter to apply to the query.
            page_number (int): Current page number being processed.
            is_retraction (bool): Whether this is a retraction request.

        Yields:
            Union[Dict, str]: Threat data records or error messages from each
                1-hour interval.

        Note:
            Each 1-hour interval is treated as a sub-page with numbering format
            "{page_number}.{inner_page}" for tracking purposes.
        """
        self.logger.info(
            f"{self.log_prefix}: Got more than 50k IoCs for"
            f" page {page_number}, splitting the page into chunks of"
            f" 1 hour to fetch the remaining IoCs."
        )
        inner_page = 0
        for hour_start, hour_end in self._create_time_based_pagination(
            start_time=fetch_start_time,
            end_time=fetch_end_time,
            pagination_interval=TIME_PAGINATION_INTERVAL_1_HOUR,
        ):
            inner_page += 1
            for (
                threat_data,
                fetch_end_time,
                page_number,
                sub_page_number
            ) in self._fetch_threat_data(
                base_url=base_url,
                headers=headers,
                fetch_start_time=hour_start,
                fetch_end_time=hour_end,
                iocs_to_be_pulled=iocs_to_be_pulled,
                profile_filter=profile_filter,
                type_to_filter=type_to_filter,
                page_number=page_number,
                sub_page_number=inner_page,
                is_retraction=is_retraction,
                is_recursive_call=True,
            ):
                yield threat_data, fetch_end_time, page_number, sub_page_number

    def _process_active_indicators_api_response(
        self,
        response: List[Dict],
        iocs_to_be_pulled: List[str],
        is_retraction: bool,
    ) -> List[Dict]:
        """
        Process active indicators API response and return processed IoC data.

        Args:
            response (List[Dict]): List of threat dictionaries from the API
                response.
            iocs_to_be_pulled (List[str]): List of IoC types that should be
                collected.
            is_retraction (bool): Whether this is processing retraction data.

        Returns:
            List[Dict]: List of processed IoC data.

        Note:
            - Skips threats with "netskope" in the threat_label for regular
                collection
            - Handles hash type mapping from generic "hash" to specific hash
                types
            - Performs IP version detection and filtering for IP addresses
            - Sets default values for missing severity (-1) and confidence
                (44) fields
            - Filters out invalid IP addresses and unsupported IoC types
        """
        processed_ioc_data = []
        for threat in response:
            if not threat:
                continue
            threat_type = threat.get("type", "").lower()
            if is_retraction:
                if threat_type == "hash":
                    if threat.get("hash_type", "") in HASH_TYPES:
                        processed_ioc_data.append(threat.get(threat_type, ""))
                    else:
                        continue
                else:
                    processed_ioc_data.append(threat.get(threat_type, ""))
            else:
                if "netskope" in threat.get("threat_label", "").lower():
                    continue
                tags_list = [
                    threat.get("threat_label", ""),
                    threat.get("property", threat.get("class", "")),
                ]
                threat_dict = {
                    "type": threat_type,
                    "value": threat.get(threat_type, ""),
                    # If we do not get threat_level from api
                    # response set the severity value to -1 which
                    # will be mapped to SeverityType.UNKNOWN in the
                    # function _severity_mapping()
                    "severity": (
                        threat.get("threat_level", -1), ACTIVE_INDICATORS
                    ),
                    # Default value for reputation is 5 (set by core if
                    # not provided)
                    # So if the api response does not provide confidence
                    # value, set it to 44 which will be normalized to 5
                    # in the function _confidence_normalization()
                    "reputation": (
                        threat.get("confidence", 44), ACTIVE_INDICATORS
                    ),
                    "tags": tags_list,
                    "comments": threat.get("extended", {}).get(
                        "notes", ""
                    ),
                }
                if (
                    threat.get("hash_type")
                    and threat.get("hash_type", "").lower() in HASH_TYPES
                ):
                    threat_dict["type"] = threat.get("hash_type").lower()
                if threat_dict.get("type", "") == "ip":
                    ip_version = self._determine_ip_version(
                        threat_dict.get("value"),
                    )
                    if "ipv4" not in iocs_to_be_pulled and (
                        ip_version == "ipv4"
                    ):
                        continue
                    if ip_version:
                        threat_dict["type"] = ip_version
                    else:
                        self.logger.info(
                            f"{self.log_prefix}: Skipping IoC with"
                            f" value {threat_dict.get('value', '')}"
                            " as IP value was invalid."
                        )
                processed_ioc_data.append(threat_dict)
        return processed_ioc_data

    def _fetch_threat_data(
        self,
        base_url: str,
        headers: Dict,
        fetch_start_time: str,
        fetch_end_time: str,
        iocs_to_be_pulled: List[str],
        profile_filter: str,
        type_to_filter: str,
        page_number: int,
        sub_page_number: int = None,
        is_retraction: bool = False,
        is_recursive_call: bool = False,
    ) -> Generator[tuple[List[Dict], str, int, int], None, None]:
        """
        Fetch threat data from Infoblox TIDE API.

        Args:
            base_url (str): The base URL of the Infoblox API.
            headers (Dict): The headers to pass in the API call.
            fetch_start_time (str): The start time for the API call.
            fetch_end_time (str): The end time for the API call.
            iocs_to_be_pulled (List[str]): The list of IOCs to be pulled.
            profile_filter (str): The profile filter for the API call.
            type_to_filter (str): The type to filter for the API call.
            page_number (int): The page number for the API call.
            sub_page_number (int): The sub page number for the API call.
            is_retraction (bool): Whether the method call is for retraction or
                not.
            is_recursive_call (bool): Whether the method call is recursive or
                not.

        Yields:
            Tuple[List[Dict], str, int, int]: A tuple containing the
                list of IOCs, the last fetch time, the page number,
                and the sub page number.
        """
        page_number_msg = page_number
        if sub_page_number:
            page_number_msg = f"{page_number} hour {sub_page_number}"
        if is_retraction:
            logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                fetch_type="fetching modified indicators",
                page_number=page_number_msg,
                indicator_source_page=ACTIVE_INDICATORS,
                platform_name=PLATFORM_NAME
            )
        else:
            logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                fetch_type="fetching threat data",
                page_number=page_number_msg,
                indicator_source_page=ACTIVE_INDICATORS,
                platform_name=PLATFORM_NAME
            )
        query_params = {
            "type": type_to_filter,
            "from_date": fetch_start_time,
            "to_date": fetch_end_time,
            "data_format": "json",
            "include_ipv6": True if "ipv6" in iocs_to_be_pulled else False,
        }
        if profile_filter:
            query_params["profile"] = profile_filter
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                url=FETCH_ACTIVE_INDICATORS_ENDPOINT.format(base_url=base_url),
                method="GET",
                params=query_params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=is_retraction,
            )
            # Split the page into 1 hour intervals to retrieve all the data
            if response.get(
                "record_count"
            ) == ACTIVE_INDICATORS_RESPONSE_LIMIT and not is_recursive_call:
                for (
                    threat_data, fetch_end_time, page_number, sub_page_number
                ) in self._paginate_over_1_hour_intervals(
                    base_url=base_url,
                    headers=headers,
                    fetch_start_time=fetch_start_time,
                    fetch_end_time=fetch_end_time,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    profile_filter=profile_filter,
                    type_to_filter=type_to_filter,
                    page_number=page_number,
                    is_retraction=is_retraction,
                ):
                    yield (
                        threat_data,
                        fetch_end_time,
                        page_number,
                        sub_page_number,
                    )
            else:
                threat_data = self._process_active_indicators_api_response(
                    response=response.get("threat", []),
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    is_retraction=is_retraction,
                )
                yield (
                    threat_data, fetch_end_time, page_number, sub_page_number
                )
        except InfobloxPluginException:
            raise
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxPluginException(error_msg)

    def _get_start_and_end_time(
        self,
        initial_pull_range: str,
        sub_checkpoint: Dict,
        ioc_page: str,
        is_retraction: bool = False,
    ) -> Tuple[str, str]:
        """
        Get the start and end time for API call to fetch IoCs from given
        IoC page.

        Args:
            initial_pull_range (str): The number of days to pull IoCs
                initially.
            sub_checkpoint (Dict): The checkpoint dictionary containing
                the last fetch time for each IoC type.
            ioc_page (str): The page of IoC to be fetched.

        Returns:
            Tuple[str, str]: A tuple containing the start time and end time
                for API call in ISO 8601 format.
        """
        end_time = datetime.strftime(
            datetime.now(timezone.utc), DATETIME_FORMAT
        )
        if sub_checkpoint and sub_checkpoint.get(ioc_page, {}).get(
            "last_fetch"
        ) and not is_retraction:
            start_time = sub_checkpoint.get(ioc_page, {}).get("last_fetch")
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {ioc_page}"
                f" page of {PLATFORM_NAME} platform using checkpoint"
                f" {str(start_time)}"
            )
        elif self.last_run_at and not is_retraction:
            start_time = datetime.strftime(self.last_run_at, DATETIME_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {ioc_page}"
                f" page of {PLATFORM_NAME} platform using checkpoint"
                f" {str(start_time)}"
            )
        else:
            start_time = datetime.strftime(
                datetime.strptime(end_time, DATETIME_FORMAT)
                - timedelta(days=int(initial_pull_range)),
                DATETIME_FORMAT,
            )
            if not is_retraction:
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch for IoC(s)"
                    f" from page {ioc_page} since checkpoint is empty. "
                    f"Querying indicators for last {initial_pull_range} days."
                )
        return start_time, end_time

    def _active_indicators_ingest_logger(
        self,
        success_ioc_count: Dict,
        total_indicators_fetched: int,
        skipped_ioc: int,
        page_number: int,
        fetch_checkpoint: Dict,
        checkpoint_time: str,
        sub_page_number: int = None,
        is_retraction: bool = False
    ) -> Tuple[int, int, Dict]:
        """
        Logs the result of indicator ingest from Active Indicators page of
        Infoblox TIDE platform.

        Args:
            success_ioc_count (Dict): A dictionary containing the count of
                successful indicator ingest per type.
            total_indicators_fetched (int): The total number of indicators
                fetched from the Active Indicators page.
            skipped_ioc (int): The total number of indicators skipped.
            page_number (int): The page number of Active Indicators page
                being fetched.
            fetch_checkpoint (Dict): The checkpoint dictionary containing
                the last fetch time for each IoC type.
            checkpoint_time (str): The current time in ISO 8601 format.
            sub_page_number (int, optional): The sub-page number of Active
                Indicators page being fetched. Defaults to None.
            is_retraction (bool, optional): A boolean indicating if this is
                a retraction pull. Defaults to False.

        Returns:
            Tuple(int, int, Dict): A tuple containing the total number of
                indicators fetched, updated page number, and the
                updated checkpoint dictionary.
        """
        if not is_retraction:
            sub_page_msg = (
                f" hour {sub_page_number}" if sub_page_number else ""
            )
            total_indicators_fetched += sum(success_ioc_count.values())
            success_hash_count = success_ioc_count[
                'md5'
            ] + success_ioc_count["sha256"]
            self.logger.info(
                f"{self.log_prefix}: Fetched "
                f"{sum(success_ioc_count.values())} "
                f"indicator(s) and skipped {skipped_ioc}"
                f" indicator(s) in page {page_number}{sub_page_msg}"
                f" from Active Indicators page of"
                f" {PLATFORM_NAME} platform. Pull Stats:"
                f" Hash: {success_hash_count},"
                f" Host: {success_ioc_count.get('host')},"
                f" URLs: {success_ioc_count.get('url')},"
                f" IPv4: {success_ioc_count.get('ipv4')},"
                f" IPv6: {success_ioc_count.get('ipv6')}"
                f" Total indicator(s) fetched - "
                f"{total_indicators_fetched}."
            )
            fetch_checkpoint[ACTIVE_INDICATORS][
                "last_fetch"
            ] = checkpoint_time
        if not sub_page_number or sub_page_number == 24:
            page_number += 1
        return total_indicators_fetched, page_number, fetch_checkpoint

    def _pull_active_indicators(
        self,
        base_url: str,
        api_key: str,
        iocs_to_be_pulled: List[str],
        data_profiles: List[str],
        enable_tagging: str,
        tag_utils: TagUtils,
        fetch_checkpoint: Dict,
        initial_pull_range: int,
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
        """
        Pulls IoC(s) from Active Indicator page on Infoblox.

        Args:
            base_url (str): The base URL of the Infoblox server.
            api_key (str): The API key to use when making requests to the
                Infoblox server.
            iocs_to_be_pulled (List[str]): A list of IoC types to be pulled.
            data_profiles (List[str]): A list of data profiles to be used
                when pulling indicators.
            enable_tagging (str): Whether tagging is enabled or not. Allowed
                values are "yes" or "no".
            tag_utils (TagUtils): An instance of the TagUtils class to be
                used when pulling indicators.
            fetch_checkpoint (Dict): A dictionary containing the last fetch
                time for each IoC type.
            initial_pull_range (int): The number of days to pull IoCs
                initially.
            is_retraction (bool, optional): A boolean indicating if this is
                a retraction pull. Defaults to False.

        Yields:
            Tuple[List[Union[Indicator, str]], Dict]: A tuple containing a
                list of indicators and the updated fetch checkpoint.
        """
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        skipped_tags = set()
        start_time, end_time = self._get_start_and_end_time(
            initial_pull_range=initial_pull_range,
            sub_checkpoint=sub_checkpoint,
            ioc_page=ACTIVE_INDICATORS,
            is_retraction=is_retraction,
        )

        profile_filter = self._get_profile_filter_query_param(data_profiles)
        type_to_filter = self._get_type_filter_query_param(iocs_to_be_pulled)
        page_number = 1
        total_indicators_fetched = 0
        headers = self.infoblox_helper.get_auth_headers(api_key)
        for page_start_time, page_end_time in self._create_time_based_pagination(
            start_time, end_time, TIME_PAGINATION_INTERVAL_1_DAY
        ):
            try:
                for (
                    threat_data_list,
                    checkpoint_time,
                    page_number,
                    sub_page_number
                ) in self._fetch_threat_data(
                    base_url=base_url,
                    headers=headers,
                    fetch_start_time=page_start_time,
                    fetch_end_time=page_end_time,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    profile_filter=profile_filter,
                    type_to_filter=type_to_filter,
                    page_number=page_number,
                    is_retraction=is_retraction,
                ):
                    (
                        success_ioc_count,
                        skipped_ioc,
                        indicator_list
                    ) = self._get_success_and_skip_count_objects(
                        ACTIVE_INDICATORS
                    )
                    if is_retraction:
                        yield threat_data_list, None
                    else:
                        for threat_data in threat_data_list:
                            (
                                indicator_obj,
                                success_ioc_count,
                                skipped_ioc,
                                skipped_tags,
                            ) = self._create_indicator_object(
                                threat_data=threat_data,
                                enable_tagging=enable_tagging,
                                success_ioc_count=success_ioc_count,
                                skipped_ioc=skipped_ioc,
                                skipped_tags=skipped_tags,
                                tag_utils=tag_utils,
                            )
                            if indicator_obj:
                                indicator_list.append(indicator_obj)
                    (
                        total_indicators_fetched, page_number, fetch_checkpoint
                    ) = self._active_indicators_ingest_logger(
                        success_ioc_count=success_ioc_count,
                        total_indicators_fetched=total_indicators_fetched,
                        skipped_ioc=skipped_ioc,
                        page_number=page_number,
                        fetch_checkpoint=fetch_checkpoint,
                        checkpoint_time=checkpoint_time,
                        sub_page_number=sub_page_number,
                        is_retraction=is_retraction
                    )
                    if not indicator_list:
                        continue
                    yield indicator_list, fetch_checkpoint
            except InfobloxPluginException:
                raise
            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while fetching"
                    " threat data from 'Active Indicators' page on"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
                raise InfobloxPluginException(err_msg)
        if not is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Completed pulling"
                f" {total_indicators_fetched} indicators from"
                f" Active Indicators page of {PLATFORM_NAME}."
            )

    def _fetch_lookalike_domains(
        self,
        base_url: str,
        headers: Dict,
        start_time: str,
        is_retraction: bool
    ) -> Generator[Tuple[List[Dict], Union[str, None], int], None, None]:
        """
        Pulls lookalike domains from the Infoblox server.

        Args:
            base_url (str): The base URL of the Infoblox server.
            headers (Dict): The headers to pass in the API call.
            start_time (str): The start time for the API call.
            is_retraction (bool): A boolean indicating whether the method call
                is for retraction or not.

        Yields:
            Tuple[List[Dict], Union[str, None], int]: A tuple containing a list
                of lookalike domains, the last fetch time and the page number.
        """
        offset = 0
        page_number = 1
        while True:
            lookalike_domain_list = []
            last_fetch = None
            if is_retraction:
                logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                    fetch_type="fetching modified indicators",
                    page_number=page_number,
                    indicator_source_page="Lookalike Domains",
                    platform_name=PLATFORM_NAME
                )
            else:
                logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                    fetch_type="fetching lookalike domains data",
                    page_number=page_number,
                    indicator_source_page="Lookalike Domains",
                    platform_name=PLATFORM_NAME
                )
            try:
                response = self.infoblox_helper.api_helper(
                    logger_msg=logger_msg,
                    method="GET",
                    url=FETCH_LOOKALIKE_DOMAINS_ENDPOINT.format(
                        base_url=base_url
                    ),
                    params={
                        "_filter": f"detected_at>'{start_time}'",
                        "_offset": offset,
                        "_limit": INFOBLOX_LOOKALIKE_DOMAINS_PULL_LIMIT,
                        "_order_by": "detected_at",
                    },
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                    is_validation=False,
                    is_handle_error_required=True,
                )
                if not response.get("results"):
                    break
                for lookalike_domain in response.get("results", []):
                    domain_value = lookalike_domain.get("lookalike_domain", "")
                    host_value = lookalike_domain.get("lookalike_host", "")
                    if domain_value == host_value:
                        host_value = None
                    if is_retraction:
                        lookalike_domain_list.append(
                            domain_value
                        )
                        if host_value:
                            lookalike_domain_list.append(host_value)
                    else:
                        lookalike_domain_list.append({
                            "type": "domain",
                            "value": domain_value,
                            "tags": [
                                f"{lookalike_domain.get('target_domain')} - lookalike",
                                f"Suspicious: {lookalike_domain.get('suspicious')}"
                            ],
                            "comments": lookalike_domain.get("reason"),
                            "first_seen": lookalike_domain.get(
                                "detected_at"
                            ),
                            "severity": (-1, LOOKALIKE_DOMAINS),
                            "reputation": (5, LOOKALIKE_DOMAINS),
                        })
                        if host_value:
                            lookalike_domain_list.append({
                                "type": "host",
                                "value": host_value,
                                "tags": [
                                    f"{lookalike_domain.get('target_domain')} - lookalike",
                                    f"Suspicious: {lookalike_domain.get('suspicious')}"
                                ],
                                "comments": lookalike_domain.get("reason"),
                                "first_seen": lookalike_domain.get(
                                    "detected_at"
                                ),
                                "severity": (-1, LOOKALIKE_DOMAINS),
                                "reputation": (5, LOOKALIKE_DOMAINS),
                            })
                        last_fetch = lookalike_domain.get("detected_at")
                yield lookalike_domain_list, last_fetch, page_number
                offset += INFOBLOX_LOOKALIKE_DOMAINS_PULL_LIMIT
                page_number += 1
            except InfobloxPluginException:
                raise
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
                raise InfobloxPluginException(err_msg)

    def _pull_lookalike_domains(
        self,
        base_url: str,
        api_key: str,
        initial_pull_range: int,
        enable_tagging: str,
        tag_utils: TagUtils,
        fetch_checkpoint: Dict,
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
        """
        This function is used to pull lookalike domains from Infoblox.

        Args:
            base_url (str): The base URL of the Infoblox .
            api_key (str): The API key to use for authentication.
            initial_pull_range (int): The initial pull range in days.
            enable_tagging (str): Whether or not to enable tagging.
            tag_utils (TagUtils): The TagUtils object to use for tagging.
            fetch_checkpoint (Dict): The fetch checkpoint dictionary.

        Yields:
            List of IoC objects and the updated fetch checkpoint dictionary.

        Raises:
            InfobloxPluginException: If there is an error while fetching
                lookalike domains.
        """
        sub_checkpoint = getattr(self, "sub_checkpoint", None)

        skipped_tags = set()
        total_indicators_fetched = 0

        headers = self.infoblox_helper.get_auth_headers(api_key)
        start_time, _ = self._get_start_and_end_time(
            initial_pull_range=initial_pull_range,
            sub_checkpoint=sub_checkpoint,
            ioc_page="Lookalike Domains",
            is_retraction=is_retraction,
        )
        try:
            for lookalike_domain_list, last_fetch, page_number in (
                self._fetch_lookalike_domains(
                    base_url=base_url,
                    headers=headers,
                    start_time=start_time,
                    is_retraction=is_retraction,
                )
            ):
                (
                    success_ioc_count,
                    skipped_ioc,
                    indicator_list
                ) = self._get_success_and_skip_count_objects(
                    LOOKALIKE_DOMAINS
                )
                if is_retraction:
                    indicator_list = lookalike_domain_list
                else:
                    for lookalike_domain in lookalike_domain_list:
                        (
                            indicator_obj,
                            success_ioc_count,
                            skipped_ioc,
                            skipped_tags,
                        ) = self._create_indicator_object(
                            threat_data=lookalike_domain,
                            enable_tagging=enable_tagging,
                            success_ioc_count=success_ioc_count,
                            skipped_ioc=skipped_ioc,
                            skipped_tags=skipped_tags,
                            tag_utils=tag_utils,
                        )
                        indicator_list.append(indicator_obj)
                total_indicators_fetched += len(indicator_list)
                if not is_retraction:
                    self.logger.info(
                        f"{self.log_prefix}: Fetched"
                        f" {sum(success_ioc_count.values())}"
                        f" indicator(s) and skipped {skipped_ioc} indicator(s)"
                        f" for page {page_number} from Lookalike"
                        f" Domains page of {PLATFORM_NAME} platform."
                        f" Pull Stats:"
                        f" Domain: {success_ioc_count.get('domain')},"
                        f" Host: {success_ioc_count.get('host')}"
                        f" Total IoC(s) fetched: {total_indicators_fetched}"
                    )
                    fetch_checkpoint[LOOKALIKE_DOMAINS][
                        "last_fetch"
                    ] = last_fetch
                if not indicator_list:
                    continue
                yield indicator_list, fetch_checkpoint
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while fetching"
                f" lookalike domains from 'Lookalike Domains'"
                f" page of {PLATFORM_NAME}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
            raise InfobloxPluginException(err_msg)
        if not is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Completed pulling"
                f" {total_indicators_fetched} indicators from"
                f" Lookalike Domains page of {PLATFORM_NAME}."
            )

    def _get_insights(
        self, base_url: str, headers: Dict
    ) -> List[str]:
        """
        Fetch insights from Infoblox server.

        Args:
            base_url (str): The base URL of the Infoblox API.
            headers (Dict): The headers to pass in the API call.

        Returns:
            List[str]: A list of insight IDs.
        """
        insight_id_list = []
        logger_msg = f"fetching insights from {PLATFORM_NAME} server"
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=FETCH_INSIGHTS_ENDPOINT.format(base_url=base_url),
                params={"status": "Active"},
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=False,
            )
            for insight in response.get("insightList", []):
                if insight.get("insightId"):
                    insight_id_list.append(insight.get("insightId"))
            return insight_id_list
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
            raise InfobloxPluginException(err_msg)

    def _fetch_soc_insights(
        self,
        base_url: str,
        headers: Dict,
        insight_id: str,
        start_time: str,
        end_time: str,
        page_number: int,
        iocs_to_be_pulled: List[str],
        is_retraction: bool,
    ) -> Generator[Union[str, Dict], None, None]:
        """
        Fetch IOCs from Infoblox API for the given insight ID.

        Args:
            base_url (str): The base URL of the Infoblox API.
            headers (Dict): The headers to pass in the API call.
            insight_id (str): The ID of the insight to fetch IOCs for.
            start_time (str): The start time to fetch IOCs for.
            end_time (str): The end time to fetch IOCs for.
            page_number (int): The page number to fetch IOCs for.
            is_retraction (bool): Whether to fetch modified IOCs or all IOCs.

        Yields:
            Union[str, Dict]: The IOC value or a dictionary containing IOC
                details.
        """
        start_time = start_time.split("Z")[0]
        start_time = start_time + ".000"
        end_time = end_time.split("Z")[0]
        end_time = end_time + ".000"
        if is_retraction:
            logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                fetch_type=(
                    f"fetching modified indicators for insight {insight_id}"
                ),
                page_number=page_number,
                indicator_source_page=SOC_INSIGHTS,
                platform_name=PLATFORM_NAME
            )
        else:
            logger_msg = BASE_PULL_LOGGER_MESSAGE.format(
                fetch_type=f"fetching indicators for insight {insight_id}",
                page_number=page_number,
                indicator_source_page=SOC_INSIGHTS,
                platform_name=PLATFORM_NAME
            )
        params = {
            "from": start_time,
            "to": end_time,
            "limit": SOC_INSIGHTS_PULL_LIMIT
        }
        try:
            response = self.infoblox_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=FETCH_INSIGHTS_INDICATORS_ENDPOINT.format(
                    base_url=base_url,
                    insight_id=insight_id
                ),
                params=params,
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=is_retraction,
            )
            for indicator in response.get("indicators", []):
                ioc_value = indicator.get("indicator")
                if is_retraction:
                    if ioc_value:
                        yield ioc_value
                else:
                    ioc_type, parent_type = self._get_ioc_type_from_value(
                        ioc_value
                    )
                    if parent_type not in iocs_to_be_pulled:
                        continue
                    ioc_action = indicator.get("action")
                    ioc_dict = {
                        "value": ioc_value,
                        "type": ioc_type,
                        "first_seen": None,
                        "severity": (
                            indicator.get("threatLevelMax", -1), SOC_INSIGHTS
                        ),
                        "reputation": (
                            indicator.get("confidence", 5), SOC_INSIGHTS
                        ),
                        "comments": f"Insight ID: {insight_id}",
                        "action": ioc_action,
                    }
                    if ioc_action:
                        ioc_dict["tags"] = [f"Action: {ioc_action}"]
                    yield ioc_dict
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
            raise InfobloxPluginException(err_msg)

    def _pull_soc_insights(
        self,
        base_url: str,
        api_key: str,
        initial_pull_range: int,
        fetch_checkpoint: Dict,
        tag_utils: TagUtils,
        enable_tagging: str,
        iocs_to_be_pulled: List[str],
        soc_insight_ioc_action_type: List[str],
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
        """
        Pulls IoC(s) from Infoblox API for the given insight ID.

        Args:
            base_url (str): The base URL of the Infoblox API.
            api_key (str): The API key to use when making requests to the
                Infoblox API.
            initial_pull_range (int): The number of days to pull IoCs
                initially.
            fetch_checkpoint (Dict): A dictionary containing the last fetch
                time for each IoC type.
            tag_utils (TagUtils): An instance of the TagUtils class to be used
                when pulling indicators.
            enable_tagging (str): Whether tagging is enabled or not. Allowed
                values are "yes" or "no".
            iocs_to_be_pulled (List[str]): A list of IoC types to be pulled.
            soc_insight_ioc_action_type (List[str]): The action type(s) of
                IOCs to be pulled.

        Yields:
            Tuple[List[Union[Indicator, str]], Dict]: A tuple containing a
                list of indicators and the updated fetch checkpoint.
        """
        sub_checkpoint = getattr(self, "sub_checkpoint", None)

        total_indicators_fetched = 0

        headers = self.infoblox_helper.get_auth_headers(api_key)
        start_time, end_time = self._get_start_and_end_time(
            initial_pull_range=initial_pull_range,
            sub_checkpoint=sub_checkpoint,
            ioc_page=SOC_INSIGHTS,
            is_retraction=is_retraction,
        )
        insight_id_list = self._get_insights(base_url, headers)
        try:
            page_number = 0
            # looping over time based pages first and then insight ids, so as
            # to maintain one common sub_checkpoint for all the insight ids
            # instead of maintaining sub_checkpoint for each individual
            # insight id
            for page_start_time, page_end_time in self._create_time_based_pagination(
                start_time=start_time,
                end_time=end_time,
                pagination_interval=TIME_PAGINATION_INTERVAL_1_DAY,
            ):
                page_number += 1
                for insight_id in insight_id_list:
                    (
                        success_ioc_count,
                        skipped_ioc,
                        indicator_list
                    ) = self._get_success_and_skip_count_objects(
                        SOC_INSIGHTS
                    )
                    action_type_skipped_ioc = 0
                    for insight_ioc in self._fetch_soc_insights(
                        base_url=base_url,
                        headers=headers,
                        insight_id=insight_id,
                        start_time=page_start_time,
                        end_time=page_end_time,
                        page_number=page_number,
                        iocs_to_be_pulled=iocs_to_be_pulled,
                        is_retraction=is_retraction,
                    ):
                        if not insight_ioc.get(
                            "action", ""
                        ).lower() in soc_insight_ioc_action_type:
                            action_type_skipped_ioc += 1
                            continue
                        if is_retraction:
                            indicator_list.append(insight_ioc)
                        else:
                            (
                                indicator_object,
                                success_ioc_count,
                                skipped_ioc,
                                _
                            ) = self._create_indicator_object(
                                threat_data=insight_ioc,
                                enable_tagging=enable_tagging,
                                success_ioc_count=success_ioc_count,
                                skipped_ioc=skipped_ioc,
                                skipped_tags=set(),
                                tag_utils=tag_utils,
                            )
                            if indicator_object:
                                indicator_list.append(indicator_object)
                    total_indicators_fetched += sum(success_ioc_count.values())
                    if not is_retraction:
                        self.logger.info(
                            f"{self.log_prefix}: Fetched "
                            f"{sum(success_ioc_count.values())} indicator(s)"
                            f" and skipped {skipped_ioc} indicator(s)"
                            f" in page {page_number} for Insight {insight_id}"
                            f" from SOC Insights page of {PLATFORM_NAME}"
                            f" platform. Pull Stats:"
                            f" MD5: {success_ioc_count.get('md5')},"
                            f" SHA256: {success_ioc_count.get('sha256')},"
                            f" Host: {success_ioc_count.get('host')},"
                            f" URLs: {success_ioc_count.get('url')},"
                            f" IPv4: {success_ioc_count.get('ipv4')},"
                            f" IPv6: {success_ioc_count.get('ipv6')},"
                            f" Domain: {success_ioc_count.get('domain')}"
                            f" Total indicator(s) fetched - "
                            f"{total_indicators_fetched}."
                        )
                        if action_type_skipped_ioc > 0:
                            self.logger.info(
                                f"{self.log_prefix}: Skipped"
                                f" {action_type_skipped_ioc} indicator(s) for"
                                f" page {page_number} as they do not match"
                                " the action type specified in the"
                                " configuration."
                            )
                        fetch_checkpoint[SOC_INSIGHTS][
                            "last_fetch"
                        ] = page_end_time
                    if not indicator_list:
                        continue
                    yield indicator_list, fetch_checkpoint
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while fetching"
                " indicators from SOC insights page on"
                f" {PLATFORM_NAME} server."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
            raise InfobloxPluginException(err_msg)
        if not is_retraction:
            self.logger.info(
                f"{self.log_prefix}: Completed pulling"
                f" {total_indicators_fetched} indicators from"
                f" SOC Insights page of {PLATFORM_NAME}."
            )

    def _pull(self) -> Generator[List[Indicator], None, None]:
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            _,
            _,
            enable_tagging,
            initial_pull_range,
            data_profiles,
            indicator_source_page,
            soc_insight_ioc_action_type,
        ) = self.infoblox_helper.get_configuration_parameters(
            self.configuration,
        )
        fetch_checkpoint = {
            ACTIVE_INDICATORS: {"last_fetch": None},
            LOOKALIKE_DOMAINS: {"last_fetch": None},
            SOC_INSIGHTS: {"last_fetch": None},
            "error_in": None
        }
        tag_utils = TagUtils()
        if INDICATOR_SOURCE_PAGES[ACTIVE_INDICATORS] in indicator_source_page:
            yield from self._pull_active_indicators(
                base_url=base_url,
                api_key=api_key,
                iocs_to_be_pulled=iocs_to_be_pulled,
                data_profiles=data_profiles,
                enable_tagging=enable_tagging,
                tag_utils=tag_utils,
                fetch_checkpoint=fetch_checkpoint,
                initial_pull_range=initial_pull_range,
            )
        if INDICATOR_SOURCE_PAGES[LOOKALIKE_DOMAINS] in indicator_source_page:
            yield from self._pull_lookalike_domains(
                base_url=base_url,
                api_key=api_key,
                initial_pull_range=initial_pull_range,
                enable_tagging=enable_tagging,
                tag_utils=tag_utils,
                fetch_checkpoint=fetch_checkpoint,
            )
        if INDICATOR_SOURCE_PAGES[SOC_INSIGHTS] in indicator_source_page:
            yield from self._pull_soc_insights(
                base_url=base_url,
                api_key=api_key,
                initial_pull_range=initial_pull_range,
                fetch_checkpoint=fetch_checkpoint,
                tag_utils=tag_utils,
                enable_tagging=enable_tagging,
                iocs_to_be_pulled=iocs_to_be_pulled,
                soc_insight_ioc_action_type=soc_insight_ioc_action_type,
            )

    def pull(self) -> List[Indicator]:
        try:
            if self.configuration.get("is_pull_required").strip() == "yes":
                if hasattr(self, "sub_checkpoint"):

                    def wrapper(self):
                        yield from self._pull()

                    return wrapper(self)
                else:
                    indicators = []
                    for batch, _ in self._pull():
                        indicators.extend(batch)
                    return indicators
            else:
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling indicators"
                f" from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxPluginException(err_msg)

    def get_modified_indicators(
        self, source_indicators: List[List[Dict]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            List of retracted indicators, Status (List, bool): List of
                retracted indicators values. Status of execution.
        """
        self.log_prefix = f"{self.log_prefix} [{RETRACTION}]"
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            _,
            retraction_interval,
            _,
            _,
            data_profiles,
            indicator_source_page,
            soc_insight_ioc_action_type,
        ) = self.infoblox_helper.get_configuration_parameters(
            self.configuration,
        )
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" from {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)

        pulled_indicators = set()
        self.logger.info(
            message=(
                f"{self.log_prefix}: Pulling modified indicators "
                f"from {PLATFORM_NAME}."
            )
        )
        try:
            if INDICATOR_SOURCE_PAGES[
                ACTIVE_INDICATORS
            ] in indicator_source_page:
                active_indicators = []
                for iocs, _ in self._pull_active_indicators(
                    base_url=base_url,
                    api_key=api_key,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    data_profiles=data_profiles,
                    enable_tagging="no",
                    tag_utils=None,
                    fetch_checkpoint={},
                    initial_pull_range=retraction_interval,
                    is_retraction=True,
                ):
                    active_indicators.extend(iocs)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(active_indicators)} modified IoC(s) from Active"
                    f" Indicators page of {PLATFORM_NAME} platform."
                )
                pulled_indicators.update(active_indicators)
            if INDICATOR_SOURCE_PAGES[
                LOOKALIKE_DOMAINS
            ] in indicator_source_page:
                lookalike_domains = []
                for iocs, _ in self._pull_lookalike_domains(
                    base_url=base_url,
                    api_key=api_key,
                    initial_pull_range=retraction_interval,
                    enable_tagging="no",
                    tag_utils=None,
                    fetch_checkpoint={},
                    is_retraction=True,
                ):
                    lookalike_domains.extend(iocs)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(lookalike_domains)} modified IoC(s) from Lookalike"
                    f" Domains page of {PLATFORM_NAME} platform."
                )
                pulled_indicators.update(lookalike_domains)
            if INDICATOR_SOURCE_PAGES[SOC_INSIGHTS] in indicator_source_page:
                soc_insights = []
                for iocs, _ in self._pull_soc_insights(
                    base_url=base_url,
                    api_key=api_key,
                    initial_pull_range=retraction_interval,
                    fetch_checkpoint={},
                    tag_utils=None,
                    enable_tagging="no",
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    soc_insight_ioc_action_type=soc_insight_ioc_action_type,
                    is_retraction=True,
                ):
                    soc_insights.extend(iocs)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(soc_insights)} modified IoC(s) from SOC Insights"
                    f" page of {PLATFORM_NAME} platform."
                )
                pulled_indicators.update(soc_insights)
        except InfobloxPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while pulling modified"
                f"indicators from {PLATFORM_NAME} server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxPluginException(err_msg)

        for ioc_page in source_indicators:
            source_unique_iocs = set()
            for ioc in ioc_page:
                source_unique_iocs.add(ioc.value)
            retracted_iocs = source_unique_iocs - pulled_indicators
            self.logger.info(
                f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) will "
                f"be marked as retracted from {len(source_unique_iocs)} total "
                f"indicator(s) present in cloud exchange for {PLATFORM_NAME}."
            )
            yield list(retracted_iocs), False

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="add"),
        ]

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get fields required for an action."""
        if action.value == "add":
            properties = self._fetch_properties()
            profiles = self._fetch_profiles()
            default_profile_value = (
                list(profiles.keys())[0] if len(profiles) > 0 else "create"
            )
            return [
                {
                    "label": "Profile",
                    "key": "profile",
                    "type": "choice",
                    "mandatory": True,
                    "choices": [
                        {
                            "key": key,
                            "value": key,
                        }
                        for key, _ in profiles.items()
                    ]
                    + [{"key": "Create new profile", "value": "create"}],
                    "default": default_profile_value,
                    "description": "Select a data profile to push data into.",
                },
                {
                    "label": "New Profile Name",
                    "key": "create_profile_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Name of the data profile to create if it does not"
                        " exist."
                    ),
                },
                {
                    "label": "Property",
                    "key": "property",
                    "type": "choice",
                    "mandatory": True,
                    "choices": [
                        {
                            "key": key,
                            "value": key,
                        }
                        for key in properties
                    ],
                    "default": properties[0] if properties else "",
                    "description": (
                        "Select threat classification for IoC. For more"
                        " details navigate to Monitor > Research >"
                        " Resources > Classification Guide page on the"
                        " Infoblox platform."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Infoblox action configuration."""
        if action.value not in ["add"]:
            self.logger.error(
                message=f"{self.log_prefix}: Unsupported action {action.label}"
                " provided. Allowed action is 'Share Indicators'."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        profile_name = action.parameters.get("profile")
        create_profile = action.parameters.get("create_profile_name")
        if not profile_name:
            err_msg = "Profile is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(profile_name, str):
            err_msg = "Invalid Profile provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if profile_name == "create":
            if not create_profile:
                err_msg = "Profile name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(create_profile, str):
                err_msg = "Invalid Profile name provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        property_name = action.parameters.get("property")
        if not property_name:
            err_msg = "Property is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(property_name, str):
            err_msg = "Invalid Property provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        success_msg = f"Validation successful for {action.value} action."
        self.logger.debug(f"{self.log_prefix}: {success_msg}")
        return ValidationResult(
            success=True,
            message=success_msg,
        )

    def _create_batches(
        self, ioc_dict: Dict[str, List[Dict]]
    ) -> Dict[str, List[List[Dict]]]:
        """
        Divide a list of IoC records into batches of DEFAULT_PUSH_BATCH.

        Args:
            ioc_dict (Dict[str, List[Dict]]): A dictionary containing IoC
                types as keys and list of IoC records as values.

        Returns:
            Dict[str, List[List[Dict]]]: A dictionary of IoC batches with the
                keys as IoC types and the values as a list of lists where
                each list represents a batch of IoC records.
        """
        ioc_batch_dict = {}
        for key, value_list in ioc_dict.items():
            if len(value_list) < DEFAULT_PUSH_BATCH:
                ioc_batch_dict[key] = [value_list]
                continue
            batches = [
                value_list[i: i + DEFAULT_PUSH_BATCH]
                for i in range(0, len(value_list), DEFAULT_PUSH_BATCH)
            ]
            ioc_batch_dict[key] = batches

        return ioc_batch_dict

    def _create_push_batch_by_type(
        self, indicators: List[Indicator], source_label: str, property: str
    ) -> Dict[str, List[List[Dict]]]:
        """
        Create IoC batches for given indicators and source label.

        Args:
            indicators (List[Indicator]): List of Indicator objects.
            source_label (str): Source label for the IoCs to be pushed.
            property (str): Property for the IoCs to be pushed.

        Returns:
            Dict[str, List[List[Dict]]]: A dictionary of IoC batches with the
                keys as IoC types and the values as a list of lists where
                each list represents a batch of IoC records.
        """
        ioc_batches = {"hash": [], "host": [], "ip": [], "url": []}
        skipped_iocs = 0
        count = 0
        skipped_ioc_types = set()
        for indicator in indicators:
            count += 1
            indicator_type = indicator.type
            if indicator_type not in [
                "hostname",
                "sha256",
                "md5",
                "ipv4",
                "ipv6",
                "url",
            ]:
                skipped_ioc_types.add(indicator_type)
                skipped_iocs += 1
                continue
            record_base = {
                "threat_label": source_label,
                "property": property,
                "notes": indicator.comments,
            }
            if severity := self._severity_mapping(
                indicator.severity, ACTIVE_INDICATORS, PUSH
            ):
                record_base["threat_level"] = severity
            if confidence := self._confidence_normalization(
                    indicator.reputation, ACTIVE_INDICATORS, PUSH
            ):
                record_base["confidence"] = confidence
            if indicator_type in HASH_TYPES:
                record_base["hash"] = indicator.value
                record_base["hash_type"] = indicator_type
                ioc_batches["hash"].append(record_base)
            elif indicator_type in IP_TYPES:
                record_base["ip"] = indicator.value
                ioc_batches["ip"].append(record_base)
            elif indicator_type == "hostname":
                record_base["host"] = indicator.value
                ioc_batches["host"].append(record_base)
            elif indicator_type == "url":
                record_base["url"] = indicator.value
                ioc_batches["url"].append(record_base)
            else:
                skipped_iocs += 1
        self.logger.info(
            message=(
                f"{self.log_prefix}: {count - skipped_iocs} IoC(s)"
                f" will be shared to Infoblox. Skipped {skipped_iocs}"
                " IoC(s) as they are not supported by Infoblox."
            ),
            details=f"Skipped IoC types: {', '.join(skipped_ioc_types)}",
        )
        ioc_batches = self._create_batches(ioc_batches)
        return ioc_batches

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push given indicators to Infoblox.

        Args:
            indicators (List[Indicator]): List of indicators received from
            business rule.
            action_dict (Dict): Action Dictionary

        Returns:
            PushResult: PushResult containing flag and message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for"
            f' "{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        if action_value != "add":
            err_msg = (
                "Invalid action parameter selected. Allowed value is "
                "'Share Indicators'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise InfobloxPluginException(err_msg)
        base_url, api_key, *_ = (
            self.infoblox_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        source_label = (
            f"Netskope CE | {plugin_name}" if plugin_name else "netskope-ce"
        )
        profile = action_dict.get("parameters", {}).get("profile")
        create_profile_name = action_dict.get(
            "parameters",
            {},
        ).get("create_profile_name")
        property = action_dict.get("parameters", {}).get("property")
        if profile == "create":
            existing_profiles = self._get_profiles(
                configuration=self.configuration
            )
            if create_profile_name in existing_profiles:
                self.logger.info(
                    f"{self.log_prefix}: Skipped creating profile "
                    f"{create_profile_name} as it already exists."
                )
                profile = create_profile_name
            else:
                profile = self._create_profile(create_profile_name)
                # Sleep for 60 seconds as pushing data instantly into
                # newly created profile sometimes gives 400 bad request error
                # as infoblox sever takes some time to create the profile
                self.logger.debug(
                    f"{self.log_prefix}: Sleeping for 60 seconds before"
                    " sharing data to newly created profile to incorporate"
                    f" profile creation delay on {PLATFORM_NAME} server."
                )
                time.sleep(DEFAULT_SLEEP_TIME)
        indicator_batches = self._create_push_batch_by_type(
            indicators, source_label, property
        )
        total_push_count = 0
        total_skip_count = 0
        for ioc_type, indicator_lists in indicator_batches.items():
            for batch_number, indicator_list in enumerate(
                indicator_lists, start=1
            ):
                error_messages = ""
                if not indicator_list:
                    continue
                logger_msg = (
                    f"sharing {len(indicator_list)} IoC(s) of type"
                    f" {ioc_type} to {PLATFORM_NAME} server for"
                    f" batch {batch_number}"
                )
                try:
                    response = self.infoblox_helper.api_helper(
                        logger_msg=logger_msg,
                        method="POST",
                        url=PUSH_ACTIVE_INDICATORS_ENDPOINT.format(
                            base_url=base_url,
                        ),
                        headers=self.infoblox_helper.get_auth_headers(
                            api_key,
                        ),
                        json={
                            "feed": {
                                "profile": profile,
                                "record_type": ioc_type,
                                "external_id": source_label,
                                "record": indicator_list,
                            }
                        },
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_handle_error_required=True,
                        is_validation=False,
                        is_retraction=False,
                    )
                    num_success = response.get("num_successful")
                    num_error = response.get("num_errors")
                    error_messages = response.get("errors", "")
                    total_push_count += num_success
                    total_skip_count += num_error
                except InfobloxPluginException as err:
                    err_msg = (
                        f"Failed to share {len(indicator_list)} IoC(s) of"
                        f" type {ioc_type} to {PLATFORM_NAME} for batch"
                        f" {batch_number}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {err}"
                    )
                    total_skip_count += len(indicator_list)
                    continue
                except Exception as err:
                    err_msg = f"Unexpected error occurred while {logger_msg}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    total_skip_count += len(indicator_list)
                    continue
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Successfully shared {num_success}"
                        f" IoC(s), failed to share {num_error} IoC(s) of type"
                        f" {ioc_type} to Infoblox for batch {batch_number}"
                        f". Total IoC(s) shared - {total_push_count}. Total"
                        f" IoC(s) skipped - {total_skip_count}."
                    ),
                    details=f"Reason for failure {json.dumps(error_messages)}",
                )
        return PushResult(
            success=True, message="Successfully shared indicators."
        )

    def _validate_connectivity(
        self, base_url: str, api_key: str, data_profiles: str
    ) -> ValidationResult:
        """
        Validate API key by making REST API call.

        Args:
            base_url (str): Base URL.
            api_key (str): Infoblox API Key.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        logger_msg = f"validating connectivity with {PLATFORM_NAME} server"
        current_config_hash = self.infoblox_helper.generate_hash(
            f"{base_url}{api_key}{data_profiles}"
        )
        data_profiles = [
            tok.strip() for tok in data_profiles.strip().split(",") if tok.strip()
        ]
        storage = self._get_storage()
        try:
            fetched_profiles = self._fetch_profiles(
                logger_msg=logger_msg,
                is_validation=True,
                base_url=base_url,
                api_key=api_key,
            )
            if data_profiles:
                invalid_profiles = []
                for profile in data_profiles:
                    if profile not in fetched_profiles:
                        invalid_profiles.append(profile)
                if invalid_profiles:
                    error = (
                        f"Given Data Profile(s) {', '.join(invalid_profiles)}"
                        f" not found on {PLATFORM_NAME} platform."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error}"
                    )
                    return ValidationResult(
                        success=False,
                        message=error,
                    )
            storage.update(
                {
                    "config_hash": current_config_hash
                }
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"connectivity with {PLATFORM_NAME} server"
                " and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message="Validation Successful.",
            )
        except InfobloxPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                f"Unexpected validation error occurred while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
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
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def is_valid_csv_string(self, value: str) -> bool:
        # Strip leading/trailing whitespace and split by comma
        parts = value.strip().split(',')

        # Check that no item is empty after stripping
        return all(part.strip() != '' for part in parts)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        max_value: int = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
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
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str:
            field_value = field_value.strip()
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {', '.join(allowed_values.keys())}."
            )
            if field_type is str and field_value not in allowed_values.values():
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type == list:
                for value in field_value:
                    if value not in allowed_values.values():
                        self.logger.error(
                            f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value <= 0
        ):
            if max_value == INTEGER_THRESHOLD:
                max_value = "2^62"
            err_msg = (
                f"Invalid {field_name} provided in configuration"
                " parameters. Valid value should be an integer "
                f"greater than 0 and less than {max_value}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the Plugin's configuration parameters."""
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            is_pull_required,
            retraction_interval,
            enable_tagging,
            initial_pull_range,
            data_profiles,
            indicator_source_page,
            soc_insight_ioc_action_type,
        ) = self.infoblox_helper.get_configuration_parameters(
            configuration,
        )

        # Validate base url
        if validation_result := self._validate_configuration_parameters(
            field_name="API Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_result

        # Validate API Key
        if validation_result := self._validate_configuration_parameters(
            field_name="API Key",
            field_value=api_key,
            field_type=str,
        ):
            return validation_result

        # Validate IoC types to be pulled
        if validation_result := self._validate_configuration_parameters(
            field_name="Type of Threat data to pull",
            field_value=iocs_to_be_pulled,
            field_type=list,
            allowed_values=INDICATOR_TYPES,
        ):
            return validation_result

        # Validate Data profiles
        if data_profiles and (
            validation_result := self._validate_configuration_parameters(
                field_name="Data Profiles",
                field_value=data_profiles,
                field_type=str,
                custom_validation_func=self.is_valid_csv_string,
            )
        ):
            return validation_result

        # Validate Indicator Source Page
        if validation_result := self._validate_configuration_parameters(
            field_name="Indicator Source Page",
            field_value=indicator_source_page,
            field_type=list,
            allowed_values=INDICATOR_SOURCE_PAGES,
        ):
            return validation_result

        # Validate Enable Polling
        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=CONFIGURATION_BOOLEAN_VALUES,
        ):
            return validation_result

        # Validate Enable Tagging
        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=CONFIGURATION_BOOLEAN_VALUES,
        ):
            return validation_result

        # Validate Initial Pull Range
        if validation_result := self._validate_configuration_parameters(
            field_name="Initial Range",
            field_value=initial_pull_range,
            field_type=int,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Retraction interval
        if validation_result := self._validate_configuration_parameters(
            field_name="Retraction Interval",
            field_value=retraction_interval,
            field_type=Union[int, None],
            max_value=INTEGER_THRESHOLD,
            is_required=False,
        ):
            return validation_result

        # SOC Insight IoC Action Type
        if validation_result := self._validate_configuration_parameters(
            field_name="SOC Insight IoC Action Type",
            field_value=soc_insight_ioc_action_type,
            field_type=list,
            allowed_values=SOC_INSIGHT_IOC_ACTION_TYPES,
        ):
            return validation_result

        if (
            INDICATOR_SOURCE_PAGES[LOOKALIKE_DOMAINS] in indicator_source_page
        ) and INDICATOR_TYPES["Domain"] not in iocs_to_be_pulled:
            err_msg = (
                "Domain IOC type is required for Lookalike Domains"
                " indicator source page."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            indicator_source_page == [INDICATOR_SOURCE_PAGES[ACTIVE_INDICATORS]]
            and iocs_to_be_pulled == [INDICATOR_TYPES["Domain"]]
        ):
            err_msg = (
                "Active Indicators page does not support pulling"
                " Domain IoC type."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_connectivity(
            base_url=base_url, api_key=api_key, data_profiles=data_profiles
        )
