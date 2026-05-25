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

Netskope Plugin implementation to push and pull the data from Netskope Tenant.
"""

import datetime
import json
import re
import traceback
from typing import Dict, List, Tuple, Union, Literal

from netskope.common.utils import (
    AlertsHelper,
    resolve_secret,
)
from netskope.common.utils.handle_exception import (
    handle_status_code,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorGenerator,
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

from .utils.helper import (
    NetskopeThreatExchangeException,
    NetskopeThreatExchangeHelper
)
from .utils.constants import (
    REGEX_FOR_URL,
    REGEX_HOST,
    BATCH_SIZE,
    MAX_PUSH_INDICATORS,
    MAX_PUSH_HOSTS,
    URLS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MAX_QUERY_INDICATORS,
    RETRACTION,
    BYTES_TO_MB,
    MAX_PROFILE_NAME_LENGTH,
    MAX_PROFILE_DESC_LENGTH,
    VALIDATION_ERROR_MSG,
    MAX_INITIAL_RANGE,
    ENABLE_POLLING_OPTIONS,
    ENABLE_TAGGING_OPTIONS,
    TYPES_OF_THREATS_OPTIONS,
    EMPTY_ERROR_MESSAGE,
    TYPE_ERROR_MESSAGE,
    INVALID_VALUE_ERROR_MESSAGE,
    URL_LIST_TYPE_OPTIONS,
    PROTOCOL_OPTIONS,
    USE_PUBLISHER_OPTIONS,
    MATCH_TYPE_OPTIONS,
    DUPLICATE_FILE_HASH_REQUEST,
)

plugin_provider_helper = PluginProviderHelper()
RETROHUNT_FP_SEVERITY_MAPPING = {
    "1": SeverityType.LOW,
    "2": SeverityType.MEDIUM,
    "3": SeverityType.HIGH,
}


class NetskopePlugin(PluginBase):
    """NetskopePlugin class having concrete implementation \
        for pulling and pushing threat information."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
    ):
        """Initialize."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.netskope_helper = NetskopeThreatExchangeHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def convert_epoch_to_datetime(self, epoch: float) -> datetime.datetime:
        """
        Convert an epoch timestamp to a datetime object.

        Args:
            epoch (float): The epoch timestamp to be converted.

        Returns:
            datetime.datetime: The corresponding datetime object.
        """
        try:
            return datetime.datetime.fromtimestamp(float(epoch))
        except Exception:
            return datetime.datetime.now()

    def create_indicator(
        self,
        threat_value: str,
        threat_type: IndicatorType,
        severity: SeverityType,
        timestamp: float,
        comment_str: str,
    ) -> Indicator:
        """Create the cte.models.Indicator object.

        Args:
            threat_value (str): Value of the indicator.
            threat_type (IndicatorType): Type of the indicator.
            severity (SeverityType): Severity of the indicator.
            timestamp (float): Timestamp of the indicator.
            comment_str (str): Comment of the indicator.
        Returns:
            cte.models.Indicator: Indicator object.
        """
        return Indicator(
            value=threat_value,
            type=threat_type,
            severity=severity,
            firstSeen=self.convert_epoch_to_datetime(timestamp),
            lastSeen=self.convert_epoch_to_datetime(timestamp),
            comments=comment_str,
        )

    def get_indicators_from_json(
        self, json_data: List[Dict]
    ) -> List[Indicator]:
        """Create the cte.models.Indicator object from the JSON object.

        Args:
            json_data (List[Dict]): List of indicators received from Netskope.
        Returns:
            List[Indicator]: List of Indicator objects from the dictionary.
        """
        indicator_list = []
        tenant_name = self.tenant.parameters.get("tenantName").replace(" ", "")
        tenant_url = tenant_name
        comment_str = tenant_url
        current_page_ioc_counts = {"sha256": 0, "md5": 0, "url": 0}
        for threat in json_data:
            severity = SeverityType.UNKNOWN
            if threat.get("severity", "").lower() in list(SeverityType):
                severity = SeverityType(threat.get("severity", "").lower())
            if threat.get("alert_type", "").lower() == "malware":
                comment_str = f"{comment_str} - {threat.get('object', '')}"
                if malware_name := threat.get("malware_name"):
                    comment_str = (
                        f"{comment_str}, Malware Name: {malware_name}"
                    )
                if malware_type := threat.get("malware_type"):
                    comment_str = (
                        f"{comment_str}, Malware Type: {malware_type}"
                    )
                # Check for MD5 in configuration
                if "MD5" in self.configuration.get(
                    "threat_data_type", ["MD5"]
                ):
                    local_md5 = threat.get("local_md5")
                    md5 = threat.get("md5")

                    # Check if local_md5 matches md5 also they should
                    # have some value
                    if local_md5 == md5 and md5:
                        # Increment the count and create an indicator
                        # for md5
                        current_page_ioc_counts["md5"] += 1
                        indicator_list.append(
                            self.create_indicator(
                                threat["md5"],
                                IndicatorType.MD5,
                                severity,
                                threat.get("timestamp"),
                                comment_str,
                            )
                        )
                    else:
                        if local_md5:
                            # Increment the count and create an indicator
                            # for local_md5 if it is present
                            current_page_ioc_counts["md5"] += 1
                            indicator_list.append(
                                self.create_indicator(
                                    threat["local_md5"],
                                    IndicatorType.MD5,
                                    severity,
                                    threat.get("timestamp"),
                                    comment_str,
                                )
                            )
                        if md5:
                            # Increment the count and create an indicator
                            # for md5 if it is present
                            current_page_ioc_counts["md5"] += 1
                            indicator_list.append(
                                self.create_indicator(
                                    threat["md5"],
                                    IndicatorType.MD5,
                                    severity,
                                    threat.get("timestamp"),
                                    comment_str,
                                )
                            )
                # Check for SHA256 in configuration
                if "SHA256" in self.configuration.get(
                    "threat_data_type", ["SHA256"]
                ):
                    local_sha256 = threat.get("local_sha256")
                    sha256 = threat.get("sha256")

                    # Check if local_sha256 matches sha256 also they
                    # should have some value
                    if local_sha256 == sha256 and sha256:
                        # Increment the count and create an indicator
                        # for sha256
                        current_page_ioc_counts["sha256"] += 1
                        indicator_list.append(
                            self.create_indicator(
                                local_sha256,
                                IndicatorType.SHA256,
                                severity,
                                threat.get("timestamp"),
                                comment_str,
                            )
                        )
                    else:
                        if local_sha256:
                            # Increment the count and create an indicator
                            # for local_sha256 if it is present
                            current_page_ioc_counts["sha256"] += 1
                            indicator_list.append(
                                self.create_indicator(
                                    local_sha256,
                                    IndicatorType.SHA256,
                                    severity,
                                    threat.get("timestamp"),
                                    comment_str,
                                )
                            )
                        if sha256:
                            # Increment the count and create an indicator
                            # for sha256 if it is present
                            current_page_ioc_counts["sha256"] += 1
                            indicator_list.append(
                                self.create_indicator(
                                    sha256,
                                    IndicatorType.SHA256,
                                    severity,
                                    threat.get("timestamp"),
                                    comment_str,
                                )
                            )

            elif threat.get(
                "alert_type", ""
            ).lower() == "malsite" and threat.get("url", None):
                current_page_ioc_counts["url"] += 1
                malsite_category = ", ".join(
                    threat.get("malsite_category", [])
                )
                comment_str = f"{comment_str} - {malsite_category}"
                indicator_list.append(
                    self.create_indicator(
                        threat["url"],
                        IndicatorType.URL,
                        severity,
                        threat.get("timestamp"),
                        comment_str,
                    )
                )
            comment_str = tenant_url
        self.logger.debug(
            f"{self.log_prefix}: Pull stat: SHA256:"
            f" {current_page_ioc_counts.get('sha256')}, MD5:"
            f" {current_page_ioc_counts.get('md5')}, URL:"
            f" {current_page_ioc_counts.get('url')}, "
            f" were fetched."
        )
        return indicator_list

    def _is_valid_domain_or_ip(self, indicator_value: str) -> bool:
        """Check if a given string is a valid domain or IP address.

        Args:
            indicator_value (str): The string to be checked.
        Returns:
            bool: True if the string is a valid domain or IP address, \
                False otherwise.
        """
        # Regular expression for a valid domain or IP address
        domain_or_ip_regex = re.compile(REGEX_HOST)

        # Check if the input string matches the domain or IP regex
        return bool(domain_or_ip_regex.match(indicator_value))

    def _extract_indicator_values(self, items: List) -> List[str]:
        """Extract indicator values from mixed data types.

        Args:
            items (List): List that may contain Indicator objects or
                string values

        Returns:
            List[str]: List of indicator values as strings
        """
        result = []
        for item in items:
            if isinstance(item, Indicator):
                result.append(item.value)
            else:
                # Assume it's already a string value
                result.append(item)
        return result

    def _create_indicator_batch(
        self,
        indicators: List[Indicator],
        indicator_types: List[IndicatorType],
        max_len: int = None,
    ) -> (List[str], List[str], List[str], int, List[Indicator]):
        """
        Generate a batch of indicators from a list of indicators \
            based on specified criteria.

        Parameters:
            indicators (List[Indicator]): A list of Indicator objects
            representing the indicators to be included in the batch.
            indicator_types (List[IndicatorType]): A list of IndicatorType
            objects representing the types of indicators to be included in the
            batch.
            max_len (int, optional): The maximum number of strings to include
            in the batch. Defaults to ... (ellipsis).
            max_size (int, optional): The maximum size of the batch in
            characters. Defaults to ... (ellipsis).

        Returns:
            List[str]: A list of strings representing the indicators included
            in the batch.
            List[str]: A list of strings representing the tags included
            in the batch.
            List[str]: A list of strings representing the indicators skipped
            due to being invalid.
            List[str]: A list of strings representing the indicators skipped
            due to being invalid.
            int: The total count of indicators.
            List[Indicator]: The list of indicators that were not shared.
        """
        out = []
        tags = []
        skip_invalid_host = []
        skip_invalid_type = []
        skip_ipv6 = []
        total_count = 0
        for indicator in indicators:
            total_count += 1
            # skip indicators of other types
            indicator_value = indicator.value
            if indicator.type not in indicator_types:
                skip_invalid_type.append(indicator_value)
                continue
            if not self._is_valid_domain_or_ip(indicator_value):
                if self.netskope_helper.is_valid_ipv6(indicator_value):
                    skip_ipv6.append(indicator_value)
                    continue
                skip_invalid_host.append(indicator_value)
                continue
            out.append(indicator_value)
            tags.extend(indicator.tags)
            if max_len and len(out) >= max_len:
                break
        remaining_indicators = list(indicators)
        total_count = len(remaining_indicators) + total_count
        unshared_indicators = remaining_indicators + skip_invalid_type

        return (
            out,
            tags,
            skip_invalid_host,
            skip_ipv6,
            total_count,
            unshared_indicators,
        )

    def make_batch(
        self,
        indicators: List[Indicator],
        indicator_types: List[IndicatorType],
        max_len: int = ...,
        max_size: int = ...,
    ) -> Tuple[List[str], List[str], List[str], int, List[Indicator]]:
        """
        Generate a batch of indicators from a list of indicators \
            based on specified criteria.

        Parameters:
            indicators (List[Indicator]): A list of Indicator objects
            representing the indicators to be included in the batch.
            indicator_types (List[IndicatorType]): A list of IndicatorType
            objects representing the types of indicators to be included in the
            batch.
            max_len (int, optional): The maximum number of strings to include
            in the batch. Defaults to ... (ellipsis).
            max_size (int, optional): The maximum size of the batch in
            characters. Defaults to ... (ellipsis).

        Returns:
            List[str]: A list of strings representing the indicators included
            in the batch.
            List[str]: The list of indicators of the specified types that were
            skipped due to being invalid.
            int: The count of indicators of the specified types that were
            skipped due to exceeding the maximum size.
            int: The total count of indicators.
            List[Indicator]: The list of indicators that were not shared.
        """
        out = []
        # Start with the size of the JSON structure that will wrap the URLs
        current_size = 0
        skip_count_invalid = []
        indicators = list(indicators)
        total_indicators = len(indicators)
        remaining_valid_count = 0
        unshared_indicators = []

        # Calculate the initial count of indicators of the specified types
        initial_type_count = sum(
            1 for indicator in indicators if indicator.type in indicator_types
        )
        for i, indicator in enumerate(indicators):
            # skip indicators of other types
            if indicator.type not in indicator_types:
                skip_count_invalid.append(indicator.value)
                continue

            # Add 2 for quotes and 1 for comma if not the first item
            url_size = len(json.dumps(indicator.value)) + (3 if out else 4)

            # Check if adding this URL would exceed our limits
            if (len(out) >= max_len) or (current_size + url_size > max_size):
                remaining_valid_count = initial_type_count - len(out)
                unshared_indicators = indicators[i:]
                break

            out.append(indicator.value)
            current_size += url_size

        return (
            out,
            skip_count_invalid,
            remaining_valid_count,
            total_indicators,
            unshared_indicators,
        )

    @staticmethod
    def _create_tags(utils, tag_name):
        """Create custom tag if it does not already exist.

        Args:
            utils (TagUtils): Object of class TagUtils for tag operations.
            tag_name (str): Name of the tag to create.
        """
        if not utils.exists(tag_name):
            utils.create_tag(TagIn(name=tag_name, color="#ED3347"))

    def get_publishers(self) -> Dict:
        """Retrieve a dictionary of publishers from Netskope.

        Returns:
            Dict: Dictionary with publisher names as keys and IDs
                as values.
        """
        dict_publishers = {}
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        logger_msg = "fetching publishers"
        params = {
            "fields": "publisher_id,publisher_name"
        }
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        try:
            publishers_json = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_PUBLISHER"].format(tenant_name),
                method="get",
                params=params,
                error_codes=["CTE_1047", "CTE_1048"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            existing_publishers = publishers_json.get("data", {}).get(
                "publishers", []
            )
            # Private app from netskope.
            for x in existing_publishers:
                dict_publishers[x["publisher_name"]] = x["publisher_id"]
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)
        return dict_publishers

    def get_private_apps(self) -> Dict:
        """Retrieve private apps from Netskope.

        Returns:
            Dict: Dictionary with app names as keys and app IDs
                as values.
        """
        dict_of_private_apps = {}
        tenant_name = self.tenant.parameters.get("tenantName").strip()

        logger_msg = "checking private apps"
        params = {"fields": "app_id,app_name"}  # we need only 2 fields
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        try:
            private_app_netskope_json = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_PRIVATE_APP"].format(tenant_name),
                method="get",
                params=params,
                error_codes=["CTE_1040", "CTE_1041"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy
            )

            existing_private_apps = private_app_netskope_json.get(
                "data", {}
            ).get("private_apps", [])
            # Private app from netskope.
            for x in existing_private_apps:
                dict_of_private_apps[x["app_name"]] = x["app_id"]
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)
        return dict_of_private_apps

    def get_url_lists(
        self,
        data_required: bool = False,
        is_retraction: bool = False
    ) -> Dict:
        """Retrieve URL lists from Netskope.

        Args:
            data_required: Whether to fetch URL list data
            is_retraction: Whether this is a retraction operation

        Returns:
            Dict: Dictionary with list names as keys and list IDs
                as values.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        dict_of_urls = {}
        tenant_name = self.tenant.parameters.get("tenantName").strip()

        logger_msg = "checking url list"
        params = {"field": "id,name"}  # we need only 2 fields
        if data_required:
            params["field"] = "id,name,data"
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        try:
            urllist_netskope_json = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_URL_LIST"].format(tenant_name),
                method="get",
                params=params,
                error_codes=["CTE_1016", "CTE_1026"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            for x in urllist_netskope_json:
                if data_required:
                    dict_of_urls[x["name"]] = x
                else:
                    dict_of_urls[x["name"]] = x["id"]
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)
        return dict_of_urls

    def _get_destination_profiles(
        self,
        is_values_required: bool = False,
        is_retraction: bool = False
    ) -> Dict:
        """Fetch destination profiles from Netskope.

        Args:
            is_values_required: If True, include profile values.
            is_retraction: If True, add Retraction in logger.

        Returns:
            Dict: Mapping of profile name to profile metadata (id, type).
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        tenant_name = self.tenant.parameters.get("tenantName").strip()
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        profiles = {}
        offset = 0
        limit = 100
        total_count = 1
        logger_msg = "fetching destination profiles"
        try:
            while offset < total_count:
                params = {
                    "fields": (
                        "id,name,type,values_count" +
                        (",values" if is_values_required else "")
                    ),
                    "offset": offset,
                    "limit": limit,
                }
                response_json = self.netskope_helper.api_helper(
                    logger_msg=logger_msg,
                    url=URLS["V2_DESTINATION_PROFILE"].format(tenant_name),
                    method="get",
                    params=params,
                    error_codes=["CTE_1055", "CTE_1056"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy
                )
                elements = response_json.get("elements", [])
                total_count = response_json.get("total_count", len(elements))
                for profile in elements:
                    profiles[profile.get("name", "")] = profile
                offset += limit
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)
        return profiles

    def _batch_generator(
        self,
        items: List[Indicator],
        batch_size: int = BATCH_SIZE,
        types: List = [
            IndicatorType.MD5,
            IndicatorType.SHA256,
            IndicatorType.URL,
            IndicatorType.FQDN,
            IndicatorType.DOMAIN,
            IndicatorType.HOSTNAME,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
        ],
    ) -> List:
        """Yield batches of items.

        Args:
            items (List[Indicator]): List of indicators to batch.
            batch_size (int): Size of each batch. Defaults to BATCH_SIZE.
            types (List): List of indicator types to include in batches.

        Yields:
            List: Batches of indicator values.
        """
        batch = []
        for item in items:
            if isinstance(item, Indicator):
                if item.type in types:
                    batch.append(item.value)
            else:
                batch.append(item)

            if len(batch) == batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    def _add_and_remove_tags(
        self,
        indicators: List,
        add_tag: str = None,
        remove_tag: str = None,
    ) -> int:
        """Add or remove tags from indicators.

        Args:
            indicators (List): List of indicators to tag.
            add_tag (str, optional): Tag name to add. Defaults to None.
            remove_tag (str, optional): Tag name to remove.
                Defaults to None.

        Returns:
            int: Count of indicators tagged.
        """
        tag_utils = TagUtils()
        if add_tag:
            self._create_tags(tag_utils, add_tag)
        count = 0
        for batch in self._batch_generator(indicators):
            count += len(batch)

            if remove_tag:
                tag_utils.on_indicators(
                    {
                        "value": {"$in": batch},
                    }
                ).remove(remove_tag)
            if add_tag:
                tag_utils.on_indicators(
                    {
                        "value": {"$in": batch},
                    }
                ).add(add_tag)
        return count

    def get_types_to_pull(self, data_type: str) -> List[str]:
        """Get the types of data to pull based on configuration.

        Args:
            data_type (str): The data type to pull (e.g., 'alerts').

        Returns:
            List[str]: List of sub types to pull (e.g., 'Malware',
                'malsite').
        """
        threat_types = self.configuration.get("threat_data_type", [])
        sub_types = []
        if (
            data_type == "alerts"
            and self.configuration.get("is_pull_required") == "Yes"
        ):
            if "SHA256" in threat_types or "MD5" in threat_types:
                sub_types.append("Malware")
            if "URL" in threat_types:
                sub_types.append("malsite")
        return sub_types

    def pull(self) -> List[Indicator]:
        """Pull the Threat information from Netskope Tenant.

        Returns:
            List[Indicator]: List of indicator objects \
                received from the Netskope.
        """
        (
            is_pull_required,
            threat_data_type,
            _,
            _,
            enable_retrohunt,
        ) = self.netskope_helper.get_configuration_parameters(
            self.configuration
        )
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        if is_pull_required == "Yes":
            self.logger.debug(f"{self.log_prefix}: Polling is enabled.")
            threat_type = threat_data_type
            alerts = []
            if "SHA256" in threat_type or "MD5" in threat_type:
                if self.sub_type.lower() == "malware":
                    malware = self.get_indicators_from_json(self.data)
                    if enable_retrohunt == "yes":
                        filtered_malware = self._filter_false_positive_hashes(
                            indicators=malware,
                            tenant_name=tenant_name,
                            is_retraction=False
                        )
                        skipped = len(malware) - len(filtered_malware)
                        self.logger.info(
                            f"{self.log_prefix}: {skipped} indicator(s) "
                            "skipped due to clean."
                        )
                        alerts += filtered_malware
                    else:
                        alerts += malware
            if "URL" in threat_type:
                if self.sub_type.lower() == "malsite":
                    alerts += self.get_indicators_from_json(self.data)
            self.logger.info(
                f"{self.log_prefix}: Successfully extracted "
                f" {len(alerts)} indicator(s) from "
                f"Netskope Tenant."
            )
            return alerts
        else:
            self.logger.info(
                f"{self.log_prefix}: " f"Polling is disabled, skipping."
            )
            return []

    def _extract_invalid_indicators(self, data: Dict) -> List[Indicator]:
        """Extract invalid indicators from API response.

        Args:
            data (Dict): API response containing validation errors.

        Returns:
            tuple: Tuple of (invalid_indicators, ipv6_iocs).
        """
        indicators = []
        ipv6_iocs = []
        for message in data.get("message", []):
            indicators.append(message[0])
            if self.netskope_helper.is_valid_ipv6(message[0]):
                ipv6_iocs.append(message[0])
        return indicators, ipv6_iocs

    def _push_private_app(
        self,
        indicators: List[Indicator],
        existing_private_app_name: str,
        new_private_app_name: str,
        protocol_type: List[str],
        tcp_ports: List[int],
        udp_ports: List[int],
        publishers: List[str],
        use_publisher_dns: bool,
        enable_tagging: bool,
        default_url: str,
    ) -> PushResult:
        """Push a private app to Netskope with the provided indicators, \
            app names, protocols, and publishers.

        Args:
            indicators (List[Indicator]): The list of indicators to be pushed.
            existing_private_app_name (str): The name of an existing \
                private app.
            new_private_app_name (str): The name of a new private app.
            protocol_type (List[str]): The list of protocol types.
            tcp_ports (List[int]): The list of TCP ports.
            udp_ports (List[int]): The list of UDP ports.
            publishers (List[str]): The list of publishers.
            use_publisher_dns (bool): A boolean indicating whether to \
                use the publisher DNS.
            enable_tagging (bool): A boolean indicating whether to \
                enable tagging.
            default_url (str): The default host.
        Returns:
            PushResult: An object representing the result of \
                the push operation.
        """
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        (
            indicators_to_push,
            tags_to_push,
            skip_invalid_host,
            skip_ipv6,
            total_hosts,
            unshared_indicators,
        ) = self._create_indicator_batch(
            indicators,
            [
                IndicatorType.URL,
                IndicatorType.FQDN,
                IndicatorType.DOMAIN,
                IndicatorType.HOSTNAME,
                IndicatorType.IPV4,
                IndicatorType.IPV6,
            ],
            max_len=MAX_PUSH_HOSTS,
        )

        try:
            if not indicators_to_push and total_hosts > 0:
                self.logger.info(
                    f"{self.log_prefix}: No host indicators to push. "
                    "The private app's page will remain unchanged. "
                    f"Skipped {len(skip_invalid_host)} indicators "
                    "due to being invalid hosts. "
                    f"Skipped {len(skip_ipv6)} IPv6 indicators "
                    "as IPv6 is not supported on Netskope."
                )
                return PushResult(
                    success=True, message="No host indicators to push."
                )
            self.logger.info(
                f"{self.log_prefix}: Out of {total_hosts}, attempting to "
                f"push {len(indicators_to_push)} host(s) "
                f"to Netskope. Skipping {len(skip_invalid_host)} "
                "indicators due to being invalid hosts, "
                f"Skipping {len(skip_ipv6)} IPv6 indicators as "
                "IPv6 is not supported on Netskope "
                "and the remaining indicators due to exceeding "
                f"the maximum size of {MAX_PUSH_HOSTS} or invalid types."
            )
            if existing_private_app_name == "create":
                private_app_name = f"[{new_private_app_name}]"
            else:
                private_app_name = existing_private_app_name
            existing_private_apps = self.get_private_apps()
            existing_publishers = self.get_publishers()
            protocols_list = []
            for protocol in protocol_type:
                if protocol == "TCP":
                    protocols_list.append(
                        {"type": "tcp", "ports": ",".join(tcp_ports)}
                    )
                if protocol == "UDP":
                    protocols_list.append(
                        {"type": "udp", "ports": ",".join(udp_ports)}
                    )

            publishers_list = []
            skipped_publishers = []
            for publisher in publishers:
                if publisher in existing_publishers:
                    publishers_list.append(
                        {
                            "publisher_id": existing_publishers[publisher],
                            "publisher_name": publisher,
                        }
                    )
                else:
                    skipped_publishers.append(publisher)

            if not publishers_list and skipped_publishers:
                self.logger.error(
                    f"{self.log_prefix}: Unable to find the "
                    f"provided publishers [{','.join(skipped_publishers)}]."
                )
                return PushResult(
                    success=False,
                    message=(
                        "Could not create new private app to share indicators."
                    ),
                )

            if skipped_publishers:
                self.logger.error(
                    f"{self.log_prefix}: Unable to find the "
                    f"following publishers [{','.join(skipped_publishers)}]. "
                    "Hence ignoring them while creating "
                    f"the private app '{private_app_name}'."
                )
            # Check if the private app already exists
            if private_app_name not in existing_private_apps:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: Private app '{private_app_name}' "
                    "does not exist. Creating a new private app."
                )

                if existing_private_app_name == "create":
                    app_name_to_create = new_private_app_name
                else:
                    app_name_to_create = existing_private_app_name

                data = {
                    "app_name": app_name_to_create,
                    "host": default_url,
                    "protocols": protocols_list,
                    "publishers": publishers_list,
                    "use_publisher_dns": use_publisher_dns,
                }
                logger_msg = "creating private app on the Netskope Tenant"
                headers = {
                    "Netskope-API-Token": resolve_secret(
                        self.tenant.parameters.get("v2token")
                    )
                }
                create_private_app = self.netskope_helper.api_helper(
                    logger_msg=logger_msg,
                    url=URLS["V2_PRIVATE_APP"].format(tenant_name),
                    method="post",
                    json=data,
                    error_codes=["CTE_1043", "CTE_1044"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False
                )
                if create_private_app.status_code not in [
                    200,
                    201,
                ]:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while {logger_msg}.",  # noqa
                        details=str(create_private_app.text),
                    )
                    return PushResult(
                        success=False,
                        message=(
                            "Could not create new private app "
                            "to share indicators."
                        ),
                    )

                create_private_app_json = handle_status_code(
                    create_private_app,
                    error_code="CTE_1044",
                    custom_message=f"Error occurred while {logger_msg}",
                    plugin=self.log_prefix,
                    log=True,
                )

                if create_private_app_json.get("status", "") != "success":
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred "
                            f"while {logger_msg}."
                        ),
                        details=repr(create_private_app_json),
                    )
                    return PushResult(
                        success=False,
                        message=(
                            "Could not create new private app "
                            "to share indicators."
                        ),
                    )

                existing_private_apps[
                    create_private_app_json["data"]["app_name"]
                ] = create_private_app_json["data"]["app_id"]

            # append hosts to private app
            tags = []
            for tag in tags_to_push:
                tags.append({"tag_name": tag})
            data = {
                "host": (
                    ",".join(indicators_to_push)
                    if total_hosts > 0
                    else default_url
                ),
                "tags": tags,
                "protocols": protocols_list,
                "publishers": publishers_list,
                "use_publisher_dns": use_publisher_dns,
            }
            logger_msg = (
                "adding indicators to private app on the Netskope Tenant"
            )
            headers = {
                "Netskope-API-Token": resolve_secret(
                    self.tenant.parameters.get("v2token")
                )
            }
            append_privateapp_netskope = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_PRIVATE_APP_PATCH"].format(
                    tenant_name, existing_private_apps[private_app_name]
                ),
                method="patch",
                json=data,
                error_codes=["CTE_1045", "CTE_1046"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False
            )

            if append_privateapp_netskope.status_code not in [
                200,
                201,
            ]:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while {logger_msg}.",
                    details=str(append_privateapp_netskope.text),
                )
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
                )

            patch_private_app_json = handle_status_code(
                append_privateapp_netskope,
                error_code="CTE_1046",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                log=True,
            )

            if patch_private_app_json.get("status", "") != "success":
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while {logger_msg}.",
                    details=repr(patch_private_app_json),
                )
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
                )

            invalid_indicators = skip_invalid_host
            if invalid_indicators:
                self._add_and_remove_tags(
                    invalid_indicators, add_tag="Invalid app"
                )
            self._add_and_remove_tags(
                indicators_to_push, remove_tag="Invalid app"
            )

            if enable_tagging:
                self._add_and_remove_tags(
                    indicators_to_push, remove_tag="Unshared"
                )
                count_skipped = self._add_and_remove_tags(
                    unshared_indicators, add_tag="Unshared"
                )
                if count_skipped:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped sharing of "
                        f"{count_skipped} indicator(s) due to "
                        "size limit or invalid type."
                    )

            self.logger.info(
                f"{self.log_prefix}: Successfully shared "
                f"{len(indicators_to_push)} indicator(s) "
                f"to configuration {self.plugin_name}."
            )
            if "failed_iocs" in PushResult.model_fields:
                failed_iocs = (
                    skip_ipv6 + invalid_indicators +
                    self._extract_indicator_values(unshared_indicators)
                )
                return PushResult(
                    success=True,
                    message="Successfully shared indicators.",
                    failed_iocs=failed_iocs,
                )
            return PushResult(
                success=True,
                message="Successfully shared indicators.",
            )
        except Exception as e:
            self.notifier.error(
                f"Plugin: Netskope - {tenant_name} "
                f"Exception occurred while pushing data to private app. "
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"  # noqa
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"Exception occurred while pushing data to private app.",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CTE_1021",
            )
            return PushResult(success=False, message=str(e))

    def _push_destination_profile(
        self,
        indicators: List[Indicator],
        profile_name: str,
        new_profile_description: str,
        match_type: str,
        apply_pending_changes: str,
        enable_tagging: bool,
    ) -> PushResult:
        """Push indicators to the destination profile on the Netskope Tenant.

        Args:
            indicators (List[Indicator]): List of indicators to push
            profile_name (str): Destination profile name
            new_profile_description (str): New destination profile description
            match_type (str): Destination profile match type
            apply_pending_changes (str): Apply pending changes
            enable_tagging (bool): Enable tagging

        Returns:
            PushResult: An object representing the result of
            the push operation.
        """
        tenant_name = self.tenant.parameters.get("tenantName").strip()

        allowed_types = [
            IndicatorType.URL,
            IndicatorType.IPV4,
            IndicatorType.HOSTNAME,
            IndicatorType.DOMAIN,
            IndicatorType.FQDN,
        ]
        indicators = list(indicators)
        if not indicators:
            log_msg = (
                "No indicators to share to the Destination Profile."
            )
            self.logger.info(
                f"{self.log_prefix}: {log_msg}"
            )
            return self.netskope_helper.return_push_result(
                success=True,
                message=log_msg,
                failed_iocs=[],
            )

        total_indicators = len(indicators)
        indicators_to_push = []
        skip_invalid_type = []
        ipv6_indicators = []
        invalid_format_indicators = []
        limit_exceeded_indicators = []
        existing_values = []

        # Get destination profile details
        profiles = self._get_destination_profiles(is_values_required=True)
        profile_exists = profile_name in profiles
        if (profile_dict := profiles.get(profile_name, {})):
            profile_id = profile_dict.get("id", "")
            existing_values = profile_dict.get("values", [])
            match_type = profile_dict.get("type", match_type)

        # Calculate available capacity based on limits
        max_shareable, usage_stats = (
            self.netskope_helper.calculate_destination_profile_capacity(
                profiles=profiles,
                target_profile_name=profile_name,
                match_type=match_type,
                indicators_count=len(indicators)
            )
        )

        if max_shareable == 0:
            if match_type in ["sensitive", "insensitive"]:
                if usage_stats["total_exact_available"] <= 0:
                    logger_msg = (
                        "Total Destination Profile limit reached. Cannot "
                        "have more than 300000 values in Exact type profiles "
                        "on the Netskope Tenant. Skipping sharing indicators."
                    )
                elif usage_stats["profile_available"] <= 0:
                    logger_msg = (
                        f"Destination Profile '{profile_name}' limit "
                        "reached. Cannot have more than 100000 values "
                        "in a single Exact type profile. "
                        "Skipping sharing indicators."
                    )
                else:
                    logger_msg = (
                        "Destination Profile limit reached "
                        "on the Netskope Tenant. Skipping sharing indicators."
                    )
            else:
                logger_msg = (
                    "Total Destination Profile limit reached. Cannot "
                    "have more than 1000 regex values in Regex type profiles "
                    "on the Netskope Tenant. Skipping sharing indicators."
                )

            self.logger.info(f"{self.log_prefix}: {logger_msg}")
            return self.netskope_helper.return_push_result(
                success=True,
                message=logger_msg,
                failed_iocs=[]
            )

        for indicator in indicators:
            indicator_type = indicator.type
            indicator_value = indicator.value

            if indicator_type == IndicatorType.IPV6:
                ipv6_indicators.append(indicator_value)
                continue

            if indicator_type not in allowed_types:
                skip_invalid_type.append(indicator_value)
                continue

            if len(indicators_to_push) >= max_shareable:
                limit_exceeded_indicators.append(indicator_value)
                continue

            # Validate indicators based on match type
            ioc_valid = (
                self.netskope_helper._validate_destination_profile_indicator(
                    indicator_value=indicator_value,
                    match_type=match_type
                )
            )
            if ioc_valid:
                indicators_to_push.append(indicator_value)
            else:
                invalid_format_indicators.append(indicator_value)

        limit_exceeded_count = len(limit_exceeded_indicators)
        limit_msg = ""
        if limit_exceeded_count > 0:
            if match_type in ["sensitive", "insensitive"]:
                if (
                    usage_stats["total_exact_available"] <=
                    usage_stats["profile_available"]
                ):
                    limit_msg = (
                        f" Skipping {limit_exceeded_count} indicators "
                        "due to total Destination Profile limit of "
                        "300000 values in Exact type profiles "
                        "on the Netskope Tenant has been reached."
                    )
                else:
                    limit_msg = (
                        f" Skipping {limit_exceeded_count} indicators "
                        "due to Destination Profile limit of "
                        "100000 values in a single Exact type profile "
                        "on the Netskope Tenant has been reached."
                    )
            else:
                limit_msg = (
                    f" Skipping {limit_exceeded_count} indicators "
                    "due to total Destination Profile limit of "
                    "1000 regex values in Regex type profiles "
                    "on the Netskope Tenant has been reached."
                )

        if not indicators_to_push and total_indicators > 0:
            log_msg = (
                "No indicators to share to the Destination Profile "
                "after filtering unsupported types, invalid values and "
                "destination profile limits."
            )
            self.logger.info(
                f"{self.log_prefix}: {log_msg}"
            )
            return self.netskope_helper.return_push_result(
                success=True,
                message=log_msg,
                failed_iocs=list(
                    set(
                        skip_invalid_type
                        + invalid_format_indicators
                        + ipv6_indicators
                    )
                ),
            )

        logger_msg = (
            f"Out of {total_indicators}, "
            f"attempting to push {len(indicators_to_push)} URL(s) "
            f"to the Netskope Destination Profile '{profile_name}'."
        )
        if limit_msg:
            logger_msg += limit_msg
        if skip_invalid_type:
            logger_msg += (
                f" Skipping {len(skip_invalid_type)} indicators "
                "due to being invalid URL type."
            )
        if invalid_format_indicators:
            logger_msg += (
                f" Skipping {len(invalid_format_indicators)} indicators "
                f"due to invalid values for match type '{match_type}'."
            )
        self.logger.info(f"{self.log_prefix}: {logger_msg}")

        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }

        try:
            create_result = None
            append_queue = indicators_to_push
            invalid_indicators = []
            unshared_indicators = []
            total_shared_indicators = 0

            if not profile_exists:
                create_result = self.netskope_helper.push_destination_profile_create(  # noqa
                    profile_name=profile_name,
                    description=(
                        new_profile_description or "Created from Netskope CE."
                    ),
                    match_type=match_type,
                    indicators=indicators_to_push,
                    headers=headers,
                    tenant_name=tenant_name,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                if isinstance(create_result, PushResult):
                    return create_result
                (
                    profile_id,
                    append_queue,
                    invalid_from_create,
                    ipv6_from_create,
                    shared_from_create,
                ) = create_result

                invalid_indicators.extend(invalid_from_create)
                ipv6_indicators.extend(ipv6_from_create)
                total_shared_indicators += shared_from_create
                if not profile_id:
                    profiles = self._get_destination_profiles(
                        is_values_required=True
                    )
                    profile_id = profiles.get(profile_name, {}).get("id")
                    existing_values = profiles.get(profile_name, {}).get(
                        "values", []
                    )
                if append_queue and not profile_id:
                    err_msg = (
                        "Could not find destination profile identifier to "
                        "share indicators."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return self.netskope_helper.return_push_result(
                        success=False,
                        message=err_msg,
                        failed_iocs=list(
                            set(
                                invalid_indicators +
                                ipv6_indicators +
                                skip_invalid_type
                            )
                        ),
                    )
                existing_count = len(existing_values)

            if profile_exists or append_queue:
                if not profile_id:
                    err_msg = (
                        "Could not find destination profile to share "
                        "indicators."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return self.netskope_helper.return_push_result(
                        success=False,
                        message=err_msg,
                        failed_iocs=list(
                            set(
                                invalid_indicators +
                                ipv6_indicators +
                                skip_invalid_type
                            )
                        ),
                    )
                append_result = self.netskope_helper.push_destination_profile_append(  # noqa
                    profile_id=profile_id,
                    profile_name=profile_name,
                    indicators=append_queue,
                    existing_values=existing_values,
                    headers=headers,
                    tenant_name=tenant_name,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    apply_pending_changes=apply_pending_changes,
                )
                (
                    invalid_append,
                    ipv6_append,
                    unshared_from_append,
                    shared_from_append,
                    existing_count,
                ) = append_result
                invalid_indicators.extend(invalid_append)
                ipv6_indicators.extend(ipv6_append)
                unshared_indicators.extend(unshared_from_append)
                total_shared_indicators += shared_from_append

            invalid_iocs_without_ipv6 = list(
                set(invalid_indicators) - set(ipv6_indicators)
            )

            self._add_and_remove_tags(
                indicators_to_push, remove_tag="Unshared"
            )
            self._add_and_remove_tags(
                indicators_to_push, remove_tag="Invalid host"
            )
            unshared_indicators = (
                unshared_indicators + skip_invalid_type + ipv6_indicators +
                invalid_format_indicators
            )
            if enable_tagging:
                if invalid_iocs_without_ipv6:
                    self._add_and_remove_tags(
                        invalid_iocs_without_ipv6, add_tag="Invalid host"
                    )
                count_skipped = self._add_and_remove_tags(
                    indicators=(
                        unshared_indicators + limit_exceeded_indicators
                    ),
                    add_tag="Unshared"
                )
                if count_skipped:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped sharing of "
                        f"{count_skipped} indicator(s) "
                        "due to invalid type or invalid value or "
                        "destination profile having pending changes."
                    )

            log_msg = ""
            if existing_count > 0:
                log_msg += (
                    f" Skipped sharing of {existing_count} indicator(s) "
                    "as they are already exist in destination profile."
                )
            if len(invalid_indicators) > 0:
                log_msg += (
                    f" Failed {len(invalid_indicators)} indicators "
                    "due to being invalid value."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully shared "
                f"{total_shared_indicators} indicators to "
                f"destination profile '{profile_name}'."
                f"{log_msg}"
            )

            return self.netskope_helper.return_push_result(
                success=True,
                message="Successfully shared indicators.",
                failed_iocs=list(
                    set(invalid_indicators) | set(unshared_indicators)
                ),
            )

        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Exception occurred while "
                "pushing destination profile data to Netskope.",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CTE_1061",
            )
            return PushResult(success=False, message=str(e))

    def _push_malsites(
        self,
        indicators: List[Indicator],
        list_name: str,
        list_type: str,
        max_size: int,
        default_url: str,
        enable_tagging: bool,
        is_retraction: bool = False
    ) -> PushResult:
        """
        Pushes malsite indicators to a URL list in Netskope.

        Args:
            indicators (List[Indicator]): A list of malware indicators to push.
            list_name (str): The name of the URL list.
            list_type (str): The type of the URL list.
            max_size (int): The maximum size of the URL list.
            default_url (str): The default URL to be added to the URL list.
            enable_tagging (bool): Whether to enable tagging for the URL list.
            is_retraction (bool): Whether this is a retraction operation.

        Returns:
            PushResult: An object containing the result of the push operation.

        Raises:
            Exception: If an error occurs while pushing the data to Netskope.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        tenant_name = self.tenant.parameters.get("tenantName").strip()
        (
            indicators_to_push,
            skip_count_invalid_urls,
            remaining_count,
            total_indicators,
            unshared_indicators,
        ) = self.make_batch(
            indicators,
            [
                IndicatorType.URL,
                IndicatorType.IPV4,
                IndicatorType.IPV6,
                IndicatorType.HOSTNAME,
                IndicatorType.DOMAIN,
                IndicatorType.FQDN,
            ],
            max_len=MAX_PUSH_INDICATORS,
            max_size=max_size,
        )

        try:
            if not indicators_to_push and total_indicators > 0:
                self.logger.info(
                    f"{self.log_prefix}: No valid malsite indicators to push."
                )
                return PushResult(
                    success=True, message="No malsite indicators to push."
                )
            indicators_to_push_count = len(indicators_to_push)
            if not is_retraction:
                self.logger.info(
                    f"{self.log_prefix}: Out of {total_indicators}, "
                    f"attempting to push {indicators_to_push_count} URL(s) "
                    f"to Netskope. Skipping {len(skip_count_invalid_urls)} "
                    "indicators due to being invalid URL type, "
                    f"Skipping {remaining_count} URL(s) due to exceeding "
                    f"the maximum size of {max_size // BYTES_TO_MB} MB "
                    f"or {MAX_PUSH_INDICATORS} indicators."
                )
            url_lists = self.get_url_lists(is_retraction=is_retraction)
            if list_name not in url_lists:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: URL list {list_name} does not exist. "
                    "Creating a new list."
                )
                data = {
                    "name": list_name,
                    "data": {
                        "urls": [default_url],
                        "type": list_type,
                    },
                }
                logger_msg = "creating urllist on the Netskope Tenant"
                headers = {
                    "Netskope-API-Token": resolve_secret(
                        self.tenant.parameters.get("v2token")
                    )
                }
                create_urllist = self.netskope_helper.api_helper(
                    logger_msg=logger_msg,
                    url=URLS["V2_URL_LIST"].format(tenant_name),
                    method="post",
                    json=data,
                    error_codes=["CTE_1017", "CTE_1018"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False
                )
                if create_urllist.status_code not in [
                    200,
                    201,
                ]:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while {logger_msg}.",  # noqa
                        details=str(create_urllist.text),
                    )
                    return PushResult(
                        success=False,
                        message="Could not create new URL list to share indicators.",  # noqa
                    )
            url_lists = self.get_url_lists(is_retraction=is_retraction)
            # append url to list
            data = {
                "data": {
                    "urls": (
                        indicators_to_push
                        if indicators_to_push_count > 0
                        else [default_url]
                    ),
                    "type": list_type,
                },
            }

            logger_msg = (
                "appending indicators to the URL list on the Netskope Tenant"
            )
            url_list_endpoint = URLS["V2_URL_LIST_APPEND"].format(
                tenant_name, url_lists[list_name]
            )
            if is_retraction:
                logger_msg = (
                    f"retracting indicators from the URL list '{list_name}' "
                    "on the Netskope Tenant"
                )
                url_list_endpoint = URLS["V2_URL_LIST_REPLACE"].format(
                    tenant_name, url_lists[list_name]
                )
            headers = {
                "Netskope-API-Token": resolve_secret(
                    self.tenant.parameters.get("v2token")
                )
            }
            append_urllist_netskope = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=url_list_endpoint,
                method="patch",
                json=data,
                error_codes=["CTE_1018", "CTE_1029"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False
            )
            if indicators_to_push_count == 0:
                return PushResult(
                    success=True,
                    message="Successfully shared indicators.",
                    should_run_cleanup=True,
                )
            invalid_indicators = []
            ipv6_iocs = []
            if append_urllist_netskope.status_code == 400:
                response_json = append_urllist_netskope.json()
                invalid_indicators, ipv6_iocs = (
                    self._extract_invalid_indicators(response_json)
                )
                indicators_to_push = list(
                    set(indicators_to_push) - set(invalid_indicators)
                )
                if not indicators_to_push:
                    self.logger.info(
                        f"{self.log_prefix}: No URL(s) to share "
                        "after excluding invalid URL(s)."
                    )
                    return PushResult(
                        success=True,
                        message=(
                            "No URL(s) to share after "
                            "excluding invalid URL(s)."
                        ),
                    )
                data = {
                    "data": {
                        "urls": indicators_to_push,
                        "type": list_type,
                    },
                }
                append_urllist_netskope = self.netskope_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url_list_endpoint,
                    method="patch",
                    json=data,
                    error_codes=["CTE_1029", "CTE_1030"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False
                )
                if append_urllist_netskope.status_code not in [
                    200,
                    201,
                ]:
                    return PushResult(
                        success=False,
                        message=f"Error occurred while {logger_msg}",
                    )
            elif append_urllist_netskope.status_code not in [200, 201]:
                return PushResult(
                    success=False,
                    message=f"Error occurred while {logger_msg}",
                )
            handle_status_code(
                append_urllist_netskope,
                error_code="CTE_1030",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                log=True,
            )
            invalid_iocs_without_valid_ipv6 = list(
                set(invalid_indicators) - set(ipv6_iocs)
            )
            if invalid_iocs_without_valid_ipv6:
                self._add_and_remove_tags(
                    invalid_iocs_without_valid_ipv6, add_tag="Invalid host"
                )
            if enable_tagging:
                self._add_and_remove_tags(
                    indicators_to_push, remove_tag="Unshared"
                )
            self._add_and_remove_tags(
                indicators_to_push, remove_tag="Invalid host"
            )
            if enable_tagging:
                unshared_indicators = (
                    unshared_indicators + skip_count_invalid_urls + ipv6_iocs
                )
                count_skipped = self._add_and_remove_tags(
                    unshared_indicators, add_tag="Unshared"
                )
                if count_skipped:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped sharing of "
                        f"{count_skipped} indicator(s) due to size "
                        "limit or invalid type."
                    )

            if not is_retraction:
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared "
                    f"{len(indicators_to_push)} indicators "
                    "(URL, IPv4, FQDN, hostname and domain) to "
                    f"configuration '{self.plugin_name}'. "
                    f"Failed {len(invalid_indicators)} indicators "
                    "due to being invalid value."
                )
            if "failed_iocs" in PushResult.model_fields:
                return PushResult(
                    success=True,
                    message="Successfully shared indicators.",
                    should_run_cleanup=True,
                    failed_iocs=(
                        invalid_indicators +
                        self._extract_indicator_values(unshared_indicators)
                    ),
                )
            return PushResult(
                success=True,
                message="Successfully shared indicators.",
                should_run_cleanup=True,
            )
        except Exception as e:
            self.notifier.error(
                f"Plugin: Netskope - {tenant_name} "
                f"Exception occurred while pushing data to url list. "
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"  # noqa
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"Exception occurred while pushing data to url list.",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CTE_1021",
            )
            return PushResult(success=False, message=str(e))

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to the Netskope file or URL list.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator \
                objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with \
                success flag and Push result message.
        """
        (
            _,
            _,
            _,
            enable_tagging,
            _,
        ) = self.netskope_helper.get_configuration_parameters(
            self.configuration
        )
        helper = AlertsHelper()
        if not isinstance(indicators, IndicatorGenerator):
            indicators = (i for i in indicators)
        self.tenant = helper.get_tenant_cte(self.name)
        action_value = action_dict.get("value")
        action_dict = action_dict.get("parameters")
        self.logger.debug(
            f"{self.log_prefix}: "
            f"Executing push method for Netskope plugin."
        )

        if action_value == "url":
            return self._push_malsites(
                indicators,
                list_name=(
                    action_dict.get("list")
                    if self.tenant.parameters.get("v2token")
                    and action_dict.get("list") != "create"
                    else action_dict.get("name")
                ),
                list_type=action_dict.get("url_list_type").lower(),
                max_size=action_dict.get("max_url_list_cap") * BYTES_TO_MB,
                default_url=action_dict.get("default_url", "").strip(),
                enable_tagging=enable_tagging == "yes",
            )
        elif action_value == "file":
            token = resolve_secret(self.tenant.parameters.get("token"))
            if not token:
                self.logger.error(
                    f"{self.log_prefix}: Could not share indicators to file "
                    f"hash list as V1 API token is missing."
                )
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
                )
            return self._push_malwares(
                indicators,
                list_name=action_dict.get("file_list"),
                max_size=action_dict.get("max_file_hash_cap") * BYTES_TO_MB,
                enable_tagging=enable_tagging == "yes",
                default_file_hash=action_dict.get(
                    "default_file_hash",
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # noqa
                ),
                auth_token=token,
            )
        elif action_value == "private_app":
            protocols = action_dict.get("protocol", [])
            tcp_port = action_dict.get("tcp_ports", "")
            tcp_port_list = [
                port.strip() for port in tcp_port.split(",") if port.strip()
            ]
            udp_port = action_dict.get("udp_ports", "")
            udp_port_list = [
                port.strip() for port in udp_port.split(",") if port.strip()
            ]
            use_publisher_dns = action_dict.get("use_publisher_dns", False)
            return self._push_private_app(
                indicators,
                existing_private_app_name=action_dict.get("private_app_name"),
                new_private_app_name=action_dict.get("name"),
                protocol_type=protocols,
                tcp_ports=tcp_port_list,
                udp_ports=udp_port_list,
                publishers=action_dict.get("publishers", []),
                use_publisher_dns=use_publisher_dns,
                enable_tagging=enable_tagging == "yes",
                default_url=action_dict.get("default_url", "").strip(),
            )
        elif action_value == "destination_profile":
            profile_name = action_dict.get("destination_profile_name")
            if profile_name == "create":
                profile_name = action_dict.get("new_profile_name", "").strip()

            new_profile_description = action_dict.get(
                "new_profile_description", ""
            ).strip()
            match_type = action_dict.get("profile_match_type", "insensitive")
            apply_pending_changes = action_dict.get(
                "apply_pending_changes", "No"
            )
            enable_tagging = (
                enable_tagging == "yes"
            )
            return self._push_destination_profile(
                indicators=indicators,
                profile_name=profile_name,
                new_profile_description=new_profile_description,
                match_type=match_type,
                apply_pending_changes=apply_pending_changes,
                enable_tagging=enable_tagging,
            )

    def _push_malwares(
        self,
        indicators: List[Indicator],
        list_name,
        max_size,
        enable_tagging: bool,
        default_file_hash,
        auth_token: str,
    ):
        """
        Pushes a list of malware indicators to Netskope.

        Args:
            indicators (List[Indicator]): The list of indicators to push.
            list_name (str): The name of the list to push the indicators to.
            max_size (int): The maximum size of the list in bytes.
            enable_tagging (bool): Whether to enable tagging for the list.
            default_file_hash (str): The default file hash to add to the list.
            auth_token (str): The authentication token for the Netskope API.

        Returns:
            PushResult: The result of the push operation.

        Raises:
            Exception: If an error occurs while pushing the indicators.
        """
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        (
            indicators_to_push,
            skip_count_invalid_hashes,
            remaining_count,
            total_indicators,
            unshared_indicators,
        ) = self.make_batch(
            indicators,
            [IndicatorType.MD5, IndicatorType.SHA256],
            max_len=MAX_PUSH_INDICATORS,
            max_size=max_size,
        )
        try:
            if not indicators_to_push and total_indicators > 0:
                self.logger.info(
                    f"{self.log_prefix}: No valid malware indicators to push."
                )
                return PushResult(
                    success=True, message="No malware indicators to push."
                )

            self.logger.info(
                f"{self.log_prefix}: Out of {total_indicators}, "
                f"attempting to push {len(indicators_to_push)} hash(es)"
                f"to Netskope. Skipping {len(skip_count_invalid_hashes)} "
                "indicators due to being invalid hash(es),"
                f"Skipping {remaining_count} hash(es) due to "
                f"exceeding the maximum size of {max_size // BYTES_TO_MB} MB "
                f"or {MAX_PUSH_INDICATORS} indicators."
            )
            data = {
                "name": list_name,
                "list": (
                    ",".join(indicators_to_push)
                    if len(indicators_to_push) > 0
                    else default_file_hash
                ),
                "token": auth_token,  # Authentication token
            }

            logger_msg = "pushing file hash list on the Netskope Tenant"
            file_hash_json = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V1_FILEHASH_LIST"].format(tenant_name),
                method="post",
                json=data,
                error_codes=["CTE_1035", "CTE_1036"],
                message=f"Error occurred while {logger_msg}",
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            if file_hash_json.get("status") == "error":
                file_hash_errors = str(file_hash_json.get('errors', []))
                if DUPLICATE_FILE_HASH_REQUEST in file_hash_errors:
                    self.logger.info(
                        message=(
                            f"{self.log_prefix}: File hashes are not "
                            "shared as there are no changes in file hashes "
                            f"in '{list_name}' File list name "
                            "on the Netskope Tenant."
                        ),
                    )
                    return PushResult(
                        success=True,
                        message="No changes in file hashes.",
                    )
                else:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error while pushing "
                            "file hash list to Netskope."
                        ),
                        details=str(file_hash_errors)
                    )
                    return PushResult(
                        success=False,
                        message="Could not share indicators.",
                    )
            if enable_tagging:
                self._add_and_remove_tags(
                    indicators_to_push, remove_tag="Unshared"
                )
                unshared_indicators = (
                    unshared_indicators + skip_count_invalid_hashes
                )
                count_skipped = self._add_and_remove_tags(
                    unshared_indicators, add_tag="Unshared"
                )
                if count_skipped:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped sharing of "
                        f"{count_skipped} indicator(s) due to "
                        "size limit or invalid type."
                    )
            self.logger.info(
                f"{self.log_prefix}: Successfully shared "
                f"{len(indicators_to_push)} hash(es) "
                f"to configuration {self.plugin_name}."
            )
            if "failed_iocs" in PushResult.model_fields:
                return PushResult(
                    success=True,
                    message="Successfully shared indicators.",
                    failed_iocs=self._extract_indicator_values(
                        unshared_indicators
                    ),
                )
            return PushResult(
                success=True,
                message="Successfully shared indicators.",
            )

        except Exception as e:
            self.notifier.error(
                f"Plugin: Netskope - {tenant_name} "
                f"Exception occurred while pushing data to Netskope. "
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"  # noqa
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"Exception occurred while pushing data to Netskope.",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CTE_1021",
            )
            return PushResult(success=False, message=str(e))

    def _validate_retrohunt_and_fp(
        self,
        tenant_name: str,
        token: str
    ) -> bool:
        """Validate the Retrohunt and False Positive configuration.

        Args:
            tenant_name (str): Name of the Netskope tenant.
            token (str): API v2 token.

        Returns:
            bool: True if validation successful, False otherwise.
        """
        err_msg = (
            "Error occurred while validating Retrohunt API. "
            "Check if the configured tenant has 'Advanced Threat Protection' "
            "license and 'Retrohunt API Query' flag is enabled"
        )
        data = {
            "hash": ["ffffffffffffffffffffffffffffffff"]
        }
        logger_msg = "validating Retrohunt API"
        headers = {
            "Netskope-API-Token": resolve_secret(token)
        }
        try:
            response = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_RETROHUNT_HASH_INFO"].format(tenant_name),
                method="post",
                json=data,
                error_codes=["CTE_1035", "CTE_1036"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )

            status = response.get("status", "")
            if status and status.lower() == "error":
                self.logger.error(
                    f"{self.log_prefix}: "
                    f"{err_msg}. "
                    f"Error message: {response.get('error_message')}."
                )
                return False
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)
        return True

    def _validate_parameters(
        self,
        parameter_type: Literal["configuration", "action"],
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        min_value: int = None,
        max_value: int = None,
        is_required: bool = True,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            parameter_type (Literal["configuration", "action"]): Type of
                parameter.
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            min_value (int, optional): Minimum allowed value for the
                configuration field. Defaults to None.
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that '{field_name}' field value is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that '{field_name}' field value is valid."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if allowed_values:
            allowed_values_str = ", ".join(allowed_values.values())
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_values_str
            )
            if field_type is str and field_value not in allowed_values.keys():
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        "Ensure that selected value is from the "
                        "allowed values. Allowed values are: "
                        f"{allowed_values_str}."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type == list:
                for value in field_value:
                    if value not in allowed_values.keys():
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {VALIDATION_ERROR_MSG}"
                                f"{err_msg}"
                            ),
                            resolution=(
                                "Ensure that selected values are from the "
                                "allowed values. Allowed values are: "
                                f"{allowed_values_str}."
                            )
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value < min_value
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += (
                " Valid value should be an integer "
                f"greater than {min_value} and less than {max_value}."
            )
            self.logger.error(
                f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that the {field_name} value is between "
                    f"{min_value} and {max_value}."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def validate(self, configuration, tenant_name=None):
        """Validate the Plugin configuration parameters.

        Args:
            configuration: Plugin configuration parameters.
            tenant_name: Name of the tenant.

        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object \
                with success flag and message.
        """
        (
            is_pull_required,
            threat_data_type,
            initial_range,
            enable_tagging,
            enable_retrohunt,
        ) = self.netskope_helper.get_configuration_parameters(configuration)

        # Validate Enable Polling
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=ENABLE_POLLING_OPTIONS
        ):
            return validation_result

        # Validate Types of Threat Data to Pull
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Types of Threat Data to Pull",
            field_value=threat_data_type,
            field_type=list,
            allowed_values=TYPES_OF_THREATS_OPTIONS
        ):
            return validation_result

        # Validate Initial Range (in days)
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            min_value=0,
            max_value=MAX_INITIAL_RANGE,
        ):
            return validation_result

        # Validate Enable Tagging
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=ENABLE_TAGGING_OPTIONS
        ):
            return validation_result

        # Validate Enable Retrohunt
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Retrohunt",
            field_value=enable_retrohunt,
            field_type=str,
            allowed_values=ENABLE_TAGGING_OPTIONS
        ):
            return validation_result

        types = []
        if (
            "SHA256" in threat_data_type
            or "MD5" in threat_data_type
        ):
            types.append("Malware")
        if "URL" in threat_data_type:
            types.append("malsite")

        helper = AlertsHelper()
        if not tenant_name:
            tenant_name = helper.get_tenant_cte(self.name).name
        provider = plugin_provider_helper.get_provider(
            tenant_name=tenant_name
        )
        provider.permission_check(
            {"alerts": types},
            plugin_name=self.plugin_name,
            configuration_name=self.name,
        )

        if enable_retrohunt == "yes":
            tenant_name = provider.configuration.get("tenantName").strip()
            token = provider.configuration.get("v2token")
            validation = self._validate_retrohunt_and_fp(
                tenant_name=tenant_name,
                token=token
            )
            if not validation:
                return ValidationResult(
                    success=False,
                    message=(
                        "Validation failed querying Retrohunt API "
                        "for Clean Indicators. Check if the configured "
                        "tenant has 'Advanced Threat Protection' "
                        "license and 'Retrohunt API Query' flag is enabled."
                    ),
                )

        return ValidationResult(
            success=True,
            message="Validation Successful for Netskope plugin.",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Add to URL List",
                value="url",
                patch_supported=True
            ),
            ActionWithoutParams(
                label="Add to File Hash List",
                value="file",
                patch_supported=False
            ),
            ActionWithoutParams(
                label="Add to Private App",
                value="private_app",
                patch_supported=False
            ),
            ActionWithoutParams(
                label="Add to Destination Profile",
                value="destination_profile",
                patch_supported=True
            )
        ]

    def run_action_cleanup(self):
        """Deploy URL list changes to Netskope.

        Executes the deploy API call to apply URL list changes
        on the Netskope tenant.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        # deploy the changes.
        self.logger.debug(
            f"{self.log_prefix}: Deploying URL list changes on Netskope."
        )

        logger_msg = "deploying URL list changes on the Netskope Tenant"
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        try:
            deploy_urllist = self.netskope_helper.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_URL_LIST_DEPLOY"].format(tenant_name),
                method="post",
                error_codes=["CTE_1019", "CTE_1033"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False
            )
            if deploy_urllist.status_code == 400:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred "
                        f"while {logger_msg}."
                    ),
                    details=str(deploy_urllist.json().get("message", [""])[0]),
                )
                return PushResult(
                    success=False,
                    message=(
                        "Could not deploy the URL lists "
                        "on the Netskope Tenant."
                    ),
                )
            deploy_urllist = handle_status_code(
                deploy_urllist,
                error_code="CTE_1033",
                custom_message=f"Error while {logger_msg}",
                plugin=self.log_prefix,
                log=True,
            )
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)

    def validate_port(self, port) -> bool:
        """Validate the port or port range.

        Args:
            port: Port number as int/str or port range as 'lower-upper' string

        Returns:
            bool: True if port or port range is valid, False otherwise
        """
        # Handle port range (e.g., '1000-2000')
        if isinstance(port, str) and '-' in port:
            try:
                lower, upper = port.split('-')
                lower_port = int(lower.strip())
                upper_port = int(upper.strip())
                # Check if ports are within valid range
                if not (0 <= lower_port <= 65535 and 0 <= upper_port <= 65535):
                    return False
                # Check if lower is less than upper and they are not equal
                if lower_port >= upper_port:
                    return False
                return True
            except (ValueError, AttributeError):
                return False

        # Handle single port
        try:
            port = int(port)
            return 0 <= port <= 65535
        except (ValueError, TypeError):
            return False

    def validate_action(self, action: Action):
        """Validate action parameters for Netskope plugin.

        Args:
            action (Action): Action object containing parameters
                to validate.

        Returns:
            ValidationResult: Result of the validation.
        """
        if action.value not in [
            "url", "file", "private_app", "destination_profile"
        ]:
            error_msg = (
                "Unsupported sharing target provided. "
                "Supported actions are 'Add to URL List', "
                "'Add to File Hash List', 'Add to Private App', "
                "and 'Add to Destination Profile'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                resolution=(
                    "Ensure that valid sharing target is selected "
                    "from the dropdown."
                )
            )
            return ValidationResult(
                success=False, message=error_msg
            )

        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        if action.value == "url":
            if self.tenant.parameters.get("v2token"):
                try:
                    urls = self.get_url_lists()
                except Exception as e:
                    self.logger.info(
                        message=(
                            f"{self.log_prefix}: "
                            f"Exception occurred while "
                            "validating action parameters."
                        ),
                        details=traceback.format_exc(),
                        error_code="CTE_1024",
                    )
                    return ValidationResult(success=False, message=str(e))
                list_of_urls_keys = list(urls.keys())
                list_of_urls_keys.append("create")

                list_name = action.parameters.get("list")
                new_list_name = action.parameters.get("name")

                if list_name not in list_of_urls_keys:
                    err_msg = (
                        "Invalid URL list provided. Select URL List "
                        "from the dropdown."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that the URL List is selected "
                            "from the dropdown only."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                if (
                    list_name == "create"
                    and new_list_name == ""
                ):
                    err_msg = (
                        "'Create New List' should not be empty "
                        "if Create new list is selected in List Name. "
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid New List name is provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )

                # Validate URL List Type
                url_list_type = action.parameters.get("url_list_type")
                if validation_result := self._validate_parameters(
                    parameter_type="action",
                    field_name="URL List Type",
                    field_value=url_list_type,
                    field_type=str,
                    allowed_values=URL_LIST_TYPE_OPTIONS,
                    is_required=False
                ):
                    return validation_result
            else:
                if action.parameters.get("name", "") == "":
                    err_msg = (
                        "List Name should not be empty."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid List Name is provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )

            # Validate List Size
            max_url_list_cap = action.parameters.get("max_url_list_cap")
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="List Size",
                field_value=max_url_list_cap,
                field_type=int,
                min_value=0,
                max_value=7,
            ):
                return validation_result

            # Validate Default URL
            default_url = action.parameters.get("default_url", "")
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Default URL",
                field_value=default_url,
                field_type=str,
                is_required=False
            ):
                return validation_result

            if default_url and not re.compile(REGEX_FOR_URL).match(
                default_url.strip()
            ):
                err_msg = (
                    "Invalid Default URL provided."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that valid Default URL is provided."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        elif action.value == "private_app":
            try:
                existing_private_apps = self.get_private_apps()
                existing_publishers = self.get_publishers()
            except Exception as e:
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Exception occurred while validating action parameters.",
                    details=traceback.format_exc(),
                    error_code="CTE_1042",
                )
                return ValidationResult(success=False, message=str(e))

            list_of_private_apps_list = list(existing_private_apps.keys())
            list_of_private_apps_list.append("create")

            private_app_name = action.parameters.get("private_app_name")
            new_app_name = action.parameters.get("name", "")
            if (
                private_app_name
                not in list_of_private_apps_list
            ):
                err_msg = (
                    "Invalid Private App provided. Select Private App "
                    "from the dropdown."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the Private App is selected "
                        "from the dropdown only."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
            if (
                private_app_name == "create"
                and new_app_name == ""
            ):
                err_msg = (
                    "'New Private App Name' should not be empty "
                    "if Create new private app is selected "
                    "in Private App Name."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that valid New Private App Name is provided."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )

            # Validate Protocol
            protocols = action.parameters.get("protocol", [])
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Protocol",
                field_value=protocols,
                field_type=list,
                allowed_values=PROTOCOL_OPTIONS,
            ):
                return validation_result

            tcp_port = action.parameters.get("tcp_ports", "")
            tcp_port_list = [
                port.strip() for port in tcp_port.split(",") if port.strip()
            ]
            udp_port = action.parameters.get("udp_ports", "")
            udp_port_list = [
                port.strip() for port in udp_port.split(",") if port.strip()
            ]

            if "TCP" in protocols:
                if not tcp_port_list:
                    err_msg = (
                        "'TCP Ports' should not be empty "
                        "if 'TCP' is selected in Protocols."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid TCP Port is provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                if not all(
                    self.validate_port(port) for port in tcp_port_list
                ):
                    err_msg = (
                        "Invalid TCP Port or Port Range provided. "
                        "Valid values are between 0 and 65535."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid TCP Port or Port Range "
                            "between 0 and 65535 provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
            if "UDP" in protocols:
                if not udp_port_list:
                    err_msg = (
                        "'UDP Ports' should not be empty "
                        "if 'UDP' is selected in Protocols."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid UDP Port is provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                if not all(
                    self.validate_port(port) for port in udp_port_list
                ):
                    err_msg = (
                        "Invalid UDP Port or Port Range provided. "
                        "Valid values are between 0 and 65535."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that valid UDP Port or Port Range "
                            "between 0 and 65535 provided."
                        )
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )

            publishers = action.parameters.get("publishers", [])
            if publishers and not all(
                publisher in existing_publishers for publisher in publishers
            ):
                err_msg = (
                    "Invalid publisher provided."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that valid publisher is selected "
                        "from the dropdown."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )

            # Validate Use Publisher DNS
            use_publisher_dns = action.parameters.get(
                "use_publisher_dns", False
            )
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Use Publisher DNS",
                field_value=use_publisher_dns,
                field_type=bool,
                allowed_values=USE_PUBLISHER_OPTIONS,
            ):
                return validation_result

            default_url = action.parameters.get("default_url", "")
            if default_url is None or not re.compile(REGEX_HOST).match(
                default_url.strip()
            ):
                err_msg = (
                    "Invalid Default Host provided."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that valid Default Host is provided."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        elif action.value == "file":
            is_v1_token = resolve_secret(self.tenant.parameters.get("token"))
            if not is_v1_token:
                err_msg = (
                    "V1 token is not provided. "
                    "Please configure V1 token under Settings > "
                    "Tenants to share file hashes."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that V1 token is configured for "
                        "Netskope Tenant."
                        "Please configure V1 token under Settings > "
                        "Tenants to share file hashes."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )

            # Validate List Name
            file_list_name = action.parameters.get("file_list", "")
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="List Name",
                field_value=file_list_name,
                field_type=str,
            ):
                return validation_result

            # Validate List Size
            max_file_hash_cap = action.parameters.get("max_file_hash_cap")
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="List Size",
                field_value=max_file_hash_cap,
                field_type=int,
                min_value=0,
                max_value=8,
            ):
                return validation_result
        elif action.value == "destination_profile":
            destination_profiles = self._get_destination_profiles()
            profile_names = list(destination_profiles.keys()) + ["create"]
            selected_profile = action.parameters.get(
                "destination_profile_name"
            )
            if selected_profile not in profile_names:
                error_msg = (
                    "Invalid Destination Profile provided. "
                    "Select Destination Profile from the dropdown."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    resolution=(
                        "Ensure that the Destination Profile "
                        "is selected from the dropdown."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )

            new_profile_name = (
                action.parameters.get("new_profile_name", "").strip()
            )
            if selected_profile == "create" and not new_profile_name:
                error_msg = (
                    "Create New Profile should not be empty if "
                    "'Create new profile' is selected in "
                    "Destination Profile."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    resolution=(
                        "Ensure that a non empty valid 'Create New Profile' "
                        "is provided."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )
            if (
                new_profile_name
                and len(new_profile_name) > MAX_PROFILE_NAME_LENGTH
            ):
                error_msg = (
                    f"Create New Profile should be less than or equal to "
                    f"{MAX_PROFILE_NAME_LENGTH} characters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    resolution=(
                        "Ensure that the Create New Profile is less than "
                        f"or equal to {MAX_PROFILE_NAME_LENGTH} characters."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )

            # Validate Profile Description
            new_profile_description = action.parameters.get(
                "new_profile_description", ""
            )
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Profile Description",
                field_value=new_profile_description,
                field_type=str,
                is_required=False
            ):
                return validation_result
            if (
                new_profile_name and new_profile_description
                and len(new_profile_description) > MAX_PROFILE_DESC_LENGTH
            ):
                error_msg = (
                    f"Profile Description should be less than or equal to "
                    f"{MAX_PROFILE_DESC_LENGTH} characters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    resolution=(
                        "Ensure that the Profile Description is less than "
                        f"or equal to {MAX_PROFILE_DESC_LENGTH} characters."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )

            # Validate Match Type
            match_type = action.parameters.get(
                "profile_match_type", "insensitive"
            )
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Match Type",
                field_value=match_type,
                field_type=str,
                allowed_values=MATCH_TYPE_OPTIONS,
                is_required=False
            ):
                return validation_result

            # Validate Apply Pending Changes
            apply_pending_changes = action.parameters.get(
                "apply_pending_changes", "No"
            )
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Apply Pending Changes",
                field_value=apply_pending_changes,
                field_type=str,
                allowed_values=ENABLE_POLLING_OPTIONS
            ):
                return validation_result

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_action_fields(self, action: Action):
        """Get action-specific fields for the given action.

        Args:
            action (Action): Action object to get fields for.

        Returns:
            List: List of field definitions for the action.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        if action.value == "url":
            if self.tenant.parameters.get("v2token"):
                urls = self.get_url_lists()
                field = [
                    {
                        "label": "List Name",
                        "key": "list",
                        "type": "choice",
                        "choices": [
                            {"key": key, "value": key}
                            for key in sorted(urls.keys())
                        ]
                        + [{"key": "Create new list", "value": "create"}],
                        "default": "",
                        "mandatory": True,
                        "description": "Select a URL list.",
                    },
                    {
                        "label": "Create New List",
                        "key": "name",
                        "type": "text",
                        "default": "",
                        "mandatory": False,
                        "description": (
                            "Create URL list with given name. "
                            "(Only Enter if you have selected "
                            "'Create new list' in List.)"
                        ),
                    },
                    {
                        "label": "URL List Type",
                        "key": "url_list_type",
                        "type": "choice",
                        "choices": [
                            {"key": "Exact", "value": "Exact"},
                            {"key": "Regex", "value": "Regex"},
                        ],
                        "default": "Exact",
                        "mandatory": False,
                        "description": (
                            "Type of URL List on Netskope where malsites "
                            "should be stored."
                        ),
                    },
                ]
            else:
                field = [
                    {
                        "label": "List Name",
                        "key": "name",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            "Update Existing URL list with given name."
                        ),
                    }
                ]

            return [
                *field,
                {
                    "label": "List Size",
                    "key": "max_url_list_cap",
                    "type": "number",
                    "default": 7,
                    "mandatory": True,
                    "description": (
                        "Size of allowed payload(In MBs) for URL list. "
                        "Maximum size of the list is 7MB."
                    ),
                },
                {
                    "label": "Default URL",
                    "key": "default_url",
                    "type": "text",
                    "default": "cedefaultpush.io",
                    "mandatory": False,
                    "description": (
                        "The default URL to be used when "
                        "the URL list is empty."
                    ),
                },
            ]
        if action.value == "file":
            return [
                {
                    "label": "List Name",
                    "key": "file_list",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The name of Existing File Hash List on Netskope "
                        "where malware file hashes should be pushed."
                    ),
                },
                {
                    "label": "List Size",
                    "key": "max_file_hash_cap",
                    "type": "number",
                    "default": 8,
                    "mandatory": True,
                    "description": (
                        "Size of allowed payload(In MBs) for File Hash List. "
                        "Maximum size of the list is 8MB."
                    ),
                },
                {
                    "label": "Default File Hash",
                    "key": "default_file_hash",
                    "type": "text",
                    "default": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # noqa
                    "mandatory": False,
                    "description": (
                        "The default MD5/SHA256 file hash to be used "
                        "when the file hash list is empty."
                    ),
                },
            ]
        if action.value == "private_app":
            existing_private_apps = self.get_private_apps()
            existing_publishers = self.get_publishers()
            field = [
                {
                    "label": "Private App Name",
                    "key": "private_app_name",
                    "type": "choice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_private_apps.keys())
                    ]
                    + [{"key": "Create new private app", "value": "create"}],
                    "default": "",
                    "mandatory": True,
                    "description": "Select a private app.",
                },
                {
                    "label": "Create New Private App",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create private app with given name. "
                        "(Only enter if you have selected "
                        "'Create new private app' in Private App Name.)"
                    ),
                },
                {
                    "label": "Protocol",
                    "key": "protocol",
                    "type": "multichoice",
                    "choices": [
                        {"key": "UDP", "value": "UDP"},
                        {"key": "TCP", "value": "TCP"},
                    ],
                    "default": ["TCP", "UDP"],
                    "mandatory": True,
                    "description": "Protocol.",
                },
                {
                    "label": "TCP Ports",
                    "key": "tcp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Comma-separated ports or port ranges for "
                        "the TCP protocol. (e.g. 443, 8080-8090)"
                        "(Only enter if you have selected 'TCP' in Protocol.)"
                    ),
                },
                {
                    "label": "UDP Ports",
                    "key": "udp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Comma-separated ports or port ranges for "
                        "the UDP protocol. (e.g. 443, 8080-8090)"
                        "(Only enter if you have selected 'UDP' in Protocol.)"
                    ),
                },
                {
                    "label": "Publisher",
                    "key": "publishers",
                    "type": "multichoice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_publishers.keys())
                    ],
                    "default": (
                        []
                        if not existing_publishers.keys()
                        else [list(existing_publishers.keys())[0]]
                    ),
                    "mandatory": False,
                    "description": "Select publishers.",
                },
                {
                    "label": "Use Publisher DNS",
                    "key": "use_publisher_dns",
                    "type": "choice",
                    "choices": [
                        {"key": "No", "value": False},
                        {"key": "Yes", "value": True},
                    ],
                    "default": False,
                    "mandatory": True,
                    "description": "Use publishers DNS.",
                },
                {
                    "label": "Default Host",
                    "key": "default_url",
                    "type": "text",
                    "default": "cedefaultpush.io",
                    "mandatory": False,
                    "description": (
                        "The default Host to be used when the "
                        "private app is empty."
                    ),
                },
            ]
            return field
        if action.value == "destination_profile":
            destination_profiles = self._get_destination_profiles()
            fields = [
                {
                    "label": "Destination Profile",
                    "key": "destination_profile_name",
                    "type": "choice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(destination_profiles.keys())
                    ]
                    + [{"key": "Create new profile", "value": "create"}],
                    "default": "",
                    "mandatory": True,
                    "description": "Select a Destination Profile list.",
                },
                {
                    "label": "Create New Profile",
                    "key": "new_profile_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create Destination Profile with given name. "
                        "(Only Enter if you have selected "
                        "'Create new profile' in Destination Profile Name) "
                        "Create New Profile should be less than or equal to "
                        f"{MAX_PROFILE_NAME_LENGTH} characters."
                    ),
                },
                {
                    "label": "Profile Description",
                    "key": "new_profile_description",
                    "type": "text",
                    "default": "Created from Netskope CE.",
                    "mandatory": False,
                    "description": (
                        "Create Destination Profile with given description. "
                        "(Only Enter if you have selected "
                        "'Create new profile' in Destination Profile Name) "
                        "Profile Description should be less than or equal to "
                        f"{MAX_PROFILE_DESC_LENGTH} characters."
                    ),
                },
                {
                    "label": "Match Type",
                    "key": "profile_match_type",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Exact (Case Insensitive)",
                            "value": "insensitive"
                        },
                        {
                            "key": "Exact (Case Sensitive)",
                            "value": "sensitive"
                        },
                        {
                            "key": "RegEx",
                            "value": "regex"
                        },
                    ],
                    "default": "insensitive",
                    "mandatory": False,
                    "description": (
                        "Match Type of New Destination Profile on Netskope "
                        "where malsites is shared."
                    ),
                },
                {
                    "label": "Apply Pending Changes",
                    "key": "apply_pending_changes",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Yes",
                            "value": "Yes"
                        },
                        {
                            "key": "No",
                            "value": "No"
                        }
                    ],
                    "default": "No",
                    "mandatory": True,
                    "description": (
                        "Apply pending changes to the provided "
                        "Destination Profile before sharing new indicators."
                    ),
                },
            ]
            return fields

    def _process_retrohunt_hash_responses(
        self,
        batch: List[Indicator],
        response: Dict,
        is_retraction: bool,
        updated_iocs: List[Indicator],
        false_positives: List[Indicator],
    ):
        """
        Process the responses from the Retrohunt API.

        Args:
            batch (List[Indicator]): List of indicators to process.
            response (Dict): Response from \
                the Retrohunt API.
            is_retraction (bool): Whether the update is a retraction.
            updated_iocs (List[Indicator]): List of updated indicators.
            false_positives (List[Indicator]): List of false positives.
        """
        for ioc in batch:
            false_positive_data = response.get(ioc.value, {})
            if not is_retraction:
                self._process_severity_update(
                    ioc, false_positive_data, updated_iocs
                )
            else:
                self._process_false_positive(
                    ioc, false_positive_data, false_positives
                )

    def _process_severity_update(
        self,
        ioc: Indicator,
        false_positive_data: Dict,
        updated_iocs: List[Indicator],
    ):
        """
        Process the severity update from the Retrohunt API.

        Args:
            ioc (Indicator): Indicator to process.
            false_positive_data (Dict): False positive data\
                from the Retrohunt API.
            updated_iocs (List[Indicator]): List of updated indicators.
        """
        verdict = false_positive_data.get("verdict", "")
        verdict_updated = false_positive_data.get("verdict_updated", "")
        if (
            (verdict_updated and verdict_updated.lower() == "clean") or
            (not verdict_updated and verdict and verdict.lower() == "clean")
        ):
            self.logger.debug(
                f"{self.log_prefix}: Skipping indicator {ioc.value} "
                "as it is clean on the Netskope tenant."
            )
            return
        severity = self._determine_severity(ioc, false_positive_data)
        if severity != ioc.severity:
            ioc.severity = severity
        updated_iocs.append(ioc)

    def _process_false_positive(
        self,
        ioc: Indicator,
        false_positive_data: Dict,
        false_positives: List[Indicator],
    ):
        """
        Process the false positive from the Retrohunt API.

        Args:
            ioc (Indicator): Indicator to process.
            false_positive_data (Dict): False positive data from \
                the Retrohunt API.
            false_positives (List[Indicator]): List of false positives.
        """
        verdict_updated = false_positive_data.get("verdict_updated", "")
        if (
            false_positive_data
            and verdict_updated
            and verdict_updated.lower() == "clean"
        ):
            self.logger.debug(
                f"{self.log_prefix}: Indicator {ioc.value} "
                "is considered as a clean, "
                "will be marked retracted."
            )
            false_positives.append(ioc.value)
        else:
            self.logger.debug(
                f"{self.log_prefix}: Indicator {ioc.value} "
                "was not present in the clean list "
                "or is still considered malicious."
            )

    def _determine_severity(
        self,
        ioc: Indicator,
        false_positive_data: Dict,
    ) -> int:
        """
        Determine the severity of the indicator.

        Args:
            ioc (Indicator): Indicator to process.
            false_positive_data (Dict): False positive data \
                from the Retrohunt API.

        Returns:
            int: Severity of the indicator.
        """
        severity_value = 0
        if false_positive_data:
            severity_value = (
                false_positive_data.get("severity_updated", 0) or
                false_positive_data.get("severity", 0)
            )

        if severity_value and severity_value > 0:
            return RETROHUNT_FP_SEVERITY_MAPPING.get(
                str(severity_value),
                ioc.severity
            )
        return ioc.severity

    def _filter_false_positive_hashes(
        self,
        indicators: List[Indicator],
        tenant_name: str,
        is_retraction: bool = False,
    ) -> List[Indicator]:
        """
        Filter out False Positive hashes using the Retrohunt API.

        Args:
            indicators (List[Indicator]): List of indicators
            tenant_name (str): Tenant name

        Returns:
            List of indicators without false positives

        Raises:
            No exception, prints error if unable to contact Retrohunt API
        """
        self.logger.debug(
            f"{self.log_prefix}: Querying Retrohunt API for "
            "checking clean hashes."
        )
        err_msg = (
            "Error occurred while querying Retrohunt API "
            "for clean hashes in batch {batch_count}. "
            "Hence, skipping this batch for "
            "fetching clean hashes"
        )
        if not is_retraction:
            err_msg = (
                "Error occurred while querying Retrohunt API "
                "for severity update in batch {batch_count}. "
                "Hence, skipping this batch for "
                "fetching updated severity"
            )
        # Filter only MD5 and SHA256 indicators
        hash_indicators = [
            ioc for ioc in indicators if ioc.type in [
                IndicatorType.MD5, IndicatorType.SHA256
            ]
        ]
        false_positives = []
        updated_iocs = []
        try:
            for i in range(0, len(hash_indicators), MAX_QUERY_INDICATORS):
                batch = hash_indicators[i:i + MAX_QUERY_INDICATORS]
                batch_count = i//MAX_QUERY_INDICATORS + 1
                data = {
                    "hash": [
                        indicator.value
                        for indicator in batch
                    ]
                }
                logger_msg = (
                    "querying Retrohunt API "
                    f"for clean hashes in batch {batch_count}"
                )
                headers = {
                    "Netskope-API-Token": resolve_secret(
                        self.tenant.parameters.get("v2token")
                    )
                }
                try:
                    response = self.netskope_helper.api_helper(
                        logger_msg=logger_msg,
                        url=URLS["V2_RETROHUNT_HASH_INFO"].format(tenant_name),
                        method="post",
                        json=data,
                        error_codes=["CTE_1035", "CTE_1036"],
                        message=err_msg.format(batch_count=batch_count),
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                    )
                except Exception:
                    self.logger.error(
                        f"{self.log_prefix}: "
                        f"{err_msg.format(batch_count=batch_count)}."
                    )
                    if not is_retraction:
                        updated_iocs.extend(batch)
                    continue
                status = response.get("status", "")
                if status and status.lower() == "error":
                    self.logger.error(
                        f"{self.log_prefix}: "
                        f"{err_msg.format(batch_count=batch_count)}. "
                        f"Error message: {response.get('error_message')}."
                    )
                    if not is_retraction:
                        updated_iocs.extend(batch)
                    continue

                self._process_retrohunt_hash_responses(
                    batch,
                    response.get("result", {}),
                    is_retraction,
                    updated_iocs,
                    false_positives
                )

            return updated_iocs if not is_retraction else false_positives
        except Exception as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while filtering "
                    f"clean hashes. Error: {str(e)}"
                ),
                details=str(traceback.format_exc())
            )
            if not is_retraction:
                return updated_iocs
            return false_positives

    def get_modified_indicators(
        self,
        source_indicators: List[List[Indicator]]
    ):
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Indicator]]): Source Indicators.

        Yields:
            tuple: Modified Indicators and Status.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        if self.configuration.get("enable_retrohunt_and_fp") == "no":
            log_msg = (
                "Retrohunt is disabled for the "
                f'configuration "{self.config_name}". '
                "Skipping retraction of IoC(s)."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True

        self.logger.info(
            f"{self.log_prefix}: Verifying clean status "
            "of Indicators on the Netskope Tenant."
        )
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        for source_ioc_list in source_indicators:
            try:
                retracted_hashes = self._filter_false_positive_hashes(
                    indicators=source_ioc_list,
                    tenant_name=tenant_name,
                    is_retraction=True,
                )
                self.logger.info(
                    f"{self.log_prefix}: {len(retracted_hashes)}"
                    " indicator(s) will be marked as retracted "
                    f"from total {len(source_ioc_list)} indicator(s)."
                )
                yield retracted_hashes, False
            except Exception as e:
                err_msg = (
                    "Error while fetching clean "
                    "hashes from the Netskope tenant."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {e}"),
                    details=traceback.format_exc(),
                )
                raise NetskopeThreatExchangeException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from Netskope Tenant.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)

        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s) "
            f"from the Netskope Tenant."
        )

        # Validate that there are indicators to retract
        if not retracted_indicators_lists:
            self.logger.info(
                f"{self.log_prefix}: No indicators to retract."
            )
            yield ValidationResult(
                success=True,
                message="No indicators to retract."
            )
            return

        url_list_actions = set()
        destination_profile_actions = set()

        for action in list_action_dict:
            action_value = action.value
            action_params = action.parameters
            if action_value == "url":
                url_list_name = action_params.get("list", "")
                url_list_type = action_params.get("url_list_type", "").lower()
                if url_list_name == "create":
                    url_list_name = action_params.get("name", "")

                if not url_list_name:
                    self.logger.info(
                        f"{self.log_prefix}: URL list name is empty, "
                        f"skipping retraction."
                    )
                    continue

                url_list_actions.add((url_list_name, url_list_type))
            elif action_value == "destination_profile":
                profile_name = action_params.get(
                    "destination_profile_name", ""
                )
                apply_pending_changes = action_params.get(
                    "apply_pending_changes", "No"
                )
                if profile_name == "create":
                    profile_name = action_params.get("new_profile_name", "")
                if not profile_name:
                    self.logger.info(
                        f"{self.log_prefix}: Profile name is empty, "
                        "skipping retraction."
                    )
                    continue
                destination_profile_actions.add(
                    (profile_name, apply_pending_changes)
                )

        try:
            if url_list_actions:
                self.logger.info(
                    f"{self.log_prefix}: Retracting indicator(s) from "
                    f"{len(url_list_actions)} URL list(s)."
                )

                self._url_list_retract_indicators(
                    url_list_names=list(url_list_actions),
                    retracted_indicators_lists=retracted_indicators_lists,
                )

                # Deploy URL list changes to Netskope
                self.run_action_cleanup()
        except Exception:
            error_msg = (
                "Error occurred while retracting "
                "indicator(s) from the URL list(s)."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_msg}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            yield ValidationResult(
                success=False,
                message=error_msg,
            )

        try:
            if destination_profile_actions:
                self.logger.info(
                    f"{self.log_prefix}: Retracting indicator(s) from "
                    f"{len(destination_profile_actions)} "
                    "destination profile(s)."
                )

                self._destination_profile_retract_indicators(
                    destination_profile_names=(
                        list(destination_profile_actions)
                    ),
                    retracted_indicators_lists=retracted_indicators_lists,
                )
        except Exception:
            error_msg = (
                "Error occurred while "
                "retracting indicator(s) from the "
                "destination profile(s)."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_msg}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            yield ValidationResult(
                success=False,
                message=error_msg,
            )

        yield ValidationResult(
            success=True,
            message=(
                "Completed execution for retraction."
            ),
        )

    def _url_list_retract_indicators(
        self,
        url_list_names: List[Tuple[str, str]],
        retracted_indicators_lists: List[List[Indicator]]
    ) -> None:
        """
        Retract indicators from URL lists.

        Args:
            url_list_names: List of URL list names and types to process
            retracted_indicators_lists: List of retracted indicators to remove
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        # Get URL lists with data for retraction
        url_lists = self.get_url_lists(
            data_required=True,
            is_retraction=True
        )

        for url_list_name, url_list_type in url_list_names:
            if url_list_name not in url_lists:
                self.logger.info(
                    f"{self.log_prefix}: URL List '{url_list_name}' "
                    "not found on the Netskope Tenant. "
                    "Hence, skip retracting indicator(s) for this list."
                )
                continue

            existing_urls = (
                url_lists.get(url_list_name, {})
                .get("data", {})
                .get("urls", [])
            )
            retraction_batch_count = 1
            for retraction_batch in retracted_indicators_lists:
                try:
                    if not retraction_batch:
                        continue

                    retracted_values = {ioc.value for ioc in retraction_batch}
                    existing_set = set(existing_urls)

                    remaining_iocs = [
                        Indicator(value=val, type=IndicatorType.URL)
                        for val in existing_set - retracted_values
                    ]

                    self.logger.info(
                        f"{self.log_prefix}: Retracting indicator(s) "
                        f"from the URL list '{url_list_name}' "
                        f"for retraction batch {retraction_batch_count}."
                    )
                    push_result = self._push_malsites(
                        indicators=remaining_iocs,
                        list_name=url_list_name,
                        list_type=url_list_type,
                        max_size=(7 * BYTES_TO_MB),
                        default_url="cedefaultpush.io",
                        enable_tagging="no",
                        is_retraction=True
                    )

                    if not push_result.success:
                        self.logger.error(
                            f"{self.log_prefix}: Unable to retract "
                            f"indicator(s) from the URL list "
                            f"'{url_list_name}' for retraction batch "
                            f"{retraction_batch_count}."
                        )
                        continue

                    self.logger.info(
                        f"{self.log_prefix}: Successfully retracted "
                        f"{len(retracted_values)} indicator(s) from "
                        f"the URL list '{url_list_name}' "
                        f"for retraction batch {retraction_batch_count}."
                    )

                    # Update existing_urls with current state after retraction
                    existing_urls = [
                        val for val in existing_urls
                        if val not in retracted_values
                    ]
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error occurred "
                            f"while retracting batch {retraction_batch_count} "
                            f"from URL list '{url_list_name}'. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                finally:
                    retraction_batch_count += 1

    def _destination_profile_retract_indicators(
        self,
        destination_profile_names: List[str],
        retracted_indicators_lists: List[List[Indicator]]
    ) -> None:
        """
        Retract indicators from destination profiles.

        Args:
            destination_profile_names: List of destination profile names
            retracted_indicators_lists: List of retracted indicators to remove
        """
        tenant_name = self.tenant.parameters.get("tenantName").strip()
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        # Get destination profiles for retraction
        profile_lists = self._get_destination_profiles(
            is_retraction=True
        )

        for profile_name, apply_pending_changes in destination_profile_names:
            if profile_name not in profile_lists:
                self.logger.info(
                    f"{self.log_prefix}: Destination Profile '{profile_name}' "
                    "not found on the Netskope Tenant. "
                    "Hence, skip retracting indicator(s) for this profile."
                )
                continue

            profile_id = profile_lists.get(profile_name, {}).get("id", "")
            retraction_batch_count = 1
            for retraction_batch in retracted_indicators_lists:
                try:
                    if not retraction_batch:
                        continue

                    retracted_iocs = [ioc.value for ioc in retraction_batch]

                    self.logger.info(
                        f"{self.log_prefix}: Retracting indicator(s) "
                        f"from the Destination Profile '{profile_name}' "
                        f"for retraction batch {retraction_batch_count}."
                    )
                    append_result = self.netskope_helper.push_destination_profile_append(  # noqa
                        profile_id=profile_id,
                        profile_name=profile_name,
                        indicators=retracted_iocs,
                        existing_values=[],
                        headers=headers,
                        tenant_name=tenant_name,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        apply_pending_changes=apply_pending_changes,
                        is_retraction=True
                    )
                    (
                        _,
                        _,
                        _,
                        shared_from_append,
                        _,
                    ) = append_result

                    if shared_from_append == 0:
                        self.logger.error(
                            f"{self.log_prefix}: Unable to retract "
                            f"indicator(s) from the Destination Profile "
                            f"'{profile_name}' for retraction batch "
                            f"{retraction_batch_count}."
                        )
                        continue

                    self.logger.info(
                        f"{self.log_prefix}: Successfully retracted "
                        f"{len(retracted_iocs)} indicator(s) from "
                        f"the Destination Profile '{profile_name}' "
                        f"for retraction batch {retraction_batch_count}."
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error occurred "
                            f"while retracting batch {retraction_batch_count} "
                            f"from Destination Profile '{profile_name}'. "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                finally:
                    retraction_batch_count += 1
