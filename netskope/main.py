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
"""

"""Netskope Plugin implementation to push and pull the data from Netskope Tenant."""

import datetime
import ipaddress
import json
import os
import re
import traceback
from typing import Dict, List, Tuple

import requests
from netskope.common.utils import (
    AlertsHelper,
    add_installation_id,
    add_user_agent,
    resolve_secret,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
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

from .utils.constants import (
    REGEX_FOR_URL,
    REGEX_HOST,
    BATCH_SIZE,
    MAX_PUSH_INDICATORS,
    MAX_PUSH_HOSTS,
    JSON_DATA_OFFSET,
    URLS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MAX_QUERY_INDICATORS,
    RETROHUNT_FP_SEVERITY_MAPPING,
    RETRACTION,
    BYTES_TO_MB,
)

plugin_provider_helper = PluginProviderHelper()

class NetskopeException(Exception):
    """Netskope exception class."""

    pass


class NetskopePlugin(PluginBase):
    """NetskopePlugin class having concrete implementation for pulling and pushing threat information."""

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

    def _is_valid_ipv6(self, address: str) -> bool:
        """Validate IPV6 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv6Address(address)
            return True
        except Exception:
            return False

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
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

    def convert_epoch_to_datetime(self, epoch) -> datetime.datetime:
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
            return datetime.now()

    def create_indicator(
        self, threat_value, threat_type, severity, timestamp, comment_str
    ):
        """Create the cte.models.Indicator object.

        Args:
            threat_value (str): Value of the indicator.
            threat_type (str): Type of the indicator.
            severity (str): Severity of the indicator.
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

    def get_indicators_from_json(self, json_data):
        """Create the cte.models.Indicator object from the JSON object.

        Args:
            json_data (dict): Indicator received from Netskope.
        Returns:
            cte.models.Indicator: Indicator object from the dictionary.
        """
        indicator_list = []
        tenant_name = self.tenant.parameters["tenantName"].replace(" ", "")
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
                if "MD5" in self.configuration.get("malware_type", ["MD5"]):
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
                    "malware_type", ["SHA256"]
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
            f" {current_page_ioc_counts['sha256']}, MD5:"
            f" {current_page_ioc_counts['md5']}, URL:"
            f" {current_page_ioc_counts['url']}, "
            f" were fetched."
        )
        return indicator_list

    def _is_valid_domain_or_ip(self, indicator_value):
        """Check if a given string is a valid domain or IP address.

        Args:
            indicator_value (str): The string to be checked.
        Returns:
            bool: True if the string is a valid domain or IP address, False otherwise.
        """
        # Regular expression for a valid domain or IP address
        domain_or_ip_regex = re.compile(REGEX_HOST)

        # Check if the input string matches the domain or IP regex
        return bool(domain_or_ip_regex.match(indicator_value))

    def _extract_indicator_values(self, items):
        """Extract indicator values from mixed data types.

        Args:
            items: List that may contain Indicator objects or string values

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
        Generate a batch of indicators from a list of indicators based on specified criteria.

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
                if self._is_valid_ipv6(indicator_value):
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
        """Create custom tag if it not already available.

        Args: utils (TagUtils obj): Object of class TagUtils. Contains all
        """
        if not utils.exists(tag_name):
            utils.create_tag(TagIn(name=tag_name, color="#ED3347"))

    def get_publishers(self) -> Dict:
        """Retrieve a dictionary of publishers.

        :return: A dictionary containing publisher names as keys and publisher IDs as values.
        :rtype: dict
        """
        dict_publishers = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, publishers_resp = handle_exception(
            self.session.get,
            error_code="CTE_1047",
            custom_message="Error occurred while fetching publishers",
            plugin=self.log_prefix,
            url=URLS["V2_PUBLISHER"].format(tenant_name),
            params={
                "fields": "publisher_id,publisher_name"
            },  # we need only 2 fields
        )
        if not success:
            raise publishers_resp
        publishers_json = handle_status_code(
            publishers_resp,
            error_code="CTE_1048",
            custom_message="Error occurred while fetching publishers",
            plugin=self.log_prefix,
            log=True,
        )

        existing_publishers = publishers_json.get("data", {}).get(
            "publishers", []
        )
        # Private app from netskope.
        for x in existing_publishers:
            dict_publishers[x["publisher_name"]] = x["publisher_id"]
        return dict_publishers

    def get_private_apps(self) -> Dict:
        """Check private app present in Netskope and create a new one if not found."""
        dict_of_private_apps = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, private_app_netskope = handle_exception(
            self.session.get,
            error_code="CTE_1040",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            url=URLS["V2_PRIVATE_APP"].format(tenant_name),
            params={"fields": "app_id,app_name"},  # we need only 2 fields
        )
        if not success:
            raise private_app_netskope
        private_app_netskope_json = handle_status_code(
            private_app_netskope,
            error_code="CTE_1041",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            log=True,
        )

        existing_private_apps = private_app_netskope_json.get("data", {}).get(
            "private_apps", []
        )
        # Private app from netskope.
        for x in existing_private_apps:
            dict_of_private_apps[x["app_name"]] = x["app_id"]
        return dict_of_private_apps

    def get_url_lists(self) -> Dict:
        """Check urllist present in Netskope and create a new one if not found."""
        dict_of_urls = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, urllist_netskope = handle_exception(
            self.session.get,
            error_code="CTE_1016",
            custom_message="Error occurred while checking urllist",
            plugin=self.log_prefix,
            url=URLS["V2_URL_LIST"].format(tenant_name),
            params={"field": "id,name"},  # we need only 2 fields
        )
        if not success:
            raise urllist_netskope
        urllist_netskope_json = handle_status_code(
            urllist_netskope,
            error_code="CTE_1026",
            custom_message="Error occurred while checking urllist",
            plugin=self.log_prefix,
            log=True,
        )
        # Urllist from netskope.
        for x in urllist_netskope_json:
            dict_of_urls[x["name"]] = x["id"]
        return dict_of_urls

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
        """Yield batches of items."""
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
        self, indicators, add_tag: str = None, remove_tag: str = None
    ) -> int:
        """Tag the indicators with the tag_name."""
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

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
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

    def pull(self):
        """Pull the Threat information from Netskope Tenant.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Netskope.
        """
        config = self.configuration
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        self.session = requests.Session()
        tenant_name = self.tenant.parameters["tenantName"].strip()
        self.session.headers.update(
            add_installation_id(
                add_user_agent(
                    {
                        "Netskope-API-Token": resolve_secret(
                            self.tenant.parameters["v2token"]
                        ),
                    }
                )
            )
        )
        if config["is_pull_required"] == "Yes":
            self.logger.debug(f"{self.log_prefix}: Polling is enabled.")
            threat_type = config["threat_data_type"]
            alerts = []
            if "SHA256" in threat_type or "MD5" in threat_type:
                if self.sub_type.lower() == "malware":
                    malware = self.get_indicators_from_json(self.data)
                    if config["enable_retrohunt_and_fp"] == "yes":
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
        """
        Extract invalid indicators from the given response.

        Args:
            data (Dict): A dictionary containing the data.

        Returns:
            List[Indicator]: A list of invalid indicators extracted from the data.
        """
        indicators = []
        ipv6_iocs = []
        for message in data.get("message", []):
            indicators.append(message[0])
            if self._is_valid_ipv6(message[0]):
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
        """Push a private app to Netskope with the provided indicators, app names, protocols, and publishers.

        Args:
            indicators (List[Indicator]): The list of indicators to be pushed.
            existing_private_app_name (str): The name of an existing private app.
            new_private_app_name (str): The name of a new private app.
            protocol_type (List[str]): The list of protocol types.
            tcp_ports (List[int]): The list of TCP ports.
            udp_ports (List[int]): The list of UDP ports.
            publishers (List[str]): The list of publishers.
            use_publisher_dns (bool): A boolean indicating whether to use the publisher DNS.
            enable_tagging (bool): A boolean indicating whether to enable tagging.
            default_url (str): The default host.
        Returns:
            PushResult: An object representing the result of the push operation.
        """
        tenant_name = self.tenant.parameters["tenantName"].strip()
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
                    f"{self.log_prefix}: No host indicators to push."
                    " The private app's page will remain unchanged."
                    f" Skipped {len(skip_invalid_host)} indicators due to being invalid hosts."
                    f" Skipped {len(skip_ipv6)} IPv6 indicators as IPv6 is not supported on Netskope."
                )
                return PushResult(
                    success=True, message="No host indicators to push."
                )
            self.logger.info(
                f"{self.log_prefix}: Out of {total_hosts}, attempting to push {len(indicators_to_push)} host(s)"
                f" to Netskope. Skipping {len(skip_invalid_host)} indicators due to being invalid hosts,"
                f" Skipping {len(skip_ipv6)} IPv6 indicators as IPv6 is not supported on Netskope"
                f" and the remaining indicators due to exceeding the maximum size of {MAX_PUSH_HOSTS} or invalid types."
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
                    f"{self.log_prefix}: Unable to find the provided publishers [{','.join(skipped_publishers)}]."
                )
                return PushResult(
                    success=False,
                    message="Could not create new private app to share indicators.",
                )

            if skipped_publishers:
                self.logger.error(
                    f"{self.log_prefix}: Unable to find the following publishers [{','.join(skipped_publishers)}]."
                    f" Hence ignoring them while creating the private app '{private_app_name}'."
                )
            # Check if the private app already exists
            if private_app_name not in existing_private_apps:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: Private app '{private_app_name}' does not exist. Creating a new private app."
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
                success, create_private_app = handle_exception(
                    self.session.post,
                    error_code="CTE_1043",
                    custom_message="Error occurred while creating private app in Netskope",
                    plugin=self.log_prefix,
                    url=URLS["V2_PRIVATE_APP"].format(tenant_name),
                    json=data,
                )
                if not success or create_private_app.status_code not in [
                    200,
                    201,
                ]:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while creating private app.",
                        details=(
                            repr(create_private_app)
                            if not success
                            else create_private_app.text
                        ),
                    )
                    return PushResult(
                        success=False,
                        message="Could not create new private app to share indicators.",
                    )

                create_private_app_json = handle_status_code(
                    create_private_app,
                    error_code="CTE_1044",
                    custom_message="Error occurred while creating private app in Netskope",
                    plugin=self.log_prefix,
                    log=True,
                )

                if create_private_app_json.get("status", "") != "success":
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while creating private app.",
                        details=repr(create_private_app_json),
                    )
                    return PushResult(
                        success=False,
                        message="Could not create new private app to share indicators.",
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
            (
                success,
                append_privateapp_netskope,
            ) = handle_exception(
                self.session.patch,
                error_code="CTE_1045",
                custom_message="Error occurred while adding indicators to private app to Netskope",
                plugin=self.log_prefix,
                url=URLS["V2_PRIVATE_APP_PATCH"].format(
                    tenant_name, existing_private_apps[private_app_name]
                ),
                json=data,
            )
            if not success or append_privateapp_netskope.status_code not in [
                200,
                201,
            ]:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while adding indicators to private app.",
                    details=repr(success),
                )
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
                )

            patch_private_app_json = handle_status_code(
                append_privateapp_netskope,
                error_code="CTE_1046",
                custom_message="Error occurred while updating private app in Netskope",
                plugin=self.log_prefix,
                log=True,
            )

            if patch_private_app_json.get("status", "") != "success":
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while adding indicators to private app.",
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
                f"{self.log_prefix}: Successfully shared {len(indicators_to_push)} indicator(s)"
                f" to configuration {self.plugin_name}."
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
                f"Exception occurred while pushing data to Netskope. "
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"
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

    def _push_malsites(
        self,
        indicators: List[Indicator],
        list_name: str,
        list_type: str,
        max_size: int,
        default_url: str,
        enable_tagging: bool,
    ) -> PushResult:
        """
        Pushes malsite indicators to a URL list in Netskope.

        Args:
            indicators (List[Indicator]): A list of malware indicators to push.
            list_name (str): The name of the URL list.
            list_type (str): The type of the URL list.
            max_size (int): The maximum size of the URL list.
            default_url (str): The default URL to be added to the URL list.

        Returns:
            PushResult: An object containing the result of the push operation.

        Raises:
            Exception: If an error occurs while pushing the data to Netskope.
        """
        tenant_name = self.tenant.parameters["tenantName"].strip()
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
            if (
                "URL" not in self.configuration["threat_data_type"]
                or not indicators_to_push
            ) and total_indicators > 0:
                return PushResult(
                    success=True, message="No malsite indicators to push."
                )
            indicators_to_push_count = len(indicators_to_push)
            self.logger.info(
                f"{self.log_prefix}: Out of {total_indicators}, attempting to push {indicators_to_push_count} URL(s)"
                f" to Netskope. Skipping {len(skip_count_invalid_urls)} indicators due to being invalid URL type,"
                f" Skipping {remaining_count} URL(s) due to exceeding the maximum size of"
                f" {max_size // BYTES_TO_MB} MB or {MAX_PUSH_INDICATORS} indicators."
            )
            url_lists = self.get_url_lists()
            if list_name not in url_lists:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: URL list {list_name} does not exist. Creating a new list."
                )
                data = {
                    "name": list_name,
                    "data": {
                        "urls": [default_url],
                        "type": list_type,
                    },
                }
                success, create_urllist = handle_exception(
                    self.session.post,
                    error_code="CTE_1017",
                    custom_message="Error occurred while creating urllist",
                    plugin=self.log_prefix,
                    url=URLS["V2_URL_LIST"].format(tenant_name),
                    json=data,
                )
                if not success or create_urllist.status_code not in [
                    200,
                    201,
                ]:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while creating urllist.",
                        details=(
                            repr(create_urllist)
                            if not success
                            else create_urllist.text
                        ),
                    )
                    return PushResult(
                        success=False,
                        message="Could not create new URL list to share indicators.",
                    )
            url_lists = self.get_url_lists()
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
            (
                success,
                append_urllist_netskope,
            ) = handle_exception(
                self.session.patch,
                error_code="CTE_1018",
                custom_message="Error occurred while appending indicators to URL list to Netskope",
                plugin=self.log_prefix,
                url=URLS["V2_URL_LIST_REPLACE"].format(
                    tenant_name, url_lists[list_name]
                ),
                json=data,
            )
            if not success:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while appending indicators to URL list.",
                    details=repr(success),
                )
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
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
                        f"{self.log_prefix}: No URL(s) to share after excluding invalid URL(s)."
                    )
                    return PushResult(
                        success=True,
                        message="No URL(s) to share after excluding invalid URL(s).",
                    )
                data = {
                    "data": {
                        "urls": indicators_to_push,
                        "type": list_type,
                    },
                }
                (
                    success,
                    append_urllist_netskope,
                ) = handle_exception(
                    self.session.patch,
                    error_code="CTE_1029",
                    custom_message="Error occurred while appending URL list to Netskope",
                    plugin=self.log_prefix,
                    url=URLS["V2_URL_LIST_REPLACE"].format(
                        tenant_name, url_lists[list_name]
                    ),
                    json=data,
                )
                if not success:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while appending "
                        f"indicators to URL list after excluding invalid indicators."
                    )
                    return PushResult(
                        success=False,
                        message="Could not share indicators.",
                    )
                if append_urllist_netskope.status_code not in [
                    200,
                    201,
                ]:
                    return PushResult(
                        success=False,
                        message="Error occurred while appending URL list to Netskope",
                    )
            elif append_urllist_netskope.status_code not in [200, 201]:
                return PushResult(
                    success=False,
                    message="Error occurred while appending URL list to Netskope",
                )
            handle_status_code(
                append_urllist_netskope,
                error_code="CTE_1030",
                custom_message="Error occurred while appending URL list to Netskope",
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
                        f"{self.log_prefix}: Skipped sharing of {count_skipped} indicator(s) due to size limit or invalid type."
                    )
            self.logger.info(
                f"{self.log_prefix}: Successfully shared {len(indicators_to_push)} indicators"
                f" (URL, IPv4, FQDN, hostname and domain) to configuration '{self.plugin_name}'."
                f" Failed {len(invalid_indicators)} indicators due to being invalid value."
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
                f"Exception occurred while pushing data to Netskope. "
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"
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

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to the Netskope file or URL list.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and Push result message.
        """
        helper = AlertsHelper()
        if not isinstance(indicators, IndicatorGenerator):
            indicators = (i for i in indicators)
        self.tenant = helper.get_tenant_cte(self.name)
        self.session = requests.Session()
        action_value = action_dict.get("value")
        action_dict = action_dict.get("parameters")
        self.logger.debug(
            f"{self.log_prefix}: "
            f"Executing push method for Netskope plugin."
        )

        if action_value == "url":
            # add v2 related auth headers
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            return self._push_malsites(
                indicators,
                list_name=(
                    action_dict.get("list")
                    if self.tenant.parameters["v2token"]
                    and action_dict.get("list") != "create"
                    else action_dict.get("name")
                ),
                list_type=action_dict.get("url_list_type").lower(),
                max_size=action_dict.get("max_url_list_cap") * BYTES_TO_MB,
                default_url=action_dict.get("default_url", "").strip(),
                enable_tagging=self.configuration.get(
                    "enable_tagging", "no"
                ).lower()
                == "yes",
            )
        elif action_value == "file":
            self.session.headers.update(
                add_installation_id(add_user_agent({}))
            )
            token = resolve_secret(self.tenant.parameters["token"])
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
                enable_tagging=self.configuration.get(
                    "enable_tagging", "no"
                ).lower()
                == "yes",
                default_file_hash=action_dict.get(
                    "default_file_hash",
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                ),
                auth_token=token,
            )
        elif action_value == "private_app":
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
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
                enable_tagging=self.configuration.get(
                    "enable_tagging", "no"
                ).lower()
                == "yes",
                default_url=action_dict.get("default_url", "").strip(),
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
        tenant_name = self.tenant.parameters["tenantName"].strip()
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
            if (
                (
                    "SHA256" not in self.configuration["threat_data_type"]
                    and "MD5" not in self.configuration["threat_data_type"]
                )
                or not indicators_to_push
            ) and total_indicators > 0:
                return PushResult(
                    success=True, message="No malware indicators to push."
                )

            self.logger.info(
                f"{self.log_prefix}: Out of {total_indicators}, attempting to push {len(indicators_to_push)} hash(es)"
                f" to Netskope. Skipping {len(skip_count_invalid_hashes)} indicators due to being invalid hash(es),"
                f" Skipping {remaining_count} hash(es) due to exceeding the maximum size of"
                f" {max_size // BYTES_TO_MB} MB or {MAX_PUSH_INDICATORS} indicators."
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
            success, response = handle_exception(
                self.session.post,
                error_code="CTE_1035",
                custom_message="Error while pushing file hash list to Netskope.",
                plugin=self.log_prefix,
                url=URLS["V1_FILEHASH_LIST"].format(tenant_name),
                json=data,
            )
            if not success:
                return PushResult(
                    success=False,
                    message="Could not share indicators.",
                )
            file_hash_json = handle_status_code(
                response,
                error_code="CTE_1036",
                custom_message="Error while pushing file hash list to Netskope. ",
                plugin=self.log_prefix,
                log=True,
            )
            if file_hash_json.get("status") == "error":
                self.logger.error(
                    f"{self.log_prefix}: Error while pushing file hash list to "
                    f"Netskope. {' '.join(file_hash_json.get('errors', []))}"
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
                        f"{self.log_prefix}: Skipped sharing of {count_skipped} indicator(s) due to size limit or invalid type."
                    )
            self.logger.info(
                f"{self.log_prefix}: Successfully shared {len(indicators_to_push)} hash(es)"
                f" to configuration {self.plugin_name}."
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
                f"{re.sub(r'token=([0-9a-zA-Z]*)', 'token=********&', str(repr(e)))}"
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

    def _validate_retrohunt_and_fp(self, tenant_name):
        """Validate the Retrohunt and False Positive configuration."""
        err_msg = (
            "Error occurred while validating Retrohunt API. "
            "Check if the configured tenant has 'Advanced Threat Protection' "
            "license and 'Retrohunt API Query' flag is enabled"
        )
        data = {
            "hash": ["ffffffffffffffffffffffffffffffff"]
        }
        success, response = handle_exception(
            self.session.post,
            error_code="CTE_1035",
            custom_message=err_msg,
            plugin=self.log_prefix,
            url=URLS["V2_RETROHUNT_HASH_INFO"].format(tenant_name),
            json=data,
        )
        if not success:
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}."
            )
            return False
        response = handle_status_code(
            response,
            error_code="CTE_1036",
            custom_message=err_msg,
            plugin=self.log_prefix,
            log=True,
        )
        status = response.get("status", "")
        if status and status.lower() == "error":
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}. "
                f"Error message: {response.get('error_message')}."
            )
            return False
        return True

    def validate(self, configuration, tenant_name=None):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Netskope Executing validate method for Netskope plugin"
        )
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > 365:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if "is_pull_required" not in configuration or configuration[
            "is_pull_required"
        ] not in [
            "Yes",
            "No",
        ]:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred for Netskope plugin "
                "Error: Type of Pulling configured should be integer.",
                error_code="CTE_1022",
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        enable_retrohunt_and_fp = configuration.get(
            "enable_retrohunt_and_fp", ""
        )
        if enable_retrohunt_and_fp not in [
            "yes",
            "no",
        ]:
            err_msg = (
                "Invalid value for 'Enable Retrohunt' "
                "provided. Allowed values are 'Yes', or 'No'."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                error_code="CTE_1022",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        THREAT_DATA_TYPES = ["SHA256", "MD5", "URL"]
        if "threat_data_type" not in configuration or any(
            t not in THREAT_DATA_TYPES
            for t in configuration["threat_data_type"]
        ):
            self.logger.error(
                f"{self.log_prefix}: Netskope Invalid value for 'Types of Threat Data to Pull' provided. "
                "Allowed values are SHA256, MD5, or URL.",
                error_code="CTE_1023",
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Types of Threat data to pull' provided. "
                "Allowed values are 'SHA256', 'MD5', or 'URL'.",
            )

        types = []
        if (
            "SHA256" in configuration["threat_data_type"]
            or "MD5" in configuration["threat_data_type"]
        ):
            types.append("Malware")
        if "URL" in configuration["threat_data_type"]:
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

        if enable_retrohunt_and_fp == "yes":
            tenant_name = provider.configuration["tenantName"].strip()
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                provider.configuration["v2token"]
                            ),
                        }
                    )
                )
            )
            validation = self._validate_retrohunt_and_fp(tenant_name)
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
            ActionWithoutParams(label="Add to URL List", value="url"),
            ActionWithoutParams(label="Add to File Hash List", value="file"),
            ActionWithoutParams(
                label="Add to Private App", value="private_app"
            ),
        ]

    def run_action_cleanup(self):
        """Run Deploy API call for URLlist to Netskope."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        tenant_name = self.tenant.parameters["tenantName"].strip()
        # deploy the changes.
        self.logger.debug(
            f"{self.log_prefix}: Deploying URL list changes on Netskope."
        )
        self.session = requests.Session()
        self.session.headers.update(
            add_installation_id(
                add_user_agent(
                    {
                        "Netskope-API-Token": resolve_secret(
                            self.tenant.parameters["v2token"]
                        ),
                    }
                )
            )
        )
        success, deploy_urllist = handle_exception(
            self.session.post,
            error_code="CTE_1019",
            custom_message="Error while deploying changes",
            plugin=self.log_prefix,
            url=URLS["V2_URL_LIST_DEPLOY"].format(tenant_name),
        )
        if not success:
            return PushResult(
                success=False,
                message="Could not deploy the URL lists on Netskope.",
            )
        if deploy_urllist.status_code == 400:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while deploying URL list changes on Netskope.",
                details=deploy_urllist.json().get("message", [""])[0],
            )
            return PushResult(
                success=False,
                message="Could not deploy the URL lists on Netskope.",
            )
        deploy_urllist = handle_status_code(
            deploy_urllist,
            error_code="CTE_1033",
            custom_message="Error while deploying changes",
            plugin=self.log_prefix,
            log=True,
        )

    def validate_port(self, port):
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
        """Validate Netskope configuration."""
        if action.value not in ["url", "file", "private_app"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        if action.value == "url":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            if self.tenant.parameters["v2token"]:
                try:
                    urls = self.get_url_lists()
                except Exception as e:
                    self.logger.info(
                        f"{self.log_prefix}: "
                        f"Exception occurred while validating action parameters.",
                        details=traceback.format_exc(),
                        error_code="CTE_1024",
                    )
                    return ValidationResult(success=False, message=str(e))
                list_of_urls_keys = list(urls.keys())
                list_of_urls_keys.append("create")
                if action.parameters.get("list") not in list_of_urls_keys:
                    return ValidationResult(
                        success=False, message="Invalid urls provided."
                    )
                if (
                    action.parameters.get("list") == "create"
                    and action.parameters.get("name", "") == ""
                ):
                    return ValidationResult(
                        success=False,
                        message="List Name should not be empty. If you choose Create new list in List. ",
                    )
                if action.parameters.get("url_list_type") not in [
                    "Regex",
                    "Exact",
                ]:
                    return ValidationResult(
                        success=False,
                        message="Invalid URL List Type provided.",
                    )
            else:
                if action.parameters.get("name", "") == "":
                    return ValidationResult(
                        success=False,
                        message="List Name should not be empty.",
                    )

            max_url_list_cap = action.parameters.get("max_url_list_cap")
            if max_url_list_cap is None or type(max_url_list_cap) not in [int, float]:
                return ValidationResult(
                    success=False, message="Invalid List Size provided."
                )
            elif max_url_list_cap <= 0 or max_url_list_cap > 7:
                return ValidationResult(
                    success=False, message="List Size should be greater than 0 and less than or equal to 7MB."
                )
            default_url = action.parameters.get("default_url", "")
            if default_url is None or not re.compile(REGEX_FOR_URL).match(
                default_url.strip()
            ):
                return ValidationResult(
                    success=False,
                    message="Invalid Default URL.",
                )
        elif action.value == "private_app":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
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
            if (
                action.parameters.get("private_app_name")
                not in list_of_private_apps_list
            ):
                return ValidationResult(
                    success=False, message="Invalid private app provided."
                )
            if (
                action.parameters.get("private_app_name") == "create"
                and action.parameters.get("name", "") == ""
            ):
                return ValidationResult(
                    success=False,
                    message="If you have selected 'Create new private app' in Private App Name,"
                    " New Private App Name should not be empty.",
                )
            protocols = action.parameters.get("protocol", [])
            if not protocols:
                return ValidationResult(
                    success=False,
                    message="Protocol is a required field.",
                )
            if not all(protocol in ["TCP", "UDP"] for protocol in protocols):
                return ValidationResult(
                    success=False,
                    message="Invalid Protocol provided. Valid values are TCP or UDP.",
                )
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
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'TCP' in Protocols, TCP Port should not be empty.",
                    )
                if not all(
                    self.validate_port(port) for port in tcp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message="Invalid TCP Port or Port Range provided. Valid values are between 0 and 65535.",
                    )
            if "UDP" in protocols:
                if not udp_port_list:
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'UDP' in Protocols, UDP Port should not be empty.",
                    )
                if not all(
                    self.validate_port(port) for port in udp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message="Invalid UDP Port or Port Range provided. Valid values are between 0 and 65535.",
                    )

            publishers = action.parameters.get("publishers", [])
            if publishers and not all(
                publisher in existing_publishers for publisher in publishers
            ):
                return ValidationResult(
                    success=False, message="Invalid publisher provided."
                )

            use_publisher_dns = action.parameters.get(
                "use_publisher_dns", False
            )
            if use_publisher_dns is None or use_publisher_dns not in [
                True,
                False,
            ]:
                return ValidationResult(
                    success=False,
                    message="Invalid Use Publisher DNS provided.",
                )

            default_url = action.parameters.get("default_url", "")
            if default_url is None or not re.compile(REGEX_HOST).match(
                default_url.strip()
            ):
                return ValidationResult(
                    success=False,
                    message="Invalid Default Host.",
                )
        elif action.value == "file":
            is_v1_token = resolve_secret(self.tenant.parameters["token"])
            if not is_v1_token:
                return ValidationResult(
                    success=False,
                    message="Please configure V1 token under Settings > Netskope Tenants to share file hashes.",
                )
            if action.parameters.get("file_list", "") == "":
                return ValidationResult(
                    success=False, message="Invalid List Name provided."
                )
            max_file_hash_cap = action.parameters.get("max_file_hash_cap")
            if max_file_hash_cap is None or type(max_file_hash_cap) not in [int, float]:
                return ValidationResult(
                    success=False, message="Invalid List Size provided."
                )
            elif max_file_hash_cap <= 0 or max_file_hash_cap > 8:
                return ValidationResult(
                    success=False, message="List Size should be greater than 0 and less than or equal to 8MB."
                )

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_cte(self.name)
        self.session = requests.Session()
        self.session.headers.update(
            add_installation_id(
                add_user_agent(
                    {
                        "Netskope-API-Token": resolve_secret(
                            self.tenant.parameters["v2token"]
                        ),
                    }
                )
            )
        )
        if action.value == "url":
            if self.tenant.parameters["v2token"]:
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
                        "The default URL to be used when the URL list is empty."
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
                    "default": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
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
        Filters out False Positive hashes using the Retrohunt API

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
                success, response = handle_exception(
                    self.session.post,
                    error_code="CTE_1035",
                    custom_message=err_msg.format(batch_count=batch_count),
                    plugin=self.log_prefix,
                    url=URLS["V2_RETROHUNT_HASH_INFO"].format(tenant_name),
                    json=data,
                )
                if not success:
                    self.logger.error(
                        f"{self.log_prefix}: "
                        f"{err_msg.format(batch_count=batch_count)}."
                    )
                    if not is_retraction:
                        updated_iocs.extend(batch)
                    continue
                response = handle_status_code(
                    response,
                    error_code="CTE_1036",
                    custom_message=err_msg.format(batch_count=batch_count),
                    plugin=self.log_prefix,
                    log=True,
                )
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
        if self.configuration["enable_retrohunt_and_fp"] == "no":
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
        self.session = requests.Session()
        tenant_name = self.tenant.parameters["tenantName"].strip()
        self.session.headers.update(
            add_installation_id(
                add_user_agent(
                    {
                        "Netskope-API-Token": resolve_secret(
                            self.tenant.parameters["v2token"]
                        ),
                    }
                )
            )
        )
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
                raise NetskopeException(err_msg)
