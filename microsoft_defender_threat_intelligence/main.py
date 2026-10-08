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

    CTE Plugin's main file which contains the implementation of all the
    plugin's methods.
"""
import json
import os
import traceback
from typing import Dict, List, Tuple
from datetime import datetime, timedelta

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    TagIn
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
from .utils import microsoft_defender_threat_intelligence_constants as constants

from .utils.microsoft_defender_threat_intelligence_helper import (
    MicrosoftDefenderThreatIntelligencePluginHelper,
    MicrosoftDefenderThreatIntelligencePluginException
)
from .utils.microsoft_defender_threat_intelligence_config_validators import (
    PluginConfigValidators,
)


class MicrosoftDefenderThreatIntelligencePlugin(PluginBase):
    """MicrosoftDefenderThreatIntelligencePlugin class having implementation all
    plugin's methods."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{constants.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.microsoft_defender_threat_intelligence_helper = (
            MicrosoftDefenderThreatIntelligencePluginHelper(
                logger=self.logger,
                log_prefix=self.log_prefix,
                configuration=self.configuration,
                plugin_name=self.plugin_name,
                plugin_version=self.plugin_version,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MicrosoftDefenderThreatIntelligencePlugin.metadata
            plugin_name = manifest_json.get("name", constants.PLUGIN_NAME)
            plugin_version = manifest_json.get("version", constants.PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (constants.PLUGIN_NAME, constants.PLUGIN_VERSION)

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the platform.
        """
        if hasattr(self, "sub_checkpoint"):
            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            return indicators

    def create_indicators(self, final_intel_product_dict):
        indicator_list = []
        skipped_tags = set()
        skipped = []
        tag_utils = TagUtils()
        for product in final_intel_product_dict:
            comment = product.get("comment", "")
            for ioc_key, ioc_json in product.get("indicators", {}).items():
                tags, skipped_type_tag = self._create_tags(
                    tag_utils,
                    ioc_json.get("tags", []),
                    self.configuration,
                )
                skipped = skipped + skipped_type_tag
                indicator_list.append(
                    Indicator(
                        value=ioc_key,  # Assuming the IOC key is the value you want to use
                        type=IndicatorType.URL,  # Assuming all IOCs are of type MD5; adjust as necessary
                        reputation=ioc_json.get("reputation"),
                        comments=comment,  # Using the comment from the product dict
                        firstSeen=ioc_json.get("first_seen"),
                        lastSeen=ioc_json.get("last_seen"),
                        tags=tags if tags else [],
                    )
                )
        skipped_tags.update(skipped)
        self.logger.debug(f"Skipped Tags: {skipped_tags}")
        return indicator_list

    def _create_tags(
        self, utils: TagUtils, tags: List[dict], configuration: dict
    ) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""

        tag_names, skipped_tags = [], []
        for tag in tags:
            try:
                if tag is not None and not utils.exists(tag.strip()):
                    tag = f"{constants.TAG_PREFIX}-{tag}"
                    utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))
            except ValueError:
                skipped_tags.append(tag)
            except Exception:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def fetch_and_normalize_reputation(self, headers, hosts_intel_profile_list):
        for host_data in hosts_intel_profile_list:
            for ioc_key in host_data["indicators"]:
                # The keys of the `Indicators` dictionary are the host IDs
                host_id = ioc_key
                reputation_endpoint = f"{constants.GRAPH_API_BASE_URL}/security/threatIntelligence/hosts/{host_id}/reputation"
                # Fetch the reputation using the API helper method
                response_data = self.microsoft_defender_threat_intelligence_helper.api_helper(
                    logger_msg=f"fetching reputation for host Id '{host_id}'",
                    url=reputation_endpoint,
                    method="get",
                    headers=headers
                )
                # Get the score and normalize it from 1-100 to 1-10
                score = response_data.get("score", 0)
                if score <= 5:
                    normalized_score = 1
                else:
                    normalized_score = round(score / 10)
                # Update the respective indicator in the dictionary with the normalized reputation score
                host_data["indicators"][ioc_key]["reputation"] = normalized_score
                host_data["indicators"][ioc_key]["tags"].append(response_data.get("classification", "unknown"))
        return hosts_intel_profile_list


    def fetch_intel_profile_ids(self, headers, checkpoint, next_link):
        """Fetch Intel Profile Ids from Microsoft Defender Threat Intelligence.

        Args:
            headers (dict): Headers for the request.
            checkpoint (datetime): Checkpoint to fetch the articles from.
            next_link (str): Next link to fetch the Profiles from.

        Returns:
            Tuple[List: List of article IDs
        """
        total_indicators = 0
        total_count_single_page = 0
        total_count_all_pages = 0
        intel_profile_url = f"{constants.GRAPH_API_BASE_URL}{constants.INTEL_PROFILE_ENDPOINT}"
        if not next_link:
            filtered_article_url = f"{intel_profile_url}?$filter=firstActiveDateTime ge {checkpoint}&$select=id,tradecraft,kind&$top=100"
        else:
            filtered_article_url = next_link
        # Loop through the pages of the API
        page = 0
        while filtered_article_url:
            current_page_profile_list = []
            page += 1
            response = self.microsoft_defender_threat_intelligence_helper.api_helper(
                logger_msg=f"fetching Intelligence Profiles for page {page}",
                url=filtered_article_url,
                method="get",
                headers=headers
            )
            current_page_intel_profile = response.get('value', [])

            # Extract IDs and add to the list
            for item in current_page_intel_profile:
                if item.get("kind", "") == "actor":
                    current_page_profile_list.append(
                        {
                            "id": item.get("id", ""),
                            "comment": item.get("tradecraft", {}).get("content", "")
                        }
                    )

            # Update counts
            total_count_single_page = len(current_page_profile_list)
            total_count_all_pages += total_count_single_page

            self.logger.info(
                f"{self.log_prefix}: Total Intelligence Profiles fetched for page {page}: "
                f"{total_count_single_page}. Total Intelligence Profiles fetched till now: {total_count_all_pages}."
            )

            # Check for the next link to handle pagination
            next_link = response.get('@odata.nextLink', '')
            if next_link:
                filtered_article_url = next_link  # Set the next URL to fetch the next page
            else:
                filtered_article_url = None  # No more pages to fetch

            # Step 2: Fetch all the Indicators(host/Ip address ids) from the Intel Profile Indicators using the article IDS
            hosts_intel_profile_list, ip_hosts_page_count = self.fetch_host_ip(
                headers,
                current_page_profile_list
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {ip_hosts_page_count} indicator(s)(IP Addresses and Host names) from {total_count_single_page} profiles fetched in page {page}."
            )
            # Step 3: Fetch all the Reputation of the Indicators from the Host Reputations
            final_intel_profile_list = self.fetch_and_normalize_reputation(
                headers,
                hosts_intel_profile_list
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched Reputation of {ip_hosts_page_count} indicator(s)."
            )
            # Step 4: Create Indicators
            indicators = self.create_indicators(final_intel_profile_list)
            total_indicators += len(indicators)
            self.logger.info(
                f"{self.log_prefix}: "
                f"Total Threat Intel Profiles fetched: {total_count_all_pages} for page {page}. "
                f"Total Indicator(s) fetched from these Threat Intel Profiles: {len(indicators)}. "
                f"Total Indicator(s) fetched till now for the current cycle: {total_indicators}."
            )
            yield indicators, None if not filtered_article_url else {"next_link": filtered_article_url}

    def fetch_host_ip(self, headers, profile_ids_list):
        """Fetch Hosts and IPs from Microsoft Defender Threat Intelligence > Intelligence Profiles Indicator."""

        # Initialize total counters for all articles
        total_host_count = 0
        total_ip_count = 0

        for profile in profile_ids_list:
            # Initialize the indicators dictionary for this profile
            indicators = {}
            total_profile_ip, total_profile_host = 0, 0
            # Construct the initial API endpoint for each intelligenceProfileId
            intel_profile_id = profile["id"]
            endpoint = f"{constants.GRAPH_API_BASE_URL}/security/threatIntelligence/intelProfiles/{intel_profile_id}/indicators"

            # Initialize page counter
            indicators_page = 0
            # Pagination loop
            while endpoint:
                indicators_page += 1
                # Initialize counters for the current page
                host_count_page = 0
                ip_count_page = 0

                # Fetch the response using the API helper method
                response_data = self.microsoft_defender_threat_intelligence_helper.api_helper(
                    logger_msg=f"fetching indicators for profile Id '{profile['id']}' - page {indicators_page}",
                    url=endpoint,
                    method="get",
                    headers=headers
                )
                # Iterate over the values in the response and extract required details
                for value in response_data.get("value", []):
                    odata_type = value.get("artifact", {}).get("@odata.type", "")
                    artifact_id = value.get("artifact", {}).get("id", "")
                    first_seen = value.get("firstSeenDateTime", "")
                    last_seen = value.get("lastSeenDateTime", "")

                    # Check if the odata.type is for a hostname and increment the host counter
                    if odata_type == "#microsoft.graph.security.hostname":
                        indicators[artifact_id] = {
                            "first_seen": first_seen,
                            "last_seen": last_seen,
                            "tags": []
                        }
                        host_count_page += 1
                        total_host_count += 1

                    # Check if the odata.type is for an IP address and increment the IP counter
                    elif odata_type == "#microsoft.graph.security.ipaddress":
                        indicators[artifact_id] = {
                            "firstSeenDateTime": first_seen,
                            "lastSeenDateTime": last_seen,
                            "tags": []
                        }
                        ip_count_page += 1
                        total_ip_count += 1

                # Output the counts for the current page
                self.logger.debug(
                    f"{self.log_prefix}: "
                    f"Statistics for fetching Indicator(s) from Intelligence "
                    f"Profile '{intel_profile_id}' -  Hosts: {host_count_page}, "
                    f"IP Address: {ip_count_page}"
                )

                # Check for the next link for pagination
                endpoint = response_data.get('@odata.nextLink', '')
                total_profile_host += host_count_page
                total_profile_ip += ip_count_page
            self.logger.info(
                f"{self.log_prefix}: "
                f"Successfully fetched {total_profile_host} Host name(s) and {total_profile_ip} IP Addresses from "
                f"Intelligence Profile '{intel_profile_id}'"
            )
            # Update the profile dictionary with the indicators
            profile["indicators"] = indicators
        # Output the total counts for all profiles
        total_iocs = total_host_count + total_ip_count
        return profile_ids_list, total_iocs

    def _pull(self):
        checkpoint = None
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        next_link = None
        sub_checkpoint_next_link = sub_checkpoint.get("next_link", "") if sub_checkpoint else ""
        if sub_checkpoint_next_link:
            next_link = sub_checkpoint_next_link
        elif not self.last_run_at:
            # Initial Run
            days = self.configuration["days"]

            checkpoint = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.logger.info(
                f"{self.log_prefix}: This is initial ran of plugin hence"
                f" pulling indicators from last {days} days."
            )
        else:
            checkpoint = self.last_run_at.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Define the headers for the request, including authorization
        token = self.microsoft_defender_threat_intelligence_helper.generate_token(
            logger_msg="Fetching article IDs"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        headers = self.microsoft_defender_threat_intelligence_helper._add_user_agent(headers)

        # Step 1: Fetch all Article IDs
        yield from self.fetch_intel_profile_ids(
            headers,
            checkpoint,
            next_link
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        plugin_config_validator = PluginConfigValidators(
            config=configuration, logger=self.logger, log_prefix=self.log_prefix
        )
        # Implementing validations for field 'tenant_id'.
        (
            validation_passed,
            validation_result,
        ) = plugin_config_validator.execute_validations(
            parent_field=None,
            field_name="tenant_id",
            validation_checks={
                "field_not_empty_check": {
                    "error_message": "Tenant ID is a required configuration parameter."
                },
                "field_value_type_check": {
                    "error_message": "Invalid Tenant ID provided in the configuration parameters.",
                    "value_type": "text"
                },
            },
        )

        if not validation_passed:
            return validation_result

        # Implementing validations for field 'client_id'.
        (
            validation_passed,
            validation_result,
        ) = plugin_config_validator.execute_validations(
            parent_field=None,
            field_name="client_id",
            validation_checks={
                "field_not_empty_check": {
                    "error_message": "Application (client) ID is a required configuration parameter."
                },
                "field_value_type_check": {
                    "error_message": "Invalid Client ID provided.",
                    "value_type": "text"
                }
            },
        )
        if not validation_passed:
            return validation_result

        # Implementing validations for field 'client_secret'.
        (
            validation_passed,
            validation_result,
        ) = plugin_config_validator.execute_validations(
            parent_field=None,
            field_name="client_secret",
            validation_checks={
                "field_not_empty_check": {
                    "error_message": "Client Secret is a required configuration parameter.",
                },
                "field_value_type_check": {
                    "error_message": "Invalid Client Secret provided in the configuration parameters.",
                    "value_type": "text"
                },
            },
        )

        if not validation_passed:
            return validation_result

        (
            validation_passed,
            validation_result,
        ) = plugin_config_validator.execute_validations(
            parent_field=None,
            field_name="days",
            validation_checks={
                "field_value_type_check": {
                    "error_message": "Invalid Initial Range (in days) provided.",
                    "value_type": "number"
                },
                "field_not_empty_check": {
                    "error_message": "Initial Range (in days) is a required configuration parameter."
                },
                "validate_range": {
                    "from": 1,
                    "to": 365,
                    "error_message": "Invalid Initial Range (in days) provided. Should be between 1 and 365."
                }
            },
        )

        if not validation_passed:
            return validation_result

        try:
            logger_msg = "generating token for validation"
            token = self.microsoft_defender_threat_intelligence_helper.generate_token(
                logger_msg, True, configuration=configuration
            )
        except MicrosoftDefenderThreatIntelligencePluginException as err:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err}"
            )
            return ValidationResult(success=False, message=str(err))
        try:
            logger_msg = "fetching indicators for validation"
            intel_profile_url = (
                f"{constants.GRAPH_API_BASE_URL}"
                f"{constants.INTEL_PROFILE_ENDPOINT}"
            )
            headers = {
                "Authorization": f"Bearer {token}"
            }
            # Add User-Agent to headers using the _add_user_agent helper function
            headers = self.microsoft_defender_threat_intelligence_helper._add_user_agent(headers)
            params = {
                "$top": 1  # To pull only one article
            }
            self.microsoft_defender_threat_intelligence_helper.api_helper(
                logger_msg=logger_msg,
                url=intel_profile_url,
                method="get",
                headers=headers,
                params=params,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_auth_token=False,
            )
            return ValidationResult(
                success=True,
                message="Validation successful."
            )
        except MicrosoftDefenderThreatIntelligencePluginException as err:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err}"
            )
            return ValidationResult(success=False, message=str(err))
