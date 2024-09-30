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

CTE CrowdStrike Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import datetime
import ipaddress
import re
import traceback
from typing import Dict, Generator, List, Tuple, Union

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.crowdstrike_constants import (
    BASE_URLS,
    BIFURCATE_INDICATOR_TYPES,
    CASE_INSENSITIVE_IOC_TYPES,
    CROWDSTRIKE_TO_INTERNAL_TYPE,
    DATE_FORMAT,
    DATE_FORMAT_FOR_IOCS,
    DEFAULT_BATCH_SIZE,
    DEFAULT_NETSKOPE_TAG,
    ENDPOINT_DETECTION,
    ENDPOINT_DETECTION_DETAILS_BATCH_SIZE,
    INTERNAL_TYPES_TO_CROWDSTRIKE,
    IOC_MANAGEMENT,
    IOC_MANAGEMENT_INDICATORS_LIMIT,
    IOC_MANAGEMENT_PULL_PAGE_LIMIT,
    IOC_MANAGEMENT_SEVERITY_MAPPING,
    IOC_SOURCE_PAGES,
    ISOLATE_REMEDIATE_BATCH_SIZE,
    MAX_INDICATOR_THRESHOLD,
    MAX_LIMIT_FOR_HOSTS,
    MODULE_NAME,
    NON_CROWDSTRIKE_DISCOVERED,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    THREAT_MAPPING,
    THREAT_TYPES,
    PREFIX_IOC_SOURCE_TAG,
)
from .utils.crowdstrike_helper import (
    CrowdstrikePluginException,
    CrowdStrikePluginHelper,
)


class CrowdStrikePlugin(PluginBase):
    """CrowdStrikePlugin class having implementation all
    plugin's methods."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """CrowdStrike plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.crowdstrike_helper = CrowdStrikePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        self.total_indicators = 0

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CrowdStrikePlugin.metadata
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

    def get_severity_from_int(self, severity: int):
        """Get severity from score.

        None (0)
        Low (10-39)
        Medium (40-69)
        High (70-89)
        Critical (90-100)
        """
        if not isinstance(severity, int) or severity == 0:
            return SeverityType.UNKNOWN
        if 10 <= severity <= 39:
            return SeverityType.LOW
        if 40 <= severity <= 69:
            return SeverityType.MEDIUM
        if 70 <= severity <= 89:
            return SeverityType.HIGH
        if 90 <= severity <= 100:
            return SeverityType.CRITICAL
        return SeverityType.UNKNOWN

    def _filter_indicators(self, indicators: List, action_dict: Dict) -> Dict:
        """Filter indicators and create payloads from it.

        Args:
            indicators (indicators): Indicators received from business rule.
            action_dict (Dict): Action parameter dictionary.
        """
        source = self.configuration.get("source", "").strip()
        if not source:
            source = PREFIX_IOC_SOURCE_TAG
        else:
            source = PREFIX_IOC_SOURCE_TAG + " | " + source
        action_params = action_dict.get("parameters", {})
        action = action_params.get("action", "").strip()
        platforms = action_params.get("platforms", ["windows", "mac", "linux"])

        generated_payload = {}
        skipped_count = 0
        total_ioc_count = 0
        action_skip_count = 0

        # Iterate on generator received from business rule.
        for indicator in indicators:
            total_ioc_count += 1
            if indicator.type in BIFURCATE_INDICATOR_TYPES and action in [
                "allow",
                "prevent_no_ui",
                "prevent",
            ]:
                # Skipping indicators having types
                # (Domain, URL, FQDN, IPv4 & IPv6) as above actions are
                # not supported for such types.
                action_skip_count += 1
                continue

            tags = indicator.tags
            expiration = indicator.expiresAt.strftime(DATE_FORMAT)
            tags.append(DEFAULT_NETSKOPE_TAG)
            if indicator.severity == SeverityType.UNKNOWN:
                indicator.severity = "informational"
            ioc_payload = {
                "source": source,
                "action": action,
                "platforms": platforms,
                "applied_globally": True,
                "severity": indicator.severity,
                "tags": tags,
                "type": INTERNAL_TYPES_TO_CROWDSTRIKE.get(indicator.type),
                "description": indicator.comments,
                "expiration": expiration,
            }
            ioc_value = indicator.value
            if indicator.type in CASE_INSENSITIVE_IOC_TYPES:
                ioc_value = ioc_value.lower()
            # If URL is there then extract host and validate it.
            if indicator.type in BIFURCATE_INDICATOR_TYPES:
                try:
                    if self._validate_domain(ioc_value):
                        ioc_type = "domain"
                    elif self._is_valid_ipv4(ioc_value):
                        ioc_type = "ipv4"
                    elif self._is_valid_ipv6(ioc_value):
                        ioc_type = "ipv6"
                    elif self._is_valid_fqdn(ioc_value):
                        ioc_type = "domain"
                    else:
                        skipped_count += 1
                        continue

                    ioc_payload.update(
                        {
                            "value": ioc_value,
                            "type": ioc_type,
                        }
                    )
                    generated_payload.update({ioc_value: ioc_payload})
                except Exception:
                    skipped_count += 1
                    continue
            else:
                # Store SHA256 and MD5 directly.
                ioc_payload["value"] = ioc_value
                generated_payload.update({ioc_value: ioc_payload})

        if skipped_count > 0:
            self.logger.info(
                f"{self.log_prefix}: {skipped_count} indicator(s) will "
                f"not shared or updated on {IOC_MANAGEMENT}, because "
                "they might have invalid domain, ipv4 or ipv6 value in it."
            )

        if action_skip_count > 0:
            err_msg = (
                f"Skipped sharing of {action_skip_count} indicator(s) "
                f"to {IOC_MANAGEMENT} as the {action} action "
                "is only applicable to hashes i.e. SHA256 and MD5."
            )
            self.logger.info(f"{self.log_prefix}: {err_msg}")

        self.logger.info(
            f"{self.log_prefix}: Successfully filtered "
            f"{len(generated_payload)} indicators out of {total_ioc_count}, "
            f"received from the business rule."
        )
        return generated_payload

    def _verify_ioc_existence(
        self, headers: Dict, indicators: Dict, action: str
    ) -> Tuple:
        """Verify existence of indicators on CrowdStrike IOC Management.

        Args:
            headers (Dict): Dictionary containing auth token.
            indicators (Dict): Indicator payloads.

        Returns:
            Tuple: List of indicators to share, List of indicators to update
        """
        base_url = self.configuration.get("base_url", "").strip()
        query_endpoint = f"{base_url}/iocs/combined/indicator/v1"  # noqa
        self.logger.debug(
            f"{self.log_prefix}: Verifying existence of indicator(s) on "
            f"{IOC_MANAGEMENT}."
        )
        push_payload, update_payload = [], []
        verification_payload = list(indicators.keys())
        total_verification_count = len(verification_payload)
        for batch in self.divide_in_chunks(
            verification_payload, IOC_MANAGEMENT_PULL_PAGE_LIMIT
        ):
            chunk_size = len(batch)
            page_push_count, page_update_count = 0, 0
            query_params = {
                "limit": IOC_MANAGEMENT_PULL_PAGE_LIMIT,
                "filter": f"value: {batch}",
            }
            self.logger.debug(
                f"{self.log_prefix}: Performing API call with {chunk_size}"
                f" indicator(s) to {IOC_MANAGEMENT} for verifying "
                f"existence of indicator(s)."
            )
            resp_json = self.crowdstrike_helper.api_helper(
                url=query_endpoint,
                method="GET",
                params=query_params,
                headers=headers,
                is_handle_error_required=True,
                logger_msg=(
                    "Verifying the existence of indicator(s)"
                    f" within {IOC_MANAGEMENT}"
                ),
                configuration=self.configuration,
            )

            resources = resp_json.get("resources", [])
            tmp_dict = {
                resource.get("value"): resource.get("id")
                for resource in resources
            }

            for value in batch:
                if value in tmp_dict:
                    indicators[value]["id"] = tmp_dict[value]
                    update_payload.append(indicators[value])
                    page_update_count += 1
                else:
                    page_push_count += 1
                    push_payload.append(indicators[value])

            self.logger.info(
                f"{self.log_prefix}: Total {len(push_payload)} indicator(s) "
                f"will be shared and {len(update_payload)} will be updated "
                f"out of {total_verification_count} since they are already "
                f"present on the {IOC_MANAGEMENT}."
            )

        self.logger.info(
            f"{self.log_prefix}: Total {len(push_payload)} indicator(s) will "
            f"be shared and {len(update_payload)} indicator(s) will be updated"
            f" within {IOC_MANAGEMENT}."
        )
        return push_payload, update_payload

    def _get_detection_detailed(
        self,
        ioc_type_counts: Dict,
        threat_types_to_pull: List[str],
        detection_ids: List[str],
        headers: Dict,
    ) -> List[Indicator]:
        """Get detailed information by Detection IDs.

        Args:
            detection_ids (List): Detection ids fetched from Endpoint
            detections.
            threat_types_to_pull (List): Threat types to pull.
            headers (dict): Header dict having Auth token as bearer header.

        Returns:
            List[cte.models.Indicators]: List of indicators fetched from
            Endpoint detection details.
        """
        base_url = self.configuration.get("base_url", "").strip()
        indicator_endpoint = f"{base_url}/detects/entities/summaries/GET/v1"
        self.logger.info(
            f"{self.log_prefix}: Pulling the details for {len(detection_ids)} "
            f"detections in the batch of "
            f"{ENDPOINT_DETECTION_DETAILS_BATCH_SIZE} from "
            f"{ENDPOINT_DETECTION}."
        )
        page_ioc_counts = {
            "sha256": 0,
            "md5": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
        }
        skip_count = 0
        indicator_list = []
        for ioc_chunks in self.divide_in_chunks(
            detection_ids, ENDPOINT_DETECTION_DETAILS_BATCH_SIZE
        ):
            json_payload = {"ids": list(ioc_chunks)}

            resp_json = self.crowdstrike_helper.api_helper(
                url=indicator_endpoint,
                method="POST",
                headers=headers,
                json=json_payload,
                logger_msg=(
                    "fetching details from detection"
                    f" id(s) from {ENDPOINT_DETECTION}"
                ),
                is_handle_error_required=True,
                configuration=self.configuration,
            )

            indicators_json_list = resp_json.get("resources", [])

            for indicator_json in indicators_json_list:
                behaviors = indicator_json.get("behaviors", [])
                detection_id = indicator_json.get("detection_id")

                for behavior_info in behaviors:
                    ioc_value = behavior_info.get("ioc_value")
                    ioc_type = behavior_info.get("ioc_type")
                    ioc_value_list = ioc_value.split(",")
                    for value in ioc_value_list:
                        try:
                            if (
                                ioc_type
                                and value
                                # Condition to check whether the ioc type is
                                # known or not
                                and ioc_type in CROWDSTRIKE_TO_INTERNAL_TYPE
                                # Condition to check whether to pull or not.
                                and ioc_type in threat_types_to_pull
                            ):
                                confidence = round(
                                    int(behavior_info.get("confidence", 10))
                                    / 10
                                )
                                # If confidence is less than 10
                                # Range of confidence in CE is 1-10
                                if confidence == 0:
                                    confidence = 1
                                ioc_type_internal = (
                                    CROWDSTRIKE_TO_INTERNAL_TYPE[ioc_type]
                                )
                                ioc_description = behavior_info.get(
                                    "ioc_description", ""
                                )
                                timestamp = behavior_info.get("timestamp")
                                firstseen = (
                                    datetime.datetime.strptime(
                                        timestamp, DATE_FORMAT_FOR_IOCS
                                    )
                                    if timestamp
                                    else None
                                )
                                lastseen = (
                                    datetime.datetime.strptime(
                                        timestamp, DATE_FORMAT_FOR_IOCS
                                    )
                                    if timestamp
                                    else None
                                )
                                severity = self.get_severity_from_int(
                                    behavior_info.get("severity", 0)
                                )

                                indicator = Indicator(
                                    value=value,
                                    type=ioc_type_internal,
                                    comments=ioc_description,
                                    firstSeen=firstseen,
                                    lastSeen=lastseen,
                                    severity=severity,
                                    reputation=confidence,
                                )

                                indicator_list.append(indicator)
                                for threat_type in page_ioc_counts:
                                    if ioc_type in THREAT_MAPPING.get(
                                        threat_type
                                    ):
                                        page_ioc_counts[threat_type] += 1
                                        ioc_type_counts[threat_type] += 1
                                # Return if the indicator values is above
                                # the threshold
                                if (
                                    sum(ioc_type_counts.values())
                                    >= MAX_INDICATOR_THRESHOLD
                                ):
                                    return (
                                        indicator_list,
                                        page_ioc_counts,
                                        ioc_type_counts,
                                        skip_count,
                                    )
                            else:
                                skip_count += 1
                        except (ValidationError, Exception) as error:
                            error_message = (
                                "Validation error occurred"
                                if isinstance(error, ValidationError)
                                else "Unexpected error occurred"
                            )
                            self.logger.info(
                                f"{self.log_prefix}: {error_message} while "
                                f"creating indicator for {ioc_value} from "
                                f"detection id {detection_id} Hence "
                                f"skipping this indicator. Error: {error}"
                            )

        return indicator_list, page_ioc_counts, ioc_type_counts, skip_count

    def create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        for tag in tags:
            tag_name = tag.strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, tag_name, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def _get_checkpoint(self, detection_id: str, headers: Dict):
        """Get checkpoint for the pagination.

        Args:
            detection_id (str): Detection id of the detection.
            headers (Dict): Headers containing auth token.
        """
        base_url = self.configuration.get("base_url", "").strip()
        indicator_endpoint = f"{base_url}/detects/entities/summaries/GET/v1"
        self.logger.debug(
            f"{self.log_prefix}: Performing API call to get the last_behavior"
            f' timestamp for the detection id "{detection_id}".'
        )
        json_payload = {"ids": [detection_id]}
        resp_json = self.crowdstrike_helper.api_helper(
            url=indicator_endpoint,
            method="POST",
            json=json_payload,
            headers=headers,
            is_handle_error_required=True,
            logger_msg=(
                "fetching details from detection"
                f" id(s) from {ENDPOINT_DETECTION}"
            ),
            configuration=self.configuration,
        )
        resources_list = resp_json.get("resources", [])
        if resources_list:
            last_resource = resources_list[-1]
            last_behavior = last_resource.get("last_behavior")
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched last behavior"
                f' timestamp for detection id "{detection_id}". last '
                f'behavior timestamp: "{last_behavior}"'
            )
            return last_behavior

    def _pull_iocs_from_endpoint_detections(
        self,
        threat_data_type: List,
        initial_check_point: str,
        storage: Dict,
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Get a list of Detection IDs from the Endpoint detection.

        Args:
            - threat_data_type (string): Type of threat data to pull.
            - initial_check_point (string): A string representation of datetime
            object of the Endpoint Detection.
            - storage (Dict): A mutable copy of self.storage dictionary.
        Returns:
            - Generator[Indicator, bool, None]: A Generator of Indicator
            objects representing the retrieved indicators.
            - Dict: A dictionary containing the checkpoint details.
        """
        self.logger.debug(
            f"{self.log_prefix}: Pulling indicators from {ENDPOINT_DETECTION}"
            f" using checkpoint {initial_check_point}."
        )
        (base_url, client_id, client_secret) = (
            self.crowdstrike_helper.get_credentials(self.configuration)
        )
        headers = self.crowdstrike_helper.get_auth_header(
            client_id, client_secret, base_url
        )
        query_endpoint = f"{base_url}/detects/queries/detects/v1"

        threat_types_to_pull = []
        for threat_type in threat_data_type:
            threat_types_to_pull.extend(THREAT_MAPPING.get(threat_type, []))

        self.logger.debug(
            f"{self.log_prefix}: Indicators of type(s) "
            f"{', '.join(threat_types_to_pull)} will be pulled from "
            f"{ENDPOINT_DETECTION}. Detection ids will be pulled and details "
            f"for the detections will be pulled."
        )
        ioc_type_counts = {
            "sha256": 0,
            "md5": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
        }
        skip_count, page_count = 0, 0
        total_detection_ids = 0
        checkpoint, offset = None, 0
        indicators = []
        next_page = True
        while next_page:
            page_count += 1
            # use the behavior timestamp of last detection id as checkpoint.
            # Or use the provided detection endpoint checkpoints from args.
            time_filter = checkpoint if checkpoint else initial_check_point
            ioc_source_filter = (
                f"behaviors.ioc_source:!*'{PREFIX_IOC_SOURCE_TAG}*'"
            )
            ioc_type_filter = f"behaviors.ioc_type:{threat_types_to_pull}"
            filter_query = f"last_behavior:>='{time_filter}'+{ioc_type_filter}+{ioc_source_filter}"  # noqa
            query_params = {
                "limit": PAGE_SIZE,
                "filter": filter_query,
                "sort": "last_behavior|asc",
            }

            self.logger.debug(
                f"{self.log_prefix}: Pulling detection id(s) of threat "
                f"type(s) {', '.join(threat_types_to_pull)} from "
                f"{ENDPOINT_DETECTION}."
            )

            resp_json = self.crowdstrike_helper.api_helper(
                url=query_endpoint,
                method="GET",
                params=query_params,
                headers=headers,
                is_handle_error_required=True,
                logger_msg=f"pulling detection ids from {PLATFORM_NAME}",
                configuration=self.configuration,
            )
            current_detection_ids = resp_json.get("resources", [])
            total_detection_ids += len(current_detection_ids)
            offset += PAGE_SIZE

            current_page_ioc_counts = {
                "sha256": 0,
                "md5": 0,
                "domain": 0,
                "ipv4": 0,
                "ipv6": 0,
            }
            if current_detection_ids:
                (
                    indicators,
                    current_page_ioc_counts,
                    ioc_type_counts,
                    current_page_skip_count,
                ) = self._get_detection_detailed(
                    ioc_type_counts=ioc_type_counts,
                    threat_types_to_pull=threat_types_to_pull,
                    detection_ids=current_detection_ids,
                    headers=headers,
                )
                skip_count += current_page_skip_count
                self.total_indicators += len(indicators)

            self.logger.debug(
                f"{self.log_prefix}: Pull stat: SHA256:"
                f" {current_page_ioc_counts['sha256']}, MD5:"
                f" {current_page_ioc_counts['md5']}, Domain:"
                f" {current_page_ioc_counts['domain']}, "
                f"IPv4: {current_page_ioc_counts['ipv4']} "
                f"and IPv6: {current_page_ioc_counts['ipv6']}"
                f" were fetched in page {page_count}"
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{sum(current_page_ioc_counts.values())} indicator(s) in "
                f"the page {page_count} from {ENDPOINT_DETECTION}. Total "
                f" indicator(s) fetched - {sum(ioc_type_counts.values())}."
            )

            last_indicator_checkpoint = datetime.datetime.now()
            if (
                self.total_indicators >= MAX_INDICATOR_THRESHOLD
                and not hasattr(self, "sub_checkpoint")
            ):
                last_indicator_checkpoint = indicators[-1].lastSeen
                self.logger.debug(
                    f"{self.log_prefix}: Maximum limit for"
                    f" {MAX_INDICATOR_THRESHOLD} indicators "
                    f"reached while fetching indicators from "
                    f"{ENDPOINT_DETECTION} for a sync interval"
                    " hence storing checkpoint "
                    f"{last_indicator_checkpoint} for next sync interval."
                )
                next_page = False

            if self.last_run_at:
                last_indicator_checkpoint = self.last_run_at
            elif indicators:
                if indicators[-1].lastSeen is not None:
                    last_indicator_checkpoint = indicators[-1].lastSeen

            # Update the checkpoint of detection endpoint in the storage.
            storage["checkpoints"][
                "endpoint_detection_checkpoint"
            ] = last_indicator_checkpoint

            if len(current_detection_ids) < PAGE_SIZE:
                next_page = False
            else:
                last_record_id = current_detection_ids[-1]
                checkpoint = self._get_checkpoint(
                    detection_id=last_record_id, headers=headers
                )

            if not next_page:
                if skip_count > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped {skip_count} record(s) "
                        "as IoC value might be empty string or the IoC type "
                        'does not match the "Type of Threat data to pull" '
                        "configuration parameter."
                    )

                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_type_counts.values())} indicator(s) for "
                    f"{total_detection_ids} detection id(s) from "
                    f"{ENDPOINT_DETECTION}. Total "
                    f"{ioc_type_counts['sha256']} SHA256, "
                    f"{ioc_type_counts['md5']} MD5, "
                    f"{ioc_type_counts['domain']} Domain(s), "
                    f"{ioc_type_counts['ipv4']} IPv4 and "
                    f"{ioc_type_counts['ipv6']} IPv6 indicator(s) "
                    "were fetched."
                )

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_type_counts.values())} indicator(s) for "
                    f"{total_detection_ids} detection id(s) from "
                    f"{ENDPOINT_DETECTION}."
                )

            if hasattr(self, "sub_checkpoint"):
                yield indicators, storage.get("checkpoints")
            else:
                yield indicators

    def _extract_ioc_management_iocs(
        self,
        ioc_payload: Dict,
        fetched_ioc_counts: int,
        skipped_tags: set,
    ):
        """Extract IOC Management Indicators.

        Args:
            ioc_payload (Dict): Responses received from API Call.
            fetched_ioc_counts (int): Total IOCs fetched so far.
            skipped_tags (set): Skipped tags tag.

        Returns:
            Tuple: Indicators,ioc_counts,skipped_tags
        """
        indicators = []
        current_page_ioc_counts = {
            "sha256": 0,
            "md5": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
        }
        page_ioc_count = 0
        for resource in ioc_payload:
            try:
                ioc_value = resource.get("value")
                ioc_type = resource.get("type")
                resource_tag = resource.get("tags", [])
                resource_tag.append(NON_CROWDSTRIKE_DISCOVERED)

                created_tags, curr_skipped_tags = self.create_tags(
                    resource_tag
                )
                skipped_tags.update(set(curr_skipped_tags))

                comment = (
                    f"Source: {resource.get('source')}, "
                    f"Action: {resource.get('action')}, "
                    f"Platforms: {resource.get('platforms')}, "
                    f"Description: {resource.get('description')}"
                )

                indicator = Indicator(
                    value=ioc_value,
                    type=CROWDSTRIKE_TO_INTERNAL_TYPE[ioc_type],
                    severity=IOC_MANAGEMENT_SEVERITY_MAPPING.get(
                        resource.get("severity"), SeverityType.UNKNOWN
                    ),
                    firstSeen=resource.get("created_on"),
                    lastSeen=resource.get("modified_on"),
                    comments=comment,
                    tags=created_tags,
                )

                indicators.append(indicator)
                current_page_ioc_counts[ioc_type] += 1
                page_ioc_count += 1
                if (
                    fetched_ioc_counts + page_ioc_count
                    >= MAX_INDICATOR_THRESHOLD
                ):
                    return indicators, current_page_ioc_counts, skipped_tags

            except (ValidationError, Exception) as error:
                error_message = (
                    "Validation error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.info(
                    f"{self.log_prefix}: {error_message} while "
                    f"creating indicator. Hence {ioc_value} indicator "
                    f"will be skipped. Error: {error}, Record: {resource}"
                )
        return indicators, current_page_ioc_counts, skipped_tags

    def _pull_iocs_from_ioc_management(
        self,
        threat_data_type: List,
        initial_check_point: str,
        storage: Dict,
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Pull indicators from IOC Management Page.

        Args:
            - threat_data_type (string): Type of threat data to pull.
            - initial_check_point (string): A string representation of datetime
            object of the IOC Management checkpoint.
            - storage (Dict): A mutable copy of self.storage dictionary.
        Returns:
            - Generator[Indicator, bool, None]: A Generator of Indicator
            objects representing the retrieved indicators.
            - Dict: A dictionary containing the checkpoint details.
        """
        self.logger.debug(
            f"{self.log_prefix}: Pulling indicators from {IOC_MANAGEMENT}"
            f" using checkpoint {initial_check_point}."
        )
        (base_url, client_id, client_secret) = (
            self.crowdstrike_helper.get_credentials(self.configuration)
        )
        page_count = 0
        base_url = self.configuration.get("base_url", "")
        query_endpoint = f"{base_url}/iocs/combined/indicator/v1"
        headers = self.crowdstrike_helper.get_auth_header(
            client_id, client_secret, base_url
        )

        query_params = {
            "limit": IOC_MANAGEMENT_PULL_PAGE_LIMIT,
            "filter": f"type: {threat_data_type}+modified_on:>='{initial_check_point}'+tags:!'{DEFAULT_NETSKOPE_TAG}'",  # noqa
        }
        skipped_tags = set()
        ioc_counts = {"sha256": 0, "md5": 0, "domain": 0, "ipv4": 0, "ipv6": 0}
        self.logger.debug(
            f"{self.log_prefix}: Indicator(s) of types "
            f"{', '.join(threat_data_type)} will be pulled from "
            f"{IOC_MANAGEMENT}."
        )
        next_page = True
        while next_page:
            page_count += 1
            resp_json = self.crowdstrike_helper.api_helper(
                url=query_endpoint,
                method="GET",
                headers=headers,
                params=query_params,
                is_handle_error_required=True,
                logger_msg=(
                    f"pulling indicators from {IOC_MANAGEMENT} for "
                    f"page {page_count}"
                ),
                configuration=self.configuration,
            )
            meta = resp_json.get("meta")
            after = meta.get("pagination", {}).get("after")
            query_params["after"] = after
            resources = resp_json.get("resources", [])

            (
                indicators,
                current_page_ioc_counts,
                skipped_tags,
            ) = self._extract_ioc_management_iocs(
                resources,
                self.total_indicators,
                skipped_tags,
            )
            # Add the total count of indicators fetched so far from IOC
            # Management as well as Endpoint Detection.
            self.total_indicators += len(indicators)

            # Add current page IOC counts to total IOC Counts.
            for ioc_type, count in current_page_ioc_counts.items():
                ioc_counts[ioc_type] += count

            self.logger.debug(
                f"{self.log_prefix}: Pull stat: SHA256:"
                f" {current_page_ioc_counts['sha256']}, MD5:"
                f" {current_page_ioc_counts['md5']}, Domain:"
                f" {current_page_ioc_counts['domain']}, "
                f"IPv4: {current_page_ioc_counts['ipv4']} "
                f"and IPv6: {current_page_ioc_counts['ipv6']}"
                f" were fetched in page {page_count}"
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{sum(current_page_ioc_counts.values())} indicator(s) "
                f"in page {page_count} from {IOC_MANAGEMENT}. Total "
                f"indicator(s) fetched - {sum(ioc_counts.values())}."
            )

            last_indicator_checkpoint = datetime.datetime.now()
            if (
                self.total_indicators >= MAX_INDICATOR_THRESHOLD
                and not hasattr(self, "sub_checkpoint")
            ):
                last_indicator_checkpoint = indicators[-1].lastSeen
                self.logger.debug(
                    f"{self.log_prefix}: Maximum limit for"
                    f" {MAX_INDICATOR_THRESHOLD} indicators reached while "
                    f"fetching indicators from {IOC_MANAGEMENT} for a "
                    f"sync interval hence storing checkpoint "
                    f"{last_indicator_checkpoint} for next sync interval."
                )
                next_page = False

            if self.last_run_at:
                last_indicator_checkpoint = self.last_run_at
            elif indicators:
                if indicators[-1].lastSeen is not None:
                    last_indicator_checkpoint = indicators[-1].lastSeen
            storage["checkpoints"][
                "ioc_management_checkpoint"
            ] = last_indicator_checkpoint

            if not after or (len(resources) < IOC_MANAGEMENT_PULL_PAGE_LIMIT):
                next_page = False

            if not next_page:
                if skipped_tags:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped following tags(s) "
                        "because they were longer than expected size or due "
                        "to some other exceptions that occurred while "
                        f"creation of them: {list(skipped_tags)}"
                    )

                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) from "
                    f"{IOC_MANAGEMENT}. Total {ioc_counts['sha256']} SHA256, "
                    f"{ioc_counts['md5']} MD5, {ioc_counts['domain']} Domain,"
                    f" {ioc_counts['ipv4']} IPv4 and {ioc_counts['ipv6']} "
                    "IPv6 indicator(s) were fetched."
                )

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) from "
                    f"{IOC_MANAGEMENT} in total {page_count} pages."
                )

            if hasattr(self, "sub_checkpoint"):
                yield indicators, storage.get("checkpoints", {})
            else:
                yield indicators

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from CrowdStrike platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the CrowdStrike platform.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", ""
        ).strip()
        endpoint_detection_checkpoint = None
        ioc_management_checkpoint = None
        storage = self.storage if self.storage is not None else {}

        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint:
            endpoint_detection_checkpoint = sub_checkpoint.get(
                "endpoint_detection_checkpoint"
            )
            ioc_management_checkpoint = sub_checkpoint.get(
                "ioc_management_checkpoint"
            )
        elif storage.get("checkpoints", {}):
            endpoint_detection_checkpoint = storage.get("checkpoints", {}).get(
                "endpoint_detection_checkpoint"
            )
            ioc_management_checkpoint = storage.get("checkpoints", {}).get(
                "ioc_management_checkpoint"
            )
        elif self.last_run_at:
            endpoint_detection_checkpoint = self.last_run_at
            ioc_management_checkpoint = self.last_run_at

        if not endpoint_detection_checkpoint or not ioc_management_checkpoint:
            endpoint_detection_checkpoint = (
                datetime.datetime.now()
                - datetime.timedelta(days=self.configuration.get("days"))
            )
            ioc_management_checkpoint = (
                datetime.datetime.now()
                - datetime.timedelta(days=self.configuration.get("days"))
            )

        storage.update(
            {
                "checkpoints": {
                    "endpoint_detection_checkpoint": endpoint_detection_checkpoint,  # noqa
                    "ioc_management_checkpoint": ioc_management_checkpoint,
                }
            }
        )

        if is_pull_required == "Yes":
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self._pull(storage)

                return wrapper(self)
            else:
                indicators = []
                for batch in self._pull(storage):
                    indicators.extend(batch)
                return indicators
        else:
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
            return []

    def _pull(self, storage):
        threat_data_type = self.configuration.get("threat_data_type")
        indicator_source_page = self.configuration.get("indicator_source_page")

        pull_ioc_methods = {}
        if "endpoint_detections" in indicator_source_page:
            pull_ioc_methods[self._pull_iocs_from_endpoint_detections] = (
                storage.get("checkpoints", {})
                .get("endpoint_detection_checkpoint")
                .strftime(DATE_FORMAT)
            )

        if "ioc_management" in indicator_source_page:
            pull_ioc_methods[self._pull_iocs_from_ioc_management] = (
                storage.get("checkpoints", {})
                .get("ioc_management_checkpoint")
                .strftime(DATE_FORMAT)
            )

        for pull_method, check_point in pull_ioc_methods.items():
            if self.total_indicators < MAX_INDICATOR_THRESHOLD:
                yield from pull_method(
                    threat_data_type=threat_data_type,
                    initial_check_point=check_point,
                    storage=storage,
                )

    def _get_total_iocs_on_ioc_management(self, headers: Dict) -> int:
        """Check the count of indicators present on CrowdStrike IOC Management.

        Args:
            headers (Dict): Headers containing auth token.

        Returns:
            int: Total indicators present on IOC Management.
        """
        base_url = self.configuration.get("base_url", "")
        query_endpoint = f"{base_url}/iocs/combined/indicator/v1"  # noqa
        self.logger.debug(
            f"{self.log_prefix}: Verifying the count of indicators within "
            f"{IOC_MANAGEMENT}."
        )

        resp_json = self.crowdstrike_helper.api_helper(
            url=query_endpoint,
            method="GET",
            headers=headers,
            is_handle_error_required=True,
            logger_msg=(
                f"checking the count of indicator(s) within {IOC_MANAGEMENT}"
            ),
            configuration=self.configuration,
        )
        ioc_count = (
            resp_json.get("meta", {})
            .get("pagination", {})
            .get("total", IOC_MANAGEMENT_INDICATORS_LIMIT)
        )

        self.logger.debug(
            f"{self.log_prefix}: {ioc_count} indicator(s)"
            f" are present on {IOC_MANAGEMENT}."
        )
        return ioc_count

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_ipv6(self, address: str) -> bool:
        """Validate IPv6 address.

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

    def _is_valid_fqdn(self, fqdn: str) -> bool:
        """Validate FQDN (Absolute domain).

        Args:
            - fqdn (str): FQDN to validate.

        Returns:
            - bool: True if valid else False.
        """
        if re.match(
            r"^(?!.{255}|.{253}[^.])([a-z0-9](?:[-a-z-0-9]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?[.]?$",  # noqa
            fqdn,
            re.IGNORECASE,
        ):
            return True
        else:
            return False

    def _filter_iocs_and_fetch_host_ids(
        self, indicators: List, headers: Dict, base_url: str
    ) -> List:
        """Filter the indicators for isolate/remediate action.

        Args:
            indicators (List): List of indicators received from business rule.
            headers (Dict): Dictionary containing auth token.
            base_url (str): Base URL

        Returns:
            List: List of host ids.
        """
        self.logger.info(
            f"{self.log_prefix}: Filtering indicators "
            "and fetching host ids for filtered indicators."
        )
        counts = {
            "sha256": 0,
            "md5": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
            "fqdn": 0,
        }
        host_ids = set()
        skip_count = 0
        ioc_count = 0

        for indicator in indicators:
            ioc_type = None
            if indicator.type == IndicatorType.SHA256:
                ioc_type = "sha256"
            elif indicator.type == IndicatorType.MD5:
                ioc_type = "md5"
            elif indicator.type in BIFURCATE_INDICATOR_TYPES:
                try:
                    if self._validate_domain(indicator.value):
                        ioc_type = "domain"
                    elif self._is_valid_ipv4(indicator.value):
                        ioc_type = "ipv4"
                    elif self._is_valid_ipv6(indicator.value):
                        ioc_type = "ipv6"
                    elif self._is_valid_fqdn(indicator.value):
                        ioc_type = "domain"
                    else:
                        skip_count += 1
                        continue
                except Exception:
                    skip_count += 1
                    continue
            else:
                skip_count += 1
                continue

            current_host_ids = self._get_host_ids_from_indicator(
                base_url=base_url,
                headers=headers,
                ioc_type=ioc_type,
                ioc_value=indicator.value,
            )
            if len(current_host_ids) > 0:
                host_ids.update(current_host_ids)
                counts[ioc_type] += len(current_host_ids)
                ioc_count += 1
            else:
                skip_count += 1

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} indicators(s) as "
                f"they might have invalid value in it or host id(s) are not "
                f"present on {PLATFORM_NAME}."
            )

        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(host_ids)} unique "
            f"host id(s) for {ioc_count} indicator(s). Total "
            f"{counts['sha256']} SHA256, {counts['md5']} MD5, "
            f"{counts['domain']} Domain, {counts['ipv4']} IPv4 "
            f"{counts['ipv6']} IPv6 and {counts['fqdn']} FQDN host id(s) "
            "fetched per indicator type."
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(host_ids)} unique "
            f"host id(s) for {ioc_count} indicator(s)."
        )
        return list(host_ids)

    def _execute_isolate_remediate_workflow(
        self, indicators: List, action: str
    ):
        """Execute workflow of Isolate/Remediate Hosts action.

        Args:
            indicators (List): List of indicators received from
            business rule.
            action (str): Action to perform on host.

        Raises:
            CrowdstrikePluginException: _description_

        Returns:
            int: Total
        """
        (base_url, client_id, client_secret) = (
            self.crowdstrike_helper.get_credentials(self.configuration)
        )

        # Step-1 Fetch access token.
        headers = self.crowdstrike_helper.get_auth_header(
            client_id, client_secret, base_url
        )

        # Step-2 Filter indicators and fetch host ids.
        hosts = self._filter_iocs_and_fetch_host_ids(
            indicators=indicators, headers=headers, base_url=base_url
        )

        # Step-3
        # Perform Isolate/Remediate action on fetched hosts.
        if hosts:
            self._perform_isolate_remediate_action(
                hosts, action, headers, base_url
            )

    def _get_host_ids_from_indicator(
        self, base_url: str, ioc_type, ioc_value, headers: Dict
    ) -> List:
        """Get the hosts ids from the indicator value.

        Args:
            indicators (Dict): Indicators.
            headers (Dict): Headers containing the auth token.
            base_url (str): Base URL

        Returns:
            List: List of hosts ids on which action should be performed.
        """
        host_ids = []
        endpoint = f"{base_url}/indicators/queries/devices/v1"
        err_msg = f'while fetching the hosts for indicator "{ioc_value}"'
        try:
            offset = ""
            while True:
                params = {
                    "type": ioc_type,
                    "value": ioc_value,
                    "limit": MAX_LIMIT_FOR_HOSTS,
                    "offset": offset,
                }
                response = self.crowdstrike_helper.api_helper(
                    method="GET",
                    url=endpoint,
                    headers=headers,
                    params=params,
                    logger_msg=err_msg,
                    is_handle_error_required=False,
                    configuration=self.configuration,
                )
                if response.status_code == 200:
                    resp_json = self.crowdstrike_helper.parse_response(
                        response
                    )
                    # Fetch the resources
                    resources = resp_json.get("resources", [])
                    # Extend the resource to host_ids
                    host_ids.extend(resources)
                    # Append the count for logger.
                    offset = (
                        resp_json.get("meta", {})
                        .get("pagination", {})
                        .get("offset")
                    )
                    if not offset or len(resources) < 100:
                        break
                elif response.status_code == 404:
                    break
                else:
                    self.crowdstrike_helper.handle_error(
                        response,
                        err_msg,
                    )
        except CrowdstrikePluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred {err_msg}."
                    " Skipped fetching hosts for indicator"
                    f' value "{ioc_value}"'
                ),
                details=str(exp),
            )
        return host_ids

    def _perform_isolate_remediate_action(
        self, host_ids: List, action: str, headers: Dict, base_url: str
    ) -> int:
        """Perform Isolate/Remediate action on hosts.

        Args:
            host_ids (List): List of host ids.
            action (str): action to perform. e.g. contain
            headers (Dict): Headers containing auth token.
            base_url (str): Base URL.
        """
        success, failed = 0, 0
        base_url = self.configuration.get("base_url", "").strip()
        endpoint = f"{base_url}/devices/entities/devices-actions/v2"
        self.logger.info(
            f'{self.log_prefix}: Performing "{action}" action on host(s).'
        )
        total_host_ids = len(host_ids)
        batch_size = ISOLATE_REMEDIATE_BATCH_SIZE
        if action in ["hide_host", "unhide_host"]:
            batch_size = 100
        # Action will be performed in batch of 5k for contain
        # and lift_containment For hide_host and unhide_host
        # batch_size will be 100
        for host_batch in self.divide_in_chunks(host_ids, batch_size):
            payload = {
                "action_parameters": [{"name": action, "value": action}],
                "ids": host_batch,
            }
            params = {"action_name": action}
            self.logger.debug(
                f'{self.log_prefix}: Performing "{action}" action'
                f" on {len(host_batch)} host(s)."
            )
            response = self.crowdstrike_helper.api_helper(
                method="POST",
                url=endpoint,
                headers=headers,
                params=params,
                json=payload,
                is_handle_error_required=False,
                logger_msg=f"executing {action} on hosts",
                configuration=self.configuration,
            )
            if response.status_code == 202:
                success += len(host_batch)
                self.logger.info(
                    f'{self.log_prefix}: Successfully performed "{action}"'
                    f" action on {len(host_batch)} host(s). "
                    f"{total_host_ids-success-failed} host(s) are remaining "
                    "for action to perform."
                )
            elif response.status_code == 404:
                # If 404 occurred then it will perform action on the valid host
                # For invalid host(s) it will raise error.
                resp_json = self.crowdstrike_helper.parse_response(response)
                resources = resp_json.get("resources", [])
                errors = resp_json.get("errors", [])
                # Append the count of resources to success.
                success += len(resources)
                # Append the count of errors to failed.
                failed += len(errors)
                self.logger.info(
                    f"{self.log_prefix}: Successfully performed {action}"
                    f" action on {len(resources)} host(s)."
                )
                self.logger.info(
                    f"{self.log_prefix}: Failed to perform action on"
                    f" {len(errors)} host(s). API Response: {resp_json}"
                )
            else:
                try:
                    self.crowdstrike_helper.handle_error(
                        response, f"executing {action} on hosts"
                    )
                except CrowdstrikePluginException as exp:
                    # Capture general if anything is raised from API helper.
                    self.logger.error(
                        message=f"{self.log_prefix}: {exp}",
                        details=str(traceback.format_exc()),
                    )
                    failed += len(host_batch)

        if failed > 0:
            self.logger.info(
                f'{self.log_prefix}: Failed execution of "{action}" '
                f"action on {failed} host(s). The failure may occur "
                f"if the host does not exist on {PLATFORM_NAME}."
            )
        self.logger.info(
            f'{self.log_prefix}: Successfully executed "{action}" '
            f"action on {success} host(s)."
        )

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to CrowdStrike.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        action_value = action_dict.get("value")

        if action_value == "action":
            target_action = action_dict.get("parameters", {}).get("action")

            (base_url, client_id, client_secret) = (
                self.crowdstrike_helper.get_credentials(self.configuration)
            )
            batch_size = int(
                self.configuration.get("batch_size", DEFAULT_BATCH_SIZE)
            )
            # Prepare headers.
            headers = self.crowdstrike_helper.get_auth_header(
                client_id, client_secret, base_url
            )
            total_indicators = self._get_total_iocs_on_ioc_management(
                headers=headers
            )
            is_push_accepted = True
            if total_indicators >= IOC_MANAGEMENT_INDICATORS_LIMIT:
                err_msg = (
                    f"Limit of 1 Million indicators on {IOC_MANAGEMENT} "
                    "is reached hence no new indicators will be shared, "
                    f"remove existing indicators from {IOC_MANAGEMENT}"
                    " to remain under this limit."
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
                is_push_accepted = False

            # Step-1 Filter indicators received from business rule.
            # Verify existence of indicators on IOC Management.
            indicator_payloads = self._filter_indicators(
                indicators=indicators, action_dict=action_dict
            )

            # Step-2 Verify existence of indicators.
            push_payloads, update_payloads = self._verify_ioc_existence(
                headers=headers,
                indicators=indicator_payloads,
                action=target_action,
            )

            # Step-3
            # Update Indicators in Custom IOC Management.
            if update_payloads:
                self._update_indicators_in_ioc_management(
                    payloads=update_payloads,
                    headers=headers,
                    batch_size=batch_size,
                )

            # Step-4
            # Share indicators with Custom IOC Management.
            if is_push_accepted is False and len(push_payloads) > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped sharing of "
                    f"{len(push_payloads)} indicator(s) on {IOC_MANAGEMENT} as"
                    " it already has 1 Million indicators on it. Remove "
                    "existing indicators to remain under this limit."
                )
            elif push_payloads:
                self._push_indicators_to_ioc_management(
                    payloads=push_payloads,
                    headers=headers,
                    batch_size=batch_size,
                )
            log_msg = (
                f'Successfully executed push method for "{action_label}" '
                f"target action."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        elif action_value == "isolate_remediate_action":
            # Perform Isolate/Remediate action on hosts
            # that observed the indicator.
            action_value = action_dict.get("parameters", {}).get("action")
            self._execute_isolate_remediate_workflow(indicators, action_value)
            err_msg = (
                "Successfully executed workflow for "
                '"Isolate/Remediate Hosts" action.'
            )
            return PushResult(
                success=True,
                message=err_msg,
            )

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def _update_indicators_in_ioc_management(
        self, headers: Dict, payloads: List[Dict], batch_size: int
    ):
        """Update indicators in IOC Management.

        Args:
            headers (Dict): Headers dictionary containing auth token.
            payloads (List[Dict]): Json payloads.
            batch_size (int): Batch size to consider while updating.
        """
        self.logger.info(
            f"{self.log_prefix}: Updating indicator(s) on {IOC_MANAGEMENT}."
        )
        base_url = self.configuration.get("base_url", "").strip()
        push_endpoint = f"{base_url}/iocs/entities/indicators/v1"
        self.logger.debug(
            f"{self.log_prefix}: {len(payloads)} indicator(s) "
            f"will be updated on {IOC_MANAGEMENT} in the batch of "
            f"{batch_size}."
        )
        total_indicators_count = len(payloads)
        update_success, update_failed = 0, 0
        for payload_list in self.divide_in_chunks(payloads, batch_size):
            chunk_size = len(payload_list)
            json_body = {
                "indicators": payload_list,
                "comment": "Indicators updated from Netskope Cloud Exchange.",
            }
            logger_msg = (
                f"Updating {chunk_size} indicator(s) on {IOC_MANAGEMENT}"
            )
            try:
                response = self.crowdstrike_helper.api_helper(
                    url=push_endpoint,
                    method="PATCH",
                    headers=headers,
                    json=json_body,
                    is_handle_error_required=False,
                    logger_msg=logger_msg,
                    configuration=self.configuration,
                )
                if response.status_code in [200, 201]:
                    update_success += chunk_size
                    self.logger.info(
                        f"{self.log_prefix}: Successfully updated "
                        f"{update_success} indicator(s) out of "
                        f"{total_indicators_count} indicator(s) "
                        f"on {IOC_MANAGEMENT}."
                    )

                elif response.status_code in [400, 500]:
                    update_failed += chunk_size
                    resp_json = self.crowdstrike_helper.parse_response(
                        response
                    )
                    err_msg = (
                        f"Received exit code {response.status_code}, "
                        f"while {logger_msg}"
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg}",
                        details=str(resp_json),
                    )
                    continue
                self.crowdstrike_helper.handle_error(
                    resp=response, logger_msg=logger_msg
                )
            except CrowdstrikePluginException as exp:
                err_msg = (
                    f"Error occurred while updating indicators "
                    f"in {IOC_MANAGEMENT}. Hence skipping this batch."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                update_failed += chunk_size
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while updating indicators "
                    f"in {IOC_MANAGEMENT}. Hence skipping this batch."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                update_failed += chunk_size
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {update_success} "
            f"indicator(s) and {update_failed} indicator(s) were not "
            f"updated on {IOC_MANAGEMENT}."
        )

    def _push_indicators_to_ioc_management(
        self,
        headers: Dict,
        payloads: List[Dict],
        batch_size: int,
    ) -> Dict:
        """Push the indicator to the CrowdStrike IOC Management.

        Args:
            endpoint (str): Endpoint used to push indicators on
            CrowdStrike IOC Management.
            headers (Dict): Header dictionary having OAUTH2 access token
            payload (List[Dit]): List of python dictionary object of
            JSON response model as per CrowdStrike API.
        Returns:
            Dict: JSON response dict received after successful push.
        """
        self.logger.info(
            f"{self.log_prefix}: Sharing indicator(s) with {IOC_MANAGEMENT}."
        )
        base_url = self.configuration.get("base_url", "").strip()
        push_endpoint = f"{base_url}/iocs/entities/indicators/v1"
        self.logger.debug(
            f"{self.log_prefix}: {len(payloads)} indicator(s) will be shared "
            f"to {IOC_MANAGEMENT} in the batch of {batch_size}."
        )
        total_indicators_count = len(payloads)
        push_success, push_failed = 0, 0
        is_limit_exceeded = False
        for payload_list in self.divide_in_chunks(payloads, batch_size):
            chunk_size = len(payload_list)
            json_body = {
                "comment": "Indicators shared from Netskope Cloud Exchange.",
                "indicators": payload_list,
            }
            logger_msg = (
                f"sharing {chunk_size} indicator(s) with {IOC_MANAGEMENT}"
            )
            try:
                response = self.crowdstrike_helper.api_helper(
                    url=push_endpoint,
                    method="POST",
                    headers=headers,
                    json=json_body,
                    is_handle_error_required=False,
                    logger_msg=logger_msg,
                    configuration=self.configuration,
                )
                if response.status_code == 201:
                    push_success += chunk_size
                    self.logger.info(
                        f"{self.log_prefix}: Successfully shared "
                        f"{push_success} indicator(s) out of "
                        f"{total_indicators_count} on {IOC_MANAGEMENT}."
                    )

                elif response.status_code == 400:
                    resp_json = self.crowdstrike_helper.parse_response(
                        response
                    )
                    err_msg = (
                        f"Received exit code 400, while {logger_msg}."
                        " Hence skipping this batch"
                    )
                    errors = resp_json.get("errors", [str(response.text)])[0]
                    if "Limit of 1 million indicators reached." in errors.get(
                        "message", "No error message received from API."
                    ):
                        err_msg = (
                            f"Limit of 1 million indicators on "
                            f"{IOC_MANAGEMENT} is reached hence "
                            f"skipped sharing of indicators on"
                            f" {IOC_MANAGEMENT}."
                        )
                        self.logger.info(f"{self.log_prefix}: {err_msg}")
                        push_failed = total_indicators_count - push_success
                        is_limit_exceeded = True
                        break
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg}",
                        details=str(resp_json),
                    )
                    continue
                self.crowdstrike_helper.handle_error(
                    resp=response, logger_msg=logger_msg
                )
            except CrowdstrikePluginException as exp:
                err_msg = (
                    f"Error occurred while sharing indicators "
                    f"to {IOC_MANAGEMENT}. Hence skipping this batch."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                push_failed += chunk_size
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while sharing indicators "
                    f"to {IOC_MANAGEMENT}. Hence skipping this batch."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                push_failed += chunk_size

        log_msg = (
            f"Successfully shared {push_success} indicator(s) with "
            f"{IOC_MANAGEMENT}. {push_failed} indicator(s) "
            "failed to be shared."
        )
        if is_limit_exceeded:
            log_msg = log_msg + (
                " Other indicators will not be shared as the "
                "limit of 1 Million indicators is exceeded."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")

    def _validate_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        if re.match(
            r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",  # noqa
            value,
        ):
            return True
        else:
            return False

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        validation_err_msg = "Validation error occurred"
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        base_url = configuration.get("base_url", "").strip()
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif base_url not in BASE_URLS:
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f"{err_msg} Select the Base URL from the available options."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_secret = configuration.get("client_secret")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f"{err_msg} Client Secret should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        is_pull_required = configuration.get("is_pull_required", "").strip()
        if not is_pull_required:
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif is_pull_required not in [
            "Yes",
            "No",
        ]:
            err_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        ioc_source_page = configuration.get("indicator_source_page")

        if not ioc_source_page:
            err_msg = (
                "Indicator Source Page is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(
                source_page in IOC_SOURCE_PAGES
                for source_page in ioc_source_page
            )
        ):
            err_msg = (
                "Invalid Indicator Source Page provided in the configuration "
                "parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        threat_data_type = configuration.get("threat_data_type")

        if not threat_data_type:
            err_msg = (
                "Type of Threat data to pull is a required "
                "configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(
                threat_type in THREAT_TYPES for threat_type in threat_data_type
            )
        ):
            err_msg = (
                "Invalid value provided in the Type of Threat data to "
                "pull configuration parameter. Allowed values are SHA256,"
                " MD5, Domain, IPv4 and IPv6."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        batch_size = configuration.get("batch_size")
        if batch_size is None:
            err_msg = (
                "Indicator Batch Size is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(batch_size, int) or batch_size <= 0:
            err_msg = (
                "Invalid value provided in Indicator Batch Size."
                " It should be non-zero positive integer."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        source = configuration.get("source", "").strip()
        prefixed_source = f"{PREFIX_IOC_SOURCE_TAG} | {source}"
        if source:
            if not isinstance(source, str):
                err_msg = "Invalid value provided in the IOC Source."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif len(prefixed_source) > 200:
                err_msg = (
                    "Invalid value provided in the IOC Source. "
                    "Size of source string should be less than 200 characters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with CrowdStrike platform.

        Args:
            configuration (dict): Configuration parameters dictionary.
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating auth credentials."
            )
            (base_url, client_id, client_secret) = (
                self.crowdstrike_helper.get_credentials(configuration)
            )
            ioc_source_page = configuration.get(
                "indicator_source_page", IOC_SOURCE_PAGES
            )
            is_pull_required = configuration.get(
                "is_pull_required", ""
            ).strip()

            # Prepare headers.
            headers = self.crowdstrike_helper.get_auth_header(
                client_id, client_secret, base_url, is_validation=True
            )

            if is_pull_required == "Yes":
                validation_result = self._validate_permission(
                    base_url, headers, ioc_source_page
                )
                if validation_result.success:
                    self.logger.debug(
                        f"{self.log_prefix}: Validation successful."
                    )
                return validation_result
            else:
                self.logger.debug(f"{self.log_prefix}: Validation successful.")
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except CrowdstrikePluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}. Check logs for more details.",
            )

    def _validate_permission(
        self, base_url: str, headers: dict, ioc_source_page: List
    ) -> ValidationResult:
        """
        Validate the permissions given to Client ID and Client Secret.

        Args:
            base_url (str): Base URL of CrowdStrike.
        Returns:
            Raise error if valid Base URL is not selected.
        """
        if "endpoint_detections" in ioc_source_page:
            query_endpoint = f"{base_url}/detects/queries/detects/v1?limit=1"
            response = self.crowdstrike_helper.api_helper(
                url=query_endpoint,
                method="GET",
                headers=headers,
                logger_msg=(
                    f"verifying the connectivity with {ENDPOINT_DETECTION}"
                ),
                is_handle_error_required=False,
                is_validation=True,
                regenerate_auth_token=False,
                configuration=self.configuration,
            )
            result = self._verify_permission_helper(response)
            if not result.success:
                return result

        if "ioc_management" in ioc_source_page:
            query_endpoint = f"{base_url}/iocs/combined/indicator/v1"
            response = self.crowdstrike_helper.api_helper(
                url=query_endpoint,
                method="GET",
                headers=headers,
                logger_msg=(
                    f"verifying the connectivity with {IOC_MANAGEMENT}"
                ),
                is_handle_error_required=False,
                configuration=self.configuration,
            )
            result = self._verify_permission_helper(response)
            if not result.success:
                return result

        return ValidationResult(success=True, message="Validation successful.")

    def _verify_permission_helper(self, response) -> ValidationResult:
        """Helper method for verify permissions that takes
        response and return the validation result.

        Args:
            response (response): API Response object.

        Returns:
            ValidationResult : Validation result.
        """
        if response.status_code == 200:
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif response.status_code == 403:
            err_msg = (
                f"Received exit code {response.status_code}, Forbidden. "
                "Verify the API scopes provided to Client ID "
                "and Client Secret."
            )
            resp_json = self.crowdstrike_helper.parse_response(response)
            api_errors = resp_json.get(
                "errors", "No error details received from API response."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation "
                    f"error occurred. {err_msg}"
                ),
                details=str(api_errors),
            )
            return ValidationResult(success=False, message=err_msg)

        self.crowdstrike_helper.handle_error(
            response, "validating the API permissions"
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Perform Action", value="action"),
            ActionWithoutParams(
                label="Isolate/Remediate Hosts",
                value="isolate_remediate_action",
            ),
        ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate crowdstrike configuration.

        Args:
            action (Action): Action to perform on IoCs.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["action", "isolate_remediate_action"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action_value == "action":
            if action.parameters.get("action") not in [
                "no_action",
                "prevent",
                "detect",
                "prevent_no_ui",
                "allow",
            ]:
                return ValidationResult(
                    success=False, message="Unsupported action provided."
                )

            if action.parameters.get("platforms", []) is None:
                err_msg = "Platforms should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        elif action_value == "isolate_remediate_action":
            if action.parameters.get("action") not in [
                "contain",
                "lift_containment",
                "hide_host",
                "unhide_host",
            ]:
                err_msg = "Invalid action selected."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        action_value = action.value
        if action_value == "action":
            return [
                {
                    "label": "Action",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "No Action (Applies to all indicator types)",  # noqa
                            "value": "no_action",
                        },
                        {
                            "key": "Allow (Applies to hashes only)",
                            "value": "allow",
                        },
                        {
                            "key": "Block, hide detection (Applies to hashes only)",  # noqa
                            "value": "prevent_no_ui",
                        },
                        {
                            "key": "Block (Applies to hashes only)",
                            "value": "prevent",
                        },
                        {
                            "key": "Detect only (Applies to all indicator types)",  # noqa
                            "value": "detect",
                        },
                    ],
                    "default": "no_action",
                    "mandatory": True,
                    "description": (
                        "Action to take when a host observes"
                        " the custom IOC."
                    ),
                },
                {
                    "label": "Platforms",
                    "key": "platforms",
                    "type": "multichoice",
                    "choices": [
                        {"key": "windows", "value": "windows"},
                        {"key": "mac", "value": "mac"},
                        {"key": "linux", "value": "linux"},
                    ],
                    "default": ["windows", "mac", "linux"],
                    "mandatory": True,
                    "description": (
                        "The platforms that the indicator applies to. "
                        "You can choose multiple platform names."
                    ),
                },
            ]
        elif action_value == "isolate_remediate_action":
            return [
                {
                    "label": "Action to perform on Host",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {"key": "Contain", "value": "contain"},
                        {
                            "key": "Lift Containment",
                            "value": "lift_containment",
                        },
                        {"key": "Hide Host", "value": "hide_host"},
                        {"key": "Unhide Host", "value": "unhide_host"},
                    ],
                    "default": "contain",
                    "mandatory": True,
                    "description": (
                        "Action to perform on host when CrowdStrike observes"
                        " the custom IOC."
                    ),
                }
            ]
