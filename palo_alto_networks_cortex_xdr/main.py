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

CTE Palo Alto Networks Cortex XDR plugin's main file which contains
the implementation of all the plugin's methods.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import string
import traceback
from typing import Dict, List, Tuple

from urllib.parse import urlparse
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

from .utils.palo_alto_networks_cortex_xdr_constants import (
    CORTEX_TO_CE_SEVERITY_MAPPING,
    DEFAULT_BATCH_SIZE,
    INTERNAL_SEVERITY_TO_CORTEX,
    MAX_INDICATOR_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_CHECKPOINT,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from .utils.palo_alto_networks_cortex_xdr_helper import (
    PaloAltoCortexNetworksXDRPluginException,
    PaloAltoCortexNetworksXDRPluginHelper,
)


class PaloAltoNetworksCortexXDRPlugin(PluginBase):
    """PaloAltoNetworksCortexXDRPlugin class having implementation all
    plugin's methods."""

    def __init__(self, name, *args, **kwargs):
        """PaloAltoCortexXDR plugin initializer.

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
        self.palo_alto_cortex_helper = PaloAltoCortexNetworksXDRPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

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
                return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _create_tags(self, tags: List) -> tuple:
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

    def _get_epoch_time(self, date: datetime.datetime) -> int:
        """Get epoch timestamp from datetime.

        Args:
            date (datetime.datetime): datetime object.

        Returns:
            int: Epoch timestamp.
        """
        return int(date.strftime(r"%s")) * 1000

    def _extract_iocs_from_events(
        self,
        alert: Dict,
        threat_data_type: List,
        ioc_counts: Dict,
        page_ioc_counts: Dict,
        storage: Dict,
    ):
        """Extract the indicators from the events.

        Args:
            alert (Dict): Alert received from API.
            threat_data_type (List): Type of threat data to pull
            ioc_counts (Dict): Dictionary containing total indicators count.
            page_ioc_counts (Dict): Dictionary containing page indicators
              count.
            storage (Dict): Storage dictionary.

        Returns:
            tuple: indicators, storage, ioc_counts, page_ioc_counts, skip_count
        """
        enable_tagging = self.configuration.get("enable_tagging", "yes")
        indicators = []
        events = alert.get("events", [])
        skip_count = 0
        tags = alert.get("tags", []) + alert.get("original_tags", [])
        tags = set(tags) if tags else []
        extracted_tags, skipped_tags = [], []
        # Create tags
        if enable_tagging == "yes":
            extracted_tags, skipped_tags = self._create_tags(tags)
        # Map the severity
        ioc_severity = CORTEX_TO_CE_SEVERITY_MAPPING.get(
            alert.get("severity", SeverityType.UNKNOWN).lower(),
            SeverityType.UNKNOWN,
        )

        # Extract the important fields in comments.
        ioc_comment = (
            "Description: "
            f"{alert.get('description', f'IOC from {PLATFORM_NAME}')},"
            f" Host Name: {alert.get('host_name')}, Matching Status: "
            f"{alert.get('matching_status')}, Source: "
            f"{alert.get('source')}, Resolution Status: "
            f"{alert.get('resolution_status')}"
        )
        for event in events:
            try:
                # Extract timestamp.
                timestamp = int(event.get("event_timestamp")) // 1000
                converted_timestamp = datetime.datetime.fromtimestamp(
                    timestamp
                )
                last_event_timestamp = event.get(
                    "event_timestamp",
                    self._get_epoch_time(datetime.datetime.now()),
                )
                if (
                    event.get("actor_process_image_sha256") is not None
                    and "sha256" in threat_data_type
                ):
                    indicators.append(
                        Indicator(
                            value=event.get("actor_process_image_sha256"),
                            type=IndicatorType.SHA256,
                            comments=ioc_comment,
                            severity=ioc_severity,
                            lastSeen=converted_timestamp,
                            firstSeen=converted_timestamp,
                            tags=extracted_tags,
                        )
                    )
                    page_ioc_counts["sha256"] += 1
                    ioc_counts["sha256"] += 1

                    # Break the execution if the Threshold is reached.
                    if sum(ioc_counts.values()) >= MAX_INDICATOR_THRESHOLD:
                        event_timestamp = (
                            last_event_timestamp
                            if last_event_timestamp
                            else self._get_epoch_time(datetime.datetime.now())
                        )
                        # Store the last event timestamp in the storage.
                        storage[PLUGIN_CHECKPOINT] = event_timestamp
                        self.logger.debug(
                            f"{self.log_prefix}: Maximum limit "
                            f"of {MAX_INDICATOR_THRESHOLD} "
                            f"indicators reached while "
                            f"fetching indicators from "
                            f"{PLATFORM_NAME} for a sync "
                            "interval hence storing checkpoint"
                            f" {event_timestamp} for next "
                            "sync interval."
                        )
                        return (
                            indicators,
                            storage,
                            ioc_counts,
                            page_ioc_counts,
                            skip_count,
                            skipped_tags,
                        )
                if (
                    event.get("actor_process_image_md5") is not None
                    and "md5" in threat_data_type
                ):
                    indicators.append(
                        Indicator(
                            value=event.get("actor_process_image_md5"),
                            type=IndicatorType.MD5,
                            severity=ioc_severity,
                            comments=ioc_comment,
                            lastSeen=converted_timestamp,
                            firstSeen=converted_timestamp,
                            tags=extracted_tags,
                        )
                    )
                    page_ioc_counts["md5"] += 1
                    ioc_counts["md5"] += 1

                    # Break the execution if the Threshold is reached.
                    if sum(ioc_counts.values()) >= MAX_INDICATOR_THRESHOLD:
                        event_timestamp = (
                            last_event_timestamp
                            if last_event_timestamp
                            else self._get_epoch_time(datetime.datetime.now())
                        )
                        # Store the last event timestamp in the storage.
                        storage[PLUGIN_CHECKPOINT] = event_timestamp
                        self.logger.debug(
                            f"{self.log_prefix}: Maximum limit "
                            f"of {MAX_INDICATOR_THRESHOLD} "
                            f"indicators reached while "
                            f"fetching indicators from "
                            f"{PLATFORM_NAME} for a sync "
                            "interval hence storing checkpoint"
                            f" {event_timestamp} for next "
                            "sync interval."
                        )
                        return (
                            indicators,
                            storage,
                            ioc_counts,
                            page_ioc_counts,
                            skip_count,
                            skipped_tags,
                        )

            except (ValidationError, Exception) as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.info(
                    f"{self.log_prefix}: {error_message} while "
                    f"creating indicator hence "
                    f"skipping this indicator. Error: {error}"
                )
                skip_count += 1

        return (
            indicators,
            storage,
            ioc_counts,
            page_ioc_counts,
            skip_count,
            skipped_tags,
        )

    def _extract_iocs_from_alerts(
        self,
        data: Dict,
        threat_data_type: List,
        ioc_counts: Dict,
        storage: Dict,
        page_count: int,
        skipped_tags: set,
    ):
        """Extract indicators from the Alerts received from the API.

        Args:
            data (Dict): Data received from the API.
            threat_data_type (List): Type of indicators to pull.
            ioc_counts (Dict): Dictionary containing counts.
            storage (Dict): Storage.
            page_count (int): page indicators count.
            skipped_tags (set): Skipped tags count.

        Returns:
            tuple: page_indicators, ioc_counts, storage, skip_count,
              threshold_break, detection_timestamp, skipped_tags
        """
        alerts = data.get("reply", {}).get("alerts", [])
        page_indicators = []
        skip_count = 0
        page_ioc_counts = {"sha256": 0, "md5": 0}
        threshold_break = False
        detection_timestamp = None

        for alert in alerts:
            if alert.get("matching_status", "") not in [
                "ResolvedFalsePositive",
                "ResolvedDuplicate",
            ]:
                # Extract the detection timestamp for the checkpoint.
                detection_timestamp = alert.get(
                    "detection_timestamp",
                    self._get_epoch_time(datetime.datetime.now()),
                )

                # Extract the indicators from the events.
                (
                    current_alert_indicators,
                    storage,
                    ioc_counts,
                    page_ioc_counts,
                    page_skip_count,
                    current_skipped_tags,
                ) = self._extract_iocs_from_events(
                    alert,
                    threat_data_type,
                    ioc_counts,
                    page_ioc_counts,
                    storage,
                )
                skipped_tags.update(set(current_skipped_tags))
                page_indicators.extend(current_alert_indicators)
                skip_count += page_skip_count
                # Break the execution if the threshold is reached.
            if sum(ioc_counts.values()) >= MAX_INDICATOR_THRESHOLD:
                threshold_break = True
                self.logger.info(
                    f"{self.log_prefix}: Maximum limit of "
                    f"{MAX_INDICATOR_THRESHOLD} indicators exceeded. Hence"
                    " storing last event timestamp "
                    f'"{storage.get(PLUGIN_CHECKPOINT)}" in '
                    "storage and remaining indicators will be pulled "
                    "in the next sync interval."
                )
                break
        self.logger.debug(
            f"{self.log_prefix}: Pull stats: SHA256: "
            f"{page_ioc_counts['sha256']} and MD5: "
            f"{page_ioc_counts['md5']} were fetched in "
            f"page {page_count}. Skip count: {skip_count}"
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{sum(page_ioc_counts.values())} indicator(s) in page"
            f" {page_count}. Total indicator(s) fetched - "
            f"{sum(ioc_counts.values())}."
        )

        return (
            page_indicators,
            ioc_counts,
            storage,
            skip_count,
            threshold_break,
            detection_timestamp,
            skipped_tags,
        )

    def _checkpoint_helper(
        self, storage: Dict, checkpoint, is_failure: bool = False
    ) -> Dict:
        """This is the helper method for Circuit Breaker.

        Args:
            storage (Dict): Storage dictionary
            checkpoint (None,int): Checkpoint value to store.
            is_failure (bool): False

        Returns:
            Dict: Storage
        """
        checkpoint_value = self._get_epoch_time(datetime.datetime.now())
        if self.last_run_at and not is_failure:
            checkpoint_value = self._get_epoch_time(self.last_run_at)
        elif checkpoint:
            checkpoint_value = checkpoint
        storage[PLUGIN_CHECKPOINT] = checkpoint_value
        return storage

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from Palo Alto Cortex XDR platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the Palo Alto Cortex XDR platform.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", ""
        ).strip()

        if is_pull_required == "Yes":
            base_url = (
                self.configuration.get("base_url", "").strip().strip("/")
            )
            url = f"{base_url}/public_api/v1/alerts/get_alerts_multi_events"

            severity = self.configuration.get("severity", [])
            threat_data_type = self.configuration.get("threat_data_type", [])
            storage = self.storage if self.storage is not None else {}
            offset1, offset2 = 0, 100
            indicators = []
            skipped_tags = set()
            checkpoint, detection_checkpoint = None, None

            if storage.get(PLUGIN_CHECKPOINT):
                # Fetch timestamp from storage.
                checkpoint = storage.get(
                    PLUGIN_CHECKPOINT,
                    self._get_epoch_time(datetime.datetime.now()),
                )
            else:
                # Use the last_run_at or initial range in the initial run.
                if self.last_run_at:
                    checkpoint = self._get_epoch_time(self.last_run_at)
                    self.logger.debug(
                        f"{self.log_prefix}: Pulling indicators using "
                        f"checkpoint {checkpoint} from {PLATFORM_NAME}."
                    )
                else:
                    checkpoint = self._get_epoch_time(
                        (
                            datetime.datetime.now()
                            - datetime.timedelta(
                                days=self.configuration.get("days")
                            )
                        )
                    )
                    self.logger.debug(
                        f"{self.log_prefix}: This is initial run of the plugin"
                        f" hence pulling indicators of last "
                        f"{self.configuration.get('days')} days "
                        f"from {PLATFORM_NAME}."
                    )

            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}."
                f" Indicators having creation time greater than or equal to "
                f"{checkpoint}, Threat type in {threat_data_type}, and "
                f"severity in {severity} will be pulled."
            )
            page_count, skip_count = 1, 0
            ioc_counts = {"sha256": 0, "md5": 0}
            threshold_break = False
            # Assign the value of checkpoint to detection checkpoint.
            # It can be used in the failure scenario for first page.
            detection_checkpoint = checkpoint
            try:
                while True:
                    payload = json.dumps(
                        {
                            "request_data": {
                                "filters": [
                                    {
                                        "field": "creation_time",
                                        "operator": "gte",
                                        "value": checkpoint,
                                    },
                                    {
                                        "field": "severity",
                                        "operator": "in",
                                        "value": severity,
                                    },
                                ],
                                "search_from": offset1,
                                "search_to": offset2,
                                "sort": {
                                    "field": "creation_time",
                                    "keyword": "asc",
                                },
                            }
                        }
                    )
                    self.logger.debug(
                        f"{self.log_prefix}: Pulling indicators for page "
                        f"{page_count}. Search from: {offset1} and "
                        f"Search to: {offset2}."
                    )

                    resp_json = self.palo_alto_cortex_helper.api_helper(
                        url=url,
                        method="POST",
                        proxies=self.proxy,
                        headers=self._authorize_request(
                            configuration=self.configuration
                        ),
                        data=payload,
                        verify=self.ssl_validation,
                        is_handle_error_required=True,
                        logger_msg=(
                            "pulling indicators for page "
                            f"{page_count} from {PLATFORM_NAME}"
                        ),
                    )
                    (
                        page_indicators,
                        ioc_counts,
                        storage,
                        page_skip_count,
                        threshold_break,
                        detection_checkpoint,
                        skipped_tags,
                    ) = self._extract_iocs_from_alerts(
                        resp_json,
                        threat_data_type,
                        ioc_counts,
                        storage,
                        page_count,
                        skipped_tags,
                    )
                    indicators.extend(page_indicators)
                    skip_count += page_skip_count

                    if (
                        resp_json.get("reply", {}).get("total_count", 0)
                        < offset2
                        or threshold_break
                    ):
                        break

                    offset1 = offset1 + 100
                    offset2 = offset2 + 100
                    page_count += 1

                if skip_count > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped {skip_count} record(s) as"
                        " indicator value might be None or invalid."
                    )

                if skipped_tags:
                    self.logger.info(
                        (
                            f"{self.log_prefix}: Skipped following tags(s) "
                            "because they were longer than expected size or "
                            "due to some other exceptions that occurred "
                            f"while creation of them: {list(skipped_tags)}"
                        )
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) from "
                    f"{PLATFORM_NAME}. Total {ioc_counts['sha256']} SHA256"
                    f" and {ioc_counts['md5']} MD5 were fetched."
                )

                if not threshold_break:
                    storage = self._checkpoint_helper(
                        storage, detection_checkpoint
                    )
            except PaloAltoCortexNetworksXDRPluginException:
                storage = self._checkpoint_helper(
                    storage, detection_checkpoint, True
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) from "
                    f"{PLATFORM_NAME}. Total {ioc_counts['sha256']} SHA256"
                    f" and {ioc_counts['md5']} MD5 were fetched."
                )
            except Exception as err:
                storage = self._checkpoint_helper(
                    storage, detection_checkpoint, True
                )
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing the "
                    f"pull cycle for page {page_count}. "
                    "The pulling of the indicators will be resumed in the "
                    f"next pull cycle. Error: {err}."
                )
                self.logger.error(
                    message=err_msg, details=traceback.format_exc()
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) from "
                    f"{PLATFORM_NAME}. Total {ioc_counts['sha256']} SHA256"
                    f" and {ioc_counts['md5']} MD5 were fetched."
                )
            self.logger.debug(
                f"{self.log_prefix}: Successfully executed pull "
                f"method for {self.plugin_name}. Storage: {storage}"
            )
            return indicators

        else:
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameters hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
            return []

    def _extract_host(self, url):
        """Extract host from URL.

        Args:
            url (st): URL value received form indicator object.
        Raises:
            ValueError: If not able to extract host.

        Returns:
            str: host/url
        """
        try:
            host_regex = r"^(?:[a-zA-Z]*:\/\/)?([\w\-\.]+)(?:\/)?"
            host = re.findall(host_regex, url).pop()
            if host:
                return host
            else:
                raise ValueError("Could not extract host name")
        except Exception:
            return url

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

    def _generate_payloads(self, indicators: List[Indicator]) -> List[Dict]:
        """Generate payloads from the indicators received from business rule.

        Args:
            indicators (List[Indicator]): Indicators

        Returns:
            List: List of payloads.
        """
        self.logger.debug(
            f"{self.log_prefix}: Filtering indicators "
            "received from business rule."
        )
        payloads = []
        total_ioc_count, skip_count = 0, 0
        for indicator in indicators:
            total_ioc_count += 1
            payload = {
                "severity": INTERNAL_SEVERITY_TO_CORTEX[indicator.severity],
                "comment": str(indicator.comments),
                "vendors": [{"vendor_name": "Netskope Cloud Exchange"}],
                "expiration_date": int(indicator.expiresAt.strftime(r"%s"))
                * 1000,
            }
            if indicator.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                payload.update(
                    {
                        "indicator": indicator.value,
                        "type": "HASH",
                    }
                )
                payloads.append(payload)
            elif indicator.type == IndicatorType.URL:
                try:
                    url_value = indicator.value
                    # If host is a valid domain then
                    if self._validate_domain(url_value):
                        payload.update(
                            {"indicator": url_value, "type": "DOMAIN_NAME"}
                        )
                        payloads.append(payload)
                    elif self._is_valid_ipv4(url_value):
                        payload.update(
                            {"indicator": indicator.value, "type": "IP"}
                        )
                        payloads.append(payload)
                    else:
                        skip_count += 1
                except Exception:
                    skip_count += 1

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} indicator(s) "
                "for sharing as they might have invalid Domain "
                "or IPv4 value."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully filtered "
            f"{len(payloads)} indicators from {total_ioc_count}"
            f" total indicators received from business rule."
        )
        return payloads

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Palo Alto Cortex XDR.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        fqdn = self.configuration.get("base_url", "").strip().strip("/")
        url = f"{fqdn}/public_api/v1/indicators/insert_jsons"
        action_value = action_dict.get("value", "")
        if action_value == "create_iocs":
            self.logger.info(
                f"{self.log_prefix}: Executing push method for "
                f'"{action_value}" target action.'
            )
            batch_size = int(
                action_dict.get("parameters", {}).get("batch_size")
            )

            # Generate Payloads
            payloads = self._generate_payloads(indicators)
            total_indicators_count = len(payloads)
            self.logger.debug(
                f"{self.log_prefix}: {total_indicators_count} indicator(s) "
                f"will be shared with {PLATFORM_NAME} in the batch of "
                f"{batch_size}."
            )

            push_success, push_failed = 0, 0

            # Share indicators in the batch of Batch Size
            # provided in the action configuration.
            for batch in self.divide_in_chunks(payloads, batch_size):
                chunk_size = len(batch)

                # Create Payload.
                final_data = {"request_data": batch, "validate": True}
                self.logger.debug(
                    f"{self.log_prefix}: Sharing {chunk_size} indicator(s)"
                    f" with {PLATFORM_NAME}."
                )
                logger_msg = f"sharing indicators to {PLATFORM_NAME}"
                try:
                    response = self.palo_alto_cortex_helper.api_helper(
                        url=url,
                        method="POST",
                        headers=self._authorize_request(
                            configuration=self.configuration
                        ),
                        data=json.dumps(final_data),
                        proxies=self.proxy,
                        verify=self.ssl_validation,
                        is_handle_error_required=False,
                        logger_msg=logger_msg,
                    )
                    if response.status_code in [200, 201]:
                        resp_json = (
                            self.palo_alto_cortex_helper.parse_response(
                                response
                            )
                        )
                        validation_errors = resp_json.get("reply", {}).get(
                            "validation_errors", False
                        )
                        batch_fail_count = len(validation_errors)
                        batch_push_count = chunk_size - len(validation_errors)
                        if batch_fail_count > 0:
                            msg = (
                                f"Successfully shared shared "
                                f"{batch_push_count} indicators"
                                f" and failed to share {batch_fail_count} "
                                f"indicators to {PLATFORM_NAME}."
                            )
                            self.logger.info(
                                message=f"{self.log_prefix}: {msg}"
                            )

                        push_success += batch_push_count
                        push_failed += batch_fail_count
                    else:
                        self.palo_alto_cortex_helper.handle_error(
                            response, logger_msg
                        )

                    self.logger.info(
                        f"{self.log_prefix}: Successfully shared "
                        f"{push_success} indicator(s) out of "
                        f"{total_indicators_count} indicator(s) "
                        f"on {PLATFORM_NAME}."
                    )
                except PaloAltoCortexNetworksXDRPluginException as exp:
                    err_msg = (
                        f"Error occurred while sharing indicators "
                        f"to {PLATFORM_NAME}. Hence skipping this batch."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {exp}",
                        details=str(traceback.format_exc()),
                    )
                    push_failed += chunk_size
                except Exception as exp:
                    err_msg = (
                        f"Unexpected error occurred while sharing indicators "
                        f"to {PLATFORM_NAME}. Hence skipping this batch."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {exp}",
                        details=str(traceback.format_exc()),
                    )
                    push_failed += chunk_size
            log_msg_push = (
                f"Successfully shared {push_success} indicator(s) and "
                f"{push_failed} indicator(s) failed to be shared "
                f"with {PLATFORM_NAME}."
            )

            log_msg_action = (
                "Successfully executed push method for "
                f'{action_dict.get("value", "")} '
                "target action."
            )
            self.logger.info(
                f"{self.log_prefix}: {log_msg_push} {log_msg_action}"
            )
            return PushResult(
                success=True,
                message=log_msg_action,
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        # Validate Base URL.
        base_url = configuration.get("base_url", "").strip()
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            err_msg = (
                "Invalid Base URl provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate API Key ID
        api_key_id = configuration.get("api_key_id", "").strip()
        if not api_key_id:
            err_msg = "API Key ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(api_key_id, str):
            err_msg = (
                "Invalid API Key ID provided "
                "in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate API Key
        api_key = configuration.get("api_key")
        if not api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid API Key provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Authentication Method
        auth_method = configuration.get("auth_method")
        if not auth_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif auth_method not in ["standard", "advanced"]:
            err_msg = (
                "Invalid value provided in Authentication"
                " Method configuration parameter. Allowed values are "
                "Standard and Advanced."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Enable Polling
        is_pull_required = configuration.get("is_pull_required", "").strip()
        if not is_pull_required:
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
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

        # Validate Type of Threat data to pull
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
                threat_type in ["sha256", "md5"]
                for threat_type in threat_data_type
            )
        ):
            err_msg = (
                "Invalid value provided in the Type of Threat data to "
                "pull configuration parameter. Allowed values are SHA256,"
                " and MD5."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Severity
        severity = configuration.get("severity")
        if not severity:
            err_msg = "Severity is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(
                severity_types
                in ["informational", "low", "medium", "high", "critical"]
                for severity_types in severity
            )
        ):
            err_msg = (
                "Invalid value provided in the Severity configuration "
                "parameter. Allowed values are Informational, Low, Medium,"
                " High, and Critical."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Enable tagging.
        enable_tagging = configuration.get("enable_tagging")
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details="Allowed values are 'Yes' and 'No'.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif enable_tagging not in ["yes", "no"]:
            err_msg = (
                "Invalid value provided in Enable "
                "Tagging configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details="Allowed values are 'Yes' and 'No'.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Initial Range
        days = configuration.get("days")
        if not days:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration) -> ValidationResult:
        """Validate the authentication params with
        Palo Alto Cortex XDR platform.

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
            base_url = configuration.get("base_url", "").strip().strip("/")
            headers = self._authorize_request(configuration=configuration)
            payload = json.dumps(
                {
                    "request_data": {
                        "filters": [],
                        "search_from": 0,
                        "search_to": 1,
                    }
                }
            )
            url = f"{base_url}/public_api/v1/alerts/get_alerts_multi_events/"  # noqa
            logger_msg = "validating auth credentials"
            response = self.palo_alto_cortex_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                data=payload,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=False,
                logger_msg=logger_msg,
            )
            if response.status_code == 200:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated"
                    " auth credentials and plugin configuration."
                )
                return ValidationResult(
                    success=True,
                    message=(
                        "Validation successful for"
                        f" {PLUGIN_NAME} plugin configuration."
                    ),
                )
            elif response.status_code == 400:
                err_msg = (
                    "Received exit code 400. Resource not found. Verify"
                    " FQDN Key provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(response.text),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif response.status_code == 401:
                err_msg = (
                    "Received exit code 401, Unauthorized access. "
                    "Verify API Key, API Key ID and Authentication Method "
                    "provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(response.text),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif response.status_code == 403:
                err_msg = (
                    "Received exit code 403, Forbidden access. "
                    "Verify API Key provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(response.text),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            self.palo_alto_cortex_helper.handle_error(
                resp=response, logger_msg=logger_msg
            )
        except PaloAltoCortexNetworksXDRPluginException as exp:
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
                message=f"{err_msg} Check logs for more details.",
            )

    def _authorize_request(self, configuration: Dict) -> Dict:
        """Authorize request on the basis of Authentication Method.

        Args:
            configuration(Dict): Configuration parameters.

        Returns:
            Dict: Dictionary containing authorization headers.
        """
        headers = {"Content-Type": "application/json"}
        auth_method = configuration.get("auth_method")
        api_key = configuration.get("api_key")
        api_key_id = configuration.get("api_key_id")
        if auth_method == "standard":
            headers.update(
                {"x-xdr-auth-id": str(api_key_id), "Authorization": api_key}
            )
            return headers
        elif auth_method == "advanced":
            # Generate a 64 bytes random string
            nonce = "".join(
                [
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(64)
                ]
            )
            # Get the current timestamp as milliseconds.
            timestamp = (
                int(datetime.datetime.now(datetime.timezone.utc).timestamp())
                * 1000
            )
            # Generate the auth key:
            auth_key = "%s%s%s" % (api_key, nonce, timestamp)
            # Convert to bytes object
            auth_key = auth_key.encode("utf-8")
            # Calculate sha256:
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            headers.update(
                {
                    "x-xdr-timestamp": str(timestamp),
                    "x-xdr-nonce": nonce,
                    "x-xdr-auth-id": str(api_key_id),
                    "Authorization": api_key_hash,
                }
            )
            return headers
        else:
            err_msg = (
                "Invalid Authentication Method found "
                "in the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise PaloAltoCortexNetworksXDRPluginException(err_msg)

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Create IOCs", value="create_iocs"),
        ]

    def validate_action(self, action: Action):
        """Validate Palo Alto Cortex XDR Action Configuration."""
        if action.value not in ["create_iocs"]:
            err_msg = "Invalid action provided in action configuration."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        batch_size = action.parameters.get("batch_size")
        if not batch_size:
            err_msg = (
                "Batch Size is a required action configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(batch_size, int):
            err_msg = (
                "Invalid value provided in Batch Size action"
                " configuration parameter. Batch Size should "
                "be positive integer value."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif int(batch_size) <= 0:
            err_msg = (
                "Batch Size should be an integer value " "greater than 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "create_iocs":
            return [
                {
                    "label": "Batch Size",
                    "key": "batch_size",
                    "type": "number",
                    "default": DEFAULT_BATCH_SIZE,
                    "mandatory": True,
                    "description": (
                        "Number of Threat IoCs to push in one API call."
                    ),
                }
            ]
        else:
            return []
