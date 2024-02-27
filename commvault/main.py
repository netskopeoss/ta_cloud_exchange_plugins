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

CTE Commvault Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import hashlib
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse
import uuid
from pydantic import ValidationError
from typing import Dict, Tuple
import re
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
)

from .utils.commvault_constant import (
    BATCH_SIZE,
    MODULE_NAME,
    MAX_INDICATOR_THRESHOLD,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PLUGIN_NAME,
    ANOMALOUS_EVENTCODE_STRINGS,
    COMMVAULT_TO_NETSCOPE_SEVERITY,
)
from .utils.commvault_helper import (
    CommvaultPluginException,
    CommvaultPluginHelper,
)


class CommVaultPlugin(PluginBase):
    """The CommVault plugin implementation."""

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
        self.base_url = None
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.commvault_helper = CommvaultPluginHelper(
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
            manifest_json = CommVaultPlugin.metadata
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

    def _validate_url(self, url: str) -> bool:
        """
        Validates a given URL.

        Args:
            url (str): The URL to be validated.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        parsed = urlparse(url.strip())
        flag = (parsed.scheme.strip() != "") and (parsed.netloc.strip() != "")
        return flag

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        """
        Validates the provided credentials by making an API request to the
        command center URL with the given authentication token.

        Args:
            configuration (dict): A dictionary containing the configuration
            parameters.

        Returns:
            ValidationResult: An object representing the result of the
            validation. It contains a success flag indicating if the
            validation was successful, and a message providing additional
            information about the result.
        """
        try:
            base_url = (
                configuration.get("commandcenter_url", "").strip().strip("/")
            )
            auth_token = configuration.get("auth_token", "")
            self.commvault_helper.api_helper(
                "validating credentials",
                f"{base_url}/commandcenter/api/Events",
                "GET",
                headers=self._get_headers(auth_token),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.info(f"{self.log_prefix}: Validation successful.")
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except CommvaultPluginException as ex:
            return ValidationResult(
                success=False,
                message=str(ex),
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _extract_indicators(self, events: list, storage: Dict) -> tuple:
        """Extract indicators.

        Args:
            events (list): Events fetched from API.
            storage (Dict): Storage dictionary.

        Returns:
            tuple : Tuple containing List of indicators fetched,
            page skip count, threshold break and checkpoint.
        """
        page_indicators = []
        page_skip_count = 0
        threshold_break = False
        detected_time_checkpoint = None
        for event in events:
            try:
                time_source = int(
                    event.get("timeSource", int(datetime.now().timestamp()))
                )
                detected_time = datetime.fromtimestamp(time_source)
                detected_time_checkpoint = (
                    time_source
                    if time_source
                    else int(datetime.now().timestamp())
                )
                event_desc = event.get("description", "")
                event_code = event.get("eventCodeString")
                re_extended_info = ANOMALOUS_EVENTCODE_STRINGS[event_code].get(
                    "extended_info"
                )
                re_comments = ANOMALOUS_EVENTCODE_STRINGS[event_code].get(
                    "comments", ""
                )
                if len(re_extended_info.findall(event_desc)) > 0:
                    extended_info = (
                        re_extended_info.findall(event_desc)[0]
                        .strip()
                        .strip('"')
                        .strip('"')
                    )
                    res = urlparse(extended_info)
                    if not all([res.scheme, res.netloc]):
                        extended_info = ""
                else:
                    extended_info = ""
                comments = re_comments.sub("", event.get("description", ""))
                comments = " ".join(comments.split())
                comments = re.sub(
                    "Please click here for more details.",
                    "",
                    comments,
                    flags=re.I,
                )
                if len(page_indicators) >= MAX_INDICATOR_THRESHOLD:
                    threshold_break = True
                    storage["checkpoint"] = detected_time_checkpoint
                    self.logger.debug(
                        f"{self.log_prefix}: Maximum limit for"
                        f" {MAX_INDICATOR_THRESHOLD} indicators "
                        f"reached while fetching indicators from "
                        f"{PLATFORM_NAME} for a sync interval"
                        " hence storing checkpoint "
                        f"{detected_time_checkpoint} for next sync interval."
                    )
                    return (
                        page_indicators,
                        page_skip_count,
                        threshold_break,
                        detected_time_checkpoint,
                    )
                page_indicators.append(
                    Indicator(
                        value=event.get("client_hostname"),
                        type=IndicatorType.URL,
                        firstSeen=detected_time,
                        lastSeen=detected_time,
                        severity=COMMVAULT_TO_NETSCOPE_SEVERITY.get(  # noqa
                            event.get("severity"), -1
                        ),
                        tags=[],
                        comments=comments,
                        extendedInformation=extended_info,
                    )
                )
            except (ValidationError, Exception) as error:
                page_skip_count += 1
                error_message = (
                    "Validation error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while"
                        f" creating indicator. This record "
                        f"will be skipped. Error: {error}."
                    ),
                    details=str(traceback.format_exc()),
                )
        return (
            page_indicators,
            page_skip_count,
            threshold_break,
            detected_time_checkpoint,
        )

    def get_client_hostname(self, client_id: int, headers: dict) -> str:
        """Get the hostname from client properties using client id

        Args:
            client_id (int): Client ID.
            headers (dict): Request headers.

        Returns:
            str: Client's host name retrieved from API.
        """
        response = self.commvault_helper.api_helper(
            url=f"{self.base_url}/commandcenter/api/Client/{client_id}",
            method="GET",
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
            logger_msg=(
                "fetching client properties for client having "
                f"ID {client_id}"
            ),
        )
        return (
            response.get("clientProperties", [{}])[0]
            .get("client", {})
            .get("clientEntity", {})
            .get("hostName", "")
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
        checkpoint_value = int(datetime.now().timestamp())
        if self.last_run_at and not is_failure:
            checkpoint_value = int(self.last_run_at.timestamp())
        elif checkpoint:
            checkpoint_value = checkpoint
        storage["checkpoint"] = checkpoint_value
        return storage

    def pull(self):
        """Pull the indicators from Commvault platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the Commvault platform.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", "Yes"
        ).strip()
        if is_pull_required != "Yes":
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
            return []
        storage = self.storage if self.storage is not None else {}
        try:
            skip_count = 0
            self.base_url = (
                self.configuration.get("commandcenter_url", "")
                .strip()
                .strip("/")
            )
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators "
                f"from {PLATFORM_NAME}."
            )
            checkpoint = None
            if storage.get("checkpoint"):
                checkpoint = storage.get("checkpoint")
            elif not self.last_run_at:
                initial_range = int(self.configuration.get("days"))
                from_time = datetime.now() - timedelta(days=initial_range)
                self.logger.debug(
                    f"{self.log_prefix}: This is initial run of the plugin"
                    f" hence pulling indicators of last {initial_range} "
                    f"days from {PLATFORM_NAME}."
                )
                checkpoint = int(from_time.timestamp())
            else:
                from_time = int(self.last_run_at.timestamp())
                self.logger.debug(
                    f"{self.log_prefix}: Pulling indicators greater than "
                    f"timestamp {str(from_time)} [{str(self.last_run_at)}]"
                    f" from {PLATFORM_NAME}."
                )
                checkpoint = from_time
            params = {
                "level": 10,
                "showAnomalous": True,
            }
            if checkpoint:
                params["fromTime"] = checkpoint

            self.logger.info(
                f"{self.log_prefix}: Fetching events greater than timestamp "
                f"{checkpoint} [{str(datetime.fromtimestamp(checkpoint))}] "
                f"from {PLATFORM_NAME}."
            )
            indicators = []
            detected_time_checkpoint = checkpoint
            threshold_break = False
            auth_token = self.configuration.get("auth_token")
            client_hostname_headers = self._get_headers(auth_token=auth_token)
            headers = self._get_headers(auth_token=auth_token)
            headers.update({"paginginfo": "0"})
            page_count = 0
            while True:
                resp_json = self.commvault_helper.api_helper(
                    logger_msg=(
                        f"pulling events for page"
                        f" {page_count} from {PLATFORM_NAME}"
                    ),
                    url=f"{self.base_url}/commandcenter/api/Events",
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                )

                events = resp_json.get("commservEvents", [])
                events = [
                    d
                    for d in events
                    if d.get("eventCodeString") in ANOMALOUS_EVENTCODE_STRINGS
                ]
                events = sorted(
                    events,
                    key=lambda d: d.get(
                        "timeSource",
                    ),
                )
                for event in events:
                    try:
                        client_id = int(
                            event.get("clientEntity", {}).get("clientId")
                        )
                        client_hostname = self.get_client_hostname(
                            client_id, client_hostname_headers
                        )
                        event["client_hostname"] = client_hostname
                    except (KeyError, Exception) as e:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error occurred while "
                                f"getting client's hostname. Error: {e}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        continue
                (
                    page_indicators,
                    page_skip_count,
                    threshold_break,
                    detected_time_checkpoint,
                ) = self._extract_indicators(events, storage)
                indicators.extend(page_indicators)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(page_indicators)} indicator(s) and skipped "
                    f"{page_skip_count} indicator(s) in page {page_count} "
                    f"from {PLATFORM_NAME}. Total indicator(s) fetched:"
                    f" {len(indicators)}"
                )

                if not events:
                    break
                page_count += 1
                headers["paginginfo"] = str(page_count)
            if not threshold_break:
                storage = self._checkpoint_helper(
                    storage, detected_time_checkpoint
                )
        except CommvaultPluginException as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {e}"
                ),
                details=str(traceback.format_exc()),
            )
            storage = self._checkpoint_helper(
                storage, detected_time_checkpoint, True
            )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            storage = self._checkpoint_helper(
                storage, detected_time_checkpoint, True
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(indicators)}  "
            f"indicator(s) from {PLATFORM_NAME}."
        )
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} record(s)"
                " as indicator value might invalid or due to some"
                " other exception."
            )
        self.logger.debug(
            f"{self.log_prefix}: Successfully executed pull "
            f"method for {PLATFORM_NAME}. Storage: {storage}"
        )
        return indicators

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push(self, indicators, action_dict) -> PushResult:
        """Push the Indicator list to Commvault.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        skip_count = 0
        ioc_count = 0
        self.logger.info(
            f"{self.log_prefix}: Sharing indicators started at: "
            + f"{str(datetime.now())}"
        )
        self.base_url = (
            self.configuration.get("commandcenter_url", "").strip().strip("/")
        )
        anomaly_detections = []
        non_url_counter = 0
        # build the body
        if action_dict.get("value") == "report_client_as_anomalous":
            request_body = {"anomalyDetections": []}
            for indicator in indicators:
                if indicator.type == IndicatorType.URL:
                    hostname = indicator.value.strip()
                    vendorname = "netskope-ce"
                    detection_time = int(indicator.lastSeen.timestamp())
                    extendedInformation = indicator.extendedInformation
                    event_id = int(
                        hashlib.sha1("URL".encode("utf-8")).hexdigest(),
                        16,
                    ) % (10**8)
                    anomaly_reason = str(indicator.comments)
                    anomaly_dict = {
                        "client": {"hostName": hostname},
                        "anomalyDetectedBy": {
                            "vendorName": vendorname,
                            "anomalyDetails": [
                                {
                                    "anomalyEvents": [
                                        {
                                            "detectionTime": detection_time,
                                            "eventId": str(uuid.uuid4())[:8],
                                            "eventUrl": (extendedInformation),
                                        }
                                    ],
                                    "detectionTime": detection_time,
                                    "anomalyReason": anomaly_reason,
                                    "eventId": str(event_id),
                                    "timesSeen": 1,
                                    "eventType": "URL",
                                }
                            ],
                        },
                    }
                    anomaly_detections.append(anomaly_dict)
                else:
                    non_url_counter += 1
        if non_url_counter > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped sharing of {non_url_counter} "
                f"indicator(s) to {PLATFORM_NAME} as they are not of type URL."
            )
        self.logger.info(
            f"{self.log_prefix}: {len(anomaly_detections)} indicator(s) will"
            f" be shared to {PLATFORM_NAME} in the batch of {BATCH_SIZE}."
        )
        headers = self._get_headers(
            auth_token=self.configuration.get("auth_token")
        )
        for request_body in self.divide_in_chunks(
            anomaly_detections, BATCH_SIZE
        ):
            batch_length = len(request_body)
            page_skip_count, page_ioc_count = 0, 0
            request_body = {"anomalyDetections": request_body}

            url = f"{self.base_url}/commandcenter/api/Client/Action/Report/Bulk/Anomaly"  # noqa
            try:
                response = self.commvault_helper.api_helper(
                    method="PUT",
                    url=url,
                    json=request_body,
                    params={},
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"sharing {batch_length}"
                        f" indicator(s) to {PLATFORM_NAME}"
                    ),
                    is_handle_error_required=False,
                )
                error_response = []
                if response.status_code == 200:
                    resp_json = self.commvault_helper.parse_response(
                        response, False
                    )
                    for anomaly_detection in resp_json.get(
                        "anomalyDetections", []
                    ):
                        if anomaly_detection.get("errorResponse", {}):
                            error_response.append(anomaly_detection)
                            page_skip_count += 1
                        else:
                            page_ioc_count += 1
                    if page_skip_count > 0:
                        skip_count += page_skip_count
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unable to share "
                                f"{page_skip_count} indicator(s)"
                                f"from {batch_length} indicator(s) to "
                                f"{PLATFORM_NAME}. The indicators may have "
                                "an invalid value, or the client's hostname "
                                f"might not be available in {PLATFORM_NAME}."
                            ),
                            details=str(error_response),
                        )

                    ioc_count += page_ioc_count
                    self.logger.info(
                        f"{self.log_prefix}: Successfully shared "
                        f"{page_ioc_count} indicator(s) in the current "
                        f"batch of {batch_length} indicator(s). Total "
                        f"indicators shared: {ioc_count}"
                    )
                else:
                    self.commvault_helper.handle_error(
                        resp=response,
                        logger_msg=(
                            f"sharing {batch_length}"
                            f" indicator(s) to {PLATFORM_NAME}"
                        ),
                        is_validation=False,
                    )
            except (Exception, CommvaultPluginException):
                skip_count += batch_length
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while sharing"
                        f" {batch_length} indicator(s) to {PLATFORM_NAME} "
                        "hence skipping this batch."
                    ),
                    details=str(traceback.format_exc()),
                )

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped sharing of {skip_count} "
                "indicator(s) as they might have invalid value, or the  "
                f"client's hostname might not available on {PLATFORM_NAME},"
                " or due to an unknown error."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully shared {ioc_count} "
            f"indicator(s) to {PLATFORM_NAME}."
        )
        return PushResult(
            success=True,
            message=f"Pushed indicators successfully to {PLUGIN_NAME}.",
        )

    def _get_headers(self, auth_token) -> dict:
        """
        Get common headers.
        Returns:
            dict: The common headers.
        """
        headers = {
            "authToken": auth_token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        return headers

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        commandcenter_url = (
            configuration.get("commandcenter_url", "").strip().strip("/")
        )
        if not commandcenter_url:
            err_msg = (
                "Command Center URL is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not self._validate_url(commandcenter_url):
            err_msg = (
                "Invalid Command Center URL provided in the "
                "configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        auth_token = configuration.get("auth_token", "")
        if not auth_token:
            err_msg = (
                "Commvault Access Token is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        is_pull_required = configuration.get("is_pull_required", "Yes").strip()
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

        days = configuration.get("days")
        if not days:
            err_msg = (
                "Initial Range (in days) is a required configuration "
                "parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(days, int) or days <= 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return self._validate_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return [
            Action(
                label="Report client as Anomalous",
                value="report_client_as_anomalous",
            )
        ]

    def validate_action(self, action: Action):
        """Validate Commvault action configuration."""

        if action.value not in [
            "report_client_as_anomalous",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
