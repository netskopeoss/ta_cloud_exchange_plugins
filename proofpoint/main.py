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

"""Implementation of Proofpoint CTE plugin."""


from typing import List, Union
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from requests.exceptions import HTTPError

from netskope.common.utils import add_user_agent

from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models.business_rule import Action

INDICATOR_TYPE_MAP = {
    "url": IndicatorType.URL,
    "attachment": IndicatorType.SHA256,
}


class ProofpointPlugin(PluginBase):
    """The Proofpoint plugin implementation class."""

    def pull(self) -> List[Indicator]:
        """Pull IoCs from Proofpoint."""
        start_time = self.last_run_at  # datetime.datetime object.
        end_time = datetime.now()

        if not start_time:
            self.logger.info(
                f"Proofpoint Plugin: This is initial data fetch since "
                f"checkpoint is empty. Querying indicators for last {self.configuration['hours']} hours."
            )
            start_time = end_time - timedelta(
                hours=int(self.configuration["hours"])
            )
        else:
            # If the start time is older than 12 hours, the data which is older
            # than 12 hours from current time will be lost because Proofpoint
            # only supports maximum of 12 hours query in past.
            if end_time - start_time > timedelta(hours=12):
                self.logger.warn(
                    "Proofpoint plugin: Found checkpoint older than 12 hours. Fetching the indicators "
                    "only from last 12 hours. Indicators older than that will not be retrieved."
                )

                # Set start time to last 12 hours (max possible range)
                start_time = end_time - timedelta(hours=12)

        # Split the entire query range into intervals of 1 hour and fetch the data

        # If the interval is <= 1 hour, no need for pagination
        if start_time + timedelta(hours=1) >= end_time:
            return self._fetch_iocs(
                (end_time - start_time).seconds, is_interval=False
            )

        # pagination
        interval_start = start_time
        interval_end = interval_start + timedelta(hours=1)

        indicators = []
        while interval_end <= end_time:
            interval = self._get_interval_query(interval_start, interval_end)
            indicators.extend(self._fetch_iocs(interval))

            interval_start = interval_end + timedelta(
                seconds=1
            )  # for non overlapping intervals
            interval_end = interval_start + timedelta(hours=1)

        # Fetch data for last interval having size < 1 hour (if exists)
        if (
            interval_start < end_time
            and (end_time - interval_start).seconds > 0
        ):
            # Make last interval >= 30 sec. because min. allowed query interval is 30 sec.
            if (end_time - interval_start).seconds < 30:
                # Shift the query start time in past by at max by 29s
                interval_start = interval_start - timedelta(
                    seconds=30 - (end_time - interval_start).seconds
                )
            interval = self._get_interval_query(interval_start, end_time)
            indicators.extend(self._fetch_iocs(interval))

        return indicators

    def _get_interval_query(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Generate interval query string from given start and end time."""
        return f"{start_time.replace(microsecond=0).isoformat()}Z/{end_time.replace(microsecond=0).isoformat()}Z"

    def _create_tag(
        self, tag_utils: TagUtils, tag: str, color: str = "#FF0000"
    ) -> List[str]:
        """Create given tag if it does not already exist."""
        if self.configuration["enable_tagging"] != "yes":
            return []

        if not tag_utils.exists(tag.strip()):
            tag_utils.create_tag(TagIn(name=tag.strip(), color=color))

        return [tag]

    def _parse_click_events(
        self, click_events: list, event_type: str
    ) -> List[Indicator]:
        """Parse given list of click events."""
        indicators, tag_utils = [], TagUtils()
        for click_event in click_events:
            indicators.append(
                Indicator(
                    value=click_event.get("url"),
                    type=IndicatorType.URL,
                    firstSeen=click_event.get("threatTime", None),
                    extendedInformation=click_event.get("threatURL", ""),
                    tags=self._create_tag(tag_utils, event_type),
                )
            )
        return indicators

    def _parse_message_events(
        self, message_events: list, event_type: str
    ) -> List[Indicator]:
        """Parse given list of message events."""
        indicators, tag_utils = [], TagUtils()
        for message_event in message_events:
            for threat_info in message_event.get("threatsInfoMap", []):
                if (
                    threat_info.get("threatType", "").lower()
                    in INDICATOR_TYPE_MAP
                ):
                    indicators.append(
                        Indicator(
                            value=threat_info.get("threat"),
                            type=INDICATOR_TYPE_MAP.get(
                                threat_info.get("threatType").lower()
                            ),
                            firstSeen=threat_info.get("threatTime", None),
                            extendedInformation=threat_info.get(
                                "threatUrl", ""
                            ),
                            tags=self._create_tag(tag_utils, event_type),
                        )
                    )
        return indicators

    def _parse_indicators(self, response: dict) -> List[Indicator]:
        """Parse the IoCs from Proofpoint response JSON."""
        indicators = []
        event_types = self.configuration["event_types"]

        if "clicksPermitted" in event_types:
            indicators.extend(
                self._parse_click_events(
                    response.get("clicksPermitted", []), "Click Permitted"
                )
            )
        if "clicksBlocked" in event_types:
            indicators.extend(
                self._parse_click_events(
                    response.get("clicksBlocked", []), "Click Blocked"
                )
            )

        if "messagesDelivered" in event_types:
            indicators.extend(
                self._parse_message_events(
                    response.get("messagesDelivered", []), "Message Delivered"
                )
            )
        if "messagesBlocked" in event_types:
            indicators.extend(
                self._parse_message_events(
                    response.get("messagesBlocked", []), "Message Blocked"
                )
            )
        return indicators

    def _make_rest_call(self, params, configuration):
        """Make REST API call to Proofpoint using given configurations."""
        return requests.get(
            f"{configuration['base_url'].strip('/')}/v2/siem/all",
            params=params,
            auth=(configuration["username"], configuration["password"]),
            verify=self.ssl_validation,
            proxies=self.proxy,
            headers=add_user_agent(),
        )

    def _fetch_iocs(
        self, query: Union[str, int], is_interval: bool = True
    ) -> List[Indicator]:
        """Make REST API call to Proofpoint and fetch all the IoCs for given time range."""
        params = {"format": "JSON"}
        if is_interval:
            params["interval"] = query
        else:
            params["sinceSeconds"] = query

        response = self._make_rest_call(params, self.configuration)

        try:
            response.raise_for_status()
        except HTTPError as ex:
            if response.status_code == 429:
                raise HTTPError(
                    "Proofpoint API rate limit exceeded. Could not poll "
                    "IoCs from Proofpoint. HTTP request returned with status code 429."
                )
            if response.text:
                raise HTTPError(
                    f"Status code: {response.status_code}, Error: {response.text}"
                )
            else:
                raise ex

        return self._parse_indicators(response.json())

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configurations."""
        if (
            "base_url" not in configuration
            or type(configuration["base_url"]) != str
            or not configuration["base_url"].strip()
            or not self._validate_url(configuration["base_url"])
        ):
            self.logger.error(
                "Proofpoint Plugin: Validation error occurred. Error: "
                "Invalid base URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid base URL provided."
            )

        if (
            "username" not in configuration
            or type(configuration["username"]) != str
            or not configuration["username"].strip()
        ):
            self.logger.error(
                "Proofpoint Plugin: Validation error occurred. Error: "
                "Invalid username found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid username provided."
            )

        if (
            "password" not in configuration
            or type(configuration["password"]) != str
            or not configuration["password"].strip()
        ):
            self.logger.error(
                "Proofpoint Plugin: Validation error occurred. Error: "
                "Invalid password found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid password provided."
            )

        try:
            if (
                "hours" not in configuration
                or not configuration["hours"]
                or int(configuration["hours"]) > 12
                or int(configuration["hours"]) <= 0
            ):
                self.logger.error(
                    "Proofpoint Plugin: Validation error occurred. Error: "
                    "Invalid hours provided. Possible range is 1 to 12 hours."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid hours provided. Possible range is 1 to 12 hours.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid hours provided. Hours should be integer ranging between 1 to 12.",
            )

        if (
            "event_types" not in configuration
            or type(configuration["event_types"]) != list
            or not set(configuration["event_types"]).issubset(
                [
                    "clicksPermitted",
                    "clicksBlocked",
                    "messagesDelivered",
                    "messagesBlocked",
                ]
            )
            or len(configuration["event_types"]) == 0
        ):
            self.logger.error(
                f"Proofpoint Plugin: Validation error occurred. Error: "
                f"Found invalid value for 'Event Type(s). Possible values are "
                f"{', '.join(['clicksPermitted', 'clicksBlocked', 'messagesDelivered', 'messagesBlocked'])}"
            )
            return ValidationResult(
                success=False,
                message="Invalid value provided for Event type(s). Check logs.",
            )

        if "enable_tagging" not in configuration or configuration[
            "enable_tagging"
        ] not in ["yes", "no"]:
            self.logger.error(
                "Proofpoint Plugin: Validation error occurred. Error: "
                "Found Invalid value for 'Enable Tagging'. Allowed values are 'yes' or 'no'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided. Allowed values are 'yes' or 'no'.",
            )

        return self.validate_auth_credentials(configuration)

    def validate_auth_credentials(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the authentication parameters using Proofpoint API call."""
        try:
            response = self._make_rest_call(
                {"format": "JSON", "sinceSeconds": 1}, configuration
            )

            if response.status_code in [200, 204]:
                return ValidationResult(
                    success=True, message="Authentication Successful."
                )
            elif response.status_code in [401, 403]:
                self.logger.error(
                    f"Proofpoint Plugin: Invalid credentials or user does not have sufficient rights to access API(s). "
                    f"HTTP request returned with status code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid credentials or user does not have sufficient rights to access API(s).",
                )
            elif response.status_code == 429:
                self.logger.error(
                    f"Proofpoint Plugin: Proofpoint API rate limit exceeded. "
                    f"Could not validate authentication credentials. "
                    f"HTTP request returned with status code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Proofpoint API rate limit exceeded. Could not validate authentication credentials.",
                )
            else:
                self.logger.error(
                    f"Proofpoint Plugin: Could not validate authentication credentials. "
                    f"HTTP request returned with status code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Could not validate authentication credentials. Check Logs.",
                )
        except Exception as ex:
            self.logger.error(
                "Proofpoint Plugin: Could not validate authentication credentials."
            )
            self.logger.error(repr(ex))
        return ValidationResult(
            success=False,
            message="Error occurred while validating account credentials. Check Logs.",
        )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate proofpoint configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
