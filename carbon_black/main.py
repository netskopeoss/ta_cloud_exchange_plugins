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

"""Carbon Black Plugin implementation to push and pull the data from Netskope Tenant."""


from typing import Dict
import requests
import time
import traceback
from datetime import datetime, timedelta
import json
from urllib.parse import urlparse
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

HOST_NAME = "https://defense.conferdeploy.net"
MAX_PAGE_SIZE = 100
MAX_PULL_PAGE_SIZE = 2000
PLUGIN_NAME = "CTE Carbon Black Plugin"
MAX_RETRY_COUNT = 4
TIME_OUT = 30


CARBONBLACK_TO_INTERNAL_TYPE = {
    0: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.LOW,
    4: SeverityType.MEDIUM,
    5: SeverityType.MEDIUM,
    6: SeverityType.MEDIUM,
    7: SeverityType.HIGH,
    8: SeverityType.HIGH,
    9: SeverityType.HIGH,
    10: SeverityType.CRITICAL,
}


class CarbonBlackPlugin(PluginBase):
    """The CarbonBlack plugin implementation."""

    def handle_status_code(
        self,
        response,
        custom_message: str = None,
        plugin: str = None,
    ):
        """Handle status code of response.

        Args:
            response (response): response of API call
            error_code (str, optional): error code. Defaults to None.
            custom_message (str, optional): custom message to write. Defaults to None.
            plugin (str, optional): plugin name. Defaults to None.
        """
        if response.status_code == 200 or response.status_code == 201:
            try:
                return response.json()
            except ValueError as err:
                error = (
                    f"{(custom_message + ',') if custom_message is not None else ''} "
                    f"Exception occurred while parsing JSON response."
                )
                if plugin:
                    error = f"{plugin}, {error}"
                self.logger.error(error, details=traceback.format_exc())
                raise err
        elif response.status_code == 401:
            self.logger.error(
                f"{plugin}, {(custom_message + ',') if custom_message is not None else ''} "
                f"Received exit code 401, Authentication Error.",
                details=response.text,
            )
        elif response.status_code == 403:
            self.logger.error(
                f"{(custom_message + ',') if custom_message is not None else ''} "
                f"{plugin}, Received exit code 403, Forbidden Error.",
                details=response.text,
            )
        elif response.status_code == 429:
            self.logger.error(
                f"{(custom_message + ',') if custom_message is not None else ''} "
                f"{plugin}, Received exit code 429, Too many requests.",
                details=response.text,
            )
        elif response.status_code == 409:
            self.logger.error(
                f"{(custom_message + ',') if custom_message is not None else ''} "
                f"{plugin}, Received exit code 409, Concurrency found while calling the API.",
                details=response.text,
            )
        elif response.status_code >= 400 and response.status_code < 500:
            self.logger.error(
                f"{plugin}, {(custom_message + ',') if custom_message is not None else ''} "
                f"Received exit code {response.status_code}, HTTP client Error.",
                details=response.text,
            )
        elif response.status_code >= 500 and response.status_code < 600:
            self.logger.error(
                f"{plugin}, {(custom_message + ',') if custom_message is not None else ''} "
                f"Received exit code {response.status_code}, HTTP server Error.",
                details=response.text,
            )
        response.raise_for_status()

    def _validate_url(self, url: str) -> bool:
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string(str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(
                string.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"
            )
        except Exception:
            return datetime.now()

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        try:
            headers = {
                "X-Auth-Token": f"{configuration['api_secret'].strip()}/{configuration['api_id'].strip()}"
            }
            response = requests.post(
                (
                    f"{configuration['management_url'].strip().strip('/')}/appservices/v6/orgs/"
                    f"{configuration['org_key'].strip()}/alerts/_search"
                ),
                json={"rows": 0},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            _ = self.handle_status_code(
                response, "Error occurred while validating the configuratoin", PLUGIN_NAME
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except requests.ConnectionError as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False, message="Incorrect Management URL provided."
            )
        except Exception as ex:
            self.logger.error(str(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while validating configuration parameters. Check logs for more detail.",
            )

    def _create_tags(self, utils):
        for tag in self.configuration["reputation"]:
            if not utils.exists(tag.strip()):
                utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))

    def pull(self):
        """Pull indicators from CarbonBlack."""
        try:
            if self.configuration["is_pull_required"] == "Yes":
                utils = TagUtils()
                if self.configuration["enable_tagging"] == "yes":
                    self._create_tags(utils)
                    tagging = True
                else:
                    tagging = False
                end_time = datetime.now()
                HOST_NAME = self.configuration["management_url"].strip("/")
                url = f"{HOST_NAME}/appservices/v6/orgs/{self.configuration['org_key'].strip()}/alerts/_search"
                if not self.last_run_at:
                    start_time = datetime.now() - timedelta(
                        days=int(self.configuration["days"])
                    )
                else:
                    start_time = self.last_run_at
                body = {
                    "rows": MAX_PULL_PAGE_SIZE,
                    "criteria": {
                        "create_time": {
                            "start": f"{start_time.isoformat()}Z",
                            "end": f"{end_time.isoformat()}Z",
                        },
                        "minimum_severity": self.configuration[
                            "minimum_severity"
                        ],
                        "reputation": self.configuration["reputation"],
                    },
                    "start": 0,
                    "sort": [{"field": "create_time", "order": "ASC"}],
                }
                indicators = []
                hash_of_ioc = set()
                counter = 0
                last_num_found = 0
                while True:
                    headers = self._get_headers()
                    for retry in range(MAX_RETRY_COUNT):
                        response = requests.post(
                            url,
                            json=body,
                            headers=add_user_agent(headers),
                            proxies=self.proxy,
                            verify=self.ssl_validation,
                        )
                        if (
                            retry == MAX_RETRY_COUNT - 1
                            or response.status_code not in [429]
                        ):
                            break
                        self.logger.info(
                            f"{PLUGIN_NAME}: Error occured while pulling indicators. "
                            f"Received exit code 429, Too many requests. Retry Count: {retry + 1}"
                        )
                        time.sleep(TIME_OUT)
                    data = self.handle_status_code(
                        response,
                        "Error occurred while pulling indicators",
                        PLUGIN_NAME,
                    )
                    if not len(data.get("results", [])):
                        break
                    temp_create_time = data["results"][-1]["create_time"]
                    for alert in data["results"]:
                        ioc_hash = hash(json.dumps(alert))
                        counter += 1
                        if (
                            alert.get("threat_cause_reputation", "")
                            not in self.configuration["reputation"]
                        ):
                            continue
                        if ioc_hash in hash_of_ioc:
                            continue
                        if alert.get("create_time") == temp_create_time:
                            hash_of_ioc.add(ioc_hash)
                        indicators.append(
                            Indicator(
                                value=alert["threat_cause_actor_sha256"],
                                type=IndicatorType.SHA256,
                                firstSeen=self._str_to_datetime(
                                    alert.get("first_event_time")
                                ),
                                lastSeen=self._str_to_datetime(
                                    alert.get("last_event_time")
                                ),
                                severity=CARBONBLACK_TO_INTERNAL_TYPE.get(
                                    alert.get("severity", 0)
                                ),
                                tags=[alert.get("threat_cause_reputation")]
                                if tagging
                                else [],
                                comments=alert.get(
                                    "threat_cause_actor_name", ""
                                )
                                or "",
                            )
                        )
                    if body["start"] == 8000:
                        last_num_found = int(data.get("num_found", 0))
                    if body["start"] == 0 and last_num_found == int(
                        data.get("num_found", 0)
                    ):
                        if len(data["results"]):
                            body["criteria"]["create_time"][
                                "start"
                            ] = f'{(datetime.strptime(data["results"][-1]["create_time"], "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(milliseconds=1)).isoformat()}Z'
                        else:
                            break
                    elif body["start"] + body["rows"] >= int(
                        data.get("num_available", 0)
                    ):
                        if int(data.get("num_found", 0)) == int(
                            data.get("num_available", 0)
                        ):
                            break
                        else:
                            body["criteria"]["create_time"]["start"] = data[
                                "results"
                            ][-1]["create_time"]
                            body["start"] = 0
                    else:
                        body["start"] += body["rows"]
                return indicators
            else:
                self.logger.info(
                    f"{PLUGIN_NAME}: Polling is disabled, skipping."
                )
                return []
        except Exception as err:
            self.logger.error(
                f"{PLUGIN_NAME}: Error occured while pulling indicators, {err}",
                details=traceback.format_exc(),
            )
            raise err

    def _get_headers(self) -> dict:
        """Get common headers."""
        return {
            "X-Auth-Token": f"{self.configuration['api_secret'].strip()}/{self.configuration['api_id'].strip()}"
        }

    def _update_feed_description(self, feed, action_dict: Dict):
        """Update the feed description."""
        feed["summary"] = action_dict.get("feed_description")
        HOST_NAME = self.configuration["management_url"].strip("/")
        org_key = self.configuration["org_key"].strip()
        headers = self._get_headers()
        for retry in range(MAX_RETRY_COUNT):
            response = requests.put(
                f"{HOST_NAME}/threathunter/feedmgr/v2/orgs/{org_key}/feeds/{feed['id']}/feedinfo",
                json=feed,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if retry == MAX_RETRY_COUNT - 1 or response.status_code not in [
                429
            ]:
                break
            self.logger.info(
                f"{PLUGIN_NAME}: Error occured while updating feed description. "
                f"Received exit code 429, Too many requests. Retry Count: {retry + 1}."
            )
            time.sleep(TIME_OUT)
        if response.status_code != 200:
            self.logger.error(
                f"{PLUGIN_NAME}: Could not update feed description"
                f"'. HTTP status code {response.json()}."
            )
        response.raise_for_status()

    def _get_feed_id(self, name: str, action_dict: Dict):
        """Get feed ID from feed name."""
        HOST_NAME = self.configuration["management_url"].strip("/")
        headers = self._get_headers()
        for retry in range(MAX_RETRY_COUNT):
            response = requests.get(
                f"{HOST_NAME}/threathunter/feedmgr/v2/orgs/{self.configuration['org_key'].strip()}/feeds",
                params={"include_public": True},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if retry == MAX_RETRY_COUNT - 1 or response.status_code not in [
                429
            ]:
                break
            self.logger.info(
                f"{PLUGIN_NAME}: Error occured while getting feed details. "
                f"Received exit code 429, Too many requests. Retry Count: {retry + 1}."
            )
            time.sleep(TIME_OUT)
        # response.raise_for_status()
        data = self.handle_status_code(
            response, "Error occurred while collecting the feed ID", PLUGIN_NAME
        )
        for feed in data.get("results", []):
            if feed["name"] == name:
                if feed["summary"] != action_dict.get("feed_description"):
                    self._update_feed_description(feed, action_dict)
                return feed["id"]
        # feed does not exist; create one
        headers = self._get_headers()
        for retry in range(MAX_RETRY_COUNT):
            response = requests.post(
                f"{HOST_NAME}/threathunter/feedmgr/v2/orgs/{self.configuration['org_key'].strip()}/feeds",
                headers=add_user_agent(headers),
                json={
                    "feedinfo": {
                        "name": name,
                        "owner": self.configuration["org_key"].strip(),
                        "provider_url": "",
                        "summary": action_dict.get("feed_description"),
                        "category": "development",
                    },
                    "reports": [],
                },
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if retry == MAX_RETRY_COUNT - 1 or response.status_code not in [
                429
            ]:
                break
            self.logger.info(
                f"{PLUGIN_NAME}: Error occured while creating feed. "
                f"Received exit code 429, Too many requests. Retry Count: {retry + 1}."
            )
            time.sleep(TIME_OUT)

        resp_json = self.handle_status_code(
            response, "Error occurred while creating a new feed", PLUGIN_NAME
        )
        if not resp_json.get("id"):
            # feed does not exist; failed to create one.
            self.logger.error(
                f"{PLUGIN_NAME}: Could not find or create a feed with name "
                f"'{name}'. HTTP status code {response.status_code}."
            )
        return resp_json.get("id")

    def push(self, indicators, action_dict: Dict):
        """Push indicators to Carbon Black."""
        HOST_NAME = self.configuration["management_url"].strip("/")
        action_dict = action_dict.get("parameters", {})
        feed_id = self._get_feed_id(action_dict.get("feed_name"), action_dict)
        if not feed_id:
            return PushResult(
                success=False,
                message=f"Could not create feed '{action_dict.get('feed_name')}'.",
            )
        reports = []
        report = {
            "title": "Netskope CTE Threat Report",
            "description": "",
            "severity": 10,
            "timestamp": int(datetime.now().timestamp()),
            "iocs": {"md5": []},
            "iocs_v2": [
                {
                    "match_type": "equality",
                    "field": "process_sha256",
                    "values": [],
                }
            ],
        }
        reports.append(report)
        # build the body
        url = 0
        for indicator in indicators:
            if indicator.type == IndicatorType.MD5:
                report["iocs"]["md5"].append(indicator.value)
            elif indicator.type == IndicatorType.SHA256:
                report["iocs_v2"][0]["values"].append(indicator.value)
            elif indicator.type == IndicatorType.URL:
                url += 1
        report["id"] = str(hash(json.dumps(reports)))
        report["iocs_v2"][0]["id"] = str(hash(json.dumps(reports)))
        total_md5 = len(report["iocs"]["md5"])
        total_sha256 = len(report["iocs_v2"][0]["values"])
        if total_md5 == 0 and total_sha256 == 0:
            if url:
                self.logger.warn(
                    f"{PLUGIN_NAME}: Skipping {url} URLs. Carbon Black plugin does not support pushing URLs."
                )
            return PushResult(success=True, message="Nothing to push.")
        if total_md5 == 0:
            del report["iocs"]
        if total_sha256 == 0:
            del report["iocs_v2"]
        headers = self._get_headers()
        for retry in range(MAX_RETRY_COUNT):
            response = requests.post(
                (
                    f"{HOST_NAME}/threathunter/feedmgr/v2/orgs/"
                    f"{self.configuration['org_key'].strip()}/feeds/{feed_id}/reports"
                ),
                json={"reports": reports},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if retry == MAX_RETRY_COUNT - 1 or response.status_code not in [
                429
            ]:
                break
            self.logger.info(
                f"{PLUGIN_NAME}: Error occured while pushing indicators. "
                f"Received exit code 429, Too many requests. Retry Count: {retry + 1}."
            )
            time.sleep(TIME_OUT)
        response = self.handle_status_code(
            response, "Error occurred while pushing indicators", PLUGIN_NAME
        )
        if response.get("success", False):
            if url:
                self.logger.warn(
                    f"{PLUGIN_NAME}: Skipping {url} URLs. Carbon Black plugin does not support pushing URLs."
                )
            return PushResult(
                success=True, message="Pushed all the indicators successfully."
            )
        else:
            return PushResult(
                success=False,
                message=f"Could not push threats to Carbon Black. HTTP status code {response.status_code}.",
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "management_url" not in configuration
            or type(configuration["management_url"]) != str
            or not configuration["management_url"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No management_url key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Management URL can not be empty."
            )
        if not self._validate_url(configuration["management_url"]):
            self.logger.error(
                f"{PLUGIN_NAME}: Invalid Management URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Management URL provided."
            )
        if (
            "api_id" not in configuration
            or type(configuration["api_id"]) != str
            or not configuration["api_id"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No api_id key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid API ID provided."
            )

        if (
            "api_secret" not in configuration
            or type(configuration["api_secret"]) != str
            or not configuration["api_secret"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No api_secret key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid API Secret provided."
            )

        if (
            "org_key" not in configuration
            or type(configuration["org_key"]) != str
            or not configuration["org_key"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No org_key key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Organization Key provided."
            )

        if "reputation" not in configuration:
            self.logger.error(
                f"{PLUGIN_NAME}: No reputation found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Reputation is not provided."
            )

        if "enable_tagging" not in configuration or configuration[
            "enable_tagging"
        ] not in ["yes", "no"]:
            self.logger.error(
                f"{PLUGIN_NAME}: Value of Enable Tagging should be 'yes' or 'no'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided. Allowed values are 'yes', or 'no'.",
            )

        if "is_pull_required" not in configuration or configuration[
            "is_pull_required"
        ] not in ["Yes", "No"]:
            self.logger.error(
                f"{PLUGIN_NAME}: Value of Pulling configured should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        try:
            if (
                "minimum_severity" not in configuration
                or not configuration["minimum_severity"]
                or not 1 <= int(configuration["minimum_severity"]) <= 10
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: Validation error occured Error: Invalid Minimum Severity provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Minimum Severity value provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Minimum Severity value provided.",
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: Validation error occured Error: Invalid days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Number of days provided.",
            )

        return self._validate_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to feed", value="feed"),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        if action.value not in ["feed"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.parameters.get("feed_name") is None:
            return ValidationResult(
                success=False, message="Feed Name should not be empty."
            )

        if action.parameters.get("feed_description") is None:
            return ValidationResult(
                success=False, message="Feed Description should not be empty."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "feed":
            return [
                {
                    "label": "Feed Name",
                    "key": "feed_name",
                    "type": "text",
                    "default": "CTE Threat Feed",
                    "mandatory": True,
                    "description": "Name of Carbon Black feed where indicator should be pushed.",
                },
                {
                    "label": "Feed Description",
                    "key": "feed_description",
                    "type": "text",
                    "default": "Created from Netskope CTE",
                    "mandatory": True,
                    "description": "Description of Carbon Black feed.",
                },
            ]
