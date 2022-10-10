"""
BSD 3-Clause License.

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

"""Mimecast Plugin implementation to push and pull the data from Mimecast."""

import re
import csv
import base64
import hashlib
import hmac
import uuid
import requests
from typing import Dict, List
from datetime import datetime, timedelta

from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.common.utils import add_user_agent

PAGE_SIZE = 100
MAX_REQUEST_URL = 25
MAX_CREATE_URL = 20


class MimecastPlugin(PluginBase):
    """The Mimecast plugin implementation."""

    def _parse_errors(self, failures):
        """Parse the error messages from Mimecast response."""
        messages = []
        for failure in failures:
            for error in failure.get("errors", []):
                messages.append(error.get("message"))
        return messages

    def _parse_csv(
        self, raw_csv: str, indicator_key
    ) -> List[Indicator]:
        """Parse given raw CSV string based on given feed type."""
        indicators = []
        raw_csv = raw_csv.split("\n")

        # This means no indicator data is returned
        if len(raw_csv) == 1:
            return indicators

        reader = csv.DictReader(raw_csv, delimiter="|")
        for row in reader:
            list_indicators = []
            if "MD5" in indicator_key:
                indicator = row.get("MD5")
                if indicator:
                    list_indicators.append({"indicator": indicator, "type": "MD5"})
            if "SHA256" in indicator_key:
                indicator = row.get("SHA256")
                if indicator:
                    list_indicators.append({"indicator": indicator, "type": "SHA256"})
            for obj in list_indicators:
                indicators.append(
                    Indicator(
                        value=obj["indicator"],
                        type=IndicatorType[obj["type"]],
                        comments=f"Sent from {row.get('SenderAddress')}"
                        if row.get("SenderAddress")
                        else "",
                    )
                )
        return indicators

    def get_rewritten_urls(self, start_time) -> List[Dict]:
        """Return rewritten urls from mimecast.

        Args:
            start_time (str): start time from where you want the data.

        Returns:
            List[Dict]: return list of dictionary of rewritten url from
            mimecast.
        """
        # REWRITTEN URL
        url, headers = self._get_auth_headers(
            self.configuration, "/api/ttp/url/get-logs"
        )
        rewritten_urls = []
        pagetoken = ""
        start_time = start_time.replace(microsecond=0)
        while True:
            body = {
                "meta": {
                    "pagination": {
                        "pageSize": PAGE_SIZE,
                        "pageToken": pagetoken,
                    }
                },
                "data": [
                    {
                        "from": f"{start_time.astimezone().isoformat()}",
                    }
                ],
            }
            response = requests.post(
                url,
                json=body,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            response.raise_for_status()
            response = response.json()
            if failures := response.get("fail", []):
                self.logger.error(
                    "Error: " + ",".join(self._parse_errors(failures))
                )
            elif response.get("data", []):
                rewritten_urls.extend(
                    single_response["url"]
                    for single_response in response.get("data", [])[0].get(
                        "clickLogs", []
                    )
                    if single_response.get("url", None) not in [" ", None]
                    and single_response.get("scanResult", "") == "malicious"
                )
            pagetoken = response["meta"]["pagination"].get("next", None)
            if not pagetoken:
                return rewritten_urls

    def make_indicators(self, indicators_data) -> List[Indicator]:
        """Make netskope indicators from indicator data.

        Args:
            indicators_data (List[Dict]): List of dictionary contain url info.

        Raises:
            requests.exceptions.HTTPError: Raise error while getting response.

        Returns:
            List[Indicator]: Returns list of indicators.
        """
        indicators = []
        invalid_iocs = 0
        for index in range(0, len(indicators_data), MAX_REQUEST_URL):
            decode_url, headers = self._get_auth_headers(
                self.configuration, "/api/ttp/url/decode-url"
            )
            response = requests.post(
                decode_url,
                json={
                    "data": indicators_data[index: index + MAX_REQUEST_URL]
                },
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            response.raise_for_status()
            response = response.json()
            if response.get("data", []):
                indicators.extend(
                    Indicator(
                        value=urls_info.get("url", " "),
                        type=IndicatorType.URL,
                    )
                    for urls_info in response.get("data", [])
                )

            if response.get("fail", []):
                for urls_info in response.get("fail", []):
                    if not urls_info.get("errors", []):
                        indicators.append(
                            Indicator(
                                value=urls_info.get("key", "").get("url", ""),
                                type=IndicatorType.URL,
                            )
                        )
                    elif "Token is invalid" in urls_info.get("errors", [])[
                        0
                    ].get("message", " "):
                        invalid_iocs += 1
                    else:
                        raise requests.exceptions.HTTPError(
                            f"Error while pulling data from mimecast, "
                            f"{urls_info.get('errors', []).get('message', '')}"
                        )
        if invalid_iocs != 0:
            self.logger.warn(
                f"Skipping, {invalid_iocs} invalid IoC(s) from Pulling."
            )
        return indicators

    def get_decoded_urls(self, rewritten_urls) -> List[Indicator]:
        """Return decoded url from rewritten url.

        Args:
            rewritten_urls (List): List of rewritten url.

        Returns:
            List[Indicator]: Return list of Indicators.
        """
        indicators = []
        indicators_data = [{"url": url} for url in rewritten_urls]
        try:
            indicators += self.make_indicators(indicators_data)
            return indicators
        except Exception as e:
            self.logger.error(str(e))

    def pull(self) -> List[Indicator]:
        """Pull the indicators from Mimecast."""
        # Get start time based on checkpoint
        if not self.last_run_at:
            self.logger.info(
                f"Mimecast Plugin: This is initial data fetch for indicator "
                f"feed since "
                f"checkpoint is empty. Querying indicators for last "
                f"{self.configuration['days']} day(s)."
            )
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
        else:
            start_time = self.last_run_at

        indicators = []

        # MALWARE
        if self.configuration["feed_type"] in [
            "malware_customer",
            "malware_grid",
        ]:
            url, headers = self._get_auth_headers(
                self.configuration, "/api/ttp/threat-intel/get-feed"
            )
            start_time = start_time.replace(microsecond=0)
            current_time = datetime.now()
            while start_time < current_time:
                body = {
                    "data": [
                        {
                            "fileType": "csv",
                            "start": f"{start_time.astimezone().isoformat()}",
                            "feedType": self.configuration["feed_type"],
                        }
                    ]
                }

                response = requests.post(
                    url,
                    json=body,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
                response.raise_for_status()
                if response.status_code == 200:
                    try:
                        indicators += self._parse_csv(
                            response.text,
                            self.configuration.get("indicator_type", ["MD5", "SHA256"])
                        )
                    except Exception as ex:
                        self.logger.error(
                            f"Mimecast Plugin: Error occurred while parsing CSV "
                            f"response: {repr(ex)}"
                        )
                start_time = start_time + timedelta(days=1)
        # MALSITE
        else:
            rewritten_urls = self.get_rewritten_urls(start_time)
            indicators = self.get_decoded_urls(rewritten_urls)
        return indicators

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push the given list of indicators to Mimecast."""
        # First check if push is enabled
        if action_dict["value"] == "operation":
            # Prepare list of only file hashes
            hashes = []
            for indicator in indicators:
                if indicator.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                    hashes.append(
                        {
                            "hash": indicator.value,
                            # Length of description is required to be <= 20 on
                            # Mimecast.
                            "description": indicator.comments
                            if len(indicator.comments) <= 20
                            else "",
                        }
                    )

            # If all the indicators are of type other than file hash, skip.
            if len(hashes) == 0:
                return PushResult(
                    success=False,
                    message="Found no indicators eligible for pushing to "
                    "Mimecast. Only file hashes are supported. Skipping.",
                )

            body = {
                "data": [
                    {
                        "hashList": [],
                        "operationType": action_dict.get("parameters", {}).get("operation_type", ""),
                    }
                ]
            }

            # Mimecast only supports "push" in batch of 1000 indicators at a
            # time
            batch_size = 1000
            for pos in range(0, len(hashes), batch_size):
                url, headers = self._get_auth_headers(
                    self.configuration,
                    "/api/byo-threat-intelligence/create-batch",
                )
                body["data"][0]["hashList"] = hashes[
                    pos : pos + batch_size  # noqa
                ]

                response = requests.post(
                    url,
                    json=body,
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
                response.raise_for_status()
                failures = response.json().get("fail", [])
                if failures:
                    return PushResult(
                        success=False,
                        message=", ".join(self._parse_errors(failures)),
                    )

            return PushResult(
                success=True, message="Pushed all the indicators successfully."
            )
        # PUSH URL
        elif action_dict["value"] == "managed_url":
            indicators_data = []
            for indicator in indicators:
                if indicator.type == IndicatorType.URL and len(
                    indicator.value
                ):
                    indicators_data.append(
                        {
                            "url": indicator.value,
                            "action": action_dict.get("parameters").get(
                                "action_type"
                            ),
                        }
                    )
            invalid_urls = 0
            already_exists = 0
            for index in range(0, len(indicators_data), MAX_CREATE_URL):
                url, headers = self._get_auth_headers(
                    self.configuration, "/api/ttp/url/create-managed-url"
                )
                response = requests.post(
                    url,
                    json={
                        "data": indicators_data[index: index + MAX_CREATE_URL]
                    },
                    headers=add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
                response.raise_for_status()
                response = response.json()
                if response.get("fail", []):
                    for urls_info in response.get("fail", []):
                        errors = urls_info.get("errors", [])
                        if not errors:
                            continue
                        elif "The URL is invalid" in errors[0].get(
                            "message", " "
                        ):
                            invalid_urls += 1
                        elif errors[0].get("code", " ") in [
                            "err_managed_url_exists_code",
                            "err_managed_url_create_failure",
                        ]:
                            already_exists += 1
                        else:
                            self.logger.error(
                                f"Error while pushing IoC(s): "
                                f"{errors[0].get('message',' ')}"
                            )
                            return PushResult(
                                success=False,
                                message=f"Error while pushing IoC(s): "
                                f"{errors[0].get('message',' ')}",
                            )
            if invalid_urls:
                self.logger.warn(
                    f"Skipping, {invalid_urls} invalid URL(s) while pushing."
                )
            if already_exists:
                self.logger.warn(
                    f"Skipping, {already_exists} IoC(s) as they already exist "
                    f"on Mimecast."
                )
            return PushResult(
                success=True,
                message="Pushed all the indicators successfully.",
            )

    def _get_auth_headers(
        self, configuration: dict, endpoint: str
    ) -> (str, dict):
        """Generate the Mimecast authentication headers."""
        request_url = configuration.get("url").strip("/") + endpoint
        request_id = str(uuid.uuid4())
        request_datetime = (
            datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
        )

        # Create the HMAC SHA1 of the Base64 decoded secret key for the
        # Authorization header
        hmac_sha1 = hmac.new(
            base64.b64decode(configuration.get("secret_key")),
            ":".join(
                [
                    request_datetime,
                    request_id,
                    endpoint,
                    configuration.get("app_key"),
                ]
            ).encode("utf-8"),
            digestmod=hashlib.sha1,
        ).digest()

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": "MC "
            + configuration.get("access_key")
            + ":"
            + sig.decode("utf-8"),
            "x-mc-app-id": configuration.get("app_id"),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        return request_url, headers

    def _validate_credentials(
        self, configuration: dict
    ) -> (ValidationResult, List[str]):
        """Validate credentials by making REST API call."""
        try:
            url, headers = self._get_auth_headers(
                configuration, "/api/account/get-account"
            )
            response = requests.post(
                url,
                json={"data": []},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

            if response.status_code == 200:
                failures = response.json().get("fail", [])
                if not failures:
                    return ValidationResult(
                        success=True, message="Validation successful."
                    ), response.json().get("data", [{}])[0].get("packages", [])
                return (
                    ValidationResult(
                        success=False,
                        message=", ".join(self._parse_errors(failures)),
                    ),
                    None,
                )

            elif response.status_code == 401:
                return (
                    ValidationResult(
                        success=False,
                        message="Incorrect access key or secret key or "
                        "application key provided.",
                    ),
                    None,
                )
            else:
                return (
                    ValidationResult(
                        success=False,
                        message=(
                            f"An HTTP error occurred while validating "
                            f"configuration parameters. "
                            f"Status code {response.status_code}."
                        ),
                    ),
                    None,
                )
        except requests.ConnectionError as ex:
            self.logger.error(repr(ex))
            return (
                ValidationResult(
                    success=False,
                    message="Incorrect Mimecast base URL provided.",
                ),
                None,
            )
        except Exception as ex:
            self.logger.error(repr(ex))
            return (
                ValidationResult(
                    success=False,
                    message="Error occurred while validating configuration "
                    "parameters. Check logs for more detail.",
                ),
                None,
            )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configurations."""
        if (
            "url" not in configuration
            or not configuration["url"].strip()
            or type(configuration["url"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Mimecast base URL must be a valid non-empty "
                "string."
            )
            return ValidationResult(
                success=False,
                message="Mimecast base URL must be a valid non-empty string.",
            )

        if (
            "app_id" not in configuration
            or not configuration["app_id"].strip()
            or type(configuration["app_id"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Application ID must be a valid non-empty "
                "string."
            )
            return ValidationResult(
                success=False,
                message="Application ID must be a valid non-empty string.",
            )

        if (
            "app_key" not in configuration
            or not configuration["app_key"].strip()
            or type(configuration["app_key"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Application Key must be a valid non-empty "
                "string."
            )
            return ValidationResult(
                success=False,
                message="Application Key must be a valid non-empty string.",
            )

        if (
            "access_key" not in configuration
            or not configuration["access_key"].strip()
            or type(configuration["access_key"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Access Key must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Access Key must be a valid non-empty string.",
            )

        if (
            "secret_key" not in configuration
            or not configuration["secret_key"].strip()
            or type(configuration["secret_key"]) != str
            or
            # Base 64 check
            not re.match(
                r"^([A-Za-z0-9+/]{4})"
                r"*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
                configuration["secret_key"],
            )
        ):
            self.logger.error(
                "Mimecast Plugin: Access Secret must be a valid non-empty "
                "string."
            )
            return ValidationResult(
                success=False,
                message="Access Secret must be a valid non-empty string.",
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    "Mimecast Plugin: Invalid number of initial days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid number of initial days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid number of initial days provided.",
            )

        if "feed_type" not in configuration or configuration[
            "feed_type"
        ] not in ["malware_customer", "malware_grid", "malsite"]:
            self.logger.error(
                "Mimecast Plugin: Value of Feed Type must be either "
                "'malware_customer' or 'malware_grid'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Feed Type' provided. Allowed "
                "values are 'malware_customer' or 'malware_grid'.",
            )

        try:
            if (
                configuration["feed_type"] in ["malware_customer", "malware_grid"]
                and configuration["indicator_type"]
                not in [["MD5"], ["SHA256"], ["MD5", "SHA256"], ["SHA256", "MD5"]]
            ):
                self.logger.error(
                    "Mimecast Plugin: Value of Indicator type must be either "
                    "'MD5' or 'SHA256'."
                )
                return ValidationResult(
                    success=False,
                    message="Mimecast Plugin: Value of Indicator type must be either "
                    "'MD5' or 'SHA256'.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Mimecast Plugin: Value of Indicator type must be either "
                "'MD5' or 'SHA256'.",
            )

        validation_result, packages = self._validate_credentials(configuration)

        # If credentials are invalid
        if not validation_result.success:
            return validation_result

        return validation_result

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Perform Operation", value="operation"),
            ActionWithoutParams(
                label="Create Managed URL", value="managed_url"
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        if action.value not in ["operation", "managed_url"]:
            return ValidationResult(
                success=False, message="Unsupported target provided."
            )
        _, packages = self._validate_credentials(self.configuration)
        if (
            action.value == "operation"
            and "BYO: Threat Intelligence [1089]" not in packages
        ):
            return ValidationResult(
                success=False,
                message="'Bring Your Own Threat Intel' package is not enabled "
                "in configured account and hence push is not supported. "
                "Disable push and try again.",
            )
        if action.value == "operation" and action.parameters.get(
            "operation_type"
        ) not in [
            "ALLOW",
            "BLOCK",
            "DELETE",
        ]:
            return ValidationResult(
                success=False,
                message="Invalid value of Operation Type provided.",
            )
        if action.value == "managed_url" and action.parameters.get(
            "action_type"
        ) not in [
            "permit",
            "block",
        ]:
            return ValidationResult(
                success=False,
                message="Invalid value of Action Type provided.",
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "operation":
            return [
                {
                    "label": "Operation Type",
                    "key": "operation_type",
                    "type": "choice",
                    "choices": [
                        {"key": "ALLOW", "value": "ALLOW"},
                        {"key": "BLOCK", "value": "BLOCK"},
                        {"key": "DELETE", "value": "DELETE"},
                    ],
                    "mandatory": True,
                    "default": "ALLOW",
                    "description": "The action to take based on the "
                    "batch of indicators. "
                    "For example, a file-hash can be added with a BLOCK "
                    "action to prevent the delivery "
                    "of a message with an attachment matching that file-hash.",
                }
            ]
        elif action.value == "managed_url":
            return [
                {
                    "label": "Action Type",
                    "key": "action_type",
                    "type": "choice",
                    "choices": [
                        {"key": "BLOCK", "value": "block"},
                        {"key": "PERMIT", "value": "permit"},
                    ],
                    "mandatory": True,
                    "default": "permit",
                    "description": "The action to take based on the "
                    "batch of indicators. "
                    "For example, a url can be black listed with a BLOCK "
                    "action type and white listed with PERMIT action type.",
                }
            ]
