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

"""SentinelOne CTE Plugin implementation to push and pull the data from SentinelOne
Platform."""

import requests
from netskope.common.utils import add_user_agent
from datetime import datetime, timedelta
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from typing import List, Dict
from pydantic import ValidationError
from requests.models import Response

MAX_PAGE_SIZE = 50
LIMIT = 2500
PLUGIN_NAME = "SentinelOne CTE Plugin"


class SentinelOneException(Exception):
    """SentinelOne exception class."""

    pass


class SentinelOnePlugin(PluginBase):
    """The SentinelOne cte plugin implementation."""

    def handle_error(self, resp: Response):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API
            call.
        Returns:
            dict: Returns the dictionary of response JSON when the response
            code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        err_msg = f"Response code {resp.status_code} received."
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.logger.error(
                    f"{PLUGIN_NAME}: Response is not JSON format. "
                )
                raise SentinelOneException(
                    f"{PLUGIN_NAME}: Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SentinelOneException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Error"
            )

    def _get_site_id(self, name, url=None, token=None):
        response = requests.get(
            f"{(url if url else self.configuration.get('url','').strip()).strip('/')}/web/api/v2.0/sites",
            params={"name": name},
            headers=add_user_agent(
                {
                    "Authorization": f"ApiToken {token if token else self.configuration.get('token')}"
                }
            ),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        resp_json = self.handle_error(response)
        if not resp_json:
            self.logger.error(
                f"{PLUGIN_NAME}: Error occurred while fetching siteId."
            )
        try:
            return (
                resp_json.get("data", {}).get("sites", [])[0].get("id", None)
            )
        except Exception:
            self.logger.error(f"{PLUGIN_NAME}: Site {name} does not exist.")
            return None

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string (str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(
                string.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"
            )
        except Exception:
            return datetime.now()

    def pull(self):
        """Pull indicators from SentinelOne."""
        end_time = datetime.now()
        url = f"{self.configuration['url'].strip().strip('/')}/web/api/v2.0/threats"
        if not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
        else:
            start_time = self.last_run_at
        indicators = []
        params = {
            "createdAt__gte": f"{start_time.isoformat()}Z",
            "createdAt__lte": f"{end_time.isoformat()}Z",
            "limit": MAX_PAGE_SIZE,
        }
        cursor = None
        if self.configuration["site"]:
            site_id = self._get_site_id(self.configuration["site"])
            if site_id is None:
                return
            params["siteIds"] = site_id
        while True:
            if cursor:
                params["cursor"] = cursor
            response = requests.get(
                url,
                params=params,
                headers=add_user_agent(
                    {
                        "Authorization": f"ApiToken {self.configuration['token']}"
                    }
                ),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

            data = self.handle_error(response)
            for alert in data.get("data", []):
                if not alert.get("fileSha256", None):
                    continue
                try:
                    indicators.append(
                        Indicator(
                            value=alert.get("fileSha256"),
                            type=IndicatorType.SHA256,
                            comments=(
                                f"{alert.get('classification','')}: "
                                f"{self.configuration['url'].strip().strip('/')}/analyze/threats/{alert.get('id')}/overview"
                            ),
                            firstSeen=self._str_to_datetime(
                                alert.get("createdAt")
                            ),
                            lastSeen=self._str_to_datetime(
                                alert.get("updatedAt")
                            ),
                        )
                    )
                except ValidationError as err:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while pulling IOCs. Hence skipping {alert.get('fileSha256',None)}",
                        details=f"Error Details: {err}",
                    )

            cursor = data.get("pagination", {}).get("nextCursor")
            if cursor is None:
                break
        return indicators

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push indicators to the SentinelOne.

        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary

        Returns:
            PushResult : return PushResult with success and message parameters.
        """
        indicators_data = []
        headers = {"Authorization": f"ApiToken {self.configuration['token']}"}
        error_occur = False
        ioc_url = f"{self.configuration['url'].strip().strip('/')}/web/api/v2.1/threat-intelligence/iocs"
        if action_dict["value"] == "create_iocs":
            # Threat IoCs
            for indicator in indicators:
                indicators_data.append(
                    {
                        "value": indicator.value,
                        "type": indicator.type.upper(),
                        "source": "Netskope",
                        "externalId": indicator.value,
                        "method": "EQUALS",
                        "creationTime": indicator.firstSeen.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                        ),
                        "validUntil": indicator.expiresAt.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                        )
                        if indicator.expiresAt
                        else None,
                        "description": indicator.comments,
                    }
                )

            for chunked_list in self.divide_in_chunks(indicators_data, LIMIT):
                indicator_json_data = {
                    "data": chunked_list,
                    "filter": {},
                }
                response = requests.post(
                    ioc_url,
                    headers=headers,
                    json=indicator_json_data,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
                if not self.handle_error(response):
                    error_occur = True
                    break

            if not error_occur:
                return PushResult(
                    success=True,
                    message="Indicators pushed successfully to SentinelOne.",
                )
            else:
                return PushResult(
                    success=False,
                    message="Indicators failed to push to SentinelOne.",
                )

    def _validate_credentials(
        self, url: str, token: str, site: str
    ) -> ValidationResult:
        """Validate API Credentials.

        Args:
            token (str): API Token.
            site (str): Site name.

        Returns:
            ValidationResult: Validation result.
        """
        params = {"limit": 1}
        if site:
            site_id = self._get_site_id(site, url, token)
            if site_id is None:
                err_msg = f"Could not find the Site {site}"
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            params["siteIds"] = site_id
        response = requests.get(
            f"{url.strip().strip('/')}/web/api/v2.0/threats",
            params=params,
            headers=add_user_agent({"Authorization": f"ApiToken {token}"}),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        if response.status_code == 200:
            response.json()
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        elif response.status_code == 401:
            err_msg = "Invalid API Token provided."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif response.status_code == 403:
            err_msg = (
                f"API Token does not have rights to access the site '{site}'."
            )
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        else:
            err_msg = (
                f"Validation error occurred with response {response.json()}"
            )
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred.",
                details=f"Error Details: {err_msg}",
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "url" not in configuration
            or type(configuration["url"]) != str
            or not configuration["url"].strip()
        ):
            err_msg = "Management URL is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            "token" not in configuration
            or type(configuration["token"]) != str
            or not configuration["token"].strip()
        ):
            err_msg = "API Token is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if "site" not in configuration or type(configuration["site"]) != str:
            err_msg = "Invalid Site Name Provided."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                err_msg = "Invalid Initial Range Provided."
                self.logger.error(
                    f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except ValueError:
            err_msg = "Invalid Initial Range Provided."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        try:
            return self._validate_credentials(
                configuration["url"].strip(),
                configuration["token"].strip(),
                configuration["site"],
            )
        except Exception as err:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred.",
                details=f"Error Details: {err}",
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Create IoCs",
                value="create_iocs",
            ),
        ]

    def validate_action(self, action: Action):
        """Validate SentinelOne Action Configuration."""
        if action.value not in ["create_iocs"]:
            return ValidationResult(success=False, message="Invalid action.")
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
