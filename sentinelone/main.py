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


import requests
from netskope.common.utils import add_user_agent
from datetime import datetime, timedelta
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
)


MAX_PAGE_SIZE = 50


class SentinelOnePlugin(PluginBase):
    """The SentinelOne plugin implementation."""

    def _get_site_id(self, name, url=None, token=None):
        response = requests.get(
            f"{(url if url else self.configuration.get('url')).strip('/')}/web/api/v2.0/sites",
            params={"name": name},
            headers=add_user_agent(
                {
                    "Authorization": f"ApiToken {token if token else self.configuration.get('token')}"
                }
            ),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        if response.status_code != 200:
            self.logger.error(
                "SentinelOne Plugin: Error occurred while fetching siteId."
            )
            return None
        try:
            return response.json()["data"]["sites"][0]["id"]
        except Exception:
            self.logger.error(
                f"SentinelOne Plugin: Site {name} does not exist."
            )
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
        url = f"{self.configuration['url'].strip('/')}/web/api/v2.0/threats"
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
        if self.configuration["site"]:
            site_id = self._get_site_id(self.configuration["site"])
            if site_id is None:
                return
            params["siteIds"] = site_id
        while True:
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
            data = response.json()
            for alert in data["data"]:
                if not alert.get("fileSha256", None):
                    continue
                indicators.append(
                    Indicator(
                        value=alert["fileSha256"],
                        type=IndicatorType.SHA256,
                        comments=(
                            f"{alert['classification']}: "
                            f"{self.configuration['url'].strip('/')}/analyze/threats/{alert['id']}/overview"
                        ),
                        firstSeen=self._str_to_datetime(
                            alert.get("createdAt")
                        ),
                        lastSeen=self._str_to_datetime(alert.get("updatedAt")),
                    )
                )
            params["cursor"] = data["pagination"]["nextCursor"]
            if params["cursor"] is None:
                break
        return indicators

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
                return ValidationResult(
                    success=False, message=f"Could not find the site '{site}'"
                )
            params["siteIds"] = site_id
        response = requests.get(
            f"{url.strip('/')}/web/api/v2.0/threats",
            params=params,
            headers=add_user_agent({"Authorization": f"ApiToken {token}"}),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        if response.status_code == 401:
            return ValidationResult(
                success=False, message="Invalid API Token provided."
            )
        elif response.status_code == 403:
            return ValidationResult(
                success=False,
                message=f"Provided API Token does not have rights to access the site '{site}'.",
            )
        elif response.status_code != 200:
            return ValidationResult(
                success=False,
                message=(
                    f"Could not validate API credentials. "
                    f"HTTP status code {response.status_code} occurred."
                ),
            )
        return ValidationResult(success=True, message="Validation successful.")

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "url" not in configuration
            or type(configuration["url"]) != str
            or not configuration["url"]
        ):
            self.logger.error(
                "SentinelOne Plugin: No url key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid URL provided."
            )

        if (
            "token" not in configuration
            or type(configuration["token"]) != str
            or not configuration["token"]
        ):
            self.logger.error(
                "SentinelOne Plugin: No token name key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid token provided."
            )

        if "site" not in configuration or type(configuration["site"]) != str:
            self.logger.error(
                "SentinelOne Plugin: No site name key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid site name provided."
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    "SentinelOne Plugin: Validation error occured Error: Invalid days provided."
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
        try:
            return self._validate_credentials(
                configuration["url"],
                configuration["token"],
                configuration["site"],
            )
        except requests.ConnectionError:
            return ValidationResult(
                success=False,
                message=f"Could not connect to the URL {configuration['url']}",
            )
        except Exception as ex:
            self.logger.error(
                "SentinelOne Plugin: Could not validate configuration."
            )
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False, message="Could not validate the configuration."
            )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate SentinelOne configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
