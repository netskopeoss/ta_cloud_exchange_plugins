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

"""MCASB implementation to push and pull the data."""


import requests
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.utils import add_user_agent


PAGE_SIZE = 50


class MicrosoftCASBPlugin(PluginBase):
    """The TAXIIPlugin implementation."""

    def _create_tags(self, utils):
        if not utils.exists(self.configuration["tag"].strip()):
            utils.create_tag(
                TagIn(name=self.configuration["tag"].strip(), color="#ED3347")
            )

    def pull(self):
        """Pull data from MCAS."""
        utils = TagUtils()
        if self.configuration["enable_tagging"] == "yes":
            self._create_tags(utils)
            tagging = True
        else:
            tagging = False
        domains = []
        skip = 0
        while True:
            response = requests.get(
                f"{self.configuration['url'].strip('/')}/api/discovery_block_scripts/",
                params={"type": "banned", "limit": PAGE_SIZE, "skip": skip},
                headers=add_user_agent({
                    "Authorization": f"Token {self.configuration['token']}"
                }),
            )
            response.raise_for_status()
            response_json = response.json()
            if response.status_code == 200:
                data = response_json.get("data", [])
                for item in data:
                    domains += item.get("domainList", [])
            skip = skip + PAGE_SIZE
            if not response_json.get("hasNext", False):
                break
        indicators = []
        for domain in domains:
            indicators.append(
                Indicator(
                    value=domain,
                    type=IndicatorType.URL,
                    tags=[self.configuration["tag"].strip()]
                    if tagging
                    else [],
                )
            )
        if tagging:
            utils.on_indicators(
                {"source": self.name, "value": {"$nin": domains}}
            ).remove(self.configuration["tag"].strip())
        return indicators

    def _validate_credentials(self, url: str, token: str):
        """Validate API credentials."""
        try:
            response = requests.get(
                f"{url.strip('/')}/api/discovery_block_scripts/",
                params={"type": "banned", "limit": 1},
                headers=add_user_agent({"Authorization": f"Token {token}"}),
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 401:
                return ValidationResult(
                    success=False, message="Invalid API Token provided."
                )
            elif response.status_code == 404:
                return ValidationResult(
                    success=False, message="Invalid URL provided."
                )
            else:
                return ValidationResult(
                    success=False, message="Could not verify credentials."
                )
        except Exception as ex:
            self.logger.error(f"MCASB Plugin: {repr(ex)}")
            return ValidationResult(
                success=False, message="Could not verify credentials."
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if "url" not in configuration or not configuration["url"].strip():
            self.logger.error(
                "MCASB Plugin: No url key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid URL provided."
            )

        if "token" not in configuration or not configuration["token"].strip():
            self.logger.error(
                "MCASB Plugin: No token key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid token provided."
            )

        if "tag" not in configuration or not configuration["tag"].strip():
            self.logger.error(
                "MCASB Plugin: No tag key found in the configuration parameters.."
            )
            return ValidationResult(
                success=False, message="Invalid tag name provided."
            )

        if len(configuration["tag"].strip()) > 50:
            return ValidationResult(
                success=False, message="Tag name can not exceed 50 characters."
            )

        return self._validate_credentials(
            configuration["url"], configuration["token"]
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate mcas configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
