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

"""Sophos CTE Plugin providing implementation for pull and validate methods from PluginBase."""

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from pydantic import ValidationError
import requests


PLUGIN_NAME = "Sophos CTE Plugin"

SEVERITY_MAPPING = {
    "unknown": SeverityType.UNKNOWN,
    "low": SeverityType.LOW,
    "medium": SeverityType.MEDIUM,
    "high": SeverityType.HIGH,
    "critical": SeverityType.CRITICAL,
}


class SophosException(Exception):
    """Sophos Exception class."""

    pass


class SophosPlugin(PluginBase):
    """Sophos class template implementation."""

    def handle_error(self, resp: requests.models.Response):
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
                err_msg = "Error occurred while parsing response to json."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                raise SophosException(f"{PLUGIN_NAME}: {err_msg}")
        elif resp.status_code == 401:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Error"
            )

    def get_authorization_token(self, configuration):
        """Get authorization token from Sophos"""
        url = "https://id.sophos.com/api/v2/oauth2/token"

        payload = f"grant_type=client_credentials&scope=token&client_id={configuration.get('client_id').strip()}&client_secret={configuration.get('client_secret').strip()}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request(
            "POST",
            url,
            headers=add_user_agent(headers),
            data=payload,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        if response.status_code == 200:
            try:
                access_token = response.json().get("access_token")
                return access_token
            except Exception as err:
                self.logger.error(
                    message=f"{PLUGIN_NAME}: Validation error occurred.",
                    details=f"Error Details: {err}",
                )
                raise SophosException(
                    f"{PLUGIN_NAME}: Validation error occurred. Error: {err}."
                )
        elif response.status_code == 401 or response.status_code == 400:
            err_msg = "Invalid Client ID or Client Secret provided."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise requests.HTTPError(err_msg)
        else:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred.",
                details=f"Error Details: {response.json()}",
            )
            raise requests.HTTPError(
                f"{PLUGIN_NAME}: Validation error occurred with response {response.json()}"
            )

    def get_tenant_info(self, access_token):
        """Get Tenant_id and DataRegion from Sophos"""
        err_msg = "Error occurred while fetching tenant id and data region"

        url = "https://api.central.sophos.com/whoami/v1"
        payload = {}
        headers = {"Authorization": f"Bearer {access_token}"}

        response = requests.request(
            "GET",
            url,
            headers=add_user_agent(headers),
            data=payload,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        try:
            resp_json = self.handle_error(response)
            tenant_id = resp_json.get("id")
            dataRegion = resp_json.get("apiHosts", {}).get("dataRegion")

            return tenant_id, dataRegion

        except Exception as err:
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=f"Error details: {err}",
            )

    def pull(self):
        """Pull indicators from Sophos."""

        access_token = self.get_authorization_token(self.configuration)
        if not access_token:
            err_msg = "Error occurred while fetching Access Token from Sophos Platform"
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise SophosException(err_msg)

        tenant_id, dataRegion = self.get_tenant_info(access_token)
        cursor = None
        indicators = []
        params = {"limit": 200}
        payload = {}
        headers = {
            "X-Tenant-ID": tenant_id,
            "Authorization": f"Bearer {access_token}",
        }

        while True:
            if cursor:
                params["cursor"] = cursor
            response = requests.request(
                "GET",
                dataRegion + "/siem/v1/events",
                params=params,
                headers=add_user_agent(headers),
                data=payload,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

            data = self.handle_error(response)

            for item in data.get("items", []):

                if not item.get("appSha256"):
                    continue
                try:
                    indicators.append(
                        Indicator(
                            value=item.get("appSha256"),
                            type=IndicatorType.SHA256,
                            comments=item.get("threat", ""),
                            severity=SEVERITY_MAPPING.get(
                                item.get("severity", "").lower(),
                                SeverityType.UNKNOWN,
                            ),
                        )
                    )
                except ValidationError as err:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while pulling IOCs. Hence skipping {item.get('appSha256', None)}",
                        details=f"Error Details: {err}",
                    )
            cursor = data.get("next_cursor")
            if data.get("has_more") == False:
                break
        return indicators

    def validate(self, data):
        """Validate the Plugin configuration parameters.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        if (
            "client_id" not in data
            or type(data["client_id"]) != str
            or not data["client_id"].strip()
        ):
            err_msg = "Client ID is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            "client_secret" not in data
            or type(data["client_secret"]) != str
            or not data["client_secret"].strip()
        ):
            err_msg = "Client Secret is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            if self.get_authorization_token(data):
                return ValidationResult(
                    success=True,
                    message="Validation Successful.",
                )
            else:
                self.logger.error(
                    message=f"{PLUGIN_NAME}: Validation error occurred. Error Details: Unable to fetch access token with provided credentials.",
                )
                return ValidationResult(
                    success=False,
                    message="Validation error occurred.",
                )
        except requests.HTTPError as err:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred. Error occurred while validating credentials",
                details=f"Error Details: {err}",
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )
        except Exception as err:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred.",
                details=f"Error Details: {err}",
            )
            return ValidationResult(
                success=False,
                message="Validation error occurred. Check logs for more details.",
            )
