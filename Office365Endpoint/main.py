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

"""Office 365 Endpoint Plugin providing implementation for pull and validate methods from PluginBase."""

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
from netskope.common.utils import add_user_agent
from pydantic import ValidationError
from .utils.office365_constants import REGIONS, SERVICE_TYPES
import uuid
import requests

PLUGIN_NAME = "Microsoft Office 365 Endpoint CTE Plugin"


class Office365EndpointException(Exception):
    """Office365Endpoint Exception class."""

    pass


class Office365EndpointPlugin(PluginBase):
    """Office365Endpoint class template implementation."""

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
                self.logger.error(
                    f"{PLUGIN_NAME}: Response is not JSON format. "
                )
                raise Office365EndpointException(
                    f"{PLUGIN_NAME}: Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise Office365EndpointException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Error"
            )

    def pull(self):
        """Pull indicators from Office365Endpoint."""

        """Create dynamic client request > requirement for this website"""
        clientRequestId = str(uuid.uuid4())

        """Get all content from location configured on the plugin"""
        region = self.configuration["region"].strip()
        url = f"https://endpoints.office.com/endpoints/{region}"
        params = {"clientRequestId": clientRequestId}

        response = requests.get(
            url,
            params=params,
            headers=add_user_agent(),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        data = self.handle_error(response)
        indicators = []

        if not self.configuration.get("typeservices"):
            services = SERVICE_TYPES
        else:
            services = self.configuration.get("typeservices")
            
        """Append url values into indicators list"""
        for endpointSet in data:
            if endpointSet.get("serviceAreaDisplayName") in services:
                for url in endpointSet.get("urls", []):
                    try:
                        indicators.append(
                            Indicator(
                                value=url,
                                type=IndicatorType.URL,
                            )
                        )
                    except ValidationError as err:
                        self.logger.error(
                            message=f"{PLUGIN_NAME}: Error occurred while pulling IOCs. Hence skipping {url}",
                            details=f"Error Details: {err}",
                        )
        return indicators

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        err_msg = None
        if (
            "region" not in configuration
            or type(configuration.get("region")) != str
            or not configuration["region"].strip()
        ):
            err_msg = "Instance is Required Field."

        if configuration["region"] not in REGIONS:
            err_msg = "Invalid Instance Provided"

        if (
            "typeservices" not in configuration
            or type(configuration.get("typeservices")) != list
        ):
            err_msg = "Type of Services is Required Field."
        if not all(x in SERVICE_TYPES for x in configuration["typeservices"]):
            err_msg = "Invalid Type of Services Provided."

        if not err_msg:
            return ValidationResult(
                success=True,
                message=f"{PLUGIN_NAME}: Validation Successful.",
            )
        else:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
