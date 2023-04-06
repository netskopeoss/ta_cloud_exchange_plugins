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

"""Skyhigh CASB Published URL Plugin providing implementation for pull and validate methods from PluginBase."""

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
import requests

PLUGIN_NAME = "CTE Skyhigh CASB Published URL Plugin:"


class SkyhighPlugin(PluginBase):
    """Skyhigh CASB Published URL Plugin class template implementation."""

    def pull(self):
        """Pull indicators from Skyhigh CASB Published URL"""

        url = self.configuration['url'].strip()
        indicator_comment = ""
        category = self.configuration.get('category', '').strip()
        if category:
            category = category.split(',')
            invalid_category = [cat.strip() for cat in category]
            category = [f"Define category {cat.strip()}" for cat in category]
        else:
            category = []
            invalid_category = []

        try:
            response = requests.get(
                url=url,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            resp = self.handle_error(response)

            indicators = []
            start_collecting = False

            for line in resp.splitlines():
                if f"Define category" in line:
                    category_name = line.replace("Define category ", "").strip()
                    indicator_comment = f"Defined in category: {category_name}"
                    if line in category:
                        start_collecting = True
                        try:
                            invalid_category.remove(category_name)
                        except:
                            pass
                    continue
                if "end" == line.lower():
                    start_collecting = False
                    continue
                if start_collecting or not category:
                    indicators.append(
                        Indicator(
                            value=line,
                            comments=indicator_comment,
                            type=IndicatorType.URL,
                        )
                    )

            if invalid_category:
                self.logger.warn(f"{PLUGIN_NAME} Could not find category with name {', '.join(invalid_category)} for the given URL")
            return indicators

        except requests.exceptions.ProxyError as e:
            err_msg = "Validation error, Invalid proxy configuration."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.ConnectionError as e:
            err_msg = "Validation Error, Unable to establish connection to Skyhigh."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.HTTPError as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation error occurred. "
                f"Exception: {exp}"
            )
            return ValidationResult(
                success=False,
                message=str(exp)
            )
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation error. "
                f"Exception: {exp}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Please check logs for more details"
            )

    def handle_error(self, response):
        if response.status_code == 200:
            return response.text

        if response.status_code == 401:
            err_msg = "Received exit code 401, Authentication Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}."
            )
            raise requests.exceptions.HTTPError(err_msg)
        elif response.status_code == 404:
            err_msg = "Received exit code 404, Resource Not Found"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}."
            )
            raise requests.exceptions.HTTPError(err_msg)
        elif 400 <= response.status_code < 500:
            err_msg = f"Received exit code {response.status_code}, HTTP Client Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}."
            )
            raise requests.exceptions.HTTPError(err_msg)
        elif 500 <= response.status_code < 600:
            err_msg = f"Received exit code {response.status_code}, HTTP Server Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}."
            )
            raise requests.exceptions.HTTPError(err_msg)
        else:
            err_msg = f"Received exit code {response.status_code}, HTTP Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}."
            )
            raise requests.exceptions.HTTPError(err_msg)

    def validate_auth_credentials(self, configuration):

        url = configuration.get("url", "").strip()
        try: 
            response = requests.get(
                url=url,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            _ = self.handle_error(response)
                
            return ValidationResult(    
                success=True,
                message='Successfully validated credentials to Skyhigh'
            )
        except requests.exceptions.ProxyError as e:
            err_msg = "Validation error, Invalid proxy configuration."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.ConnectionError as e:
            err_msg = "Validation Error, Unable to establish connection to Skyhigh."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.HTTPError as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation error occurred. "
                f"Exception: {exp}"
            )
            return ValidationResult(
                success=False,
                message=str(exp)
            )
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation error. "
                f"Exception: {exp}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Please check logs for more details"
            )
        
    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        if (
            "url" not in configuration
            or type(configuration["url"]) != str
            or not configuration["url"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME} Validation error occurred. Error: "
                "Invalid Skyhigh CASB Published URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Skyhigh CASB Published URL provided."
            )

        return self.validate_auth_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate Skyhigh CASB Published URL configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
