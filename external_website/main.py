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

External Website Plugin providing implementation for pull and validate
methods from PluginBase."""
import json
import os
import re
import traceback
from typing import Tuple, List

from netskope.integrations.cte.models import Indicator, IndicatorType

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from urllib.parse import urlparse
from pydantic import ValidationError

from .utils.externalwebsite_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    THREAT_TYPES,
)

from .utils.externalwebsite_helper import (
    ExternalWebsitePluginException,
    ExternalWebsitePluginHelper,
)


class ExternalWebsitePlugin(PluginBase):
    """External Website Plugin class template implementation."""

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
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.externalwebsite_helper = ExternalWebsitePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def pull(self):
        """Pull indicators from External Website Plugin."""

        url = self.configuration['url'].strip()
        indicator_type = self.configuration["type"]
        try:
            self.logger.info(f"{self.log_prefix}: Pulling indicators.")
            response = self.externalwebsite_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="pulling indicators"
            )
            indicators, skipped_count = self.extract_indicators(
                response, indicator_type
            )

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(indicators)} indicator(s)."
            )
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} record(s) as "
                    "IoC value might be empty string or the IoC type does not "
                    'match the "Type of Threat data to pull" '
                    "configuration parameter."
                )
            return indicators

        except ExternalWebsitePluginException as exp:
            err_msg = "Error occurred while pulling indicators."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg}"),
                details=str(traceback.format_exc()),
            )
            raise exp
        except Exception as exp:
            err_msg = "Error occurred while pulling indicators."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise exp

    def extract_indicators(self, response, indicator_type) -> List[dict]:
        indicators = []
        skipped_count = 0
        if "sha256" in indicator_type:
            sha256_list = re.findall(r"\b[a-fA-F0-9]{64}\b", response)
            for sha256 in sha256_list:
                try:
                    indicators.append(
                        Indicator(value=sha256, type=IndicatorType.SHA256)
                    )
                except ValidationError:
                    skipped_count += 1

        if "url" in indicator_type:
            url_ipv4_regex = r'((?:https?://)?(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/[a-zA-Z0-9-._\/~?%&=]*)?)'
            data_into_list = re.findall(url_ipv4_regex, response)
            for item in data_into_list:
                try:
                    indicators.append(
                        Indicator(value=item.strip(),
                                  type=IndicatorType.URL)
                    )
                except ValidationError:
                    skipped_count += 1

        if "md5" in indicator_type:
            md5_list = re.findall(r"(\b[a-fA-F\d]{32}\b)", response)

            for md5 in md5_list:
                try:
                    indicators.append(
                        Indicator(value=md5, type=IndicatorType.MD5))
                except ValidationError:
                    skipped_count += 1
        return indicators, skipped_count

    def is_url(self, url: str) -> bool:
        """Validate URL.
        Args:
            url (str): URL for validation.
        Returns:
            bool: True if URL is valid else False
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def validate_auth_credentials(self, url):
        try:
            self.externalwebsite_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="validating configuration parameters."
            )

            self.logger.debug(f"{self.log_prefix}: Validation successful.")
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        except ExternalWebsitePluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            validation_err = "Validation error occurred."
            err_msg = f"{validation_err} Check logs for more details."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.
        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        url = configuration.get("url", "").strip()
        threat_type = configuration.get("type")
        validation_err = "Validation error occurred."
        if not url:
            err_msg = ("External Website URL is a required "
                       "configuration parameter.")
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not self.is_url(url):
            err_msg = ("Invalid External Website URL provided. External "
                       "Website URL should contain device IP address "
                       "or domain name.")
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if not threat_type:
            err_msg = (
                "Type of Threat data to pull is a required "
                "configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(threat_type in THREAT_TYPES for threat_type in threat_type)
        ):
            err_msg = (
                "Invalid value for 'Type of Threat data to pull' "
                "provided. Allowed values are 'SHA256', 'MD5' or 'URL'."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_credentials(url)
