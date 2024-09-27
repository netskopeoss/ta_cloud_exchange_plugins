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

CTE Secureworks Taegis Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import csv
import json
import traceback
from ipaddress import IPv4Address, ip_address
from typing import Dict, List, Tuple, Union

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
)
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils

from .utils.secureworks_taegis_constants import (
    BASE_URLS,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    THREAT_TYPES,
)
from .utils.secureworks_taegis_helper import (
    SecureworksTaegisPluginException,
    SecureworksTaegisPluginHelper,
)


class SecureworksTaegisPlugin(PluginBase):
    """SecureworksTaegisPlugin class having implementation all
    plugin's methods."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Secureworks Taegis plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.secureworks_taegis_helper = SecureworksTaegisPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version
        )
        self.total_indicators = 0

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = SecureworksTaegisPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_indicator_types(self, threat_types: List) -> Dict:
        """Return a mapping of Indicator Types, Based on the threat types to \
        pull configuration parameter And, Depending on Neskope CE Version.

        Args:
            - threat_types: A list of threat types to pull.
        Returns:
            - Dictionary mapping of Indicator Types to Netskope CE Supported
            Indicator Types.
        """
        indicator_types = {}

        if "domain" in threat_types:
            indicator_types["domain"] = getattr(
                IndicatorType, "DOMAIN", IndicatorType.URL
            )

        if "ip" in threat_types:
            indicator_types["ipv4"] = getattr(IndicatorType, "IPV4", IndicatorType.URL)
            indicator_types["ipv6"] = getattr(IndicatorType, "IPV6", IndicatorType.URL)

        return indicator_types

    def _fetch_ioc_data(self, ioc, ioc_threat_type):
        """
        Fetch IOC data based on the provided URL, type, and name.

        Args:
            ioc: The IOC data to process.
            ioc_threat_type: The type of IOC data.

        Returns:
            list: A list of IOC data fetched from the URL.
        """
        ioc_list = []
        try:
            ioc_url = ioc.get("link", "")
            ioc_name = ioc.get("name", "")
            logger_msg = (
                f"pulling indicators of type '{ioc_threat_type.upper()}' from '{ioc_name}'"
            )
            ioc_resp = self.secureworks_taegis_helper.api_helper(
                url=ioc_url,
                method="GET",
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=logger_msg,
                is_handle_error_required=False,
                is_url_with_auth=True
            )
            ioc_list = list(csv.DictReader(ioc_resp.text.splitlines()))
            return ioc_list
        except Exception as exp:
            err_msg = (
                "Error occurred while fetching indicators."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
        return ioc_list

    def _create_tags(
        self, tags: List[dict], enable_tagging: str
    ) -> Union[List[str], List[str], List[str]]:
        """Create new tag(s) in database if required.

        Args:
            tags (List[dict]): Tags to be created
            enable_tagging (str): Enable/disable tagging

        Returns:
            Union[List[str], List[str]]: Created tags, Skipped tags, Skipped tags value error
        """
        tag_utils = TagUtils()
        tag_names, skipped_tags_val_err, skipped_tags = [], [], []

        if enable_tagging != "yes":
            return [], [], []

        for tag in tags:
            try:
                if tag is not None and not tag_utils.exists(tag.strip()):
                    tag_utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))
            except ValueError:
                skipped_tags_val_err.append(tag)
            except Exception:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags_val_err, skipped_tags

    def _make_indicators(
        self,
        ioc_data: List[Dict],
        indicator_types: Dict,
        ioc_threat_type: str,
        enable_tagging: str,
    ):
        """Add received data to Netskope.

        Args:
            - ioc_data (List[Dict]): List of Dictionary containing ioc details.
            - indicator_types: A mapping of Indicator Types supported by netskope CE.
            - ioc_threat_type (str): The type of IOC data.
            - enable_tagging (Bool): A boolean flag for enable/disable tagging.

        Returns:
            - indicators (List[Indicator]): List of Indicator model objects.
            - total_ioc (int): Total number of IoCs pulled.
            - skipped_ioc (int): Total number of IoCs skipped while creating them.
            - total_skipped_tags (int): Total number of tags skipped while creating them.
        """
        ioc_counts = {ioc_type: 0 for ioc_type in indicator_types}
        skipped_ioc_counts = {ioc_type: 0 for ioc_type in indicator_types}
        skipped_ioc = 0
        indicators = []
        skipped_tags = []
        skipped_tags_due_to_val_err = []

        for indicator in ioc_data:
            try:
                created_tags = []
                indicator_attr = {
                    "comments": indicator.get("ReasonAdded", ""),
                    "firstSeen": indicator.get("MemberSince", ""),
                }


                # IP Addresses (IPV4 & IPv6)
                if ioc_threat_type == "ip":
                    try:
                        indicator_value = indicator.get("HostAddress", "")
                        if isinstance(
                            ip_address(indicator_value), IPv4Address
                        ):
                            ioc_ip_type = "ipv4"
                        else:
                            ioc_ip_type = "ipv6"

                        tags = [indicator.get("WatchList", "").split(" List", 1)[0]] if indicator.get("WatchList", "") else []
                        created, val_err, skipped = self._create_tags(
                            tags=tags,
                            enable_tagging=enable_tagging,
                        )
                        created_tags.extend(created)
                        skipped_tags.extend(skipped)
                        skipped_tags_due_to_val_err.extend(val_err)

                        indicators.append(
                            Indicator(
                                **{
                                    "value": indicator_value,
                                    "type": indicator_types[ioc_ip_type],
                                    "tags": created_tags,
                                    **indicator_attr,
                                }
                            )
                        )
                        ioc_counts[ioc_ip_type] += 1
                    except Exception:
                        skipped_ioc_counts[ioc_ip_type] += 1

                # Domain
                elif ioc_threat_type == "domain":
                    try:
                        indicator_value = indicator.get("HostAddress", "")

                        tags = [indicator.get("WatchList", "").split(" List", 1)[0]] if indicator.get("WatchList", "") else []
                        created, val_err, skipped = self._create_tags(
                            tags=tags,
                            enable_tagging=enable_tagging,
                        )
                        created_tags.extend(created)
                        skipped_tags.extend(skipped)
                        skipped_tags_due_to_val_err.extend(val_err)

                        indicators.append(
                            Indicator(**{
                                "value": indicator_value,
                                "type": indicator_types["domain"],
                                "tags": created_tags,
                                **indicator_attr,
                            })
                        )
                        ioc_counts["domain"] += 1
                    except Exception:
                        skipped_ioc_counts["domain"] += 1

                else:
                    self.logger.warn(
                        message=(
                            "Received unknown ioc type. "
                            "Hence discarding this indicator."
                        ),
                        details=f"Indicator Details: {json.dumps(indicator)}",
                    )
                    skipped_ioc += 1
            except Exception as exp:
                err_msg = (
                    "Error occurred while creating the indicator "
                    "hence this record will be skipped."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                skipped_ioc += 1
                continue

        if len(skipped_tags_due_to_val_err) > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {len(skipped_tags_due_to_val_err)} "
                    "tag(s) skipped as they were longer than expected size: "
                    f"({', '.join(set(skipped_tags_due_to_val_err))})"
                )
            )

        if len(skipped_tags) > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {len(skipped_tags)} tag(s) skipped "
                    "as some failure occurred while creating these tags."
                ),
                details=f"Skipped Tags: ({', '.join(set(skipped_tags))})",
            )

        pull_stats = ", ".join(
            [f"{key.upper()}: {str(val)}" for key, val in ioc_counts.items()]
        )
        self.logger.debug(
            f"{self.log_prefix}: Pull Stats: {pull_stats} indicator(s) were fetched."
        )

        total_ioc = sum(ioc_counts.values())
        total_skipped_ioc = sum(skipped_ioc_counts.values()) + skipped_ioc
        total_skipped_tags = len(skipped_tags) + len(skipped_tags_due_to_val_err)
        return indicators, total_ioc, total_skipped_ioc, total_skipped_tags

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from Secureworks Taegis platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the Secureworks Taegis platform.
        """
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch in self._pull():
                indicators.extend(batch)
            return indicators

    def _pull(self):
        """
        Pull the Threat IoCs from Secureworks Taegis platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the Secureworks Taegis platform.
        """
        total_created_ioc = 0
        total_skipped_ioc = 0
        total_skipped_tag = 0
        indicators = []
        ioc_data = []
        enable_tagging = self.configuration.get("enable_tagging", "yes")
        threat_data_type = self.configuration.get("threat_data_type", [])
        indicator_types = self._get_indicator_types(threat_data_type)

        self.logger.info(f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}.")

        (base_url, client_id, client_secret) = (
            self.secureworks_taegis_helper.get_config_params(self.configuration)
        )

        # Prepare headers.
        headers = self.secureworks_taegis_helper.get_auth_header(
            client_id, client_secret, base_url
        )

        query_endpoint = f"{base_url}/intel-requester/ti-list/latest"
        try:
            resp_json = self.secureworks_taegis_helper.api_helper(
                url=query_endpoint,
                method="GET",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                configuration=self.configuration,
                logger_msg=f"pulling indicators from {PLATFORM_NAME}",
            )

            for ioc_threat_type in threat_data_type:
                for ioc_link in resp_json:
                    if (ioc_threat_type == 'ip' and 'ip-list' in ioc_link['name']) or \
                        (ioc_threat_type == 'domain' and 'domain-list' in ioc_link['name']):
                        ioc_data = self._fetch_ioc_data(ioc_link, ioc_threat_type)
                        if ioc_data:
                            (
                                indicators, created_ioc, skipped_ioc, skipped_tag
                            ) = self._make_indicators(
                                ioc_data, indicator_types, ioc_threat_type, enable_tagging
                            )

                            total_created_ioc += created_ioc
                            total_skipped_ioc += skipped_ioc
                            total_skipped_tag += skipped_tag

                            self.logger.info(
                                f"{self.log_prefix}: Successfully fetched {created_ioc}"
                                f" indicator(s) from '{ioc_link['name']}'. Total fetched "
                                f"{total_created_ioc} indicator(s), Total skipped "
                                f"{total_skipped_ioc} indicator(s), Total skipped "
                                f"{total_skipped_tag} tag(s)."
                            )

                            if hasattr(self, "sub_checkpoint"):
                                yield indicators, {}
                            else:
                                yield indicators
                        else:
                            self.logger.info(
                                f"{self.log_prefix}: No indicator fetched "
                                f"from '{ioc_link['name']}'. Total fetched "
                                f"{total_created_ioc} indicator(s), Total skipped "
                                f"{total_skipped_ioc} indicator(s), Total skipped "
                                f"{total_skipped_tag} tag(s)."
                            )

        except SecureworksTaegisPluginException:
            raise
        except Exception:
            err_msg = (
                f"Unexpected error occurred while pulling "
                f"indicators from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        validation_err_msg = "Validation error occurred"

        # Validate Base URL
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif (base_url not in BASE_URLS) or (not isinstance(base_url, str)):
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f"{err_msg} Select the Base URL from the available options."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client ID
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. " f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client Secret
        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f"{err_msg} Client Secret should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Threat data type
        threat_data_type = configuration.get("threat_data_type", [])
        if not threat_data_type:
            err_msg = (
                "Type of Threat data to pull is a required "
                "configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(
                threat_type in THREAT_TYPES for threat_type in threat_data_type
            )
        ):
            err_msg = (
                "Invalid value provided in the Type of Threat data to "
                "pull configuration parameter. Allowed values are "
                "Domain and IP Address."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Enable Tagging
        enable_tagging = configuration.get("enable_tagging", "").strip()
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif enable_tagging not in ["yes", "no"]:
            err_msg = (
                "Invalid value provided in Enable Tagging configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with Secureworks Taegis platform.

        Args:
            configuration (dict): Configuration parameters dictionary.
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating auth credentials."
            )
            (base_url, client_id, client_secret) = (
                self.secureworks_taegis_helper.get_config_params(configuration)
            )

            # Prepare headers.
            headers = self.secureworks_taegis_helper.get_auth_header(
                client_id, client_secret, base_url, is_validation=True
            )

            query_endpoint = f"{base_url}/intel-requester/ti-list/latest"

            self.secureworks_taegis_helper.api_helper(
                url=query_endpoint,
                method="GET",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=f"checking connectivity with {PLATFORM_NAME} platform",
                is_validation=True,
                regenerate_auth_token=False
            )

            return ValidationResult(
                success=True,
                message=(
                    "Validation successful for {} {} Plugin.".format(
                        MODULE_NAME, self.plugin_name
                    )
                ),
            )

        except SecureworksTaegisPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
