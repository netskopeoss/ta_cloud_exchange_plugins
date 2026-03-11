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

CTE Web Page IOC Scraper Plugin.
"""

import re
import traceback
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, List

from urllib.parse import urlparse
from pydantic import ValidationError

from netskope.integrations.cte.models import Indicator, IndicatorType

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from .utils.externalwebsite_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    THREAT_TYPES,
)

from .utils.externalwebsite_helper import (
    WebPageIOCScraperPluginException,
    WebPageIOCScraperPluginHelper,
)


class WebPageIOCScraperPlugin(PluginBase):
    """Web Page IOC Scraper Plugin class template implementation."""

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
        self.web_page_ioc_scraper_helper = WebPageIOCScraperPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = WebPageIOCScraperPlugin.metadata
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

        if "md5" in threat_types:
            indicator_types["md5"] = IndicatorType.MD5

        if "sha256" in threat_types:
            indicator_types["sha256"] = IndicatorType.SHA256

        if "url" in threat_types:
            indicator_types["url"] = IndicatorType.URL

        if "domain" in threat_types:
            indicator_types["domain"] = getattr(
                IndicatorType, "DOMAIN", IndicatorType.URL
            )

        if "ipv4" in threat_types:
            indicator_types["ipv4"] = getattr(
                IndicatorType, "IPV4", IndicatorType.URL
            )

        if "ipv6" in threat_types:
            indicator_types["ipv6"] = getattr(
                IndicatorType, "IPV6", IndicatorType.URL
            )
        return indicator_types

    def pull(self) -> List[Indicator]:
        """Pull indicators from Web Page IOC Scraper Plugin."""
        url = self.configuration["url"].strip().strip("/")

        try:
            indicator_types = self._get_indicator_types(
                threat_types=self.configuration.get("type", "")
            )
            self.logger.info(f"{self.log_prefix}: Pulling IOC(s) from {url}.")
            response = self.web_page_ioc_scraper_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="pulling IOC(s)",
            )
            indicators, skipped_count, indicator_type_count = (
                self.extract_indicators(response, indicator_types)
            )

            pull_stats = ", ".join(
                [
                    f"{str(val)} {key.upper()}"
                    for key, val in indicator_type_count.items()
                ]
            )
            self.logger.debug(
                f"Pull Stat: {pull_stats} indicator(s) were fetched. "
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{sum(indicator_type_count.values())} IOC(s) "
                f"from '{url}'."
            )
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} record(s) as "
                    "IOC value might be duplicate, invalid or the IOC"
                    ' type does not match the "Type of Threat data to pull" '
                    "selected in the configuration parameter."
                )
            return indicators

        except WebPageIOCScraperPluginException as exp:
            err_msg = "Error occurred while pulling indicators."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {str(exp)}"),
                details=str(traceback.format_exc()),
            )
            raise exp
        except Exception as exp:
            err_msg = "Error occurred while pulling indicators."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {str(exp)}"),
                details=str(traceback.format_exc()),
            )
            raise exp

    def extract_indicators(
        self, response, indicator_types: Dict
    ) -> List[dict]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicator_types (Dict): A dictionary mapping indicator types to \
                                    their corresponding values.

        Returns:
            Tuple[List[dict], int]: A tuple containing a list of extracted \
                                    indicators and the number of skipped indicators.
        """
        all_indicators_set = set()
        indicators = []
        exact_indicators = []
        extracted_domains = []
        extracted_domains_2 = []
        skipped_count = 0
        exact_skipped_count = 0
        extracted_skipped_count = 0
        domain_flag = False
        indicator_type_count = {
            "sha256": 0,
            "md5": 0,
            "url": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
        }

        if "sha256" in indicator_types:
            sha256_regex = r"\b[a-fA-F0-9]{64}\b"
            sha256_list = re.findall(sha256_regex, response)
            for sha256 in sha256_list:
                try:
                    indicators.append(
                        Indicator(
                            value=sha256.strip(),
                            type=indicator_types["sha256"],
                        )
                    )
                    indicator_type_count["sha256"] += 1
                    all_indicators_set.add(sha256.strip())
                except ValidationError:
                    skipped_count += 1
                except Exception:
                    skipped_count += 1

        if "md5" in indicator_types:
            md5_regex = r"\b[a-fA-F\d]{32}\b"
            md5_list = re.findall(md5_regex, response)

            for md5 in md5_list:
                try:
                    indicators.append(
                        Indicator(
                            value=md5.strip(), type=indicator_types["md5"]
                        )
                    )
                    indicator_type_count["md5"] += 1
                    all_indicators_set.add(md5.strip())
                except ValidationError:
                    skipped_count += 1
                except Exception:
                    skipped_count += 1

        if "ipv4" in indicator_types:
            ipv4_regex = r"(?<![:\/\.\d])\b(?:\d{1,3}\.){3}\d{1,3}\b\/*?(?![:\/\.\dA-Za-z])"  # noqa
            ipv4_list = re.findall(ipv4_regex, response)
            for ipv4 in ipv4_list:
                try:
                    ipv4 = ipv4.strip().strip("/")
                    if isinstance(ip_address(ipv4), IPv4Address):
                        indicators.append(
                            Indicator(
                                value=ipv4,
                                type=indicator_types["ipv4"],
                            )
                        )
                        indicator_type_count["ipv4"] += 1
                        all_indicators_set.add(ipv4)
                except ValidationError:
                    skipped_count += 1
                except Exception:
                    skipped_count += 1

        if "ipv6" in indicator_types:

            response_list_regex = r"[^\s]+"

            ipv6_regex = r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|([0-9a-fA-F]{1,4}:){1,7}:)(\/*)?$"  # noqa

            response_list = re.findall(response_list_regex, str(response))

            pattern = re.compile(ipv6_regex, re.VERBOSE | re.MULTILINE)

            ipv6_list = [
                match[0]
                for ip in response_list
                for match in re.findall(pattern, ip)
            ]
            for ipv6 in ipv6_list:
                try:
                    ipv6 = ipv6.strip().strip("/")
                    if isinstance(ip_address(ipv6), IPv6Address):
                        indicators.append(
                            Indicator(
                                value=ipv6,
                                type=indicator_types["ipv6"],
                            )
                        )
                        indicator_type_count["ipv6"] += 1
                        all_indicators_set.add(ipv6)
                except ValidationError:
                    skipped_count += 1
                except Exception:
                    skipped_count += 1

        if "url" in indicator_types:

            extract_domains = self.configuration.get("extract_domains", "yes")
            domain_regex = r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"  # noqa

            domain_regex_2 = r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"

            response_list_regex = r"[^\s]+"

            response_list = re.findall(response_list_regex, response)

            for indicator in response_list:
                try:
                    try:
                        parse_result = urlparse(indicator)
                    except Exception as e:
                        err_msg = f"Error while parsing indicator {indicator}."
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} Error: {e}",
                            details=traceback.format_exc(),
                        )
                        if indicator not in all_indicators_set:
                            all_indicators_set.add(indicator)
                            exact_skipped_count += 1
                        continue

                    netloc = parse_result.netloc.strip()
                    fragment = parse_result.fragment.strip()
                    path = parse_result.path.strip()
                    scheme = parse_result.scheme.strip()

                    if extract_domains == "yes":
                        if netloc and (netloc not in all_indicators_set):
                            extracted_domains.append(
                                Indicator(
                                    value=netloc,
                                    type=getattr(
                                        IndicatorType,
                                        "DOMAIN",
                                        IndicatorType.URL,
                                    ),
                                )
                            )
                            indicator_type_count["domain"] += 1
                            all_indicators_set.add(netloc)
                        else:
                            extracted_domain = re.findall(domain_regex, path)
                            if not extracted_domain:
                                extracted_domain = re.findall(
                                    domain_regex_2, path
                                )

                            if (
                                extracted_domain
                                and (extracted_domain[0] != fragment)
                                and (
                                    extracted_domain[0]
                                    not in all_indicators_set
                                )
                            ):
                                extracted_domains.append(
                                    Indicator(
                                        value=extracted_domain[0],
                                        type=getattr(
                                            IndicatorType,
                                            "DOMAIN",
                                            IndicatorType.URL,
                                        ),
                                    )
                                )
                                indicator_type_count["domain"] += 1
                                all_indicators_set.add(extracted_domain[0])
                            else:
                                if indicator not in all_indicators_set:
                                    extracted_skipped_count += 1
                                    all_indicators_set.add(indicator)
                    else:
                        if indicator not in all_indicators_set:
                            exact_indicators.append(
                                Indicator(
                                    value=indicator,
                                    type=IndicatorType.URL,
                                )
                            )
                            indicator_type_count["url"] += 1
                            all_indicators_set.add(indicator)
                except Exception as e:
                    err_msg = f"Error while parsing indicator {indicator}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {e}",
                        details=traceback.format_exc(),
                    )
                    indicators.append(
                        Indicator(
                            value=indicator,
                            type=IndicatorType.URL,
                        )
                    )
                    indicator_type_count["url"] += 1
                    all_indicators_set.add(indicator)
                    continue

            indicators += (
                exact_indicators if exact_indicators else extracted_domains
            )

        if "domain" in indicator_types:
            extract_domains = self.configuration.get("extract_domains", "yes")

            if ("url" in indicator_types and extract_domains == "no") or (
                "url" not in indicator_types
            ):
                domain_flag = True

            domain_regex = r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"  # noqa

            domain_regex_2 = r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"

            response_list_regex = r"[^\s]+"

            response_list = re.findall(response_list_regex, response)

            for indicator in response_list:
                try:
                    try:
                        parse_result = urlparse(indicator)
                    except Exception as e:
                        err_msg = f"Error while parsing indicator {indicator}."
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} Error: {e}",
                            details=traceback.format_exc(),
                        )
                        if indicator not in all_indicators_set:
                            all_indicators_set.add(indicator)
                            exact_skipped_count += 1
                        continue

                    netloc = parse_result.netloc.strip()
                    fragment = parse_result.fragment.strip()
                    path = parse_result.path.strip()
                    scheme = parse_result.scheme.strip()

                    if netloc and (netloc not in all_indicators_set):
                        extracted_domains_2.append(
                            Indicator(
                                value=netloc,
                                type=getattr(
                                    IndicatorType,
                                    "DOMAIN",
                                    IndicatorType.URL,
                                ),
                            )
                        )
                        indicator_type_count["domain"] += 1
                        all_indicators_set.add(netloc)
                    else:
                        extracted_domain = re.findall(domain_regex, path)
                        if not extracted_domain:
                            extracted_domain = re.findall(domain_regex_2, path)

                        if (
                            extracted_domain
                            and (extracted_domain[0] != fragment)
                            and (extracted_domain[0] not in all_indicators_set)
                        ):
                            extracted_domains_2.append(
                                Indicator(
                                    value=extracted_domain[0],
                                    type=getattr(
                                        IndicatorType,
                                        "DOMAIN",
                                        IndicatorType.URL,
                                    ),
                                )
                            )
                            indicator_type_count["domain"] += 1
                            all_indicators_set.add(extracted_domain[0])
                        else:
                            if (
                                domain_flag
                                and indicator not in all_indicators_set
                            ):
                                extracted_skipped_count += 1
                                all_indicators_set.add(indicator)

                except Exception as e:
                    err_msg = f"Error while parsing indicator {indicator}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {e}",
                        details=traceback.format_exc(),
                    )
                    if indicator not in all_indicators_set:
                        skipped_count += 1
                        all_indicators_set.add(indicator)
                    continue

            indicators += extracted_domains_2

        skipped_count = (
            skipped_count + extracted_skipped_count + exact_skipped_count
        )

        return indicators, skipped_count, indicator_type_count

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
        except (ValueError, Exception):
            return False

    def _validate_url(self, url):
        """
        Validate the URL provided in configuration parameters.

        Args:
            url (str): The URL to validate.

        Returns:
            ValidationResult: The result of the validation.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating URL provided in configuration parameters."
            )
            self.web_page_ioc_scraper_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"verifying the connectivity with {url}.",
                is_validation=True,
            )

            validation_msg = f"Validation successful for {MODULE_NAME} {self.plugin_name} Plugin."
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(
                success=True,
                message=validation_msg,
            )
        except WebPageIOCScraperPluginException as exp:
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
        url = configuration.get("url", "").strip().strip("/")
        threat_type = configuration.get("type", [])
        validation_err = "Validation error occurred."
        if not url:
            err_msg = "Website URL is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(url, str) or not self.is_url(url):
            err_msg = (
                "Invalid website URL provided in configuration parameters."
            )
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
                f"provided. Allowed values are {', '.join(THREAT_TYPES).upper()}."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        extract_domains = configuration.get("extract_domains", "").strip()
        if not extract_domains:
            err_msg = "Extract Domains from URL is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif extract_domains not in ["yes", "no"]:
            err_msg = (
                "Invalid value for Extract Domains from URL "
                "provided. Allowed values are 'Yes' and 'No'."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self._validate_url(url)
