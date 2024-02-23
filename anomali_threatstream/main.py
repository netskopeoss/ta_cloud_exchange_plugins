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

CTE Anomali Threatstream Plugin's main file which contains the implementation 
of all the plugin's methods."""

from datetime import datetime, timedelta
import traceback
import json
import re
import ipaddress
import math
import sys

from urllib.parse import urlparse
from pydantic import ValidationError
from typing import List, Tuple

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from netskope.integrations.cte.utils import TagUtils

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from .utils.anomali_threatstream_helper import (
    AnomaliThreatstreamPluginHelper,
    AnomaliThreatstreamPluginException,
)

from .utils.anomali_threatstream_constant import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    DATE_FORMAT_FOR_IOCS,
    MAX_PAGE_SIZE,
    PAGE_LIMIT,
    TARGET_SIZE_MB,
    ANOMALI_SEVERITY_MAPPING,
    SEVERITY_MAPPING,
    ANOMALI_TO_INTERNAL_TYPE,
    ANOMALI_SEVERITY,
    INDICATOR_TYPES,
    ANOMALI_STATUS,
)


class AnomaliThreatstreamPlugin(PluginBase):
    """AnomaliThreatstreamPlugin class for pulling threat information."""

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
        self.anomali_threatstream_helper = AnomaliThreatstreamPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AnomaliThreatstreamPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def get_headers(self, configuration):
        """Get headers required for the API call."""
        return self.anomali_threatstream_helper._add_user_agent(
            {
                "Authorization": f"apikey {configuration.get('username').strip()}:{configuration.get('api_key')}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        base_url = configuration.get("base_url", "").strip()
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str) or not self._validate_url(base_url, True):
            err_msg = "Invalid Base URL provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        username = configuration.get("username", "").strip()
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(username, str):
            err_msg = "Invalid Username provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        api_key = configuration.get("api_key", "")
        if not api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(api_key, str):
            err_msg = "Invalid API Key provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        remote_observables = configuration.get("remote_observables")
        if remote_observables and remote_observables not in ["Yes", "No"]:
            self.logger.error(
                f"{validation_err_msg} Value of Remote Observables "
                "should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Remote Observables' "
                "provided. Allowed values are 'Yes' or 'No'.",
            )

        indicator_type = configuration.get("indicator_type")
        if not indicator_type:
            err_msg = (
                "Type of Threat data to pull is a required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not (
            all(indicator_type in INDICATOR_TYPES for indicator_type in indicator_type)
        ):
            err_msg = "Invalid value for Type of Threat data to pull provided. Available values are 'IP','IPv6', 'Domain', 'URL', 'Hash [SHA256]', or 'Hash [MD5]'."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        confidence = configuration.get("confidence")
        if confidence and not isinstance(confidence, int):
            err_msg = (
                "Invalid value provided in Minimum Confidence configuration parameter."
                "Minimum Confidence should be positive integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif confidence and not (0 <= confidence <= 100):
            err_msg = "Minimum Confidence should be in range of 0 to 100."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        severity = configuration.get("severity", [])
        if severity and not (all(sev in ANOMALI_SEVERITY for sev in severity)):
            err_msg = "Invalid value for Severity provided. Available values are 'Low', 'Medium', 'High' or 'Very-High'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        status = configuration.get("status", [])
        if status and not (all(stat in ANOMALI_STATUS for stat in status)):
            err_msg = "Invalid value for Status provided. Available values are 'Active','Inactive' or 'False Positive'."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        enable_tagging = configuration.get("enable_tagging")
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif enable_tagging not in ["Yes", "No"]:
            self.logger.error(
                f"{validation_err_msg} Value of Enable Tagging should "
                "be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided."
                " Allowed values are 'Yes' or 'No'.",
            )

        is_pull_required = configuration.get("is_pull_required")
        if not is_pull_required:
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif is_pull_required not in ["Yes", "No"]:
            self.logger.error(
                f"{validation_err_msg} Value of Enable Polling should "
                "be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided."
                " Allowed values are 'Yes' or 'No'.",
            )

        initial_range = configuration.get("days", 0)
        if initial_range is None:
            err_msg = "Initial Range (in days) is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid value provided in Initial Range (in days) "
                "in configuration parameter. Initial Range (in days) "
                "should be positive integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif initial_range <= 0 or initial_range > 365:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 - 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration, validation_err_msg)

    def validate_auth_params(self, configuration, validation_err_msg):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            base_url = configuration.get("base_url").strip().strip("/")
            query_params = {"limit": 1}
            headers = self.get_headers(configuration)
            self.anomali_threatstream_helper.api_helper(
                logger_msg="validating authentication parameters",
                url=f"{base_url}/api/v2/intelligence",
                method="GET",
                params=query_params,
                headers=headers,
                is_validation=True,
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except AnomaliThreatstreamPluginException as err:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Unexpected error occurred. Check logs for more details.",
            )

    def convert_into_date_time(self, date: str):
        """Convert str to datetime object.

        Args:
            date (str): str.

        Returns:
            datetime: datetime object.
        """
        try:
            return datetime.strptime(date, DATE_FORMAT_FOR_IOCS) if date else None
        except Exception:
            return None

    def _validate_url(self, url: str, base_url: bool) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        if base_url:
            return (
                parsed.scheme.strip() != ""
                and parsed.netloc.strip() != ""
                and (parsed.path.strip() == "/" or parsed.path.strip() == "")
            )
        else:
            return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_ipv6(self, address: str) -> bool:
        """Validate IPV6 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv6Address(address)
            return True
        except Exception:
            return False

    def _validate_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        if re.match(
            r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",  # noqa
            value,
        ):
            return True
        else:
            return False

    def get_reputation(self, confidence) -> int:
        """
        Calculate the reputation based on the given confidence level.

        Parameters:
            confidence (int): The confidence level, ranging from 0 to 100.

        Returns:
            int: The calculated reputation, ranging from 1 to 10.
        """
        if confidence:
            return math.ceil(confidence / 10)
        else:
            return 5

    def create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()
        for tag in tags:
            tag_name = tag.get("name").strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, tag_name, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def pull(self):
        """Pull the data from the Anomali ThreatStream platform.

        Returns:
            Indicators: PullResult object with list of observables.
        """

        try:
            if self.configuration.get("is_pull_required") == "Yes":
                self.logger.info(
                    f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}."
                )
                headers = self.get_headers(self.configuration)
                return self.get_indicators(headers)
            else:
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
            return []

        except AnomaliThreatstreamPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise exp

    def get_indicators(self, headers):
        """
        Retrieves a list of indicators from the API.

        Args:
            headers (dict): The headers to be used in the API request.

        Returns:
            list: A list of Indicator objects representing the retrieved indicators.

        Raises:
            AnomaliThreatstreamPluginException: If an error occurs while executing the pull cycle.
            Exception: If an unexpected error occurs while executing the pull cycle.
        """

        indicator_list = []
        total_skipped_tags = set()
        skipped_count = 0
        page_count = 0
        base_url = self.configuration.get("base_url").strip().strip("/")
        query_endpoint = f"{base_url}/api/v2/intelligence"
        try:
            storage = self.storage if self.storage is not None else {}

            last_updated = storage.get("last_updated", "")
            self.logger.debug(
                f"{self.log_prefix}: Pulling indicators. Storage: {storage}."
            )

            start_time = None
            if not self.last_run_at:
                start_time = datetime.now() - timedelta(
                    days=self.configuration.get("days")
                )
                start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            elif last_updated:
                start_time = last_updated
            else:
                start_time = self.last_run_at
                start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            query_params = {
                "modified_ts__gte": start_time,
                "update_id__gt": 0,
                "limit": MAX_PAGE_SIZE,
                "order_by": "update_id",
            }
            if (
                self.configuration.get("remote_observables")
                and self.configuration.get("remote_observables") == "Yes"
            ):
                query_params["remote_api"] = "true"
            confidence = self.configuration.get("confidence")
            status = self.configuration.get("status")
            severity = self.configuration.get("severity")
            indicator_types = self.configuration.get("indicator_type")
            i_types = [
                "hash" if indicator_type in [
                    "md5", "sha256"] else indicator_type
                for indicator_type in indicator_types
            ]
            query_params["type"] = ",".join(i_types)

            if all(x in indicator_types for x in ("md5", "sha256")):
                query_params["hash$subtype"] = "MD5,SHA256"
            elif "md5" in indicator_types:
                query_params["hash$subtype"] = "MD5"
            elif "sha256" in indicator_types:
                query_params["hash$subtype"] = "SHA256"

            if confidence:
                query_params["confidence_gte"] = confidence
            if status:
                query_params["status"] = ",".join(status)
            if severity:
                query_params["severity"] = ",".join(severity)

            indicator_type_count = {
                "ip": 0,
                "ipv6": 0,
                "url": 0,
                "domain": 0,
                "md5": 0,
                "sha256": 0,
            }

            last_indicator = None
            while True:
                try:
                    page_count += 1
                    current_page_skip_count = 0
                    current_extracted_indicators = []

                    resp_json = self.anomali_threatstream_helper.api_helper(
                        logger_msg=f"pulling data for page {page_count}",
                        url=query_endpoint,
                        method="GET",
                        headers=headers,
                        params=query_params,
                    )
                    indicators_json_list = resp_json.get("objects", [])
                    if not indicators_json_list:
                        break
                    last_indicator = indicators_json_list[-1]

                    for indicator in indicators_json_list:
                        try:
                            skip_indicator = False
                            tags_data = (
                                indicator.get("tags", [])
                                if indicator.get("tags")
                                else []
                            )
                            if tags_data:
                                for tag in tags_data:
                                    if tag.get("name", "") == "netskope-ce":
                                        skip_indicator = True
                                        break
                            if not skip_indicator:
                                if self.configuration["enable_tagging"] == "No":
                                    tags_data = []

                                if indicator.get("value") and indicator.get("type"):
                                    tags, skipped_tags = self.create_tags(
                                        tags_data)
                                    total_skipped_tags.update(skipped_tags)

                                    description = indicator.get("description")
                                    indicator_type = indicator.get("type")
                                    if (
                                        indicator_type == IndicatorType.MD5
                                        and indicator.get("subtype") == "SHA256"
                                    ):
                                        indicator_type = IndicatorType.SHA256
                                    current_extracted_indicators.append(
                                        Indicator(
                                            value=indicator.get(
                                                "value").lower(),
                                            type=ANOMALI_TO_INTERNAL_TYPE.get(
                                                indicator_type
                                            ),
                                            firstSeen=self.convert_into_date_time(
                                                indicator.get("created_ts")
                                            ),
                                            lastSeen=self.convert_into_date_time(
                                                indicator.get("modified_ts")
                                            ),
                                            severity=SEVERITY_MAPPING.get(
                                                indicator.get("meta", {}).get(
                                                    "severity", SeverityType.UNKNOWN
                                                ),
                                            ),
                                            tags=tags,
                                            reputation=self.get_reputation(
                                                indicator.get("confidence", "")
                                            ),
                                            comments=description
                                            if description is not None
                                            else "",
                                        )
                                    )

                                    indicator_type_count[indicator_type] += 1

                                else:
                                    current_page_skip_count += 1
                            else:
                                current_page_skip_count += 1
                        except (ValidationError, Exception) as error:
                            current_page_skip_count += 1
                            error_message = (
                                "Validation error occurred"
                                if isinstance(error, ValidationError)
                                else "Unexpected error occurred"
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_message} while"
                                    " creating indicator. This record "
                                    f"will be skipped. Error: {error}."
                                ),
                                details=str(traceback.format_exc()),
                            )

                    skipped_count += current_page_skip_count
                    indicator_list.extend(current_extracted_indicators)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{len(current_extracted_indicators)} indicator(s) "
                        f"for page {page_count}. Total indicator(s) "
                        f"fetched - {len(indicator_list)}."
                    )

                    if len(indicators_json_list) < MAX_PAGE_SIZE:
                        storage.clear()
                        break
                    else:
                        query_params["update_id__gt"] = last_indicator.get(
                            "update_id")

                    if page_count >= PAGE_LIMIT:
                        storage.clear()
                        if last_indicator and last_indicator.get("modified_ts"):
                            storage["last_updated"] = last_indicator.get(
                                "modified_ts")
                        self.logger.info(
                            f"{self.log_prefix}: Page limit of {PAGE_LIMIT} "
                            f"has reached. Returning {len(indicator_list)} "
                            "indicator(s). The pulling of the indicators will "
                            "be resumed in the next pull cycle."
                        )

                        self.logger.info(
                            f"{self.log_prefix}: Completed fetching indicators"
                            " for the plugin. Total indicator(s) fetched "
                            f"{len(indicator_list)}, {indicator_type_count['sha256']} SHA256, "
                            f"{indicator_type_count['md5']} MD5, {indicator_type_count['url']} URL, "
                            f"{indicator_type_count['domain']} Domain, {indicator_type_count['ip']} IP, "
                            f"and {indicator_type_count['ipv6']} IPv6 indicator(s)"
                            f" fetched. skipped {skipped_count} indicator(s), "
                            f"total {len(total_skipped_tags)} tag(s) skipped."
                        )
                        return indicator_list

                except AnomaliThreatstreamPluginException as ex:
                    storage.clear()
                    if last_indicator and last_indicator.get("modified_ts"):
                        storage["last_updated"] = last_indicator.get(
                            "modified_ts")
                    err_msg = (
                        f"{self.log_prefix}: Error occurred while executing "
                        "the pull cycle. The pulling of the indicators will be"
                        f" resumed in the next pull cycle. Error: {ex}."
                    )
                    self.logger.error(
                        message=err_msg, details=(str(traceback.format_exc()))
                    )
                    break

                except Exception as ex:
                    storage.clear()
                    if last_indicator and last_indicator.get("modified_ts"):
                        storage["last_updated"] = last_indicator.get(
                            "modified_ts")
                    err_msg = (
                        f"{self.log_prefix}: Error occurred while executing "
                        "the pull cycle. The pulling of the indicators will be"
                        f" resumed in the next pull cycle. Error: {ex}."
                    )
                    self.logger.error(
                        message=err_msg, details=(str(traceback.format_exc()))
                    )
                    break

            self.logger.info(
                f"{self.log_prefix}: Total indicator(s) fetched "
                f"{len(indicator_list)}, {indicator_type_count['sha256']} SHA256, "
                f"{indicator_type_count['md5']} MD5, {indicator_type_count['url']} URL, "
                f"{indicator_type_count['domain']} Domain, {indicator_type_count['ip']} IP, "
                f"and {indicator_type_count['ipv6']} IPv6 indicator(s) fetched"
                f". skipped {skipped_count} indicator(s), "
                f"total {len(total_skipped_tags)} tag(s) skipped."
            )

            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} record(s)"
                    " as indicator value might be None or invalid or "
                    " it has 'netskope-ce' tag in it."
                )
            if len(total_skipped_tags) > 0:
                self.logger.info(
                    f"{self.log_prefix}: {len(total_skipped_tags)} tag(s) "
                    "skipped as they were longer than expected size or due"
                    " to some other exceptions that occurred while "
                    "creation of them. tags: "
                    f"({', '.join(total_skipped_tags)})."
                )

            return indicator_list

        except AnomaliThreatstreamPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise exp

    def push(self, indicators: list, action_dict: dict) -> PushResult:
        """Push method will push the indicators to Anomali.

        Args:
            indicators (list): List of indicators.

        Returns:
            PushResult : PushResult object with success and message
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        skipped_count = 0

        if action_value == "share_ioc":
            if not indicators:
                self.logger.info(
                    f"{self.log_prefix}: No indicators found to push.")
                return PushResult(success=True, message="No indicators found.")

            action_params = action_dict.get("parameters", {})
            hash_itype = action_params.get("hash_itype", "")
            ip_itype = action_params.get("ip_itype", "")
            ipv6_itype = action_params.get("ipv6_itype", "")
            domain_itype = action_params.get("domain_itype", "")
            url_itype = action_params.get("url_itype", "")
            objects = []
            for indicator in indicators:
                tags = indicator.tags if indicator.tags else []
                if tags:
                    tags = [{"name": tag} for tag in tags]
                tags.append({"name": "netskope-ce"})

                payload = {
                    "tags": tags,
                    "severity": ANOMALI_SEVERITY_MAPPING.get(indicator.severity),
                    "confidence": indicator.reputation * 10,
                }

                if indicator.type == IndicatorType.URL:
                    try:
                        if self._validate_url(indicator.value, False):
                            payload["url"] = indicator.value
                            payload["itype"] = url_itype
                        elif self._is_valid_ipv4(indicator.value):
                            payload["srcip"] = indicator.value
                            payload["itype"] = ip_itype
                        elif self._is_valid_ipv6(indicator.value):
                            payload["ipv6"] = indicator.value
                            payload["itype"] = ipv6_itype
                        elif self._validate_domain(indicator.value):
                            payload["domain"] = indicator.value
                            payload["itype"] = domain_itype
                        else:
                            skipped_count += 1
                            continue
                    except Exception as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error occurred while "
                                f"sharing the indicator. Error: {err}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skipped_count += 1
                        continue

                elif indicator.type == IndicatorType.SHA256:
                    payload["md5"] = indicator.value
                    payload["subtype"] = "SHA256"
                    payload["itype"] = hash_itype
                elif indicator.type == IndicatorType.MD5:
                    payload["md5"] = indicator.value
                    payload["subtype"] = "MD5"
                    payload["itype"] = hash_itype

                objects.append(payload)

            results = []
            size_in_bytes = sys.getsizeof(json.dumps(objects))
            # Convert bytes to megabytes
            size_in_mb = size_in_bytes / (1024.0**2)
            if size_in_mb > TARGET_SIZE_MB:
                chunk_data = self.anomali_threatstream_helper.split_into_size(
                    objects)
                results.extend(chunk_data)
            else:
                results.append(objects)

            headers = self.get_headers(self.configuration)
            base_url = self.configuration.get("base_url").strip().strip("/")
            final_payload = {
                "meta": {"classification": "private", "allow_unresolved": True, "allow_update": True, "enrich": False},
            }

            page_count = 0
            total_count = 0
            for result in results:
                page_count += 1
                final_payload["objects"] = result
                try:
                    self.anomali_threatstream_helper.api_helper(
                        logger_msg=f"pushing indicators to {self.plugin_name} for page {page_count}",
                        url=f"{base_url}/api/v2/intelligence/",
                        method="PATCH",
                        data=json.dumps(final_payload),
                        headers=headers,
                    )
                    total_count += len(result)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully shared {len(result)}"
                        f" indicator(s) for page {page_count}. Total indicator"
                        f"(s) shared - {total_count}."
                    )
                except (AnomaliThreatstreamPluginException, Exception) as err:
                    skipped_count += len(result)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while pushing"
                            f" indicators. Error: {str(err)}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    continue

            self.logger.info(
                f"{self.log_prefix}: Successfully shared {total_count} indicator(s)."
            )
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: {skipped_count} indicator(s) will "
                    f"not be shared or updated on {self.plugin_name} platform."
                    " Invalid Domain, IP/IPv6, URL or Hashes(SHA256, MD5) received."
                )
            return PushResult(success=True, message="Successfully pushed indicators.")

    def get_actions(self):
        """Get available actions."""
        return [ActionWithoutParams(label="Share Indicators", value="share_ioc")]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate crowdstrike configuration.

        Args:
            action (Action): Action to perform on IoCs.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["share_ioc"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action_value == "share_ioc":

            if not action.parameters.get("url_itype"):
                err_msg = "URL itype should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if not action.parameters.get("ip_itype"):
                err_msg = "IP itype should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if not action.parameters.get("ipv6_itype"):
                err_msg = "IPv6 itype should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if not action.parameters.get("domain_itype"):
                err_msg = "Domain itype should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if not action.parameters.get("hash_itype"):
                err_msg = "Hash itype should not be empty."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        action_value = action.value
        if action_value == "share_ioc":
            return [
                {
                    "label": "URL iType",
                    "key": "url_itype",
                    "type": "choice",
                    "choices": [
                        {"key": "APT URL", "value": "apt_url"},
                        {"key": "Bot URL", "value": "bot_url"},
                        {"key": "Malware C&C URL", "value": "c2_url"},
                        {"key": "Compromised URL", "value": "compromised_url"},
                        {"key": "Cryptocurrency URL", "value": "crypto_url"},
                        {"key": "Downloader URL", "value": "downloader_url"},
                        {"key": "Data Exfiltration URL", "value": "exfil_url"},
                        {"key": "Exploit Kit URL", "value": "exploit_url"},
                        {"key": "Fraud URL", "value": "fraud_url"},
                        {"key": "IP Geolocation URL", "value": "geolocation_url"},
                        {
                            "key": "Information Stealer URL",
                            "value": "infostealer_url",
                        },
                        {
                            "key": "Internet Of Things Malicious URL",
                            "value": "iot_url",
                        },
                        {"key": "IP Check URL", "value": "ipcheck_url"},
                        {"key": "Malware URL", "value": "mal_url"},
                        {"key": "Parked URL", "value": "parked_url"},
                        {"key": "Paste Site URL", "value": "pastesite_url"},
                        {"key": "Phishing URL", "value": "phish_url"},
                        {"key": "Point Of Sale Malicious URL", "value": "pos_url"},
                        {"key": "Ransomware URL", "value": "ransomware_url"},
                        {"key": "Social Media URL", "value": "social_media_url"},
                        {"key": "Spam URL", "value": "spam_url"},
                        {"key": "Speedtest URL", "value": "speedtest_url"},
                        {"key": "Suspicious URL", "value": "suspicious_url"},
                        {
                            "key": "Torrent Tracker URL",
                            "value": "torrent_tracker_url",
                        },
                        {"key": "Trojan URL", "value": "trojan_url"},
                    ],
                    "default": "apt_url",
                    "mandatory": True,
                    "description": (
                        "Select the iType that you want to assign to your URL."
                    ),
                },
                {
                    "label": "IP iType",
                    "key": "ip_itype",
                    "type": "choice",
                    "choices": [
                        {"key": "Actor IP", "value": "actor_ip"},
                        {"key": "Anonymous Proxy IP", "value": "anon_proxy"},
                        {"key": "Anonymous VPN IP", "value": "anon_vpn"},
                        {"key": "APT IP", "value": "apt_ip"},
                        {"key": "Infected Bot IP", "value": "bot_ip"},
                        {"key": "Brute Force IP", "value": "brute_ip"},
                        {"key": "Malware C&C IP", "value": "c2_ip"},
                        {"key": "Commercial Webproxy IP",
                            "value": "comm_proxy_ip"},
                        {"key": "Compromised IP", "value": "compromised_ip"},
                        {"key": "Cryptocurrency IP", "value": "crypto_ip"},
                        {"key": "DDOS IP", "value": "ddos_ip"},
                        {"key": "Downloader IP", "value": "downloader_ip"},
                        {"key": "Data Exfiltration IP", "value": "exfil_ip"},
                        {"key": "Exploit Kit IP", "value": "exploit_ip"},
                        {"key": "Fraud IP", "value": "fraud_ip"},
                        {"key": "I2P IP", "value": "i2p_ip"},
                        {"key": "Information Stealer IP",
                            "value": "infostealer_ip"},
                        {"key": "Internet Of things Malicious IP", "value": "iot_ip"},
                        {"key": "Malware IP", "value": "mal_ip"},
                        {"key": "Peer-to-Peer C&C IP", "value": "p2pcnc"},
                        {"key": "Domain Parking IP", "value": "parked_ip"},
                        {"key": "Phishing IP", "value": "phish_ip"},
                        {"key": "Point Of Sale Malicious IP", "value": "pos_ip"},
                        {"key": "Open Proxy IP", "value": "proxy_ip"},
                        {"key": "Ransomware IP", "value": "ransomware_ip"},
                        {"key": "Scanning IP", "value": "scan_ip"},
                        {"key": "Sinkhole IP", "value": "sinkhole_ip"},
                        {"key": "Spammer IP", "value": "spam_ip"},
                        {"key": "SSH Brute Force IP", "value": "ssh_ip"},
                        {"key": "Suppress Alerts", "value": "suppress"},
                        {"key": "Suspicious IP", "value": "suspicious_ip"},
                        {"key": "TOR Node IP", "value": "tor_ip"},
                        {"key": "Trojan IP Address", "value": "trojan_ip"},
                        {"key": "Cloud Server IP", "value": "vps_ip"},
                    ],
                    "default": "actor_ip",
                    "mandatory": True,
                    "description": (
                        "Select the iType that you want to assign to your IP."
                    ),
                },
                {
                    "label": "IPv6 iType",
                    "key": "ipv6_itype",
                    "type": "choice",
                    "choices": [
                        {"key": "Actor IPv6", "value": "actor_ipv6"},
                        {"key": "Anonymous Proxy IPv6",
                            "value": "anon_proxy_ipv6"},
                        {"key": "Anonymous VPN IPv6", "value": "anon_vpn_ipv6"},
                        {"key": "APT IPv6", "value": "apt_ipv6"},
                        {"key": "Infected Bot IPv6", "value": "bot_ipv6"},
                        {"key": "Brute Force IPv6", "value": "brute_ipv6"},
                        {"key": "Malware C&C IPv6", "value": "c2_ipv6"},
                        {"key": "Commercial Webproxy IPv6",
                            "value": "comm_proxy_ipv6"},
                        {"key": "Compromised IPv6", "value": "compromised_ipv6"},
                        {"key": "Cryptocurrency IPv6", "value": "crypto_ipv6"},
                        {"key": "DDOS IPv6", "value": "ddos_ipv6"},
                        {"key": "Downloader IPv6", "value": "downloader_ipv6"},
                        {"key": "Data Exfiltration IPv6", "value": "exfil_ipv6"},
                        {"key": "Exploit Kit IPv6", "value": "exploit_ipv6"},
                        {"key": "Fraud IPv6", "value": "fraud_ipv6"},
                        {"key": "I2P IPv6", "value": "i2p_ipv6"},
                        {
                            "key": "Information Stealer IPv6",
                            "value": "infostealer_ipv6",
                        },
                        {
                            "key": "Internet Of Things Malicious IPv6",
                            "value": "iot_ipv6",
                        },
                        {"key": "Malware IPv6", "value": "mal_ipv6"},
                        {"key": "Peer-to-Peer C&C IPv6", "value": "p2pcnc_ipv6"},
                        {"key": "Domain Parking IPv6", "value": "parked_ipv6"},
                        {"key": "Phishing IPv6", "value": "phish_ipv6"},
                        {"key": "Point Of Sale Malicious IPv6", "value": "pos_ipv6"},
                        {"key": "Open Proxy IPv6", "value": "proxy_ipv6"},
                        {"key": "Ransomware IPv6", "value": "ransomware_ipv6"},
                        {"key": "Scanning IPv6", "value": "scan_ipv6"},
                        {"key": "Sinkhole IPv6", "value": "sinkhole_ipv6"},
                        {"key": "Spammer IPv6", "value": "spam_ipv6"},
                        {"key": "SSH Brute Force IPv6", "value": "ssh_ipv6"},
                        {"key": "Suppress Alerts IPv6", "value": "suppress_ipv6"},
                        {"key": "Suspicious IPv6", "value": "suspicious_ipv6"},
                        {"key": "TOR Node IPv6", "value": "tor_ipv6"},
                        {"key": "Trojan IPv6 Address", "value": "trojan_ipv6"},
                        {"key": "Cloud Server IPv6", "value": "vps_ipv6"},
                    ],
                    "default": "actor_ipv6",
                    "mandatory": True,
                    "description": (
                        "Select the iType that you want to assign to your IPv6."
                    ),
                },
                {
                    "label": "Domain iType",
                    "key": "domain_itype",
                    "type": "choice",
                    "choices": [
                        {"key": "Adware Domain", "value": "adware_domain"},
                        {"key": "APT Domain", "value": "apt_domain"},
                        {"key": "Bot Domain", "value": "bot_domain"},
                        {"key": "Malware C&C Domain Name", "value": "c2_domain"},
                        {
                            "key": "Commercial Webproxy Domain",
                            "value": "comm_proxy_domain",
                        },
                        {"key": "Compromised Domain",
                            "value": "compromised_domain"},
                        {"key": "Cryptocurrency Pool Domain",
                            "value": "crypto_pool"},
                        {
                            "key": "Disposable Email Domain",
                            "value": "disposable_email_domain",
                        },
                        {"key": "Downloader Domain", "value": "downloader_domain"},
                        {"key": "Dynamic DNS", "value": "dyn_dns"},
                        {"key": "Data Exfiltration Domain",
                            "value": "exfil_domain"},
                        {"key": "Exploit Kit Domain", "value": "exploit_domain"},
                        {"key": "Fraud Domain", "value": "fraud_domain"},
                        {"key": "Free Email Domain", "value": "free_email_domain"},
                        {
                            "key": "Information Stealer Domain",
                            "value": "infostealer_domain",
                        },
                        {
                            "key": "Internet Of Things Malicious Domain",
                            "value": "iot_domain",
                        },
                        {"key": "Malware Domain", "value": "mal_domain"},
                        {"key": "Parked Domain", "value": "parked_domain"},
                        {"key": "Phishing Domain", "value": "phish_domain"},
                        {
                            "key": "Point Of Sale Malicious Domain",
                            "value": "pos_domain",
                        },
                        {"key": "Ransomware Domain", "value": "ransomware_domain"},
                        {"key": "Sinkhole Domain", "value": "sinkhole_domain"},
                        {"key": "Spam Domain", "value": "spam_domain"},
                        {"key": "Suspicious Domain", "value": "suspicious_domain"},
                        {"key": "Trojan Domain", "value": "trojan_domain"},
                        {"key": "Anonymous VPN Domain", "value": "vpn_domain"},
                        {
                            "key": "Whois Privacy Email Domain",
                            "value": "whois_privacy_domain",
                        },
                    ],
                    "default": "adware_domain",
                    "mandatory": True,
                    "description": (
                        "Select the iType that you want to assign to your Domain."
                    ),
                },
                {
                    "label": "Hash [MD5, SHA256] iType",
                    "key": "hash_itype",
                    "type": "choice",
                    "choices": [
                        {"key": "APT File Hash", "value": "apt_md5"},
                        {"key": "Bot Hash", "value": "bot_md5"},
                        {
                            "key": "Cryptocurrency Mining Software",
                            "value": "crypto_hash",
                        },
                        {"key": "Downloader File Hash",
                            "value": "downloader_hash"},
                        {"key": "Exploit Hash", "value": "exploit_md5"},
                        {"key": "Fraud Hash", "value": "fraud_md5"},
                        {"key": "Hack Tool File Hash", "value": "hack_tool_md5"},
                        {
                            "key": "Information Stealer File Hash",
                            "value": "infostealer_hash",
                        },
                        {
                            "key": "Internet Of Things Malicious File Hash",
                            "value": "iot_hash",
                        },
                        {"key": "JA3/JA3S TLS Fingerprint", "value": "ja3_md5"},
                        {"key": "Malware File Hash", "value": "mal_md5"},
                        {"key": "SSL Certificate Hash",
                            "value": "mal_sslcert_sha1"},
                        {"key": "Phishing File Hash", "value": "phish_md5"},
                        {
                            "key": "Point Of Sale Malicious File Hash",
                            "value": "pos_hash",
                        },
                        {"key": "Ransomware File Hash",
                            "value": "ransomware_hash"},
                        {"key": "Rootkit File Hash", "value": "rootkit_hash"},
                        {"key": "Trojan File Hash", "value": "trojan_hash"},
                    ],
                    "default": "apt_md5",
                    "mandatory": True,
                    "description": (
                        "Select the iType that you want to assign to your Hash [MD5, SHA256]."
                    ),
                },
            ]
