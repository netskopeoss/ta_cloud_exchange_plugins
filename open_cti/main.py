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

CTE OpenCTI  Plugin's main file which contains the implementation
of all the plugin's methods."""

import math
import re
import traceback
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Tuple, Union
from urllib.parse import urlparse
from copy import deepcopy

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.helper import (
    OpenCTIPluginException,
    OpenCTIPluginHelper,
)

from .utils.constants import (
    GRAPHQL_API,
    RETRACTION,
    INDICATOR_TYPES,
    PLUGIN_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    INTEGER_THRESHOLD,
    INDICATOR_PAGINATION,
    PAGINATION_VARIABLES,
    DEFAULT_REPUTATION,
    LIMIT,
    TAG_NAME,
    DEFAULT_IOC_TAG,
    OBSERVABLE_REGEXES,
    TAGS_ID_QUERY,
    INDICATOR_MUTATION,
)


class OpenCTIPlugin(PluginBase):
    """OpenCTI Plugin class for pulling threat information."""

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
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.opencti_helper = OpenCTIPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = OpenCTIPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLATFORM_NAME, PLUGIN_VERSION

    def get_headers(self, api_key: str) -> Dict:
        """Get headers required for the API call.
        Args:
            - api_key (str): OpenCTI API Key.
        """
        return self.opencti_helper._add_user_agent(
            {
                "Authorization": f"Bearer {api_key}",
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
        (base_url, api_key) = self.opencti_helper._get_credentials(
            configuration
        )

        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str) or not self._validate_url(
            base_url, True
        ):
            err_msg = "Invalid Base URL provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

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

        indicator_type = configuration.get("indicator_type")
        if not indicator_type:
            err_msg = (
                "Type of Threat data to pull is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not (
            all(
                indicator_type in INDICATOR_TYPES
                for indicator_type in indicator_type
            )
        ):
            err_msg = f"Invalid {indicator_type}"
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        confidence = configuration.get("confidence")
        if confidence and not isinstance(confidence, int):
            err_msg = (
                "Invalid value provided in Minimum Confidence configuration"
                "get_modified_indicatorsMinimum Confidence should be positive"
                "integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif confidence and not 0 <= confidence <= 100:
            err_msg = "Minimum Confidence should be in range of 0 to 100."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        status = configuration.get("revoked_indicators", [])
        if status and not all(stat in ["yes", "no"] for stat in status):
            err_msg = (
                f"Invalid value {status} for Revoked Indicators provided."
                "Allowed values are 'Yes or No'. "
            )
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

        tags = configuration.get("tags", "").strip()
        if tags and not isinstance(tags, str):
            err_msg = "Invalid Tags provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
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
        retraction_days = configuration.get("retraction_interval")
        if isinstance(retraction_days, int) and retraction_days is not None:
            if int(retraction_days) <= 0:
                err_msg = (
                    "Invalid Retraction Interval provided in configuration"
                    " parameters. Valid value should be an integer "
                    "greater than 0."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif int(retraction_days) > INTEGER_THRESHOLD:
                err_msg = (
                    "Invalid Retraction Interval provided in configuration"
                    " parameters. Valid value should be an integer "
                    "greater than 0 and less than 2^62."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        elif retraction_days:
            err_msg = (
                "Invalid Retraction Interval provided in the "
                "configuration parameters. Provide a valid integer value"
                " for the Retraction Interval."
            )
            self.logger.error(
                message=f"{validation_err_msg} {err_msg}",
                details=(
                    f"Retraction Interval: {retraction_days}, "
                    f"Retraction Interval type: {type(retraction_days)}"
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        initial_range = configuration.get("days", 0)
        if initial_range is None:
            err_msg = (
                "Initial Range (in days) is a required configuration"
                " parameter."
            )
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
        elif initial_range <= 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self._validate_connectivity(base_url, api_key)

    def _validate_connectivity(
        self, api_base_url: str, api_token: str
    ) -> ValidationResult:
        """Validate connectivity with OpenCTI server.

        Args:
            api_base_url (str): API Base URL.
            api_token (str): API Token.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            self.logger.info(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )

            # OpenCTI API Endpoint
            api_endpoint = GRAPHQL_API.format(api_base_url)
            indicator_graphql_query = deepcopy(INDICATOR_PAGINATION)
            indicator_graphql_variable = deepcopy(PAGINATION_VARIABLES)
            indicator_graphql_variable["first"] = 1
            indicator_graphql_query.update(
                {"variables": indicator_graphql_variable}
            )
            headers = self.get_headers(api_token)
            resp_json = self.opencti_helper.api_helper(
                url=api_endpoint,
                method="POST",
                json=indicator_graphql_query,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity " f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )

            if resp_json.get("errors"):
                if (
                    resp_json.get("errors")[0].get("message")
                    == "You must be logged in to do this."
                ):
                    message = "Unauthorized access to the API."
                else:
                    message = resp_json.get("errors")[0].get("message")
                self.logger.error(message=f"{self.log_prefix}: {message}")

                return ValidationResult(
                    success=False,
                    message=f"Received errors while calling the API:{message}",
                )

            logger_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.info(f"{self.log_prefix}: {logger_msg}")
            return ValidationResult(
                success=True,
                message=logger_msg,
            )
        except OpenCTIPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
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

    def _convert_datetime_to_openCTI_format(self, date_time: datetime) -> str:
        """
        Convert a datetime object to a string in the OpenCTI
          format.

        Args:
            date_time (datetime): The datetime object to convert.

        Returns:
            str: The datetime string in the OpenCTI format.
        """
        return date_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def get_reputation(self, confidence) -> int:
        """
        Calculate the reputation based on the given confidence level.

        Parameters:
            confidence (int): The confidence level, ranging from 0 to 100.

        Returns:
            int: The calculated reputation, ranging from 1 to 10.
        """
        if confidence:
            reputation = math.ceil(confidence / 10)
            return reputation if reputation else DEFAULT_REPUTATION
        else:
            return DEFAULT_REPUTATION

    def create_tags(self, tags: List) -> tuple:
        """
        Create tags in Netskope.

        Args:
            tags (List[Dict]): List of tags to be created.

        Returns:
            tuple: Tuple containing two lists. The first list contains the
            created tags, and the second list contains the skipped tags.
        """

        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()
        for tag in tags:
            tag_name = tag.get("value").strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred while "
                        f"creating tag {tag_name}. Error: {str(exp)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def extract_ioc_value(self, stix_pattern):
        # Dictionary to store regex patterns for different IOC types
        """
        Extract an IOC value from a given STIX pattern.

        Given a STIX pattern, iterate through a set of regex patterns for
        different IOC types and return the matched IOC value. If no match is
        found, return None.

        Parameters:
            stix_pattern (str): The STIX pattern to search.

        Returns:
            str: The matched IOC value, or None if no match is found.
        """
        ioc_patterns = {
            "md5": r"\[file:hashes.'MD5' = '([a-fA-F0-9]{32})'\]",
            "sha256": r"\[file:hashes.'SHA-256' = '([a-fA-F0-9]{64})'\]",
            "url": r"\[url:value = '(https?://[^\s]+)'\]",
            "domain": r"domain-name:value\s*=\s*'([a-zA-Z0-9.-]+)'",
            "ipv4": (
                r"\[ipv4-addr:value = "
                r"'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'\]"
            ),
            "ipv6": r"\[ipv6-addr:value = '([a-fA-F0-9:]+)'\]",
            "hostname": r"\[hostname:value = '([a-zA-Z0-9.-]+)'\]",
        }

        # Iterate through each IOC type pattern and search the STIX pattern
        for pattern in ioc_patterns.values():
            match = re.search(pattern, stix_pattern)
            if match:
                # Return only the matched value (not the IOC type)
                return match.group(1)

        else:
            return None

    def _get_ioc_type_from_openCTI(self, opencti_type):
        """
        Maps an OpenCTI type to a Netskope IOC type.

        Args:
            opencti_type (str): OpenCTI IOC type.

        Returns:
            IndicatorType: Netskope IOC type.
        """
        if opencti_type == "Domain-Name":
            return getattr(
                IndicatorType,
                "Domain",
                IndicatorType.URL,
            )
        elif opencti_type == "IPv6-Addr":
            return getattr(
                IndicatorType,
                "IPV6",
                IndicatorType.URL,
            )

        elif opencti_type == "IPv4-Addr":
            return getattr(
                IndicatorType,
                "IPV4",
                IndicatorType.URL,
            )

        elif opencti_type == "Hostname":
            return getattr(
                IndicatorType,
                "Hostname",
                IndicatorType.URL,
            )

        elif opencti_type == "Url":
            return getattr(
                IndicatorType,
                "URL",
                IndicatorType.URL,
            )

        elif opencti_type == "SHA256":
            return getattr(
                IndicatorType,
                "SHA256",
                IndicatorType.SHA256,
            )

        elif opencti_type == "MD5":
            return getattr(
                IndicatorType,
                "MD5",
                IndicatorType.MD5,
            )
        else:
            return getattr(
                IndicatorType,
                "URL",
                IndicatorType.URL,
            )

    def get_indicators(
        self,
        is_retraction: bool = False,
        retraction_time: str = "",
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """
        Pull indicators from OpenCTI.

        Args:
            is_retraction (bool): Check if indicators are being pulled for
            retraction.
            retraction_time (str): The time from which indicators will be
            pulled for retraction.

        Yields:
            Union[Generator[Indicator, bool, None], Dict]: A generator of
            extracted indicators or a dictionary with a checkpoint.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        (base_url, api_key) = self.opencti_helper._get_credentials(
            self.configuration
        )
        query_endpoint = GRAPHQL_API.format(base_url)
        headers = self.get_headers(api_key)

        start_time = None
        sub_checkpoint = getattr(self, "sub_checkpoint", {})
        if is_retraction and retraction_time:
            start_time = retraction_time
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            start_time = sub_checkpoint.get("checkpoint")
        elif self.last_run_at:
            start_time = self.last_run_at
            start_time = self._convert_datetime_to_openCTI_format(start_time)
        else:
            initial_days = self.configuration.get("days")
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying indicators for "
                f"last {initial_days} days."
            )
            start_time = datetime.now() - timedelta(days=initial_days)
            start_time = self._convert_datetime_to_openCTI_format(start_time)

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint: {start_time}"
        )

        query_filters = []
        query_filter = {
            "key": "modified",
            "values": [start_time],
            "operator": "gt",
            "mode": "or",
        }
        query_filters.append(query_filter)
        confidence = self.configuration.get("confidence")
        status = self.configuration.get("revoked_indicators", "")
        indicator_types = self.configuration.get("indicator_type")
        query_filter = {
            "key": "x_opencti_main_observable_type",
            "values": indicator_types,
            "operator": "eq",
            "mode": "or",
        }
        query_filters.append(query_filter)
        if confidence:
            query_filter = {
                "key": "confidence",
                "values": [confidence],
                "operator": "gte",
                "mode": "or",
            }
            query_filters.append(query_filter)

        if status and status != ["yes", "no"]:
            if status[0] == "no":
                status[0] = False
            query_filter = {
                "key": "revoked",
                "values": [bool(status[0])],
                "operator": "eq",
                "mode": "or",
            }
            query_filters.append(query_filter)

        openCTI_tag_ids = []
        tags = self.configuration.get("tags")
        if tags:
            tags = tags.split(",")
            for tag in tags:
                tag_id = self._get_tag_id(
                    base_url=base_url,
                    api_key=api_key,
                    tag_name=tag,
                    headers=headers,
                )
                if tag_id:
                    openCTI_tag_ids.append(tag_id)
            query_filter = {
                "key": "objectLabel",
                "values": openCTI_tag_ids if openCTI_tag_ids else [""],
                "operator": "eq",
                "mode": "or",
            }
            query_filters.append(query_filter)

        last_indicator = None
        next_page = True
        total_skipped_tags = set()
        total_indicators = 0
        page_count = 0
        after = None
        indicator_query = deepcopy(INDICATOR_PAGINATION)
        graphql_variable = deepcopy(PAGINATION_VARIABLES)
        graphql_variable["filters"]["filterGroups"][0]["filters"].extend(
            query_filters
        )
        graphql_variable["first"] = LIMIT
        try:
            while next_page:
                if after:
                    graphql_variable["after"] = after
                indicator_query.update({"variables": graphql_variable})
                page_count += 1
                indicator_type_count = {
                    "sha256": 0,
                    "md5": 0,
                    "domain": 0,
                    "ipv4": 0,
                    "ipv6": 0,
                    "hostname": 0,
                    "url": 0,
                }
                current_page_skip_count = 0
                current_extracted_indicators = set() if is_retraction else []
                logger_msg = (
                    f"pulling data for page {page_count} from {PLATFORM_NAME}"
                )

                resp_json = self.opencti_helper.api_helper(
                    logger_msg=logger_msg,
                    url=query_endpoint,
                    json=indicator_query,
                    method="POST",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                )
                indicators_json_list = []
                if resp_json.get("errors"):
                    self.logger.error(
                        f"{self.log_prefix}: Fail to pull data from "
                        f"{PLATFORM_NAME}, Error: {resp_json['errors']}"
                    )
                    raise OpenCTIPluginException(
                        f"Fail to pull data from "
                        f"{PLATFORM_NAME}, Error: {resp_json['errors']}"
                    )

                indicators_json_list = [
                    indicators_json_list["node"]
                    for indicators_json_list in resp_json["data"][
                        "indicators"
                    ]["edges"]
                    if indicators_json_list
                ]
                if indicators_json_list:
                    last_indicator = indicators_json_list[-1]
                    for indicator in indicators_json_list:
                        try:
                            skip_indicator = False
                            tags_data = indicator.get("objectLabel", [])
                            if tags_data:
                                for tag in tags_data:
                                    if tag.get("value", "") == TAG_NAME:
                                        skip_indicator = True
                                        break
                            if not skip_indicator:
                                if (
                                    self.configuration["enable_tagging"]
                                    == "No"
                                ):
                                    tags_data = []

                                indicator_type = indicator.get(
                                    "x_opencti_main_observable_type", ""
                                )
                                if indicator.get("pattern") and indicator_type:
                                    tags, skipped_tags = self.create_tags(
                                        tags_data
                                    )
                                    total_skipped_tags.update(skipped_tags)
                                    if indicator_type == "StixFile":
                                        if "SHA-256" in indicator.get(
                                            "pattern"
                                        ):
                                            indicator_type = "SHA256"
                                        else:
                                            indicator_type = "MD5"

                                    if is_retraction:
                                        extracted, is_skipped = (
                                            self._extract_observables_2x(
                                                indicator.get("pattern", ""),
                                                is_retraction=True,
                                            )
                                        )
                                        current_extracted_indicators.update(
                                            extracted
                                        )
                                    else:
                                        created_time = self._str_to_datetime(
                                            indicator.get("created")
                                        )
                                        modified_time = self._str_to_datetime(
                                            indicator.get("modified")
                                        )
                                        decay_score = indicator.get(
                                            "x_opencti_score"
                                        )
                                        expiry_date = indicator.get(
                                            "valid_until"
                                        )
                                        expiry_date = self._str_to_datetime(
                                            expiry_date
                                        )
                                        expiry_date = str(
                                            expiry_date.strftime(
                                                "%m/%d/%Y %I:%M:%S %p"
                                            )
                                        )
                                        is_revoked = indicator.get("revoked")
                                        comment = (
                                            f"Indicator with decay score "
                                            f"{decay_score}."
                                        )
                                        if is_revoked:
                                            comment += (
                                                f" This indicator is expired on "
                                                f"{expiry_date} (UTC time)."
                                            )
                                        else:
                                            comment += (
                                                f" This indicator is valid until "
                                                f"{expiry_date} (UTC time)."
                                            )
                                        if indicator.get("indicator_types"):
                                            opencti_indicator_types = (
                                                ", ".join(
                                                    indicator.get(
                                                        "indicator_types"
                                                    )
                                                )
                                            )
                                            comment += (
                                                " OpenCTI indicator types: "
                                                f"{opencti_indicator_types}"
                                            )
                                        if indicator.get("description"):
                                            description = indicator.get(
                                                "description"
                                            )
                                            comment += (
                                                f" OpenCTI description: "
                                                f"{description}"
                                            )
                                        data = {
                                            "comments": comment,
                                            "reputation": max(
                                                int(
                                                    indicator.get("confidence")
                                                    // 10
                                                ),
                                                1,
                                            ),
                                            "tags": tags,
                                            "active": not indicator.get(
                                                "revoked", False
                                            ),
                                            "firstSeen": created_time,
                                            "lastSeen": modified_time,
                                            "expiresAt": indicator.get(
                                                "valid_until"
                                            ),
                                            "extendedInformation": f"{base_url}/"
                                            "dashboard/observations/indicators/"
                                            f"{indicator.get('id')}",
                                        }
                                        extracted, is_skipped = (
                                            self._extract_observables_2x(
                                                indicator.get("pattern", ""),
                                                data,
                                            )
                                        )
                                        if is_skipped:
                                            skip_indicator = True
                                            continue
                                        current_extracted_indicators.extend(
                                            extracted
                                        )
                                    indicator_type_count[
                                        self._get_ioc_type_from_openCTI(
                                            indicator_type
                                        )
                                    ] += 1
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

                    total_indicators += len(current_extracted_indicators)
                    self.logger.info(
                        "{}: Successfully fetched {} indicator(s) and"
                        " skipped {} for page {}. Pull Stat: {} SHA256, "
                        "{} MD5, {} Url, {} Domain, {} IP, "
                        "and {} IPv6 indicator(s) "
                        "fetched. Total indicator(s) fetched -"
                        " {}.".format(
                            self.log_prefix,
                            len(current_extracted_indicators),
                            current_page_skip_count,
                            page_count,
                            indicator_type_count["sha256"],
                            indicator_type_count["md5"],
                            indicator_type_count["url"],
                            indicator_type_count["domain"],
                            indicator_type_count["ipv4"],
                            indicator_type_count["ipv6"],
                            total_indicators,
                        )
                    )

                if len(indicators_json_list) < LIMIT:
                    next_page = False
                else:
                    if resp_json["data"]["indicators"]["pageInfo"][
                        "hasNextPage"
                    ]:
                        after = resp_json["data"]["indicators"]["pageInfo"][
                            "endCursor"
                        ]
                    else:
                        next_page = False

                if page_count >= LIMIT and not is_retraction:
                    next_page = False
                if not next_page:
                    if len(total_skipped_tags) > 0:
                        self.logger.info(
                            f"{self.log_prefix}: {len(total_skipped_tags)} "
                            "tag(s) skipped as they were longer than expected "
                            "size or due to some other exceptions that "
                            "occurred while creation of them. tags: "
                            f"({', '.join(total_skipped_tags)})."
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{total_indicators} indicator(s) from "
                        f"{PLATFORM_NAME}."
                    )
                if current_extracted_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield current_extracted_indicators, {
                            "checkpoint": (
                                last_indicator.get("modified")
                                if last_indicator.get("modified")
                                else self._convert_datetime_to_openCTI_format(
                                    datetime.now()
                                )
                            )
                        }
                    else:
                        yield current_extracted_indicators
        except OpenCTIPluginException as ex:
            err_msg = (
                "Error occurred while pulling "
                f"indicators from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )

            if (
                current_extracted_indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield current_extracted_indicators
            else:
                raise OpenCTIPluginException(err_msg)

        except Exception as ex:
            err_msg = (
                "Unexpected error occurred while pulling "
                f"indicators from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            if (
                current_extracted_indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield current_extracted_indicators
            else:
                raise OpenCTIPluginException(err_msg)

    def pull(self):
        """Pull the data from the OpenCTI platform.

        Returns:
            Indicators: PullResult object with list of observables.
        """
        try:
            if self.configuration.get("is_pull_required").strip() == "Yes":
                if hasattr(self, "sub_checkpoint"):

                    def wrapper(self):
                        yield from self.get_indicators()

                    return wrapper(self)
                else:
                    indicators = []
                    for batch in self.get_indicators():
                        indicators.extend(batch)
                    return indicators
            else:
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
        except OpenCTIPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while pulling indicators"
                f" from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise OpenCTIPluginException(err_msg)

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push given indicators to OpenCTI Event.

        Args:
            indicators (List[Indicator]): List of indicators received from
            business rule.
            action_dict (Dict): Action Dictionary

        Returns:
            PushResult: PushResult containing flag and message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        if action_value != "indicators":
            err_msg = (
                "Invalid action parameter selected. Allowed "
                "value is Add Indicators."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise OpenCTIPluginException(err_msg)
        base_url, api_key = self.opencti_helper._get_credentials(
            self.configuration
        )
        headers = self.get_headers(api_key)
        source_label_tag = (
            f"Netskope CE | {plugin_name}" if plugin_name else None
        )
        default_tags_to_send = [DEFAULT_IOC_TAG]
        if source_label_tag:
            default_tags_to_send.append(source_label_tag)
        tag_ids = []
        for tag_name in default_tags_to_send:
            result = self._get_tag_id(base_url, api_key, tag_name, headers)
            if not result:
                query = """
                    mutation LabelCreationContextualMutation
                    ($input: LabelAddInput!) {
                    labelAdd(input: $input) {
                        id
                        value
                    }
                    }
                """
                variables = {"input": {"value": tag_name, "color": "#ff0000"}}

                payload = {"query": query, "variables": variables}

                resp_json = self.opencti_helper.api_helper(
                    method="POST",
                    url=GRAPHQL_API.format(base_url),
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"creating '{tag_name}' tag on {PLATFORM_NAME}"
                    ),
                    json=payload,
                )
                if (
                    resp_json
                    and resp_json.get("data", {}).get("labelAdd").get("value")
                    == tag_name.lower()
                ):
                    tag_ids.append(
                        resp_json.get("data", {}).get("labelAdd").get("id")
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created "
                        f"'{tag_name}' tag on {PLATFORM_NAME}."
                    )
                else:
                    err_msg = (
                        f"Unable to create '{tag_name}' "
                        f"tag on {PLATFORM_NAME}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(resp_json),
                    )
                    raise OpenCTIPluginException(err_msg)
            else:
                tag_ids.append(result)
        indicator_name = action_dict.get("parameters", {}).get(
            "indicator_name"
        )
        score = action_dict.get("parameters", {}).get("score")
        total_count = 0
        skipped_count = 0
        for indicator in indicators:
            tags_payload = tag_ids
            stix_patterns, is_skipped = self.create_stix_pattern(
                value=indicator.value, indicator_type=indicator.type
            )
            if is_skipped:
                skipped_count += 1
                continue
            indicator_input = {}
            indicator_input["name"] = indicator_name
            indicator_input["pattern_type"] = "stix"
            indicator_input["objectLabel"] = tags_payload
            indicator_input["pattern"] = stix_patterns
            indicator_input["confidence"] = int(indicator.reputation) * 10
            if indicator.type in (IndicatorType.SHA256, IndicatorType.MD5):
                indicator_input["x_opencti_main_observable_type"] = "StixFile"
            else:
                indicator_input["x_opencti_main_observable_type"] = (
                    self.netskope_to_opencti_map(indicator.type)
                )
            indicator_input["x_opencti_score"] = score
            variables = {"input": indicator_input}
            mutation = deepcopy(INDICATOR_MUTATION)
            try:
                self.opencti_helper.api_helper(
                    method="POST",
                    url=GRAPHQL_API.format(base_url),
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"creating '{indicator_name}' indicator on {PLATFORM_NAME}"
                    ),
                    json={"query": mutation, "variables": variables},
                )

                if resp_json.get("errors"):
                    skipped_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Fail to push data to "
                            f"{PLATFORM_NAME}, Error: {resp_json['errors']}"
                        )
                    )
                    continue
                total_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared"
                    f" indicator {indicator.value}. Total indicator"
                    f"(s) shared - {total_count}."
                )
            except (OpenCTIPluginException, Exception) as err:
                skipped_count += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while pushing"
                        f" indicators. Error: {str(err)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue

        self.logger.info(
            f"{self.log_prefix}: Successfully shared {total_count} indicator(s)"
        )
        if skipped_count > 0:
            self.logger.info(
                f"{self.log_prefix}: {skipped_count} indicator(s) will "
                f"not be shared or updated on {self.plugin_name} platform."
                " Invalid Domain, IP4, IPv6, Url or Hashes(SHA256, MD5)"
                " received."
            )
        return PushResult(
            success=True, message="Successfully pushed indicators."
        )

    def netskope_to_opencti_map(self, indicator_type):
        mapping = {
            "domain": "Domain-Name",
            "url": "Url",
            "ipv4": "IPv4-Addr",
            "ipv6": "IPv6-Addr",
        }
        if indicator_type not in mapping:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")
        return mapping[str(indicator_type.value)]

    def create_stix_pattern(self, value, indicator_type):
        """
        Create a STIX pattern for a given indicator.
        """
        indicator_type_fields = {
            "domain": "domain-name:value",
            "url": "url:value",
            "sha256": "file:hashes.'SHA-256'",
            "md5": "file:hashes.'MD5'",
            "ipv4": "ipv4-addr:value",
            "ipv6": "ipv6-addr:value",
        }

        if indicator_type not in indicator_type_fields:
            self.logger.error(
                f"Unsupported indicator type: {indicator_type}, indicator"
                " skipped."
            )
            return None, True

        # Construct the STIX pattern
        stix_pattern_field = indicator_type_fields[indicator_type]
        stix_pattern = f"[{stix_pattern_field} = '{value}']"

        return stix_pattern, False

    def _get_tag_id(
        self, base_url: str, api_key: str, tag_name: str, headers: str
    ) -> bool:
        """
        Get the ID of a tag with the given name.

        Args:
            base_url (str): Base URL for the OpenCTI API.
            api_key (str): API key for authentication.
            tag_name (str): Name of the tag to retrieve the ID for.
            headers (str): Headers for the request.

        Returns:
            str: ID of the tag, or None if not found.
        """
        variables = {"search": tag_name}
        try:
            resp_json = self.opencti_helper.api_helper(
                logger_msg="pulling tags from OpenCTI",
                url=GRAPHQL_API.format(base_url),
                json={"query": TAGS_ID_QUERY["query"], "variables": variables},
                method="POST",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling tags "
                    f"from OpenCTI. Error: {str(err)}"
                ),
                details=str(traceback.format_exc()),
            )
            return None
        tags = resp_json["data"]["labels"]["edges"]

        for tag in tags:
            if tag["node"]["value"] == tag_name:
                self.logger.info(
                    f"{self.log_prefix}: Tag '{tag_name}' found in OpenCTI."
                )
                return tag["node"]["id"]
        else:
            self.logger.info(
                f"{self.log_prefix}: Tag '{tag_name}' not found in OpenCTI."
            )
            return None

    def _get_indicators_id(
        self,
        base_url: str,
        iocs_dict: dict,
        tag_ids: List[int],
        headers: str,
    ) -> bool:
        """Is netskope-ce tag exists on OpenCTI.

        Args:
            base_url (str): Base URL for OpenCTI.
            api_key (str): Authentication Key for OpenCTI.
            values (list): List of values to search for.
            tag_ids (List[int]): List of tag IDs to search for.
            start_time (str): Start time for search.
            headers (str): Headers for the request.

        Returns:
            bool: True if tag exists else False.
        """
        try:
            query_filters = []
            query_filter = {
                "key": "objectLabel",
                "values": tag_ids,
                "operator": "eq",
                "mode": "or",
            }
            query_filters.append(query_filter)
            modified_values = []
            for value, types in iocs_dict.items():
                stix_patterns, is_skipped = self.create_stix_pattern(
                    value=value, indicator_type=types
                )
                if is_skipped:
                    continue
                modified_values.append(stix_patterns.strip('"'))
            query_filter = {
                "key": "pattern",
                "values": modified_values,
                "operator": "eq",
                "mode": "or",
            }
            query_filters.append(query_filter)
            modified_properties = deepcopy(INDICATOR_PAGINATION)
            graphql_variable = deepcopy(PAGINATION_VARIABLES)
            graphql_variable["filters"]["filters"].extend(query_filters)
            modified_properties.update({"variables": graphql_variable})
            resp_json = self.opencti_helper.api_helper(
                logger_msg="pulling indicators from OpenCTI",
                url=GRAPHQL_API.format(base_url),
                json=modified_properties,
                method="POST",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            iocs = resp_json["data"]["indicators"]["edges"]
            ioc_ids = []
            for ioc in iocs:
                if (
                    self.extract_ioc_value(ioc["node"]["pattern"])
                    in iocs_dict.keys()
                ):
                    ioc_ids.append(ioc["node"]["id"])

            return ioc_ids
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error while getting indicators id from"
                f" OpenCTI. {err}"
            )
            raise OpenCTIPluginException(
                "Error while getting indicators id from OpenCTI."
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add Indicators", value="indicators"),
        ]

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "indicators":
            return [
                {
                    "label": "Indicator Name",
                    "key": "indicator_name",
                    "type": "text",
                    "mandatory": True,
                    "default": "",
                    "description": (
                        "Name of the Indicators to be pushed to OpenCTI."
                    ),
                },
                {
                    "label": "Score",
                    "key": "score",
                    "type": "number",
                    "mandatory": True,
                    "default": 50,
                    "description": (
                        "This score is updated with the decay rule applied to "
                        "this indicator."
                    ),
                },
            ]

    def validate_action(self, action: Action):
        """Validate OpenCTI configuration."""
        if action.value not in ["indicators"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        event_name = action.parameters.get("indicator_name", "")
        if event_name is None:
            err_msg = "Indicator Name is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(event_name, str):
            err_msg = "Invalid Indicator Name provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        score = action.parameters.get("score", None)
        if not score:
            err_msg = "Score is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(score, (int)):
            err_msg = "Invalid Score provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for {action.value} "
            "action."
        )
        return ValidationResult(
            success=True,
            message=f"Validation successful for {action.value} action.",
        )

    def get_modified_indicators(self, source_indicators: List[List[Dict]]):
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            tuple: Modified Indicators and Status.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators status"
            f" from {PLATFORM_NAME}."
        )
        retraction_interval = self.configuration.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)
        start_time = datetime.now() - timedelta(days=retraction_interval)
        start_time = self._convert_datetime_to_openCTI_format(start_time)
        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                total_iocs = len(iocs)
                modified_indicators = self.get_indicators(
                    is_retraction=True, retraction_time=start_time
                )
                for indicator in modified_indicators:
                    iocs -= indicator
                self.logger.info(
                    f"{self.log_prefix}: {len(iocs)} indicator(s) will "
                    f"be marked as retracted from {total_iocs} total "
                    "active indicator(s) present in cloud exchange for"
                    f" {PLATFORM_NAME}."
                )

                yield list(iocs), False
            except Exception as err:
                err_msg = (
                    f"Error while fetching modified indicators from"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                    details=traceback.format_exc(),
                )
                raise OpenCTIPluginException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from CrowdStrike IOC Management.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix} : Retracting indicators from {PLATFORM_NAME}."
        )
        (base_url, api_key) = self.opencti_helper._get_credentials(
            self.configuration
        )
        headers = self.get_headers(api_key)
        retraction_batch_count = 1
        for retraction_batch in retracted_indicators_lists:
            retracted_iocs = {ioc.value: ioc.type for ioc in retraction_batch}
            tag_ids = self._get_tag_id(
                base_url, api_key, DEFAULT_IOC_TAG, headers
            )
            ioc_ids = []
            try:
                ioc_ids = self._get_indicators_id(
                    base_url=base_url,
                    iocs_dict=retracted_iocs,
                    tag_ids=tag_ids,
                    headers=headers,
                )

            except OpenCTIPluginException as err:
                self.logger.error(
                    message=(f"{self.log_prefix}: {err}"),
                    details=traceback.format_exc(),
                )
                yield ValidationResult(
                    success=False,
                    message=(
                        f"Error while deleting indicators for "
                        f"page no: {retraction_batch_count} error: {err}"
                    ),
                )
                retraction_batch_count += 1
                continue
            page = 1
            mutation = """
                    mutation DataTableToolBarListTaskAddMutation(
                    $input: ListTaskAddInput!
                    ) {
                    listTaskAdd(input: $input) {
                    __typename
                    id
                    type
                    }
                    }
                    """
            variables = {
                "input": {
                    "ids": ioc_ids,
                    "actions": [
                        {
                            "type": "DELETE",
                            "context": None,
                            "containerId": None,
                        }
                    ],
                    "scope": "KNOWLEDGE",
                }
            }
            try:
                self.opencti_helper.api_helper(
                    logger_msg=f"deleting {len(ioc_ids)} indicator(s) for"
                    f"page {page} from {PLATFORM_NAME}",
                    url=GRAPHQL_API.format(base_url),
                    json={"query": mutation, "variables": variables},
                    method="POST",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )

            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: Error while deleting indicators for "
                    f"page no: {retraction_batch_count} error: {err}"
                )
                yield ValidationResult(
                    success=False,
                    message=(
                        f"Error while deleting indicators for "
                        f"page no: {retraction_batch_count} error: {err}"
                    ),
                )
                retraction_batch_count += 1
                continue

            self.logger.info(
                f"{self.log_prefix}: Successfully retracted "
                f"{len(ioc_ids)} indicator(s) in page {page}"
                f" from {PLATFORM_NAME}."
            )

            yield ValidationResult(
                success=True,
                message=(
                    f"Completed execution of batch {retraction_batch_count}"
                    " for retraction."
                ),
            )
            retraction_batch_count += 1

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
        except Exception as err:
            self.logger.error(
                message=(
                    f"Exception occurred while converting to datetime"
                    f"Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return datetime.now()

    def _extract_observables_2x(
        self, pattern: str, data=None, is_retraction=False
    ):
        """
        Extracts observables from given pattern and returns them as Indicator
        objects.

        Args:
            pattern (str): Pattern to extract observables from.
            data (dict, optional): Additional data to add to Indicator objects.
            is_retraction (bool, optional): If True, returns the observables
            as strings instead of Indicator objects, and sets the "deleted"
            attribute to True. Defaults to False.

        Returns:
            tuple: A tuple containing the list of extracted observables and a
            boolean indicating whether any observables were found.
        """
        observables = []
        is_skipped = False
        for kind in OBSERVABLE_REGEXES:
            matches = re.findall(kind["regex"], pattern, re.IGNORECASE)
            if len(matches) == 0:
                is_skipped = is_skipped or False
            else:
                is_skipped = is_skipped or True
            for match in matches:
                if kind["type"] in [IndicatorType.SHA256, IndicatorType.MD5]:
                    try:
                        if is_retraction:
                            observables.append(match.replace("'", ""))
                        else:
                            observables.append(
                                Indicator(
                                    value=match.replace("'", ""),
                                    type=kind["type"],
                                    **data,
                                )
                            )
                    except Exception as exp:
                        is_skipped = True
                        self.logger.error(
                            f"{self.log_prefix}: Error while extracting"
                            f" observable: {str(exp)}"
                        )
                else:
                    try:
                        if is_retraction:
                            observables.append(match[1])
                        else:
                            observables.append(
                                Indicator(
                                    value=match[1], type=kind["type"], **data
                                )
                            )
                    except Exception as exp:
                        self.logger.error(
                            f"{self.log_prefix}: Error while extracting"
                            f" observable: {str(exp)}"
                        )
                        is_skipped = True

        return observables, not (is_skipped)
