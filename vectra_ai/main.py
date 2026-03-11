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

CTE Vectra AI plugin.
"""

import ipaddress
import re
import traceback
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Tuple, Union
from urllib.parse import urlparse

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.constants import (
    ENTITY_TYPES,
    DATE_FORMAT_FOR_IOCS,
    DETECTION_CATEGORY,
    DETECTION_LIMIT,
    DETECTION_STATE,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    ENDPOINTS,
)
from .utils.helper import VectraAIPluginException, VectraAIPluginHelper


class VectraAIPlugin(PluginBase):
    """Vectra AI Plugin class template implementation."""

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
        self.vectra_ai_helper = VectraAIPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _is_valid_domain(self, hostname: str) -> Tuple[bool, str]:
        """Validate whether a given hostname is a valid domain.

        Args:
            hostname (str): The hostname to validate.

        Returns:
            Tuple[bool, str]: A tuple of a boolean indicating whether the
            Hostname is valid, and the domain candidate.
        """
        try:
            if hostname.isdigit():
                return False, hostname

            if "#ext#" in hostname:
                parts = hostname.split("#ext#")
                domain_candidate = parts[-1].split("@")[-1]
            else:
                domain_candidate = hostname.split("@")[-1]
            domain_regex = r"""
            (?<!-)
            (?<![:\/\w.])
            (?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?
            (?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*
            \.[a-zA-Z]{2,}
            |
            (?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?
            (?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*
            \.[a-zA-Z]{2,}
            )
            (?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?
            (?:\/)?(?![:\/\w])
            """

            return (
                bool(re.fullmatch(domain_regex, domain_candidate, re.VERBOSE)),
                domain_candidate.strip(),
            )
        except Exception:
            return False, hostname

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        validation_error_msg = "Validation error occurred."
        vectra_url, client_id, client_secret_key = (
            self.vectra_ai_helper._get_auth_params(configuration)
        )

        # Vectra Portal URL validation
        if not vectra_url:
            err_msg = (
                "Vectra Portal URL is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(vectra_url, str) or not self._validate_url(
            vectra_url
        ):
            err_msg = (
                "Invalid Vectra Portal URL provided in configuration "
                "parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # API Client ID validation
        if not client_id:
            err_msg = "API Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = (
                "Invalid API Client ID provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # API Client Secret Key validation
        if not client_secret_key:
            err_msg = (
                "API Client Secret Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret_key, str):
            err_msg = (
                "Invalid API Client Secret Key"
                "provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Entity Type validation
        entity_type = configuration.get("type", "")
        if entity_type and entity_type not in ENTITY_TYPES:
            err_msg = (
                "Invalid value provided for Entity Type. "
                "Allowed values are 'Account', 'Host' or "
                "'All Entity Types'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # State validation
        state = configuration.get("state", "").strip()
        if state and state not in DETECTION_STATE:
            err_msg = (
                "Invalid value for State provided. Allowed values are "
                "'Active','Inactive' 'Ignored', 'Ignored for All'"
                " or 'All States'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Detection Category Validation
        detection_category = configuration.get("detection_category", [])
        if detection_category and not all(
            dec_cat in DETECTION_CATEGORY for dec_cat in detection_category
        ):
            err_msg = (
                "Invalid value for Detection Category "
                "provided. Allowed values are "
                "'Command','Botnet','Reconnaissance',"
                "'Lateral','Exfiltration' and 'Info'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Certainty Validation
        certainty = configuration.get("certainty")
        if certainty and not isinstance(certainty, int):
            err_msg = (
                "Invalid value provided in Certainty configuration parameter."
                "Certainty should be an integer value."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif certainty and (certainty < 0 or certainty > INTEGER_THRESHOLD):
            err_msg = (
                "Certainty should be an integer greater than or equal to 0 "
                "and less than 2^62."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Tags validation
        tags = configuration.get("tags", "").strip()
        if (tags and not isinstance(tags, str)):
            err_msg = "Invalid Tags provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Retraction Interval validation
        retraction_interval = configuration.get("retraction_interval")
        if (
            isinstance(retraction_interval, int)
            and retraction_interval is not None
        ):
            if int(retraction_interval) <= 0:
                err_msg = (
                    "Invalid Retraction Interval provided in configuration"
                    " parameters. Valid value should be an integer "
                    "greater than 0."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_error_msg} {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif int(retraction_interval) > INTEGER_THRESHOLD:
                err_msg = (
                    "Invalid Retraction Interval provided in configuration"
                    " parameters. Valid value should be an integer "
                    "greater than 0 and less than 2^62."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_error_msg} {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        elif retraction_interval:
            err_msg = (
                "Invalid Retraction Interval provided in the "
                "configuration parameters. Provide a valid integer value"
                " for the Retraction Interval."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_error_msg} {err_msg}",
                details=(
                    f"Retraction Interval: {retraction_interval}, "
                    f"Retraction Interval type: {type(retraction_interval)}"
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Enable Tagging validation
        enable_tagging = configuration.get("enable_tagging", "").strip()
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif enable_tagging not in ["yes", "no"]:
            err_msg = (
                "Invalid value provided for Enable Tagging configuration "
                "parameter. Allowed values are 'Yes' or 'No'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Initial Range validation
        initial_range = configuration.get("days", 0)
        if initial_range is None:
            err_msg = (
                "Initial Range (in days) is "
                "a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
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
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif initial_range <= 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self._validate_credentials(configuration, validation_error_msg)

    def convert_into_date_time(self, date: str):
        """Convert str to datetime object.

        Args:
            date (str): str.

        Returns:
            datetime: datetime object.
        """
        try:
            return (
                date.strftime(DATE_FORMAT_FOR_IOCS) if date else
                datetime.now().strftime(DATE_FORMAT_FOR_IOCS)
            )
        except Exception:
            current_time = datetime.now().strftime(DATE_FORMAT_FOR_IOCS)
            return current_time

    def _is_valid_ipv4(self, address: str) -> Tuple[bool, str]:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True, address
        except Exception:
            return False, address

    def _create_label_tags(self, labels: list) -> List[str]:
        """Create and return a list of tag names based on detection labels.

        If a tag for the label doesn't exist in Netskope, one is created.

        Args:
            labels (list): label objects for a given detection.

        Returns:
            List[str]: the label tag names, of the form key:value.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()
        for label in labels:
            try:
                if not tag_utils.exists(label):
                    tag_utils.create_tag(TagIn(name=label, color="#ED3347"))
                created_tags.add(label)
            except ValueError:
                skipped_tags.add(label)
            except Exception:
                skipped_tags.add(label)

        return list(created_tags), list(skipped_tags)

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = VectraAIPlugin.metadata
            plugin_name = metadata.get("name", PLUGIN_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _validate_credentials(
        self,
        configuration: dict,
        validation_err_msg: str = "",
    ):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            logger_msg = f"validating credentials of {PLUGIN_NAME} account"
            auth_headers = self.vectra_ai_helper.get_auth_headers(
                configuration=configuration, is_validation=True
            )
            vectra_url, _, _ = self.vectra_ai_helper._get_auth_params(
                configuration
            )
            detection_url = (
                f"{vectra_url}{ENDPOINTS.get('detection')}?page_size=1"
            )
            response = self.vectra_ai_helper.api_helper(
                url=detection_url,
                method="GET",
                headers=auth_headers,
                configuration=configuration,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=True,
                logger_msg=(
                    f"fetching detections from {PLATFORM_NAME} "
                    "to validate credential permissions"
                ),
            )
            if response:
                logger_msg = "Successfully validated credentials."
                self.logger.debug(f"{self.log_prefix}: {logger_msg}")
                return ValidationResult(
                    success=True,
                    message="Validation successful.",
                )
            else:
                err_msg = "Verifying permissions assigned"
                "to the provided API Client ID and API Client Secret Key."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except VectraAIPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Unexpected error occurred. "
                    "Check logs for more details."
                ),
            )

    def pull(self) -> List[Indicator]:
        """Pull the detection  from Vectra AI.

        Returns:
            List[cte.models.Indicators]: List of indicator o
            bjects received from the Vectra AI.
        """
        try:
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self._pull()

                return wrapper(self)
            else:
                indicators = []
                for batch, _ in self._pull():
                    indicators.extend(batch)
                self.logger.info(
                    f"{self.log_prefix}: Total {len(indicators)}"
                    " indicator(s) fetched."
                )
                return indicators
        except VectraAIPluginException:
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
            raise VectraAIPluginException(err_msg)

    def _pull(
        self,
        is_retraction: bool = False,
        retraction_time: str = "",
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Pull detection from Vectra AI.

        This function retrieves detections from the Vectra AI portal and
        creates indicators for them. It paginates through the detections
        and handles the last successful fetch time.

        Yields:
            List[cte.models.Indicators]: List of indicator objects
            received from the Vectra AI.
            Optional[Dict[str, str]]: last successful fetch time.

        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        indicator_list = ([], set())[is_retraction]
        total_skipped_tags = set()
        params, ioc_counts = {}, {}
        next_page = True
        page_count = 1
        checkpoint = ""
        vectra_url, _, _ = self.vectra_ai_helper._get_auth_params(
            self.configuration
        )
        detection_url = (
            f"{vectra_url}{ENDPOINTS.get('detection')}"
        )
        auth_headers = self.vectra_ai_helper.get_auth_headers(
            configuration=self.configuration,
            is_retraction=is_retraction
        )
        start_time = None
        sub_checkpoint = getattr(self, "sub_checkpoint")
        if is_retraction and retraction_time:
            start_time = retraction_time
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            start_time = sub_checkpoint.get("checkpoint")
        elif self.last_run_at:
            start_time = self.convert_into_date_time(self.last_run_at)
        else:
            initial_range = self.configuration.get("days")
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying detections for "
                f"last {initial_range} days."
            )
            start_time = self.convert_into_date_time(
                datetime.now() - timedelta(days=initial_range)
            )

        entity_type = self.configuration.get("type", "")
        if entity_type:
            if entity_type != "all_entity_types":
                params["type"] = entity_type

        state = self.configuration.get("state", "")
        if state:
            if state != "all_states":
                params["state"] = state

        detection_category = self.configuration.get("detection_category", None)
        if detection_category:
            params["detection_category"] = ",".join(detection_category)
        else:
            params["detection_category"] = ",".join(DETECTION_CATEGORY)

        if self.configuration.get("certainty", None):
            params["certainty_gte"] = self.configuration.get("certainty")

        if self.configuration.get("tags", ""):
            params["tags"] = self.configuration.get("tags")

        params.update(
            {
                "page": page_count,
                "page_size": DETECTION_LIMIT,
                "ordering": "last_timestamp",
                "last_timestamp_gte": start_time,
            }
        )
        self.logger.info(
            f"{self.log_prefix}: Pulling detections from "
            f"checkpoint: {str(start_time)}"
        )
        try:
            while next_page:
                page_indicators = set() if is_retraction else []
                response = self.vectra_ai_helper.api_helper(
                    url=detection_url,
                    method="GET",
                    params=params,
                    headers=auth_headers,
                    configuration=self.configuration,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                    logger_msg=(f"pulling detection for page {page_count}"),
                )
                results = response.get("results", [])
                if results:
                    page_indicators, ioc_counts, page_skipped_tags = (
                        self._make_indicator(
                            results,
                            vectra_url,
                            is_retraction
                        )
                    )
                    total_skipped_tags.update(page_skipped_tags)
                    if is_retraction:
                        indicator_list.update(page_indicators)
                    else:
                        indicator_list += page_indicators

                    if response.get("next"):
                        detection_url = response.get("next")
                        params = {}
                    else:
                        next_page = False
                    checkpoint = response["results"][-1]["last_timestamp"]
                    skipped_indicators = (
                        ioc_counts["skipped_hostname"] +
                        ioc_counts["skipped_ipv4"]
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{len(page_indicators)} indicator(s) "
                        f"and skipped {skipped_indicators} "
                        f"out of {len(results)} detection(s) for "
                        f"page {page_count} from {PLATFORM_NAME}. "
                        f"Pull Stats: {ioc_counts['hostname']} Domain, "
                        f"{ioc_counts['ipv4']} IPv4 indicator(s) fetched. "
                        f"Total indicator(s) fetched - {len(indicator_list)}."
                    )
                else:
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
                        f"{len(indicator_list)} indicator(s) from "
                        f"{PLATFORM_NAME}."
                    )
                if page_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield page_indicators, {"checkpoint": checkpoint}
                    else:
                        yield page_indicators
                page_count += 1
        except VectraAIPluginException:
            raise
        except Exception:
            err_msg = (
                f"Unexpected error occurred while pulling "
                f"detection for page {page_count}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )

    def _make_indicator(
        self, detection_list, vectra_url, is_retraction: bool = False
    ) -> List[Indicator]:
        """Create indicators for a list of Vectra AI detections.

        This function takes a list of Vectra AI detections
        and creates indicators for them.

        Returns:
            List[Indicator]: a list of indicators for the detections.
            datetime: the last successful fetch time.
        """
        ioc_counts = {
            "ipv4": 0,
            "hostname": 0,
            "skipped_ipv4": 0,
            "skipped_hostname": 0,
        }
        indicator_list, page_skipped_tags = ([], set())[is_retraction], set()
        enable_tagging = self.configuration.get("enable_tagging", "yes")
        for detection in detection_list:
            try:
                if detection.get("type", "") == "account":
                    if detection.get("src_account", {}).get("name", ""):

                        domain_validation, domain = self._is_valid_domain(
                            detection.get("src_account")
                            .get("name")
                            .split(":", 1)[-1]
                        )
                        if is_retraction and domain_validation:
                            indicator_list.add(domain)
                            continue

                        if domain_validation:
                            tags = []
                            lastSeen, firstSeen = None, None
                            comments, extendedInfo = "", ""
                            reputation = 1
                            indicator_type = (
                                IndicatorType.DOMAIN
                                if hasattr(IndicatorType, "DOMAIN")
                                else IndicatorType.URL
                            )
                            if "certainty" in detection:
                                reputation = max(
                                    int(detection.get("certainty") // 10), 1
                                )
                            if "id" in detection:
                                extendedInfo = (
                                    f"{vectra_url}/detections/"
                                    f"{detection.get('id', '')}"
                                )
                            if detection.get("summary", {}).get("description"):
                                comments = detection.get("summary").get(
                                    "description", ""
                                )

                            if "first_timestamp" in detection:
                                firstSeen = detection.get("first_timestamp")

                            if "last_timestamp" in detection:
                                lastSeen = detection.get("last_timestamp")
                            if (
                                detection.get("tags", "") and
                                enable_tagging == "yes"
                            ):
                                tags, skipped_tags = self._create_label_tags(
                                    detection.get("tags")
                                )
                                page_skipped_tags.update(skipped_tags)
                            try:
                                indicator_list.append(
                                    Indicator(
                                        value=domain,
                                        type=indicator_type,
                                        reputation=reputation,
                                        comments=comments,
                                        firstSeen=firstSeen,
                                        lastSeen=lastSeen,
                                        tags=tags,
                                        extendedInformation=extendedInfo,
                                    )
                                )
                            except (ValidationError, Exception) as error:
                                error_message = (
                                    "Validation error occurred"
                                    if isinstance(error, ValidationError)
                                    else "Unexpected error occurred"
                                )
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: {error_message} "
                                        "while creating indicator for "
                                        f"{domain}. This record "
                                        f"will be skipped. Error: {error}."
                                    ),
                                    details=str(traceback.format_exc()),
                                )
                                ioc_counts["skipped_hostname"] += 1
                            ioc_counts["hostname"] += 1
                        else:
                            ioc_counts["skipped_hostname"] += 1
            except Exception:
                err_msg = (
                    "Unexpected error occurred while "
                    f"creating indicator for {domain}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(traceback.format_exc())
                )
                ioc_counts["skipped_hostname"] += 1
            try:
                if detection.get("type", "") == "host":
                    if detection.get("src_host", {}).get("ip", ""):
                        ip_validation, ip = self._is_valid_ipv4(
                            detection.get("src_host").get("ip")
                        )
                        if ip_validation and is_retraction:
                            indicator_list.add(ip)
                            continue
                        if ip_validation:
                            tags = []
                            lastSeen, firstSeen = None, None
                            comments, extendedInfo = "", ""
                            reputation = 1
                            indicator_type = (
                                IndicatorType.IPV4
                                if hasattr(IndicatorType, "IPV4")
                                else IndicatorType.URL
                            )
                            if "certainty" in detection:
                                reputation = max(
                                    int(detection.get("certainty") // 10), 1
                                )
                            if "id" in detection:
                                extendedInfo = (
                                    f"{vectra_url}/detections/"
                                    f"{detection.get('id', '')}"
                                )

                            if detection.get("summary", {}).get("description"):
                                comments = detection.get("summary").get(
                                    "description", ""
                                )

                            if "first_timestamp" in detection:
                                firstSeen = detection.get("first_timestamp")

                            if "last_timestamp" in detection:
                                lastSeen = detection.get("last_timestamp")

                            if (
                                detection.get("tags", "") and
                                enable_tagging == "yes"
                            ):
                                tags, skipped_tags = self._create_label_tags(
                                    detection.get("tags")
                                )
                                page_skipped_tags.update(skipped_tags)

                            try:
                                indicator_list.append(
                                    Indicator(
                                        value=ip,
                                        type=indicator_type,
                                        reputation=reputation,
                                        comments=comments,
                                        firstSeen=firstSeen,
                                        lastSeen=lastSeen,
                                        tags=tags,
                                        extendedInformation=extendedInfo,
                                    )
                                )
                            except (ValidationError, Exception) as error:
                                error_message = (
                                    "Validation error occurred"
                                    if isinstance(error, ValidationError)
                                    else "Unexpected error occurred"
                                )
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: {error_message} "
                                        "while creating indicator for "
                                        f"{ip}. This record "
                                        f"will be skipped. Error: {error}."
                                    ),
                                    details=str(traceback.format_exc()),
                                )
                                ioc_counts["skipped_ipv4"] += 1
                            ioc_counts["ipv4"] += 1
                    else:
                        ioc_counts["skipped_ipv4"] += 1
            except Exception:
                err_msg = (
                    "Unexpected error occurred while "
                    f"creating indicator for {ip}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(traceback.format_exc())
                )
                ioc_counts["skipped_ipv4"] += 1
        return indicator_list, ioc_counts, page_skipped_tags

    def get_modified_indicators(self, source_indicators: List[List[Dict]]):
        """Get all modified indicators status.

        This function retrieves detections from Vectra AI
        that have been modified within the last retraction interval.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            List of retracted indicators, Status (List, bool): List of
                retracted indicators values. Status of execution.
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
        start_time = self.convert_into_date_time(
            datetime.now() - timedelta(days=retraction_interval)
        )
        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                total_iocs = len(iocs)
                modified_indicators = self._pull(
                    is_retraction=True, retraction_time=start_time
                )
                for indicator in modified_indicators:
                    iocs -= indicator
                self.logger.info(
                    f"{self.log_prefix}: {len(iocs)} indicator(s) will "
                    f"be marked as retracted from {total_iocs} total "
                    "indicator(s) present in cloud exchange for"
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
                raise VectraAIPluginException(err_msg)
