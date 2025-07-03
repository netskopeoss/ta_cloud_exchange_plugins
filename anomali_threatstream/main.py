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

import hashlib
import ipaddress
import json
import math
import re
import traceback
from datetime import datetime, timedelta
from sys import getsizeof
from typing import Dict, Generator, List, Tuple, Union
from urllib.parse import urlparse

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
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.anomali_threatstream_constant import (
    ANOMALI_SEVERITY,
    ANOMALI_SEVERITY_MAPPING,
    ANOMALI_STATUS,
    BYTES_TO_MB,
    DATE_FORMAT_FOR_IOCS,
    DEFAULT_REPUTATION,
    INDICATOR_TYPES,
    INTEGER_THRESHOLD,
    MAX_PAGE_SIZE,
    MODULE_NAME,
    PAGE_LIMIT,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PREFIX_IOC_SOURCE,
    RETRACTION,
    SEPARATOR,
    SEVERITY_MAPPING,
    TAG_NAME,
    TARGET_SIZE_MB,
)
from .utils.anomali_threatstream_helper import (
    AnomaliThreatstreamPluginException,
    AnomaliThreatstreamPluginHelper,
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
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.anomali_threatstream_helper = AnomaliThreatstreamPluginHelper(
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

    def get_headers(self, user_name: str, api_key: str) -> Dict:
        """Get headers required for the API call.
        Args:
            - user_name (str): Anomali ThreatStream Platform Username.
            - api_key (str): Anomali ThreatStream Platform API Key.
        """
        return self.anomali_threatstream_helper._add_user_agent(
            {
                "Authorization": f"apikey {user_name}:{api_key}",
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
        (base_url, user_name, api_key) = self._get_credentials(configuration)

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

        if not user_name:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(user_name, str):
            err_msg = "Invalid Username provided in configuration parameters."
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
            err_msg = "Type of Threat data to pull is a required configuration parameter."
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
            err_msg = (
                "Invalid value for Type of Threat data to pull provided. "
                "Allowed values are 'IP','IPv6', 'Domain', 'URL', "
                "'Hash [SHA256]', or 'Hash [MD5]'."
            )
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
        elif confidence and not 0 <= confidence <= 100:
            err_msg = "Minimum Confidence should be in range of 0 to 100."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        severity = configuration.get("severity", [])
        if severity and not all(sev in ANOMALI_SEVERITY for sev in severity):
            err_msg = (
                "Invalid value for Severity provided. Allowed values are "
                "'Low', 'Medium', 'High' or 'Very-High'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        status = configuration.get("status", [])
        if status and not all(stat in ANOMALI_STATUS for stat in status):
            err_msg = (
                "Invalid value for Status provided. Allowed values are "
                "'Active','Inactive' or 'False Positive'."
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

        feed_id = configuration.get("feed_id", "").strip()
        if feed_id and not isinstance(feed_id, str):
            err_msg = "Invalid Feed ID provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            feed_id
            and not self.anomali_threatstream_helper.validate_comma_separated_values(
                feed_id
            )
        ):
            err_msg = (
                "Invalid Feed ID provided. Feed ID should be a numeric comma "
                "separated values or single value."
            )
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
        elif initial_range <= 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 to 2^62."
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
            (base_url, user_name, api_key) = self._get_credentials(
                configuration
            )

            query_params = {"limit": 1}
            headers = self.get_headers(user_name, api_key)
            self.anomali_threatstream_helper.api_helper(
                logger_msg="validating authentication parameters",
                url=f"{base_url}/api/v2/intelligence",
                method="GET",
                params=query_params,
                headers=headers,
                is_validation=True,
                verify=self.ssl_validation,
                proxies=self.proxy,
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
            return (
                datetime.strptime(date, DATE_FORMAT_FOR_IOCS)
                if date
                else None
            )
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
        regex = r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$"  # noqa
        return True if re.match(regex, value) else False

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
                    tag_utils.create_tag(
                        TagIn(name=tag_name, color="#ED3347")
                    )
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

    def pull(self):
        """Pull the data from the Anomali ThreatStream platform.

        Returns:
            Indicators: PullResult object with list of observables.
        """
        try:
            if self.configuration.get("is_pull_required") == "Yes":
                if hasattr(self, "sub_checkpoint"):

                    def wrapper(self):
                        yield from self.get_indicators()

                    return wrapper(self)
                else:
                    indicators = []
                    for batch in self.get_indicators():
                        indicators.extend(batch)

                    self.logger.info(
                        f"{self.log_prefix}: Total {len(indicators)} "
                        "indicator(s) fetched."
                    )
                    return indicators
            else:
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
        except AnomaliThreatstreamPluginException:
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
            raise AnomaliThreatstreamPluginException(err_msg)

    def _convert_datetime_to_anomali_format(self, date_time: datetime) -> str:
        """
        Convert a datetime object to a string in the Anomali ThreatStream
          format.

        Args:
            date_time (datetime): The datetime object to convert.

        Returns:
            str: The datetime string in the Anomali ThreatStream format.
        """
        return date_time.isoformat(sep="T", timespec="milliseconds") + "Z"

    def get_indicators(
        self,
        is_retraction: bool = False,
        retraction_time: str = "",
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """
        Retrieves a list of indicators from the API.

        Args:
            - is_retraction (bool): A boolean flag indicating
            retraction is required or not.
            - retraction_time (str): A string representing the
            retraction time.
        Returns:
            - Generator[Indicator, bool, None]: A Generator of Indicator
                objects
            representing the retrieved indicators.
            - Dict: A dictionary containing the checkpoint details.

        Raises:
            AnomaliThreatstreamPluginException: If an error occurs while
            executing the pull cycle.
            Exception: If an unexpected error occurs while executing the
            pull cycle.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        (base_url, user_name, api_key) = self._get_credentials(
            self.configuration
        )
        query_endpoint = f"{base_url}/api/v2/intelligence"
        headers = self.get_headers(user_name, api_key)

        storage = self.storage if self.storage is not None else {}

        last_updated = storage.get("last_updated", "")

        start_time = None
        sub_checkpoint = getattr(self, "sub_checkpoint", {})
        if is_retraction and retraction_time:
            start_time = retraction_time
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            start_time = sub_checkpoint.get("checkpoint")
        elif last_updated:
            start_time = last_updated
        elif self.last_run_at:
            start_time = self._convert_datetime_to_anomali_format(
                self.last_run_at
            )
        else:
            initial_days = self.configuration.get("days")
            start_time = datetime.now() - timedelta(days=initial_days)
            start_time = self._convert_datetime_to_anomali_format(start_time)

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint: {start_time}"
        )
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
        indicator_types = self._get_indicator_types(
            threat_types=self.configuration.get("indicator_type")
        )
        query_params["type"] = ",".join(
            [
                (
                    "hash"
                    if indicator_type in ["md5", "sha256"]
                    else indicator_type
                )
                for indicator_type in indicator_types
            ]
        )

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

        tags = self.configuration.get("tags", "").strip()
        if tags:
            query_params["tags"] = tags

        feeding_ids = self.configuration.get("feed_id", "").strip()
        if feeding_ids:
            query_params["feed_id"] = feeding_ids

        last_indicator = None
        next_page = True
        total_skipped_tags = set()
        total_indicators = 0
        page_count = 0
        try:
            while next_page:
                page_count += 1
                indicator_type_count = {
                    indicator_type: 0 for indicator_type in indicator_types
                }
                current_page_skip_count = 0
                current_extracted_indicators = set() if is_retraction else []
                logger_msg = (
                    f"pulling data for page {page_count} from {PLATFORM_NAME}"
                )
                resp_json = self.anomali_threatstream_helper.api_helper(
                    logger_msg=logger_msg,
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                )
                indicators_json_list = resp_json.get("objects", [])
                if not indicators_json_list:
                    if not is_retraction:
                        storage.clear()
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
                                if tag.get("name", "") == TAG_NAME:
                                    skip_indicator = True
                                    break
                        if not skip_indicator:
                            if self.configuration.get("enable_tagging", "Yes") == "No":
                                tags_data = []

                            indicator_type = indicator.get("type", "")
                            if indicator.get("value") and indicator_type:
                                tags, skipped_tags = self.create_tags(
                                    tags_data
                                )
                                total_skipped_tags.update(skipped_tags)

                                description = indicator.get("description")
                                if (
                                    indicator_type == IndicatorType.MD5
                                    and indicator.get("subtype") == "SHA256"
                                ):
                                    indicator_type = IndicatorType.SHA256
                                if is_retraction:
                                    current_extracted_indicators.add(
                                        indicator.get("value")
                                    )
                                else:
                                    first_seen = self.convert_into_date_time(
                                        indicator.get("created_ts")
                                    )
                                    last_seen = self.convert_into_date_time(
                                        indicator.get("modified_ts")
                                    )
                                    current_extracted_indicators.append(
                                        Indicator(
                                            value=indicator.get("value"),
                                            type=indicator_types.get(
                                                indicator_type
                                            ),
                                            firstSeen=first_seen,
                                            lastSeen=last_seen,
                                            severity=SEVERITY_MAPPING.get(
                                                indicator.get("meta", {}).get(
                                                    "severity",
                                                    SeverityType.UNKNOWN,
                                                ),
                                            ),
                                            tags=tags,
                                            reputation=self.get_reputation(
                                                indicator.get(
                                                    "confidence", ""
                                                )
                                            ),
                                            comments=(
                                                description
                                                if description is not None
                                                else ""
                                            ),
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

                # parsed_indicators.extend(current_extracted_indicators)
                total_indicators += len(current_extracted_indicators)

                self.logger.info(
                    "{}: Successfully fetched {} indicator(s) and"
                    " skipped {} for page {}. Pull Stat: {} SHA256, "
                    "{} MD5, {} URL, {} Domain, {} IP, "
                    "and {} IPv6 indicator(s) "
                    "fetched. Total indicator(s) fetched -"
                    " {}.".format(
                        self.log_prefix,
                        len(current_extracted_indicators),
                        current_page_skip_count,
                        page_count,
                        indicator_type_count.get("sha256", 0),
                        indicator_type_count.get("md5", 0),
                        indicator_type_count.get("url", 0),
                        indicator_type_count.get("domain", 0),
                        indicator_type_count.get("ip", 0),
                        indicator_type_count.get("ipv6", 0),
                        total_indicators,
                    )
                )

                if len(indicators_json_list) < MAX_PAGE_SIZE:
                    if not is_retraction:
                        storage.clear()
                    next_page = False
                else:
                    query_params["update_id__gt"] = last_indicator.get(
                        "update_id"
                    )

                if page_count >= PAGE_LIMIT and not is_retraction:
                    # The threshold condition should only work for
                    # Normal pulling and not retraction.
                    storage.clear()
                    if last_indicator and last_indicator.get("modified_ts"):
                        storage["last_updated"] = last_indicator.get(
                            "modified_ts"
                        )

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
                                last_indicator.get("modified_ts")
                                if last_indicator.get("modified_ts")
                                else self._convert_datetime_to_anomali_format(
                                    datetime.now()
                                )
                            )
                        }
                    else:
                        yield current_extracted_indicators
        except AnomaliThreatstreamPluginException as ex:
            if not is_retraction and not hasattr(self, "sub_checkpoint"):
                storage.clear()
                if last_indicator and last_indicator.get("modified_ts"):
                    storage["last_updated"] = last_indicator.get(
                        "modified_ts"
                    )
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
                raise AnomaliThreatstreamPluginException(err_msg)

        except Exception as ex:
            if not is_retraction and not hasattr(self, "sub_checkpoint"):
                storage.clear()
                if last_indicator and last_indicator.get("modified_ts"):
                    storage["last_updated"] = last_indicator.get(
                        "modified_ts"
                    )
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
                raise AnomaliThreatstreamPluginException(err_msg)

    def push(
        self,
        indicators: list,
        action_dict: dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
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
                    f"{self.log_prefix}: No indicators found to push."
                )
                return PushResult(
                    success=True, message="No indicators found."
                )
            default_tags = [
                {"name": TAG_NAME},
            ]
            if plugin_name:
                default_tags.append(
                    {"name": f"{PREFIX_IOC_SOURCE} {SEPARATOR} {plugin_name}"}
                )
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
                tags.extend(default_tags)
                payload = {
                    "tags": tags,
                    "severity": ANOMALI_SEVERITY_MAPPING.get(
                        indicator.severity
                    ),
                    "confidence": indicator.reputation * 10,
                }

                if str(indicator.type.value) in {
                    "url",
                    "domain",
                    "ipv4",
                    "ipv6",
                }:
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
                if payload:
                    objects.append(payload)

            results = []
            size_in_bytes = getsizeof(json.dumps(objects))
            # Convert bytes to megabytes
            size_in_mb = size_in_bytes / BYTES_TO_MB
            if size_in_mb > TARGET_SIZE_MB:
                chunk_data = self.anomali_threatstream_helper.split_into_size(
                    objects
                )
                results.extend(chunk_data)
            elif objects:
                results.append(objects)

            (base_url, user_name, api_key) = self._get_credentials(
                self.configuration
            )
            headers = self.get_headers(user_name, api_key)
            final_payload = {
                "meta": {
                    "classification": "private",
                    "allow_unresolved": True,
                    "allow_update": True,
                    "enrich": False,
                },
            }

            page_count = 0
            total_count = 0
            for result in results:
                page_count += 1
                final_payload["objects"] = result
                try:
                    logger_msg = (
                        f"pushing indicators to {self.plugin_name} "
                        f"for page {page_count}"
                    )
                    self.anomali_threatstream_helper.api_helper(
                        logger_msg=logger_msg,
                        url=f"{base_url}/api/v2/intelligence/",
                        method="PATCH",
                        data=json.dumps(final_payload),
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
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
            return PushResult(
                success=True, message="Successfully pushed indicators."
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="share_ioc")
        ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Anomali configuration.

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

        return ValidationResult(
            success=True, message="Validation successful."
        )

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
                        {
                            "key": "Compromised URL",
                            "value": "compromised_url",
                        },
                        {"key": "Cryptocurrency URL", "value": "crypto_url"},
                        {"key": "Downloader URL", "value": "downloader_url"},
                        {
                            "key": "Data Exfiltration URL",
                            "value": "exfil_url",
                        },
                        {"key": "Exploit Kit URL", "value": "exploit_url"},
                        {"key": "Fraud URL", "value": "fraud_url"},
                        {
                            "key": "IP Geolocation URL",
                            "value": "geolocation_url",
                        },
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
                        {
                            "key": "Point Of Sale Malicious URL",
                            "value": "pos_url",
                        },
                        {"key": "Ransomware URL", "value": "ransomware_url"},
                        {
                            "key": "Social Media URL",
                            "value": "social_media_url",
                        },
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
                        {
                            "key": "Commercial Webproxy IP",
                            "value": "comm_proxy_ip",
                        },
                        {"key": "Compromised IP", "value": "compromised_ip"},
                        {"key": "Cryptocurrency IP", "value": "crypto_ip"},
                        {"key": "DDOS IP", "value": "ddos_ip"},
                        {"key": "Downloader IP", "value": "downloader_ip"},
                        {"key": "Data Exfiltration IP", "value": "exfil_ip"},
                        {"key": "Exploit Kit IP", "value": "exploit_ip"},
                        {"key": "Fraud IP", "value": "fraud_ip"},
                        {"key": "I2P IP", "value": "i2p_ip"},
                        {
                            "key": "Information Stealer IP",
                            "value": "infostealer_ip",
                        },
                        {
                            "key": "Internet Of things Malicious IP",
                            "value": "iot_ip",
                        },
                        {"key": "Malware IP", "value": "mal_ip"},
                        {"key": "Peer-to-Peer C&C IP", "value": "p2pcnc"},
                        {"key": "Domain Parking IP", "value": "parked_ip"},
                        {"key": "Phishing IP", "value": "phish_ip"},
                        {
                            "key": "Point Of Sale Malicious IP",
                            "value": "pos_ip",
                        },
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
                        {
                            "key": "Anonymous Proxy IPv6",
                            "value": "anon_proxy_ipv6",
                        },
                        {
                            "key": "Anonymous VPN IPv6",
                            "value": "anon_vpn_ipv6",
                        },
                        {"key": "APT IPv6", "value": "apt_ipv6"},
                        {"key": "Infected Bot IPv6", "value": "bot_ipv6"},
                        {"key": "Brute Force IPv6", "value": "brute_ipv6"},
                        {"key": "Malware C&C IPv6", "value": "c2_ipv6"},
                        {
                            "key": "Commercial Webproxy IPv6",
                            "value": "comm_proxy_ipv6",
                        },
                        {
                            "key": "Compromised IPv6",
                            "value": "compromised_ipv6",
                        },
                        {
                            "key": "Cryptocurrency IPv6",
                            "value": "crypto_ipv6",
                        },
                        {"key": "DDOS IPv6", "value": "ddos_ipv6"},
                        {
                            "key": "Downloader IPv6",
                            "value": "downloader_ipv6",
                        },
                        {
                            "key": "Data Exfiltration IPv6",
                            "value": "exfil_ipv6",
                        },
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
                        {
                            "key": "Peer-to-Peer C&C IPv6",
                            "value": "p2pcnc_ipv6",
                        },
                        {
                            "key": "Domain Parking IPv6",
                            "value": "parked_ipv6",
                        },
                        {"key": "Phishing IPv6", "value": "phish_ipv6"},
                        {
                            "key": "Point Of Sale Malicious IPv6",
                            "value": "pos_ipv6",
                        },
                        {"key": "Open Proxy IPv6", "value": "proxy_ipv6"},
                        {
                            "key": "Ransomware IPv6",
                            "value": "ransomware_ipv6",
                        },
                        {"key": "Scanning IPv6", "value": "scan_ipv6"},
                        {"key": "Sinkhole IPv6", "value": "sinkhole_ipv6"},
                        {"key": "Spammer IPv6", "value": "spam_ipv6"},
                        {"key": "SSH Brute Force IPv6", "value": "ssh_ipv6"},
                        {
                            "key": "Suppress Alerts IPv6",
                            "value": "suppress_ipv6",
                        },
                        {
                            "key": "Suspicious IPv6",
                            "value": "suspicious_ipv6",
                        },
                        {"key": "TOR Node IPv6", "value": "tor_ipv6"},
                        {
                            "key": "Trojan IPv6 Address",
                            "value": "trojan_ipv6",
                        },
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
                        {
                            "key": "Malware C&C Domain Name",
                            "value": "c2_domain",
                        },
                        {
                            "key": "Commercial Webproxy Domain",
                            "value": "comm_proxy_domain",
                        },
                        {
                            "key": "Compromised Domain",
                            "value": "compromised_domain",
                        },
                        {
                            "key": "Cryptocurrency Pool Domain",
                            "value": "crypto_pool",
                        },
                        {
                            "key": "Disposable Email Domain",
                            "value": "disposable_email_domain",
                        },
                        {
                            "key": "Downloader Domain",
                            "value": "downloader_domain",
                        },
                        {"key": "Dynamic DNS", "value": "dyn_dns"},
                        {
                            "key": "Data Exfiltration Domain",
                            "value": "exfil_domain",
                        },
                        {
                            "key": "Exploit Kit Domain",
                            "value": "exploit_domain",
                        },
                        {"key": "Fraud Domain", "value": "fraud_domain"},
                        {
                            "key": "Free Email Domain",
                            "value": "free_email_domain",
                        },
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
                        {
                            "key": "Ransomware Domain",
                            "value": "ransomware_domain",
                        },
                        {
                            "key": "Sinkhole Domain",
                            "value": "sinkhole_domain",
                        },
                        {"key": "Spam Domain", "value": "spam_domain"},
                        {
                            "key": "Suspicious Domain",
                            "value": "suspicious_domain",
                        },
                        {"key": "Trojan Domain", "value": "trojan_domain"},
                        {
                            "key": "Anonymous VPN Domain",
                            "value": "vpn_domain",
                        },
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
                        {
                            "key": "Downloader File Hash",
                            "value": "downloader_hash",
                        },
                        {"key": "Exploit Hash", "value": "exploit_md5"},
                        {"key": "Fraud Hash", "value": "fraud_md5"},
                        {
                            "key": "Hack Tool File Hash",
                            "value": "hack_tool_md5",
                        },
                        {
                            "key": "Information Stealer File Hash",
                            "value": "infostealer_hash",
                        },
                        {
                            "key": "Internet Of Things Malicious File Hash",
                            "value": "iot_hash",
                        },
                        {
                            "key": "JA3/JA3S TLS Fingerprint",
                            "value": "ja3_md5",
                        },
                        {"key": "Malware File Hash", "value": "mal_md5"},
                        {
                            "key": "SSL Certificate Hash",
                            "value": "mal_sslcert_sha1",
                        },
                        {"key": "Phishing File Hash", "value": "phish_md5"},
                        {
                            "key": "Point Of Sale Malicious File Hash",
                            "value": "pos_hash",
                        },
                        {
                            "key": "Ransomware File Hash",
                            "value": "ransomware_hash",
                        },
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

    def _get_credentials(self, configuration) -> Tuple[str, str, str]:
        """Get API Credentials.
        Args:
            - configuration (Dict): Configuration Dictionary.
        Returns:
            - Tuple: Tuple containing Base URL, Username, API Key.
        """
        base_url = configuration.get("base_url", "").strip().strip("/")
        user_name = configuration.get("username", "").strip()
        api_key = configuration.get("api_key")
        return base_url, user_name, api_key

    def _get_indicator_types(self, threat_types: List) -> Dict:
        """Returns a mapping of Indicator Types, Based on the threat types to
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

        if "ip" in threat_types:
            indicator_types["ip"] = getattr(
                IndicatorType, "IPV4", IndicatorType.URL
            )

        if "ipv6" in threat_types:
            indicator_types["ipv6"] = getattr(
                IndicatorType, "IPV6", IndicatorType.URL
            )
        return indicator_types

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
        start_time = self._convert_datetime_to_anomali_format(start_time)
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
                raise AnomaliThreatstreamPluginException(err_msg)
