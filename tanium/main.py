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

CTE Tanium Plugin constants.
"""

import json
import traceback
from datetime import datetime, timedelta
from typing import Callable, Dict, Generator, List, Set, Union, Tuple
from urllib.parse import urlparse

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils

from .utils.constants import (
    DATETIME_FORMAT,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    INDICATOR_TYPES,
    TANIUM_ALERTS_ENDPOINT,
    PER_PAGE_LIMIT,
    ENABLE_TAGGING_VALUES
)
from .utils.helper import TaniumPluginException, TaniumPluginHelper


class TaniumPlugin(PluginBase):
    """Tanium Plugin class"""

    def __init__(self, name, *args, **kwargs):
        """Init function.

        Args:
           name (str): Configuration Name.
        """
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
        self.tanium_helper = TaniumPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = TaniumPlugin.metadata
            plugin_name = metadata.get("name", PLATFORM_NAME)
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

    def _validate_connectivity(
        self, api_base_url: str, api_token: str
    ) -> ValidationResult:
        """
        Validate connectivity with Tanium server by making REST API call.

        Args:
            api_base_url (str): Base URL.
            api_token (str): Tanium API Token.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )
            headers = self.tanium_helper.get_auth_headers(api_token=api_token)

            # Tanium API Endpoint
            api_endpoint = TANIUM_ALERTS_ENDPOINT.format(
                api_base_url=api_base_url
            )
            params = {
                "limit": 1
            }
            self.tanium_helper.api_helper(
                url=api_endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"validating connectivity "
                    f"with {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )

            logger_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True,
                message=logger_msg,
            )
        except TaniumPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp)
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

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        max_value: int = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str:
            field_value = field_value.strip()
        if (
            is_required and not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {', '.join(allowed_values.keys())}."
            )
            if (
                field_type is str
                and field_value not in allowed_values.values()
            ):
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type is list:
                for value in field_value:
                    if value not in allowed_values.values():
                        self.logger.error(
                            f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value <= 0
        ):
            if max_value == INTEGER_THRESHOLD:
                max_value = "2^62"
            err_msg = (
                f"Invalid {field_name} provided in configuration"
                " parameters. Valid value should be an integer "
                f"greater than 0 and less than {max_value}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the Plugin's configuration parameters.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        (
            api_base_url,
            api_token,
            iocs_to_be_pulled,
            enable_tagging,
            retraction_interval,
            initial_pull_range,
        ) = self.tanium_helper.get_configuration_parameters(
            configuration,
        )

        # Validate base url
        if validation_result := self._validate_configuration_parameters(
            field_name="API Base URL",
            field_value=api_base_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_result

        # Validate API Token
        if validation_result := self._validate_configuration_parameters(
            field_name="API Token",
            field_value=api_token,
            field_type=str,
        ):
            return validation_result

        # Validate IoC types to be pulled
        if validation_result := self._validate_configuration_parameters(
            field_name="Type of Threat data to pull",
            field_value=iocs_to_be_pulled,
            field_type=list,
            allowed_values=INDICATOR_TYPES,
        ):
            return validation_result

        # Validate Enable Tagging
        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=ENABLE_TAGGING_VALUES,
        ):
            return validation_result

        # Validate Initial Pull Range
        if validation_result := self._validate_configuration_parameters(
            field_name="Initial Range",
            field_value=initial_pull_range,
            field_type=int,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Retraction interval
        if validation_result := self._validate_configuration_parameters(
            field_name="Retraction Interval",
            field_value=retraction_interval,
            field_type=Union[int, None],
            max_value=INTEGER_THRESHOLD,
            is_required=False,
        ):
            return validation_result

        return self._validate_connectivity(
            api_base_url=api_base_url, api_token=api_token
        )

    def _create_indicator(
        self,
        threat_value: str,
        threat_type: str,
        severity: str,
        first_seen: str,
        last_seen: str,
        comment_str: str,
        tags: List[str],
    ) -> Indicator:
        """Create the cte.models.Indicator object.

        Args:
            threat_value (str): Value of the indicator.
            threat_type (str): Type of the indicator.
            severity (str): Severity of the indicator.
            first_seen (str): First seen of the indicator.
            last_seen (str): Last seen of the indicator.
            comment_str (str): Comment of the indicator.
            tags (List[str]): Tags of the indicator.
        Returns:
            cte.models.Indicator: Indicator object.
        """
        return Indicator(
            value=threat_value,
            type=threat_type,
            severity=severity,
            firstSeen=first_seen,
            lastSeen=last_seen,
            comments=comment_str,
            tags=tags,
        )

    def _severity_mapping(self, value: str):
        """
        Maps the given value to a SeverityType.

        Args:
            value (str): The value to map.

        Returns:
            SeverityType: The mapped severity type.
        """
        if not value:
            return SeverityType.UNKNOWN
        value = value.lower()
        if value == "info":
            return SeverityType.UNKNOWN
        elif value == "low":
            return SeverityType.LOW
        elif value == "medium":
            return SeverityType.MEDIUM
        elif value == "high":
            return SeverityType.HIGH
        elif value == "critical":
            return SeverityType.CRITICAL
        else:
            return SeverityType.UNKNOWN

    def _create_tags(
        self,
        tags: List[str],
        enable_tagging: str,
    ) -> Tuple[List[str], List[str]]:
        """Create new tag(s) in database if required.

        Args:
            tags (List[str]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Tuple[List[str], List[str]]: Created tags, Skipped tags
        """

        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        if enable_tagging != "yes":
            return created_tags, skipped_tags

        for label in tags:
            try:
                if not tag_utils.exists(label):
                    tag_utils.create_tag(TagIn(name=label, color="#ED3347"))
                created_tags.add(label)
            except ValueError:
                skipped_tags.add(label)
            except Exception:
                skipped_tags.add(label)

        return list(created_tags), list(skipped_tags)

    def _process_alerts_response(
        self,
        page_results: List[Dict],
        iocs_to_be_pulled: List[str],
        is_retraction: bool,
        enable_tagging: str,
    ) -> Tuple[List[Dict], Dict[str, int], int, Set[str], int]:
        """
        Process alerts API response and return processed IoC data.

        Args:
            response (List[Dict]): List of alerts.
            iocs_to_be_pulled (List[str]): List of IoC types.
            is_retraction (bool): Whether this is processing retraction data.
            enable_tagging (str): Whether tagging is enabled.

        Returns:
            Tuple of:
                - List of processed IoC data \
                    (or Set of IoC values for retraction)
                - Dict of IoC counts
                - Count of successful alerts processed
                - Set of skipped tags (currently unused)
                - Count of skipped alerts
        """
        current_page_ioc_counts = {"sha256": 0, "md5": 0}
        page_indicator_list = set() if is_retraction else []
        page_skipped_tags = set()
        alert_success_count = 0
        skipped_alert_count = 0
        skip_ioc_count = 0
        for alert in page_results:
            try:
                alert_details = json.loads(alert.get("details", "{}"))
                severity = self._severity_mapping(alert.get("severity", ""))
                first_seen = (
                    alert_details.get("finding", {}).get("first_seen", "")
                )
                last_seen = (
                    alert_details.get("finding", {}).get("last_seen", "")
                )
                if not first_seen and not last_seen:
                    first_seen = self._convert_into_date_time(
                        alert.get("alertedAt", "")
                    )
                    last_seen = self._convert_into_date_time(
                        alert.get("updatedAt", "")
                    )

                # Tags
                tags = []
                match_type = alert.get("matchType", "")
                if match_type:
                    tags.append(match_type)

                # Prepare comment string
                priority = alert.get("priority", "").capitalize()
                intel_name = alert.get("intelDoc", {}).get("name", "")
                intel_description = (
                    alert.get("intelDoc", {}).get("description", "")
                )
                intel_source_name = (
                    alert.get("intelDoc", {}).get("source", {}).get("name", "")
                )

                comment_str = ""
                if priority:
                    comment_str += f"Priority: {priority}"
                if intel_name:
                    comment_str += f", Intel Name: {intel_name}"
                if intel_description:
                    comment_str += f", Intel Description: {intel_description}"
                if intel_source_name:
                    comment_str += f", Intel Source Name: {intel_source_name}"

                alert_properties = (
                    alert_details.get("match", {}).get("properties", {})
                )

                # Helper for processing hash types
                def _process_hash(
                    hash_value,
                    hash_type,
                    comment_str,
                    path,
                    tags,
                ):
                    nonlocal skip_ioc_count
                    if hash_value:
                        if is_retraction:
                            if hash_value not in page_indicator_list:
                                page_indicator_list.add(hash_value)
                                current_page_ioc_counts[
                                    hash_type.value.lower()
                                ] += 1
                        else:
                            if path:
                                comment_str += f", Path: {path}"

                            created_tags, skipped_tags = self._create_tags(
                                tags,
                                enable_tagging,
                            )
                            page_skipped_tags.update(skipped_tags)
                            page_indicator_list.append(
                                self._create_indicator(
                                    threat_value=hash_value,
                                    threat_type=hash_type,
                                    severity=severity,
                                    first_seen=first_seen,
                                    last_seen=last_seen,
                                    comment_str=comment_str,
                                    tags=created_tags,
                                )
                            )
                            current_page_ioc_counts[
                                hash_type.value.lower()
                            ] += 1
                    else:
                        skip_ioc_count += 1

                # Process MD5 indicators
                if "md5" in iocs_to_be_pulled:
                    md5_file = alert_properties.get("file", {})
                    md5 = md5_file.get("md5", "")
                    split_md5 = md5.split(",")
                    path = md5_file.get("fullpath", "")

                    parent_md5_file = (
                        alert_properties.get("parent", {}).get("file", {})
                    )
                    parent_md5 = parent_md5_file.get("md5", "")
                    split_parent_md5 = parent_md5.split(",")
                    parent_path = parent_md5_file.get("fullpath", "")

                    for md5 in split_md5:
                        _process_hash(
                            md5,
                            IndicatorType.MD5,
                            comment_str,
                            path,
                            tags + ["Child Process Hash"],
                        )
                    for parent_md5 in split_parent_md5:
                        _process_hash(
                            parent_md5,
                            IndicatorType.MD5,
                            comment_str,
                            parent_path,
                            tags + ["Parent Process Hash"],
                        )

                # Process SHA256 indicators
                if "sha256" in iocs_to_be_pulled:
                    sha256_file = alert_properties.get("file", {})
                    sha256 = sha256_file.get("sha256", "")
                    split_sha256 = sha256.split(",")
                    path = sha256_file.get("fullpath", "")

                    parent_sha256_file = (
                        alert_properties.get("parent", {}).get("file", {})
                    )
                    parent_sha256 = parent_sha256_file.get("sha256", "")
                    split_parent_sha256 = parent_sha256.split(",")
                    parent_path = parent_sha256_file.get("fullpath", "")

                    for sha256 in split_sha256:
                        _process_hash(
                            sha256,
                            IndicatorType.SHA256,
                            comment_str,
                            path,
                            tags + ["Child Process Hash"],
                        )
                    for parent_sha256 in split_parent_sha256:
                        _process_hash(
                            parent_sha256,
                            IndicatorType.SHA256,
                            comment_str,
                            parent_path,
                            tags + ["Parent Process Hash"],
                        )
            except Exception as e:
                err_msg = (
                    "Error occurred while processing alert details."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {e}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_alert_count += 1
                continue
            alert_success_count += 1
        return (
            page_indicator_list,
            current_page_ioc_counts,
            alert_success_count,
            page_skipped_tags,
            skipped_alert_count,
            skip_ioc_count,
        )

    def _convert_date_time_to_str(self, date: datetime):
        """Convert datetime to str.

        Args:
            date (datetime): datetime.

        Returns:
            str: str.
        """
        try:
            if isinstance(date, str):
                return date
            return (
                date.strftime(DATETIME_FORMAT) if date else
                datetime.now().strftime(DATETIME_FORMAT)
            )
        except Exception:
            current_time = datetime.now().strftime(DATETIME_FORMAT)
            return current_time

    def _pull_indicators(
        self,
        api_base_url: str,
        api_token: str,
        iocs_to_be_pulled: List[str],
        initial_pull_range: int,
        enable_tagging: str = "yes",
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
        """
        Pulls IoC(s) from Active Indicator page on Tanium.

        Args:
            api_base_url (str): Base URL of the Tanium server.
            api_token (str): API token for authentication.
            iocs_to_be_pulled (List[str]): List of IoCs to be pulled.
            initial_pull_range (int): Initial pull range.
            enable_tagging (str, optional): Whether to enable tagging.
                Defaults to "yes".
            is_retraction (bool, optional): Whether to enable retraction.
                Defaults to False.

        Yields:
            Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
                Generator of indicators and checkpoint.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if is_retraction:
            start_time = datetime.now() - timedelta(days=initial_pull_range)
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            start_time = sub_checkpoint.get("checkpoint")
        elif self.last_run_at:
            start_time = self.last_run_at
        else:
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying indicators for "
                f"last {initial_pull_range} days."
            )
            start_time = (
                datetime.now() - timedelta(days=initial_pull_range)
            )

        start_time = self._convert_date_time_to_str(start_time)
        indicator_count = 0
        total_skipped_tags = set()
        next_page = True
        page_count = 1
        checkpoint = ""
        headers = self.tanium_helper.get_auth_headers(api_token)
        params = {
            "expand": "intelDoc",
            "limit": PER_PAGE_LIMIT,
            "alertedAtFrom": start_time,
            "offset": 0,
            "sort": "alertedAt"
        }
        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from "
            f"checkpoint: {str(start_time)}"
        )
        url = TANIUM_ALERTS_ENDPOINT.format(api_base_url=api_base_url)
        try:
            while next_page:
                page_indicators = set() if is_retraction else []
                response = self.tanium_helper.api_helper(
                    url=url,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                    logger_msg=(f"pulling indicators for page {page_count}"),
                )
                page_results = response.get("data", [])
                current_page_count = len(page_results)
                if page_results:
                    (
                        page_indicators,
                        page_ioc_counts,
                        alert_success_count,
                        page_skipped_tags,
                        skipped_alert_count,
                        skip_ioc_count,
                    ) = self._process_alerts_response(
                        page_results,
                        iocs_to_be_pulled,
                        is_retraction,
                        enable_tagging,
                    )
                    total_skipped_tags.update(page_skipped_tags)
                    indicator_count += len(page_indicators)

                    if current_page_count < PER_PAGE_LIMIT:
                        next_page = False
                    else:
                        params["offset"] += PER_PAGE_LIMIT
                    checkpoint = response["data"][-1]["alertedAt"]
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{len(page_indicators)} indicator(s) "
                        f"from {alert_success_count} alerts "
                        f"and skipped {skipped_alert_count} alerts "
                        f"for page {page_count} from {PLATFORM_NAME}. "
                        f"Pull Stats: {page_ioc_counts.get('md5')} MD5, "
                        f"{page_ioc_counts.get('sha256')} SHA256 "
                        "indicator(s) fetched. "
                        f"Total indicator(s) fetched - {indicator_count}."
                    )
                    if skip_ioc_count > 0:
                        self.logger.info(
                            f"{self.log_prefix}: Skipped {skip_ioc_count} "
                            "indicator(s) as value might not available in "
                            "the response."
                        )
                else:
                    next_page = False

                if not next_page:
                    if len(total_skipped_tags) > 0:
                        self.logger.info(
                            f"{self.log_prefix}: {len(total_skipped_tags)} "
                            "tag(s) skipped as they were longer than expected "
                            "size or due to some other exceptions that "
                            "occurred while creation of them. Tags: "
                            f"({', '.join(total_skipped_tags)})."
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{indicator_count} indicator(s) from "
                        f"{PLATFORM_NAME}."
                    )
                if page_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield page_indicators, {"checkpoint": checkpoint}
                    else:
                        yield page_indicators
                page_count += 1
        except TaniumPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while pulling "
                f"indicators for page {page_count}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise TaniumPluginException(err_msg)

    def _pull(self) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pulls IoC(s) from Tanium Threat Response Alerts.

        Yields:
            Generator[Tuple[List[Indicator], Dict], None, None]: Generator
                of indicators and checkpoint.
        """
        (
            api_base_url,
            api_token,
            iocs_to_be_pulled,
            enable_tagging,
            _,
            initial_pull_range,
        ) = self.tanium_helper.get_configuration_parameters(
            self.configuration,
        )
        yield from self._pull_indicators(
            api_base_url=api_base_url,
            api_token=api_token,
            iocs_to_be_pulled=iocs_to_be_pulled,
            initial_pull_range=initial_pull_range,
            enable_tagging=enable_tagging,
        )

    def pull(self) -> List[Indicator]:
        """Pulls IoC(s) from Tanium Threat Response Alerts.

        Returns:
            List[Indicator]: List of indicators.
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
                return indicators
        except TaniumPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling indicators "
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise TaniumPluginException(err_msg)

    def get_modified_indicators(
        self, source_indicators: List[List[Dict]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            List of retracted indicators, Status (List, bool): List of
                retracted indicators values. Status of execution.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        (
            api_base_url,
            api_token,
            iocs_to_be_pulled,
            _,
            retraction_interval,
            _,
        ) = self.tanium_helper.get_configuration_parameters(
            self.configuration,
        )
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" from {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)
        self.logger.info(
            message=(
                f"{self.log_prefix}: Pulling modified indicators "
                f"from {PLATFORM_NAME}."
            )
        )
        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                total_iocs = len(iocs)
                modified_indicators = self._pull_indicators(
                    api_base_url=api_base_url,
                    api_token=api_token,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    initial_pull_range=retraction_interval,
                    is_retraction=True,
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
                    f"Error while fetching modified indicators from "
                    f"{PLATFORM_NAME}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                    details=traceback.format_exc(),
                )
                raise TaniumPluginException(err_msg)
