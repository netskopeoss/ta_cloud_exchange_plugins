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

CTE Imperva Plugin constants.
"""

import traceback
import time
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, Generator, List, Set, Union, Tuple

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
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    IMPERVA_INCIDENT_ENDPOINT,
    IMPERVA_INCIDENT_URL,
    ENABLE_TAGGING_VALUES,
    CHUNK_HOURS
)
from .utils.helper import ImpervaPluginException, ImpervaPluginHelper


class ImpervaPlugin(PluginBase):
    """Imperva Plugin class"""

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
        self.imperva_helper = ImpervaPluginHelper(
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
            metadata = ImpervaPlugin.metadata
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
        self,
        account_id: str,
        api_id: str,
        api_key: str
    ) -> ValidationResult:
        """
        Validate connectivity with Imperva server by making REST API call.

        Args:
            account_id (str): Account ID.
            api_id (str): API ID.
            api_key (str): API Key.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} server."
            )
            headers = self.imperva_helper.get_auth_headers(
                api_id=api_id,
                api_key=api_key
            )

            sample_epoch = int(time.time() * 1000)
            params = {
                "caid": account_id,
                "from_timestamp": sample_epoch,
                "to_timestamp": sample_epoch
            }

            self.imperva_helper.api_helper(
                url=IMPERVA_INCIDENT_ENDPOINT,
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
        except ImpervaPluginException as exp:
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

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        max_value: int = None,
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
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} value is provided in the "
                    "configuration parameters."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure that valid value for {field_name} is "
                    "provided in the configuration parameters."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            allowed_values_str = ', '.join(allowed_values.keys())
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {allowed_values_str}."
            )
            resolution = (
                f"Ensure that valid value for {field_name} is "
                "provided in the configuration parameters "
                "and it should be one of "
                f"{allowed_values_str}."
            )
            if (
                field_type is str
                and field_value not in allowed_values.values()
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=resolution,
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type is list:
                for value in field_value:
                    if value not in allowed_values.values():
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg}"
                                f"{err_msg}"
                            ),
                            resolution=resolution,
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value <= 0
        ):
            err_msg = (
                f"Invalid value for {field_name} provided in configuration "
                "parameters. Valid value should be an integer "
                f"greater than 0 and less than {max_value}."
            )
            resolution = (
                f"Ensure that value for {field_name} is "
                f"an integer greater than 0 and less than {max_value}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                ),
                resolution=resolution,
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
            account_id,
            api_id,
            api_key,
            enable_tagging,
            retraction_interval,
            initial_pull_range,
        ) = self.imperva_helper.get_configuration_parameters(
            configuration,
        )

        # Validate Account ID
        if validation_result := self._validate_configuration_parameters(
            field_name="Account ID",
            field_value=account_id,
            field_type=str,
        ):
            return validation_result

        # Validate API ID
        if validation_result := self._validate_configuration_parameters(
            field_name="API ID",
            field_value=api_id,
            field_type=str,
        ):
            return validation_result

        # Validate API Key
        if validation_result := self._validate_configuration_parameters(
            field_name="API Key",
            field_value=api_key,
            field_type=str,
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
            account_id=account_id, api_id=api_id, api_key=api_key
        )

    def _create_indicator(
        self,
        ioc_value: str,
        ioc_type: str,
        severity: str,
        first_seen: str,
        last_seen: str,
        comment_str: str,
        tags: List[str],
        incident_url: str,
    ) -> Indicator:
        """Create the cte.models.Indicator object.

        Args:
            ioc_value (str): Value of the indicator.
            ioc_type (str): Type of the indicator.
            severity (str): Severity of the indicator.
            first_seen (str): First seen of the indicator.
            last_seen (str): Last seen of the indicator.
            comment_str (str): Comment of the indicator.
            tags (List[str]): Tags of the indicator.
            incident_url (str): URL of the incident.
        Returns:
            cte.models.Indicator: Indicator object.
        """
        return Indicator(
            value=ioc_value,
            type=ioc_type,
            severity=severity,
            firstSeen=first_seen,
            lastSeen=last_seen,
            comments=comment_str,
            tags=tags,
            extendedInformation=incident_url,
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
        if value == "minor":
            return SeverityType.LOW
        elif value == "major":
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

    def _determine_ip_version(
        self, ip_string: str
    ) -> Union[IndicatorType, None]:
        """
        Determine IP version of given string.

        Args:
            ip_string (str): IP string

        Returns:
            IndicatorType: IndicatorType.IPV4 or IndicatorType.IPV6 \
                if valid IP string, None otherwise
        """
        try:
            ip_obj = ip_address(ip_string)
            if isinstance(ip_obj, IPv4Address):
                return IndicatorType.IPV4
            elif isinstance(ip_obj, IPv6Address):
                return IndicatorType.IPV6
        except (ValueError, Exception):
            return None

    def _process_incidents_response(
        self,
        page_results: List[Dict],
        is_retraction: bool,
        enable_tagging: str,
    ) -> Tuple[List[Indicator], int, Set[str], int]:
        """
        Process incidents API response and return processed IoC data.

        Args:
            page_results (List[Dict]): List of incidents.
            is_retraction (bool): Whether this is processing retraction data.
            enable_tagging (str): Whether tagging is enabled.

        Returns:
            Tuple of:
                - List[Dict]: List of IoCs.
                - int: Number of incidents processed.
                - Set[str]: Set of skipped tags.
                - int: Number of skipped IoCs.
        """
        page_indicator_list = set() if is_retraction else []
        page_skipped_tags = set()
        incident_success_count = 0
        skip_ioc_count = 0
        for incident in page_results:
            try:
                ioc_ipv4 = incident.get("dominant_attack_ip", {}).get("ip", "")
                ioc_type = self._determine_ip_version(ioc_ipv4) if ioc_ipv4 else None

                if not ioc_ipv4 or not ioc_type:
                    skip_ioc_count += 1
                    continue

                if is_retraction:
                    false_positive = incident.get("false_positive", "")
                    if not false_positive:
                        page_indicator_list.add(ioc_ipv4)
                    incident_success_count += 1
                    continue

                severity = self._severity_mapping(incident.get("severity", ""))
                first_seen = incident.get("first_event_time", "")
                last_seen = incident.get("last_event_time", "")

                incident_url = IMPERVA_INCIDENT_URL.format(
                    incident_id=incident.get("id", "")
                )

                # Tags
                tags = []

                if incident_type := incident.get("incident_type", ""):
                    tags.append(incident_type)
                if dominant_attack_violation := incident.get(
                    "dominant_attack_violation", ""
                ):
                    tags.append(dominant_attack_violation)
                if severity_explanation := incident.get(
                    "severity_explanation", ""
                ):
                    tags.append(severity_explanation)
                if dominant_attack_ip := incident.get(
                    "dominant_attack_ip", {}
                ):
                    reputations = dominant_attack_ip.get("reputation", [])
                    if reputations:
                        for reputation in reputations:
                            if reputation:
                                tags.append(reputation)

                    if dominance := dominant_attack_ip.get("dominance", ""):
                        tags.append(dominance)

                # Prepare comment string

                comment_str = ""
                if main_sentence := incident.get("main_sentence", ""):
                    comment_str += main_sentence
                if secondary_sentence := incident.get(
                    "secondary_sentence", ""
                ):
                    comment_str += f"{secondary_sentence}. "
                if dominant_attacked_host := incident.get(
                    "dominant_attacked_host", {}
                ).get("value", ""):
                    comment_str += f"Attacked Host: {dominant_attacked_host}, "
                if dominant_attack_tool := incident.get(
                    "dominant_attack_tool", {}
                ).get("name", ""):
                    comment_str += f"Attack Tool: {dominant_attack_tool}, "
                if dominant_attack_country := incident.get(
                    "dominant_attack_country", {}
                ).get("country", ""):
                    comment_str += f"Attack Country: {dominant_attack_country}"

                # Create Tags
                created_tags, skipped_tags = self._create_tags(
                    tags,
                    enable_tagging,
                )
                page_skipped_tags.update(skipped_tags)

                # Create Indicator
                indicator = self._create_indicator(
                    ioc_value=ioc_ipv4,
                    ioc_type=ioc_type,
                    severity=severity,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    comment_str=comment_str,
                    tags=created_tags,
                    incident_url=incident_url,
                )
                page_indicator_list.append(indicator)

            except Exception as e:
                err_msg = (
                    "Error occurred while processing incident details."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {e}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_ioc_count += 1
                continue
            incident_success_count += 1
        return (
            page_indicator_list,
            incident_success_count,
            page_skipped_tags,
            skip_ioc_count,
        )

    def _pull_indicators(
        self,
        account_id: str,
        api_id: str,
        api_key: str,
        initial_pull_range: int,
        enable_tagging: str = "yes",
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
        """
        Pulls IoC(s) from Attack Analytics Incidents page on Imperva.

        Args:
            account_id (str): Account ID of the Imperva server.
            api_id (str): API ID for authentication.
            api_key (str): API Key for authentication.
            initial_pull_range (int): Initial pull range.
            enable_tagging (str, optional): Whether to enable tagging.
                Defaults to "yes".
            is_retraction (bool, optional): Whether to enable retraction.
                Defaults to False.

        Yields:
            Generator[Tuple[List[Union[Indicator, str]], Dict], None, None]:
                Generator of IoCs and checkpoint.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        end_time = datetime.now().replace(microsecond=0)

        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if is_retraction:
            start_time = int((time.time() - initial_pull_range * 86400) * 1000)
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            start_time = sub_checkpoint.get("checkpoint")
        elif self.last_run_at:
            start_time = int(self.last_run_at.timestamp() * 1000)
        else:
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying IoC(s) for "
                f"last {initial_pull_range} days."
            )
            start_time = int((time.time() - initial_pull_range * 86400) * 1000)

        indicator_count = 0
        total_skipped_tags = set()
        page_count = 1
        headers = self.imperva_helper.get_auth_headers(
            api_id=api_id,
            api_key=api_key,
        )

        current_start = datetime.fromtimestamp(start_time / 1000)
        chunk_delta = timedelta(hours=CHUNK_HOURS)

        self.logger.info(
            f"{self.log_prefix}: Pulling IoC(s) from "
            f"checkpoint: {str(current_start)}"
        )
        try:
            while current_start < end_time:
                current_end = min(current_start + chunk_delta, end_time)

                start_ms = int(current_start.timestamp() * 1000)
                end_ms = int(current_end.timestamp() * 1000)

                page_indicators = set() if is_retraction else []
                page_indicator_count = 0
                incident_success_count = 0
                skip_ioc_count = 0

                params = {
                    "caid": account_id,
                    "from_timestamp": start_ms,
                    "to_timestamp": end_ms
                }
                response = self.imperva_helper.api_helper(
                    url=IMPERVA_INCIDENT_ENDPOINT,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=is_retraction,
                    logger_msg=(f"pulling IoC(s) for page {page_count}"),
                )
                if response:
                    (
                        page_indicators,
                        incident_success_count,
                        page_skipped_tags,
                        skip_ioc_count,
                    ) = self._process_incidents_response(
                        response,
                        is_retraction,
                        enable_tagging,
                    )
                    page_indicator_count = len(page_indicators)
                    total_skipped_tags.update(page_skipped_tags)
                    indicator_count += page_indicator_count

                    checkpoint = end_ms

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_indicator_count} IoC(s) "
                    f"from {incident_success_count} incidents "
                    f"and skipped {skip_ioc_count} IoCs "
                    f"for page {page_count} from {PLATFORM_NAME}. "
                    f"Pull Stats: {page_indicator_count} IPv4 "
                    "IoC(s) fetched. "
                    f"Total IoC(s) fetched - {indicator_count}."
                )
                if skip_ioc_count > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped {skip_ioc_count} "
                        "IoC(s) as IP value might not available in "
                        f"the incident response for page {page_count}."
                    )

                current_start = current_end

                if page_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield page_indicators, {"checkpoint": checkpoint}
                    else:
                        yield page_indicators, None
                page_count += 1

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
                f"{indicator_count} IoC(s) from "
                f"{PLATFORM_NAME}."
            )
        except ImpervaPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while pulling "
                f"IoC(s) for page {page_count}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ImpervaPluginException(err_msg)

    def _pull(self) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pulls IoC(s) from Imperva Attack Analytics Incidents.

        Yields:
            Generator[Tuple[List[Indicator], Dict], None, None]: Generator
                of IoCs and checkpoint.
        """
        (
            account_id,
            api_id,
            api_key,
            enable_tagging,
            _,
            initial_pull_range,
        ) = self.imperva_helper.get_configuration_parameters(
            self.configuration,
        )
        yield from self._pull_indicators(
            account_id=account_id,
            api_id=api_id,
            api_key=api_key,
            enable_tagging=enable_tagging,
            initial_pull_range=initial_pull_range,
        )

    def pull(self) -> List[Indicator]:
        """Pulls IoC(s) from Imperva Attack Analytics Incidents.

        Returns:
            List[Indicator]: List of IoCs.
        """
        try:
            if hasattr(self, "sub_checkpoint"):
                return self._pull()
            else:
                indicators = []
                for batch, _ in self._pull():
                    indicators.extend(batch)
                return indicators
        except ImpervaPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling IoCs "
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ImpervaPluginException(err_msg)

    def get_modified_indicators(
        self, source_indicators: List[List[Dict]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified IoCs status.

        Args:
            source_indicators (List[List[Dict]]): Source IoCs.

        Yields:
            List of retracted IoCs, Status (List, bool): List of
                retracted IoCs values. Status of execution.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        (
            account_id,
            api_id,
            api_key,
            _,
            retraction_interval,
            _,
        ) = self.imperva_helper.get_configuration_parameters(
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
                f"{self.log_prefix}: Pulling modified IoCs "
                f"from {PLATFORM_NAME}."
            )
        )
        modified_indicators_gen = self._pull_indicators(
            account_id=account_id,
            api_id=api_id,
            api_key=api_key,
            initial_pull_range=retraction_interval,
            is_retraction=True,
        )
        modified_iocs = set()
        for ioc_values_set, _ in modified_indicators_gen:
            modified_iocs.update(ioc_values_set)

        for source_ioc_list in source_indicators:
            try:
                total_iocs = len(source_ioc_list)
                iocs = {
                    ioc.value for ioc in source_ioc_list
                    if ioc and ioc.value not in modified_iocs
                }

                self.logger.info(
                    f"{self.log_prefix}: {len(iocs)} IoC(s) will "
                    f"be marked as retracted from {total_iocs} total "
                    "IoC(s) present in Cloud Exchange for "
                    f"{PLATFORM_NAME} due to retraction "
                    "interval or incidents are false positives."
                )
                yield list(iocs), False
            except Exception as err:
                err_msg = (
                    f"Error while fetching modified IoCs from "
                    f"{PLATFORM_NAME}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                    details=traceback.format_exc(),
                )
                raise ImpervaPluginException(err_msg)
