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

CTE Recorded Future IOC Plugin.
"""

import traceback
from typing import List

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from pydantic import ValidationError

from .utils.recorded_future_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RISK_LIST,
    FETCH_RISK_LIST_ENDPOINT,
)

from .utils.recorded_future_helper import (
    RecordedFuturePluginException,
    RecordedFuturePluginHelper,
)


class RecordedFuturePlugin(PluginBase):
    """Recorded Future IOC Plugin class template implementation."""

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
        self.recorded_future_helper = RecordedFuturePluginHelper(
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
            metadata_json = RecordedFuturePlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
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
        return PLATFORM_NAME, PLUGIN_VERSION

    def pull(self) -> List[Indicator]:
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
        """Pull indicators from Recorded Future IOC plugin."""
        risk_lists = self.configuration.get("risk_lists", "")
        total_indicators = 0
        total_unexpected_error = 0

        self.logger.info(
            f"{self.log_prefix}: Pulling indicator(s) "
            f"from the Risk List {', '.join(risk_lists)}."
        )
        for index, risklist in enumerate(risk_lists):
            individual_count = {
                "ipv4": 0,
                "ipv6": 0,
                "url": 0,
                "domain": 0,
                "md5": 0,
                "sha256": 0,
            }

            url = FETCH_RISK_LIST_ENDPOINT.format(risklist)
            headers = self.recorded_future_helper.get_headers(
                self.configuration.get("api_key", ""),
            )
            logger_msg = f"pulling indicators(s) from {risklist} Risk List"
            try:
                response = self.recorded_future_helper.api_helper(
                    url=url,
                    method="GET",
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=logger_msg,
                    headers=headers,
                )
                (
                    indicators,
                    individual_count_val,
                    failed_count,
                    unexpected_error,
                ) = self.extract_indicators(
                    response, risklist, individual_count
                )
                current_list_count = sum(individual_count_val.values())
                total_indicators += current_list_count
                total_unexpected_error += unexpected_error
                info_msg = (
                    f"Successfully fetched {current_list_count} "
                    "indicator(s) from the "
                    f"'{risklist}' Risk List."
                )
                debug_msg = (
                    f"{self.log_prefix}: "
                    "Current Pull Stats: Successfully fetched total "
                    f"{total_indicators} indicator(s). "
                    f"Domains: {individual_count_val['domain']}, "
                    f"IP: {individual_count_val['ipv4']}, "
                    f"URL: {individual_count_val['url']}, "
                    f"MD5: {individual_count_val['md5']}."
                )
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")
                if risklist == "ip" and failed_count:
                    info_msg += (
                        f" Failed to fetch {failed_count} "
                        "IP address(es) as they contained invalid values."
                    )
                elif risklist == "hash" and failed_count:
                    info_msg += (
                        f" Failed to fetch {failed_count} "
                        "Hash(es) as they contained type other than "
                        "MD5 or SHA256."
                    )
                info_msg += f" Total indicators fetched: {total_indicators}."

                self.logger.info(f"{self.log_prefix}: {info_msg}")
                if index == len(risk_lists) - 1:
                    if total_unexpected_error:
                        error_msg = (
                            f" Failed to create "
                            f"{total_unexpected_error} indicator(s) "
                            "due to an unexpected error."
                            "Indicator value and the error cause can "
                            "be found in separate error logs."
                        )
                        self.logger.error(f"{self.log_prefix}: {error_msg}")

                if hasattr(self, "sub_checkpoint"):
                    yield indicators, None
                else:
                    yield indicators

            except RecordedFuturePluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f"Error: {str(exp)}"
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg}"),
                    details=str(traceback.format_exc()),
                )
                raise RecordedFuturePluginException(err_msg)

    def extract_indicators(self, response, risklist, individual_count):
        """
        Extract indicators from a given response based on the \
            specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            risklist (string): the type of IOC fetching

        Returns:
            Tuple[List[dict], int]: A tuple containing a list of extracted \
                                    indicators and the number of indicators.
        """
        headers = True
        indicators = []
        unexpected_error = 0
        skipped_ioc = 0

        for line in response.splitlines():
            if not headers:
                values = line.split('","')
                values = [value.strip('"') for value in values]

                current_value = self.recorded_future_helper.safe_get(
                    values, 0, None
                )

                # convert risklist into netskope types.
                if risklist == "ip":
                    ip_type = self.recorded_future_helper.check_ip_version(
                        current_value
                    )
                    if ip_type == "IPv4":
                        current_type = getattr(
                            IndicatorType, "IPV4", IndicatorType.URL
                        )
                        individual_count["ipv4"] += 1
                    elif ip_type == "IPv6":
                        current_type = getattr(
                            IndicatorType, "IPV6", IndicatorType.URL
                        )
                        individual_count["ipv6"] += 1
                    else:
                        self.logger.info(
                            f"{self.log_prefix}: Invalid IP address found, "
                            f"the indicator '{current_value}' will be skipped."
                        )
                        skipped_ioc += 1
                        continue
                elif risklist == "hash":
                    hash_type = self.recorded_future_helper.safe_get(
                        values, 1, None
                    )
                    if hash_type == "SHA-256":
                        current_type = IndicatorType.SHA256
                        individual_count["sha256"] += 1
                    elif hash_type == "MD5":
                        current_type = IndicatorType.MD5
                        individual_count["md5"] += 1
                    else:
                        skipped_ioc += 1
                        continue
                elif risklist == "domain":
                    current_type = getattr(
                        IndicatorType, "DOMAIN", IndicatorType.URL
                    )
                    individual_count["domain"] += 1
                elif risklist == "url":
                    current_type = IndicatorType.URL
                    individual_count["url"] += 1
                else:
                    self.logger.error(
                        f"{self.log_prefix}: "
                        f"Unsupported Risk List provided,"
                        "Skipping fetching indicator(s) for "
                        f" {risklist} Risk List."
                    )
                    continue

                if risklist == "hash":
                    current_risk_score = self.recorded_future_helper.safe_get(
                        values, 2, None
                    )
                    current_evidences = self.recorded_future_helper.safe_get(
                        values, 4, None
                    )
                else:
                    current_risk_score = self.recorded_future_helper.safe_get(
                        values, 1, None
                    )
                    current_evidences = self.recorded_future_helper.safe_get(
                        values, 3, None
                    )
                fetch_evidence = self.configuration.get(
                    "fetch_evidences", "yes"
                )
                if fetch_evidence == "yes":
                    current_evidences = "".join(current_evidences)

                try:
                    current_risk_score = (
                        int(current_risk_score) if current_risk_score else None
                    )
                except ValueError:
                    self.logger.error(
                        f"{self.log_prefix}: "
                        f"Value error occured while converting the "
                        f"Risk Score({current_risk_score}) "
                        "to integer. The Severity for the indicator "
                        f"'{current_value}' will be set as 'Unknown'."
                    )
                    current_risk_score = None

                if (
                    not isinstance(current_risk_score, int)
                    or current_risk_score == 0
                ):
                    current_risk = SeverityType.UNKNOWN
                elif current_risk_score <= 39:
                    current_risk = SeverityType.LOW
                elif current_risk_score <= 69:
                    current_risk = SeverityType.MEDIUM
                elif current_risk_score <= 89:
                    current_risk = SeverityType.HIGH
                else:
                    current_risk = SeverityType.CRITICAL

                try:
                    indicators.append(
                        Indicator(
                            value=current_value,
                            type=current_type,
                            severity=current_risk,
                            comments=(
                                current_evidences.replace('"', "")
                                if fetch_evidence == "yes"
                                else ""
                            ),
                        )
                    )
                except (ValidationError, Exception) as error:
                    unexpected_error += 1
                    error_message = (
                        "Validation error occurred"
                        if isinstance(error, ValidationError)
                        else "Unexpected error occurred"
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} while"
                            " creating indicator for Risk List"
                            f"{risklist}. This record will be"
                            f" skipped. Error: {error}."
                        ),
                        details=str(traceback.format_exc()),
                    )
            else:
                headers = False
        return indicators, individual_count, skipped_ioc, unexpected_error

    def validate_api_key(self, api_key) -> ValidationResult:
        """Validate the API Key.

        Args:
            api_key (str): Recorded Future API Key
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        # Validating API Key by fetching IP Addresses
        url = FETCH_RISK_LIST_ENDPOINT.format("ip")
        headers = self.recorded_future_helper.get_headers(api_key)
        try:
            logger_msg = "validating API Key"
            self.recorded_future_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=logger_msg,
                headers=headers,
                is_validation=True,
            )
            return ValidationResult(
                success=True, message="Validation Successful."
            )

        except RecordedFuturePluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while "
                "validating the API Key provided in the "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: "
                f"Validation error occurred {err_msg} "
                f"Error: {str(err)}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        api_key = configuration.get("api_key", "")
        validation_err = "Validation error occurred."

        # Validating API Key
        if not api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid API Key provided in the " "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validating risklist
        risk_list = configuration.get("risk_lists", [])
        if not risk_list:
            err_msg = "Risk Lists is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(x in RISK_LIST for x in risk_list)
            and isinstance(risk_list, list)
        ):
            err_msg = (
                "Invalid Risk Lists provided in "
                "configuration parameters. "
                "Select values from the given list items."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validating Fetch Evidences
        fetch_evidences = configuration.get("fetch_evidences", "yes")
        if not fetch_evidences:
            err_msg = "Fetch Evidences is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(fetch_evidences, str) or fetch_evidences not in [
            "yes",
            "no",
        ]:
            err_msg = (
                "Invalid Fetch Evidences selected in "
                "configuration parameters. "
                "Allowed values are 'Yes' or 'No'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_api_key(api_key)
