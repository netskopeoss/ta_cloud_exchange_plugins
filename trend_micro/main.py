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

Trend Vision One Plugin to push and pull the data from Trend Vision One Platform.
"""

from datetime import datetime, timedelta
from typing import List, Tuple, Dict
import re
import traceback
import ipaddress
from pydantic import ValidationError

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
)

from .utils.trend_micro_helper import (
    TrendMicroPluginHelper,
    TrendMicroPluginException,
    MaximumLimitExceededException,
)

from .utils.trend_micro_constant import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    DATE_FORMAT_FOR_IOCS,
    TRENDMICRO_TO_INTERNAL_TYPE,
    TRENDMICRO_BASE_URLS,
    IOC_DESCRIPTION,
    TRENDMICRO_TO_INTERNAL_SEVERITY,
    INTERNAL_SEVERITY_TO_TRENDMICRO,
    INDICATOR_TYPES,
)


def check_url_domain_ip(type):
    """Categorize UTL as Domain, IP or URL."""
    regex_domain = (
        "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    )
    try:
        ipaddress.ip_address(type)
        return "ip"
    except Exception:
        if re.search(regex_domain, type):
            return "domain"
        else:
            return "url"


class TrendMicroPlugin(PluginBase):
    """Trend Vision One Plugin class for pulling and pushing threat indicators."""

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
        self.trend_micro_helper = TrendMicroPluginHelper(
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
            manifest_json = TrendMicroPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}."
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL and Authentication Token.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("token"),
        )

    def get_headers(self, authentication_token: str) -> Dict:
        """Get headers required for the API call."""
        return self.trend_micro_helper._add_user_agent(
            {
                "Authorization": "Bearer " f"{authentication_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        (base_url, authentication_token) = self._get_credentials(configuration)
        if not base_url:
            err_msg = "Data Region is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif base_url not in TRENDMICRO_BASE_URLS:
            err_msg = "Invalid value for Data Region provided. Select value from the given options only."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not authentication_token:
            err_msg = (
                "Authentication Token is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(authentication_token, str):
            err_msg = "Invalid Authentication Token, Type of Authentication Token should be String."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message="Type of Authentication Token should be String.",
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
            err_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        initial_range = configuration.get("initial_range", 0)
        if initial_range is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid value provided in Initial Range "
                "in configuration parameter. Valid value "
                "should be an positive integer greater then zero."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif initial_range <= 0 or initial_range > 365:
            err_msg = (
                "Invalid value for Initial Range provided. "
                "Select a value between 1 - 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self.validate_auth_params(configuration, validation_err_msg)

    def validate_auth_params(
        self, configuration, validation_err_msg
    ) -> ValidationResult:
        """Validate the Trend Vision One Plugin Authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating Authentication parameters"
        )
        try:
            (base_url, authentication_token) = self._get_credentials(
                configuration
            )

            query_params = {
                "top": 1,
            }
            headers = self.get_headers(authentication_token)
            self.trend_micro_helper.api_helper(
                logger_msg="validating Authentication parameters.",
                url=f"{base_url}/v3.0/threatintel/suspiciousObjects",
                method="GET",
                params=query_params,
                headers=headers,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully Validated Authentication parameters"
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except TrendMicroPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}, Check logs for more details.",
            )

    def pull(self) -> List[Indicator]:
        """Pull the Threat information from Trend Vision One platform.

        Returns : List[cte.models.Indicators] :
        List of indicator objects received from the Trend Vision One platform.
        """
        try:
            is_pull_required = self.configuration.get(
                "is_pull_required", "Yes"
            ).strip()
            if is_pull_required == "No":
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self.get_indicators()

                return wrapper(self)

            else:
                indicators = []
                for batch in self.get_indicators():
                    indicators.extend(batch)

                total_counts_msg = (
                    f"Successfully fetched {len(indicators)} indicator(s) "
                    f"from {PLATFORM_NAME}."
                )
                self.logger.info(f"{self.log_prefix}: {total_counts_msg}")
                return indicators

        except TrendMicroPluginException as err:
            raise err
        except Exception as exp:
            err_msg = "Error occurred while pulling indicaors."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" indicators. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(str(err_msg))

    def get_indicators(self):
        """Get indicators from Trend Vision One.

        Args:
            headers (dict): Header dict object having authentication token.
        Returns:
            List[dict]: List of python dict object of JSON response model
            as per Trend Vision One API.
        """
        (base_url, authentication_token) = self._get_credentials(
            self.configuration
        )

        query_endpoint = f"{base_url}/v3.0/threatintel/suspiciousObjects"
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint:
            checkpoint = sub_checkpoint.get("checkpoint")
        else:
            checkpoint = self._get_trend_micro_last_seen()

        query_params = {
            "startDateTime": checkpoint,
            "endDateTime": datetime.now(),
            "top": 200,
        }
        headers = self.get_headers(authentication_token)

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint: {checkpoint}"
        )

        next_page = True
        page_count = 0
        total_indicators = 0
        indicator_checkpoint = checkpoint

        try:
            while next_page:
                page_count += 1
                logger_msg = (
                    f"Pulling indicators for page {page_count} "
                    f"from {PLATFORM_NAME}."
                )
                self.logger.info(f"{self.log_prefix}: {logger_msg}")

                resp_json = self.trend_micro_helper.api_helper(
                    logger_msg=f"Pulling data for page {page_count}.",
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    params=query_params,
                )
                if resp_json.get("code"):
                    log_msg = "Unexpected response received from Trend Vision One APIs, reach out to the Trend vision One Support for more information."
                    self.logger.error(f"{self.log_prefix}: {log_msg}")
                    raise TrendMicroPluginException(str(log_msg))

                indicators_json_list = resp_json.get("items", [])

                indicator_list = []
                indicators_per_page = {
                    "total": 0,
                    "fileSha256": 0,
                    "domain": 0,
                    "url": 0,
                    "ip": 0,
                    "skipped": 0,
                }

                for indicator in indicators_json_list:

                    indicator_checkpoint = indicator.get(
                        "lastModifiedDateTime",
                        str(datetime.now().strftime(DATE_FORMAT_FOR_IOCS)),
                    )

                    if (
                        str(IOC_DESCRIPTION)
                        not in indicator.get("description", "")
                        and indicator.get("type") in INDICATOR_TYPES
                    ):
                        ioc_type = indicator.get("type")
                        indicator_type, skipped = self._detect_indicator_type(
                            str(ioc_type)
                        )

                        if skipped:
                            indicators_per_page["skipped"] += 1
                            continue
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=indicator.get(ioc_type),
                                    type=indicator_type,
                                    comments=str(
                                        indicator.get("description", "")
                                    ),
                                    lastSeen=datetime.strptime(
                                        indicator.get("lastModifiedDateTime"),
                                        DATE_FORMAT_FOR_IOCS,
                                    ),
                                    severity=TRENDMICRO_TO_INTERNAL_SEVERITY.get(
                                        indicator.get("riskLevel")
                                    ),
                                )
                            )
                        except ValidationError:
                            indicators_per_page["skipped"] += 1

                        indicators_per_page[ioc_type] += 1
                        indicators_per_page["total"] += 1
                    else:
                        indicators_per_page["skipped"] += 1

                total_indicators += len(indicator_list)
                count_per_page_msg = (
                    "Successfully fetched {total} indicator(s) and skipped "
                    "{skipped} indicator(s) in page {page}. Pull Stats: "
                    "SHA256={SHA256}, Domain={domain}, IP={ip}, URL={url},"
                    " Total indicator(s) fetched: {total_indicators}".format(
                        total=indicators_per_page["total"],
                        skipped=indicators_per_page["skipped"],
                        page=page_count,
                        SHA256=indicators_per_page["fileSha256"],
                        domain=indicators_per_page["domain"],
                        ip=indicators_per_page["ip"],
                        url=indicators_per_page["url"],
                        total_indicators=total_indicators,
                    )
                )
                indicators_per_page_count = indicators_per_page["total"]
                self.logger.info(
                    f"{self.log_prefix}:Fetched {indicators_per_page_count} indicators in page {page_count}"
                    f", Total indicators fetched till now {total_indicators}."
                )
                self.logger.debug(f"{self.log_prefix}: {count_per_page_msg}")

                if hasattr(self, "sub_checkpoint"):
                    yield indicator_list, {"checkpoint": indicator_checkpoint}
                else:
                    yield indicator_list

                if "nextLink" not in resp_json or "nextLink" == "":
                    next_page = False
                    break
                else:
                    query_params.clear()
                    query_endpoint = resp_json["nextLink"]

        except TrendMicroPluginException as trend_micro_err:
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: Error Occurred while pulling "
                    f"indicators from {PLATFORM_NAME}. Error: {trend_micro_err}"
                ),
                details=traceback.format_exc(),
            )
            raise TrendMicroPluginException(str(trend_micro_err))
        except Exception as exp:
            err_msg = f"Error occurred while pulling indicators from {PLATFORM_NAME}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise TrendMicroPluginException(err_msg)

    def _detect_indicator_type(self, indicator_type: str) -> Tuple[str, bool]:
        """To detect the type of indicator
        Returns:
            Tuple[str, bool]: (Type of indicator and True) if it is a valid indicator and (skipped and False)
            for invalid indicators
        """
        detected = TRENDMICRO_TO_INTERNAL_TYPE.get(indicator_type)
        if not detected:
            return "skipped", True
        return detected, False

    def _get_trend_micro_last_seen(self) -> str:
        """Get Trend Vision One LastSeen Or DateChanged parameter.
        Returns:
            LastSeen/DateChanged (str):
                A datetime object as string representation.
        """
        if not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(self.configuration.get("initial_range"))
            )
        else:
            start_time = self.last_run_at
        return start_time.strftime(DATE_FORMAT_FOR_IOCS)

    def push_indicators_to_trendmicro(self, json_payload, action_value, batch):
        """Push Indicators to Trend Vision One's selected Target List."""
        (base_url, authentication_token) = self._get_credentials(
            self.configuration
        )
        if action_value == "suspicious_object":
            push_endpoint = f"{base_url}/v3.0/threatintel/suspiciousObjects"
        else:
            push_endpoint = (
                f"{base_url}/v3.0/threatintel/suspiciousObjectExceptions"
            )

        headers = self.get_headers(authentication_token)
        check_flag = True
        fail_count = 0
        success_count = 0
        try:

            response = self.trend_micro_helper.api_helper(
                logger_msg=f"sharing {len(json_payload)} indicator(s) to {PLATFORM_NAME} in batch {batch}.",
                url=push_endpoint,
                method="POST",
                json=json_payload,
                headers=headers,
            )
            if isinstance(response, list):
                response_code = [status.get("status") for status in response]
                for status in response_code:
                    if status in [201, 202]:
                        if status == 201:
                            success_count += 1
                        else:
                            fail_count += 1
            else:
                if response.get("code"):
                    log_msg = "Unexpected response received, please provide the required minumum permissions."
                else:
                    log_msg = "Unexpected response received."
                self.logger.error(
                    message=f"{self.log_prefix}: {log_msg}",
                    details=f"{response}",
                )
                raise TrendMicroPluginException(str(log_msg))
        except MaximumLimitExceededException:
            fail_count += len(json_payload)
            check_flag = False
            return fail_count, success_count, check_flag
        except TrendMicroPluginException:
            fail_count += len(json_payload)
            pass
        except Exception as exp:
            fail_count += len(json_payload)
            err_msg = (
                f"Error occurred while sharing indicator(s) of batch {batch}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )

        return fail_count, success_count, check_flag

    def push(self, indicators: List[Indicator], action_dict: Action):
        """Push indicators to Trend Vision One."""
        action_value = action_dict.get("value")
        action_params = action_dict.get("parameters", {})

        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_dict.get("label")}" target action.'
        )
        batch_chunk_size = 0
        if action_value == "suspicious_object":
            batch_chunk_size = 1000
        else:
            batch_chunk_size = 100

        total_fail_count = 0
        total_success_count = 0
        batch = 1
        payload_list = self.prepare_payload(indicators, action_params)
        for chunked_list in self.divide_in_chunks(
            payload_list, batch_chunk_size
        ):
            chunk_size = len(chunked_list)
            chunk_fail_count, chunk_success_count, check_flag = (
                self.push_indicators_to_trendmicro(
                    chunked_list, action_value, batch
                )
            )
            total_fail_count += chunk_fail_count
            total_success_count += chunk_success_count
            if not check_flag:
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared {total_success_count} indicator(s) and failed to share {total_fail_count} indicator(s). No more indicators will be shared as maximum limit has exceeded, delete some indicators from the platform for sharing."
                )
                break

            self.logger.info(
                f"{self.log_prefix}: Successfully shared {chunk_success_count} indicator(s) and "
                f"failed to share {chunk_fail_count} indicator(s) from {chunk_size} indicators in batch {batch}."
                f" Total indicator(s) shared: {total_success_count}."
            )

            batch += 1
        log_msg = f"Successfully shared {total_success_count} indicator(s) to {PLATFORM_NAME}."
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(
            success=True,
            message=log_msg,
        )

    def prepare_payload(self, indicators, action_dict):
        """Prepare the JSON payload for Push.

        Args:
            indicators (List[cte.models.Indicators]):
            List of Indicator objects to be pushed.
            action_dict (Dict) : Dictionary contains the action
            and plateforms for sharing.
        Returns:
            List[dict]: List of python dict object of JSON response model
            as per Trend Vision One API.
        """
        md5_count = 0
        domain_count = 0
        url_count = 0
        sha256_count = 0
        skip_count = 0
        payload_list = []
        for indicator in indicators:
            try:
                if indicator.type in [IndicatorType.URL, IndicatorType.SHA256]:
                    if indicator.type == IndicatorType.URL:
                        indicator_value = indicator.value
                        type_of_url = check_url_domain_ip(indicator.value)
                        if type_of_url == "domain":
                            indicator_value = indicator_value.rstrip("/")
                            domain_count += 1
                        payload = {
                            type_of_url: indicator_value,
                            "description": (
                                f"{action_dict.get('desc')} {IOC_DESCRIPTION}"
                            ),
                            "riskLevel": INTERNAL_SEVERITY_TO_TRENDMICRO[
                                indicator.severity
                            ],
                        }
                        url_count += 1
                    else:
                        payload = {
                            "fileSha256": indicator.value,
                            "description": (
                                f"{action_dict.get('desc')} {IOC_DESCRIPTION}"
                            ),
                            "riskLevel": INTERNAL_SEVERITY_TO_TRENDMICRO[
                                indicator.severity
                            ],
                        }
                        sha256_count += 1
                    payload_list.append(payload)
                else:
                    md5_count += 1
                    skip_count += 1
            except Exception as err:
                skip_count += 1
                err_msg = "Exception occurred while Preparing Payload."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return PushResult(
                    success=False,
                    message=(f"Error :{repr(err)}: {err_msg}"),
                )

        log_msg = (
            f"Successfully created payload for {len(payload_list)}"
            f" indicator(s) and skipped {skip_count} indicator(s) for sharing in which {md5_count} "
            f" MD5 indicator(s). Total {sha256_count} SHA256, {url_count} "
            f"URL(s), {domain_count} domain(s) will be shared. "
        )

        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return payload_list

    def divide_in_chunks(self, indicators, chunk_size):
        """Divide the json payload into chunks of size less than 1MB."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Add to Suspicious Object List",
                value="suspicious_object",
            ),
            ActionWithoutParams(
                label="Add to Exception List",
                value="suspicious_object_exception",
            ),
        ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Netskope configuration."""
        if action.value not in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:

            err_msg = "Unsupported action provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=f"{err_msg}")
        if action.parameters.get("desc") is None:

            err_msg = "Invalid Description Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=f"{err_msg}")

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:
            return [
                {
                    "label": "Description",
                    "key": "desc",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Description to be sent with Threat IOCs.",
                },
            ]
