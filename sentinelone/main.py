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

SentinelOne CTE Plugin implementation to push and pull the data from
SentinelOne Platform.
"""

import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from netskope.integrations.cte.models import Indicator
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.constants import (
    API_VERSION,
    DATE_FORMAT,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PREFIX_IOC_SOURCE,
    PULL_PAGE_SIZE,
    PUSH_DATE_FORMAT,
    PUSH_PAGE_SIZE,
    RETRACTION,
    USER_TYPE_OPTIONS,
)
from .utils.helper import SentinelOnePluginException, SentinelOnePluginHelper


class SentinelOnePlugin(PluginBase):
    """The SentinelOne cte plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """SentinelOne plugin initializer.

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
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.sentinelone_helper = SentinelOnePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = SentinelOnePlugin.metadata
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

    def _get_site_id(
        self,
        name: str,
        url: str = None,
        token: str = None,
        is_validate: bool = False,
        is_retraction: bool = False,
    ) -> str:
        """Get Site ID.

        Args:
            name (str): Site Name.
            url (str, optional): URL of SentinelOne. Defaults to None.
            token (str, optional): API Token. Defaults to None.
            is_validate (bool, optional): Is this validate call?
              Defaults to False.
            is_retraction (bool, optional): Is this an retractoin call?
              Defaults to False.

        Returns:
            str: Site ID.
        """
        resp_json = self.sentinelone_helper.api_helper(
            method="GET",
            url=f"{url}{API_VERSION}/sites",
            params={"name": name},
            headers={"Authorization": f"ApiToken {token}"},
            is_validation=is_validate,
            logger_msg=f'getting site id for site "{name}"',
            proxies=self.proxy,
            verify=self.ssl_validation,
            is_retraction=is_retraction,
        )
        try:
            return (
                resp_json.get("data", {}).get("sites", [])[0].get("id", None)
            )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Site {name} does not exist"
                    f" on {PLATFORM_NAME}."
                ),
                details=str(resp_json),
            )
            return None

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string (str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(string.replace(".", ""), DATE_FORMAT)
        except Exception:
            return datetime.now()

    def pull(self) -> List[Indicator]:
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            self.logger.info(
                f"Successfully fetched {len(indicators)} indicator(s) "
                f"from {PLATFORM_NAME}."
            )
            return indicators

    def _create_indicators(
        self, ioc_type: str, alert: Dict, url: str
    ) -> Indicator:
        """Create indicators.

        Args:
            ioc_type (str): IOC Type.
            alert (Dict): Alert Dictionary.
            url (str): URL.

        Returns:
            Indicator: Create indicator.
        """
        threatInfo = alert.get("threatInfo", {})
        if ioc_type == "sha256":
            ioc_value = threatInfo.get("sha256")
        elif ioc_type == "md5":
            ioc_value = threatInfo.get("md5")

        alert_id = alert.get("id", "")
        last_seen = self._str_to_datetime(threatInfo.get("updatedAt", ""))
        return (
            Indicator(
                value=ioc_value,
                type=ioc_type,
                comments=(
                    "Classification: "
                    f"{threatInfo.get('classification', '')}"
                ),
                firstSeen=self._str_to_datetime(
                    threatInfo.get("createdAt", "")
                ),
                lastSeen=last_seen,
                extendedInformation=(
                    f"{url}/analyze/threats/{alert_id}/overview"
                ),
            ),
            f"{last_seen.isoformat()}Z",
        )

    def _pull(self, is_retraction: bool = False, retraction_time: str = ""):
        """Pull indicators from SentinelOne.

        Args:
            is_retraction (bool, optional): Is this retraction call?
                Defaults to False.
            retraction_time (str, optional): Retraction Time. Defaults to
                empty string.

        Yields:
            Tuple|List: Tuple of indicator list and checkpoint or only
                indicator list.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}] "
        end_time = datetime.now()
        url, token, site_name = self.sentinelone_helper.get_config_params(
            self.configuration
        )
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if is_retraction and retraction_time:
            start_time = retraction_time
        elif sub_checkpoint:
            start_time = sub_checkpoint.get("checkpoint")
        elif not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
            start_time = f"{start_time.isoformat()}Z"
        else:
            start_time = self.last_run_at
            start_time = f"{start_time.isoformat()}Z"

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from checkpoint: "
            f"{str(start_time)}"
        )
        params = {
            "updatedAt__gte": start_time,
            "updatedAt__lte": f"{end_time.isoformat()}Z",
            "limit": PULL_PAGE_SIZE,
        }

        user_type = self.configuration.get("user_type", "account")
        if user_type == "global":
            params["tenant"] = True

        cursor = None
        if site_name:
            site_id = self._get_site_id(
                name=site_name,
                url=url,
                token=token,
                is_retraction=is_retraction,
            )
            if site_id is None:
                err_msg = (
                    f"Site {site_name} does not exist on {PLATFORM_NAME}."
                    f" Validate Site Name provided in configuration "
                    "parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise SentinelOnePluginException(err_msg)
            params["siteIds"] = site_id
        api_endpoint = f"{url}{API_VERSION}/threats"
        page = 1
        checkpoint = start_time
        skip_count = 0
        fail_count = 0
        total_ioc_count = 0
        try:
            while True:
                page_indicators = set() if is_retraction else []
                ioc_counts = {"sha256": 0, "md5": 0}
                if cursor:
                    params["cursor"] = cursor
                resp_json = self.sentinelone_helper.api_helper(
                    method="GET",
                    url=api_endpoint,
                    params=params,
                    headers={"Authorization": f"ApiToken {token}"},
                    logger_msg=f"pulling threats for page {page}",
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    is_retraction=is_retraction,
                )
                for alert in resp_json.get("data", []):
                    threatInfo = alert.get("threatInfo", {})
                    if not (threatInfo.get("sha256") or threatInfo.get("md5")):
                        skip_count += 1
                        continue
                    if threatInfo.get("sha256"):
                        try:
                            if is_retraction:
                                page_indicators.add(threatInfo.get("sha256"))
                            else:
                                sha256_indicator, checkpoint = (
                                    self._create_indicators(
                                        "sha256", alert, url
                                    )
                                )
                                page_indicators.append(sha256_indicator)
                            ioc_counts["sha256"] += 1
                        except Exception as err:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    f"fetching indicators from threat with id "
                                    f"{alert.get('id','NA')}. Hence skipping "
                                    f"{threatInfo.get('sha256')}. Error: {err}"
                                ),
                                details=traceback.format_exc(),
                            )
                            fail_count += 1
                    if threatInfo.get("md5"):
                        try:
                            if is_retraction:
                                page_indicators.add(threatInfo.get("md5"))
                            else:
                                md5_indicator, checkpoint = (
                                    self._create_indicators("md5", alert, url)
                                )
                                page_indicators.append(md5_indicator)
                            ioc_counts["md5"] += 1
                        except Exception as err:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    f"fetching indicators from threat with id "
                                    f"{alert.get('id', 'NA')}. Hence skipping "
                                    f"{threatInfo.get('md5')}. Error: {err}"
                                ),
                                details=traceback.format_exc(),
                            )
                            fail_count += 1
                total_ioc_count += len(page_indicators)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(page_indicators)} indicator(s) in page {page}. Pull"
                    f" Stats: SHA256: {ioc_counts['sha256']}, MD5: "
                    f"{ioc_counts['md5']}. Skipped: {skip_count}. Failed: "
                    f"{fail_count}. Total indicator(s) fetched:"
                    f" {total_ioc_count}."
                )
                if hasattr(self, "sub_checkpoint") and not is_retraction:
                    yield page_indicators, {"checkpoint": checkpoint}
                else:
                    yield page_indicators
                cursor = resp_json.get("pagination", {}).get("nextCursor")
                if cursor is None:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{total_ioc_count} indicator(s) from {PLATFORM_NAME}."
                    )
                    break

                page += 1

        except SentinelOnePluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while pulling"
                f" indicators from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise SentinelOnePluginException(err_msg)

    def divide_in_chunks(self, indicators: List, chunk_size: int):
        """Return Fixed size chunks from list.

        Args:
            indicators (List): Indicators list
            chunk_size (int): Chunk size

        Yields:
            List: Indicators chunk list.
        """
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push indicators to the SentinelOne.

        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary
            source (str): Source configuration name.
            business_rule (str): Business rule name.
            plugin_name (str): Source plugin name.

        Returns:
            PushResult: return PushResult with success and message parameters.
        """
        self.logger.info(
            f"{self.log_prefix}: Sharing indicators to {PLATFORM_NAME}."
        )
        if action_dict["value"] != "create_iocs":
            err_msg = (
                "Invalid action provided in action "
                "parameters. Valid action is: Create IoCs."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return PushResult(
                success=False,
                message=err_msg,
            )

        indicators_data = []
        url, token, _ = self.sentinelone_helper.get_config_params(
            self.configuration
        )
        headers = {"Authorization": f"ApiToken {token}"}
        ioc_url = f"{url}/{API_VERSION}/threat-intelligence/iocs"

        # Threat IoCs
        self.logger.info(
            f"{self.log_prefix}: Preparing payload for indicators"
            f" to send to {PLATFORM_NAME}."
        )
        ioc_source = f"{PREFIX_IOC_SOURCE}"
        if plugin_name:
            ioc_source = ioc_source + " | " + plugin_name
        for indicator in indicators:
            ioc_type = indicator.type
            if ioc_type in ["sha256", "md5", "url", "ipv4", "ipv6"]:
                ioc_type = ioc_type.upper()
            else:
                ioc_type = "DNS"
            indicators_data.append(
                {
                    "value": indicator.value,
                    "type": ioc_type,
                    "source": ioc_source,
                    "externalId": indicator.value,
                    "method": "EQUALS",
                    "creationTime": indicator.firstSeen.strftime(
                        PUSH_DATE_FORMAT,
                    ),
                    "validUntil": (
                        indicator.expiresAt.strftime(
                            PUSH_DATE_FORMAT,
                        )
                        if indicator.expiresAt
                        else None
                    ),
                    "description": indicator.comments,
                }
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully created payload for "
            f"{len(indicators_data)} indicator(s) to share to "
            f"{PLATFORM_NAME}. Indicators will be shared in batches"
            f" of {PUSH_PAGE_SIZE}."
        )
        batch = 1
        total_success_count = 0
        total_failed_count = 0

        user_type = self.configuration.get("user_type", "account")
        filters = {}
        if user_type == "global":
            filters = {"tenant": True}

        for chunked_list in self.divide_in_chunks(
            indicators_data, PUSH_PAGE_SIZE
        ):
            indicator_json_data = {
                "data": chunked_list,
                "filter": filters,
            }
            try:
                self.sentinelone_helper.api_helper(
                    method="POST",
                    url=ioc_url,
                    headers=headers,
                    json=indicator_json_data,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"sharing indicators for batch {batch}"
                        f" to {PLATFORM_NAME}."
                    ),
                )

                total_success_count += len(chunked_list)
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared "
                    f"{len(chunked_list)} indicator(s) in batch {batch}"
                    f" to {PLATFORM_NAME}. Total indicator(s) shared:"
                    f" {total_success_count}."
                )
            except SentinelOnePluginException:
                total_failed_count += len(chunked_list)
            except Exception as exp:
                self.logger.error(
                    f"{self.log_prefix}: Unexpected error occurred while "
                    f"sharing {len(chunked_list)} indicator(s) in batch "
                    f"{batch} to {PLATFORM_NAME}. Error: {exp}",
                    details=traceback.format_exc(),
                )
                total_failed_count += len(chunked_list)

            batch += 1
        log_msg = (
            f"Successfully shared {total_success_count} indicator(s) to "
            f"{PLATFORM_NAME}."
        )
        if total_failed_count > 0:
            log_msg += (
                f" {total_failed_count} indicator(s) were failed to share."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(
            success=True,
            message=log_msg,
        )

    def _validate_credentials(
        self, url: str, token: str, site: str, user_type: str
    ) -> ValidationResult:
        """Validate API Credentials.

        Args:
            url (str): URL.
            token (str): API Token.
            site (str): Site name.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            params = {"limit": 1}
            if user_type == "global":
                params["tenant"] = True
            if site:
                site_id = self._get_site_id(site, url, token, True)
                if site_id is None:
                    err_msg = (
                        f"Could not find the Site {site}"
                        f" on {PLATFORM_NAME}. Verify Site Name "
                        "provided in configuration parameters."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                params["siteIds"] = site_id

            self.sentinelone_helper.api_helper(
                method="GET",
                url=f"{url}{API_VERSION}/threats",
                params=params,
                headers={"Authorization": f"ApiToken {token}"},
                is_validation=True,
                logger_msg="validating API credentials",
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            log_msg = "Successfully validated plugin configuration."
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=True,
                message=log_msg,
            )
        except SentinelOnePluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating API credentials."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration (Dict): Configuration Parameters.

        Returns:
            ValidationResult: Validation Result.
        """
        validation_err_msg = "Validation error occurred"
        url, token, site = self.sentinelone_helper.get_config_params(
            configuration
        )
        if not url:
            err_msg = "Management URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(url, str) or not self._validate_url(url):
            err_msg = (
                "Invalid Management URL provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not token:
            err_msg = "API Token is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(token, str):
            err_msg = "Invalid API Token provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if site and (not isinstance(site, str)):
            err_msg = "Invalid Site Name provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        user_type = configuration.get("user_type")
        if not user_type:
            err_msg = "User Type is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(user_type, str):
            err_msg = "Invalid User Type provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if user_type not in USER_TYPE_OPTIONS:
            err_msg = (
                "Invalid User Type value provided in configuration parameters."
                " Valid values are 'Global User' and 'Account User'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer greater than or equal to "
                "0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        retraction_days = configuration.get("retraction_interval")
        if isinstance(retraction_days, int) and retraction_days is not None:
            if int(retraction_days) <= 0:
                err_msg = (
                    "Invalid Retraction Interval provided in configuration"
                    " parameters. Valid value should be an integer "
                    "greater than 0."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
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
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        return self._validate_credentials(
            url=url,
            token=token,
            site=site,
            user_type=user_type,
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Create IoCs",
                value="create_iocs",
            ),
        ]

    def validate_action(self, action: Action):
        """Validate SentinelOne Action Configuration."""
        if action.value not in ["create_iocs"]:
            return ValidationResult(success=False, message="Invalid action.")
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

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
        end_time = datetime.now()
        start_time = end_time - timedelta(days=int(retraction_interval))
        start_time = f"{start_time.isoformat()}Z"
        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                modified_indicators = self._pull(
                    is_retraction=True, retraction_time=start_time
                )
                for indicator in modified_indicators:
                    iocs -= indicator

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
                raise SentinelOnePluginException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from SentinelOne IOC Management.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        end_time = datetime.now()
        retraction_interval = self.configuration.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield ValidationResult(
                success=False,
                disabled=True,
                message=log_msg,
            )

        retraction_interval = int(retraction_interval)
        start_time = end_time - timedelta(days=int(retraction_interval))
        start_time = f"{start_time.isoformat()}Z"
        self.logger.info(
            f"{self.log_prefix}: Start time for this retract"
            f' indicators cycle is "{start_time}".'
        )
        url, token, _ = self.sentinelone_helper.get_config_params(
            self.configuration
        )

        user_type = self.configuration.get("user_type", "account")
        filters = {}
        api_endpoint = f"{url}/{API_VERSION}/threat-intelligence/iocs"
        batch = 1
        for retraction_batch in retracted_indicators_lists:
            retraction_count = 0
            fail_count = 0
            ioc_values = [ioc.value for ioc in retraction_batch]
            for ioc_value in ioc_values:
                try:
                    if user_type == "global":
                        filters = {
                            "filter": {"value": ioc_value, "tenant": True},
                        }
                    else:
                        filters = {
                            "filter": {"value": ioc_value},
                        }
                    self.sentinelone_helper.api_helper(
                        method="DELETE",
                        url=api_endpoint,
                        json=filters,
                        headers={"Authorization": f"ApiToken {token}"},
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=(
                            f"retracting indicator with value {ioc_value}"
                            f" from batch {batch} from Threat Intelligence"
                            f" of {PLATFORM_NAME}"
                        ),
                        is_retraction=True,
                    )
                    retraction_count += 1
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully retracted indicator"
                        f" with value {ioc_value} from Threat Intelligence. "
                        f"Total retracted indicators: {retraction_count}."
                    )

                except SentinelOnePluginException:
                    fail_count += 1
                    continue
                except Exception as err:
                    err_msg = (
                        "Unexpected error occurred while retracting "
                        f"indicator with value {ioc_value} for batch {batch} "
                        f"from Threat Intelligence of {PLATFORM_NAME}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    fail_count += 1
            log_msg = f"Successfully retracted {retraction_count} indicator(s)"
            if fail_count > 0:
                log_msg += (
                    f" and {fail_count} indicator(s) were failed to retract"
                )
            log_msg += (
                f" in batch {batch} from Threat Intelligence of "
                f"{PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield ValidationResult(
                success=True,
                message=(
                    f"Completed execution for batch {batch} for retraction."
                ),
            )
            batch += 1
