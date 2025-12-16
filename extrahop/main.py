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

CTE ExtraHop Reveal(x) 360 Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import traceback
import urllib.parse
from typing import Dict, List, Tuple, Generator, Union
from datetime import datetime, timedelta
import time
import ipaddress

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)

from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils

from .utils.helper import (
    ExtraHopPluginHelper,
    ExtraHopPluginException,
)

from .utils.constants import (
    IOC_ENDPOINT,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PAGE_LIMIT,
    MAX_PAGES,
    RETRACTION,
)


class ExtraHopPlugin(PluginBase):
    """ExtraHopPlugin class having implementation all
    plugin's methods."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """ExtraHop Reveal(x) 360 plugin initializer.

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
        self.extrahop_helper = ExtraHopPluginHelper(
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
            manifest_json = ExtraHopPlugin.metadata
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

    def risk_score_to_severity(self, risk_score):
        """Convert Risk Score to CE Severity.

        Args:
            risk_score (integer): risk score of the detection.

        Returns:
            class: CE Severity Type
        """
        if 1 <= risk_score <= 30:
            return SeverityType.LOW
        elif 31 <= risk_score <= 79:
            return SeverityType.MEDIUM
        elif 80 <= risk_score <= 99:
            return SeverityType.HIGH
        else:
            return SeverityType.UNKNOWN

    def _create_external_and_role_tags(self, external, role: str) -> List[str]:
        """Create new tag(s) based on the external and role."""
        tags_list = []
        if external is not None and external != "":
            tags_list.append(
                "ExtraHop-External-Threat" if external else "ExtraHop-Internal-Threat"
            )
        if role is not None and role != "":
            tags_list.append(
                "ExtraHop-Role-Offender"
                if role == "offender"
                else "ExtraHop-Role-Victim"
            )
        return tags_list

    def _create_tags(
        self, utils: TagUtils, tags: List[dict]
    ) -> Tuple[List[str], List[str]]:
        """Create new tag(s) in database if required."""
        tag_names = []
        skipped_tags = []
        for tag in tags:
            try:
                if tag is not None and not utils.exists(tag.strip()):
                    utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))
            except ValueError as err:
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Value error occurred while creating tags. "
                    f"Error: {err}"
                )
                skipped_tags.append(tag)
            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Error occurred while creating tags. "
                    f"Error: {err}"
                )
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def _is_ip_address(self, value):
        """Check if the given value is a valid IP address or not."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except Exception:
            return False

    def make_indicators(
        self, json_response
    ) -> Tuple[int, int, List[Indicator], List[int]]:
        """Create indicators for the page.

        Args:
            json_response (dict): json response containing the detections
            indicator_list (list): indicator list

        Returns:
            total_ioc_count: total indicators pulled for the page
            total_skipped_count: total indicators skipped for the page
        """
        indicator_list = []
        ip_address, hostname = 0, 0
        skipped_ip_addresses, skipped_hostnames = 0, 0
        tag_utils = TagUtils()
        skipped_tags = []
        for ioc in json_response:
            ioc_comments = (
                f"ID: {ioc.get('id', '')}, "
                f"Risk Score: {ioc.get('risk_score', 0)}, "
                f"Type: {ioc.get('type', '')}, "
                f"Mattire Information: {ioc.get('mitre_tactics', [])}, "
                f"Description: {ioc.get('description', '')}"
            )
            ioc_severity = self.risk_score_to_severity(ioc.get("risk_score", 0))
            ioc_firstSeen_lastseen = datetime.fromtimestamp(
                ioc.get("mod_time", (time.time() * 1000)) / 1000
            )
            for participant in ioc.get("participants", []):
                if hasattr(IndicatorType, "IPV4") and self._is_ip_address(
                    participant.get("object_value", "")
                ):
                    ioc_type = IndicatorType.IPV4
                else:
                    ioc_type = IndicatorType.URL
                if (
                    participant.get("role", "")
                    and participant.get("role", "") == "offender"
                ):
                    tags_list = self._create_external_and_role_tags(
                        participant.get("external", None),
                        participant.get("role", None),
                    )
                    if participant.get("object_value", ""):
                        type_tags, tags_skipped = self._create_tags(
                            tag_utils,
                            tags_list,
                        )
                        skipped_tags.extend(tags_skipped)
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=participant.get("object_value"),
                                    type=ioc_type,
                                    severity=ioc_severity,
                                    comments=ioc_comments,
                                    firstSeen=ioc_firstSeen_lastseen,
                                    lastSeen=ioc_firstSeen_lastseen,
                                    tags=type_tags if type_tags else [],
                                )
                            )
                            ip_address += 1
                        except Exception as err:
                            self.logger.info(
                                f"{self.log_prefix}: Error occurred while "
                                f"creating indicator for detection with ID "
                                f"'{ioc.get('id', 'ID not found')}' hence "
                                f"skipping this indicator. Error: {err}"
                            )
                            skipped_ip_addresses += 1
                    if participant.get("hostname", ""):
                        type_tags, tags_skipped = self._create_tags(
                            tag_utils,
                            tags_list,
                        )
                        skipped_tags.extend(tags_skipped)
                        if hasattr(IndicatorType, "HOSTNAME"):
                            ioc_type = IndicatorType.HOSTNAME
                        else:
                            ioc_type = IndicatorType.URL
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=participant.get("hostname"),
                                    type=ioc_type,
                                    severity=ioc_severity,
                                    comments=ioc_comments,
                                    firstSeen=ioc_firstSeen_lastseen,
                                    lastSeen=ioc_firstSeen_lastseen,
                                    tags=type_tags if type_tags else [],
                                )
                            )
                            hostname += 1
                        except Exception as err:
                            self.logger.info(
                                f"{self.log_prefix}: Error occurred while "
                                f"creating indicator for detection with ID "
                                f"'{ioc.get('id', 'none')}' hence "
                                f"skipping this indicator. Error: {err}"
                            )
                            skipped_hostnames += 1
        if len(skipped_tags) > 0:
            self.logger.info(
                f"{self.log_prefix}: {len(skipped_tags)} "
                "tag(s) skipped as they were longer than expected "
                "size or due to some other exceptions that "
                "occurred while creation of them. Tags: "
                f"({', '.join(skipped_tags)})."
            )
        total_ioc_count = ip_address + hostname
        total_skipped_count = skipped_ip_addresses + skipped_hostnames
        return (
            total_ioc_count,
            total_skipped_count,
            indicator_list,
            [ip_address, hostname],
        )

    def check_config_match(self, prev_configuration, configuration):
        """Compare previous and current configuration.

        Args:
            prev_configuration_dict (dict): previous configuration dictionary
            configuration (dict): current configuration dictionary
        """
        prev_base_url = prev_configuration.get("base_url", "").strip().rstrip("/")
        prev_access_id = prev_configuration.get("client_id", "").strip()
        prev_risk_level = prev_configuration.get("min_risk_score", 0)
        base_url = configuration.get("base_url", "").strip().rstrip("/")
        access_id = configuration.get("client_id", "").strip()
        risk_level = configuration.get("min_risk_score", 0)
        configuration_match = (
            prev_base_url == base_url
            and prev_access_id == access_id
            and prev_risk_level == risk_level
        )
        self.logger.debug(
            f"{self.log_prefix}: Previous configuration's comparison with "
            f"current configuration. Match result: {configuration_match}."
        )
        return configuration_match

    def _pull(
        self,
    ) -> Generator[
        Union[Tuple[List[Indicator], Union[Dict, None]], List[Indicator]], None, None
    ]:
        """
        Generator function to pull the indicators from ExtraHop Reveal(x) 360.

        The function will generate a tuple containing a list of indicators and
        a dictionary containing the last successful fetch details. The last
        successful fetch details will be used to resume the pulling of the
        indicators in the next pull cycle if the pulling of the indicators is
        interrupted.

        The function will yield a tuple containing a list of indicators and
        a dictionary containing the last successful fetch details for each
        page of the indicators.

        The function will stop yielding tuples when the pulling of the
        indicators is completed or the page limit is reached.

        Args:
            None

        Yields:
            tuple: A tuple containing a list of indicators and a dictionary
                containing the last successful fetch details.

        Raises:
            ExtraHopPluginException: If any error occurs while executing the
                pull cycle.
        """
        try:
            self.logger.info(
                f"{self.log_prefix}: "
                f"Executing pull method for the {PLUGIN_NAME} plugin."
            )
            total_ioc_fetched, total_ioc_skipped = 0, 0
            storing_configuration_dict = {}
            last_successful_fetch = {}
            sub_checkpoint = getattr(self, "sub_checkpoint", None)
            if not hasattr(self, "sub_checkpoint") and self.storage is not None:
                storage = self.storage
                self.logger.debug(f"{self.log_prefix}: Storage value - {storage}")
            else:
                storage = {}
            page_count = 1
            min_risk_score = self.configuration.get("min_risk_score", 0)
            if not min_risk_score:
                min_risk_score = 0
            for key, value in self.configuration.items():
                if key != "client_secret":
                    storing_configuration_dict[key] = value
            last_run_time = self.last_run_at if self.last_run_at else None
            # Condition for first pull
            if not last_run_time and not sub_checkpoint and not storage:
                last_run_time = datetime.now() - timedelta(
                    days=self.configuration.get("days")
                )
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since "
                    "checkpoint is empty. Querying indicators for "
                    f"last {last_run_time} days."
                )
            # Condition for subsequent pulls
            if sub_checkpoint is None:
                if storage and self.check_config_match(
                    storage.get("configuration_details"), self.configuration
                ):
                    json_body = storage.get("json_body")
                    page_count = storage.get("page_count")
                else:
                    epoch_timestamp_milliseconds = int(last_run_time.timestamp() * 1000)
                    json_body = {
                        "limit": PAGE_LIMIT,
                        "offset": 0,
                        "mod_time": epoch_timestamp_milliseconds,
                        "filter": {"risk_score_min": min_risk_score},
                        "sort": [{"direction": "asc", "field": "mod_time"}],
                    }
            else:
                json_body = sub_checkpoint.get("json_body", {})
                page_count = sub_checkpoint.get("page_count")
            endpoint = (
                f"{self.configuration.get('base_url').strip().rstrip('/')}"
                f"{IOC_ENDPOINT}"
            )
            auth_token = self.extrahop_helper.generate_auth_token(
                self.configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            if not auth_token:
                err_msg = (
                    "Error occurred while generating auth token."
                    "Check the Client ID and Client Secret."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg} ")
                raise ExtraHopPluginException(err_msg)
            headers = {"Authorization": f"Bearer {auth_token}"}
            while True:
                indicator_list = []
                pull_resp = self.extrahop_helper.api_helper(
                    url=endpoint,
                    configuration=self.configuration,
                    method="POST",
                    headers=headers,
                    json=json_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    logger_msg=f"pulling indicators for page {page_count}",
                    regenerate_auth_token=True,
                    is_validation=False,
                )
                if hasattr(self, "sub_checkpoint"):
                    last_successful_fetch["json_body"] = json_body
                    last_successful_fetch["configuration_details"] = (
                        storing_configuration_dict
                    )
                    last_successful_fetch["page_count"] = page_count
                else:
                    storage.clear()
                    storage["json_body"] = json_body
                    storage["configuration_details"] = storing_configuration_dict
                    storage["page_count"] = page_count
                if not pull_resp:
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                        f"Total indicator(s) fetched {total_ioc_fetched}, "
                        f"skipped {total_ioc_skipped} indicator(s)."
                    )
                    storage.clear()
                    break
                (
                    ioc_count_per_page,
                    ioc_skipped_per_page,
                    indicator_list,
                    count_by_ioc,
                ) = self.make_indicators(pull_resp)
                total_ioc_fetched += ioc_count_per_page
                total_ioc_skipped += ioc_skipped_per_page
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched {ioc_count_per_page}"
                    f" indicator(s) for page {page_count}. "
                    f" Pull Stat: {count_by_ioc[0]} IP addresses, "
                    f" {count_by_ioc[1]} Hostname indicator(s) fetched."
                    f"Total indicators fetched - {total_ioc_fetched}."
                )
                if len(pull_resp) < PAGE_LIMIT:
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for the"
                        f" plugin. Total indicator(s) fetched {total_ioc_fetched},"
                        f" skipped {total_ioc_skipped} indicator(s)."
                    )
                    if hasattr(self, "sub_checkpoint"):
                        yield indicator_list, None
                    else:
                        # Clear storage when pulling is successfully completed
                        storage.clear()
                        yield indicator_list
                    break
                if not hasattr(self, "sub_checkpoint") and page_count >= MAX_PAGES:
                    self.logger.info(
                        f"{self.log_prefix}: Page limit of {MAX_PAGES} pages has "
                        f"reached. Returning {total_ioc_fetched} indicator(s). "
                        "The pulling of the indicators will be resumed in the "
                        "next pull cycle."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for the"
                        f" plugin. Total indicator(s) fetched {total_ioc_fetched},"
                        f" skipped {total_ioc_skipped} indicator(s)."
                    )
                    yield indicator_list
                    storage["page_count"] = 1
                    break
                else:
                    if hasattr(self, "sub_checkpoint"):
                        yield indicator_list, last_successful_fetch
                    else:
                        yield indicator_list
                    page_count += 1
                    json_body["offset"] += PAGE_LIMIT

        except ExtraHopPluginException as err:
            storage.clear()
            storage["json_body"] = json_body
            storage["configuration_details"] = storing_configuration_dict
            storage["page_count"] = page_count
            err_msg = (
                "Error occurred while executing the pull "
                f"cycle for page {page_count}. "
                "The pulling of the indicators will be resumed in the "
                f"next pull cycle. Error: {err}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=traceback.format_exc()
            )
            if indicator_list and not hasattr(self, "sub_checkpoint"):
                yield indicator_list
            else:
                raise ExtraHopPluginException(err_msg)
        except Exception as err:
            storage.clear()
            storage["json_body"] = json_body
            storage["configuration_details"] = storing_configuration_dict
            storage["page_count"] = page_count
            err_msg = (
                "Error occurred while executing the pull "
                f"cycle for page {page_count}. "
                "The pulling of the indicators will be resumed in the "
                f"next pull cycle. Error: {err}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=traceback.format_exc()
            )
            if indicator_list and not hasattr(self, "sub_checkpoint"):
                yield indicator_list
            else:
                raise ExtraHopPluginException(err_msg)

    def pull(
        self,
    ) -> Union[
        Generator[Tuple[List[Indicator], Union[Dict, None]], None, None],
        List[Indicator],
    ]:
        """Pull the Threat IoCs from ExtraHop Reveal(x) 360 platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the ExtraHop Reveal(x) 360 platform.
        """
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch in self._pull():
                indicators.extend(batch)
            return indicators

    def get_modified_indicators(
        self, source_indicators: List[List[Indicator]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Indicator]]): Source Indicators.

        Yields:
            List of retracted indicators, Status (List, bool): List of
                retracted indicators values. Status of execution.
        """
        self.log_prefix = f"{self.log_prefix} [{RETRACTION}]"
        retraction_interval = self.configuration.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" from {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True

        total_iocs = 0
        total_ioc_fetched = 0
        retraction_interval = int(retraction_interval)
        min_risk_score = self.configuration.get("min_risk_score", 0)
        if not min_risk_score:
            min_risk_score = 0
        pull_start_time = datetime.now() - timedelta(days=retraction_interval)
        epoch_timestamp_milliseconds = int(pull_start_time.timestamp() * 1000)
        pulled_indicators = set()
        json_body = {
            "limit": PAGE_LIMIT,
            "offset": 0,
            "mod_time": epoch_timestamp_milliseconds,
            "filter": {"risk_score_min": min_risk_score},
            "sort": [{"direction": "asc", "field": "mod_time"}],
        }
        endpoint = (
            f"{self.configuration.get('base_url').strip().rstrip('/')}"
            f"{IOC_ENDPOINT}"
        )
        page_count = 1
        try:
            auth_token = self.extrahop_helper.generate_auth_token(
                configuration=self.configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            if not auth_token:
                err_msg = (
                    "Error occurred while generating auth token."
                    "Check the Client ID and Client Secret."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg} ")
                raise ExtraHopPluginException(err_msg)
            headers = {"Authorization": f"Bearer {auth_token}"}
            self.logger.info(
                f"{self.log_prefix}: Pulling modified indicators from"
                f" {PLATFORM_NAME} since {pull_start_time}"
            )
            while True:
                retraction_pull_resp = self.extrahop_helper.api_helper(
                    url=endpoint,
                    configuration=self.configuration,
                    method="POST",
                    headers=headers,
                    json=json_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    logger_msg=f"pulling indicators for page {page_count}",
                    regenerate_auth_token=True,
                    is_retraction=True,
                    is_validation=False,
                )
                if not retraction_pull_resp:
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                        f"Total indicator(s) fetched {total_ioc_fetched}"
                    )
                    break
                for data in retraction_pull_resp:
                    for particiant in data.get("participants", []):
                        if particiant.get("role", "") == "offender":
                            if particiant.get("object_value"):
                                pulled_indicators.add(particiant.get("object_value"))
                                total_ioc_fetched += 1
                            if particiant.get("hostname"):
                                pulled_indicators.add(particiant.get("hostname"))
                                total_ioc_fetched += 1
                page_count += 1
                json_body["offset"] += PAGE_LIMIT
        except ExtraHopPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Unexpected error occurred while pulling modified "
                f"indicators for page {page_count} "
                f"from {PLATFORM_NAME}. Error: {err}"
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(error_msg)
        try:
            for ioc_page in source_indicators:
                source_unique_iocs = set()
                for ioc in ioc_page:
                    total_iocs += 1
                    source_unique_iocs.add(ioc.value)
                self.logger.info(
                    f"{self.log_prefix}: Getting modified indicators status"
                    f" for {len(source_unique_iocs)} indicator(s) from"
                    f" {PLATFORM_NAME}."
                )
                retracted_iocs = source_unique_iocs - pulled_indicators
                self.logger.info(
                    f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) will "
                    f"be marked as retracted from {total_iocs} total "
                    f"indicator(s) present in cloud exchange for"
                    f" {PLATFORM_NAME}."
                )
                yield list(retracted_iocs), False
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while marking indicators as retracted."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}. Error: {err}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(error_msg)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urllib.parse.urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        validation_error_msg = "Validation error occurred."
        # Base URL
        base_url = configuration.get("base_url", "").strip().rstrip("/")
        if "base_url" not in configuration or not base_url:
            err_msg = "Base URL is a required field."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str) or not self._validate_url(base_url):
            err_msg = "Invalid Base URL provided."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Client ID
        client_id = configuration.get("client_id", "").strip()
        if "client_id" not in configuration or not client_id:
            err_msg = "Client ID is a required field."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Client Secret
        client_secret = configuration.get("client_secret")
        if "client_secret" not in configuration or not client_secret:
            err_msg = "Client Secret is a required field."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret provided."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # MIN Risk Score
        min_risk_score = configuration.get("min_risk_score", 0)
        if min_risk_score and (
            not isinstance(min_risk_score, int)
            or int(min_risk_score) < 0
            or int(min_risk_score) > 99
        ):
            err_msg = "Invalid Minimum Risk Score provided, must be between 0 to 99."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Retraction Interval
        retraction_interval = configuration.get("retraction_interval", 0)
        if retraction_interval and (
            not isinstance(retraction_interval, int)
            or int(retraction_interval) <= 0
            or int(retraction_interval) > INTEGER_THRESHOLD
        ):
            err_msg = (
                "Invalid Retraction Interval provided in configuration"
                " parameters. Valid value should be an integer greater than 0 and less than 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Initial Pull Range
        initial_pull_range = configuration.get("days")
        if "days" not in configuration or not initial_pull_range:
            err_msg = "Initial Pull Range is a required field."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_pull_range, int):
            err_msg = "Invalid Initial Pull Range provided."
            self.logger.error(f"{self.log_prefix}: {validation_error_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        try:
            auth_token = self.extrahop_helper.generate_auth_token(
                configuration=configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="generating auth token while authenticating credentials",
            )
            if not auth_token:
                err_msg = "Error occurred while generating auth token."
                self.logger.error(
                    f"{self.log_prefix}: {validation_error_msg} {err_msg} "
                    "Check the Client ID and Client Secret."
                )
                return ValidationResult(success=False, message=err_msg)
            endpoint = (
                f"{configuration.get('base_url').strip().rstrip('/')}{IOC_ENDPOINT}"
            )
            json_body = {"limit": 0}
            headers = {"Authorization": f"Bearer {auth_token}"}
            self.extrahop_helper.api_helper(
                url=endpoint,
                configuration=self.configuration,
                method="POST",
                headers=headers,
                json=json_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                logger_msg="pulling indicators while authenticating credentials",
                regenerate_auth_token=True,
                is_validation=True,
            )
            success_msg = (
                f"Successfully validated credentials for {PLUGIN_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {success_msg}")
            return ValidationResult(success=True, message=success_msg)
        except ExtraHopPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while validating "
                f"credentials. Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(err))
