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

import json
import os
import traceback
import urllib.parse
from typing import List, Tuple
import datetime
import time

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

from .utils.extrahop_helper import (
    ExtraHopPluginHelper,
    ExtraHopPluginException,
)

from .utils.extrahop_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PAGE_LIMIT,
    MAX_PAGES,
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
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.extrahop_helper = ExtraHopPluginHelper(
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
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

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

    def _create_tags(
        self, utils: TagUtils, tags: List[dict]
    ) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""
        tag_names = []
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
            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Error occurred while creating tags. "
                    f"Error: {err}"
                )
            else:
                tag_names.append(tag)
        return tag_names

    def make_indicators(self, json_response, indicator_list):
        """Create indicators for the page.

        Args:
            json_response (dict): json response containing the detections
            indicator_list (list): indicator list

        Returns:
            total_ioc_count: total indicators pulled for the page
            total_skipped_count: total indicators skipped for the page
        """
        ip_address, hostname = 0, 0
        skipped_ip_addresses, skipped_hostnames = 0, 0
        tag_utils = TagUtils()
        for ioc in json_response:
            ioc_comments = (
                f"ID: {ioc.get('id', '')}, "
                f"Risk Score: {ioc.get('risk_score', 0)}, "
                f"Type: {ioc.get('type', '')}, "
                f"Mattire Information: {ioc.get('mitre_tactics', [])}, "
                f"Description: {ioc.get('description', '')}"
            )
            ioc_type = IndicatorType.URL
            ioc_severity = self.risk_score_to_severity(
                ioc.get("risk_score", 0)
            )
            ioc_firstSeen_lastseen = datetime.datetime.fromtimestamp(
                ioc.get("mod_time", (time.time() * 1000)) / 1000
            )
            for participant in ioc.get("participants", []):
                if (
                    participant.get("role", "")
                    and participant.get("role", "") == "offender"
                ):
                    if participant.get("object_value", ""):
                        type_tags = self._create_tags(
                            tag_utils,
                            ["extrahop-reveal(x)-360-ipaddress"],
                        )
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=participant["object_value"],
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
                        type_tags = self._create_tags(
                            tag_utils,
                            ["extrahop-reveal(x)-360-hostname"],
                        )
                        try:
                            indicator_list.append(
                                Indicator(
                                    value=participant["hostname"],
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

        self.logger.debug(
            f"{self.log_prefix}: Pull Stats - IP Addresses: {ip_address}, "
            f"Hostnames: {hostname}. Skipped IOC(s) Stats - "
            f"Skipped IP Addresses: {skipped_ip_addresses}, "
            f"Skipped Hostnames: {skipped_hostnames}."
        )
        total_ioc_count = ip_address + hostname
        total_skipped_count = skipped_ip_addresses + skipped_hostnames
        return total_ioc_count, total_skipped_count

    def check_config_match(self, storage, configuration):
        """Compare previous and current configuration.

        Args:
            storage (dict): storage configuration dictionary
            configuration (dict): current configuration dictionary
        """
        prev_configuration = storage.get("configuration_details", {})
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

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from ExtraHop Reveal(x) 360 platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the ExtraHop Reveal(x) 360 platform.
        """
        try:
            self.logger.info(
                f"{self.log_prefix}: "
                f"Executing pull method for the {PLUGIN_NAME} plugin."
            )
            indicator_list = []
            total_ioc_fetched, total_ioc_skipped = 0, 0
            storing_configuration_dict = {}
            for key, value in self.configuration.items():
                if key != "client_secret":
                    storing_configuration_dict[key] = value
            if self.storage is not None:
                storage = self.storage
                self.logger.debug(
                    f"{self.log_prefix}: Storage value - {storage}"
                )
            else:
                storage = {}
            if self.last_run_at:
                last_run_time = self.last_run_at
            else:
                last_run_time = datetime.datetime.now() - datetime.timedelta(
                    days=self.configuration.get("days")
                )

            stored_offset = storage.get("offset")
            stored_mod_time = storage.get("mod_time")
            config_match = self.check_config_match(storage, self.configuration)
            offset = 0
            epoch_timestamp_milliseconds = int(
                last_run_time.timestamp()
                * 1000
            )
            if stored_mod_time and stored_offset and config_match:
                offset = stored_offset
                epoch_timestamp_milliseconds = stored_mod_time
            endpoint = (
                f"{self.configuration.get('base_url').strip().rstrip('/')}"
                "/api/v1/detections/search"
            )
            min_risk_score = self.configuration.get('min_risk_score', 0)
            if not min_risk_score:
                min_risk_score = 0
            page_count = 1
            json_body = {
                "limit": PAGE_LIMIT,
                "offset": offset,
                "mod_time": epoch_timestamp_milliseconds,
                "filter": {
                    "risk_score_min": min_risk_score
                },
                "sort": [{"direction": "asc", "field": "mod_time"}],
            }
            try:
                auth_token = self.extrahop_helper.generate_auth_token(
                    self.configuration
                )
                if not auth_token:
                    err_msg = (
                        "Error occurred while generating auth token."
                        "Check the Client ID and Client Secret."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} "
                    )
                    raise ExtraHopPluginException(err_msg)
                headers = {"Authorization": f"Bearer {auth_token}"}
                headers = self.extrahop_helper._add_user_agent(headers)
                while True:
                    pull_resp = self.extrahop_helper.api_helper(
                        url=endpoint,
                        configuration=self.configuration,
                        method="POST",
                        headers=headers,
                        json=json_body,
                        is_handle_error_required=True,
                        logger_msg=f"pulling indicators for page {page_count}",
                        regenerate_auth_token=True,
                    )
                    if not pull_resp:
                        storage.clear()
                        storage["configuration_details"] = storing_configuration_dict
                        self.logger.info(
                            f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                            f"Total indicator(s) fetched {total_ioc_fetched}, "
                            f"skipped {total_ioc_skipped} indicator(s)."
                        )
                        return indicator_list

                    (
                        ioc_count_per_page,
                        ioc_skipped_per_page,
                    ) = self.make_indicators(pull_resp, indicator_list)
                    total_ioc_fetched += ioc_count_per_page
                    total_ioc_skipped += ioc_skipped_per_page
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched {ioc_count_per_page}"
                        f" indicator(s) for page {page_count}. "
                        f"Total indicators fetched - {total_ioc_fetched}."
                    )

                    if len(pull_resp) < PAGE_LIMIT:
                        storage.clear()
                        storage["configuration_details"] = storing_configuration_dict
                        self.logger.info(
                            f"{self.log_prefix}: Completed fetching indicators for the"
                            f" plugin. Total indicator(s) fetched {total_ioc_fetched},"
                            f" skipped {total_ioc_skipped} indicator(s)."
                        )
                        return indicator_list
                    if page_count >= MAX_PAGES:
                        storage["offset"] = offset + PAGE_LIMIT
                        storage["mod_time"] = epoch_timestamp_milliseconds
                        storage["configuration_details"] = storing_configuration_dict
                        self.logger.info(
                            f"{self.log_prefix}: Page limit of {MAX_PAGES} pages has "
                            f"reached. Returning {len(indicator_list)} indicator(s). "
                            "The pulling of the indicators will be resumed in the "
                            "next pull cycle."
                        )
                        self.logger.info(
                            f"{self.log_prefix}: Completed fetching indicators for the"
                            f" plugin. Total indicator(s) fetched {total_ioc_fetched},"
                            f" skipped {total_ioc_skipped} indicator(s)."
                        )
                        return indicator_list
                    offset += PAGE_LIMIT
                    json_body["offset"] = offset
                    page_count += 1
            except ExtraHopPluginException as err:
                storage.clear()
                storage["configuration_details"] = storing_configuration_dict
                storage["offset"] = offset
                storage["mod_time"] = epoch_timestamp_milliseconds
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing the pull "
                    f"cycle for page {page_count}. "
                    "The pulling of the indicators will be resumed in the "
                    f"next pull cycle. Error: {err}."
                )
                self.logger.error(message=err_msg, details=traceback.format_exc())
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Total indicator(s) fetched {total_ioc_fetched}, "
                    f"skipped {total_ioc_skipped} indicator(s)."
                )
                return indicator_list
            except Exception as err:
                storage.clear()
                storage["configuration_details"] = storing_configuration_dict
                storage["offset"] = offset
                storage["mod_time"] = epoch_timestamp_milliseconds
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing the pull "
                    f"cycle for page {page_count}. "
                    "The pulling of the indicators will be resumed in the "
                    f"next pull cycle. Error: {err}."
                )
                self.logger.error(message=err_msg, details=traceback.format_exc())
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Total indicator(s) fetched {total_ioc_fetched}, "
                    f"skipped {total_ioc_skipped} indicator(s)."
                )
                return indicator_list
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: "
                "Error occurred while executing the pull method "
                f"for {PLUGIN_NAME} plugin."
                f"Error: {err}"
            )
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg} Error: {err}"
            )
            raise ExtraHopPluginException(err_msg)

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
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str) or not self._validate_url(base_url):
            err_msg = "Invalid Base URL provided."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Client ID
        client_id = configuration.get("client_id", "").strip()
        if "client_id" not in configuration or not client_id:
            err_msg = "Client ID is a required field."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Client Secret
        client_secret = configuration.get("client_secret")
        if "client_secret" not in configuration or not client_secret:
            err_msg = "Client Secret is a required field."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client Secret provided."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
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
            err_msg = (
                "Invalid Minimum Risk Score provided, must be between 0 to 99."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        try:
            auth_token = self.extrahop_helper.generate_auth_token(
                configuration, "generating auth token while authenticating credentials"
            )
            if not auth_token:
                err_msg = "Error occurred while generating auth token."
                self.logger.error(
                    f"{self.log_prefix}: {validation_error_msg} {err_msg} "
                    "Check the Client ID and Client Secret."
                )
                return ValidationResult(success=False, message=err_msg)
            endpoint = (
                f"{configuration.get('base_url').strip().rstrip('/')}"
                "/api/v1/detections/search"
            )
            json_body = {"limit": 0}
            headers = {"Authorization": f"Bearer {auth_token}"}
            headers = self.extrahop_helper._add_user_agent(headers)
            self.extrahop_helper.api_helper(
                url=endpoint,
                configuration=self.configuration,
                method="POST",
                headers=headers,
                json=json_body,
                is_handle_error_required=True,
                logger_msg="pulling indicators while authenticating credentials",
                regenerate_auth_token=True,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully configured "
                f"{PLUGIN_NAME} plugin."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except ExtraHopPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while validating "
                f"credentials. Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(err))
