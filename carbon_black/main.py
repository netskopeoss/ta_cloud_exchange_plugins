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

Carbon Black Plugin implementation to push and pull the data from Netskope
Tenant.

"""

import traceback
import json
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from pydantic import ValidationError
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    TagIn,
)
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from .utils.carbon_black_constants import (
    DATE_FORMAT_FOR_IOCS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLATFORM_NAME,
    MAX_PULL_PAGE_SIZE,
    PLUGIN_VERSION,
    CARBONBLACK_TO_INTERNAL_TYPE,
    REPUTATION,
    FETCH_ALERS_API_ENDPOINT,
    FEEDS_API_ENDPOINT,
)
from .utils.carbon_black_helper import (
    CarbonBlackPluginException,
    CarbonBlackPluginHelper,
)


class CarbonBlackPlugin(PluginBase):
    """The CarbonBlack plugin implementation."""

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
        self.carbon_black_helper = CarbonBlackPluginHelper(
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
            manifest_json = CarbonBlackPlugin.metadata
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

    def _validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string(str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(string.replace(".", ""), DATE_FORMAT_FOR_IOCS)
        except Exception:
            return datetime.now()

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        try:
            self.carbon_black_helper.api_helper(
                "validating credentials",
                FETCH_ALERS_API_ENDPOINT.format(
                    configuration["management_url"].strip().rstrip("/"),
                    configuration["org_key"].strip(),
                ),
                "POST",
                data=json.dumps({"rows": 0}),
                headers=self._get_headers(configuration),
                is_validation=True,
            )

            return ValidationResult(success=True, message="Validation successful.")

        except CarbonBlackPluginException as err:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
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
                message=f"{err_msg} Check logs for more details.",
            )

    def create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        skipped_tags = set()

        for tag in tags:
            tag_name = tag.strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, tag_name, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(skipped_tags)

    def pull(self):
        """Pull indicators from CarbonBlack."""

        if self.configuration["is_pull_required"] == "Yes":
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}."
            )
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self.get_indicators()

                return wrapper(self)

            else:
                indicators = []
                for batch in self.get_indicators():
                    indicators.extend(batch)

                self.logger.info(
                    f"{self.log_prefix}: Total {len(indicators)} indicator(s) fetched."
                )
                return indicators
        else:
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
        return []

    def get_indicators(self):
        """
        Get indicators from a specified endpoint based on certain criteria and configuration settings.
        """

        hash_of_ioc = set()
        page_count = 0
        total_skipped_tags = set()

        create_tags = False
        tagging = self.configuration["enable_tagging"].lower() == "yes"
        if tagging:
            if self.configuration.get("reputation", []):
                skipped_tags = self.create_tags(self.configuration["reputation"])
                total_skipped_tags.update(skipped_tags)
            else:
                create_tags = True

        end_time = datetime.now()
        url = FETCH_ALERS_API_ENDPOINT.format(
            self.configuration["management_url"].strip().rstrip("/"),
            self.configuration["org_key"].strip(),
        )

        checkpoint = None
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint and sub_checkpoint.get("checkpoint"):
            checkpoint = sub_checkpoint.get("checkpoint")
        elif not (self.last_run_at or sub_checkpoint):
            # Initial Run
            days = self.configuration["days"]
            checkpoint = datetime.now() - timedelta(days=days)
            self.logger.info(
                f"{self.log_prefix}: This is initial ran of plugin hence"
                f" pulling indicators from last {days} days."
            )
        else:
            checkpoint = self.last_run_at

        body = {
            "rows": MAX_PULL_PAGE_SIZE,
            "criteria": {
                "minimum_severity": self.configuration["minimum_severity"],
                "process_reputation": self.configuration["reputation"],
            },
            "time_range": {
                "start": (
                    checkpoint
                    if isinstance(checkpoint, str)
                    else f"{checkpoint.isoformat()}Z"
                ),
                "end": f"{end_time.isoformat()}Z",
            },
            "start": 1,
            "sort": [{"field": "backend_timestamp", "order": "ASC"}],
        }
        headers = self._get_headers(self.configuration)
        last_indicator_timestamp = checkpoint

        is_next_page = True
        last_num_found = 0
        total_indicators = 0
        while is_next_page:
            current_extracted_indicators = []
            page_count += 1
            current_page_skip_count = 0
            try:
                response = self.carbon_black_helper.api_helper(
                    "pulling indicators for page {}".format(page_count),
                    url,
                    "POST",
                    data=json.dumps(body),
                    headers=headers,
                )

                if not response.get("results"):
                    self.logger.info(
                        f"{self.log_prefix}: No indicators found for the page {page_count}."
                    )
                    break

                temp_create_time = response["results"][-1].get("backend_timestamp")
                for alert in response["results"]:
                    try:
                        ioc_hash = hash(json.dumps(alert))
                        last_indicator_timestamp = alert.get("backend_timestamp")
                        if (
                            len(self.configuration.get("reputation"))
                            and alert.get("process_reputation", "")
                            not in self.configuration["reputation"]
                        ):
                            current_page_skip_count += 1
                            continue

                        if ioc_hash in hash_of_ioc:
                            continue
                        if alert.get("backend_timestamp") == temp_create_time:
                            hash_of_ioc.add(ioc_hash)
                        if tagging and create_tags and alert.get("process_reputation"):
                            skipped_tags = self.create_tags(
                                [alert.get("process_reputation")]
                            )
                            total_skipped_tags.update(skipped_tags)
                        if alert.get("process_sha256"):
                            current_extracted_indicators.append(
                                Indicator(
                                    value=alert.get("process_sha256"),
                                    type=IndicatorType.SHA256,
                                    firstSeen=self._str_to_datetime(
                                        alert.get("first_event_timestamp")
                                    ),
                                    lastSeen=self._str_to_datetime(
                                        alert.get("last_event_timestamp")
                                    ),
                                    severity=CARBONBLACK_TO_INTERNAL_TYPE.get(
                                        alert.get("severity", 0)
                                    ),
                                    tags=(
                                        [alert.get("process_reputation")]
                                        if tagging
                                        else []
                                    ),
                                    comments=alert.get("process_name", ""),
                                )
                            )
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
                                " creating indicator. This record will be"
                                f" skipped. Error: {error}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                total_indicators += len(current_extracted_indicators)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(current_extracted_indicators)} indicator(s) and skipped"
                    f" {current_page_skip_count} indicator(s) in page {page_count}."
                    f" Total indicator(s) fetched - {total_indicators}."
                )

                if total_skipped_tags:
                    self.logger.info(
                        (
                            f"{self.log_prefix}: Skipped following tags(s) in"
                            f" page {page_count} because they might be longer"
                            " than expected size or due to some other "
                            "exceptions that occurred while creating "
                            f"them: ({', '.join(total_skipped_tags)})."
                        )
                    )
                if body["start"] == 8001:
                    last_num_found = int(response.get("num_found", 0))
                if body["start"] == 1 and last_num_found == int(
                    response.get("num_found", 0)
                ):
                    if len(response["results"]):
                        body["time_range"][
                            "start"
                        ] = f"{(datetime.strptime(temp_create_time, DATE_FORMAT_FOR_IOCS) + timedelta(milliseconds=1)).isoformat()}Z"
                    else:
                        is_next_page = False
                elif body["start"] + body["rows"] >= int(
                    response.get("num_available", 0)
                ):
                    if int(response.get("num_found", 0)) == int(
                        response.get("num_available", 0)
                    ):
                        is_next_page = False
                    else:
                        body["time_range"]["start"] = temp_create_time
                        body["start"] = 1
                else:
                    body["start"] += body["rows"]

                if hasattr(self, "sub_checkpoint"):
                    yield current_extracted_indicators, {
                        "checkpoint": last_indicator_timestamp
                    }
                else:
                    yield current_extracted_indicators

            except (CarbonBlackPluginException, Exception) as ex:
                err_msg = (
                    f"{self.log_prefix}: Error occurred while pulling the indicators"
                    f". Error: {ex}."
                )
                self.logger.error(
                    message=err_msg, details=(str(traceback.format_exc()))
                )
                raise CarbonBlackPluginException(err_msg)

    def _get_headers(self, configuration: dict = None) -> dict:
        """Get common headers."""
        return self.carbon_black_helper._add_user_agent(
            {
                "X-Auth-Token": f"{configuration['api_secret']}/{configuration['api_id'].strip()}",
                "Content-Type": "application/json",
            }
        )

    def is_valid_ipv4(self, address: str) -> bool:
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

    def is_valid_ipv6(self, address: str) -> bool:
        """Validate IPv6 address.

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

    def is_valid_dns(self, dns: str) -> bool:
        """
        Check if a given DNS string is valid.

        Args:
            dns (str): The DNS string to be validated.

        Returns:
            bool: True if the DNS string is valid, False otherwise.
        """
        try:
            pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
            return re.match(pattern, dns) is not None
        except Exception:
            return False

    def _update_feed_description(self, feed, action_dict: Dict):
        """Update the feed description."""
        feed["summary"] = action_dict.get("feed_description")
        org_key = self.configuration["org_key"].strip()
        feed_url = FEEDS_API_ENDPOINT.format(
            self.configuration["management_url"].strip().rstrip("/"), org_key
        )
        headers = self._get_headers(self.configuration)
        response = self.carbon_black_helper.api_helper(
            "updating feed description",
            f"{feed_url}/{feed['id']}/feedinfo",
            "PUT",
            data=json.dumps(feed),
            headers=headers,
        )
        if not response:
            raise CarbonBlackPluginException("Failed to update feed description")
        return response

    def _get_feed_id(self, name: str, action_dict: Dict):
        """Get feed ID from feed name."""
        headers = self._get_headers(self.configuration)
        org_key = self.configuration["org_key"].strip()
        feed_url = FEEDS_API_ENDPOINT.format(
            self.configuration["management_url"].strip().rstrip("/"), org_key
        )

        response = self.carbon_black_helper.api_helper(
            "getting feed details",
            feed_url,
            "GET",
            params={"include_public": True},
            headers=headers,
        )

        if not response.get("results"):
            return None
        for feed in response.get("results", []):
            if feed["name"] == name:
                if feed["summary"] != action_dict.get("feed_description"):
                    self._update_feed_description(feed, action_dict)
                return feed.get("id", "")
        # feed does not exist; create one
        res_json = self.carbon_black_helper.api_helper(
            "creating feed",
            feed_url,
            "POST",
            data=json.dumps(
                {
                    "feedinfo": {
                        "name": name,
                        "owner": org_key,
                        "provider_url": "",
                        "summary": action_dict.get("feed_description"),
                        "category": "development",
                    },
                    "reports": [],
                }
            ),
            headers=headers,
        )

        if not res_json.get("id"):
            # feed does not exist; failed to create one.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not find or create a feed with name"
                    f" '{name}'. HTTP status code {res_json.status_code}."
                ),
                details=str(res_json),
            )
        return res_json.get("id")

    def push(self, indicators, action_dict: Dict):
        """Push indicators to Carbon Black."""
        action_dict = action_dict.get("parameters", {})
        action_label = action_dict.get("feed_name")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for '{action_label}' Feed."
        )
        HOST_NAME = self.configuration["management_url"].strip().rstrip("/")

        feed_id = self._get_feed_id(action_label, action_dict)
        if not feed_id:
            return PushResult(
                success=False,
                message=f"Could not create feed '{action_label}'.",
            )
        ioc_md5, ioc_sha256 = set(), set()
        ioc_ipv4, ioc_ipv6, ioc_dns = set(), set(), set()
        reports = []
        # build the body
        skipped_count = 0
        for indicator in indicators:
            if indicator.type == IndicatorType.MD5:
                ioc_md5.add(indicator.value)
            elif indicator.type == IndicatorType.SHA256:
                ioc_sha256.add(indicator.value)
            elif indicator.type == IndicatorType.URL:
                if self.is_valid_ipv6(indicator.value):
                    ioc_ipv6.add(indicator.value)
                elif self.is_valid_ipv4(indicator.value):
                    ioc_ipv4.add(indicator.value)
                elif self.is_valid_dns(indicator.value):
                    ioc_dns.add(indicator.value)
                else:
                    skipped_count += 1

        report = {
            "title": "Netskope CTE Threat Report",
            "description": "",
            "severity": 10,
            "timestamp": int(datetime.now().timestamp()),
            "iocs_v2": [],
        }

        total_md5 = len(list(ioc_md5))
        total_sha256 = len(list(ioc_sha256))
        total_ipv4 = len(list(ioc_ipv4))
        total_ipv6 = len(list(ioc_ipv6))
        total_dns = len(list(ioc_dns))
        ioc_count = total_md5 + total_sha256 + total_ipv4 + total_ipv6 + total_dns
        if (
            total_md5 == 0
            and total_sha256 == 0
            and total_ipv4 == 0
            and total_ipv6 == 0
            and total_dns == 0
        ):
            msg = "No indicators to shared. Carbon Black supports sharing only MD5, SHA256, IPv4, IPv6 and DNS indicators."
            self.logger.info(f"{self.log_prefix}: {msg}")
            return PushResult(
                success=True,
                message=msg,
            )
        if total_md5 > 0:
            md5_val = list(ioc_md5)[0]
            report["iocs_v2"].append(
                {
                    "match_type": "equality",
                    "field": "process_md5",
                    "values": list(ioc_md5),
                    "id": str(hash(md5_val)),
                }
            )
        if total_sha256 > 0:
            sha256_val = list(ioc_sha256)[0]
            report["iocs_v2"].append(
                {
                    "match_type": "equality",
                    "field": "process_sha256",
                    "values": list(ioc_sha256),
                    "id": str(hash(sha256_val)),
                }
            )
        if total_ipv4 > 0:
            ipv4_val = list(ioc_ipv4)[0]
            report["iocs_v2"].append(
                {
                    "match_type": "equality",
                    "field": "ipv4",
                    "values": list(ioc_ipv4),
                    "id": str(hash(ipv4_val)),
                }
            )
        if total_ipv6 > 0:
            ipv6_val = list(ioc_ipv6)[0]
            report["iocs_v2"].append(
                {
                    "match_type": "equality",
                    "field": "ipv6",
                    "values": list(ioc_ipv6),
                    "id": str(hash(ipv6_val)),
                }
            )
        if total_dns > 0:
            ioc_dns_val = list(ioc_dns)[0]
            report["iocs_v2"].append(
                {
                    "match_type": "equality",
                    "field": "dns",
                    "values": list(ioc_dns),
                    "id": str(hash(ioc_dns_val)),
                }
            )
        reports.append(report)
        report["id"] = str(hash(json.dumps(reports)))
        url = FEEDS_API_ENDPOINT.format(
            HOST_NAME, self.configuration["org_key"].strip()
        )
        try:
            response = self.carbon_black_helper.api_helper(
                logger_msg=f"pushing indicators to {PLUGIN_NAME}",
                url=f"{url}/{feed_id}/reports",
                method="POST",
                data=json.dumps({"reports": reports}),
                headers=self._get_headers(self.configuration),
            )
            if not response:
                raise CarbonBlackPluginException(
                    "Failed to push indicators to Carbon Black"
                )
            self.logger.debug(
                f"{self.log_prefix}: Pushed all the indicators successfully."
            )
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} indicator(s) as "
                    "they might have invalid md5, sha256, domain, ipv4 or ipv6 value in it."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully shared {ioc_count} unique "
                f"indicator(s). Total {total_sha256} SHA256, {total_md5} MD5, "
                f"{len(ioc_dns)} Domain, {len(ioc_ipv4)} IPv4 and "
                f"{len(ioc_ipv6)} IPv6 values shared."
            )
            return PushResult(
                success=True, message="Pushed all the indicators successfully."
            )
        except CarbonBlackPluginException as ex:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while pushing indicators. Error: {ex}"
            )
            return PushResult(
                success=False,
                message=f"Could not push indicators to {PLATFORM_NAME}. Error: {ex}",
            )
        except Exception as ex:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while pushing indicators. Error: {ex}"
            )
            return PushResult(
                success=False,
                message=f"Could not push indicators to {PLATFORM_NAME}. Error: {ex}",
            )

    def validate(self, configuration):
        """Validate the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and validation result message.
        """

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        url = configuration.get("management_url", "").strip().rstrip("/")
        if not url:
            err_msg = "Management URL is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(url, str) or not self._validate_url(url):
            err_msg = "Invalid Management URL provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        api_id = configuration.get("api_id", "").strip()
        if not api_id:
            err_msg = "API ID is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(api_id, str):
            err_msg = "Invalid API ID provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        api_secret = configuration.get("api_secret", "")
        if not api_secret:
            err_msg = "API Secret is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(api_secret, str):
            err_msg = "Invalid API Secret provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        org_key = configuration.get("org_key", "").strip()
        if not org_key:
            err_msg = "Organization Key is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(org_key, str):
            err_msg = "Invalid Organization Key provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        reputation = configuration.get("reputation")
        if reputation and not (
            all(reputation in REPUTATION for reputation in reputation)
        ):
            err_msg = f"Invalid value for 'Reputation' provided. Allowed values are {', '.join(REPUTATION)}."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        enable_tagging = configuration.get("enable_tagging")
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif enable_tagging and enable_tagging not in ["yes", "no"]:
            err_msg = "Invalid value for 'Enable Tagging' provided. Allowed values are 'Yes' or 'No'."
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
        elif is_pull_required and is_pull_required not in ["Yes", "No"]:
            err_msg = "Invalid value for 'Enable Polling' provided. Allowed values are 'Yes' or 'No'."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        minimum_severity = configuration.get("minimum_severity")
        if minimum_severity is None:
            err_msg = "Minimum Severity is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(minimum_severity, int):
            err_msg = (
                "Invalid value provided in Minimum Severity configuration "
                "parameter. Minimum Severity should be positive integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not (1 <= minimum_severity <= 10):
            err_msg = "Minimum Severity should be non-zero positive integer value in range of 1 to 10 "
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(days, int) or days < 0:
            err_msg = "Invalid Initial Range provided in configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to feed", value="feed"),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        if action.value not in ["feed"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.parameters.get("feed_name") is None:
            return ValidationResult(
                success=False, message="Feed Name should not be empty."
            )

        if action.parameters.get("feed_description") is None:
            return ValidationResult(
                success=False, message="Feed Description should not be empty."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "feed":
            return [
                {
                    "label": "Feed Name",
                    "key": "feed_name",
                    "type": "text",
                    "default": "CTE Threat Feed",
                    "mandatory": True,
                    "description": "Name of Carbon Black feed where indicator should be pushed.",
                },
                {
                    "label": "Feed Description",
                    "key": "feed_description",
                    "type": "text",
                    "default": "Created from Netskope CTE",
                    "mandatory": True,
                    "description": "Description of Carbon Black feed.",
                },
            ]
