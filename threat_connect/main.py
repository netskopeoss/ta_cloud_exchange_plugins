"""
BSD 3-Clause License.

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

ThreatConnect Plugin implementation to pull the data from
ThreatConnect Platform.
"""

import base64
import datetime
import hashlib
import hmac
import json
import re
import time
import traceback
from ipaddress import IPv4Address, ip_address
from typing import Dict, List, Tuple, Union
from urllib.parse import quote, urlparse

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.models.business_rule import Action, ActionWithoutParams
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils

from .utils.constants import (
    DEFAULT_CONFIDENCE,
    INDICATOR_TYPES,
    INTEGER_THRESHOLD,
    LIMIT,
    MODULE_NAME,
    PAGE_LIMIT,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PUSH_INDICATOR_FAILURE,
    RATING_TO_SEVERITY,
    SEVERITY_TO_RATING,
    TAG_NAME,
    THREAT_CONNECT_URLS,
    BIFURCATE_INDICATOR_TYPES
)
from .utils.helper import ThreatConnectException, ThreatConnectPluginHelper


class ThreatConnectPlugin(PluginBase):
    """ThreatConnect plugin implementation class.

    ThreatConnect class inherits PluginBase class from Cloud Threat Exchange
    Integrations.
    """

    def __init__(self, name: str, *args, **kwargs):
        """initializes the ThreatConnectPlugin class.
        Args:
            - name (str): Plugin Configuration Name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self._api_helper = ThreatConnectPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ThreatConnectPlugin.metadata
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

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.
        Args:
            configuration (Dict): Configuration Dictionary.
        Returns:
            Tuple: Tuple containing Base URL, Access ID, Secret Key.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("access_id", "").strip(),
            configuration.get("secret_key", ""),
        )

    def check_url_domain_ip(self, ioc_value):
        """Categorize URL as Domain, IP or URL.
        This method is used for mapping the Netskope supported indicator type
        with ThreatConnect supported indicator type.
        """
        regex_domain = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
        try:
            ip_address(ioc_value)
            return "Address"
        except Exception:
            if re.search(regex_domain, ioc_value):
                return "Host"
            else:
                return "URL"

    def _get_headers_for_auth(
        self, api_path: str, access_id: str, secret_key: str, request_type: str
    ) -> Dict:
        """Return header for authentication.

        Args:
            - api_path (str): API path.
            - access_id (str): Access ID.
            - secret_key (str): Secret key.
            - request_type (str): Request type.

        Returns:
            - dict: Header for authentication.
        """
        unix_epoch_time = int(time.time())
        api_path = f"{api_path}:{request_type}:{unix_epoch_time}"
        bytes_api_path = bytes(api_path, "utf-8")
        bytes_secret_key = bytes(secret_key, "utf-8")

        # HMAC-SHA256
        dig = hmac.new(
            bytes_secret_key, msg=bytes_api_path, digestmod=hashlib.sha256
        ).digest()

        # BASE64 ENCODE
        hmac_sha256 = base64.b64encode(dig).decode()
        signature = f"TC {access_id}:{hmac_sha256}"
        header = {
            "Authorization": str(signature),
            "Timestamp": str(unix_epoch_time),
        }
        return header

    def get_reputation(self, confidence: int = DEFAULT_CONFIDENCE) -> int:
        """Get reputation value based on confidence score.

        Args:
            - confidence (int): An integer between 0 and 100
            representing ThreatConnect confidence.

        Returns:
            - int: Reputation score ( >= 1 and <= 10).
        """
        if confidence > 10:
            return round(confidence / 10)
        else:
            return 1

    def get_api_url(self, api_path, threat_type):
        """Get API url.

        Args:
            api_path (str): API endpoint.
            threat_type (str): Type of data to pull.

        Returns:
            str: return API url endpoint.
        """
        result_start = 0
        if self.last_run_at:
            last_run_time = self.last_run_at
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            last_run_time = datetime.datetime.now() - datetime.timedelta(
                days=self.configuration.get("days")
            )
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = f"typeName IN {tuple(threat_type)}"
        query += f" AND lastModified >= '{last_run_time}'"

        filtered_string = "tql=" + quote(query)
        api_url = f"{api_path}?sorting=lastModified%20asc&fields=tags&{filtered_string}"
        api_url += f"&resultStart={result_start}&resultLimit={LIMIT}"
        return api_url

    def _create_tags(self, tags: List[dict]) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""
        utils = TagUtils()
        tag_names, skipped_tags_val_err, skipped_tags = [], [], []
        for tag in tags:
            try:
                if tag is not None and not utils.exists(tag.strip()):
                    utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))
            except ValueError:
                skipped_tags_val_err.append(tag)
            except Exception:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags_val_err, skipped_tags

    def _is_valid_credentials(
        self, base_url: str, access_id: str, secret_key: str
    ) -> Tuple[bool, str]:
        """Validate credentials.

        Args:
            - access_id (str): Access ID for ThreatConnect.
            - secret_key (str): Secret Key for ThreatConnect.

        Returns:
            - bool: True for valid credentials and false for not valid.
            - str: success/failure message for validating credentials.
        """
        try:
            api_path = THREAT_CONNECT_URLS["owners"]
            query_endpoint = base_url + api_path

            # Get Headers.
            headers = self._get_headers_for_auth(api_path, access_id, secret_key, "GET")

            # Logger message
            logger_msg = (
                f"Validating {PLUGIN_NAME} Access ID and Secret Key "
                "configuration parameters."
            )
            response = self._api_helper.api_helper(
                logger_msg=logger_msg,
                url=query_endpoint,
                method="GET",
                headers=headers,
                is_handle_error_required=False,
                is_validation=True,
            )
            resp_json = self._api_helper.parse_response(response)
            if response.status_code == 200:
                msg = f"Successfully validated configuration for {PLUGIN_NAME} plugin."
                return True, msg
            elif response.status_code == 401:
                err_msg = (
                    "Received exit code 401, Unauthorized access."
                    f"Verify {PLUGIN_NAME} Access ID, Secret Key or Base URL "
                    "provided in the configuration parameters."
                )
                return False, msg
            else:
                err_msg = (
                    f"Received exit code {str(response.status_code)}, "
                    "Please check logs for more details."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{PLUGIN_NAME} API Response: {str(resp_json)}",
                )
                return False, err_msg
        except ThreatConnectException as tc_err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while validating "
                    f"configuration parameters. Error: {str(tc_err)}"
                ),
                details=f"Traceback: {str(traceback.format_exc())}",
            )
            return False, str(tc_err)
        except Exception as exp:
            err_msg = "Unexpected error occurred. Please check logs for more details."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return False, "Unexpected validation error occurred."

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            - url (str): Given URL.

        Returns:
            - bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            - configuration (Dict): Configuration from manifest.json,

        Returns:
            - ValidationResult: Valid configuration fields or not.
        """
        (base_url, access_id, secret_key) = self._get_credentials(configuration)
        threat_types = configuration.get("threat_type", [])
        enable_tagging = configuration.get("enable_tagging")
        is_pull_required = configuration.get("is_pull_required")
        initial_range = configuration.get("days")

        validation_err_msg = "Validation error occurred."

        # Base URL
        if not bool(base_url):
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif (
            not isinstance(base_url, str)
            or not self._validate_url(base_url)
            or "threatconnect" not in base_url
        ):
            err_msg = "Invalid Base URL provided in the configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Access ID
        if not bool(access_id):
            err_msg = "Access ID is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(access_id, str):
            err_msg = "Invalid Access ID Provided in the configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Secret Key
        if not bool(secret_key):
            err_msg = "Secret Key is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(secret_key, str):
            err_msg = "Invalid Secret Key is Provided in the configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Type of Threat Indicator(s) to pull
        if not bool(threat_types):
            err_msg = "Type of Threat Indicator is required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(threat_types, list):
            err_msg = "Invalid value provided for Type of Threat Indicator."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not set(threat_types).issubset(INDICATOR_TYPES):
            available_types = ", ".join(INDICATOR_TYPES)
            err_msg = (
                "Invalid value provided for Type of Threat Indicator. "
                f"Available Values are: {available_types}"
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Enable Tagging
        if not bool(enable_tagging):
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif enable_tagging not in {"Yes", "No"}:
            err_msg = (
                "Invalid value provided for Enable Tagging configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Enable Polling
        if not bool(is_pull_required):
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif is_pull_required not in {"Yes", "No"}:
            err_msg = (
                "Invalid value provided for Enable Polling configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Initial Range
        if not bool(initial_range):
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid Initial Range provided in the "
                "configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif initial_range < 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        success, message = self._is_valid_credentials(
            base_url, access_id, secret_key
        )
        return ValidationResult(success=success, message=message)

    def _create_configuration_digest(self, configuration) -> str:
        """Create a MD5 Digest of configurations.

        Args:
            - configuration (Dict): A dictionary containing configuration parameters.

        Returns:
            - A string representation of MD5 hexdigest of configuration.
        """
        base_url, access_id, secret_key = self._get_credentials(configuration)
        threat_types = configuration.get("threat_type", [])

        config = {
            "base_url": base_url,
            "access_id": access_id,
            "secret_key": secret_key,
            "threat_types": threat_types,
        }
        return hashlib.md5(
            json.dumps(config, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _get_indicator_types(self, threat_types: List) -> Dict:
        """Returns a mapping of Indicator Types.
        Based on the threats types to pull config param.
        And, Netskope CE version.

        Args:
            - threat_types: A List of indicator types to pull.
        Returns:
            - Dictionary mapping of Indicator Types.
        """
        indicator_types = {}

        if "File" in threat_types:
            indicator_types["md5"] = IndicatorType.MD5
            indicator_types["sha256"] = IndicatorType.SHA256

        if "URL" in threat_types:
            indicator_types["url"] = IndicatorType.URL

        if "Host" in threat_types:
            indicator_types["hostname"] = getattr(
                IndicatorType, "HOSTNAME", IndicatorType.URL
            )

        if "Address" in threat_types:
            indicator_types["ipv4"] = getattr(IndicatorType, "IPV4", IndicatorType.URL)
            indicator_types["ipv6"] = getattr(IndicatorType, "IPV6", IndicatorType.URL)

        return indicator_types

    def _is_config_modified(self) -> bool:
        """This method is used to determine wether configuration
        is modified or not.

        Returns:
            - Returns bool flag. True or False
        """
        # Create current configuration digest
        current_config_digest = self._create_configuration_digest(self.configuration)

        # Fetch previous configuration digest from storage
        config_digest = self.storage.get("config_digest")
        if not config_digest and "configuration_details" in self.storage:
            # if previous config digest not present in storage
            # then create a new one.
            config_digest = self._create_configuration_digest(
                self.storage["configuration_details"]
            )
            self.storage["config_digest"] = config_digest
            del self.storage["configuration_details"]

        is_config_modified = bool(current_config_digest == config_digest)
        if is_config_modified:
            # if config is modified, set new config digest in storage.
            self.storage["config_digest"] = current_config_digest

        return is_config_modified

    def pull(self) -> Union[List[Indicator], Dict]:
        """Pull Indicators data from ThreatConnect API.

        Returns:
            - List[Indicator]: Returns List of Indicator model.
            - Dict: A dictionary containing details of checkpoint.
        """
        is_pull_required = self.configuration.get("is_pull_required")

        if is_pull_required == "Yes":
            is_config_modified = self._is_config_modified()

            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self._pull(is_config_modified)

                return wrapper(self)
            else:
                indicators = []
                for batch in self._pull(is_config_modified):
                    indicators.extend(batch)
                return indicators
        else:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Polling is disabled, "
                    "Indicator(s) will not be fetched."
                )
            )
            return []

    def make_indicators(
        self,
        ioc_data: List[Dict],
        indicator_types: Dict,
        enable_tagging: bool,
    ):
        """Add received data to Netskope.

        Args:
            - ioc_data (List[Dict]): List of Dictionary containing ioc details.
            - indicator_types: A mapping of Indicator Types supported by netskope CE.
            - enable_tagging (Bool): A boolean flag for enable/disable tagging.

        Returns:
            - indicators (List[Indicator]): List of Indicator model objects.
            - total_ioc (int): Total number of IoCs pulled.
            - skipped_ioc (int): Total number of IoCs skipped while creating them.
        """
        ioc_counts = {ioc_type: 0 for ioc_type in indicator_types}
        skipped_ioc_counts = {ioc_type: 0 for ioc_type in indicator_types}
        skipped_ioc = 0
        skipped_tags = []
        skipped_tags_due_to_val_err = []
        indicators = []

        for indicator in ioc_data:
            try:
                indicator_attr = {
                    "active": indicator.get("active", True),
                    "severity": RATING_TO_SEVERITY[indicator.get("rating", 0)],
                    "reputation": self.get_reputation(
                        indicator.get("confidence", DEFAULT_CONFIDENCE)
                    ),
                    "comments": indicator.get("description", ""),
                    "firstSeen": indicator.get("dateAdded"),
                    "lastSeen": indicator.get("lastModified"),
                }

                created_tags = []
                tags_data = indicator.get("tags", {}).get("data", [])
                tags = [tag.get("name") for tag in tags_data if "name" in tag]
                if TAG_NAME in tags:
                    # if indicator has Netskope CE tag then skip it.
                    # As, the indicator was created by Netskope CE.
                    skipped_ioc += 1
                    continue

                if enable_tagging:
                    created, val_err, skipped = self._create_tags(tags)
                    skipped_tags.extend(skipped)

                indicator_type = indicator["type"]
                # MD4 & SHA256
                if indicator_type == "File":

                    if "md5" in indicator:
                        try:
                            created, val_err, skipped = self._create_tags(
                                ["ThreatConnect-File-MD5"]
                            )
                            created_tags.extend(created)
                            skipped_tags.extend(skipped)
                            skipped_tags_due_to_val_err.extend(val_err)

                            indicators.append(
                                Indicator(**{
                                    "value": indicator["md5"],
                                    "type": indicator_types["md5"],
                                    "tags": created_tags,
                                    **indicator_attr
                                })
                            )
                            ioc_counts["md5"] += 1
                        except Exception:
                            skipped_ioc_counts["md5"] += 1

                    if "sha256" in indicator:
                        try:
                            created, val_err, skipped = self._create_tags(
                                ["ThreatConnect-File-SHA256"]
                            )
                            created_tags.extend(created)
                            skipped_tags.extend(skipped)
                            skipped_tags_due_to_val_err.extend(val_err)

                            indicators.append(
                                Indicator(**{
                                    "value": indicator["sha256"],
                                    "type": indicator_types["sha256"],
                                    "tags": created_tags,
                                    **indicator_attr,
                                })
                            )
                            ioc_counts["sha256"] += 1
                        except Exception:
                            skipped_ioc_counts["sha256"] += 1

                # IP Addresses (IPV4 & IPv6)
                elif indicator_type == "Address":
                    try:
                        if isinstance(
                            ip_address(indicator["ip"]), IPv4Address
                        ):
                            tag_name = "ThreatConnect-Address-IPV4"
                            ioc_type = "ipv4"
                        else:
                            tag_name = "ThreatConnect-Address-IPV6"
                            ioc_type = "ipv6"

                        created, val_err, skipped = self._create_tags(
                            [tag_name]
                        )
                        created_tags.extend(created)
                        skipped_tags.extend(skipped)
                        skipped_tags_due_to_val_err.extend(val_err)

                        indicators.append(
                            Indicator(
                                **{
                                    "value": indicator["ip"],
                                    "type": indicator_types[ioc_type],
                                    "tags": created_tags,
                                    **indicator_attr,
                                }
                            )
                        )
                        ioc_counts[ioc_type] += 1
                    except Exception:
                        skipped_ioc_counts[ioc_type] += 1

                # Domain
                elif indicator_type == "Host":
                    try:
                        created, val_err, skipped = self._create_tags(
                            ["ThreatConnect-Host"]
                        )
                        created_tags.extend(created)
                        skipped_tags.extend(skipped)
                        skipped_tags_due_to_val_err.extend(val_err)

                        indicators.append(
                            Indicator(**{
                                "value": indicator["hostName"],
                                "type": indicator_types["hostname"],
                                "tags": created_tags,
                                **indicator_attr,
                            })
                        )
                        ioc_counts["hostname"] += 1
                    except Exception:
                        skipped_ioc_counts["hostname"] += 1

                # URL
                elif indicator_type == "URL":
                    created, val_err, skipped = self._create_tags(
                        ["ThreatConnect-URL"]
                    )
                    created_tags.extend(created)
                    skipped_tags.extend(skipped)
                    skipped_tags_due_to_val_err.extend(val_err)

                    for url in indicator["text"].split(","):
                        try:
                            indicators.append(
                                Indicator(
                                    **{
                                        "value": url,
                                        "type": indicator_types["url"],
                                        "tags": created_tags,
                                        **indicator_attr,
                                    }
                                )
                            )
                            ioc_counts["url"] += 1
                        except Exception:
                            skipped_ioc_counts["url"] += 1

                # Other types of Indicators supported by ThreatConnect
                else:
                    self.logger.warning(
                        message=(
                            f"Received unknown ioc type: {indicator_type}, "
                            "Hence discarding this indicator having Id: "
                            f"{indicator['id']}"
                        ),
                        details=f"Indicator Details: {json.dumps(indicator)}",
                    )
                    skipped_ioc += 1
            except Exception as exp:
                err_msg = (
                    "Error occurred while creating the indicator having "
                    f"Id {indicator.get('id')} hence this record "
                    "will be skipped."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                skipped_ioc += 1
                continue

        if len(skipped_tags_due_to_val_err) > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {len(skipped_tags_due_to_val_err)} "
                    "tag(s) skipped as they were longer than expected size: "
                    f"({', '.join(set(skipped_tags_due_to_val_err))})"
                )
            )

        if len(set(skipped_tags)) > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {len(skipped_tags)} tag(s) skipped "
                    "as some failure occurred while creating these tags."
                ),
                details=f"Skipped Tags: ({', '.join(set(skipped_tags))})",
            )

        pull_stats = ", ".join(
            [f"{key.upper()} = {str(val)}" for key, val in ioc_counts.items()]
        )
        skipped_pull_stats = ", ".join(
            [
                f"{key.upper()} = {str(val)}"
                for key, val in skipped_ioc_counts.items()
            ]
        )
        self.logger.debug(
            f"{self.log_prefix}: Pull Stats: {pull_stats}. Skipped IOCs "
            f"as they were previously shared by Netskope CE: {skipped_ioc} "
            "Skipped IOC(s) as some error occurred while creating these "
            f"IOC(s): {skipped_pull_stats}"
        )

        total_ioc = sum(ioc_counts.values())
        total_skipped_ioc = sum(skipped_ioc_counts.values()) + skipped_ioc
        total_skipped_tags = len(skipped_tags) + len(skipped_tags_due_to_val_err)
        return indicators, total_ioc, total_skipped_ioc, total_skipped_tags

    def _pull(
        self, is_config_modified: bool
    ) -> Union[List[Indicator], Dict]:
        """Fetch Data from ThreatConnect API.

        Args:
            - is_config_modified (bool): Boolean flag indicates that
            configuration is modified or not.

        Returns:
            - List[Indicator]: List of Indicator model.
            - Dict: A dictionary containing details of checkpoint.
        """
        # initialize local variables.
        indicators = []
        page = 1
        next_page = True
        total_created_ioc = 0
        total_skipped_ioc = 0
        total_skipped_tag = 0
        api_path = THREAT_CONNECT_URLS["indicators"]

        # Set enable_tagging flag.
        if self.configuration.get("enable_tagging") == "Yes":
            enable_tagging = True
        else:
            enable_tagging = False

        (
            base_url, access_id, secret_key
        ) = self._get_credentials(self.configuration)

        threat_types = self.configuration.get("threat_type", [])
        indicator_types = self._get_indicator_types(threat_types)

        # Get Indicator API Endpoint form storage. if not present in storage
        # or configuration modified then prepare a fresh api url end point.
        api_url = ""
        query_endpoint = ""
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint:
            api_url = sub_checkpoint.get("next_uri")
        elif self.storage and "next_uri" in self.storage:
            api_url = self.storage.get("next_uri")

        if is_config_modified or not api_url:
            api_url = self.get_api_url(api_path, threat_types)

        while next_page:
            try:
                logger_msg = (
                    f"Pulling indicator(s) from page {page} for "
                    f"{PLUGIN_NAME} plugin."
                )

                # Prepare headers
                headers = self._get_headers_for_auth(
                    api_url, access_id, secret_key, "GET"
                )

                # Update Indicator API Endpoint.
                query_endpoint = base_url + api_url
                ioc_response = self._api_helper.api_helper(
                    logger_msg=logger_msg,
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    is_handle_error_required=True,
                )
                ioc_data = ioc_response.get("data", [])
                if ioc_data:
                    (
                        indicators, created_ioc, skipped_ioc, skipped_tag
                    ) = self.make_indicators(
                        ioc_data, indicator_types, enable_tagging
                    )

                    total_created_ioc += created_ioc
                    total_skipped_ioc += skipped_ioc
                    total_skipped_tag += skipped_tag

                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched {created_ioc}"
                        f" indicator(s) for page {page}. Total indicator(s) "
                        f"fetched {total_created_ioc}."
                    )

                    # Set api_url for next page.
                    next_url = ioc_response.get("next", "")
                    if next_url:
                        api_url = next_url.replace(base_url.strip("/"), "")
                        self.storage["next_uri"] = api_url

                    if len(ioc_data) < LIMIT:
                        # Last page of the pull cycle.
                        next_page = False
                        if self.storage and 'next_uri' in self.storage:
                            del self.storage["next_uri"]
                else:
                    # case: status -> Success, return -> []
                    next_page = False

                # Circuit Breaker.
                page += 1
                if page >= PAGE_LIMIT:
                    self.storage["next_uri"] = api_url
                    next_page = False
                    self.logger.info(
                        message=(
                            f"{self.log_prefix}: Page limit of {PAGE_LIMIT} "
                            f"has reached. Returning {len(indicators)}"
                            "indicator(s). The pulling of the indicators will"
                            "be resumed in the next pull cycle."
                        )
                    )

                if not next_page:
                    message = (
                        f"{self.log_prefix}: Completed fetching indicators "
                        f"for the {PLUGIN_NAME} plugin. Total fetched "
                        f"{total_created_ioc} indicator(s), Total skipped "
                        f"{total_skipped_ioc} indicator(s), Total skipped "
                        f"{total_skipped_tag} Tag(s)."
                    )
                    self.logger.info(message)

                if hasattr(self, "sub_checkpoint"):
                    yield indicators, {"next_uri": self.storage.get("next_uri")}
                else:
                    yield indicators
            except ThreatConnectException as tc_err:
                self.storage["next_uri"] = api_url
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error Occurred while pulling "
                        f"indicator(s) from {PLUGIN_NAME} using next_uri "
                        f"{self.storage['next_uri']}. Error: {str(tc_err)}"
                    ),
                    details=traceback.format_exc(),
                )

                if not hasattr(self, "sub_checkpoint"):
                    yield indicators
            except Exception as exp:
                self.storage["next_uri"] = api_url
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing the "
                    "pull cycle. The pulling of the indicators will be "
                    f"resumed in the next pull cycle. Error: {exp}."
                )
                self.logger.error(
                    message=err_msg,
                    details=traceback.format_exc()
                )

                if not hasattr(self, "sub_checkpoint"):
                    yield indicators
            else:
                api_url = self.storage.get("next_uri")

    def get_group_id(self, action_dict):
        """Return group id based on condition.

        Args:
            action_dict (Dict): Action dictionary.

        Returns:
            str: Return group id.
        """
        group_names = self.get_group_names()
        (base_url, access_id, secret_key) = self._get_credentials(self.configuration)

        action_params = action_dict.get("parameters", {})
        if action_params.get("group_name", "") != "create_group":
            if action_params.get("group_name", "") not in group_names.values():
                err_msg = (
                    "The group selected in the sharing configuration "
                    f"no longer exists on {PLUGIN_NAME}, sharing will be skipped."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise ThreatConnectException(err_msg)
            return action_params["group_name"]

        # Creating New Group
        api_path = THREAT_CONNECT_URLS["groups"]
        create_group_api = base_url + api_path
        headers = self._get_headers_for_auth(api_path, access_id, secret_key, "POST")
        if action_params.get("new_group_name", "").strip() not in group_names:
            data = {
                "name": action_params.get("new_group_name", "").strip(),
                "type": action_params.get("new_group_type", "").strip(),
                "tags": {
                    "data": [
                        {"name": TAG_NAME},
                    ]
                },
            }
            try:
                response = self._api_helper.api_helper(
                    logger_msg=(
                        f"Creating groups on {PLUGIN_NAME} platform using."
                    ),
                    url=create_group_api,
                    method="POST",
                    headers=headers,
                    json=data,
                    is_handle_error_required=True,
                )

                status = response.get("status", "")
                if (
                    status == "Success"
                    and "name" in response.get("data", {})
                    and "id" in response.get("data", {})
                ):
                    action_dict["parameters"]["group_name"] = response["data"]["name"]
                    return response["data"]["id"]
                else:
                    err_msg = f"{self.log_prefix}: Error while creating a group."
                    resp_msg = response.get("message", "Error message not available.")
                    self.logger.error(
                        message=err_msg, details=f"Error Message: {resp_msg}"
                    )
            except ThreatConnectException as tc_err:
                err_msg = (
                    f"Error occurred while creating group {data['name']} on "
                    f"{PLUGIN_NAME} platform."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} "
                        f"Exception: {str(tc_err)}"
                    ),
                    details=f"Traceback: {str(traceback.format_exc())}",
                )
                raise ThreatConnectException(err_msg)
            except Exception as exp:
                err_msg = (
                    f"Unexpected Error occurred while creating group "
                    f"{data['name']} on {PLUGIN_NAME} platform."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                    details=str(traceback.format_exc()),
                )
                raise ThreatConnectException(err_msg)
        else:
            return group_names[action_params.get("new_group_name", "")]

    def prepare_payload(self, indicator, existing_group_id):
        """Prepare payload for request.

        Args:
            indicator (Indicator): given indicators.
            existing_group_id (_type_): group id.

        Returns:
            Dict: return dictionary of data.
        """
        data = {}
        is_invalid_ioc = False
        if (
            str(indicator.type.value) in BIFURCATE_INDICATOR_TYPES
            and 1 <= len(indicator.value) <= 500
        ):
            url_subtype = self.check_url_domain_ip(indicator.value)
            if url_subtype == "Address":
                data["ip"] = indicator.value
            elif url_subtype == "Host":
                data["hostName"] = indicator.value
            else:
                data["text"] = indicator.value
            data["type"] = url_subtype
        elif indicator.type == IndicatorType.MD5:
            data["md5"] = indicator.value
            data["type"] = "File"
        elif indicator.type == IndicatorType.SHA256:
            data["sha256"] = indicator.value
            data["type"] = "File"
        else:
            is_invalid_ioc = True

        data["associatedGroups"] = {
            "data": [
                {
                    "id": existing_group_id,
                }
            ]
        }
        data["tags"] = {"data": [{"name": TAG_NAME}]}
        data["rating"] = SEVERITY_TO_RATING[indicator.severity]
        data["confidence"] = indicator.reputation * 10
        return data, is_invalid_ioc

    def update_ioc(self, value, group_id) -> bool:
        """Update IoCs metadata for multiple groups.

        Args:
            value (str): value of IoC
            group_id (str): group id

        Returns:
            Boolean Flag indicates updating indicator operation was
            successful or not.
        """
        api_path = THREAT_CONNECT_URLS["update_indicators"].format(value=value)
        (base_url, access_id, secret_key) = self._get_credentials(self.configuration)
        url = base_url + api_path
        headers = self._get_headers_for_auth(
            api_path,
            access_id,
            secret_key,
            "PUT",
        )
        update_data = {
            "associatedGroups": {
                "data": [
                    {"id": group_id},
                ],
                "mode": "append",
            },
        }
        try:
            logger_msg = (
                f"Updating indicator(s) on {PLUGIN_NAME} platform for "
                f"Indicator Value: {value} and Group Id: {group_id}"
            )
            response = self._api_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="PUT",
                headers=headers,
                json=update_data,
                is_handle_error_required=True,
            )
            status = response.get("status", "")
            return True if status == "Success" else False
        except ThreatConnectException as tc_err:
            err_msg = (
                f"Error occurred while updating indicator. "
                f"Indicator Value: {value}, Error: {str(tc_err)}"
            )
            self.logger.error(
                message=err_msg, details=f"Traceback: {traceback.format_exc()}"
            )
            return False
        except Exception as exp:
            err_msg = "Unexpected error occurred while updating indicator."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return False

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push Indicators to ThreatConnect Platform.

        Args:
            indicators (List[Indicator]): List of Indicators to push.
            action_dict (Dict): action dictionary for performing actions.

        Returns:
            PushResult: return PushResult object with success and message
            parameters.
        """
        try:
            existing_group_id = self.get_group_id(action_dict)
            (base_url, access_id, secret_key) = self._get_credentials(
                self.configuration
            )
            api_path = THREAT_CONNECT_URLS["indicators"]
            query_endpoint = base_url + api_path
            invalid_ioc, indicator_pushed = 0, 0
            already_exists = 0
            self.logger.debug(
                f"{self.log_prefix}: API URL to share the indicators: {query_endpoint}."
            )
            total_ioc_received = 0

            for indicator in indicators:
                total_ioc_received += 1
                if (
                    str(indicator.type.value) in BIFURCATE_INDICATOR_TYPES
                    and len(indicator.value) > 500
                ):
                    invalid_ioc += 1
                    continue
                try:
                    # Try to push indicator.
                    data, is_invalid_ioc = self.prepare_payload(
                        indicator, existing_group_id
                    )
                    if is_invalid_ioc:
                        invalid_ioc += 1
                        continue
                    headers = self._get_headers_for_auth(
                        api_path, access_id, secret_key, "POST"
                    )
                    logger_msg = (
                        f"Pushing indicator on {PLUGIN_NAME} platform "
                        f"having indicator value: {indicator.value}"
                    )
                    response = self._api_helper.api_helper(
                        logger_msg=logger_msg,
                        url=query_endpoint,
                        method="POST",
                        headers=headers,
                        json=data,
                        is_handle_error_required=True,
                    )

                    resp_msg = response.get("message", "")
                    # Push Successful
                    if (
                        response.get("status", "") == "Success"
                        and resp_msg == "Created"
                    ):
                        indicator_pushed += 1
                    # Already exists hence, update indicator
                    elif resp_msg.endswith("already exists"):
                        is_successful = self.update_ioc(
                            indicator.value.upper(),
                            data["associatedGroups"]["data"][0]["id"],
                        )
                        if is_successful:
                            already_exists += 1
                        else:
                            invalid_ioc += 1
                    # Handling Push response error message.
                    elif (
                        resp_msg.startswith("Please enter a valid")
                        or resp_msg == PUSH_INDICATOR_FAILURE
                    ):
                        err_msg = (
                            f"{self.log_prefix}: Failed to push indicator - "
                            f"{indicator.value} to {PLUGIN_NAME}."
                        )
                        self.logger.error(
                            message=err_msg,
                            details=f"Failed to push indicator. Error: {resp_msg}",
                        )
                        invalid_ioc += 1
                    # In case of Unknown response message, mark it as failure.
                    else:
                        err_msg = (
                            f"{self.log_prefix}: Failed to push indicator - "
                            f"{indicator.value} to {PLUGIN_NAME}."
                        )
                        self.logger.error(
                            message=err_msg,
                            details=f"Failed to push indicator. Error: {resp_msg}",
                        )
                        invalid_ioc += 1
                except ThreatConnectException as error_msg:
                    return PushResult(
                        success=False,
                        message=f"{error_msg}",
                    )
                except Exception as err:
                    error_msg = (
                        f"{self.log_prefix}: Error Ocurred while ingesting "
                        f"indicators to {PLUGIN_NAME}. Error: {err}"
                    )
                    self.logger.error(message=error_msg, details=traceback.format_exc())
                    return PushResult(
                        success=False,
                        message=error_msg,
                    )
            # Push stats
            self.logger.info(
                f"{self.log_prefix}: Push Stats: "
                f"indicator(s) received - {total_ioc_received}, "
                f"indicator(s) successfully pushed - {indicator_pushed}, "
                f"indicator(s) already exists(modified) - {already_exists}, "
                f"indicator(s) failed to share: {invalid_ioc}."
            )

            # return PushResult
            return PushResult(
                success=True,
                message=f"Indicators pushed successfully to {PLUGIN_NAME}.",
            )

        except ThreatConnectException as error_msg:
            return PushResult(
                success=False,
                message=f"{error_msg}",
            )
        except Exception as err:
            error_msg = (
                f"{self.log_prefix}: Error Occurred while fetching group IDs. "
                f"Error: {err}"
            )
            self.logger.error(message=error_msg, details=traceback.format_exc())
            return PushResult(
                success=False,
                message=error_msg,
            )

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available Actions.

        Returns:
            List[ActionWithoutParams]: Return list of actions.
        """
        return [ActionWithoutParams(label="Add to Group", value="add_to_group")]

    def get_owner(self):
        """Get owner information from given API credentials.

        Returns:
            str: Name of owner.
        """
        api_path = THREAT_CONNECT_URLS["owners_mine"]
        (base_url, access_id, secret_key) = self._get_credentials(self.configuration)
        headers = self._get_headers_for_auth(api_path, access_id, secret_key, "GET")
        endpoint = base_url + api_path
        # Fetching owner_name
        try:
            logger_msg = "Fetching Owners information using given API Credentials."
            response = self._api_helper.api_helper(
                logger_msg=logger_msg,
                url=endpoint,
                method="GET",
                headers=headers,
                is_handle_error_required=True,
            )
            status = response.get("status", "")
            name = response.get("data", {}).get("owner", {}).get("name")
            if status == "Success" and bool(name):
                return name

            # Not able to fetch Owner.
            err_msg = f"{self.log_prefix}: Error while fetching owner information."
            self.logger.error(
                message=err_msg,
                details=f"Error: {response.get('message', 'Error message not available.')}",
            )
            return None
        except ThreatConnectException:
            return None
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: Error while fetching owner information. "
                f"Error: {err}"
            )
            self.logger.error(message=err_msg, details=traceback.format_exc())
            return None

    def get_group_names(self) -> Dict:
        """Get names of available group along with id.

        Returns:
            Dict: dictionary of group name as key and group id as value.
        """
        group_names = {}
        owner_name = self.get_owner()
        if owner_name:
            query = quote(f"ownerName == '{owner_name}'")
            api_path = f"/api/v3/groups?tql={query}&resultLimit={LIMIT}"

            (base_url, access_id, secret_key) = self._get_credentials(
                self.configuration
            )
            url = base_url + api_path

            next_page = True
            while next_page:
                headers = self._get_headers_for_auth(
                    api_path, access_id, secret_key, "GET"
                )
                # Fetching group Name based on owner name.
                try:
                    logger_msg = "Fetching the group details based on owner."
                    response = self._api_helper.api_helper(
                        logger_msg=logger_msg, url=url, method="GET", headers=headers
                    )
                    if response.get("status", "") == "Success":
                        group_names.update({
                            group.get("name", ""): str(group.get("id", ""))
                            for group in response.get("data", [])
                        })

                        if response.get("next", None):
                            api_path = response.get("next").replace(
                                base_url, ""
                            )
                            url = response.get("next", None)
                        else:
                            next_page = False
                    else:
                        # Not able to fetch Groups.
                        err_msg = (
                            f"{self.log_prefix}: Error while fetching group details."
                        )
                        resp_msg = response.get(
                            "message", "Error message not available."
                        )
                        self.logger.error(
                            message=err_msg, details=f"Error: {resp_msg}"
                        )
                        next_page = False
                except ThreatConnectException:
                    next_page = False
                except Exception as err:
                    err_msg = (
                        f"{self.log_prefix}: Error while fetching group details. "
                        f"Error: {err}"
                    )
                    self.logger.error(
                        message=err_msg,
                        details=traceback.format_exc()
                    )
                    next_page = False
        return group_names

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get action fields for a given action.

        Args:
            action (Action): Given action.

        Returns:
            List[Dict]: List of configuration parameters for a given action.
        """
        if action.value == "add_to_group":
            group_names = dict(sorted(self.get_group_names().items()))
            group_types = [
                "Adversary",
                "Attack Pattern",
                "Campaign",
                "Course of Action",
                "Email",
                "Event",
                "Incident",
                "Intrusion Set",
                "Malware",
                "Tactic",
                "Task",
                "Threat",
                "Tool",
                "Vulnerability",
            ]  # Document, Report, Signature not supported.
            return [
                {
                    "label": "Add to Existing Group",
                    "key": "group_name",
                    "type": "choice",
                    "choices": [
                        {"key": group_name, "value": group_id}
                        for group_name, group_id in group_names.items()
                    ]
                    + [{"key": "Create New Group", "value": "create_group"}],
                    "mandatory": True,
                    "description": f"Available groups on {PLUGIN_NAME}.",
                },
                {
                    "label": "Name of New Group (only applicable for Create "
                    "New Group)",
                    "key": "new_group_name",
                    "type": "text",
                    "mandatory": False,
                    "default": "",
                    "description": "Name of new group in which you want to "
                    "add all your IoCs.",
                },
                {
                    "label": "Type of New Group (only applicable for Create "
                    "New Group)",
                    "key": "new_group_type",
                    "type": "choice",
                    "choices": [
                        {"key": group_type, "value": group_type}
                        for group_type in group_types
                    ],
                    "mandatory": False,
                    "default": "Incident",
                    "description": "Select group type for new group.",
                },
            ]
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action configuration.

        Returns:
            ValidationResult: Valid configuration or not for action.
        """
        if action.value not in ["add_to_group"]:
            return ValidationResult(success=False, message="Invalid Action Provided.")
        if (
            action.value in ["add_to_group"]
            and action.parameters["group_name"] == "create_group"
            and action.parameters["new_group_name"].strip() == ""
        ):
            return ValidationResult(
                success=False,
                message=(
                    "'Name of New Group' is a required field when "
                    "'Create New Group' is selected in the "
                    "'Add to Existing Group' parameter."
                )
            )
        if (
            action.value in ["add_to_group"]
            and action.parameters["group_name"] == "create_group"
            and action.parameters["new_group_type"].strip() == ""
        ):
            return ValidationResult(
                success=False,
                message=(
                    "'Type of New Group' is a required field when "
                    "'Create New Group' is selected in the "
                    "'Add to Existing Group' parameter."
                )
            )
        return ValidationResult(
            success=True,
            message="Action configuration validated.",
        )
