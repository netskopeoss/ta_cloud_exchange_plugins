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

CTE ThreatQ plugin.
"""

import ipaddress
import re
import traceback
from typing import Dict, List

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.models.business_rule import (
    Action,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import SeverityType, IndicatorType

from .lib.threatqsdk import Threatq, ThreatLibrary
from .lib.threatqsdk.exceptions import AuthenticationError

from .utils.helper import (
    get_config_params,
    ThreatQPluginException,
)

from .utils.constants import (
    SUPPORTED_TYPES,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    RETRACTION_BATCH,
    NO_SAVED_SEARCHES,
    ENABLE_TAGGING,
    ORANGE_HEX_CODE,
    FIELDS,
)

SEVERITY_MAPPING = {
    "10": SeverityType.CRITICAL,
    "9": SeverityType.HIGH,
    "8": SeverityType.MEDIUM,
    "7": SeverityType.MEDIUM,
    "6": SeverityType.LOW,
    "5": SeverityType.LOW,
    "4": SeverityType.LOW,
    "3": SeverityType.LOW,
    "2": SeverityType.LOW,
    "1": SeverityType.LOW,
    "0": SeverityType.LOW,
}

THREATQ_TO_INTERNAL_TYPE = {
    "URL": IndicatorType.URL,
    "MD5": IndicatorType.MD5,
    "SHA-256": IndicatorType.SHA256,
    "IP Address": IndicatorType.URL,
    "IPv6 Address": IndicatorType.URL,
    "FQDN": IndicatorType.URL,
}


class ThreatQ(PluginBase):
    """ThreatQ Plugin."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
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
        self.retraction_batch = RETRACTION_BATCH

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = ThreatQ.metadata
            plugin_name = metadata.get("name", PLUGIN_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_ioc_type_from_value(
        self,
        value: str,
        typename: str
    ):
        """
        Get IoC type from attribute.

        args:
            value: attribute value
            typename: attribute type

        returns:
            IndicatorType: IoC type
        """
        continue_flag = False
        if typename == "IP Address":
            if self._is_valid_ipv4(value):
                return getattr(
                    IndicatorType,
                    "IPV4",
                    IndicatorType.URL,
                ), continue_flag
            else:
                continue_flag = True
                return None, continue_flag
        elif typename == "IPv6 Address":
            if self._is_valid_ipv6(value):
                return getattr(
                    IndicatorType,
                    "IPV6",
                    IndicatorType.URL,
                ), continue_flag
            else:
                continue_flag = True
                return None, continue_flag
        elif typename == "FQDN":
            if self._is_valid_fqdn(value):
                return getattr(
                    IndicatorType,
                    "FQDN",
                    IndicatorType.URL,
                ), continue_flag
            else:
                continue_flag = True
                return None, continue_flag
        elif typename == "URL":
            return getattr(
                IndicatorType,
                "URL",
                IndicatorType.URL,
            ), continue_flag

        return None, True

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

    def _is_valid_fqdn(self, fqdn: str) -> bool:
        """Validate FQDN (Absolute domain).

        Args:
            - fqdn (str): FQDN to validate.

        Returns:
            - bool: True if valid else False.
        """
        if re.match(
            r"^(?=.{1,255}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,})\.?$",  # noqa
            fqdn,
            re.IGNORECASE,
        ):
            return True
        else:
            return False

    def _create_tags(self, tags: List[str], enable_tagging: str) -> List[str]:
        """Create new tag(s) in database if required.

        Args:
            tags (List[str]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Union[List[str], List[str]]: Created tags, Skipped tags
        """
        if enable_tagging != "yes":
            return [], []

        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        for tag in tags:
            tag_name = f"{PLATFORM_NAME}-{tag.strip()}"
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(
                        TagIn(name=tag_name, color=ORANGE_HEX_CODE)
                    )
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix, tag_name, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def pull(self) -> List[Indicator]:
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            return indicators

    def _pull(self, is_retraction: bool = False):
        """
        Pull indicators from ThreatQ.

        Args:
            is_retraction (bool, optional): Is retraction. Defaults to False.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        self.logger.info(
            f"{self.log_prefix}: Pulling IOC(s) from {PLATFORM_NAME}."
        )

        (
            tq_host,
            tq_client_id,
            tq_client_secret,
            tq_searches,
            enable_tagging,
        ) = get_config_params(self.configuration)

        proxy_info = None
        if self.proxy:
            proxy_info = self.proxy.get("https") or self.proxy.get("http")

        # Verify that our host has https:// as only it is supported by ThreatQ
        tq_host = f"https://{tq_host.removeprefix('http://').removeprefix('https://')}"  # noqa

        ioc_type = None
        tq = None
        total_skipped_tags = 0
        try:
            tq = Threatq(
                tq_host,
                (tq_client_id, tq_client_secret),
                private=True,
                verify=self.ssl_validation,
                proxy=proxy_info,
            )

            tlsearch = ThreatLibrary(tq, fields=FIELDS)
            search_list = list(
                filter(
                    lambda i: len(i) > 0,
                    map(
                        lambda i: i.strip(),
                        tq_searches.split(","),
                    ),
                )
            )
            batch_count = 0
            total_skip_iocs = 0
            total_indicators_fetched_count = 0
            for search_name in search_list:
                for batch in tlsearch.get_saved_search(search_name).execute(
                    "indicators", yield_batches=True
                ):
                    ioc_counts = {
                        "sha256": 0,
                        "md5": 0,
                        "ipv4": 0,
                        "ipv6": 0,
                        "url": 0,
                        "fqdn": 0,
                        "others": 0,
                    }
                    indicators = []
                    batch_count += 1
                    for ind in batch:
                        continue_flag = False
                        score = min(max(ind.get("score", 1), 1), 10)
                        typename = ind.get("type")
                        value = ind.get("value")
                        tq_url = "{}/indicators/{}/details".format(
                            tq_host, ind.get("id")
                        )
                        status = ind.get("status")
                        tags_list = ind.get("tags", [])

                        ioc_tag = None
                        if tags_list and enable_tagging == "yes":
                            ioc_tag, skipped_tags = self._create_tags(
                                tags_list, enable_tagging
                            )
                            total_skipped_tags += len(skipped_tags)
                        if not typename or typename not in SUPPORTED_TYPES:
                            ioc_counts["others"] += 1
                            continue

                        if typename == "MD5" or typename == "SHA-256":
                            ioc_type = THREATQ_TO_INTERNAL_TYPE.get(typename)
                        else:
                            (
                                ioc_type, continue_flag
                            ) = self._get_ioc_type_from_value(
                                value,
                                typename
                            )
                            if continue_flag:
                                ioc_counts["others"] += 1
                                continue

                        ioc_counts[ioc_type] += 1
                        new_ind = Indicator(
                            value=value,
                            type=ioc_type,
                            reputation=score,
                            severity=SEVERITY_MAPPING.get(str(score)),
                            extendedInformation=tq_url,
                            active=status != "Expired",
                            tags=ioc_tag if ioc_tag else [],
                        )

                        indicators.append(new_ind)

                    total_indicators_fetched_count += len(indicators)
                    total_skip_iocs += ioc_counts["others"]
                    self.logger.info(
                        "{}: Successfully fetched {} indicator(s) and"
                        " skipped {} for batch {}. Pull Stat: {} SHA256, "
                        "{} MD5, {} URL, {} FQDN, {} IPv4, "
                        "and {} IPv6 indicator(s) "
                        "fetched. Total indicator(s) fetched:"
                        " {}.".format(
                            self.log_prefix,
                            len(indicators),
                            ioc_counts["others"],
                            batch_count,
                            ioc_counts["sha256"],
                            ioc_counts["md5"],
                            ioc_counts["url"],
                            ioc_counts["fqdn"],
                            ioc_counts["ipv4"],
                            ioc_counts["ipv6"],
                            total_indicators_fetched_count,
                        )
                    )

                    if hasattr(self, "sub_checkpoint"):
                        yield indicators, None
                    else:
                        yield indicators
                if total_skipped_tags > 0:
                    self.logger.info(
                        f"{self.log_prefix}: {len(total_skipped_tags)} tag(s) "
                        "skipped as they were longer than expected size or due"
                        " to some other exceptions that occurred while "
                        "creation of them. tags: "
                        f"({', '.join(total_skipped_tags)})."
                    )

                info_msg = (
                    f"Successfully fetched {total_indicators_fetched_count} "
                    f"indicator(s) from {PLATFORM_NAME}."
                )
                if total_skip_iocs:
                    info_msg += (
                        f" Skipped {total_skip_iocs} indicator(s) because"
                        " either they were invalid or of unsupported type."
                    )
                self.logger.info(f"{self.log_prefix}: {info_msg}")
        except ThreatQPluginException:
            raise
        except AuthenticationError as ex:
            err_msg = (
                f"Authentication error occurred while "
                f"pulling data from {PLATFORM_NAME}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            raise ThreatQPluginException(err_msg)
        except Exception as ex:
            err_msg = (
                f"Error occurred while pulling data from {PLATFORM_NAME}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            raise ThreatQPluginException(err_msg)

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

        stored_indicators = set()
        modified_indicators = []
        try:
            for indicator_list in source_indicators:
                for indicator in indicator_list:
                    if indicator:
                        stored_indicators.add(indicator.value)

            for result in self._pull(is_retraction=True):
                if isinstance(result, tuple):
                    indicators = result[0]
                else:
                    indicators = result

                for indicator in indicators:
                    modified_indicators.append(indicator.value)

            modified_indicators = set(modified_indicators)
            retracted_indicators = list(
                stored_indicators - modified_indicators
            )

            if len(retracted_indicators) > 0:
                self.logger.info(
                    f"{self.log_prefix}: Total {len(retracted_indicators)} "
                    f"indicator(s) will be retracted as part "
                    f"of IoC(s) Retraction task out of "
                    f"{len(stored_indicators)} total indicator(s)."
                )
            yield retracted_indicators, False
        except Exception as err:
            err_msg = (
                f"Error while fetching modified indicators from"
                f" {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
            raise ThreatQPluginException(err_msg)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate configuration parameters."""

        validation_err_msg = "Validation error occurred"

        (
            tq_host,
            tq_client_id,
            tq_client_secret,
            tq_searches,
            enable_tagging,
        ) = get_config_params(configuration)

        if not tq_host:
            err_msg = "ThreatQ Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(tq_host, str):
            err_msg = (
                "Invalid ThreatQ Base URL provided in"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not tq_client_id:
            err_msg = (
                "ThreatQ Client ID is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(tq_client_id, str):
            err_msg = (
                "Invalid ThreatQ Client ID provided"
                " in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not tq_client_secret:
            err_msg = (
                "ThreatQ Client Secret is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(tq_client_secret, str):
            err_msg = (
                "Invalid ThreatQ Client Secret provided"
                " in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not tq_searches:
            err_msg = "ThreatQ Search is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(tq_searches, str):
            err_msg = (
                "Invalid ThreatQ Search provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif (
            not isinstance(enable_tagging, str)
            or enable_tagging not in ENABLE_TAGGING
        ):
            err_msg = (
                "Invalid Enable Tagging found in the configuration "
                "parameters. Valid values are 'Yes' or 'No'."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self._validate_auth_params(
            tq_host, tq_client_id, tq_client_secret, tq_searches
        )

    def _validate_auth_params(
        self, host: str, client_id: str, client_secret: str, tq_searches: str
    ):
        """Validate authentication parameters.

        Args:
            host (str): ThreatQ Base URL
            client_id (str): ThreatQ Client ID
            client_secret (str): ThreatQ Client Secret
            tq_searches (str): ThreatQ Search

        Returns:
            ValidationResult
        """

        proxy_info = None
        if self.proxy:
            proxy_info = self.proxy.get("https") or self.proxy.get("http")

        # Verify that our host has https:// as only it is supported by ThreatQ
        host = (
            f"https://{host.removeprefix('http://').removeprefix('https://')}"
        )
        try:
            tq = Threatq(
                host,
                (client_id, client_secret),
                private=True,
                verify=self.ssl_validation,
                proxy=proxy_info,
            )
        except AuthenticationError as ex:
            err_msg = (
                f"Invalid {PLATFORM_NAME} Base URL, Client ID or"
                " Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
        except Exception as ex:
            err_msg = (
                "Unexpected validation error occurred while authenticating."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

        tlsearch = ThreatLibrary(tq, fields=FIELDS)
        search_list = list(
            filter(
                lambda i: len(i) > 0,
                map(
                    lambda i: i.strip(),
                    tq_searches.split(","),
                ),
            )
        )
        try:
            for search_name in search_list:
                for ind in tlsearch.get_saved_search(search_name).execute(
                    "indicators"
                ):
                    break
        except ValueError as ex:
            msg = "Error occurred while validating ThreatQ Search Name(s)."
            if NO_SAVED_SEARCHES in str(ex):
                msg = (
                    f"Invalid ThreatQ Search Name '{search_name}' provided"
                    " in configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {msg} Error: {ex}",
                    details=traceback.format_exc(),
                )

            return ValidationResult(
                success=False, message=f"{msg} Check logs for more details."
            )
        except Exception as ex:
            err_msg = (
                "Unexpected error occurred while validating"
                f" {PLATFORM_NAME} Search Name(s)."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
        return ValidationResult(
            success=True,
            message="Validation successful.",
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate ThreatQ configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
