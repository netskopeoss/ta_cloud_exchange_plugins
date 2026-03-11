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

CTE Abnormal Security Plugin.
"""

import re
import traceback
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Callable, Dict, Generator, List, Literal, Tuple, Union

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from packaging import version
from pydantic import ValidationError

from .utils.constants import (
    ABNORMAL_SECURITY_TO_INTERNAL_TYPE,
    ABNORMAL_SITES,
    API_RESPONSE_LIMIT,
    CONFIGURATION_BOOLEAN_VALUES,
    DATETIME_FORMAT,
    INDICATOR_TYPES,
    INDICATOR_TYPE_LIST,
    INTEGER_THRESHOLD,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
)
from .utils.helper import (
    AbnormalSecurityPluginException,
    AbnormalSecurityPluginHelper,
)


class AbnormalSecurityPlugin(PluginBase):
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
        self._is_ce_post_v512 = self._check_ce_version()
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.abnormal_security_helper = AbnormalSecurityPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = AbnormalSecurityPlugin.metadata
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

    def _check_ce_version(self):
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _fetch_threat_ids(
        self,
        fetch_start_time: str,
        fetch_end_time: str,
        checkpoint_query_params: Dict = {},
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Dict], Dict], None, None]:
        """
        Fetch threat ids from Abnormal Security.

        Args:
            fetch_start_time (str): Start Time.
            fetch_end_time (str): End Time.
            is_retraction (bool): IoC Retraction Flag.

        Returns:
            Generator: Threat Ids
        """
        base_url, api_key, *_ = (
            self.abnormal_security_helper.get_configuration_data(
                self.configuration
            )
        )
        fetch_threat_ids_url = f"{base_url}/threats"
        headers = self.abnormal_security_helper.get_auth_headers(api_key)
        page = 1
        if checkpoint_query_params:
            query_params = checkpoint_query_params
            page = int(query_params.get("pageNumber", page))
        else:
            query_params = {
                "pageSize": API_RESPONSE_LIMIT,
                "pageNumber": page,
                "filter": (
                    f"receivedTime gte {fetch_start_time} lte {fetch_end_time}"
                ),
            }
        try:
            while True:
                logger_msg = f"fetching Threat IDs for page: {page}"
                response = self.abnormal_security_helper.api_helper(
                    logger_msg=logger_msg,
                    method="GET",
                    url=fetch_threat_ids_url,
                    headers=headers,
                    params=query_params,
                    is_validation=False,
                    is_retraction=is_retraction,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                if response.get("threats"):
                    yield response.get("threats"), query_params

                # Last page check
                if response.get("nextPageNumber"):
                    page = int(response.get("nextPageNumber"))
                    query_params["pageNumber"] = page
                else:
                    break
        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {str(e)}"
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)

    def _fetch_threat_details_by_id(
        self, threat_id: str, is_retraction: bool = False
    ) -> Generator[List[Dict], None, None]:
        """
        Fetch threat details by threat_id.

        Args:
            threat_id (str): Threat Id
            is_retraction (bool, optional): Whether it is a retraction or not.
                Defaults to False.

        Yields:
            Generator[List[Dict], None, None]: Threat details
        """
        base_url, api_key, *_ = (
            self.abnormal_security_helper.get_configuration_data(
                self.configuration
            )
        )
        fetch_threat_details_url = f"{base_url}/threats/{threat_id}"
        headers = self.abnormal_security_helper.get_auth_headers(api_key)
        threat_details_list = []
        page = 1
        logger_msg = f"fetching threat details for Threat ID: {threat_id}"
        try:
            while True:
                response = self.abnormal_security_helper.api_helper(
                    logger_msg=logger_msg,
                    method="GET",
                    url=fetch_threat_details_url,
                    headers=headers,
                    params={
                        "pageSize": API_RESPONSE_LIMIT,
                        "pageNumber": page,
                    },
                    is_validation=False,
                    is_retraction=is_retraction,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                for threat_detail in response.get("messages", []):
                    tags = []
                    tags.extend(threat_detail.get("summaryInsights", []))
                    if remediation_status := threat_detail.get(
                        "remediationStatus"
                    ):
                        tags.append(remediation_status)
                    threat_details_list.append(
                        {
                            "threat_id": threat_id,
                            "attack_type": threat_detail.get("attackType"),
                            "extended_information": threat_detail.get(
                                "abxPortalUrl"
                            ),
                            "domain": threat_detail.get("senderDomain"),
                            "ip_address": threat_detail.get("senderIpAddress"),
                            "urls": threat_detail.get("urls", []),
                            "received_time": threat_detail.get("receivedTime"),
                            "tags": tags,
                            "message_id": threat_detail.get("abxMessageIdStr"),
                            "attachment_names": threat_detail.get(
                                "attachmentNames", []
                            ),
                            "comments": threat_detail.get("subject", ""),
                        }
                    )
                yield threat_details_list

                if response.get("nextPageNumber"):
                    page = response.get("nextPageNumber")
                    threat_details_list = []
                else:
                    break
        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            error_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {str(e)}"
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(error_msg)

    def _fetch_message_attachments_data(
        self,
        message_id: str,
        attachment_names: List[str],
        is_retraction: bool = False,
    ) -> Generator[List[dict], None, None]:
        """
        Fetch attachment data for a message.

        Args:
            message_id (str): Message Id
            attachment_names (List[str]): List of attachment names
            is_retraction (bool, optional): Whether it is a retraction or not.
                Defaults to False.

        Yields:
            Generator[List[dict], None, None]: Attachment data
        """
        base_url, api_key, *_ = (
            self.abnormal_security_helper.get_configuration_data(
                self.configuration
            )
        )
        headers = self.abnormal_security_helper.get_auth_headers(api_key)
        try:
            for attachment_name in attachment_names:
                fetch_message_attachment_url = (
                    f"{base_url}/messages/{message_id}"
                    f"/attachment/{attachment_name}"
                )
                logger_msg = (
                    f"fetching attachment data for {attachment_name} "
                    f"with Message ID {message_id}"
                )
                response = self.abnormal_security_helper.api_helper(
                    logger_msg=logger_msg,
                    method="GET",
                    url=fetch_message_attachment_url,
                    headers=headers,
                    is_validation=False,
                    is_retraction=is_retraction,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                for attachment_data in response.get("data", []):
                    yield {
                        "attachment_name": attachment_data.get(
                            "attachmentName"
                        ),
                        "md5": attachment_data.get("md5", ""),
                        "sha256": attachment_data.get("sha256", ""),
                        "urls": attachment_data.get("url", []),
                    }
        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            error_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {str(e)}"
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(error_msg)

    def _create_tags(
        self, utils: TagUtils, tags: List[str], enable_tagging: str
    ) -> Tuple[List[str], List[str]]:
        """Create new tag(s) in database if required.

        Args:
            utils (TagUtils): Utils
            tags (List[str]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Tuple[List[str], List[str]]: Created tags, Skipped tags
        """
        if enable_tagging != "yes":
            return [], []

        tag_names, skipped_tags = [], []
        for tag in tags:
            tag = tag.strip()
            tag = f"{PLUGIN_NAME}-{tag}"
            try:
                if not utils.exists(tag):
                    utils.create_tag(
                        TagIn(
                            name=tag,
                            color="#ED3347",
                        )
                    )
            except ValueError:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def _determine_ip_version(
        self,
        ip_address_str: str
    ) -> Literal["ipv4", "ipv6"]:
        try:
            ip_obj = ip_address(ip_address_str)
            if isinstance(ip_obj, IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, IPv6Address):
                return "ipv6"
        except (ValueError, Exception):
            return None

    def _is_valid_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        regex_str = r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"  # noqa

        if re.match(
            regex_str,
            value,
        ):
            return True
        else:
            return False

    def _get_start_time_from_sub_checkpoint(self, query_params: Dict):
        """Get start time from sub-checkpoint.

        Args:
            query_params (Dict): Query parameters.

        Returns:
            str: Start time.
        """
        query_filter = query_params.get("filter", "")
        start_time = query_filter.split("gte ")[1].split(" lte ")[0]
        # If error occurs on page x sub checkpoint provides us page x-1
        # so to start pulling from page x we increment the pageNumber by 1
        query_params["pageNumber"] = int(query_params.get("pageNumber")) + 1
        return start_time

    def _create_indicator_object(
        self,
        indicator_value: Union[List, str],
        indicator_type: str,
        tags: list,
        extended_information: str,
        successfully_created_ioc: Dict,
        skipped_ioc: int,
        skipped_ioc_values: List[str],
        first_seen=None,
        last_seen=None,
        comments: str = "",
        iocs_to_be_pulled: List[str] = INDICATOR_TYPE_LIST,
    ) -> Tuple[Union[List[Indicator], Indicator, None], Dict, int, List[str]]:
        """
        Create Indicator object(s) from given indicator value, type, tags and
            extended information.

        Args:
            indicator_value (Union[List, str]): Indicator value(s).
            indicator_type (str): Indicator type.
            tags (list): Tags to be associated with the indicator.
            extended_information (str): Extended information for the indicator.
            successfully_created_ioc (Dict): Dictionary to store the count of
                successfully created IOC.
            skipped_ioc (int): Count of skipped IOC.
            skipped_ioc_values (List[str]): List of skipped IOC values.
            first_seen (datetime, optional): First seen datetime for the
                indicator. Defaults to None.
            last_seen (datetime, optional): Last seen datetime for the
                indicator. Defaults to None.
            iocs_to_be_pulled (List[str], optional): List of IOC types to be
                pulled. Defaults to ["sha256", "md5", "url", "domain", "ipv4"].

        Returns:
            Tuple[Union[List[Indicator], Indicator, None], Dict, int, List[str]]:
                - List of Indicator objects if indicator_type is "url" else a
                    single Indicator object.
                - Dictionary of successfully created IOC.
                - Count of skipped IOC.
                - List of skipped IOC values.
        """
        if indicator_type not in iocs_to_be_pulled:
            return (
                None,
                successfully_created_ioc,
                skipped_ioc,
                skipped_ioc_values,
            )
        try:
            # Check if the indicator value is empty
            if (isinstance(indicator_value, str) and not indicator_value) or (
                indicator_value is None
            ):
                skipped_ioc += 1
                return (
                    None,
                    successfully_created_ioc,
                    skipped_ioc,
                    skipped_ioc_values,
                )
            elif indicator_type == "url":
                url_indicator_list = []
                skipped_url_indicator = 0
                for url in indicator_value:
                    if not url:
                        # Created a variable to count skipped empty url values
                        # because if we directly increment the skipped_ioc
                        # count by 1 for empty value
                        # and then an exception is raised for any value
                        # after that empty value then
                        # the empty value will be counted twice as we
                        # will add the length
                        # of the indicator_value list to skipped_ioc in
                        # the except block
                        skipped_url_indicator += 1
                        continue
                    url_indicator_list.append(
                        Indicator(
                            value=url,
                            type=ABNORMAL_SECURITY_TO_INTERNAL_TYPE.get(
                                indicator_type
                            ),
                            firstSeen=first_seen,
                            lastSeen=last_seen if last_seen else first_seen,
                            tags=tags,
                            extendedInformation=extended_information,
                            comments=comments,
                        )
                    )
                    successfully_created_ioc[indicator_type] += 1
                skipped_ioc += skipped_url_indicator
                return (
                    url_indicator_list,
                    successfully_created_ioc,
                    skipped_ioc,
                    skipped_ioc_values,
                )
            else:
                if indicator_type == "domain" and not self._is_valid_domain(
                    indicator_value
                ):
                    skipped_ioc_values.append(indicator_value)
                    skipped_ioc += 1
                    return (
                        None,
                        successfully_created_ioc,
                        skipped_ioc,
                        skipped_ioc_values,
                    )
                indicator_object = Indicator(
                    value=indicator_value,
                    type=ABNORMAL_SECURITY_TO_INTERNAL_TYPE.get(
                        indicator_type
                    ),
                    firstSeen=first_seen,
                    lastSeen=last_seen if last_seen else first_seen,
                    tags=tags,
                    extendedInformation=extended_information,
                    comments=comments,
                )
                successfully_created_ioc[indicator_type] += 1
                return (
                    indicator_object,
                    successfully_created_ioc,
                    skipped_ioc,
                    skipped_ioc_values
                )
        except (ValidationError, Exception) as e:
            error_msg = (
                "Validation error occurred"
                if isinstance(e, ValidationError)
                else "Unexpected error occurred"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_msg} while creating "
                    f"indicator object for indicator type '{indicator_type}'"
                    f" and indicator value '{indicator_value}'."
                ),
                details=str(traceback.format_exc()),
            )
            if indicator_type == "url" and isinstance(indicator_value, list):
                skipped_ioc += len(indicator_value)
                skipped_ioc_values.extend(indicator_value)
            else:
                skipped_ioc_values.append(indicator_value)
                skipped_ioc += 1
            return (
                None,
                successfully_created_ioc,
                skipped_ioc,
                skipped_ioc_values
            )

    def _pull(self) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pull indicators from Abnormal Security"""

        iocs_to_be_pulled = self.configuration.get("type", [])
        end_time = datetime.strftime(datetime.now(), DATETIME_FORMAT)
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        start_time = None
        if sub_checkpoint:
            start_time = self._get_start_time_from_sub_checkpoint(
                sub_checkpoint
            )
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME} "
                f"using checkpoint start time {str(start_time)} and page"
                f" number: {sub_checkpoint.get('pageNumber')}."
            )
        elif self.last_run_at:
            start_time = datetime.strftime(self.last_run_at, DATETIME_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME} "
                f"using checkpoint: {str(start_time)}"
            )
        else:
            initial_pull_range = self.configuration.get(
                "initial_pull_range", 7
            )
            start_time = datetime.strftime(
                datetime.strptime(end_time, DATETIME_FORMAT)
                - timedelta(days=int(initial_pull_range)),
                DATETIME_FORMAT,
            )
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch for IoC(s)"
                f" since checkpoint is empty. Querying indicators for last"
                f" {initial_pull_range} days."
            )
        total_skipped_iocs = 0
        skipped_ioc_values = []
        total_skipped_tags = []
        tag_utils = TagUtils()
        total_fetched_iocs = 0
        try:
            # Getting pages of thread ids
            for threat_ids_page, query_params in self._fetch_threat_ids(
                fetch_start_time=start_time,
                fetch_end_time=end_time,
                checkpoint_query_params=sub_checkpoint,
            ):
                page_number = query_params["pageNumber"]
                skipped_ioc = 0
                indicators_list = []
                successfully_extracted_ioc_count = {
                    "url": 0,
                    "ipv4": 0,
                    "ipv6": 0,
                    "domain": 0,
                    "sha256": 0,
                    "md5": 0,
                }
                # Iterating over a single page of thread ids
                for threat_id in threat_ids_page:
                    # Getting threat details list of one threat
                    for (
                        threat_details_list
                    ) in self._fetch_threat_details_by_id(
                        threat_id.get("threatId", "")
                    ):
                        # Iterating over a single page of threat details
                        for threat_detail in threat_details_list:
                            tags, skipped_tags = self._create_tags(
                                tag_utils,
                                threat_detail.get("tags", []),
                                enable_tagging=self.configuration.get(
                                    "enable_tagging", ""
                                ),
                            )
                            total_skipped_tags.extend(skipped_tags)

                            # Append IoC type Domain in the Indicators List
                            (
                                indicator_object,
                                successfully_extracted_ioc_count,
                                skipped_ioc,
                                skipped_ioc_values,
                            ) = self._create_indicator_object(
                                indicator_value=threat_detail.get(
                                    "domain", ""
                                ),
                                indicator_type="domain",
                                tags=tags,
                                extended_information=threat_detail.get(
                                    "extended_information"
                                ),
                                first_seen=threat_detail.get("received_time"),
                                successfully_created_ioc=(
                                    successfully_extracted_ioc_count
                                ),
                                skipped_ioc=skipped_ioc,
                                skipped_ioc_values=skipped_ioc_values,
                                iocs_to_be_pulled=iocs_to_be_pulled,
                                comments=threat_detail.get("comments"),
                            )
                            if indicator_object:
                                indicators_list.append(indicator_object)
                            # Append IoC type IPv4 in the Indicators List
                            ip_ioc_value = threat_detail.get("ip_address", "")
                            ip_version = self._determine_ip_version(
                                ip_ioc_value
                            )
                            if ip_version:
                                (
                                    indicator_object,
                                    successfully_extracted_ioc_count,
                                    skipped_ioc,
                                    skipped_ioc_values,
                                ) = self._create_indicator_object(
                                    indicator_value=ip_ioc_value,
                                    indicator_type=ip_version,
                                    tags=tags,
                                    extended_information=threat_detail.get(
                                        "extended_information"
                                    ),
                                    first_seen=threat_detail.get(
                                        "received_time"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
                                    skipped_ioc_values=skipped_ioc_values,
                                    iocs_to_be_pulled=iocs_to_be_pulled,
                                    comments=threat_detail.get("comments"),
                                )
                                if indicator_object:
                                    indicators_list.append(indicator_object)
                            else:
                                skipped_ioc_values.append(ip_ioc_value)
                                skipped_ioc += 1
                            # Append IoC type URL extracted from email
                            # body in the Indicators List
                            (
                                url_indicator_list,
                                successfully_extracted_ioc_count,
                                skipped_ioc,
                                skipped_ioc_values,
                            ) = self._create_indicator_object(
                                indicator_value=threat_detail.get("urls"),
                                indicator_type="url",
                                tags=tags,
                                extended_information=threat_detail.get(
                                    "extended_information"
                                ),
                                first_seen=threat_detail.get("received_time"),
                                successfully_created_ioc=(
                                    successfully_extracted_ioc_count
                                ),
                                skipped_ioc=skipped_ioc,
                                skipped_ioc_values=skipped_ioc_values,
                                iocs_to_be_pulled=iocs_to_be_pulled,
                                comments=threat_detail.get("comments"),
                            )
                            if url_indicator_list:
                                indicators_list.extend(url_indicator_list)

                            # Extract the message attachment details
                            message_id = threat_detail.get("message_id")
                            attachment_names = threat_detail.get(
                                "attachment_names", []
                            )
                            for (
                                message_attachment_details
                            ) in self._fetch_message_attachments_data(
                                message_id, attachment_names
                            ):
                                # Append IoC type SHA256 to the Indicators List
                                (
                                    indicator_object,
                                    successfully_extracted_ioc_count,
                                    skipped_ioc,
                                    skipped_ioc_values,
                                ) = self._create_indicator_object(
                                    indicator_value=(
                                        message_attachment_details.get(
                                            "sha256"
                                        )
                                    ),
                                    indicator_type="sha256",
                                    tags=tags,
                                    extended_information=threat_detail.get(
                                        "extended_information"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
                                    skipped_ioc_values=skipped_ioc_values,
                                    iocs_to_be_pulled=iocs_to_be_pulled,
                                    comments=threat_detail.get("comments"),
                                )
                                if indicator_object:
                                    indicators_list.append(indicator_object)
                                # Append IoC type MD5 to the Indicators List
                                (
                                    indicator_object,
                                    successfully_extracted_ioc_count,
                                    skipped_ioc,
                                    skipped_ioc_values,
                                ) = self._create_indicator_object(
                                    indicator_value=(
                                        message_attachment_details.get(
                                            "md5"
                                        )
                                    ),
                                    indicator_type="md5",
                                    tags=tags,
                                    extended_information=threat_detail.get(
                                        "extended_information"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
                                    skipped_ioc_values=skipped_ioc_values,
                                    iocs_to_be_pulled=iocs_to_be_pulled,
                                    comments=threat_detail.get("comments"),
                                )
                                if indicator_object:
                                    indicators_list.append(indicator_object)
                                # Append IoC type URL extracted
                                # from the message attachment
                                # to Indicators list
                                (
                                    url_indicator_list,
                                    successfully_extracted_ioc_count,
                                    skipped_ioc,
                                    skipped_ioc_values,
                                ) = self._create_indicator_object(
                                    indicator_value=(
                                        message_attachment_details.get(
                                            "urls", []
                                        )
                                    ),
                                    indicator_type="url",
                                    tags=tags,
                                    extended_information=threat_detail.get(
                                        "extended_information"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
                                    skipped_ioc_values=skipped_ioc_values,
                                    iocs_to_be_pulled=iocs_to_be_pulled,
                                    comments=threat_detail.get("comments"),
                                )
                                if url_indicator_list:
                                    indicators_list.extend(url_indicator_list)
                            # One thread detail done
                        # One page of details done
                    # All details of one threat done,
                    # move to next threat in page
                # One page of threats done
                total_indicators_fetched_in_page = sum(
                    successfully_extracted_ioc_count.values()
                )
                total_fetched_iocs += total_indicators_fetched_in_page
                total_skipped_iocs += skipped_ioc
                self.logger.info(
                    f"{self.log_prefix}: Fetched "
                    f"{total_indicators_fetched_in_page} "
                    f"indicator(s) and skipped {skipped_ioc} indicator(s) in "
                    f"page {page_number} from {PLATFORM_NAME}."
                    " Pull Stats:"
                    f" SHA256: {successfully_extracted_ioc_count.get('sha256')},"
                    f" MD5: {successfully_extracted_ioc_count.get('md5')},"
                    f" URLs: {successfully_extracted_ioc_count.get('url')},"
                    f" Domain: {successfully_extracted_ioc_count.get('domain')},"
                    f" IPv4: {successfully_extracted_ioc_count.get('ipv4')}."
                    f" IPv6: {successfully_extracted_ioc_count.get('ipv6')}."
                    f" Total indicator(s) fetched: {total_fetched_iocs}."
                )

                yield indicators_list, query_params
            # All threats done
            if total_skipped_iocs > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped pulling {total_skipped_iocs}"
                    f" IoC(s) from {PLATFORM_NAME} as they were empty or of"
                    " invalid type.",
                    details=f"Skipped IoC(s): {', '.join(skipped_ioc_values)}",
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{total_fetched_iocs} indicator(s) from "
                f"{PLATFORM_NAME}."
            )
            if len(total_skipped_tags) > 0:
                self.logger.info(
                    f"{self.log_prefix}: {len(total_skipped_tags)} "
                    "tag(s) skipped as they were longer than expected "
                    "size or due to some other exceptions that "
                    "occurred while creation of them. tags: "
                    f"({', '.join(total_skipped_tags)})."
                )

        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            error_msg = (
                f"Unexpected error occurred while pulling "
                f"indicators for page {page_number} "
                f"from {PLATFORM_NAME}. Error: {e}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=str(traceback.format_exc()),
            )
            raise AbnormalSecurityPluginException(error_msg)

    def pull(self):
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            return indicators

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
        retraction_interval = int(retraction_interval)
        end_time = datetime.now()
        start_time = datetime.strftime(
            end_time - timedelta(days=retraction_interval),
            DATETIME_FORMAT,
        )
        end_time = datetime.strftime(end_time, DATETIME_FORMAT)
        ioc_to_be_retracted = self.configuration.get("type", "")
        pulled_indicators = set()
        self.logger.info(
            f"{self.log_prefix}: Pulling modified indicators "
            f"from {PLATFORM_NAME}"
        )
        try:
            for threat_ids_page, query_params in self._fetch_threat_ids(
                fetch_start_time=start_time,
                fetch_end_time=end_time,
                is_retraction=True,
            ):
                page_number = query_params["pageNumber"]
                for threat_id in threat_ids_page:
                    for (
                        threat_details_list
                    ) in self._fetch_threat_details_by_id(
                        threat_id.get("threatId", ""), is_retraction=True
                    ):
                        for threat_detail in threat_details_list:
                            if (
                                "domain" in ioc_to_be_retracted
                                and threat_detail.get("domain")
                            ):
                                pulled_indicators.add(
                                    threat_detail.get("domain")
                                )
                            ip_address_str = threat_detail.get("ip_address")
                            ip_version = self._determine_ip_version(
                                ip_address_str
                            )
                            if (
                                ip_version in ioc_to_be_retracted
                                and threat_detail.get("ip_address")
                            ):
                                pulled_indicators.add(
                                    threat_detail.get("ip_address")
                                )
                            if (
                                "url" in ioc_to_be_retracted
                                and threat_detail.get("urls")
                            ):
                                pulled_indicators.update(
                                    threat_detail.get("urls")
                                )
                            message_id = threat_detail.get("message_id", "")
                            attachment_names = threat_detail.get(
                                "attachment_names", []
                            )
                            for (
                                message_attachment_details
                            ) in self._fetch_message_attachments_data(
                                message_id,
                                attachment_names,
                                is_retraction=True,
                            ):
                                if (
                                    "sha256" in ioc_to_be_retracted
                                    and message_attachment_details.get(
                                        "sha256"
                                    )
                                ):
                                    pulled_indicators.add(
                                        message_attachment_details.get(
                                            "sha256"
                                        )
                                    )
                                if (
                                    "md5" in ioc_to_be_retracted
                                    and message_attachment_details.get("md5")
                                ):
                                    pulled_indicators.add(
                                        message_attachment_details.get("md5")
                                    )
                                if (
                                    "url" in ioc_to_be_retracted
                                    and message_attachment_details.get("urls")
                                ):
                                    pulled_indicators.update(
                                        message_attachment_details.get("urls")
                                    )
            self.logger.info(
                f"{self.log_prefix}: Total {len(pulled_indicators)} "
                f"indicator(s) fetched from {PLATFORM_NAME}."
            )
        except AbnormalSecurityPluginException:
            raise
        except Exception as exp:
            error_msg = (
                f"Unexpected error occurred while pulling "
                f"indicators for page {page_number} "
                f"from {PLATFORM_NAME}. Error: {exp}"
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(error_msg)

        # We are filtering IoC based on type and the
        # IoC type provided in configuration
        # include IPv4 and DOMAIN types but the older
        # version of core does not include
        # IPV4 and DOMAIN types hence replacing them with URL
        if not hasattr(IndicatorType, "DOMAIN") and not hasattr(
            IndicatorType, "IPV4"
        ) and not hasattr(IndicatorType, "IPV6"):
            if "domain" in ioc_to_be_retracted:
                ioc_to_be_retracted.remove("domain")
                ioc_to_be_retracted.append("url")
            if "ipv4" in ioc_to_be_retracted:
                ioc_to_be_retracted.remove("ipv4")
                ioc_to_be_retracted.append("url")
            if "ipv6" in ioc_to_be_retracted:
                ioc_to_be_retracted.remove("ipv6")
                ioc_to_be_retracted.append("url")
            ioc_to_be_retracted = list(set(ioc_to_be_retracted))

        for ioc_page in source_indicators:
            source_unique_iocs = set()
            for ioc in ioc_page:
                if ioc.type in ioc_to_be_retracted:
                    source_unique_iocs.add(ioc.value)
            retracted_iocs = source_unique_iocs - pulled_indicators
            self.logger.info(
                f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) will "
                f"be marked as retracted from {len(source_unique_iocs)} total "
                "indicator(s) present in cloud exchange for"
                f" {PLATFORM_NAME}."
            )
            yield list(retracted_iocs), False

    def _validate_connectivity(
        self,
        base_url: str,
        api_key: str,
    ) -> Union[bool, ValidationResult]:
        """Validate Authentication Key by making REST API call.

        Args:
            base_url (str): Base URL.
            api_key (str): Abnormal Security Authentication Key.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        try:
            headers = self.abnormal_security_helper.get_auth_headers(api_key)
            self.abnormal_security_helper.api_helper(
                logger_msg=f"validating connectivity with {PLATFORM_NAME}",
                method="GET",
                url=f"{base_url}/threats",
                headers=headers,
                params={"pageSize": 1, "pageNumber": 1},
                is_validation=True,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"{PLATFORM_NAME} configuration parameters."
            )
            return ValidationResult(
                success=True, message="Validation Successful."
            )
        except AbnormalSecurityPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Unexpected validation error occurred while authenticating."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin's configuration parameters."""

        # Validate Base URL configuration parameter
        (
            base_url,
            api_key,
            types_to_pull,
            enable_tagging,
            retraction_interval,
            initial_pull_range,
        ) = self.abnormal_security_helper.get_configuration_data(configuration)

        if validation_failure := self._validate_configuration_parameters(
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            allowed_values=ABNORMAL_SITES,
        ):
            return validation_failure

        if validation_failure := self._validate_configuration_parameters(
            field_name="API Key",
            field_value=api_key,
            field_type=str,
        ):
            return validation_failure

        # Validate IoC types to be pulled configuration parameter
        if validation_failure := self._validate_configuration_parameters(
            field_name="IoC types to be pulled",
            field_value=types_to_pull,
            field_type=list,
            allowed_values=INDICATOR_TYPES,
        ):
            return validation_failure

        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=CONFIGURATION_BOOLEAN_VALUES,
        ):
            return validation_result

        if validation_result := self._validate_configuration_parameters(
            field_name="Initial Range",
            field_value=initial_pull_range,
            field_type=int,
            max_value=INTEGER_THRESHOLD,
            allow_zero_value=True,
        ):
            return validation_result

        # Validate Retraction interval
        if validation_result := self._validate_configuration_parameters(
            field_name="Retraction Interval",
            field_value=retraction_interval,
            field_type=int,
            max_value=INTEGER_THRESHOLD,
            allow_zero_value=False,
            is_required=False,
        ):
            return validation_result

        return self._validate_connectivity(base_url=base_url, api_key=api_key)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        max_value: int = None,
        allow_zero_value: bool = False,
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
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
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
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
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
            if field_type is str and field_value not in allowed_values.values():
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        "Please provide a valid value from the allowed values."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type == list:
                for value in field_value:
                    if value not in allowed_values.values():
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg}"
                                f" {err_msg}"
                            ),
                            resolution=(
                                "Please provide a valid value from the allowed"
                                " values."
                            ),
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if isinstance(field_value, int):
            if allow_zero_value:
                zero_condition = (field_value < 0)
                min_value = 0
            else:
                zero_condition = (field_value <= 0)
                min_value = 1
            if max_value and (
                field_value > max_value or zero_condition
            ):
                if max_value == INTEGER_THRESHOLD:
                    max_value = "2^62"
                err_msg = (
                    f"Invalid value for {field_name} provided in configuration"
                    " parameters. Valid value should be an integer "
                    f"greater than {min_value} and less than {max_value}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        f"Please provide a valid value greater than"
                        f" {min_value} and less than {max_value}."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
