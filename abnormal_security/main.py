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
from ipaddress import IPv4Address
from typing import Dict, Generator, List, Tuple, Union

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.constants import (
    API_RESPONSE_LIMIT,
    DATETIME_FORMAT,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    ABNORMAL_SITES,
    INDICATOR_TYPES,
)
from .utils.helper import (
    AbnormalSecurityPluginException,
    AbnormalSecurityPluginHelper,
)

ABNORMAL_SECURITY_TO_INTERNAL_TYPE = {
    "domain": (
        IndicatorType.DOMAIN
        if hasattr(IndicatorType, "DOMAIN")
        else IndicatorType.URL
    ),
    "ipv4": (
        IndicatorType.IPV4
        if hasattr(IndicatorType, "IPV4")
        else IndicatorType.URL
    ),
    "url": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
}


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

    def _fetch_threat_ids(
        self,
        fetch_start_time: str,
        fetch_end_time: str,
        is_retraction: bool = False,
    ) -> Generator[Tuple[List[Dict], int], None, None]:
        """
        Fetch threat ids from Abnormal Security.

        Args:
            fetch_start_time (str): Start Time.
            fetch_end_time (str): End Time.
            is_retraction (bool): IoC Retraction Flag.

        Returns:
            Generator: Threat Ids
        """
        base_url, api_key = (
            self.abnormal_security_helper.get_configuration_data(
                self.configuration
            )
        )
        fetch_threat_ids_url = f"{base_url}/threats"
        headers = self.abnormal_security_helper.get_auth_headers(api_key)
        page = 1
        filter_str = (
            f"receivedTime gte {fetch_start_time} lte {fetch_end_time}"
        )
        try:
            while True:
                response = self.abnormal_security_helper.api_helper(
                    logger_msg=f"Fetching Threat ids for page: {page}",
                    method="GET",
                    url=fetch_threat_ids_url,
                    headers=headers,
                    params={
                        "pageSize": API_RESPONSE_LIMIT,
                        "pageNumber": page,
                        "filter": filter_str,
                    },
                    is_validation=False,
                    is_retraction=is_retraction,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                if response.get("threats"):
                    yield response.get("threats"), page

                # Last page check
                if response.get("nextPageNumber"):
                    page = response.get("nextPageNumber")
                else:
                    break
        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while "
                "fetching threat ids.",
                details=str(e),
            )
            raise AbnormalSecurityPluginException(
                f"Error occurred while fetching threat ids: {str(e)}"
            )

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
        base_url, api_key = (
            self.abnormal_security_helper.get_configuration_data(
                self.configuration
            )
        )
        fetch_threat_details_url = f"{base_url}/threats/{threat_id}"
        headers = self.abnormal_security_helper.get_auth_headers(api_key)
        threat_details_list = []
        page = 1
        try:
            while True:
                response = self.abnormal_security_helper.api_helper(
                    logger_msg=f"fetching Threat details for {threat_id}",
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
                            "tags": threat_detail.get("summaryInsights", []),
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
                f"Unexpected error occurred while fetching threat "
                f"details for threat id '{threat_id}'."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=str(e),
            )
            raise AbnormalSecurityPluginException(f"{error_msg}")

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
        base_url, api_key = (
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
                    f"with message id '{message_id}'"
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
                yield {
                    "attachment_name": response.get("attachmentName"),
                    "md5": response.get("md5"),
                    "sha256": response.get("sha256"),
                    "urls": response.get("url", []),
                    "created_on": response.get("createdOn"),
                    "updated_on": response.get("lastUpdated"),
                }
        except AbnormalSecurityPluginException:
            raise
        except Exception as e:
            error_msg = (
                f"Unexpected error occurred while fetching attachment "
                f"data for message id '{message_id}'."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=str(e),
            )
            raise AbnormalSecurityPluginException(f"{error_msg}")

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

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        reger_str = r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"  # noqa

        if re.match(
            reger_str,
            value,
        ):
            return True
        else:
            return False

    def _create_indicator_object(
        self,
        indicator_value: Union[List, str],
        indicator_type: str,
        tags: list,
        extended_information: str,
        successfully_created_ioc: Dict,
        skipped_ioc: int,
        first_seen=None,
        last_seen=None,
        comments: str = "",
        iocs_to_be_pulled: List[str] = INDICATOR_TYPES,
    ) -> Tuple[Union[List[Indicator], Indicator, None], Dict, int]:
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
            first_seen (datetime, optional): First seen datetime for the
                indicator. Defaults to None.
            last_seen (datetime, optional): Last seen datetime for the
                indicator. Defaults to None.
            iocs_to_be_pulled (List[str], optional): List of IOC types to be
                pulled. Defaults to ["sha256", "md5", "url", "domain", "ipv4"].

        Returns:
            Tuple[Union[List[Indicator], Indicator, None], Dict, int]:
                - List of Indicator objects if indicator_type is "url" else a
                    single Indicator object.
                - Dictionary of successfully created IOC.
                - Count of skipped IOC.
        """
        if indicator_type not in iocs_to_be_pulled:
            return None, successfully_created_ioc, skipped_ioc
        try:
            # Check if the indicator value is empty
            if isinstance(indicator_value, str) and not indicator_value:
                skipped_ioc += 1
                return None, successfully_created_ioc, skipped_ioc
            elif indicator_type == "url":
                url_indicator_list = []
                skipped_url_indicator = 0
                for url in indicator_value:
                    if not url:
                        # Created a varaible to count skipped empty url values
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
                )
            else:
                if indicator_type == "ipv4" and not self._is_valid_ipv4(
                    indicator_value
                ):
                    skipped_ioc += 1
                    return None, successfully_created_ioc, skipped_ioc
                if indicator_type == "domain" and not self._is_valid_domain(
                    indicator_value
                ):
                    skipped_ioc += 1
                    return None, successfully_created_ioc, skipped_ioc
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
                return indicator_object, successfully_created_ioc, skipped_ioc
        except (ValidationError, Exception) as e:
            error_msg = (
                "Validation error occurred"
                if isinstance(e, ValidationError)
                else "Unexpected error occurred"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_msg} while creating "
                    f"indicator object "
                    f"For indicator type '{indicator_type}' and "
                    f"indicator value '{indicator_value}'."
                ),
                details=str(traceback.format_exc()),
            )
            if indicator_type == "url" and isinstance(indicator_value, list):
                skipped_ioc += len(indicator_value)
            else:
                skipped_ioc += 1
            return None, successfully_created_ioc, skipped_ioc

    def _pull(self) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pull indicators from Abnormal Security"""

        iocs_to_be_pulled = self.configuration.get("type", [])
        end_time = datetime.strftime(datetime.now(), DATETIME_FORMAT)
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        successfully_extracted_ioc_count = {
            "url": 0,
            "ipv4": 0,
            "domain": 0,
            "sha256": 0,
            "md5": 0,
        }
        skipped_ioc = 0
        start_time = None
        if sub_checkpoint:
            start_time = sub_checkpoint.get("last_successful_page_fetch_time")
        elif self.last_run_at:
            start_time = datetime.strftime(self.last_run_at, DATETIME_FORMAT)
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
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME} "
            f"using checkpoint: {str(start_time)}"
        )
        indicators_list = []
        total_skipped_tags = []
        tag_utils = TagUtils()
        last_successful_page_pull = {
            "last_successful_page_fetch_time": "",
        }
        try:
            # Getting pages of thread ids
            for threat_ids_page, page_number in self._fetch_threat_ids(
                fetch_start_time=start_time, fetch_end_time=end_time
            ):
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
                            if last_successful_page_pull.get(
                                "last_successful_page_fetch_time"
                            ) <= threat_detail.get("received_time"):
                                last_successful_page_pull[
                                    "last_successful_page_fetch_time"
                                ] = threat_detail.get("received_time")
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
                                iocs_to_be_pulled=iocs_to_be_pulled,
                                comments=threat_detail.get("comments"),
                            )
                            if indicator_object:
                                indicators_list.append(indicator_object)
                            # Append IoC type IPv4 in the Indicators List
                            (
                                indicator_object,
                                successfully_extracted_ioc_count,
                                skipped_ioc,
                            ) = self._create_indicator_object(
                                indicator_value=threat_detail.get(
                                    "ip_address", ""
                                ),
                                indicator_type="ipv4",
                                tags=tags,
                                extended_information=threat_detail.get(
                                    "extended_information"
                                ),
                                first_seen=threat_detail.get("received_time"),
                                successfully_created_ioc=(
                                    successfully_extracted_ioc_count
                                ),
                                skipped_ioc=skipped_ioc,
                                iocs_to_be_pulled=iocs_to_be_pulled,
                                comments=threat_detail.get("comments"),
                            )
                            if indicator_object:
                                indicators_list.append(indicator_object)
                            # Append IoC type URL extracted from email
                            # body in the Indicators List
                            (
                                url_indicator_list,
                                successfully_extracted_ioc_count,
                                skipped_ioc,
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
                                    first_seen=message_attachment_details.get(
                                        "created_on"
                                    ),
                                    last_seen=message_attachment_details.get(
                                        "updated_on"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
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
                                    first_seen=message_attachment_details.get(
                                        "created_on"
                                    ),
                                    last_seen=message_attachment_details.get(
                                        "updated_on"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
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
                                ) = self._create_indicator_object(
                                    indicator_value=(
                                        message_attachment_details.get(
                                            "urls", []
                                        )
                                    ),
                                    indicator_type="url",
                                    first_seen=message_attachment_details.get(
                                        "created_on"
                                    ),
                                    last_seen=message_attachment_details.get(
                                        "updated_on"
                                    ),
                                    tags=tags,
                                    extended_information=threat_detail.get(
                                        "extended_information"
                                    ),
                                    successfully_created_ioc=(
                                        successfully_extracted_ioc_count
                                    ),
                                    skipped_ioc=skipped_ioc,
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
                total_indicators = sum(
                    successfully_extracted_ioc_count.values()
                ) + skipped_ioc
                self.logger.info(
                    f"{self.log_prefix}: Fetched "
                    f"{sum(successfully_extracted_ioc_count.values())} "
                    f"indicator(s) and skipped {skipped_ioc} indicator(s) in "
                    f"page {page_number} from {PLATFORM_NAME}."
                    "Pull Stats:"
                    f" SHA256: {successfully_extracted_ioc_count['sha256']},"
                    f" MD5:{successfully_extracted_ioc_count['md5']},"
                    f" URLs: {successfully_extracted_ioc_count['url']},"
                    f" Domain: {successfully_extracted_ioc_count['domain']},"
                    f" IPv4: {successfully_extracted_ioc_count['ipv4']}"
                    f"Total indicator(s) - "
                    f"{total_indicators}."
                )

                yield indicators_list, last_successful_page_pull
            # All threats done
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{sum(successfully_extracted_ioc_count.values())} "
                "total indicator(s) from "
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
        end_time = datetime.strftime(datetime.now(), DATETIME_FORMAT)
        start_time = datetime.strftime(
            datetime.now() - timedelta(days=retraction_interval),
            DATETIME_FORMAT,
        )
        ioc_to_be_retracted = self.configuration.get("type", "")
        pulled_indicators = set()
        self.logger.info(
            f"{self.log_prefix}: Pulling modified indicators "
            f"from {PLATFORM_NAME}"
        )
        try:
            for threat_ids_page, page_number in self._fetch_threat_ids(
                fetch_start_time=start_time,
                fetch_end_time=end_time,
                is_retraction=True,
            ):
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
                            if (
                                "ipv4" in ioc_to_be_retracted
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
        ):
            if "domain" in ioc_to_be_retracted:
                ioc_to_be_retracted.remove("domain")
                ioc_to_be_retracted.append("url")
            if "ipv4" in ioc_to_be_retracted:
                ioc_to_be_retracted.remove("ipv4")
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

        validation_error_msg = "validation error occurred"

        # Validate Base URL configuration parameter
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            error_msg = (
                f"{PLATFORM_NAME} Base URL is a required configuration field."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif (
            not isinstance(base_url, str)
            or base_url not in ABNORMAL_SITES.keys()
        ):
            error_msg = (
                f"Invalid {PLATFORM_NAME} Base URL "
                "provided in configuration parameters."
                f"{PLATFORM_NAME} Base URL should be one of the following: "
                f"{', '.join(ABNORMAL_SITES.values())}"
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate API key configuration parameter
        api_key = configuration.get("api_key", "")
        if not api_key:
            error_msg = (
                f"{PLATFORM_NAME} API Token is a required configuration field."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif not isinstance(api_key, str):
            error_msg = (
                f"Invalid {PLATFORM_NAME} API Token provided "
                "in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate IoC types to be pulled configuration parameter
        iocs_to_be_pulled = configuration.get("type", "")
        if not iocs_to_be_pulled:
            error_msg = (
                f"{PLATFORM_NAME} IoC types to be pulled is "
                "a required configuration parameters. "
                "Please select atleast on of the IoC types to be pulled."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif not isinstance(iocs_to_be_pulled, list):
            error_msg = (
                f"Invalid {PLATFORM_NAME} IoC types to be "
                "pulled provided in configuration parameters. "
                "Parameter should be a valid list containing "
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif not all(
            ioc_type in INDICATOR_TYPES for ioc_type in iocs_to_be_pulled
        ):
            error_msg = (
                f"Invalid {PLATFORM_NAME} IoC type "
                "provided in configuration parameters. "
                "Valid IoC types are: " + ", ".join(INDICATOR_TYPES)
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate Enable Tagging configuration parameter
        enable_tagging = configuration.get("enable_tagging", "").strip()
        if not enable_tagging:
            error_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif enable_tagging not in ["yes", "no"]:
            error_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg,
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
                    f"{self.log_prefix}: {validation_error_msg}. {err_msg}"
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
                    f"{self.log_prefix}: {validation_error_msg}. {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        # Validate Initial Range configuration parameter
        initial_pull_range = configuration.get("initial_pull_range", 0)
        if not initial_pull_range:
            error_msg = (
                f"{PLATFORM_NAME} Initial Range (in days)"
                "is a required configuration field."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif not isinstance(initial_pull_range, int):
            error_msg = (
                "Invalid value provided in Initial Range (in days) "
                "in configuration parameter. Initial Range (in days) "
                "should be positive integer value."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error_msg}. {error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)
        elif initial_pull_range <= 0 or initial_pull_range > INTEGER_THRESHOLD:
            error_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Provide a value between 1 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {error_msg}")
            return ValidationResult(
                success=False,
                message=error_msg,
            )

        return self._validate_connectivity(base_url=base_url, api_key=api_key)
