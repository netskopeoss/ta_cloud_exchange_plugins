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

CTE Maltiverse Plugin.
"""

from typing import List
from datetime import datetime
import traceback
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.tags import TagIn

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from pydantic import ValidationError

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    CLASSIFICATIONS,
    FEEDS,
    DATE_FORMAT,
    BASE_URL,
)

from .utils.helper import (
    MaltiversePluginException,
    MaltiversePluginHelper,
)


class MaltiversePlugin(PluginBase):
    """Maltiverse Plugin class template implementation."""

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
        self.maltiverse_helper = MaltiversePluginHelper(
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
            metadata_json = MaltiversePlugin.metadata
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
        """Pull indicators from Maltiverse plugin."""
        total_skipped_tags = []
        (total_iocs, total_skipped) = (0, 0)

        feeds = self.configuration.get("feed_ids", [])
        other_feeds = self.configuration.get("other_feeds", "").strip()
        if other_feeds:
            feeds += other_feeds.split(",")
        feeds = list(filter(None, map(str.strip, feeds)))

        classifications = self.configuration.get(
            "classifications", CLASSIFICATIONS
        )

        # Ensure unique values
        feeds = list(set(feeds))

        headers = self.maltiverse_helper.get_headers(
            self.configuration.get("api_key")
        )
        for feed in feeds:
            indicators = []
            url = f"{BASE_URL}/collection/" + feed + "/download"
            feed_name = FEEDS.get(feed) if FEEDS.get(feed) else feed
            logger_message = f"fetching indicators from feed '{feed_name}'"
            try:
                response = self.maltiverse_helper.api_helper(
                    url=url,
                    method="GET",
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=logger_message,
                    headers=headers,
                    is_handle_error_required=False,
                )
                if response.status_code == 404 and (
                    "Collection not found" in response.text
                    or "Feed not found" in response.text
                ):
                    logger_message = (
                        f"Feed with ID '{feed}' does not exists "
                        f"on {PLATFORM_NAME}. "
                        "Verify the feed added in 'Other Feeds' "
                        "configuration parameter."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: " f"{logger_message}"
                    )
                    continue

                response = self.maltiverse_helper.handle_error(
                    response, logger_message
                )

                if not response:
                    self.logger.info(
                        f"{self.log_prefix}: "
                        f"No data found in the feed {feed_name}."
                    )
                    continue

                (indicators, page_skipped, skipped_tags) = (
                    self.extract_indicators(
                        response, feed_name, classifications
                    )
                )
                total_skipped_tags.extend(skipped_tags)
                total_iocs += len(indicators)
                total_skipped += page_skipped
                log_msg = (
                    "Successfully fetched "
                    f"{len(indicators)} indicator(s) "
                    f"from feed '{feed_name}'. "
                    f"Total indicator(s) fetched: {total_iocs}. "
                    f"Total indicator(s) skipped: {total_skipped}."
                )

                self.logger.info(f"{self.log_prefix}: " f"{log_msg}")
                if indicators:
                    if hasattr(self, "sub_checkpoint"):
                        yield indicators, None
                    else:
                        yield indicators

            except MaltiversePluginException:
                raise
            except Exception as exp:
                err_msg = f"Unexpected error occurred while {logger_message}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {str(exp)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise MaltiversePluginException(err_msg)
        if total_skipped_tags:
            log_msg = (
                f"Skipped {len(total_skipped_tags)} "
                "tags as they had length greater than 50 "
                "or some unexpected error occurred while "
                "creating tags. "
                f"Skipped Tags - {total_skipped_tags}."
            )
            self.logger.info(
                f"{self.log_prefix}: {log_msg}"
            )

    def create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        for tag in tags:
            tag = tag.strip()
            if self.configuration.get("enable_tagging", "yes") == "no":
                # Enable Tagging is disabled hence add the tag in skipped tag
                # and continue
                skipped_tags.add(tag)
                continue
            try:
                if not tag_utils.exists(tag):
                    tag_utils.create_tag(TagIn(name=tag, color="#ED3347"))
                created_tags.add(tag)
            except ValueError:
                skipped_tags.add(tag)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, tag, exp
                        )
                    ),
                    details=traceback.format_exc(),
                )
                skipped_tags.add(tag)

        return list(created_tags), list(skipped_tags)

    def extract_indicators(
        self, json_response, feed, classifications
    ) -> tuple[list, int]:
        """
        Extract indicators from a given response based on the specified \
        indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicators (list): current indicator list

        Returns:
            Tuple[list[dict], int]: A tuple containing a set of extracted \
                                    indicators and the number of indicators.
        """
        (
            page_unsupported_ioc_type,
            total_page_skip,
            skipped_iocs,
            unknown_classification,
            unselected_classification,
            indicators,
        ) = (0, 0, 0, 0, 0, [])

        skipped_tags = set()

        for registry in json_response:
            if registry.get("classification", "") not in CLASSIFICATIONS:
                unknown_classification += 1
                continue

            if registry.get("classification", "") not in classifications:
                unselected_classification += 1
                continue

            if registry.get("type", "") == "sample":
                current_type = IndicatorType.SHA256
                current_indicator_value = registry.get("sha256", "")
            elif registry.get("type", "") == "ip":
                current_indicator_value = registry.get("ip_addr", "")
                current_type = getattr(
                    IndicatorType, "IPV4", IndicatorType.URL
                )
            elif registry.get("type", "") == "ipv6":
                current_indicator_value = registry.get("ip_addr", "")
                current_type = getattr(
                    IndicatorType, "IPV6", IndicatorType.URL
                )
            elif registry.get("type", "") == "url":
                current_type = IndicatorType.URL
                current_indicator_value = registry.get("url", "")
            elif registry.get("type", "") == "hostname":
                current_type = getattr(
                    IndicatorType, "HOSTNAME", IndicatorType.URL
                )
                current_indicator_value = registry.get("hostname", "")
            else:
                page_unsupported_ioc_type += 1
                continue
            if registry.get("classification", "") == "malicious":
                current_risk = SeverityType.CRITICAL
            elif registry.get("classification", "") == "suspicious":
                current_risk = SeverityType.MEDIUM
            elif registry.get("classification", "") == "neutral":
                current_risk = SeverityType.LOW
            else:
                current_risk = SeverityType.UNKNOWN

            tags = []

            # Extract tags from API response.
            if self.configuration.get("enable_tagging", "yes") == "yes":
                (
                    extracted_tags,
                    curr_bundle_skipped_tags,
                ) = self.create_tags(
                    tags=registry.get("tag", []),
                )

                skipped_tags.update(set(curr_bundle_skipped_tags))
                # Create tags from extracted tags
                # if Enable Tagging is enabled.
                tags += extracted_tags

            try:
                indicators.append(
                    Indicator(
                        value=current_indicator_value,
                        type=current_type,
                        severity=current_risk,
                        firstSeen=datetime.strptime(
                            registry.get("creation_time")
                            or datetime.now().strftime(DATE_FORMAT),
                            DATE_FORMAT,
                        ),
                        lastSeen=datetime.strptime(
                            registry.get("modification_time")
                            or datetime.now().strftime(DATE_FORMAT),
                            DATE_FORMAT,
                        ),
                        tags=tags if tags else [],
                    )
                )
            except (ValidationError, Exception) as error:
                error_message = (
                    "Validation error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while"
                        " creating indicator for Feed "
                        f"{feed}. This record with value "
                        f"'{current_indicator_value}' will be"
                        f" skipped. Error: {error}."
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_iocs += 1

        logger_msg = (
            f"{self.log_prefix}: "
            f"Total {len(indicators)} "
            "indicator(s) fetched from "
            f"Feed '{feed}'."
        )
        if unselected_classification:
            logger_msg += (
                f" {unselected_classification} indicator(s) "
                "will not be stored as the Classification type(s) "
                "not selected in the configuration."
            )
        if unknown_classification:
            logger_msg += (
                f" Skipped {unknown_classification} indicator(s) "
                "as they were from unknown classification."
            )
        if page_unsupported_ioc_type:
            logger_msg += (
                f" Skipped {page_unsupported_ioc_type} indicator(s) "
                "as they were of unsupported type."
            )
        if skipped_iocs:
            logger_msg += (
                f" Skipped {skipped_iocs} indicator(s) "
                "due to some unexpected error."
            )
        self.logger.info(logger_msg)

        total_page_skip = (
            unknown_classification
            + page_unsupported_ioc_type
            + skipped_iocs
            + unselected_classification
        )

        return indicators, total_page_skip, skipped_tags

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
        classifications = configuration.get("classifications", [])
        feed_ids = configuration.get("feed_ids", [])
        other_feeds = configuration.get("other_feeds", "").strip()
        enable_tagging = configuration.get("enable_tagging", "yes").strip()

        validation_err_msg = "Validation error occurred."

        # API Key
        if not api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid API Key provided in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Type of Classification
        if not (
            isinstance(classifications, list)
            and set(classifications).issubset(CLASSIFICATIONS)
        ):
            err_msg = (
                "Invalid Classifications selected in the configuration "
                "parameters. Allowed values are Malicious, "
                "Suspicious and Neutral."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Check empty Feed and Other Feed
        if not (feed_ids or other_feeds):
            error_message = (
                "Both Feeds and Other Feeds can not be empty in configuration "
                "parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {error_message} "
                "Either select a feed from Feeds parameter or "
                "provide Feed IDs in the other Feeds parameter."
            )
            return ValidationResult(success=False, message=error_message)

        # Feed Ids
        if feed_ids and not (
            isinstance(feed_ids, list) and set(feed_ids).issubset(FEEDS.keys())
        ):
            err_msg = (
                "Invalid value provided for Feeds. Select a value from the "
                "available options or if you wish to fetch indicators "
                "from some Other Feeds, keep this parameter blank and "
                "provide the required Feed ID in the parameter 'Other Feeds'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if other_feeds and not isinstance(other_feeds, str):
            err_msg = (
                "Invalid Other Feeds provided "
                "in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        
        total_feeds = []
        if other_feeds:
            total_feeds = feed_ids + other_feeds.split(",")
        
        total_feeds = list(filter(None, map(str.strip, total_feeds)))
        # Ensure unique values
        total_feeds = list(set(total_feeds))

        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif enable_tagging not in ["yes", "no"]:
            err_msg = (
                "Invalid Enable Tagging provided "
                "in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_api_key(api_key, total_feeds)

    def validate_api_key(self, api_key, feeds):
        # Validate API KEy
        try:
            headers = self.maltiverse_helper.get_headers(api_key)
            url = f"{BASE_URL}/collection/1/download"
            logger_msg = "authenticating the API Key"
            response = self.maltiverse_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
            )
            if not (
                response.status_code == 404
                and (
                    "Collection not found" in response.text
                    or "Feed not found" in response.text
                )
            ):
                self.maltiverse_helper.handle_error(response, logger_msg)
            # Verify existence of Feeds
            logger_msg = "validating feed existence"
            self.verify_feed_existence(api_key, feeds)
            self.logger.debug(
                f"{self.log_prefix}: Validation Successful "
                f"for {PLATFORM_NAME} plugin.",
            )
            return ValidationResult(
                success=True, message="Validation Successful."
            )
        except MaltiversePluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"Validation error occurred. {error_msg}"
                    f"Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False, message=f"{error_msg} Check logs for details."
            )

    def verify_feed_existence(self, api_key, feeds):
        """
        Verify the existence of feeds on the Maltiverse platform.

        Args:
            api_key (str): The API key to use for authentication.
            feeds (list): A list of feed IDs to verify.

        Returns:
            None

        Raises:
            MaltiversePluginException: If any of the feeds do not exist \
            on the Maltiverse platform.
        """
        headers = self.maltiverse_helper.get_headers(api_key)
        unknown_feeds = []
        try:
            for feed in feeds:
                logger_msg = f"verifying the existence of feed '{feed}'"
                url = f"{BASE_URL}/feed/{feed}"
                response = self.maltiverse_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="GET",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                if response.status_code == 404 and (
                    "Collection not found" in response.text
                    or "Feed not found" in response.text
                ):
                    unknown_feeds.append(feed)
                else:
                    self.maltiverse_helper.handle_error(response, logger_msg)
            if unknown_feeds:
                error_msg = (
                    f"The following feeds does not "
                    f"exists on the {PLATFORM_NAME} platform - "
                    f"{', '.join(unknown_feeds)}. "
                    "Verify the provided feeds. "
                    "Make sure to provide the ID of the feed."
                )
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Validation error occurred. "
                    f"Error: {error_msg}"
                )
                raise MaltiversePluginException(error_msg)
        except MaltiversePluginException:
            raise
        except Exception as err:
            error_msg = (
                "Unexpected error occurred "
                f"while {logger_msg}. "
                "Verify the Feeds or Other Feeds provided."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    "Validation error occurred. "
                    f"{error_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise MaltiversePluginException(error_msg)
