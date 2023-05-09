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

CTE Feedly plugin.
"""
import json
import os
import traceback
from datetime import datetime, timedelta
from typing import List

from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError
from requests.exceptions import HTTPError

from .lib.feedly.api_client.enterprise.indicators_of_compromise import (
    IoCDownloaderBuilder,
    IoCFormat,
)
from .lib.feedly.api_client.protocol import (
    BadRequestAPIError,
    RateLimitedAPIError,
    UnauthorizedAPIError,
)
from .lib.feedly.api_client.session import FeedlySession

FEEDLY_TO_INDICATOR_TYPE = {
    "url": IndicatorType.URL,
    "domain": IndicatorType.URL,
    "ip-src": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
}

PLATFORM_NAME = "Feedly"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.0.0"
DATE_FORMAT = r"%Y-%m-%dT%H:%M:%S"
ARTICLE_URL_CONSTANT = "Feedly Article URL"
SOURCE_ARTICLE_URL_CONSTANT = "Article Source URL"


class FeedlyException(Exception):
    """Feedly Exception Class."""


class Feedly(PluginBase):
    """CTE Feedly Plugin Class"""

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
        self.log_prefix_with_name = f"{self.log_prefix} [{name}]"

    def _add_client_name(self) -> str:
        """Add Client Name to request plugin make.

        Returns:
            str: String containing the Client Name.
        """
        headers = add_user_agent()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        return "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower(),
            self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
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
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        """Validate auth credentials.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Validate Result.
        """
        start_time = datetime.now()
        token = configuration.get("enterprise_token")
        stream_id = configuration.get("stream_id", "").strip()
        try:

            session = FeedlySession(
                auth=token,
                client_name=self._add_client_name(),
                ssl_verification=self.ssl_validation,
                proxy=self.proxy,
            )

            # Create the MISP IoC downloader builder object
            downloader_builder = IoCDownloaderBuilder(
                session=session, newer_than=start_time, format=IoCFormat.MISP
            )
            downloader = downloader_builder.from_stream_id(stream_id=stream_id)

            downloader.download_all()

        except RateLimitedAPIError as error:
            err_msg = "API Rate limit Exceeded."
            exp_msg = self._remove_secrets(
                configuration=configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}",
                details=exp_traceback,
            )
            return ValidationResult(success=False, message=err_msg)

        except BadRequestAPIError:
            err_msg = "Bad Request. Verify the provided Feedly Stream ID."
            exp_traceback = self._remove_secrets(
                configuration=configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=exp_traceback,
            )
            return ValidationResult(success=False, message=err_msg)

        except UnauthorizedAPIError as error:
            err_msg = (
                "Unauthorized API error occurred. Verify "
                "Feedly Enterprise Access Token provided."
            )
            exp_msg = self._remove_secrets(
                configuration=configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}",
                details=exp_traceback,
            )
            return ValidationResult(success=False, message=err_msg)

        except HTTPError as error:
            err_msg = (
                "HTTP Error occurred. Verify Feedly Stream ID and Feedly"
                " Enterprise Access Token provided."
            )
            exp_msg = self._remove_secrets(
                configuration=configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}",
                details=exp_traceback,
            )
            return ValidationResult(success=False, message=err_msg)

        except Exception as exp:
            err_msg = "Validation error occurred during authentication."
            exp_msg = self._remove_secrets(
                configuration=configuration, error=exp
            )
            exp_traceback = self._remove_secrets(
                configuration=configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}",
                details=exp_traceback,
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        if (
            "stream_id" not in configuration
            or not str(configuration.get("stream_id", "")).strip()
        ):
            err_msg = "Feedly Stream ID is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(configuration.get("stream_id"), str):
            err_msg = "Invalid Feedly Stream ID value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if (
            "enterprise_token" not in configuration
            or not str(configuration.get("enterprise_token", "")).strip()
        ):
            err_msg = "Feedly Enterprise Access Token is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(configuration.get("enterprise_token"), str):
            err_msg = "Invalid Feedly Enterprise Access Token value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if "ioc_types" not in configuration or not configuration.get(
            "ioc_types"
        ):
            err_msg = "Type of IoCs is a required field."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=(
                    "Error: Allowed values are 'MD5 Hash', 'SHA256 Hash',"
                    " 'Domains', 'URLs', and 'IP Addresses'"
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not (
            all(
                ioc_type in FEEDLY_TO_INDICATOR_TYPE.keys()
                for ioc_type in configuration.get("ioc_types")
            )
        ):
            err_msg = "Invalid Type of IoCs value provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=(
                    "Error: Allowed values are 'MD5 Hash', 'SHA256 Hash',"
                    " 'Domains', 'URLs', and 'IP Addresses'"
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not (
            "enable_tagging" in configuration
            and str(configuration.get("enable_tagging", "")).strip()
        ):
            err_msg = "Enable Tagging is a required field."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif configuration.get("enable_tagging") not in ["yes", "no"]:
            err_msg = "Invalid Enable Tagging value provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details="Allowed values are 'Yes' or 'No'.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if "days" not in configuration or configuration.get("days") is None:
            err_msg = "Initial Range is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if (
            not isinstance(configuration.get("days", 0), int)
            or configuration.get("days", 0) < 0
        ):
            err_msg = "Invalid Initial Range value provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_credentials(configuration)

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
            tag_name = tag.get("name", "").strip()
            if self.configuration.get("enable_tagging", "yes") == "no":
                # Enable Tagging is disabled hence add the tag in skipped tag
                # and continue
                skipped_tags.add(tag_name)
                continue
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
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
                    details=traceback.format_exc(),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def _remove_secrets(self, configuration: dict, error) -> str:
        """Remove Secret information from error message or trace back.

        Args:
            configuration (dict): Configuration parameters dictinary.
            error (Any): Error message.

        Returns:
            str: String with removed secret credentials.
        """
        return str(error).replace(
            configuration.get("enterprise_token"),
            "Feedly Enterprise Access Token",
        )

    def pull(self) -> List[Indicator]:
        """Pull IoCs from Feedly.

        Returns:
            List: List of indicators.
        """
        self.logger.info(
            "{}: Pulling IoCs from {} platform for configured"
            " Feedly Stream ID.".format(
                self.log_prefix_with_name, PLATFORM_NAME
            )
        )
        token = self.configuration.get("enterprise_token")
        stream_id = self.configuration.get("stream_id", "").strip()

        indicator_list = []
        skipped_tags = set()

        try:
            # Create a Feedly client session
            session = FeedlySession(
                auth=token,
                client_name=self._add_client_name(),
                ssl_verification=self.ssl_validation,
                proxy=self.proxy,
            )

            start_time = self.last_run_at
            if not start_time:
                self.logger.info(
                    "{}: This is the initial data fetch since checkpoint "
                    "is empty. Querying indicators for last {} days.".format(
                        self.log_prefix_with_name,
                        self.configuration.get("days"),
                    )
                )
                start_time = datetime.now() - timedelta(
                    days=int(self.configuration.get("days"))
                )

            # Create the MISP IoC downloader builder object, and
            # limit it to the number of days the user specified
            # Usually newer_than will be the datetime of the last fetch
            downloader_builder = IoCDownloaderBuilder(
                session=session, newer_than=start_time, format=IoCFormat.MISP
            )

            # Fetch IoCs from Feedly based on the stream_id that captured them
            downloader = downloader_builder.from_stream_id(stream_id=stream_id)

            for bundle in downloader.stream_bundles():
                # Iterate through each stream bundles.
                ioc_counter = 0

                for event in bundle.get("response", []):
                    indicators = []  # Indicator list for each Event.
                    # Iterate through response.
                    article_urls = {
                        ARTICLE_URL_CONSTANT: [],
                        SOURCE_ARTICLE_URL_CONSTANT: [],
                    }  # Dictionary which store article urls.
                    attributes = event.get("Event", {}).get("Attribute", [])
                    article_source_url = ""

                    # Iterate through Attributes to extract Article URLs.
                    for attribute in attributes:
                        attribute_type = attribute.get("type")
                        if attribute_type == "link":
                            link = attribute.get("value")
                            if link.__contains__("https://feedly.com"):
                                article_urls[ARTICLE_URL_CONSTANT].append(link)
                            else:
                                article_urls[
                                    SOURCE_ARTICLE_URL_CONSTANT
                                ].append(link)
                                article_source_url = link

                        elif attribute_type in self.configuration.get(
                            "ioc_types"
                        ):
                            ioc = {
                                "value": attribute.get("value"),
                                "type": FEEDLY_TO_INDICATOR_TYPE.get(
                                    attribute_type
                                ),
                                "comments": "Category: {}".format(
                                    attribute.get("category")
                                ),
                            }

                            if attribute.get("timestamp") is not None:
                                timestamp = int(attribute.get("timestamp"))
                                first_seen = datetime.fromtimestamp(
                                    timestamp
                                ).strftime(DATE_FORMAT)
                                ioc.update(
                                    {
                                        "firstSeen": first_seen,
                                        "lastSeen": first_seen,
                                    }
                                )
                            indicators.append(ioc)

                    tags = []

                    # Extract tags from API response.
                    (
                        extracted_tags,
                        curr_bundle_skipped_tags,
                    ) = self.create_tags(
                        tags=event.get("Event", {}).get("Tag", []),
                    )

                    skipped_tags.update(set(curr_bundle_skipped_tags))
                    # Create tags from extracted tags
                    # if Enable Tagging is enabled.
                    if (
                        self.configuration.get("enable_tagging", "yes")
                        == "yes"
                    ):
                        tags += extracted_tags

                    # Iterate through indicators list to add comments,
                    # tags and extendedInformation and create final.
                    # indicator list
                    for indicator in indicators:
                        comments = [
                            indicator.get("comments"),
                            "{}: {}".format(
                                ARTICLE_URL_CONSTANT,
                                ", ".join(
                                    article_urls.get(ARTICLE_URL_CONSTANT, [])
                                ),
                            ),
                            "{}: {}".format(
                                SOURCE_ARTICLE_URL_CONSTANT,
                                ", ".join(
                                    article_urls.get(
                                        SOURCE_ARTICLE_URL_CONSTANT, []
                                    )
                                ),
                            ),
                            "Tags: {}".format(
                                extracted_tags + curr_bundle_skipped_tags
                            ),
                        ]
                        indicator.update(
                            {
                                "comments": ", ".join(comments),
                                "tags": tags,
                                "extendedInformation": article_source_url,
                            }
                        )

                        try:
                            indicator_list.append(Indicator(**indicator))
                            ioc_counter += 1
                        except ValidationError as error:
                            self.logger.error(
                                message=(
                                    "{}: Validation error occurred while "
                                    " creating indicator for {}.".format(
                                        self.log_prefix_with_name,
                                        indicator.get("value"),
                                    )
                                ),
                                details=str(error),
                            )

                self.logger.info(
                    (
                        "{}: Successfully fetched {} IoCs in current stream "
                        "bundle. Total {} IoCs fetched so far in current pull "
                        "cycle for configured {} Stream ID.".format(
                            self.log_prefix_with_name,
                            ioc_counter,
                            len(indicator_list),
                            PLATFORM_NAME,
                        )
                    )
                )
            if (
                skipped_tags
                and self.configuration.get("enable_tagging", "yes") == "yes"
            ):
                self.logger.warn(
                    (
                        "{}: Skipped following tags(s) because they were "
                        "longer than expected size or due to some other "
                        "exceptions that occurred while creation of "
                        "them: {}".format(
                            self.log_prefix_with_name,
                            list(skipped_tags),
                        )
                    )
                )

            self.logger.info(
                "{}: Successfully fetched {} IoCs"
                " from {} platform.".format(
                    self.log_prefix_with_name,
                    len(indicator_list),
                    PLATFORM_NAME,
                )
            )
            return indicator_list

        except RateLimitedAPIError as error:
            err_msg = "API Rate Limit Exceeded."
            exp_msg = self._remove_secrets(
                configuration=self.configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=self.configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}.",
                details=exp_traceback,
            )
            raise FeedlyException(exp_msg)

        except BadRequestAPIError:
            err_msg = (
                "Bad Request. Verify the provided Feedly Stream ID"
                " in configuration parameters."
            )
            exp_traceback = self._remove_secrets(
                configuration=self.configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix_with_name}: {err_msg}",
                details=exp_traceback,
            )
            raise FeedlyException(err_msg)

        except UnauthorizedAPIError as error:
            err_msg = (
                "Unauthorized API error occurred. Verify "
                "Feedly Enterprise Access Token provided."
            )
            exp_msg = self._remove_secrets(
                configuration=self.configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=self.configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message="{}: {} Error: {}".format(
                    self.log_prefix_with_name, err_msg, exp_msg
                ),
                details=exp_traceback,
            )
            raise FeedlyException(exp_msg)

        except HTTPError as error:
            err_msg = (
                "HTTP Error occurred. Verify Feedly Stream ID and "
                "Feedly Enterprise Access Token provided in "
                "configuration parameters."
            )
            exp_msg = self._remove_secrets(
                configuration=self.configuration, error=error
            )
            exp_traceback = self._remove_secrets(
                configuration=self.configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp_msg}",
                details=exp_traceback,
            )
            raise FeedlyException(exp_msg)

        except Exception as exp:
            err_msg = "Unexpected error occurred while fetching indicators."
            exp_msg = self._remove_secrets(
                configuration=self.configuration, error=exp
            )
            exp_traceback = self._remove_secrets(
                configuration=self.configuration, error=traceback.format_exc()
            )
            self.logger.error(
                message="{}: {} Error: {}".format(
                    self.log_prefix_with_name, err_msg, exp_msg
                ),
                details=exp_traceback,
            )
            raise FeedlyException(exp_msg)
