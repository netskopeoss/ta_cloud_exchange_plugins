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
"""

"""Mimecast Plugin implementation to push and pull the data from Mimecast."""

import csv
import base64
import hashlib
import hmac
import uuid
import traceback
from urllib.parse import urlparse
from typing import Dict, List
from datetime import datetime, timedelta

from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from .utils.mimecast_constants import (
    MAX_REQUEST_URL,
    MAX_CREATE_URL,
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    GET_TYPE_FROM_MAPPING,
    URL_OPERATION_TYPE,
    HASH_OPERATION_TYPE,
    PUSH_HASH_BATCH_SIZE,
    PULL_URL_BATCH_SIZE,
    FETCH_HASHES_ENDPOINT,
    FETCH_URL_ENDPOINT,
    PUSH_HASH_ENDPOINT,
    GET_ACCOUNT_ENDPOINT,
    DECODE_URL_ENDPOINT,
    PUSH_URL_ENDPOINT,
    MALWARE_TYPE,
    FEED_TYPES,
    MALWARE_TYPES,
)

from .utils.mimecast_helper import MimecastPluginHelper, MimecastPluginException


class MimecastPlugin(PluginBase):
    """The Mimecast plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
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
        self.mimecast_helper = MimecastPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            configuration=self.configuration,
            plugin_name=PLUGIN_NAME,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MimecastPlugin.metadata
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

    def _parse_errors(self, failures):
        """Parse the error messages from Mimecast response."""
        messages = []
        for failure in failures:
            for error in failure.get("errors", []):
                messages.append(error.get("message"))
        return messages

    def _parse_csv(
        self, raw_csv: str, indicator_key, pull_location: str
    ) -> List[Indicator]:
        """Parse given raw CSV string based on given feed type."""
        indicators = []
        md5_count = 0
        sha256_count = 0
        raw_csv = raw_csv.split("\n")

        # This means no indicator data is returned
        if len(raw_csv) == 1:
            return indicators

        reader = csv.DictReader(raw_csv, delimiter="|")
        for row in reader:
            if "MD5" in indicator_key:
                indicator = row.get("MD5")
                if indicator:
                    indicators.append(
                        Indicator(
                            value=indicator,
                            type=IndicatorType.MD5,
                            comments=f"Sent from {row.get('SenderAddress')}"
                            if row.get("SenderAddress")
                            else "",
                        )
                    )
                    md5_count += 1
            if "SHA256" in indicator_key:
                indicator = row.get("SHA256")
                if indicator:
                    indicators.append(
                        Indicator(
                            value=indicator,
                            type=IndicatorType.SHA256,
                            comments=f"Sent from {row.get('SenderAddress')}"
                            if row.get("SenderAddress")
                            else "",
                        )
                    )
                    sha256_count += 1

        self.logger.debug(
            f"{self.log_prefix}: Completed fetching hashes from {pull_location}."
            f" Pull Stats - SHA256: {sha256_count}, MD5: {md5_count}. "
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched Hashes {indicator_key} from {pull_location}."
            f" Total hashes fetched: {len(indicators)}."
        )
        return indicators

    def get_rewritten_urls(self, start_time) -> List[Dict]:
        """Return rewritten urls from mimecast.

        Args:
            start_time (str): start time from where you want the data.

        Returns:
            List[Dict]: return list of dictionary of rewritten url from
            mimecast.
        """
        # REWRITTEN URL
        headers = self.mimecast_helper._get_auth_headers(
            self.configuration, FETCH_URL_ENDPOINT
        )
        rewritten_urls = []
        page_token = ""
        start_time = start_time.replace(microsecond=0)
        body = {
            "meta": {
                "pagination": {
                    "pageSize": PULL_URL_BATCH_SIZE,
                    "pageToken": page_token,
                }
            },
            "data": [
                {
                    "from": f"{start_time.astimezone().isoformat()}",
                    "scanResult": "malicious"
                }
            ],
        }
        page_count = 0
        try:
            while True:
                page_count += 1
                log_msg = f"fetching page {page_count} of rewritten URLs"
                response = self.mimecast_helper.api_helper(
                    logger_msg=log_msg,
                    url_endpoint=FETCH_URL_ENDPOINT,
                    method="POST",
                    retry=True,
                    headers=headers,
                    json_params=body,
                    is_handle_error_required=True,
                )
                if failures := response.get("fail", []):
                    error_msg = (
                        f"Error occurred while {log_msg}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_msg} "
                        "Error: " + ",".join(self._parse_errors(failures))
                    )
                    raise MimecastPluginException(
                        error_msg
                    )
                elif response.get("data", []):
                    rewritten_urls.extend(
                        single_response["url"]
                        for single_response in response.get("data", [{}])[0].get(
                            "clickLogs", []
                        )
                        if single_response.get("url", None) not in [" ", None]
                    )
                page_token = response.get("meta", {}).get("pagination", {}).get("next", None)
                body["meta"]["pagination"]["pageToken"] = page_token
                if not page_token:
                    return rewritten_urls
        except MimecastPluginException as err:
            raise MimecastPluginException(err)

    def make_indicators(self, indicators_data) -> List[Indicator]:
        """Make netskope indicators from indicator data.

        Args:
            indicators_data (List[Dict]): List of dictionary contain url info.

        Raises:
            requests.exceptions.HTTPError: Raise error while getting response.

        Returns:
            List[Indicator]: Returns list of indicators.
        """
        indicators = []
        total_invalid_iocs = 0
        total_valid_iocs = 0
        page = 0
        headers = self.mimecast_helper._get_auth_headers(
            self.configuration, DECODE_URL_ENDPOINT
        )
        for index in range(0, len(indicators_data), MAX_REQUEST_URL):
            invalid_ioc_for_batch = 0
            valid_ioc_for_batch = 0
            body = {
                "data": indicators_data[index: index + MAX_REQUEST_URL]
            }
            page += 1
            response = self.mimecast_helper.api_helper(
                logger_msg=f"decoding URLs batch {page}",
                url_endpoint=DECODE_URL_ENDPOINT,
                method="POST",
                retry=True,
                headers=headers,
                json_params=body,
                is_handle_error_required=True,
            )
            if response.get("data", []):
                for urls_info in response.get("data", []):
                    try:
                        indicators.append(
                            Indicator(
                                value=urls_info["url"],
                                type=IndicatorType.URL,
                            )
                        )
                        valid_ioc_for_batch += 1
                    except Exception:
                        invalid_ioc_for_batch += 1

            if response.get("fail", []):
                for urls_info in response.get("fail", []):
                    if not urls_info.get("errors", []):
                        try:
                            indicators.append(
                                Indicator(
                                    value=urls_info.get("key", "").get("url", ""),
                                    type=IndicatorType.URL,
                                )
                            )
                        except Exception:
                            invalid_ioc_for_batch += 1
                    else:
                        invalid_ioc_for_batch += 1
            total_invalid_iocs += invalid_ioc_for_batch
            total_valid_iocs += valid_ioc_for_batch
            self.logger.info(
                f"{self.log_prefix}: Total URLs fetched for batch {page}: "
                f"{valid_ioc_for_batch}. Total URL indicator fetched: {total_valid_iocs}."
            )
        if total_invalid_iocs != 0:
            self.logger.info(
                f"{self.log_prefix}: {total_invalid_iocs} invalid URLs found while fetching Malsites from "
                f"{PLUGIN_NAME}, hence skipping."
            )
        return indicators

    def get_decoded_urls(self, rewritten_urls) -> List[Indicator]:
        """Return decoded url from rewritten url.

        Args:
            rewritten_urls (List): List of rewritten url.

        Returns:
            List[Indicator]: Return list of Indicators.
        """
        indicators = []
        indicators_data = [{"url": url} for url in rewritten_urls]
        try:
            indicators += self.make_indicators(indicators_data)
            return indicators
        except MimecastPluginException:
            raise
        except Exception as err:
            error_msg = (
                "Error occurred while decoding the URLs. "
                f"Error: {err}"
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            raise MimecastPluginException(error_msg)

    def pull_hashes(self, start_time: datetime, pull_location: str) -> List[Indicator]:
        """Pull Hashes form Malware Customer or Malware Grid."""
        headers = self.mimecast_helper._get_auth_headers(
            self.configuration, FETCH_HASHES_ENDPOINT
        )
        start_time = start_time.replace(microsecond=0)
        indicators = []
        logger_msg = f"pulling hashes from {pull_location}"
        body = {
            "data": [
                {
                    "fileType": "csv",
                    "start": f"{start_time.astimezone().isoformat()}",
                    "feedType": MALWARE_TYPE.get(pull_location),
                }
            ]
        }
        try:
            response = self.mimecast_helper.api_helper(
                logger_msg=logger_msg,
                url_endpoint=FETCH_HASHES_ENDPOINT,
                method="POST",
                retry=True,
                headers=headers,
                json_params=body,
                is_handle_error_required=True,
            )
            if response.status_code == 200:
                try:
                    indicators += self._parse_csv(
                        response.text,
                        self.configuration.get("indicator_type", ["MD5", "SHA256"]),
                        pull_location
                    )
                except Exception as ex:
                    error_msg = (
                        f"Error occurred while parsing CSV while {logger_msg}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_msg} "
                        f"Error: {str(ex)}",
                        details=traceback.format_exc()
                    )
                    raise MimecastPluginException(error_msg)
            return indicators
        except MimecastPluginException:
            raise

    def pull(self) -> List[Indicator]:
        """Pull the indicators from Mimecast."""
        # Get start time based on checkpoint
        if not self.last_run_at:
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch for indicator "
                f"feed since "
                f"checkpoint is empty. Querying indicators for last "
                f"{self.configuration.get('days')} day(s)."
            )
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
        else:
            start_time = self.last_run_at
        indicators = []
        feed_types = self.configuration.get("feed_type", [])
        try:
            if "malware_customer" in feed_types:
                indicators += self.pull_hashes(start_time, "Malware Customer")
            if "malware_grid" in feed_types:
                indicators += self.pull_hashes(start_time, "Malware Grid")
            if "malsite" in feed_types:
                rewritten_urls = self.get_rewritten_urls(start_time)
                indicators += self.get_decoded_urls(rewritten_urls)
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(indicators)} indicator(s) for "
                f"{PLUGIN_NAME} with feed types - {feed_types}."
            )
            return indicators
        except MimecastPluginException as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while pulling indicators from {PLUGIN_NAME}. "
                f"{err}",
                details=traceback.format_exc()
            )
            raise MimecastPluginException(err)
        except Exception as err:
            error_msg = (
                f"{self.log_prefix}: Unexpected error occurred while pulling indicators from {PLUGIN_NAME}."
                f"Error: {err}"
            )
            self.logger.error(
                error_msg,
                details=traceback.format_exc()
            )
            raise MimecastPluginException(err)

    def push_hashes(self, operation_type, hashes):
        body = {
            "data": [
                {
                    "hashList": [],
                    "operationType": operation_type,
                }
            ]
        }
        headers = self.mimecast_helper._get_auth_headers(
            self.configuration,
            PUSH_HASH_ENDPOINT
        )
        # Mimecast only supports "push" in batch of 1000 indicators at a
        # time
        push_page_count = 0
        successful_push_count = 0
        failures_count = 0
        failure_msg_list = []
        for pos in range(0, len(hashes), PUSH_HASH_BATCH_SIZE):
            successful_batch_push_count = 0
            failures_batch_count = 0
            push_page_count += 1
            body["data"][0]["hashList"] = hashes[
                pos : pos + PUSH_HASH_BATCH_SIZE  # noqa
            ]
            response = self.mimecast_helper.api_helper(
                logger_msg=f"pushing batch {push_page_count} of hashlist",
                url_endpoint=PUSH_HASH_ENDPOINT,
                method="POST",
                retry=True,
                headers=headers,
                json_params=body,
                is_handle_error_required=True,
            )
            failures = response.get("fail", [])
            data = response.get("data", [])
            if data:
                successful_batch_push_count += data[0].get("hashCount", 0)
            if failures:
                failures_batch_count += len(failures)
                failure_msg_list.extend(
                    self._parse_errors(failures)
                )
            successful_push_count += successful_batch_push_count
            failures_count += failures_batch_count
            self.logger.debug(
                f"{self.log_prefix}: Successfully shared {successful_batch_push_count} Hashes for batch {push_page_count}. "
                f"Total Hashes shared: {successful_push_count}."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully shared {successful_push_count} Hashes."
        )
        if failures_count:
            self.logger.info(
                f"{self.log_prefix}: Failed to share {failures_count} "
                f"hashes to {PLUGIN_NAME}. "
                f"Error List: {failure_msg_list}"
            )

    def push_urls(self, indicators_data):
        invalid_urls = 0
        already_exists = 0
        unknown_error = 0
        headers = self.mimecast_helper._get_auth_headers(
            self.configuration, PUSH_URL_ENDPOINT
        )
        batch_count_url = 0
        successful_push_count = 0
        failures_count = 0
        failure_msg_list = []
        for index in range(0, len(indicators_data), MAX_CREATE_URL):
            successful_batch_push_count = 0
            failures_batch_count = 0
            batch_count_url += 1
            json_data = {
                "data": indicators_data[index: index + MAX_CREATE_URL]
            }
            response = self.mimecast_helper.api_helper(
                logger_msg=f"pushing URL batch {batch_count_url}",
                url_endpoint=PUSH_URL_ENDPOINT,
                method="POST",
                retry=True,
                headers=headers,
                json_params=json_data,
                is_handle_error_required=True,
            )
            data = response.get("data", [])
            failures = response.get("fail", [])
            if data:
                successful_batch_push_count += len(data)
            if failures:
                failures_batch_count += len(failures)
                for urls_info in response.get("fail", []):
                    errors = urls_info.get("errors", [])
                    if not errors:
                        continue
                    elif "The URL is invalid" in errors[0].get(
                        "message", " "
                    ):
                        invalid_urls += 1
                    elif errors[0].get("code", " ") == "err_managed_url_exists_code":
                        already_exists += 1
                    else:
                        unknown_error += 1
                        failure_msg_list.extend(
                            self._parse_errors(failures)
                        )
            successful_push_count += successful_batch_push_count
            failures_count += failures_batch_count
            self.logger.info(
                f"{self.log_prefix}: Successfully shared {successful_batch_push_count} URLs for batch {batch_count_url}. "
                f"Total URLs shared: {successful_push_count}."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully shared {successful_push_count} URLs."
        )
        if failures_count:
            log_msg = (
                f"Failed to share {failures_count} URL(s) to {PLUGIN_NAME}. "
                f"Invalid URL(s): {invalid_urls}, Already Existing URL(s): {already_exists}."
            )
            if unknown_error:
                log_msg += (
                    f" Failed to create {unknown_error} URL(s) on {PLUGIN_NAME} - "
                    "please check with Mimecast Admin for details."
                    f" Failure message list: {failure_msg_list}."
                )
            self.logger.info(
                f"{self.log_prefix}: {log_msg}"
            )

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push the given list of indicators to Mimecast."""
        # First check if push is enabled
        action_label = action_dict.get("label", "")
        action_value = action_dict.get("value", "")
        action_parameters = action_dict.get("parameters", {})
        operation_type = action_parameters.get("operation_type", "")
        if action_value == "operation":
            # Prepare list of only file hashes
            hashes = []
            for indicator in indicators:
                if indicator.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                    hashes.append(
                        {
                            "hash": indicator.value,
                            "provider": "NetskopeCE",
                            # Length of description is required to be <= 20 on
                            # Mimecast.
                            "description": indicator.comments
                            if len(indicator.comments) <= 20
                            else "",
                        }
                    )

            # If all the indicators are of type other than file hash, skip.
            if len(hashes) == 0:
                log_msg = (
                    " Found no indicators eligible for pushing to "
                    f"{PLUGIN_NAME}. Only file hashes are supported for action "
                    f"'{action_label}' hence action will be skipped."
                )
                self.logger.info(
                    f"{self.log_prefix}: {log_msg}"
                )
                return PushResult(
                    success=True,
                    message=log_msg,
                )
            self.logger.info(
                f"{self.log_prefix}: Trying to share {len(hashes)} Hashes found in the business rule."
            )
            self.push_hashes(operation_type, hashes)
            return PushResult(
                success=True,
                message=f"Successfully executed push method for "
                f"action '{action_label}' for plugin {PLUGIN_NAME}.",
            )

        # PUSH URL
        elif action_value == "managed_url":
            indicators_data = []
            total_ioc_to_push = 0
            for indicator in indicators:
                if indicator.type == IndicatorType.URL and len(
                    indicator.value
                ):
                    total_ioc_to_push += 1
                    indicators_data.append(
                        {
                            "url": indicator.value,
                            "action": action_dict.get("parameters").get(
                                "action_type"
                            ),
                        }
                    )
            if not total_ioc_to_push:
                log_msg = (
                    f"{self.log_prefix}: Found no indicators eligible for pushing to "
                    f"{PLUGIN_NAME}. Only URLs are supported for action "
                    f"'{action_label}' hence action will be skipped."
                )
                self.logger.info(
                    f"{self.log_prefix}: {log_msg}"
                )
                return PushResult(
                    success=True,
                    message=log_msg
                )
            self.logger.info(
                f"{self.log_prefix}: Trying to share {total_ioc_to_push} URL(s) found in the business rule."
            )
            self.push_urls(indicators_data)
            return PushResult(
                success=True,
                message=f"Successfully executed push method for "
                f"action '{action_label}' for plugin {PLUGIN_NAME}.",
            )


    def _validate_credentials(
        self, configuration: dict, logger_msg
    ):
        """Validate credentials by making REST API call."""
        try:
            headers = self.mimecast_helper._get_auth_headers(
                configuration, GET_ACCOUNT_ENDPOINT
            )
            response = self.mimecast_helper.api_helper(
                logger_msg=logger_msg,
                configuration=configuration,
                url_endpoint=GET_ACCOUNT_ENDPOINT,
                method="POST",
                retry=False,
                headers=headers,
                json_params={"data": []},
                is_handle_error_required=True,
            )
            if response.get("meta", {}).get("status", "") == 200:
                failures = response.get("fail", [])
                data = response.get("data", [])
                if not failures and data:
                    packages = data[0].get("packages", [])
                    return packages
                api_error = ', '.join(self._parse_errors(failures))
                error_msg = (
                    f"Error occurred while {logger_msg}. Check the credentials provided."
                )
                if api_error:
                    error_msg += f" API error mesaage: {api_error}"
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}"
                )
                raise MimecastPluginException(error_msg)
        except MimecastPluginException:
            raise
        except Exception as ex:
            error_msg = (
                f"Unexpected error ocurred while {logger_msg}. "
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg} "
                f"Error: {ex}",
                details=str(traceback.format_exc())
            )
            raise MimecastPluginException(error_msg)

    def check_range(self, field_value, min, max):
        if field_value < min or field_value > max:
            return False
        return True

    def _validate_url(self, url: str) -> bool:
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )


    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configurations."""
        validation_msg = "Validation error occurred."

        url = configuration.get("url", "").strip().rstrip("/")
        if not url:
            error_msg = (
                "Base URL is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(url, str) or not self._validate_url(url):
            error_msg = (
                "Invalid Base URL found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        
        app_id = configuration.get("app_id", "").strip()
        if not app_id:
            error_msg = (
                "Application ID is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        
        elif not isinstance(app_id, str):
            error_msg = (
                "Invalid Application ID found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        
        app_key = configuration.get("app_key", "")
        if not app_key:
            error_msg = (
                "Application Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(app_key, str):
            error_msg = (
                "Invalid Application Key found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )

        access_key = configuration.get("access_key")
        if not access_key:
            error_msg = (
                "Access Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(access_key, str):
            error_msg = (
                "Invalid Access Key found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        
        secret_key = configuration.get("secret_key")
        if not secret_key:
            error_msg = (
                "Secret Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(secret_key, str):
            error_msg = (
                "Invalid Secret Key found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )

        feed_type = configuration.get("feed_type", [])
        if not feed_type:
            error_msg = (
                "Indicator Feed Type is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(feed_type, list) or not (
            all(
                feed in FEED_TYPES.keys()
                for feed in feed_type
            )
        ):
            error_msg = (
                "Invalid Indicator Feed Type found in the configuration parameter. "
                f"Allowed values are: {', '.join(FEED_TYPES.values())}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )

        indicator_type = configuration.get("indicator_type", [])
        if not indicator_type:
            error_msg = (
                "'Types of Malware to Pull' is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(indicator_type, list):
            error_msg = (
                "Invalid value for 'Types of Malware to Pull' found in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        elif not isinstance(indicator_type, list) or not (
            all(
                malware_type in MALWARE_TYPES
                for malware_type in indicator_type
            )
        ):
            error_msg = (
                "Invalid value for 'Type of Malware to Pull' found in the configuration parameter. "
                f"Allowed values are: {', '.join(MALWARE_TYPES)}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_msg} {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range (in days) is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not isinstance(days, int) or days < 0 or days > 365:
            err_msg = (
                "Invalid Initial Range (in days) provided in configuration parameter."
                " Make sure the initial range is between 1 - 365 days."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        try:

            self._validate_credentials(configuration, "validating credentials")
            return ValidationResult(
                    success=True,
                    message="Validation successful"
                )
        except MimecastPluginException as error:
            return ValidationResult(
                success=False,
                message=str(error)
            )
        except Exception as err:
            err_msg = (
                "Error occurred while validating configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Perform Operation (applicable for File hashes(SHA256, MD5)",
                value="operation"
            ),
            ActionWithoutParams(
                label="Create Managed URL (applicable for URLs)",
                value="managed_url"
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        action_value = action.value
        operation_type = action.parameters.get(
            "operation_type", ""
        )
        action_type = action.parameters.get(
            "action_type", ""
        )
        if action_value not in ["operation", "managed_url"]:
            return ValidationResult(
                success=False,
                message="Unsupported action provided."
            )
        packages = self._validate_credentials(
            self.configuration,
            "validating credentials for sharing MD5 or SHA256"
        )
        if (
            action_value == "operation"
            and "BYO: Threat Intelligence [1089]" not in packages
        ):
            error_msg = (
                "'Bring Your Own Threat Intel' package is not enabled "
                "in the configured account, hence Hashes cannot be shared."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )
        if action_value == "operation" and not operation_type:
            error_msg = (
                "Operation Type is a required parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )
        if action_value == "operation" and operation_type not in HASH_OPERATION_TYPE.keys():
            error_msg = (
                "Invalid Operation Type provided. Allowed values are "
                f"{', '.join(HASH_OPERATION_TYPE)}."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )
        if action_value == "managed_url" and not action_type:
            error_msg = (
                "Action Type is a required parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )
        if action_value == "managed_url" and action_type not in URL_OPERATION_TYPE.values():
            error_msg = (
                "Invalid value of Action Type provided. "
                "Allowed values are "
                f"{', '.join(URL_OPERATION_TYPE.keys())}."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "operation":
            choice_list = [
                {"key": key, "value": value}
                for key, value in HASH_OPERATION_TYPE.items()
            ]
            return [
                {
                    "label": "Operation Type",
                    "key": "operation_type",
                    "type": "choice",
                    "choices": choice_list,
                    "mandatory": True,
                    "default": choice_list[0]["value"],
                    "description": "Perform the selected action on the batch of file hash indicators "
                    "matched in the business rule. "
                    "For example, a file-hash can be added with a BLOCK "
                    "action to prevent the delivery "
                    "of a message with an attachment matching that file-hash.",
                }
            ]
        elif action.value == "managed_url":
            choice_list = [
                {"key": key, "value": value}
                for key, value in URL_OPERATION_TYPE.items()
            ]
            return [
                {
                    "label": "Action Type",
                    "key": "action_type",
                    "type": "choice",
                    "choices": choice_list,
                    "mandatory": True,
                    "default": choice_list[0]["value"],
                    "description": "Perform the selected action on the batch of URL indicators "
                    "matched in the business rule. "
                    "For example, a URL can be black listed with a BLOCK "
                    "action type and white listed with PERMIT action type.",
                }
            ]
