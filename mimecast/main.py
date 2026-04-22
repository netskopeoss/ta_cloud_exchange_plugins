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

Mimecast Plugin implementation to push and pull the data from Mimecast."""

import csv
import traceback
from dateutil import parser
from typing import Dict, Generator, List, Tuple, Union
from datetime import datetime, timedelta
from pydantic import ValidationError
from urllib.parse import urlparse

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
from netskope.common.api import __version__ as CE_VERSION
from packaging import version
from .utils.mimecast_constants import (
    GET_ACCOUNT_ENDPOINT,
    MAX_REQUEST_URL,
    MAX_CREATE_URL,
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    URL_MATCH_TYPE,
    URL_OPERATION_TYPE,
    HASH_OPERATION_TYPE,
    PUSH_HASH_BATCH_SIZE,
    PULL_URL_BATCH_SIZE,
    FETCH_HASHES_ENDPOINT,
    FETCH_URL_ENDPOINT,
    PUSH_HASH_ENDPOINT,
    DECODE_URL_ENDPOINT,
    PUSH_URL_ENDPOINT,
    GET_URL_ENDPOINT,
    DELETE_URL_ENDPOINT,
    MALWARE_TYPE,
    FEED_TYPES,
    MALWARE_TYPES,
    INTEGER_THRESHOLD,
    RETRACTION,
    PREFIX_IOC_SOURCE,
    SEPARATOR,
    RETRACTION_BATCH,
    QUOTA_ERROR,
    MAXIMUM_CE_VERSION,
    VALIDATION_ERROR_MSG,
    ACTION_TYPES,
    MAX_FAILURE_COUNT_THRESHOLD
)

from .utils.mimecast_helper import (
    MimecastPluginHelper,
    MimecastPluginException,
    QuotaNotAvailableException
)


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
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.retraction_batch = RETRACTION_BATCH
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.mimecast_helper = MimecastPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.total_invalid_hashes = 0

    def _validate_url(self, url: str) -> bool:
        """Validate URL using urlparse.
        
        Args:
            url (str): URL to validate
            
        Returns:
            bool: True if URL is valid, False otherwise
        """
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url.strip())
            return (
                parsed.scheme.strip() != ""
                and parsed.netloc.strip() != ""
            )
        except Exception:
            return False

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

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        return self.storage if self.storage is not None else {}

    def get_bearer_token_and_storage(
        self,
        configuration: Dict,
        is_validation: bool = False,
        is_retraction: bool = False,
    ) -> Tuple[Dict, Dict]:
        """Get headers with bearer token and storage.

        Args:
            configuration (Dict): Configuration.
            is_validation (bool, optional): Is validation. Defaults to False.
            is_retraction (bool, optional): Is retraction. Defaults to False.

        Returns:
            Tuple[Dict, Dict]: Headers with Authorization and storage.
        """
        storage = self._get_storage()

        # Get auth headers which will handle token caching internally
        auth_headers = self.mimecast_helper._get_auth_headers(
            proxy=self.proxy,
            verify=self.ssl_validation,
            configuration=configuration,
            storage=storage,
            is_validation=is_validation,
            is_retraction=is_retraction,
        )
        return auth_headers, storage

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
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

    def _parse_errors(self, failures: List[Dict]) -> set:
        """Parse the error messages from Mimecast response.

        Args:
            failures (List[Dict]): List of dictionaries \
                containing error messages.

        Returns:
            set: Set of unique error messages.
        """
        messages = set()
        for failure in failures:
            for error in failure.get("errors", []):
                error_msg = error.get("message", "")
                if error_msg:
                    messages.add(error_msg)
                    if QUOTA_ERROR in error_msg:
                        err_msg = (
                            "Quota not available error occurred"
                            f" while making request to {PLUGIN_NAME}"
                            f" platform. Error: {error_msg}"
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(list(messages)),
                        )
                        raise QuotaNotAvailableException(err_msg)
        return messages
    
    def get_rewritten_urls(
        self,
        start_time,
        storage: Dict,
        pull_location="Malsite",
        is_retraction: bool = False
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Return rewritten urls from mimecast.

        Args:
            start_time (str): Start time from where you want the data. This
                should be in ISO 8601 format.
            pull_location (str, optional): The location to pull the url
                indicators from.
            is_retraction (bool, optional): Whether to pull retraction urls.
                Defaults to False.

        Returns:
            List[Dict]: Return list of dictionary of rewritten url from
            mimecast.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Pulling URL indicator(s) from "
            f"{PLUGIN_NAME} platform using checkpoint: {start_time}"
        )
        # Get headers and storage once
        headers, storage = self.get_bearer_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
            is_retraction=is_retraction,
        )

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
                    "scanResult": "malicious",
                    "oldestFirst": True
                }
            ],
        }
        page_count = 1
        fetch_url_endpoint = self.mimecast_helper.build_url(
            FETCH_URL_ENDPOINT, self.configuration
        )
        try:
            while True:
                log_msg = f"pulling rewritten URLs of page {page_count}"
                response = self.mimecast_helper.api_helper(
                    url=fetch_url_endpoint,
                    method="POST",
                    headers=headers,
                    json=body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=log_msg,
                    is_retraction=is_retraction
                )
                if failures := response.get("fail", []):
                    error_msg = f"Error occurred while {log_msg}."
                    parsed_errors = self._parse_errors(failures)
                    error_details = ", ".join(list(parsed_errors)) if parsed_errors else "No error details available"
                    
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_msg}",
                        details=error_details
                    )
                    raise MimecastPluginException(error_msg)
                elif response.get("data", []):
                    url_json_list = response.get("data", [{}])[0].get(
                        "clickLogs", []
                    )
                    yield from self.get_decoded_urls(
                        rewritten_urls=url_json_list,
                        page_number=page_count,
                        headers=headers,
                        storage=storage,
                        is_retraction=is_retraction
                    )
                page_count += 1
                page_token = (
                    response.get("meta", {}).get("pagination", {})
                    .get("next", None)
                )
                if not page_token:
                    break
                body["meta"]["pagination"]["pageToken"] = page_token
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled "
                f"URL indicator(s) from {PLUGIN_NAME} platform."
            )
        except QuotaNotAvailableException as err:
            raise MimecastPluginException(err)
        except MimecastPluginException as err:
            raise MimecastPluginException(err)
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while pulling "
                f"URL indicator(s) from {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def get_decoded_urls(
        self,
        rewritten_urls: List[dict],
        page_number: int,
        headers: dict,
        storage: Dict,
        is_retraction: bool = False
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Return decoded url from rewritten url.

        Args:
            rewritten_urls (List): List of rewritten url.
            page_number (int): Page number.
            headers (dict): Headers.
            is_retraction (bool): Whether to pull retraction urls.

        Returns:
            List[Indicator]: Return list of Indicators.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
            total_invalid_iocs = 0
            total_valid_iocs = 0
            batch = 0
            for index in range(0, len(rewritten_urls), MAX_REQUEST_URL):
                indicators = set() if is_retraction else []
                invalid_ioc_for_batch = 0
                valid_ioc_for_batch = 0
                url_batch = rewritten_urls[index: index + MAX_REQUEST_URL]
                batch_indicators_data = [
                    {"url": url.get("url", "")} for url in url_batch
                ]
                body = {
                    "data": batch_indicators_data
                }
                batch += 1
                decode_url_endpoint = self.mimecast_helper.build_url(
                    DECODE_URL_ENDPOINT, self.configuration
                )
                response = self.mimecast_helper.api_helper(
                    url=decode_url_endpoint,
                    method="POST",
                    headers=headers,
                    json=body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=(
                        f"decoding URLs for batch {batch}, page {page_number}"
                    ),
                    is_retraction=is_retraction
                )
                decoded_url_response = response.get("data", [])
                decoded_url_failure = response.get("fail", [])
                if decoded_url_response:
                    last_decoded_url_info = url_batch[-1]
                    for urls_info in decoded_url_response:
                        try:
                            url_ioc = urls_info.get("url", "")
                            if url_ioc:
                                if is_retraction:
                                    indicators.add(url_ioc)
                                    valid_ioc_for_batch += 1
                                else:
                                    indicators.append(
                                        Indicator(
                                            value=url_ioc,
                                            type=IndicatorType.URL,
                                        )
                                    )
                                    valid_ioc_for_batch += 1
                            else:
                                invalid_ioc_for_batch += 1
                        except (ValidationError, Exception) as error:
                            invalid_ioc_for_batch += 1
                            error_message = (
                                "Validation error occurred"
                                if isinstance(error, ValidationError)
                                else "Unexpected error occurred"
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_message} "
                                    "while creating indicator. "
                                    "This record will be skipped. "
                                    f"Error: {error}."
                                ),
                                details=str(traceback.format_exc()),
                            )

                if decoded_url_failure:
                    for urls_info in decoded_url_failure:
                        if not urls_info.get("errors", []):
                            try:
                                url_indicator = (
                                    urls_info.get("key", "").get("url", "")
                                )
                                if url_indicator:
                                    if is_retraction:
                                        indicators.add(url_indicator)
                                        valid_ioc_for_batch += 1
                                    else:
                                        indicators.append(
                                            Indicator(
                                                value=url_indicator,
                                                type=IndicatorType.URL,
                                            )
                                        )
                                        valid_ioc_for_batch += 1
                                else:
                                    invalid_ioc_for_batch += 1
                            except (ValidationError, Exception) as error:
                                invalid_ioc_for_batch += 1
                                error_message = (
                                    "Validation error occurred"
                                    if isinstance(error, ValidationError)
                                    else "Unexpected error occurred"
                                )
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: {error_message} "
                                        "while creating indicator. "
                                        "This record will be skipped. "
                                        f"Error: {error}."
                                    ),
                                    details=str(traceback.format_exc()),
                                )
                        else:
                            invalid_ioc_for_batch += 1
                total_invalid_iocs += invalid_ioc_for_batch
                total_valid_iocs += valid_ioc_for_batch

                if not is_retraction:
                    # Keep adding the checkpoints to avoid the
                    # duplication of indicators in case of
                    # failure scenarios.
                    checkpoint = (
                        parser.parse(last_decoded_url_info.get("date"))
                        if last_decoded_url_info.get("date")
                        else datetime.now()
                    )
                    storage["checkpoints"]["url_checkpoint"] = checkpoint

                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled "
                    f"{valid_ioc_for_batch} URL indicator(s) "
                    f"for batch {batch}, page {page_number}. "
                    "Total URL indicator(s) "
                    f"pulled: {total_valid_iocs}."
                )
                if indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield indicators, storage.get("checkpoints")
                    else:
                        yield indicators
            if total_invalid_iocs > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped pulling {total_invalid_iocs} "
                    "record(s) as URL value might be a empty string."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled "
                f"{total_valid_iocs} URL indicator(s) "
                f"for page {page_number} from {PLUGIN_NAME}."
            )
        except MimecastPluginException as err:
            if (
                indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield indicators
            else:
                raise MimecastPluginException(str(err))
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while decoding the URLs "
                f"from {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            if (
                indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield indicators
            else:
                raise MimecastPluginException(err_msg)

    def pull_hashes(
        self,
        start_time: datetime,
        pull_location: str,
        storage: Dict,
        is_retraction: bool = False
    ) -> Union[Generator[Indicator, bool, None], Dict]:
        """Pull Hashes form Malware Customer or Malware Grid.

        Args:
            start_time (datetime): The start time for pulling the hashes.
            pull_location (str): The location of hashes to pull from, either
                "Malware Customer" or "Malware Grid".
            is_retraction (bool, optional): Whether this is a retraction call.
                Defaults to False.

        Yields:
            Generator[Indicator, bool, None]: The generator of hashes.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        file_hash_types = self.configuration.get(
            "indicator_type", ["MD5", "SHA256"]
        )
        hash_type_msg = " and ".join(file_hash_types)

        self.logger.info(
            f"{self.log_prefix}: Pulling file hash indicator(s) of type "
            f"{hash_type_msg} from {PLUGIN_NAME} platform "
            f"using checkpoint: {start_time}"
        )
        # Get headers and storage once
        headers, storage = self.get_bearer_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
            is_retraction=is_retraction,
        )
        start_time = start_time.replace(microsecond=0)
        body = {
            "data": [
                {
                    "fileType": "csv",
                    "start": f"{start_time.astimezone().isoformat()}",
                    "feedType": MALWARE_TYPE.get(pull_location, ""),
                }
            ]
        }
        page_count = 0
        total_indicators = 0
        total_skip_count = 0
        next_page = True
        fetch_hashes_endpoint = self.mimecast_helper.build_url(
            FETCH_HASHES_ENDPOINT, self.configuration
        )
        try:
            while next_page:
                page_count += 1
                md5_count = 0
                sha256_count = 0
                current_page_skip_count = 0
                current_page_invalid_count = 0
                page_indicators = set() if is_retraction else []
                logger_msg = (
                    f"pulling file hash for page {page_count} "
                    f"from {pull_location}"
                )
                response = self.mimecast_helper.api_helper(
                    url=fetch_hashes_endpoint,
                    method="POST",
                    headers=headers,
                    json=body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=logger_msg,
                    is_retraction=is_retraction
                )
                # Response object is returned as hash API
                # giving csv file in response
                if response.status_code == 200:
                    try:
                        raw_csv = response.text.split("\n")

                        # If CSV has only one row means csv file is empty
                        if len(raw_csv) == 1:
                            next_page = False

                        reader = csv.DictReader(raw_csv, delimiter="|")
                        for row in reader:
                            try:
                                if "MD5" in file_hash_types:
                                    indicator = row.get("MD5", "")
                                    timestamp = row.get("Timestamp", "")
                                    if indicator and indicator.strip() != "null":
                                        if is_retraction:
                                            page_indicators.add(indicator)
                                        else:
                                            page_indicators.append(
                                                Indicator(
                                                    value=indicator,
                                                    type=IndicatorType.MD5,
                                                    comments=(
                                                        f"Sent from {row.get('SenderAddress')}"
                                                        if row.get("SenderAddress", "") else ""
                                                    ),
                                                    first_seen=timestamp if timestamp else None,
                                                    last_seen=timestamp if timestamp else None
                                                )
                                            )
                                            md5_count += 1
                                    else:
                                        current_page_invalid_count += 1
                                if "SHA256" in file_hash_types:
                                    indicator = row.get("SHA256", "")
                                    timestamp = row.get("Timestamp", "")
                                    if indicator and indicator.strip() != "null":
                                        if is_retraction:
                                            page_indicators.add(indicator)
                                        else:
                                            page_indicators.append(
                                                Indicator(
                                                    value=indicator,
                                                    type=IndicatorType.SHA256,
                                                    comments=(
                                                        f"Sent from {row.get('SenderAddress')}"
                                                        if row.get("SenderAddress", "") else ""
                                                    ),
                                                    first_seen=timestamp if timestamp else None,
                                                    last_seen=timestamp if timestamp else None
                                                )
                                            )
                                            sha256_count += 1
                                    else:
                                        current_page_invalid_count += 1
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
                                        " creating indicator. This record "
                                        f"will be skipped. Error: {error}."
                                    ),
                                    details=str(traceback.format_exc()),
                                )
                        total_indicators += len(page_indicators)
                        total_skip_count += current_page_skip_count
                        self.total_invalid_hashes += current_page_invalid_count
                        self.logger.info(
                            f"{self.log_prefix}: Successfully pulled "
                            f"{len(page_indicators)} file hash indicator(s) "
                            f"for page {page_count} from {pull_location}. "
                            f"Pull Stats: {sha256_count} SHA256 and "
                            f"{md5_count} MD5. Total File Hash indicator(s) "
                            f"pulled: {total_indicators}."
                        )
                    except Exception as ex:
                        error_msg = (
                            f"Error occurred while fetching file hashes "
                            f"from CSV file for page {page_count}."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {error_msg} "
                            f"Error: {str(ex)}",
                            details=str(traceback.format_exc())
                        )
                        raise MimecastPluginException(error_msg)

                next_feed_token = response.headers.get(
                    "x-mc-threat-feed-next-token", ""
                )
                if not next_feed_token:
                    next_page = False
                else:
                    body["data"][0]["token"] = next_feed_token

                if not next_page:
                    if total_skip_count > 0:
                        self.logger.info(
                            f"{self.log_prefix}: Skipped {total_skip_count} "
                            "record(s) due to some exceptions are occurred "
                            "while pulling indicators."
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully pulled "
                        f"{total_indicators} file hash indicator(s) "
                        f"of type {hash_type_msg} "
                        f"from {PLUGIN_NAME} platform."
                    )
                    if not is_retraction:
                        # Store checkpoint for next sync interval if request
                        # is not for retraction.
                        storage["checkpoints"][
                            "hash_checkpoint"
                        ] = datetime.now()
                elif (
                    next_page
                    and hasattr(self, "sub_checkpoint")
                    and not is_retraction
                ):
                    # Keep adding the checkpoints to avoid the duplication of
                    # indicators in case of failure scenarios.
                    checkpoint = (
                        parser.parse(timestamp)
                        if timestamp else datetime.now()
                    )
                    storage["checkpoints"]["hash_checkpoint"] = checkpoint

                if page_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield page_indicators, storage.get("checkpoints")
                    else:
                        yield page_indicators
        except MimecastPluginException as ex:
            if (
                page_indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield page_indicators
            else:
                raise MimecastPluginException(str(ex))
        except Exception as ex:
            err_msg = (
                "Unexpected error occurred while pulling "
                f"indicators from {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {ex}",
                details=str(traceback.format_exc()),
            )
            if (
                page_indicators
                and not hasattr(self, "sub_checkpoint")
                and not is_retraction
            ):
                yield page_indicators
            else:
                raise MimecastPluginException(err_msg)

    def _pull(self) -> Union[Generator[Indicator, bool, None], Dict]:
        """Pull the indicators from Mimecast.

        Yields:
            Union[Generator[Indicator, bool, None], Dict]: Generator of
                indicators and their metadata.
        """
        url_checkpoint = None
        hash_checkpoint = None
        storage = self.storage if self.storage is not None else {}

        sub_checkpoint = getattr(self, "sub_checkpoint", {})
        # Get start time based on checkpoint
        if sub_checkpoint:
            url_checkpoint = sub_checkpoint.get("url_checkpoint", "")
            hash_checkpoint = sub_checkpoint.get("hash_checkpoint", "")
        elif self.last_run_at:
            url_checkpoint = self.last_run_at
            hash_checkpoint = self.last_run_at
        else:
            initial_days = int(self.configuration.get("days", 7))
            self.logger.info(
                f"{self.log_prefix}: This is initial indicator fetch since "
                f"checkpoint is empty. Querying indicators for last "
                f"{initial_days} day(s)."
            )
            start_time = datetime.now() - timedelta(days=initial_days)
            url_checkpoint = start_time
            hash_checkpoint = start_time

        # Important: Update the storage.
        # We need to update the storage to track the checkpoints for each run.
        storage.update(
            {
                "checkpoints": {
                    "url_checkpoint": url_checkpoint,
                    "hash_checkpoint": hash_checkpoint,
                }
            }
        )

        feed_types = self.configuration.get("feed_type", [])
        pull_ioc_methods = {}
        if "malware_grid" in feed_types:
            pull_ioc_methods[(self.pull_hashes, "Malware Grid")] = (
                hash_checkpoint
            )

        if "malware_customer" in feed_types:
            pull_ioc_methods[(self.pull_hashes, "Malware Customer")] = (
                hash_checkpoint
            )

        if "malsite" in feed_types:
            pull_ioc_methods[(self.get_rewritten_urls, "Malsite")] = (
                url_checkpoint
            )

        for (pull_method, pull_location), start_time in pull_ioc_methods.items():
            yield from pull_method(
                start_time=start_time,
                pull_location=pull_location,
                storage=storage
            )

        if self.total_invalid_hashes > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped pulling {self.total_invalid_hashes} "
                "record(s) as hash value might be empty or null."
            )

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from Mimecast platform.

        Yields:
            List[cte.models.Indicators]: List of indicator objects pulled
            from the Mimecast platform.
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

    def push_hashes(
        self,
        operation_type: str,
        hashes: List[Dict],
        is_retraction: bool = False
    ):
        """Push hashes to Mimecast.

        Args:
            operation_type (str): The type of operation \
                to perform on the hashes.
            hashes (List[Dict]): The list of hashes to push.
            is_retraction (bool, optional): Whether this is a \
                retraction operation. Defaults to False.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        body = {
            "data": [
                {
                    "hashList": [],
                    "operationType": operation_type
                }
            ]
        }
        # Get headers and storage once
        headers, storage = self.get_bearer_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
            is_retraction=is_retraction
        )
        # Mimecast only supports "push" in batch of 1000 indicators at a time
        push_page_count = 0
        successful_push_count = 0
        failures_count = 0
        failure_msg_list = set()
        failure_msg_count = 0
        push_hash_endpoint = self.mimecast_helper.build_url(
            PUSH_HASH_ENDPOINT, self.configuration
        )
        for pos in range(0, len(hashes), PUSH_HASH_BATCH_SIZE):
            try:
                successful_batch_push_count = 0
                failures_batch_count = 0
                push_page_count += 1
                body["data"][0]["hashList"] = hashes[
                    pos : pos + PUSH_HASH_BATCH_SIZE
                ]
                logger_msg = (
                    f"sharing batch {push_page_count} of hash list"
                )
                if is_retraction:
                    logger_msg = (
                        f"retracting batch {push_page_count} of hash list"
                    )
                response = self.mimecast_helper.api_helper(
                    url=push_hash_endpoint,
                    method="POST",
                    headers=headers,
                    json=body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=logger_msg,
                    is_retraction=is_retraction,
                )
                failures = response.get("fail", [])
                data = response.get("data", [])
                if data:
                    successful_batch_push_count += data[0].get("hashCount", 0)
                if failures:
                    failures_batch_count += len(failures)
                    if len(failure_msg_list) < MAX_FAILURE_COUNT_THRESHOLD: 
                        failure_msg_list.update(self._parse_errors(failures))
                        failure_msg_count = len(failure_msg_list)
                    if is_retraction:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unable to retract "
                                f"{failures_batch_count} Hash indicator(s) "
                                f"for {push_page_count}."
                            ),
                            details=f"Error: {failures}"
                        )
                successful_push_count += successful_batch_push_count
                failures_count += failures_batch_count
                if is_retraction:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully retracted "
                        f"{successful_batch_push_count} Hash indicator(s) "
                        f"for batch {push_page_count}."
                    )
                else:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully shared "
                        f"{successful_batch_push_count} Hash indicator(s) "
                        f"for batch {push_page_count}. "
                        f"Total Hashes shared: {successful_push_count}."
                    )
            except QuotaNotAvailableException as err:
                raise MimecastPluginException(err)
            except (MimecastPluginException, Exception) as err:
                if failures:
                    failures_count += failures_batch_count
                else:
                    failures_count += len(body["data"][0]["hashList"])
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while pushing"
                        f" indicators. Error: {str(err)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue

        if is_retraction:
            log_msg = (
                f"Successfully retracted {successful_push_count} "
                f"Hash indicator(s) from {PLUGIN_NAME}"
            )
        else:
            log_msg = (
                f"Successfully shared {successful_push_count} "
                f"Hash indicator(s) to {PLUGIN_NAME}"
            )
            if failures_count:
                # Log with failure messages in details parameter
                details_msg = ""
                if failure_msg_list:
                    details_msg = str(list(failure_msg_list))
                    if failure_msg_count >= MAX_FAILURE_COUNT_THRESHOLD:
                        details_msg += f" Only first {MAX_FAILURE_COUNT_THRESHOLD} failure messages shown."
                
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to share {failures_count} "
                        f"Hash indicator(s) to {PLUGIN_NAME}."
                    ),
                    details=details_msg if details_msg else None
                )
        self.logger.info(
            f"{self.log_prefix}: {log_msg}."
        )
        if is_retraction:
            return successful_push_count

    def push_urls(self, indicators_data):
        """Pushes URL indicators to Mimecast.

        Args:
            indicators_data (List[Indicator]): \
                A list of URL indicators to push.
        """
        invalid_urls = 0
        already_exists = 0
        unknown_error = 0
        # Get headers and storage once
        headers, storage = self.get_bearer_token_and_storage(
            configuration=self.configuration, is_validation=False
        )
        batch_count_url = 0
        successful_push_count = 0
        failures_count = 0
        failure_msg_list = set()
        failure_msg_count = 0
        push_url_endpoint = self.mimecast_helper.build_url(
            PUSH_URL_ENDPOINT, self.configuration
        )
        for index in range(0, len(indicators_data), MAX_CREATE_URL):
            try:
                successful_batch_push_count = 0
                failures_batch_count = 0
                batch_count_url += 1
                json_data = {
                    "data": indicators_data[index:index + MAX_CREATE_URL]
                }
                response = self.mimecast_helper.api_helper(
                    url=push_url_endpoint,
                    method="POST",
                    headers=headers,
                    json=json_data,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=f"pushing URL batch {batch_count_url}",
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
                        elif (
                            errors[0].get("code", " ")
                            == "err_managed_url_exists_code"
                        ):
                            already_exists += 1
                        else:
                            unknown_error += 1
                            if len(failure_msg_list) < MAX_FAILURE_COUNT_THRESHOLD: 
                                failure_msg_list.update(self._parse_errors(failures))
                                failure_msg_count = len(failure_msg_list)
                successful_push_count += successful_batch_push_count
                failures_count += failures_batch_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared "
                    f"{successful_batch_push_count} URLs for batch "
                    f"{batch_count_url}. Total URLs shared: "
                    f"{successful_push_count}."
                )
            except QuotaNotAvailableException as err:
                raise MimecastPluginException(err)
            except (MimecastPluginException, Exception) as err:
                if failures:
                    failures_count += failures_batch_count
                else:
                    failures_count += len(json_data.get("data", []))
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while pushing"
                        f" indicators. Error: {str(err)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue

        self.logger.info(
            f"{self.log_prefix}: Successfully shared "
            f"{successful_push_count} URL indicator(s) to {PLUGIN_NAME}."
        )
        if failures_count:
            log_msg = (
                f"Failed to share {failures_count} URL indicator(s) "
                f"to {PLUGIN_NAME}. Invalid URL(s): {invalid_urls}, "
                f"Already Existing URL(s): {already_exists}."
            )
            if unknown_error:
                log_msg += (
                    f" Failed to create {unknown_error} URL(s) on "
                    f"{PLUGIN_NAME} - please check with Mimecast "
                    f"Admin for details."
                )
            # Log with failure messages in details parameter
            details_msg = ""
            if failure_msg_list:
                details_msg = str(list(failure_msg_list))
                if failure_msg_count >= MAX_FAILURE_COUNT_THRESHOLD:
                    details_msg += f" Only first {MAX_FAILURE_COUNT_THRESHOLD} failure messages shown"
            
            self.logger.error(
                message=f"{self.log_prefix}: {log_msg}",
                details=details_msg if details_msg else None
            )

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push the given list of indicators to Mimecast.

        Args:
            indicators (List[Indicator]): A list of indicators to push.
            action_dict (Dict): A dictionary containing information about
                the action.
            source (str, optional): The source of the indicators.
                Defaults to None.
            business_rule (str, optional): The name of the business rule
                triggering the push.
            plugin_name (str, optional): The name of the plugin
                performing the push.

        Returns:
            PushResult: The result of the push operation.
        """
        # First check if push is enabled
        action_label = action_dict.get("label", "")
        action_value = action_dict.get("value", "")
        action_parameters = action_dict.get("parameters", {})
        operation_type = action_parameters.get("operation_type", "")
        source_label = PREFIX_IOC_SOURCE
        if plugin_name:
            source_label = (
                f"{PREFIX_IOC_SOURCE} {SEPARATOR} {plugin_name}"
            )
        if action_value == "operation":
            # Prepare list of only file hashes
            hashes = []
            skipped_hashes = 0
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
                else:
                    skipped_hashes += 1

            if skipped_hashes > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped sharing "
                    f"{skipped_hashes} indicator(s) to "
                    f"{PLUGIN_NAME} due to invalid values while executing {ACTION_TYPES.get(action_value, '')}."
                )

            # If all the indicators are of type other than file hash, skip.
            if len(hashes) == 0:
                log_msg = (
                    "Found no indicators eligible for pushing to "
                    f"{PLUGIN_NAME}. Only file hashes are supported "
                    f"for action '{action_label}' hence action will "
                    "be skipped."
                )
                self.logger.info(
                    f"{self.log_prefix}: {log_msg}"
                )
                return PushResult(
                    success=True,
                    message=log_msg,
                )
            self.logger.info(
                f"{self.log_prefix}: {len(hashes)} Hash indicator(s) "
                f"will be shared to the {PLUGIN_NAME}."
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
            skipped_urls = 0
            for indicator in indicators:
                if indicator.type == IndicatorType.URL and len(
                    indicator.value
                ):
                    if self._validate_url(indicator.value):
                        total_ioc_to_push += 1
                        indicators_data.append(
                            {
                                "url": indicator.value,
                                "action": action_dict.get("parameters").get(
                                    "action_type"
                                ),
                                "comment": source_label,
                                "matchType": action_dict.get("parameters").get(
                                    "match_type"
                                ),
                            }
                        )
                    else:
                        skipped_urls += 1
                else:
                    skipped_urls += 1

            if skipped_urls > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped sharing "
                    f"{skipped_urls} indicator(s) to "
                    f"{PLUGIN_NAME} due to invalid values while executing {ACTION_TYPES.get(action_value, '')}."
                )
            if not total_ioc_to_push:
                log_msg = (
                    f"{self.log_prefix}: Found no indicators eligible "
                    f"for pushing to {PLUGIN_NAME}. Only URLs are "
                    f"supported for action '{action_label}' hence action "
                    "will be skipped."
                )
                self.logger.info(
                    f"{self.log_prefix}: {log_msg}"
                )
                return PushResult(
                    success=True,
                    message=log_msg
                )
            self.logger.info(
                f"{self.log_prefix}: {total_ioc_to_push} URL indicator(s) "
                f"will be shared to the {PLUGIN_NAME}."
            )
            self.push_urls(indicators_data)
            return PushResult(
                success=True,
                message=f"Successfully executed push method for "
                f"action '{action_label}' for plugin {PLUGIN_NAME}.",
            )

    def _validate_credentials(
        self,
        configuration: dict,
        reason: str = "",
        is_validation: bool = False
    ):
        """Validate credentials by making REST API call.

        Args:
            configuration (dict): The user provided configuration.
            reason (str, optional): The reason for validating the \
                credentials. Defaults to "".
            is_validation (bool, optional): Whether it is a validation \
                call. Defaults to False.

        Returns:
            ValidationResult: ValidationResult object with validation result.
        """
        try:
            logger_msg = f"validating credentials of {PLUGIN_NAME} account"
            if reason:
                logger_msg += f" for {reason}"
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg.capitalize()}."
            )
            # Get headers and storage once
            headers, storage = self.get_bearer_token_and_storage(
                configuration=configuration, is_validation=True
            )
            response = self.mimecast_helper.api_helper(
                url=self.mimecast_helper.build_url(GET_ACCOUNT_ENDPOINT, configuration),
                method="POST",
                headers=headers,
                configuration=configuration,
                storage=storage,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=True,
                logger_msg=logger_msg,
            )
            if response.get("meta", {}).get("status", "") == 200:
                failures = response.get("fail", [])
                data = response.get("data", [])
                if not failures and data:
                    packages = data[0].get("packages", [])
                    if is_validation:
                        logger_msg = (
                            "Successfully validated "
                            f"{PLUGIN_NAME} credentials "
                            "and configuration parameters."
                        )
                        self.logger.debug(
                            f"{self.log_prefix}: {logger_msg}"
                        )
                        return ValidationResult(
                            success=True,
                            message=logger_msg
                        )
                    return packages
                parsed_errors = self._parse_errors(failures)
                api_error = ", ".join(list(parsed_errors)) if parsed_errors else "No error details available"
                
                error_msg = (
                    f"Error occurred while {logger_msg}. "
                    "Check the Client ID and Client Secret "
                    "provided in the configuration."
                )
                
                self.logger.error(
                    message=f"{self.log_prefix}: {error_msg}",
                    details=api_error
                )
                raise MimecastPluginException(error_msg)
        except QuotaNotAvailableException as err:
            if is_validation:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=str(err),
                )
            raise MimecastPluginException(err)
        except MimecastPluginException as err:
            if is_validation:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=str(err),
                )
            raise MimecastPluginException(str(err))
        except Exception as err:
            if is_validation:
                err_msg = "Unexpected validation error occurred."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg} Check logs for more details.",
                )
            error_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg} "
                f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise MimecastPluginException(error_msg)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, int, list],
        field_type: type,
        allowed_values: list = None,
        allowed_values_display: list = None,
        is_required: bool = False,
        range_validation: bool = False,
        range_values: Tuple[int, int] = None,
        custom_validation_func: callable = None,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, int, list): Value of the configuration field.
            field_type (type): Expected type of the configuration field.
            allowed_values (list, optional): List of allowed values for
                the configuration field. Defaults to None.
            allowed_values_display (list, optional): List of user-friendly 
                display names for allowed values. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to False.
            range_validation (bool, optional): Whether to validate range.
                Defaults to False.
            range_values (Tuple[int, int], optional): Range values for
                validation. Defaults to None.
            custom_validation_func (callable, optional): Custom validation
                function to be applied. Defaults to None.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not, or None if validation passes.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        
        # Handle empty strings for optional integer fields
        if field_type is int and isinstance(field_value, str) and not field_value.strip():
            if not is_required:
                return None
            else:
                err_msg = f"{field_name} is a required configuration parameter."
                self.logger.error(
                    message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                    resolution=(
                        f"Please provide a valid integer value for {field_name} field."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        if (field_value and not isinstance(field_value, field_type)) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if range_validation and range_values:
            if not (range_values[0] <= field_value <= range_values[1]):
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. It should be in range"
                    f" {range_values[0]} to 2^62."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                    resolution=(
                        f"Please provide a value for {field_name} in the range {range_values[0]} to 2^62."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        if allowed_values:
            display_values = allowed_values_display if allowed_values_display else allowed_values
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. "
            )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    details=(
                        f"Allowed values are: "
                        f"{', '.join(str(value) for value in display_values)}."
                    ),
                    resolution=(
                        "Please provide a valid value from the allowed values."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type is list:
                if not all(item in allowed_values for item in field_value):
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                        ),
                        details=(
                            f"Allowed values are: "
                            f"{', '.join(str(value) for value in display_values)}."
                        ),
                        resolution=(
                            "Please provide valid values from the allowed values."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configurations.

        Args:
            configuration (dict): The user provided configuration.

        Returns:
            ValidationResult: ValidationResult object with validation result.
        """
        base_url = configuration.get("base_url", "")
        client_id = configuration.get("client_id", "")
        client_secret = configuration.get("client_secret", "")
        feed_type = configuration.get("feed_type", [])
        indicator_type = configuration.get("indicator_type", [])
        retraction_days = configuration.get("retraction_interval")
        initial_range = configuration.get("days", 0)
        if base_url_validation := self._validate_configuration_parameters(
            field_name="API Base URL",
            field_value=base_url,
            field_type=str,
            is_required=True,
        ):
            return base_url_validation
        if client_id_validation := self._validate_configuration_parameters(
            field_name="Client ID",
            field_value=client_id,
            field_type=str,
            is_required=True,
        ):
            return client_id_validation
        if client_secret_validation := self._validate_configuration_parameters(
            field_name="Client Secret",
            field_value=client_secret,
            field_type=str,
            is_required=True,
        ):
            return client_secret_validation
        if feed_type_validation := self._validate_configuration_parameters(
            field_name="Indicator Feed Type",
            field_value=feed_type,
            field_type=list,
            is_required=True,
            allowed_values=list(FEED_TYPES.keys()),
            allowed_values_display=list(FEED_TYPES.values()),
        ):
            return feed_type_validation
        if ("malware_customer" in feed_type) or ("malware_grid" in feed_type):
            if indicator_type_validation := self._validate_configuration_parameters(
                field_name="Types of Malware to Pull",
                field_value=indicator_type,
                field_type=list,
                is_required=True,
                allowed_values=MALWARE_TYPES,
            ):
                return indicator_type_validation
        if retraction_days is not None:
            if retraction_validation := self._validate_configuration_parameters(
                field_name="Retraction Interval",
                field_value=retraction_days,
                field_type=int,
                range_validation=True,
                range_values=(1, INTEGER_THRESHOLD),
            ):
                return retraction_validation
        if initial_range_validation := self._validate_configuration_parameters(
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            is_required=True,
            range_validation=True,
            range_values=(0, INTEGER_THRESHOLD),
        ):
            return initial_range_validation
        return self._validate_credentials(
            configuration=configuration,
            is_validation=True
        )

    def get_actions(self):
        """Get available actions.

        Returns:
            list[ActionWithoutParams]: List of action without parameter.
        """
        return [
            ActionWithoutParams(
                label=(
                    "Perform Operation (applicable for "
                    "File hashes(SHA256, MD5))"
                ),
                value="operation"
            ),
            ActionWithoutParams(
                label="Create Managed URL (applicable for URLs)",
                value="managed_url"
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        operation_type = action.parameters.get(
            "operation_type", ""
        )
        action_type = action.parameters.get(
            "action_type", ""
        )
        match_type = action.parameters.get(
            "match_type", ""
        )
        if action_value not in ["operation", "managed_url"]:
            err_msg = (
                "Unsupported action provided. Plugin only "
                "supports 'Perform Operation' and "
                "'Create Managed URL' actions."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message="Unsupported action provided."
            )
        packages = self._validate_credentials(
            self.configuration,
            "sharing MD5 or SHA256"
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
                "Operation Type is a required action parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )
        if (
            action_value == "operation" and
            operation_type not in HASH_OPERATION_TYPE.keys()
        ):
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
        if action_value == "managed_url":
            if not action_type:
                error_msg = (
                    "Action Type is a required action parameter."
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )
            if (
                action_type not in URL_OPERATION_TYPE.values()
            ):
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
            if not match_type:
                error_msg = (
                    "Match Type is a required action parameter."
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                )
            elif (
                match_type not in URL_MATCH_TYPE.values()
            ):
                error_msg = (
                    "Invalid value of Match Type provided. "
                    "Allowed values are "
                    f"{', '.join(URL_MATCH_TYPE.keys())}."
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=error_msg
                )

        log_msg = f"Validation successful for {action_value} action."
        self.logger.debug(f"{self.log_prefix}: {log_msg}")
        return ValidationResult(success=True, message=log_msg)

    def get_action_fields(self, action: Action):
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group
        """
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
                    "description": (
                        "Perform the selected action on the batch of "
                        "file hash indicators matched in the business "
                        "rule. For example, a file-hash can be added with "
                        "a BLOCK action to prevent the delivery of a "
                        "message with an attachment matching that file-hash."
                    ),
                }
            ]
        elif action.value == "managed_url":
            choice_list = [
                {"key": key, "value": value}
                for key, value in URL_OPERATION_TYPE.items()
            ]
            match_type_list = [
                {"key": key, "value": value}
                for key, value in URL_MATCH_TYPE.items()
            ]
            return [
                {
                    "label": "Action Type",
                    "key": "action_type",
                    "type": "choice",
                    "choices": choice_list,
                    "mandatory": True,
                    "default": choice_list[0]["value"],
                    "description": (
                        "Perform the selected action on the batch of "
                        "URL indicators matched in the business rule. "
                        "For example, a URL can be black listed with "
                        "a BLOCK action type and white listed with "
                        "PERMIT action type."
                    ),
                },
                {
                    "label": "Match Type",
                    "key": "match_type",
                    "type": "choice",
                    "choices": match_type_list,
                    "mandatory": True,
                    "default": match_type_list[0]["value"],
                    "description": (
                        "Perform the selected match on the batch of "
                        "URL indicators matched in the business rule. "
                        "Set to 'Explicit' to block or permit only "
                        "instances of the full URL. Set to 'Domain' "
                        "to block or permit any URL with the same domain."
                    ),
                }
            ]

    def get_modified_indicators(self, source_indicators: List[List[Dict]]):
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            tuple: Modified Indicators and Status.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators status"
            f" from {PLUGIN_NAME}."
        )
        retraction_interval = self.configuration.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration "
                f'"{self.config_name}". Skipping retraction of IoC(s) '
                f"for {PLUGIN_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)
        start_time = datetime.now() - timedelta(days=retraction_interval)
        feed_types = self.configuration.get("feed_type", [])

        modified_customer_hashes = set()
        modified_grid_hashes = set()
        modified_urls = set()

        try:
            if "malware_customer" in feed_types:
                for indicator in self.pull_hashes(
                    start_time=start_time,
                    pull_location="Malware Customer",
                    storage={},
                    is_retraction=True,
                ):
                    modified_customer_hashes.update(indicator)

            if "malware_grid" in feed_types:
                for indicator in self.pull_hashes(
                    start_time=start_time,
                    pull_location="Malware Grid",
                    storage={},
                    is_retraction=True,
                ):
                    modified_grid_hashes.update(indicator)

            if "malsite" in feed_types:
                for indicator in self.get_rewritten_urls(
                    start_time=start_time, storage={}, is_retraction=True
                ):
                    modified_urls.update(indicator)

            for source_ioc_list in source_indicators:
                hash_iocs = set()
                url_iocs = set()
                for ioc in source_ioc_list:
                    if ioc.type in [IndicatorType.URL]:
                        url_iocs.add(ioc.value)
                    if ioc.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                        hash_iocs.add(ioc.value)

                hash_iocs -= modified_customer_hashes
                hash_iocs -= modified_grid_hashes
                url_iocs -= modified_urls

                combined_ioc = url_iocs.union(hash_iocs)
                self.logger.info(
                    f"{self.log_prefix}: {len(combined_ioc)} indicator(s) will "
                    f"be marked as retracted from total "
                    f"{len(source_ioc_list)} "
                    "indicator(s) present in Cloud Exchange."
                )

                yield list(combined_ioc), False
        except Exception as err:
            err_msg = (
                f"Error while pulling modified indicators from"
                f" {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from Mimecast.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s) "
            f"from {PLUGIN_NAME}."
        )
        retraction_batch_count = 1
        retracted_hash_count = 0
        retracted_url_count = 0
        total_retracted_count = 0
        for retraction_batch in retracted_indicators_lists:
            hash_iocs = []
            url_iocs = []
            for ioc in retraction_batch:
                if ioc.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                    hash_iocs.append(
                        {
                            "hash": ioc.value,
                            "provider": "NetskopeCE",
                            "description": "Retracting File Hash",
                        }
                    )
                if ioc.type in [IndicatorType.URL]:
                    url_iocs.append(ioc.value)
            if hash_iocs:
                retracted_hash_count = self.push_hashes(
                    operation_type="DELETE",
                    hashes=hash_iocs,
                    is_retraction=True
                )
            if url_iocs:
                retracted_url_count = self._retract_url_iocs(
                    url_iocs=url_iocs
                )

            total_retracted_count = (
                retracted_url_count + retracted_hash_count
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully retracted "
                f"{total_retracted_count} indicator(s) for "
                f"batch {retraction_batch_count}."
            )
            yield ValidationResult(
                success=True,
                message=(
                    f"Completed execution of batch {retraction_batch_count} "
                    "for retraction."
                ),
            )
            retraction_batch_count += 1

    def _retract_url_iocs(
        self,
        url_iocs: List[str]
    ):
        """Retract urls from mimecast.

        Args:
            url_iocs (List[str]): List of url IOC values to be \
                retracted from mimecast.

        Returns:
            None
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        # Get headers and storage once
        headers, storage = self.get_bearer_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
            is_retraction=True,
        )
        retracted_count = 0
        get_url_endpoint = self.mimecast_helper.build_url(
            GET_URL_ENDPOINT, self.configuration
        )
        delete_url_endpoint = self.mimecast_helper.build_url(
            DELETE_URL_ENDPOINT, self.configuration
        )
        for url_value in url_iocs:
            try:
                get_url_payload = {
                    "data": [
                        {
                            "domainOrUrl": url_value,
                            "exactMatch": True
                        }
                    ]
                }
                response = self.mimecast_helper.api_helper(
                    url=get_url_endpoint,
                    method="POST",
                    headers=headers,
                    json=get_url_payload,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    logger_msg=f"getting URL id for {url_value}",
                    is_retraction=True
                )
                data = response.get("data", [])
                if data and data[0].get("id", ""):
                    url_id = data[0].get("id", "")
                    delete_url_payload = {
                        "data": [
                            {
                                "id": url_id
                            }
                        ]
                    }
                    del_res = self.mimecast_helper.api_helper(
                        url=delete_url_endpoint,
                        method="POST",
                        headers=headers,
                        json=delete_url_payload,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        configuration=self.configuration,
                        storage=storage,
                        logger_msg=f"retracting URL {url_value}",
                        is_retraction=True
                    )
                    if del_res.get("fail", []):
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unable to retract "
                                f"{url_value}."
                            ),
                            details=f"API response: {str(del_res)}",
                        )
                    else:
                        retracted_count += 1
            except MimecastPluginException:
                continue
            except Exception as exp:
                err_mg = (
                    "Unexpected error occurred while retracting "
                    f"{url_value} from {PLUGIN_NAME}. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_mg}",
                    details=str(traceback.format_exc()),
                )
        self.logger.info(
            f"{self.log_prefix}: Successfully retracted {retracted_count} "
            f"URL indicator(s) from {PLUGIN_NAME}."
        )
        return retracted_count
