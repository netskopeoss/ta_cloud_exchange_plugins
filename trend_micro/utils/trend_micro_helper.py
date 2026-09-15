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

TrendAI Vision One Plugin to push and pull data from the TrendAI Vision One
Platform.
"""

import json
import traceback
import time
from typing import Dict, List, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .trend_micro_constant import (
    MODULE_NAME,
    DEFAULT_WAIT_TIME,
    MAX_RETRIES,
    PLATFORM_NAME,
    REQUEST_TIMEOUT,
    RETRACTION,
)


class TrendMicroPluginException(Exception):
    """TrendMicro plugin custom exception class."""

    pass


class MaximumLimitExceededException(Exception):
    """TrendMicro plugin custom exception class for maximum limit exceeded."""

    pass


class TrendMicroPluginHelper(object):
    """TrendMicroPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation,
        proxy,
    ):
        """TrendMicroPluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.ssl_validation = ssl_validation
        self.proxy = proxy

    def _add_user_agent(
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add User-Agent header for TrendAI Vision One API requests.

        Args:
            headers (Dict, optional): Existing headers dict.

        Returns:
            Dict: Headers dict with User-Agent set.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def parse_response(
        self, response: requests.models.Response, is_validation: bool
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            is_validation (bool): Validation flag.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API. Error: {str(err)}"
            )
            log_kwargs = {"details": f"API response: {response.text}"}
            if is_validation:
                err_msg = (
                    "Verify Data Region and Authentication Token provided in "
                    "the configuration parameters."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the Data Region (or custom Base URL) and"
                    " Authentication Token provided in the configuration"
                    " parameters are correct."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", **log_kwargs
            )
            raise TrendMicroPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            log_kwargs = {"details": f"API Response: {response.text}"}
            if is_validation:
                err_msg = (
                    "Verify Data Region and Authentication Token provided in "
                    "the configuration parameters."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the Data Region (or custom Base URL) and"
                    " Authentication Token provided in the configuration"
                    " parameters are correct."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", **log_kwargs
            )
            raise TrendMicroPluginException(err_msg)

    def process_multi_status_response(
        self,
        response_items: List[Dict],
        submitted_payload: List[Dict],
        logger_msg: str,
    ) -> Tuple[int, int, List[str]]:
        """Walk every item of a 207 Multi-Status response.

        Both the push endpoints (suspiciousObjects,
        suspiciousObjectExceptions) and their /delete counterparts
        return one status entry per submitted IOC, in request order.
        This always inspects every entry - unlike the old inline
        first-item-only check, a failure on item 0 no longer causes
        the whole batch to be reported as failed when the rest
        succeeded.

        Args:
            response_items (List[Dict]): Parsed JSON array from the
                207 response, one entry per submitted IOC.
            submitted_payload (List[Dict]): The payload that was
                submitted, same order/length as response_items, used
                to attribute a failure back to its IOC value.
            logger_msg (str): Context for the per-item log line.

        Returns:
            Tuple[int, int, List[str]]: (success_count, fail_count,
                failed_iocs).
        """
        success_count = 0
        failed_iocs = []
        for item, submitted in zip(response_items, submitted_payload):
            status = item.get("status")
            if status in (201, 202, 204):
                success_count += 1
            else:
                value = next(iter(submitted.values()), "")
                failed_iocs.append(value)
                error_msg = (
                    (item.get("body") or {})
                    .get("error", {})
                    .get("message", "")
                )
                self.logger.error(
                    f"{self.log_prefix}: Failed to {logger_msg} for IOC"
                    f" '{value}' (status {status})."
                    f"{' ' + error_msg if error_msg else ''}"
                )
        return success_count, len(failed_iocs), failed_iocs

    def handle_error(
        self, resp: requests.models.Response, logger_msg, is_validation
    ):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """

        status_code = resp.status_code

        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
            404: "Not Found",
            413: "Payload Too Large",
            429: "Too Many Requests",
        }
        # Only these codes are ever surfaced during validate() with a
        # resolution - they are the ones a user can fix by changing
        # configuration (Data Region/Base URL/Authentication Token).
        # 413/429/5xx are never validation-time codes the user caused
        # by a config mistake, so they never carry a resolution.
        resolution_dict = {
            400: (
                "Ensure that the Data Region (or custom Base URL) and"
                " Authentication Token provided in the configuration"
                " parameters are correct."
            ),
            401: (
                "Ensure that the Authentication Token and Data Region "
                "(or custom Base URL) provided in the "
                "configuration parameters are valid and Authentication Token "
                "is not expired."
            ),
            403: (
                "Ensure that the Authentication Token has the required"
                " Suspicious Object List / Exception List permissions"
                " in TrendAI Vision One."
            ),
            404: (
                "Ensure that the Data Region (or custom Base URL)"
                " provided in the configuration parameters is"
                " correct."
            ),
        }
        # Full, single-sentence-flowing messages for the ValidationResult
        # surfaced in the UI (CE itself prefixes this with "One of the
        # configuration parameter is invalid. "). Built as complete
        # sentences per status code rather than concatenating the bare
        # error_dict word with a fixed suffix, which read as a jarring
        # one-word sentence (e.g. "Unauthorized. Verify ...").
        validation_error_dict = {
            400: (
                "Received exit code 400, Bad Request. Verify Data"
                " Region and Authentication Token provided in the "
                "configuration parameters."
            ),
            401: (
                "Received exit code 401, Unauthorized. Verify Data"
                " Region and Authentication Token provided in the "
                "configuration parameters."
            ),
            403: (
                "Received exit code 403, Forbidden. Verify Data"
                " Region and Authentication Token provided in the "
                "configuration parameters."
            ),
            404: (
                "Received exit code 404, Not Found. Verify Data"
                " Region and Authentication Token provided in the "
                "configuration parameters."
            ),
        }
        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 202:
            return {}
        elif status_code == 204:
            return {}
        elif status_code == 207:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code in error_dict:
            if (
                status_code == 400
                and "The number of objects exceeds the maximum limit"
                in str(resp.text)
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Received exit code"
                        f" {status_code}, while {logger_msg}."
                    ),
                    details=str(resp.text),
                )
                raise MaximumLimitExceededException
            err_msg = error_dict[status_code]
            log_kwargs = {"details": str(resp.text)}
            if is_validation and status_code in resolution_dict:
                log_kwargs["resolution"] = resolution_dict[status_code]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                **log_kwargs,
            )
            if is_validation:
                err_msg = validation_error_dict.get(
                    status_code,
                    "Verify Data Region and Authentication Token provided in"
                    " the configuration parameters.",
                )
            raise TrendMicroPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + "."
            raise TrendMicroPluginException(err_msg)

    def _get_retry_after(self, headers) -> int:
        """Get a safe wait time from a response's Retry-After header.

        RFC 7231 allows Retry-After to be an HTTP-date, not just
        delta-seconds, so int() on it can raise; and an unbounded
        server-supplied value could block a worker thread for a long
        time, so the result is capped at 300 seconds.

        Args:
            headers: Response headers.

        Returns:
            int: Wait time in seconds.
        """
        try:
            return min(
                int(headers.get("Retry-After", DEFAULT_WAIT_TIME)), 300
            )
        except (TypeError, ValueError):
            return DEFAULT_WAIT_TIME

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        headers=None,
        json=None,
        is_validation=False,
        is_retraction=False,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.
            is_validation : API call from validation method or not
            is_retraction : Append the [Retraction] tag to this
                helper's log prefix when True, so every log line
                emitted for this call (and by handle_error /
                process_multi_status_response on its response)
                carries it, matching the tag already applied to
                self.log_prefix on the main plugin class.

        Returns:
            dict: Response dictionary.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = f"{self.log_prefix} {RETRACTION}"

            debuglog_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. URL={url}"
            )
            if params:
                debuglog_msg += f", params={params}"

            self.logger.debug(debuglog_msg)

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    timeout=REQUEST_TIMEOUT,
                )
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )

                is_retryable = response.status_code == 429 or (
                    500 <= response.status_code <= 600
                )
                if not is_validation and is_retryable:
                    is_last_attempt = retry_counter == MAX_RETRIES - 1
                    if is_last_attempt:
                        err_msg = (
                            "Received exit code {}, while"
                            " {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(response.text),
                        )
                        raise TrendMicroPluginException(err_msg)

                    wait_time = (
                        self._get_retry_after(response.headers)
                        if response.status_code == 429
                        else DEFAULT_WAIT_TIME
                    )
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds, {} "
                            "retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                wait_time,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(wait_time)
                else:
                    return self.handle_error(
                        response, logger_msg, is_validation
                    )

        except TrendMicroPluginException:
            raise
        except MaximumLimitExceededException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            log_kwargs = {"details": str(traceback.format_exc())}
            if is_validation:
                log_kwargs["resolution"] = (
                    f"Ensure that the {PLATFORM_NAME} Data Region (or"
                    " custom Base URL) provided in the configuration"
                    " parameters is reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                **log_kwargs,
            )
            raise TrendMicroPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " provided proxy configuration."
            )
            log_kwargs = {"details": str(traceback.format_exc())}
            if is_validation:
                log_kwargs["resolution"] = (
                    "Ensure that the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                **log_kwargs,
            )
            raise TrendMicroPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with"
                f" {self.plugin_name} while {logger_msg}. Check Data"
                " Region provided in configuration parameter."
            )
            log_kwargs = {"details": str(traceback.format_exc())}
            if is_validation:
                log_kwargs["resolution"] = (
                    "Ensure that the Data Region (or custom Base URL)"
                    " provided in the configuration parameters is"
                    " correct and reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                **log_kwargs,
            )
            raise TrendMicroPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} while {logger_msg}."
            )
            log_kwargs = {"details": str(traceback.format_exc())}
            if is_validation:
                log_kwargs["resolution"] = (
                    "Ensure that the configuration parameters provided"
                    " are valid."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                **log_kwargs,
            )
            raise TrendMicroPluginException(err_msg)
