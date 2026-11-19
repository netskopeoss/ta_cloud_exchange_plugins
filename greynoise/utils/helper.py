"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE GreyNoise plugin helper module.
"""

import json
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RANGE_TO_DAYS,
    REQUEST_TIMEOUT,
    RETRACTION,
    RETRY_ERROR_MSG,
)


class GreyNoisePluginException(Exception):
    """GreyNoise CTE plugin custom exception class."""
    pass


class GreyNoisePluginHelper(object):
    """GreyNoise CTE plugin helper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """GreyNoisePluginHelper initializer.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(
        self,
        headers: Union[Dict, None] = None,
    ) -> Dict:
        """Add User-Agent header for outbound requests.

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

    def _get_headers(self, api_key: str) -> Dict:
        """Build request headers for GreyNoise API.

        Args:
            api_key (str): GreyNoise API key.

        Returns:
            Dict: Headers with key and Accept fields.
        """
        return {
            "key": api_key,
            "Accept": "application/json",
        }

    def build_url(self, endpoint: str, base_url: str) -> str:
        """Construct a full URL from base URL and endpoint path.

        Args:
            endpoint (str): API endpoint path.
            base_url (str): Configured base URL.

        Returns:
            str: Full URL string.
        """
        return f"{base_url.rstrip('/')}{endpoint}"

    def validate_url(self, url: str) -> bool:
        """Validate that a URL has a scheme and netloc.

        Args:
            url (str): URL string to validate.

        Returns:
            bool: True if valid URL; False otherwise.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
        )

    def range_to_date(
        self,
        range_value: str,
        range_days=None,
    ) -> str:
        """Convert a range string to a YYYY-MM-DD date string.

        For Callback IP API, we use last_seen_after so we subtract
        the number of days from today.

        Args:
            range_value (str): One of VALID_RANGES.
            range_days: Number of days for custom range.

        Returns:
            str: Date string in YYYY-MM-DD format.
        """
        # Use UTC so the day boundary matches GreyNoise's UTC-based
        # dates. Naive local time can be off by a day on non-UTC hosts
        # or near midnight.
        now_utc = datetime.now(timezone.utc)
        if range_value == "today":
            return now_utc.strftime("%Y-%m-%d")
        if range_value == "custom":
            try:
                days = int(range_days or 1)
            except (ValueError, TypeError):
                days = 1
            return (
                now_utc - timedelta(days=days)
            ).strftime("%Y-%m-%d")
        days = RANGE_TO_DAYS.get(range_value, 1)
        return (
            now_utc - timedelta(days=days)
        ).strftime("%Y-%m-%d")

    def get_config_params(
        self,
        configuration: Dict,
    ) -> Tuple:
        """Extract all GreyNoise plugin configuration parameters.

        Args:
            configuration (Dict): Plugin configuration dict.

        Returns:
            Tuple: (base_url, api_key, enable_tagging, ioc_types,
                    classifications, callback_stages,
                    initial_range, initial_range_days,
                    retraction_interval, retraction_interval_days)
        """
        base_url = (
            configuration.get("base_url", "").strip().rstrip("/")
        )
        api_key = configuration.get("api_key", "")
        enable_tagging = (
            configuration.get("enable_tagging", "Yes").strip()
        )
        ioc_types = configuration.get("ioc_types", ["ip"])
        classifications = configuration.get(
            "classification", ["malicious", "suspicious"]
        )
        # Callback stages are configured as two independent Yes/No
        # choice fields (callback_stage_1 / callback_stage_2). Translate
        # the user's selections into the internal stage list consumed by
        # _pull_callback (which checks "stage_1"/"stage_2" membership).
        callback_stage_1 = (
            configuration.get("callback_stage_1", "Yes") or "Yes"
        ).strip()
        callback_stage_2 = (
            configuration.get("callback_stage_2", "Yes") or "Yes"
        ).strip()
        callback_stages = []
        if callback_stage_1.lower() == "yes":
            callback_stages.append("stage_1")
        if callback_stage_2.lower() == "yes":
            callback_stages.append("stage_2")
        initial_range = (
            configuration.get("initial_range", "1d").strip()
        )
        initial_range_days = configuration.get(
            "initial_range_days", None
        )
        retraction_interval = (
            configuration.get("retraction_interval", "") or ""
        ).strip()
        retraction_interval_days = configuration.get(
            "retraction_interval_days", None
        )
        return (
            base_url,
            api_key,
            enable_tagging,
            ioc_types,
            classifications,
            callback_stages,
            initial_range,
            initial_range_days,
            retraction_interval,
            retraction_interval_days,
        )

    def _get_retry_after(self, headers) -> int:
        """Return retry wait time from Retry-After header or default.

        Args:
            headers: Response headers object.

        Returns:
            int: Seconds to wait before the next retry (max 300).
        """
        try:
            return min(
                int(headers.get("Retry-After", DEFAULT_WAIT_TIME)),
                300,
            )
        except (TypeError, ValueError):
            return DEFAULT_WAIT_TIME

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Any = None,
        headers: Optional[Dict] = None,
        json_data: Any = None,
        proxy: Any = None,
        verify: Any = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        is_retraction: bool = False,
    ) -> Union[Dict, requests.Response]:
        """Execute an HTTP request with retry and error handling.

        Args:
            logger_msg (str): Context message for log output.
            url (str): Full request URL.
            method (str): HTTP method. Defaults to "GET".
            params (Dict): Query parameters.
            data: Request body for non-JSON payloads.
            headers (Dict): Request headers.
            json_data: JSON payload.
            proxy: Proxy configuration.
            verify: SSL verification flag or path.
            is_handle_error_required (bool): Apply response error
                handling when True. Defaults to True.
            is_validation (bool): Tune error messages for validation
                flows. Defaults to False.
            is_retraction (bool): Append retraction tag to log prefix
                when True. Defaults to False.

        Returns:
            Union[dict, requests.Response]: Parsed JSON on success,
                or raw Response when is_handle_error_required=False.

        Raises:
            GreyNoisePluginException: On HTTP, connectivity, or
                unexpected errors after exhausting retries.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = (
                    self.log_prefix + f" {RETRACTION}"
                )
            if headers is None:
                headers = {}
            headers = self._add_user_agent(headers)

            self.logger.debug(
                f"{self.log_prefix}: API Request for"
                f" {logger_msg}."
                f" Endpoint: {method} {url}"
                f", params: {params}"
            )

            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxy,
                    json=json_data,
                    timeout=REQUEST_TIMEOUT,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response"
                    f" for {logger_msg}."
                    f" Status Code={status_code}."
                )

                if not is_validation and (
                    status_code == 429
                    or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                            ),
                            resolution=(
                                f"Ensure that the {PLATFORM_NAME}"
                                " platform is reachable and the"
                                " API rate limit is not exceeded."
                            ),
                        )
                        raise GreyNoisePluginException(err_msg)

                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"

                    retry_after = DEFAULT_WAIT_TIME
                    try:
                        retry_after = self._get_retry_after(
                            response.headers
                        )
                    except Exception:
                        pass

                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=(
                            MAX_API_CALLS - 1 - retry_count
                        ),
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME}"
                            " platform is reachable."
                        ),
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response, logger_msg, is_validation
                        )
                        if is_handle_error_required
                        else response
                    )

        except GreyNoisePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                "Read Timeout error occurred"
                f" while {logger_msg}."
            )
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    f"Ensure that the {PLATFORM_NAME} platform"
                    " server is reachable."
                ),
            )
            raise GreyNoisePluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}."
                " Verify the proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the proxy configuration"
                    " provided is correct and the proxy server"
                    " is reachable."
                ),
            )
            raise GreyNoisePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with"
                f" {PLATFORM_NAME} platform while {logger_msg}."
                f" Proxy server or {PLATFORM_NAME} server is"
                " not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {PLATFORM_NAME} platform. Proxy server"
                    f" or {PLATFORM_NAME} server is not"
                    " reachable."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    f"Ensure that the {PLATFORM_NAME} platform"
                    " server is reachable."
                ),
            )
            raise GreyNoisePluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = (
                f"HTTP error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration"
                    " parameters provided."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters"
                    " provided are correct."
                ),
            )
            raise GreyNoisePluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call"
                    f" to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters"
                    " provided are correct."
                ),
            )
            raise GreyNoisePluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        is_validation: bool = False,
        logger_msg: Optional[str] = None,
    ):
        """Parse JSON from a requests Response object.

        Args:
            response: HTTP response object.
            is_validation (bool): Tune error messages for validation.
            logger_msg (str): Context for log messages.

        Returns:
            Any: Parsed JSON content.

        Raises:
            GreyNoisePluginException: If JSON parsing fails.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API"
                f" while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the Base URL provided in the"
                    " configuration parameters."
                ),
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL provided in the"
                    " configuration parameters."
                    " Check logs for more details."
                )
            raise GreyNoisePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" JSON response for {logger_msg}."
                f" Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution="Check logs for more details.",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred."
                    " Verify Base URL in the configuration"
                    " parameters. Check logs for more details."
                )
            raise GreyNoisePluginException(err_msg)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle HTTP status codes and return parsed responses.

        Args:
            response: HTTP response object.
            logger_msg (str): Context for log messages.
            is_validation (bool): Tune messages for validation flows.

        Returns:
            dict: Parsed JSON for 2xx responses; {} for 204.

        Raises:
            GreyNoisePluginException: For 4xx/5xx errors.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "

        error_dict = {
            400: (
                "Received exit code 400, HTTP client error."
                " Verify that the Base URL is correct and"
                " accessible."
            ),
            401: (
                "Received exit code 401, Unauthorized."
                " Verify the API Key."
            ),
            403: (
                "Received exit code 403, Forbidden. Verify"
                " API Key permissions. Ensure the key has"
                " access to the GNQL endpoint."
            ),
            404: (
                "Received exit code 404, Resource not found."
                " Verify the Base URL. The /v3/gnql endpoint"
                " was not found."
            ),
            429: (
                "Received exit code 429, Too Many Requests."
                " The API rate limit has been exceeded."
            ),
        }
        resolution_dict = {
            400: (
                "Verify that the Base URL is correct"
                " and accessible."
            ),
            401: "Verify the API Key.",
            403: (
                "Verify API Key permissions. Ensure the key"
                " has access to the GNQL endpoint."
            ),
            404: (
                "Verify the Base URL. The /v3/gnql endpoint"
                " was not found."
            ),
            429: (
                "Wait and retry after some time, or reduce the"
                " pull frequency. Ensure the GreyNoise API rate"
                " limit is not exceeded."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request."
                    " Verify that the Base URL is correct"
                    " and accessible."
                ),
                401: (
                    "Received exit code 401, Unauthorized."
                    " Verify the API Key provided in the"
                    " configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden."
                    " Verify API Key permissions. Ensure the"
                    " key has access to the GNQL endpoint."
                ),
                404: (
                    "Received exit code 404, Resource not"
                    " found. Verify the Base URL. The"
                    " /v3/gnql endpoint was not found."
                ),
                429: (
                    "Received exit code 429, Too Many Requests."
                    " The API rate limit has been exceeded."
                ),
            }

        def _log_and_raise(resolution: str = None):
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {log_err_msg}"
                    ),
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise GreyNoisePluginException(err_msg)
            else:
                err_msg = (
                    err_msg + " while " + logger_msg + "."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise GreyNoisePluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=response,
                is_validation=is_validation,
                logger_msg=logger_msg,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict.get(status_code)
            _log_and_raise(resolution=resolution_msg)
        elif 400 <= status_code < 500:
            err_msg = "HTTP Client Error"
            _log_and_raise()
        elif 500 <= status_code < 600:
            err_msg = "HTTP Server Error"
            _log_and_raise()
        else:
            err_msg = "HTTP Error"
            _log_and_raise()
