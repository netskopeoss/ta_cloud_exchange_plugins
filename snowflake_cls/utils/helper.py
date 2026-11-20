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

Snowflake CLS Plugin API helper.
"""

import json
import time
import traceback
from typing import Any, Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    AUTH_ERROR_MESSAGE,
    BAD_REQUEST_ERROR_MESSAGE,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIME,
    HTTP_BACKOFF_FACTOR,
    MAX_RETRY_COUNT,
    MAX_WAIT_TIME,
    MODULE_NAME,
    PAYLOAD_TOO_LARGE_ERROR_MESSAGE,
    PLATFORM_NAME,
    RATE_LIMIT_ERROR_MESSAGE,
    RATE_LIMIT_VALIDATION_MESSAGE,
    SERVER_ERROR_MESSAGE,
    SERVER_ERROR_VALIDATION_MESSAGE,
    TABLE_NOT_FOUND_ERROR_MESSAGE,
)
from .exceptions import (
    SnowflakeAuthenticationError,
    SnowflakePluginException,
)


class SnowflakePluginHelper:
    """Makes every HTTP call this plugin needs.

    The streaming client and the schema helper both call api_helper()
    instead of using requests directly, so retries and error handling are
    written once.
    """

    def __init__(self, logger, log_prefix, plugin_name, plugin_version):
        """Store the logging and plugin details.

        Args:
            logger: Logger object.
            log_prefix (str): Prefix put in front of every log message.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add the Cloud Exchange User-Agent to the request headers.

        Produces, for example:
        netskope-ce-6.1.0-cls-snowflake/v1.0.0

        Snowflake's SQL API requires this header and asks for an RFC 7231
        value, so the version is separated with a slash rather than a
        hyphen. The Snowpipe Streaming endpoint treats the header as
        optional and accepts the same value.

        Args:
            headers (Dict): Headers for the request.

        Returns:
            Dict: The same headers with a User-Agent added.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        # Snowflake's SQL API requires an RFC 7231 User-Agent, where a
        # product is "name/version". The slash keeps the version its own
        # field instead of folding it into the name.
        user_agent = "{}-{}-{}/v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Any:
        """Turn a response body into a Python object.

        Args:
            response (Response): Response object.
            logger_msg (str): What the plugin was doing.
            is_validation (bool): True when called from validate().

        Returns:
            Any: The parsed JSON body.

        Raises:
            SnowflakePluginException: If the body is not valid JSON.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Could not read the JSON response from {PLATFORM_NAME}"
                f" while {logger_msg}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Check the Account URL in the configuration"
                    " parameters and make sure it points at a Snowflake"
                    " account."
                ),
            )
            if is_validation:
                err_msg = (
                    f"Could not read the response from {PLATFORM_NAME}."
                    " Check the Account URL in the configuration"
                    " parameters. Check logs for more details."
                )
            raise SnowflakePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error while reading the response from"
                f" {PLATFORM_NAME} while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=(
                    "Check logs for the full response and retry the"
                    " operation."
                ),
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while reading the response from"
                    f" {PLATFORM_NAME}. Check logs for more details."
                )
            raise SnowflakePluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Any:
        """Turn an HTTP status code into a result or an exception.

        Args:
            resp (Response): Response object.
            logger_msg (str): What the plugin was doing.
            is_validation (bool): True when called from validate().

        Returns:
            Any: Parsed body for 200/201/202, {} for 204.

        Raises:
            SnowflakeAuthenticationError: On 401 or 403.
            SnowflakePluginException: On any other error status.
        """
        status_code = resp.status_code

        if status_code in (200, 201, 202):
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        if status_code == 204:
            return {}

        error_dict = {
            400: BAD_REQUEST_ERROR_MESSAGE,
            401: AUTH_ERROR_MESSAGE,
            403: AUTH_ERROR_MESSAGE,
            404: TABLE_NOT_FOUND_ERROR_MESSAGE,
            413: PAYLOAD_TOO_LARGE_ERROR_MESSAGE,
            429: RATE_LIMIT_ERROR_MESSAGE,
        }
        resolution_dict = {
            400: (
                "Check Database, Schema and Table Name in the"
                " configuration parameters for typos."
            ),
            401: (
                "Check the Account URL and the credentials"
                " in the configuration parameters. For PAT, make sure"
                " the token has not expired and the user is covered by a"
                " network policy."
            ),
            403: (
                "Give the role behind these credentials INSERT on the"
                " table."
            ),
            404: (
                "Create the table in Snowflake first, then re-save this"
                " configuration."
            ),
            413: (
                "One record on its own is over Snowflake's 4 MB request"
                " limit. Check the source data for an oversized record."
            ),
            429: (
                "Ask Snowflake support about your account's streaming"
                " ingest quota."
            ),
        }

        if status_code in error_dict:
            err_msg = error_dict[status_code]
            if status_code == 429 and is_validation:
                # validate() turns retries off, so it must not tell the
                # user the call will be retried. Same reason as 5xx.
                err_msg = RATE_LIMIT_VALIDATION_MESSAGE
            log_msg = (
                f"Received exit code {status_code} while {logger_msg}."
                f" {err_msg}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {log_msg}",
                details=f"API response: {resp.text}",
                resolution=resolution_dict.get(status_code, ""),
            )
            if status_code in (401, 403):
                raise SnowflakeAuthenticationError(err_msg)
            raise SnowflakePluginException(err_msg, status_code)

        if 500 <= status_code < 600:
            # validate() turns retries off, so it must not tell the user
            # the call will be retried.
            err_msg = (
                SERVER_ERROR_VALIDATION_MESSAGE
                if is_validation
                else SERVER_ERROR_MESSAGE
            )
        else:
            err_msg = (
                f"Received exit code {status_code} from {PLATFORM_NAME}."
            )
        self.logger.error(
            message=(
                f"{self.log_prefix}: Received exit code {status_code}"
                f" while {logger_msg}. {err_msg}"
            ),
            details=f"API response: {resp.text}",
            resolution=(
                "Check the Snowflake service status and retry the"
                " operation."
            ),
        )
        raise SnowflakePluginException(err_msg)

    def _get_retry_wait_time(
        self, response: requests.models.Response, retry_counter: int
    ) -> int:
        """Work out how long to wait before the next retry.

        Uses the Retry-After header when Snowflake sends one, otherwise
        backs off exponentially. Either way the wait is capped at
        MAX_WAIT_TIME so one slow response cannot stall a push.

        Args:
            response (Response): Response object.
            retry_counter (int): Retry attempt number, starting at 0.

        Returns:
            int: Seconds to wait.
        """
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return min(int(float(retry_after)), MAX_WAIT_TIME)
            except (TypeError, ValueError):
                # Retry-After can also be an HTTP date. We do not parse
                # that - fall through to the backoff below.
                pass
        wait_time = DEFAULT_WAIT_TIME * (HTTP_BACKOFF_FACTOR**retry_counter)
        return min(wait_time, MAX_WAIT_TIME)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        params: Dict = None,
        data: Any = None,
        headers: Dict = None,
        json_body: Any = None,
        verify: bool = True,
        proxies: Dict = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        show_data: bool = False,
    ) -> Any:
        """Make an API call, retrying on rate limits and server errors.

        Args:
            logger_msg (str): What the plugin is doing.
            url (str): Endpoint to call.
            method (str): HTTP method.
            params (Dict): Query parameters.
            data (Any): Request body.
            headers (Dict): Request headers.
            json_body (Any): JSON body, as an alternative to data.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.
            timeout (int): Request timeout in seconds.
            is_handle_error_required (bool): Pass the response through
                handle_error() instead of returning it raw.
            is_validation (bool): True when called from validate().
                Turns off retries so the user is not left waiting.
            show_data (bool): Log the request body. Off by default so a
                record never ends up in the logs.

        Returns:
            Any: Parsed body, or the raw Response when
                is_handle_error_required is False.

        Raises:
            SnowflakeAuthenticationError: On 401 or 403.
            SnowflakePluginException: On any other failure.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_msg = (
                f"API request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_msg += f", API params: {params}"
            if data and show_data:
                debug_msg += f", API data: {data}"
            if json_body and show_data:
                debug_msg += f", API json body: {json_body}"
            self.logger.debug(f"{self.log_prefix}: {debug_msg}")

            for retry_counter in range(MAX_RETRY_COUNT):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    json=json_body,
                    verify=verify,
                    proxies=proxies,
                    timeout=timeout,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for"
                    f" {logger_msg}. Status Code={status_code}."
                )

                is_retryable = status_code == 429 or (
                    500 <= status_code < 600
                )
                if is_retryable and not is_validation:
                    if retry_counter == MAX_RETRY_COUNT - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate"
                            f" limit exceeded while {logger_msg}. Max"
                            " retries for rate limit handler exceeded"
                            f" hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                            resolution=(
                                "Check the Snowflake service status"
                                " and retry."
                            ),
                        )
                        raise SnowflakePluginException(err_msg)

                    wait_time = self._get_retry_wait_time(
                        response, retry_counter
                    )
                    reason = (
                        "hit the rate limit"
                        if status_code == 429
                        else "returned a server error"
                    )
                    # The call is being retried and may well succeed, so
                    # there is nothing for the user to do and no
                    # resolution is given here. The terminal error for a
                    # run that uses up every retry is above.
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {status_code}. {PLATFORM_NAME} {reason}"
                            f" while {logger_msg}. Retrying in"
                            f" {wait_time} seconds."
                            f" {MAX_RETRY_COUNT - 1 - retry_counter}"
                            " retries left."
                        ),
                        details=f"API response: {response.text}",
                    )
                    time.sleep(wait_time)
                    # Snowflake tells a resend apart from a new write
                    # by requestId plus retryCount, so the count has
                    # to go up each time we send the same body again.
                    # The caller's dict is updated on purpose: it owns
                    # the requestId, and its own retry carries on from
                    # the number reached here.
                    if params and "retryCount" in params:
                        params["retryCount"] += 1
                    continue

                return (
                    self.handle_error(
                        response, logger_msg, is_validation
                    )
                    if is_handle_error_required
                    else response
                )

            # Not reachable while MAX_RETRY_COUNT is at least 1, because
            # the last attempt always returns or raises. Kept so this
            # method can never hand back None.
            raise SnowflakePluginException(
                f"No attempt was made while {logger_msg}. Check that"
                " MAX_RETRY_COUNT is at least 1."
            )
        except SnowflakePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Request timed out while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Request to {PLATFORM_NAME} timed out. Check the"
                    " Account URL in the configuration"
                    " parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Check network connectivity to Snowflake and retry."
                ),
            )
            raise SnowflakePluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error while {logger_msg}. Check the proxy"
                " settings."
            )
            if is_validation:
                err_msg = "Proxy error occurred. Check the proxy settings."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Check the proxy settings on the Cloud Exchange node."
                ),
            )
            raise SnowflakePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Could not connect to {PLATFORM_NAME} while"
                f" {logger_msg}. The proxy or the {PLATFORM_NAME} host is"
                " not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Could not connect to {PLATFORM_NAME}. Check the"
                    " Account URL in the configuration parameters"
                    " and make sure the host is reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Check the Account URL and network access from"
                    " the Cloud Exchange node to Snowflake."
                ),
            )
            raise SnowflakePluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Check the configuration"
                    " parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
                resolution=(
                    "Check the configuration parameters and retry."
                ),
            )
            raise SnowflakePluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while calling"
                    f" {PLATFORM_NAME}. Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution="Check logs for the full error and retry.",
            )
            raise SnowflakePluginException(err_msg)
