"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE ServiceNow plugin helper module.
"""

import hashlib
import json
import time
import traceback
from typing import Any, Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RETRACTION,
    RETRY_ERROR_MSG,
)
from .exception import ServiceNowPluginException


class ServiceNowPluginHelper(object):
    """ServiceNowPluginHelper class.

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
        """ServiceNowPluginHelper initializer.

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
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add User-Agent header for ServiceNow API requests.

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

    def get_auth(self, configuration: Dict) -> Tuple[str, str]:
        """Build the Basic Auth credential tuple.

        Args:
            configuration (Dict): Plugin configuration dict.

        Returns:
            Tuple[str, str]: (username, password) for Basic Auth.
        """
        username = configuration.get("username", "").strip()
        password = configuration.get("password", "")
        return (username, password)

    def get_config_hash(self, configuration: Dict) -> str:
        """Compute a SHA-256 hash of the connection configuration.

        Args:
            configuration (Dict): Plugin configuration dict.

        Returns:
            str: Hex digest of url|username|password.
        """
        url = configuration.get("url", "").strip().rstrip("/")
        username = configuration.get("username", "").strip()
        password = configuration.get("password", "")
        raw = f"{url}|{username}|{password}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def build_url(self, endpoint: str, configuration: Dict) -> str:
        """Construct a full URL from the configured instance URL.

        Args:
            endpoint (str): API endpoint path.
            configuration (Dict): Plugin configuration dict.

        Returns:
            str: Full URL string.
        """
        url = configuration.get("url", "").strip().rstrip("/")
        return f"{url}{endpoint}"

    def _get_retry_after(self, headers) -> int:
        """Return the retry wait time from Retry-After header or default.

        Args:
            headers: Response headers object.

        Returns:
            int: Seconds to wait before the next retry, capped at 300.
        """
        try:
            retry_after = int(headers.get("Retry-After", DEFAULT_WAIT_TIME))
        except (TypeError, ValueError):
            return DEFAULT_WAIT_TIME
        return min(retry_after, 300)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data=None,
        headers: Dict = None,
        json: Dict = None,
        auth: Tuple[str, str] = None,
        proxy: Any = None,
        verify: Any = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        is_retraction: bool = False,
    ):
        """Execute an HTTP request with retry and error handling.

        Args:
            logger_msg (str): Context message for log output.
            url (str): Full request URL.
            method (str): HTTP method. Defaults to "GET".
            params (Dict): Query parameters.
            data: Request body for non-JSON payloads.
            headers (Dict): Request headers.
            json (Dict): JSON payload.
            auth (Tuple[str, str]): Basic Auth (username, password).
            proxy: Proxy configuration.
            verify: SSL verification flag or path.
            is_handle_error_required (bool): Apply response error
                handling when True. Defaults to True.
            is_validation (bool): Tune error messages/disable retries
                for validation flows. Defaults to False.
            is_retraction (bool): Append retraction tag to log prefix
                when True. Defaults to False.

        Returns:
            Union[Dict, requests.Response]: Parsed JSON on success, or
                raw Response when is_handle_error_required is False.

        Raises:
            ServiceNowPluginException: On HTTP, connectivity, or
                unexpected errors after exhausting retries.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = f"{self.log_prefix} {RETRACTION}"
            if headers is None:
                headers = {}
            headers = self._add_user_agent(headers)

            self.logger.debug(
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )

            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    auth=auth,
                    verify=verify,
                    proxies=proxy,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for"
                    f" {logger_msg}. Status code: {status_code}."
                )

                if not is_validation and (
                    status_code == 429 or 500 <= status_code < 600
                ):
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                        )
                        raise ServiceNowPluginException(err_msg)

                    retry_after = self._get_retry_after(
                        response.headers
                    )
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=(
                            MAX_API_CALLS - 1 - retry_count
                        ),
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"API response: {response.text}",
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
        except ServiceNowPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            log_kwargs = {"details": traceback.format_exc()}
            if is_validation:
                err_msg = "Read Timeout error occurred."
                log_kwargs["resolution"] = (
                    f"Ensure that the {PLATFORM_NAME} instance is"
                    " reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                **log_kwargs,
            )
            raise ServiceNowPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}."
            )
            log_kwargs = {"details": traceback.format_exc()}
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the proxy configuration provided"
                    " is correct and the proxy server is reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                **log_kwargs,
            )
            raise ServiceNowPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}"
                f" while {logger_msg}."
            )
            log_kwargs = {"details": traceback.format_exc()}
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {PLATFORM_NAME}. Proxy server or"
                    f" {PLATFORM_NAME} instance is not reachable."
                )
                log_kwargs["resolution"] = (
                    f"Ensure that the {PLATFORM_NAME} instance URL is"
                    " correct and reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                **log_kwargs,
            )
            raise ServiceNowPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            log_kwargs = {"details": traceback.format_exc()}
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration"
                    " parameters provided."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the configuration parameters"
                    " provided are correct."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                **log_kwargs,
            )
            raise ServiceNowPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            log_kwargs = {"details": traceback.format_exc()}
            if is_validation:
                err_msg = (
                    "Unexpected error occurred while performing API"
                    f" call to {PLATFORM_NAME}."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the configuration parameters are"
                    " valid."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                **log_kwargs,
            )
            raise ServiceNowPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        is_validation: bool = False,
        logger_msg: str = None,
    ):
        """Parse JSON from a requests Response object.

        Args:
            response: HTTP response object.
            is_validation (bool): Tune error messages for validation.
            logger_msg (str): Context for log messages.

        Returns:
            Any: Parsed JSON content.

        Raises:
            ServiceNowPluginException: If JSON parsing fails.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API while"
                f" {logger_msg}. Error: {str(err)}"
            )
            log_kwargs = {"details": f"API response: {response.text}"}
            if is_validation:
                err_msg = (
                    "Verify the ServiceNow Instance URL provided in"
                    " the configuration parameters. Check logs for"
                    " more details."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the ServiceNow Instance URL is"
                    " correct."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", **log_kwargs
            )
            raise ServiceNowPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing JSON"
                f" response for {logger_msg}. Error: {exp}"
            )
            log_kwargs = {"details": f"API response: {response.text}"}
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Check"
                    " logs for more details."
                )
                log_kwargs["resolution"] = (
                    "Ensure that the configuration parameters are"
                    " valid."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", **log_kwargs
            )
            raise ServiceNowPluginException(err_msg)

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
            dict: Parsed JSON for 2xx responses; empty dict for 204.

        Raises:
            ServiceNowPluginException: For 4xx/5xx errors.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "

        error_dict = {
            400: "Received exit code 400, HTTP client error",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            401: (
                "Ensure that the Username and Password provided in"
                " the configuration parameters are correct."
            ),
            403: (
                "Ensure that the configured user has the required"
                " access to the sn_ti_observable table."
            ),
            404: (
                "Ensure that the ServiceNow Instance URL provided in"
                " the configuration parameters is correct."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request. Verify"
                    " the ServiceNow Instance URL provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized. Verify"
                    " the Username and Password provided in the"
                    " configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden. Verify that"
                    " the configured user has the required access to"
                    " the sn_ti_observable table."
                ),
                404: (
                    "Received exit code 404, Resource not found."
                    " Verify the ServiceNow Instance URL provided in"
                    " the configuration parameters."
                ),
            }

        def _log_and_raise(resolution: str = None):
            nonlocal err_msg
            log_kwargs = {"details": f"API response: {response.text}"}
            if is_validation:
                log_msg = f"{validation_msg}{err_msg}"
                if resolution:
                    log_kwargs["resolution"] = resolution
            else:
                err_msg = f"{err_msg} while {logger_msg}."
                log_msg = err_msg
            self.logger.error(
                message=f"{self.log_prefix}: {log_msg}", **log_kwargs
            )
            raise ServiceNowPluginException(err_msg)

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
            _log_and_raise(resolution=resolution_dict.get(status_code))
        elif 400 <= status_code < 500:
            err_msg = "HTTP Client Error"
            _log_and_raise()
        elif 500 <= status_code < 600:
            err_msg = "HTTP Server Error"
            _log_and_raise()
        else:
            err_msg = "HTTP Error"
            _log_and_raise()
